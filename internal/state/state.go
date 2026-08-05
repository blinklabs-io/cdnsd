// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package state

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/dgraph-io/badger/v4"
)

const (
	chainsyncCursorKey = "chainsync_cursor"
	discoveredAddrKey  = "discovered_addresses"
	fingerprintKey     = "config_fingerprint"
	handshakeCursorKey = "handshake_cursor"

	cardanoRecordKeyPrefix     = "r_"
	cardanoDomainKeyPrefix     = "d_"
	handshakeNameHashKeyPrefix = "hs_name_hash_"
	handshakeDomainKeyPrefix   = "hs_d_"
	handshakeRecordKeyPrefix   = "hs_r_"
	dnssecRootAnchorStateKey   = "dnssec_root_anchor_state"
	cardanoDNSSECRevisionKey   = "dnssec_revision_cardano"
	handshakeDNSSECRevisionKey = "dnssec_revision_handshake"
)

// ErrStateNotLoaded is returned when an operation needs a loaded state database.
var ErrStateNotLoaded = errors.New("state database is not loaded")

// ErrStateAlreadyLoaded is returned when loading an already loaded state database.
var ErrStateAlreadyLoaded = errors.New("state database is already loaded")

type State struct {
	mu sync.RWMutex
	db *badger.DB
	// instanceID distinguishes a database reload that starts with the same
	// persisted revision, which is important to users of the state cache.
	instanceID uint64
	gcTimer    *time.Ticker
	gcStop     chan struct{}
	gcDone     chan struct{}
}

type DomainRecord struct {
	Lhs  string
	Type string
	Ttl  int
	Rhs  string
}

type DiscoveredAddress struct {
	Address  string `json:"address"`
	TldName  string `json:"tld_name"`
	PolicyId string `json:"policy_id"`
}

var globalState = &State{}

var stateInstanceCounter atomic.Uint64

func (s *State) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return ErrStateAlreadyLoaded
	}

	cfg := config.GetConfig()
	badgerOpts := badger.DefaultOptions(cfg.State.Directory).
		WithLogger(NewBadgerLogger()).
		// The default INFO logging is a bit verbose
		WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(badgerOpts)
	if err != nil {
		return err
	}
	// Make sure existing DB matches current config options
	if err := compareFingerprint(db); err != nil {
		_ = db.Close()
		return err
	}
	// Run GC periodically for Badger DB
	gcTimer := time.NewTicker(5 * time.Minute)
	gcStop := make(chan struct{})
	gcDone := make(chan struct{})
	s.db = db
	s.instanceID = stateInstanceCounter.Add(1)
	s.gcTimer = gcTimer
	s.gcStop = gcStop
	s.gcDone = gcDone
	go runGC(db, gcTimer, gcStop, gcDone)
	return nil
}

func (s *State) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	db := s.db
	gcTimer := s.gcTimer
	gcStop := s.gcStop
	gcDone := s.gcDone
	s.db = nil
	s.gcTimer = nil
	s.gcStop = nil
	s.gcDone = nil
	if gcTimer != nil {
		gcTimer.Stop()
	}
	if gcStop != nil {
		close(gcStop)
	}
	if gcDone != nil {
		<-gcDone
	}
	if db == nil {
		s.mu.Unlock()
		return nil
	}
	err := db.Close()
	s.mu.Unlock()
	return err
}

func runGC(
	db *badger.DB,
	gcTimer *time.Ticker,
	gcStop <-chan struct{},
	gcDone chan<- struct{},
) {
	defer close(gcDone)
	for {
		select {
		case <-gcStop:
			return
		case <-gcTimer.C:
			for {
				select {
				case <-gcStop:
					return
				default:
				}
				slog.Debug("database: running GC")
				err := db.RunValueLogGC(0.5)
				if err != nil {
					// Log any actual errors
					if !errors.Is(err, badger.ErrNoRewrite) {
						slog.Warn(
							fmt.Sprintf(
								"database: GC failure: %s",
								err,
							),
						)
					}
					break
				}
				// Run it again if it just ran successfully
			}
		}
	}
}

func (s *State) view(fn func(*badger.Txn) error) error {
	if s == nil {
		return ErrStateNotLoaded
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ErrStateNotLoaded
	}
	return s.db.View(fn)
}

func (s *State) update(fn func(*badger.Txn) error) error {
	if s == nil {
		return ErrStateNotLoaded
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ErrStateNotLoaded
	}
	return s.db.Update(fn)
}

type stateFingerprint struct {
	Network          string           `json:"network"`
	NetworkMagic     uint32           `json:"network_magic"`
	Address          string           `json:"address"`
	SocketPath       string           `json:"socket_path"`
	InterceptHash    string           `json:"intercept_hash"`
	InterceptSlot    uint64           `json:"intercept_slot"`
	Verify           bool             `json:"verify"`
	HandshakeAddress string           `json:"handshake_address"`
	Profiles         []string         `json:"profiles"`
	ProfileConfigs   []config.Profile `json:"profile_configs"`
}

func currentFingerprint() (string, error) {
	cfg := config.GetConfig()
	profileNames := slices.Clone(cfg.Profiles)
	slices.Sort(profileNames)
	profileConfigs := make([]config.Profile, 0, len(profileNames))
	for _, profileName := range profileNames {
		profile, ok := config.Profiles[profileName]
		if !ok {
			return "", fmt.Errorf("unknown configured profile %q", profileName)
		}
		profileConfigs = append(profileConfigs, profile)
	}
	fingerprintValue := stateFingerprint{
		Network:          cfg.Indexer.Network,
		NetworkMagic:     cfg.Indexer.NetworkMagic,
		Address:          cfg.Indexer.Address,
		SocketPath:       cfg.Indexer.SocketPath,
		InterceptHash:    cfg.Indexer.InterceptHash,
		InterceptSlot:    cfg.Indexer.InterceptSlot,
		Verify:           cfg.Indexer.Verify,
		HandshakeAddress: cfg.Indexer.HandshakeAddress,
		Profiles:         profileNames,
		ProfileConfigs:   profileConfigs,
	}
	payload, err := json.Marshal(fingerprintValue)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(payload)
	return fmt.Sprintf("sha256:%x", hash), nil
}

func compareFingerprint(db *badger.DB) error {
	fingerprint, err := currentFingerprint()
	if err != nil {
		return err
	}
	var previous string
	err = db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(fingerprintKey))
		if err != nil {
			return err
		}
		return item.Value(func(value []byte) error {
			previous = string(value)
			return nil
		})
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return db.Update(func(txn *badger.Txn) error {
			return txn.Set([]byte(fingerprintKey), []byte(fingerprint))
		})
	}
	if err != nil {
		return err
	}
	if previous == fingerprint {
		return nil
	}
	slog.Warn(
		"state source configuration changed; clearing derived index data",
		"previous_fingerprint", previous,
		"current_fingerprint", fingerprint,
	)
	if err := clearDerivedState(db); err != nil {
		return err
	}
	return db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(fingerprintKey), []byte(fingerprint))
	})
}

// clearDerivedState removes only state produced by an indexer source. It
// intentionally leaves unrelated persisted state, such as DNSSEC anchors,
// intact when the source configuration changes.
func clearDerivedState(db *badger.DB) error {
	if err := db.DropPrefix(
		[]byte(cardanoRecordKeyPrefix),
		[]byte(cardanoDomainKeyPrefix),
		[]byte(handshakeNameHashKeyPrefix),
		[]byte(handshakeDomainKeyPrefix),
		[]byte(handshakeRecordKeyPrefix),
	); err != nil {
		return err
	}
	return db.Update(func(txn *badger.Txn) error {
		for _, key := range []string{
			chainsyncCursorKey,
			discoveredAddrKey,
			handshakeCursorKey,
		} {
			if err := txn.Delete([]byte(key)); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *State) UpdateCursor(slotNumber uint64, blockHash string) error {
	err := s.update(func(txn *badger.Txn) error {
		val := fmt.Sprintf("%d,%s", slotNumber, blockHash)
		if err := txn.Set([]byte(chainsyncCursorKey), []byte(val)); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *State) GetCursor() (uint64, string, error) {
	var slotNumber uint64
	var blockHash string
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(chainsyncCursorKey))
		if err != nil {
			return err
		}
		err = item.Value(func(v []byte) error {
			tmpSlotNumber, tmpBlockHash, err := parseCursorValue(v)
			if err != nil {
				return err
			}
			slotNumber = tmpSlotNumber
			blockHash = tmpBlockHash
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return 0, "", nil
	}
	return slotNumber, blockHash, err
}

func parseCursorValue(v []byte) (uint64, string, error) {
	value := string(v)
	cursorParts := strings.Split(value, ",")
	if len(cursorParts) != 2 {
		return 0, "", fmt.Errorf(
			"malformed persisted chainsync cursor %q: expected slot,block_hash",
			value,
		)
	}
	if cursorParts[0] == "" {
		return 0, "", fmt.Errorf(
			"malformed persisted chainsync cursor %q: missing slot",
			value,
		)
	}
	slotNumber, err := strconv.ParseUint(cursorParts[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf(
			"malformed persisted chainsync cursor %q: invalid slot %q: %w",
			value,
			cursorParts[0],
			err,
		)
	}
	if cursorParts[1] == "" {
		return 0, "", fmt.Errorf(
			"malformed persisted chainsync cursor %q: missing block hash",
			value,
		)
	}
	return slotNumber, cursorParts[1], nil
}

func (s *State) AddDiscoveredAddress(addr DiscoveredAddress) error {
	err := s.update(func(txn *badger.Txn) error {
		tmpAddrs, err := getDiscoveredAddresses(txn)
		if err != nil {
			return err
		}
		tmpAddrs, changed := dedupeDiscoveredAddresses(tmpAddrs, addr)
		if !changed {
			return nil
		}
		tmpAddrsJson, err := json.Marshal(&tmpAddrs)
		if err != nil {
			return err
		}
		return txn.Set(
			[]byte(discoveredAddrKey),
			tmpAddrsJson,
		)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *State) GetDiscoveredAddresses() ([]DiscoveredAddress, error) {
	var ret []DiscoveredAddress
	err := s.view(func(txn *badger.Txn) error {
		tmpAddrs, err := getDiscoveredAddresses(txn)
		if err != nil {
			return err
		}
		ret = tmpAddrs
		return nil
	})
	return ret, err
}

func getDiscoveredAddresses(txn *badger.Txn) ([]DiscoveredAddress, error) {
	var ret []DiscoveredAddress
	item, err := txn.Get([]byte(discoveredAddrKey))
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, nil
		}
		return nil, err
	}
	err = item.Value(func(v []byte) error {
		return json.Unmarshal(v, &ret)
	})
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func dedupeDiscoveredAddresses(
	addrs []DiscoveredAddress,
	next DiscoveredAddress,
) ([]DiscoveredAddress, bool) {
	seen := make(map[string]struct{}, len(addrs)+1)
	ret := make([]DiscoveredAddress, 0, len(addrs)+1)
	nextKey := discoveredAddressDedupeKey(next)
	foundNext := false
	changed := false
	for _, addr := range addrs {
		key := discoveredAddressDedupeKey(addr)
		if _, ok := seen[key]; ok {
			changed = true
			continue
		}
		seen[key] = struct{}{}
		ret = append(ret, addr)
		if key == nextKey {
			foundNext = true
		}
	}
	if !foundNext {
		ret = append(ret, next)
		changed = true
	}
	return ret, changed
}

func discoveredAddressDedupeKey(addr DiscoveredAddress) string {
	return strings.Join(
		[]string{addr.Address, addr.PolicyId, addr.TldName},
		"\x00",
	)
}

func (s *State) UpdateDomain(
	domainName string,
	records []DomainRecord,
) error {
	domainName, records, err := normalizeDomainRecords(domainName, records)
	if err != nil {
		return err
	}
	return s.updateDomain(
		domainName,
		records,
		cardanoDomainKeyPrefix,
		cardanoRecordKeyPrefix,
		false,
	)
}

func normalizeDomainRecords(
	domainName string,
	records []DomainRecord,
) (string, []DomainRecord, error) {
	normalizedDomainName, err := normalizeStateName(domainName)
	if err != nil {
		return "", nil, fmt.Errorf("invalid domain name %q: %w", domainName, err)
	}
	domainName = normalizedDomainName
	ret := make([]DomainRecord, 0, len(records))
	for _, record := range records {
		recordName, err := normalizeStateName(record.Lhs)
		if err != nil {
			return "", nil, fmt.Errorf("invalid record name %q: %w", record.Lhs, err)
		}
		if !stateNameWithinZone(recordName, domainName) {
			return "", nil, fmt.Errorf(
				"record name %q is outside domain %q",
				record.Lhs,
				domainName,
			)
		}
		record.Lhs = recordName
		record.Type = strings.ToUpper(strings.TrimSpace(record.Type))
		if record.Type == "" || strings.ContainsAny(record.Type, " \t\r\n") {
			return "", nil, fmt.Errorf("invalid record type %q", record.Type)
		}
		if record.Ttl < 0 {
			return "", nil, fmt.Errorf("invalid negative TTL for record %q", recordName)
		}
		ret = append(ret, record)
	}
	return domainName, ret, nil
}

func normalizeStateName(name string) (string, error) {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "..") {
		return "", errors.New("name is empty or has an empty label")
	}
	if len(name) > 253 {
		return "", errors.New("name is too long")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			return "", errors.New("label is too long")
		}
	}
	return strings.ToLower(name), nil
}

func stateNameWithinZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

func (s *State) updateDomain(
	domainName string,
	records []DomainRecord,
	domainKeyPrefix string,
	recordKeyPrefix string,
	fromHandshake bool,
) error {
	domainHash := sha256.Sum256([]byte(domainName))
	err := s.update(func(txn *badger.Txn) error {
		// Add new records
		recordKeys := make([]string, 0)
		for recordIdx, record := range records {
			key := fmt.Sprintf(
				"%s%s_%s_%x_%d",
				recordKeyPrefix,
				strings.ToUpper(record.Type),
				strings.Trim(record.Lhs, `.`),
				domainHash[:8],
				recordIdx,
			)
			recordKeys = append(recordKeys, key)
			var gobBuf bytes.Buffer
			gobEnc := gob.NewEncoder(&gobBuf)
			if err := gobEnc.Encode(&record); err != nil {
				return err
			}
			recordVal := gobBuf.Bytes()[:]
			if err := txn.Set([]byte(key), recordVal); err != nil {
				return err
			}
			slog.Debug(
				fmt.Sprintf(
					"added record for domain %s: %s: %s: %s",
					domainName,
					record.Type,
					record.Lhs,
					record.Rhs,
				),
			)
		}
		// Delete old records in tracking key that are no longer present after this update
		domainRecordsKey := fmt.Appendf(
			nil,
			"%s%s_records",
			domainKeyPrefix,
			domainName,
		)
		domainRecordsItem, err := txn.Get(domainRecordsKey)
		if err != nil {
			if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}
		} else {
			domainRecordsVal, err := domainRecordsItem.ValueCopy(nil)
			if err != nil {
				return err
			}
			domainRecordsSplit := strings.SplitSeq(string(domainRecordsVal), ",")
			for tmpRecordKey := range domainRecordsSplit {
				if tmpRecordKey == "" {
					continue
				}
				if !slices.Contains(recordKeys, tmpRecordKey) {
					if err := txn.Delete([]byte(tmpRecordKey)); err != nil {
						return err
					}
				}
			}
		}
		// Update tracking key with new record keys
		recordKeysJoin := strings.Join(recordKeys, ",")
		if err := txn.Set(domainRecordsKey, []byte(recordKeysJoin)); err != nil {
			return err
		}
		revisionKey := cardanoDNSSECRevisionKey
		if fromHandshake {
			revisionKey = handshakeDNSSECRevisionKey
		}
		if err := bumpRevision(txn, revisionKey); err != nil {
			return err
		}
		return nil
	})
	return err
}

func bumpRevision(txn *badger.Txn, key string) error {
	var revision uint64
	item, err := txn.Get([]byte(key))
	if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return err
	}
	if err == nil {
		value, valueErr := item.ValueCopy(nil)
		if valueErr != nil {
			return valueErr
		}
		revision, err = strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			return fmt.Errorf("parse DNSSEC state revision: %w", err)
		}
	}
	if revision == ^uint64(0) {
		return errors.New("DNSSEC state revision exhausted")
	}
	return txn.Set([]byte(key), []byte(strconv.FormatUint(revision+1, 10)))
}

// DNSSECRevision returns a process-local state identity and the persisted
// revision for one record namespace. The identity changes on every Load so a
// cache cannot reuse records from a closed and recreated database.
func (s *State) DNSSECRevision(fromHandshake bool) (uint64, uint64, error) {
	if s == nil {
		return 0, 0, ErrStateNotLoaded
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return 0, 0, ErrStateNotLoaded
	}
	key := cardanoDNSSECRevisionKey
	if fromHandshake {
		key = handshakeDNSSECRevisionKey
	}
	var revision uint64
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		value, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		revision, err = strconv.ParseUint(string(value), 10, 64)
		if err != nil {
			return fmt.Errorf("parse DNSSEC state revision: %w", err)
		}
		return nil
	})
	return s.instanceID, revision, err
}

func (s *State) LookupRecords(
	recordTypes []string,
	recordName string,
) ([]DomainRecord, error) {
	return s.lookupRecords(
		recordTypes,
		recordName,
		cardanoRecordKeyPrefix,
	)
}

func (s *State) LookupRecordsInZone(
	recordTypes []string,
	zone string,
) ([]DomainRecord, error) {
	return s.lookupRecordsInZone(
		recordTypes,
		zone,
		cardanoRecordKeyPrefix,
	)
}

func (s *State) lookupRecordsInZone(
	recordTypes []string,
	zone string,
	recordKeyPrefix string,
) ([]DomainRecord, error) {
	var ret []DomainRecord
	zone = strings.ToLower(strings.Trim(zone, "."))
	err := s.view(func(txn *badger.Txn) error {
		for _, recordType := range recordTypes {
			keyPrefix := fmt.Appendf(
				nil,
				"%s%s_",
				recordKeyPrefix,
				strings.ToUpper(recordType),
			)
			err := func() error {
				it := txn.NewIterator(badger.DefaultIteratorOptions)
				defer it.Close()
				for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
					item := it.Item()
					val, err := item.ValueCopy(nil)
					if err != nil {
						return err
					}
					var record DomainRecord
					if err := gob.NewDecoder(bytes.NewReader(val)).
						Decode(&record); err != nil {
						return err
					}
					name := strings.ToLower(strings.Trim(record.Lhs, "."))
					if zone != "" && !stateNameWithinZone(name, zone) {
						continue
					}
					ret = append(ret, record)
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return nil, nil
	}
	return ret, nil
}

func (s *State) lookupRecords(
	recordTypes []string,
	recordName string,
	recordKeyPrefix string,
) ([]DomainRecord, error) {
	ret := []DomainRecord{}
	recordName = strings.ToLower(strings.Trim(recordName, `.`))
	err := s.view(func(txn *badger.Txn) error {
		for _, recordType := range recordTypes {
			keyPrefix := fmt.Appendf(
				nil,
				"%s%s_%s_",
				recordKeyPrefix,
				strings.ToUpper(recordType),
				recordName,
			)

			err := func() error {
				it := txn.NewIterator(badger.DefaultIteratorOptions)
				defer it.Close()
				for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
					item := it.Item()
					val, err := item.ValueCopy(nil)
					if err != nil {
						return err
					}
					gobBuf := bytes.NewReader(val)
					gobDec := gob.NewDecoder(gobBuf)
					var tmpRecord DomainRecord
					if err := gobDec.Decode(&tmpRecord); err != nil {
						return err
					}
					if strings.ToLower(strings.Trim(tmpRecord.Lhs, ".")) != recordName {
						continue
					}
					ret = append(ret, tmpRecord)
				}
				return nil
			}()
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return nil, nil
	}
	return ret, nil
}

func (s *State) UpdateHandshakeCursor(blockHash string) error {
	err := s.update(func(txn *badger.Txn) error {
		if err := txn.Set([]byte(handshakeCursorKey), []byte(blockHash)); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (s *State) GetHandshakeCursor() (string, error) {
	var blockHash string
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(handshakeCursorKey))
		if err != nil {
			return err
		}
		val, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		blockHash = string(val)
		return nil
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return "", nil
	}
	return blockHash, err
}

// GetDNSSECRootAnchorState returns the opaque, persisted RFC 5011 state.
// Keeping serialization in the DNS package lets state remain independent of
// the trust-anchor state machine while still providing atomic persistence.
func (s *State) GetDNSSECRootAnchorState() ([]byte, error) {
	var value []byte
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(dnssecRootAnchorStateKey))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		value, err = item.ValueCopy(nil)
		return err
	})
	return value, err
}

// SetDNSSECRootAnchorState atomically replaces the persisted RFC 5011 state.
func (s *State) SetDNSSECRootAnchorState(value []byte) error {
	return s.update(func(txn *badger.Txn) error {
		return txn.Set([]byte(dnssecRootAnchorStateKey), value)
	})
}

func (s *State) AddHandshakeName(name string) error {
	nameHash := sha3.Sum256([]byte(name))
	nameHashKey := fmt.Sprintf("%s%x", handshakeNameHashKeyPrefix, nameHash)
	err := s.update(func(txn *badger.Txn) error {
		return txn.Set(
			[]byte(nameHashKey),
			[]byte(name),
		)
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *State) GetHandshakeNameByHash(nameHash []byte) (string, error) {
	var ret string
	nameHashKey := fmt.Sprintf("%s%x", handshakeNameHashKeyPrefix, nameHash)
	err := s.view(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(nameHashKey))
		if err != nil {
			return err
		}
		val, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		ret = string(val)
		return nil
	})
	if err != nil {
		return "", err
	}
	return ret, nil
}

func (s *State) UpdateHandshakeDomain(
	domainName string,
	records []DomainRecord,
) error {
	domainName, records, err := normalizeDomainRecords(domainName, records)
	if err != nil {
		return err
	}
	return s.updateDomain(
		domainName,
		records,
		handshakeDomainKeyPrefix,
		handshakeRecordKeyPrefix,
		true,
	)
}

func (s *State) LookupHandshakeRecords(
	recordTypes []string,
	recordName string,
) ([]DomainRecord, error) {
	return s.lookupRecords(
		recordTypes,
		recordName,
		handshakeRecordKeyPrefix,
	)
}

func (s *State) LookupHandshakeRecordsInZone(
	recordTypes []string,
	zone string,
) ([]DomainRecord, error) {
	return s.lookupRecordsInZone(
		recordTypes,
		zone,
		handshakeRecordKeyPrefix,
	)
}

func GetState() *State {
	return globalState
}

// BadgerLogger is a wrapper type to give our logger the expected interface
type BadgerLogger struct{}

func NewBadgerLogger() *BadgerLogger {
	return &BadgerLogger{}
}

func (b *BadgerLogger) Infof(msg string, args ...any) {
	slog.Info(
		fmt.Sprintf(msg, args...),
	)
}

func (b *BadgerLogger) Warningf(msg string, args ...any) {
	slog.Warn(
		fmt.Sprintf(msg, args...),
	)
}

func (b *BadgerLogger) Debugf(msg string, args ...any) {
	slog.Debug(
		fmt.Sprintf(msg, args...),
	)
}

func (b *BadgerLogger) Errorf(msg string, args ...any) {
	slog.Error(
		fmt.Sprintf(msg, args...),
	)
}
