// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package state

import (
	"bytes"
	"crypto/sha3"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/dgraph-io/badger/v4"
)

const (
	chainsyncCursorKey = "chainsync_cursor"
	discoveredAddrKey  = "discovered_addresses"
	fingerprintKey     = "config_fingerprint"

	cardanoRecordKeyPrefix     = "r_"
	cardanoDomainKeyPrefix     = "d_"
	handshakeNameHashKeyPrefix = "hs_name_hash_"
	handshakeDomainKeyPrefix   = "hs_d_"
	handshakeRecordKeyPrefix   = "hs_r_"
)

type State struct {
	db      *badger.DB
	gcTimer *time.Ticker
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

func (s *State) Load() error {
	cfg := config.GetConfig()
	badgerOpts := badger.DefaultOptions(cfg.State.Directory).
		WithLogger(NewBadgerLogger()).
		// The default INFO logging is a bit verbose
		WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(badgerOpts)
	if err != nil {
		return err
	}
	s.db = db
	// Make sure existing DB matches current config options
	if err := s.compareFingerprint(); err != nil {
		return err
	}
	// Run GC periodically for Badger DB
	s.gcTimer = time.NewTicker(5 * time.Minute)
	go func() {
		for range s.gcTimer.C {
		again:
			slog.Debug("database: running GC")
			err := s.db.RunValueLogGC(0.5)
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
			} else {
				// Run it again if it just ran successfully
				goto again
			}
		}
	}()
	return nil
}

func (s *State) compareFingerprint() error {
	cfg := config.GetConfig()
	fingerprint := fmt.Sprintf(
		"network=%s,network-magic=%d",
		cfg.Indexer.Network,
		cfg.Indexer.NetworkMagic,
	)
	err := s.db.Update(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(fingerprintKey))
		if err != nil {
			if errors.Is(err, badger.ErrKeyNotFound) {
				if err := txn.Set([]byte(fingerprintKey), []byte(fingerprint)); err != nil {
					return err
				}
				return nil
			} else {
				return err
			}
		}
		err = item.Value(func(v []byte) error {
			if string(v) != fingerprint {
				return fmt.Errorf(
					"config fingerprint in DB doesn't match current config: %s",
					v,
				)
			}
			return nil
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *State) UpdateCursor(slotNumber uint64, blockHash string) error {
	err := s.db.Update(func(txn *badger.Txn) error {
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
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(chainsyncCursorKey))
		if err != nil {
			return err
		}
		err = item.Value(func(v []byte) error {
			var err error
			cursorParts := strings.Split(string(v), ",")
			slotNumber, err = strconv.ParseUint(cursorParts[0], 10, 64)
			if err != nil {
				return err
			}
			blockHash = cursorParts[1]
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

func (s *State) AddDiscoveredAddress(addr DiscoveredAddress) error {
	tmpAddrs, err := s.GetDiscoveredAddresses()
	if err != nil {
		return err
	}
	tmpAddrs = append(tmpAddrs, addr)
	tmpAddrsJson, err := json.Marshal(&tmpAddrs)
	if err != nil {
		return err
	}
	err = s.db.Update(func(txn *badger.Txn) error {
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
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(discoveredAddrKey))
		if err != nil {
			return err
		}
		err = item.Value(func(v []byte) error {
			return json.Unmarshal(v, &ret)
		})
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		if !errors.Is(err, badger.ErrKeyNotFound) {
			return ret, err
		}
	}
	return ret, nil
}

func (s *State) UpdateDomain(
	domainName string,
	records []DomainRecord,
) error {
	return s.updateDomain(
		domainName,
		records,
		cardanoDomainKeyPrefix,
		cardanoRecordKeyPrefix,
	)
}

func (s *State) updateDomain(
	domainName string,
	records []DomainRecord,
	domainKeyPrefix string,
	recordKeyPrefix string,
) error {
	err := s.db.Update(func(txn *badger.Txn) error {
		// Add new records
		recordKeys := make([]string, 0)
		for recordIdx, record := range records {
			key := fmt.Sprintf(
				"%s%s_%s_%d",
				recordKeyPrefix,
				strings.ToUpper(record.Type),
				strings.Trim(record.Lhs, `.`),
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
		domainRecordsKey := fmt.Appendf(nil, "%s%s_records", domainKeyPrefix, domainName)
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
		return nil
	})
	return err
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

func (s *State) lookupRecords(
	recordTypes []string,
	recordName string,
	recordKeyPrefix string,
) ([]DomainRecord, error) {
	ret := []DomainRecord{}
	recordName = strings.Trim(recordName, `.`)
	err := s.db.View(func(txn *badger.Txn) error {
		for _, recordType := range recordTypes {
			keyPrefix := fmt.Appendf(
				nil,
				"%s%s_%s_",
				recordKeyPrefix,
				strings.ToUpper(recordType),
				recordName,
			)

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
				ret = append(ret, tmpRecord)
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

func (s *State) AddHandshakeName(name string) error {
	nameHash := sha3.Sum256([]byte(name))
	nameHashKey := fmt.Sprintf("%s%x", handshakeNameHashKeyPrefix, nameHash)
	err := s.db.Update(func(txn *badger.Txn) error {
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
	err := s.db.View(func(txn *badger.Txn) error {
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
	return s.updateDomain(
		domainName,
		records,
		handshakeDomainKeyPrefix,
		handshakeRecordKeyPrefix,
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
