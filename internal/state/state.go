// Copyright 2023 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package state

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/logging"
	"github.com/dgraph-io/badger/v4"
)

const (
	chainsyncCursorKey = "chainsync_cursor"
	fingerprintKey     = "config_fingerprint"
)

type State struct {
	db *badger.DB
}

var globalState = &State{}

func (s *State) Load() error {
	cfg := config.GetConfig()
	badgerOpts := badger.DefaultOptions(cfg.State.Directory).
		WithLogger(NewBadgerLogger()).
		// The default INFO logging is a bit verbose
		WithLoggingLevel(badger.WARNING)
	db, err := badger.Open(badgerOpts)
	// TODO: setup automatic GC for Badger
	if err != nil {
		return err
	}
	s.db = db
	//defer db.Close()
	if err := s.compareFingerprint(); err != nil {
		return err
	}
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
			if err == badger.ErrKeyNotFound {
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
				return fmt.Errorf("config fingerprint in DB doesn't match current config: %s", v)
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
	if err == badger.ErrKeyNotFound {
		return 0, "", nil
	}
	return slotNumber, blockHash, err
}

func (s *State) UpdateDomain(
	domainName string,
	nameServers map[string]string,
) error {
	logger := logging.GetLogger()
	err := s.db.Update(func(txn *badger.Txn) error {
		// Delete old records for domain
		keyPrefix := []byte(fmt.Sprintf("domain_%s_", domainName))
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
			item := it.Item()
			k := item.Key()
			if err := txn.Delete(k); err != nil {
				return err
			}
			logger.Debug(
				fmt.Sprintf(
					"deleted record for domain %s with key: %s",
					domainName,
					k,
				),
			)
		}
		// Add new records
		for nameServer, ipAddress := range nameServers {
			key := fmt.Sprintf(
				"domain_%s_nameserver_%s",
				domainName,
				nameServer,
			)
			if err := txn.Set([]byte(key), []byte(ipAddress)); err != nil {
				return err
			}
			logger.Debug(
				fmt.Sprintf(
					"added record for domain %s: %s: %s",
					domainName,
					nameServer,
					ipAddress,
				),
			)
		}
		return nil
	})
	return err
}

func (s *State) LookupDomain(domainName string) (map[string]string, error) {
	ret := map[string]string{}
	keyPrefix := []byte(fmt.Sprintf("domain_%s_nameserver_", domainName))
	err := s.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Seek(keyPrefix); it.ValidForPrefix(keyPrefix); it.Next() {
			item := it.Item()
			k := item.Key()
			keyParts := strings.Split(string(k), "_")
			nameServer := keyParts[len(keyParts)-1]
			err := item.Value(func(v []byte) error {
				ret[nameServer] = string(v)
				return nil
			})
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

// LookupNameserverRecord searches the domain nameserver entries for one matching the requested record
func (s *State) LookupNameserverRecord(
	recordName string,
) (map[string]string, error) {
	ret := map[string]string{}
	err := s.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		// Makes key scans faster
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			if strings.HasSuffix(
				string(k),
				fmt.Sprintf("_nameserver_%s", recordName),
			) {
				err := item.Value(func(v []byte) error {
					ret[recordName] = string(v)
					return nil
				})
				if err != nil {
					return err
				}
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

func GetState() *State {
	return globalState
}

// BadgerLogger is a wrapper type to give our logger the expected interface
type BadgerLogger struct {
	*logging.Logger
}

func NewBadgerLogger() *BadgerLogger {
	return &BadgerLogger{
		Logger: logging.GetLogger(),
	}
}

func (b *BadgerLogger) Warningf(msg string, args ...any) {
	b.Logger.Warnf(msg, args...)
}
