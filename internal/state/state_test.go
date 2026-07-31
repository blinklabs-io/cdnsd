// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package state

import (
	"crypto/sha3"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/dgraph-io/badger/v4"
)

func newLoadedTestState(t *testing.T) *State {
	t.Helper()
	cfg := config.GetConfig()
	oldStateDir := cfg.State.Directory
	oldNetwork := cfg.Indexer.Network
	oldNetworkMagic := cfg.Indexer.NetworkMagic
	cfg.State.Directory = t.TempDir()
	cfg.Indexer.Network = "state-test"
	cfg.Indexer.NetworkMagic = 42
	t.Cleanup(func() {
		cfg.State.Directory = oldStateDir
		cfg.Indexer.Network = oldNetwork
		cfg.Indexer.NetworkMagic = oldNetworkMagic
	})
	s := &State{}
	if err := s.Load(); err != nil {
		t.Fatalf("failed to load state: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("failed to close state: %v", err)
		}
	})
	return s
}

func setRawCursor(t *testing.T, s *State, value string) {
	t.Helper()
	if err := s.update(func(txn *badger.Txn) error {
		return txn.Set([]byte(chainsyncCursorKey), []byte(value))
	}); err != nil {
		t.Fatalf("failed to set raw cursor: %v", err)
	}
}

func setRawDiscoveredAddresses(
	t *testing.T,
	s *State,
	addrs []DiscoveredAddress,
) {
	t.Helper()
	payload, err := json.Marshal(addrs)
	if err != nil {
		t.Fatalf("failed to marshal discovered addresses: %v", err)
	}
	if err := s.update(func(txn *badger.Txn) error {
		return txn.Set([]byte(discoveredAddrKey), payload)
	}); err != nil {
		t.Fatalf("failed to set discovered addresses: %v", err)
	}
}

func TestCloseStopsTickerAndClosesBadger(t *testing.T) {
	s := newLoadedTestState(t)
	if s.gcTimer == nil {
		t.Fatal("expected GC ticker to be initialized")
	}
	if err := s.UpdateCursor(7, "block-hash"); err != nil {
		t.Fatalf("failed to update cursor: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("failed to close state: %v", err)
	}
	if s.db != nil {
		t.Fatal("expected db to be cleared after close")
	}
	if s.gcTimer != nil {
		t.Fatal("expected GC ticker to be cleared after close")
	}
	if _, _, err := s.GetCursor(); !errors.Is(err, ErrStateNotLoaded) {
		t.Fatalf("expected ErrStateNotLoaded after close, got %v", err)
	}
	if err := s.Load(); err != nil {
		t.Fatalf("expected state to reload after close: %v", err)
	}
	slot, hash, err := s.GetCursor()
	if err != nil {
		t.Fatalf("failed to get cursor after reload: %v", err)
	}
	if slot != 7 || hash != "block-hash" {
		t.Fatalf("unexpected cursor after reload: slot=%d hash=%q", slot, hash)
	}
}

func TestLoadReturnsAlreadyLoadedForLoadedState(t *testing.T) {
	s := newLoadedTestState(t)
	if err := s.UpdateCursor(11, "block-hash"); err != nil {
		t.Fatalf("failed to update cursor: %v", err)
	}

	if err := s.Load(); !errors.Is(err, ErrStateAlreadyLoaded) {
		t.Fatalf("expected ErrStateAlreadyLoaded, got %v", err)
	}

	slot, hash, err := s.GetCursor()
	if err != nil {
		t.Fatalf("failed to get cursor after second load: %v", err)
	}
	if slot != 11 || hash != "block-hash" {
		t.Fatalf("unexpected cursor after second load: slot=%d hash=%q", slot, hash)
	}
}

func TestGetCursorReturnsErrorForMalformedPersistedValues(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{name: "missing separator", value: "123"},
		{name: "missing slot", value: ",block-hash"},
		{name: "invalid slot", value: "not-a-slot,block-hash"},
		{name: "missing hash", value: "123,"},
		{name: "extra separator", value: "123,block-hash,extra"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := newLoadedTestState(t)
			setRawCursor(t, s, test.value)
			_, _, err := s.GetCursor()
			if err == nil {
				t.Fatal("expected malformed cursor error")
			}
			if !strings.Contains(
				err.Error(),
				"malformed persisted chainsync cursor",
			) {
				t.Fatalf("expected clear malformed cursor error, got %v", err)
			}
		})
	}
}

func TestAddDiscoveredAddressDedupeAddressPolicyTLD(t *testing.T) {
	s := newLoadedTestState(t)
	addr := DiscoveredAddress{
		Address:  "addr1",
		PolicyId: "policy1",
		TldName:  "alpha",
	}
	sameAddressDifferentTLD := DiscoveredAddress{
		Address:  "addr1",
		PolicyId: "policy1",
		TldName:  "beta",
	}
	for _, tmpAddr := range []DiscoveredAddress{
		addr,
		addr,
		sameAddressDifferentTLD,
	} {
		if err := s.AddDiscoveredAddress(tmpAddr); err != nil {
			t.Fatalf("failed to add discovered address: %v", err)
		}
	}
	got, err := s.GetDiscoveredAddresses()
	if err != nil {
		t.Fatalf("failed to get discovered addresses: %v", err)
	}
	expected := []DiscoveredAddress{addr, sameAddressDifferentTLD}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected discovered addresses: got %#v expected %#v", got, expected)
	}

	newAddr := DiscoveredAddress{
		Address:  "addr2",
		PolicyId: "policy2",
		TldName:  "gamma",
	}
	setRawDiscoveredAddresses(
		t,
		s,
		[]DiscoveredAddress{addr, addr, sameAddressDifferentTLD},
	)
	if err := s.AddDiscoveredAddress(newAddr); err != nil {
		t.Fatalf("failed to add discovered address to duplicated set: %v", err)
	}
	got, err = s.GetDiscoveredAddresses()
	if err != nil {
		t.Fatalf("failed to get discovered addresses: %v", err)
	}
	expected = []DiscoveredAddress{addr, sameAddressDifferentTLD, newAddr}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("unexpected deduped addresses: got %#v expected %#v", got, expected)
	}
}

func TestUpdateDomainRejectsOutOfZoneRecordsAtomically(t *testing.T) {
	s := newLoadedTestState(t)
	safe := DomainRecord{
		Lhs:  "www.example",
		Type: "A",
		Ttl:  60,
		Rhs:  "192.0.2.1",
	}
	if err := s.UpdateDomain("example.", []DomainRecord{safe}); err != nil {
		t.Fatalf("failed to add safe record: %v", err)
	}
	if err := s.UpdateDomain("example.", []DomainRecord{
		{
			Lhs:  "notexample.",
			Type: "A",
			Rhs:  "192.0.2.2",
		},
	}); err == nil {
		t.Fatal("expected out-of-zone record to be rejected")
	}
	got, err := s.LookupRecords([]string{"A"}, "www.example.")
	if err != nil {
		t.Fatalf("failed to look up safe record: %v", err)
	}
	if !reflect.DeepEqual(got, []DomainRecord{safe}) {
		t.Fatalf("rejected update changed published state: got %#v", got)
	}
}

func TestStateNameWithinZoneUsesLabelBoundaries(t *testing.T) {
	if !stateNameWithinZone("www.alice.cardano", "alice.cardano") {
		t.Fatal("expected descendant name to be in zone")
	}
	if stateNameWithinZone("notalice.cardano", "alice.cardano") {
		t.Fatal("sibling name must not be considered in zone")
	}
}

func TestLoadClearsDerivedStateWhenProfileChanges(t *testing.T) {
	cfg := config.GetConfig()
	oldStateDirectory := cfg.State.Directory
	oldIndexer := cfg.Indexer
	oldProfiles := slices.Clone(cfg.Profiles)
	t.Cleanup(func() {
		cfg.State.Directory = oldStateDirectory
		cfg.Indexer = oldIndexer
		cfg.Profiles = oldProfiles
	})

	cfg.State.Directory = t.TempDir()
	cfg.Indexer.Network = "preprod"
	cfg.Indexer.NetworkMagic = 0
	cfg.Indexer.Address = ""
	cfg.Indexer.SocketPath = ""
	cfg.Indexer.InterceptHash = "old-intercept"
	cfg.Indexer.InterceptSlot = 1
	cfg.Indexer.HandshakeAddress = "old-handshake"
	cfg.Indexer.Verify = true
	cfg.Profiles = []string{"ada-preprod"}

	first := &State{}
	if err := first.Load(); err != nil {
		t.Fatalf("failed to load initial state: %v", err)
	}
	if err := first.UpdateCursor(10, "old-block"); err != nil {
		t.Fatalf("failed to persist cursor: %v", err)
	}
	if err := first.AddDiscoveredAddress(DiscoveredAddress{
		Address:  "old-address",
		TldName:  "old",
		PolicyId: "old-policy",
	}); err != nil {
		t.Fatalf("failed to persist discovered address: %v", err)
	}
	if err := first.UpdateDomain("old.example", []DomainRecord{{
		Lhs: "old.example", Type: "A", Rhs: "192.0.2.1",
	}}); err != nil {
		t.Fatalf("failed to persist domain: %v", err)
	}
	if err := first.UpdateHandshakeCursor("old-handshake-block"); err != nil {
		t.Fatalf("failed to persist handshake cursor: %v", err)
	}
	if err := first.AddHandshakeName("old-handshake-name"); err != nil {
		t.Fatalf("failed to persist handshake name: %v", err)
	}
	if err := first.UpdateHandshakeDomain("old-handshake-name", []DomainRecord{{
		Lhs: "old-handshake-name", Type: "TXT", Rhs: `"old"`,
	}}); err != nil {
		t.Fatalf("failed to persist handshake domain: %v", err)
	}
	if err := first.SetDNSSECRootAnchorState([]byte("preserve-me")); err != nil {
		t.Fatalf("failed to persist unrelated state: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("failed to close initial state: %v", err)
	}

	cfg.Profiles = []string{"auto-preprod"}
	second := &State{}
	if err := second.Load(); err != nil {
		t.Fatalf("profile change should rotate derived state, got: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if slot, hash, err := second.GetCursor(); err != nil {
		t.Fatalf("failed to read rotated cursor: %v", err)
	} else if slot != 0 || hash != "" {
		t.Fatalf("stale cursor survived profile change: %d, %q", slot, hash)
	}
	if got, err := second.GetDiscoveredAddresses(); err != nil {
		t.Fatalf("failed to read discovered addresses: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("stale discovered addresses survived profile change: %#v", got)
	}
	if got, err := second.LookupRecords([]string{"A"}, "old.example"); err != nil {
		t.Fatalf("failed to read rotated domain state: %v", err)
	} else if len(got) != 0 {
		t.Fatalf("stale domain records survived profile change: %#v", got)
	}
	if got, err := second.GetHandshakeCursor(); err != nil {
		t.Fatalf("failed to read rotated handshake cursor: %v", err)
	} else if got != "" {
		t.Fatalf("stale handshake cursor survived profile change: %q", got)
	}
	oldNameHash := sha3.Sum256([]byte("old-handshake-name"))
	if _, err := second.GetHandshakeNameByHash(oldNameHash[:]); !errors.Is(err, badger.ErrKeyNotFound) {
		t.Fatalf("stale handshake name survived profile change: %v", err)
	}
	if got, err := second.GetDNSSECRootAnchorState(); err != nil {
		t.Fatalf("failed to read unrelated state: %v", err)
	} else if string(got) != "preserve-me" {
		t.Fatalf("unrelated state was cleared: %q", got)
	}
}

func TestStateMethodsReturnNotLoadedError(t *testing.T) {
	s := &State{}
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "UpdateCursor",
			fn: func() error {
				return s.UpdateCursor(1, "block-hash")
			},
		},
		{
			name: "GetCursor",
			fn: func() error {
				_, _, err := s.GetCursor()
				return err
			},
		},
		{
			name: "AddDiscoveredAddress",
			fn: func() error {
				return s.AddDiscoveredAddress(DiscoveredAddress{})
			},
		},
		{
			name: "GetDiscoveredAddresses",
			fn: func() error {
				_, err := s.GetDiscoveredAddresses()
				return err
			},
		},
		{
			name: "UpdateDomain",
			fn: func() error {
				return s.UpdateDomain("example", nil)
			},
		},
		{
			name: "LookupRecords",
			fn: func() error {
				_, err := s.LookupRecords([]string{"A"}, "example")
				return err
			},
		},
		{
			name: "UpdateHandshakeCursor",
			fn: func() error {
				return s.UpdateHandshakeCursor("block-hash")
			},
		},
		{
			name: "GetHandshakeCursor",
			fn: func() error {
				_, err := s.GetHandshakeCursor()
				return err
			},
		},
		{
			name: "AddHandshakeName",
			fn: func() error {
				return s.AddHandshakeName("example")
			},
		},
		{
			name: "GetHandshakeNameByHash",
			fn: func() error {
				_, err := s.GetHandshakeNameByHash([]byte("hash"))
				return err
			},
		},
		{
			name: "UpdateHandshakeDomain",
			fn: func() error {
				return s.UpdateHandshakeDomain("example", nil)
			},
		},
		{
			name: "LookupHandshakeRecords",
			fn: func() error {
				_, err := s.LookupHandshakeRecords([]string{"A"}, "example")
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.fn(); !errors.Is(err, ErrStateNotLoaded) {
				t.Fatalf("expected ErrStateNotLoaded, got %v", err)
			}
		})
	}
}
