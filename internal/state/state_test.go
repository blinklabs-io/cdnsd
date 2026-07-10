// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package state

import (
	"encoding/json"
	"errors"
	"reflect"
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
