// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/miekg/dns"
)

func TestRootAnchorRFC5011Lifecycle(t *testing.T) {
	key, _ := newTestDNSSECKey(t, ".")
	key2, _ := newTestDNSSECKey(t, ".")
	now := time.Unix(1000, 0).UTC()
	m := &rootAnchorManager{
		holdDown: time.Hour,
		anchors: []persistedRootAnchor{{
			Record:    rootAnchorRecord(key),
			Status:    rootAnchorValid,
			FirstSeen: now,
		}},
	}

	changed, err := m.apply([]*dns.DNSKEY{key, key2}, now)
	if err != nil || !changed || len(m.anchors) != 2 {
		t.Fatalf("initial rollover apply = %v, %v; anchors=%v", changed, err, m.anchors)
	}
	if m.anchors[1].Status != rootAnchorPendingAdd {
		t.Fatalf("new key status = %q, want %q", m.anchors[1].Status, rootAnchorPendingAdd)
	}

	_, err = m.apply([]*dns.DNSKEY{key, key2}, now.Add(2*time.Hour))
	if err != nil || m.anchors[1].Status != rootAnchorValid {
		t.Fatalf("hold-down apply = %v; anchors=%v", err, m.anchors)
	}

	_, err = m.apply([]*dns.DNSKEY{key2}, now.Add(3*time.Hour))
	if err != nil || m.anchors[0].Status != rootAnchorPendingRemove {
		t.Fatalf("removal start = %v; anchors=%v", err, m.anchors)
	}
	_, err = m.apply([]*dns.DNSKEY{key2}, now.Add(5*time.Hour))
	if err != nil || len(m.anchors) != 1 || rootAnchorKey(mustRootKey(t, m.anchors[0].Record)) != rootAnchorKey(key2) {
		t.Fatalf("removal completion = %v; anchors=%v", err, m.anchors)
	}

	key2.Flags |= dns.REVOKE
	_, err = m.apply([]*dns.DNSKEY{key2}, now.Add(6*time.Hour))
	if err != nil || len(m.anchors) != 0 {
		t.Fatalf("revocation apply = %v; anchors=%v", err, m.anchors)
	}
}

func TestRootAnchorRefreshRejectsUnauthenticatedResponse(t *testing.T) {
	key, _ := newTestDNSSECKey(t, ".")
	other, _ := newTestDNSSECKey(t, ".")
	cfg := *config.GetConfig()
	cfg.Dns.DNSSEC.Enabled = true
	cfg.Dns.DNSSEC.TrustAnchors = testDS(t, key).String()
	resolver, err := NewResolver(&cfg)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	m := resolver.rootAnchorManager
	m.fetch = func(context.Context) (*dns.Msg, error) {
		msg := new(dns.Msg)
		msg.Rcode = dns.RcodeSuccess
		msg.Answer = []dns.RR{other}
		return msg, nil
	}
	if err := m.refresh(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "authenticate root DNSKEY") {
		t.Fatalf("refresh() error = %v, want authentication failure", err)
	}
	if len(m.anchors) != 0 {
		t.Fatalf("failed refresh changed persisted anchors: %v", m.anchors)
	}

	// The bootstrap DS itself remains usable after a failed update.
	anchors := resolver.configuredTrustAnchors(".")
	if len(anchors) == 0 || !dnskeyMatchesAnchor(key, anchors[0]) {
		t.Fatal("failed update replaced bootstrap anchor")
	}
}

func TestRootAnchorStatePersistsAcrossRestart(t *testing.T) {
	loadIsolatedTestState(t)
	key, _ := newTestDNSSECKey(t, ".")
	cfg := *config.GetConfig()
	cfg.Dns.DNSSEC.Enabled = true
	cfg.Dns.DNSSEC.RootAnchorHoldDown = time.Hour
	resolver := &Resolver{trustAnchors: map[string][]dns.RR{".": {testDS(t, key)}}}
	m := newRootAnchorManager(resolver, &cfg)
	now := time.Now().UTC()
	m.anchors = []persistedRootAnchor{{
		Record:    rootAnchorRecord(key),
		Status:    rootAnchorPendingAdd,
		FirstSeen: now,
	}}
	m.lastRefresh = now
	if err := m.persist(); err != nil {
		t.Fatalf("persist() error = %v", err)
	}
	loaded := newRootAnchorManager(resolver, &cfg)
	if len(loaded.anchors) != 1 || !loaded.anchors[0].FirstSeen.Equal(now) {
		t.Fatalf("loaded state = %v, want hold-down timestamp preserved", loaded.anchors)
	}
}

func mustRootKey(t *testing.T, record string) *dns.DNSKEY {
	t.Helper()
	key, err := parseRootAnchor(record)
	if err != nil {
		t.Fatalf("parseRootAnchor() error = %v", err)
	}
	return key
}
