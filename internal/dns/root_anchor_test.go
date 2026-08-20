// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"context"
	"strings"
	"sync"
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
		t.Fatalf(
			"initial rollover apply = %v, %v; anchors=%v",
			changed,
			err,
			m.anchors,
		)
	}
	if m.anchors[1].Status != rootAnchorPendingAdd {
		t.Fatalf(
			"new key status = %q, want %q",
			m.anchors[1].Status,
			rootAnchorPendingAdd,
		)
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
	if err != nil || len(m.anchors) != 1 ||
		rootAnchorKey(
			mustRootKey(t, m.anchors[0].Record),
		) != rootAnchorKey(
			key2,
		) {
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

func TestFetchRootDNSKEYSkipsUnusableResponses(t *testing.T) {
	key, signer := newTestDNSSECKey(t, ".")
	rrset := []dns.RR{key}
	validResponse := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: append(
			rrset,
			signTestRRset(t, ".", key, signer, rrset),
		),
	}
	badStarted := make(chan struct{})
	goodStarted := make(chan struct{})
	releaseGood := make(chan struct{})
	resolver := &Resolver{
		rootHints: map[uint16]map[string][]dns.RR{
			dns.TypeA: {
				"a.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "a.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 1},
					},
				},
				"b.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "b.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 2},
					},
				},
			},
		},
		trustAnchors: map[string][]dns.RR{".": {testDS(t, key)}},
	}
	resolver.exchangeFn = func(
		ctx context.Context,
		_ *dns.Msg,
		address string,
		_ time.Duration,
	) (*dns.Msg, error) {
		if strings.Contains(address, "192.0.2.1") {
			close(badStarted)
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeServerFailure},
			}, nil
		}
		close(goodStarted)
		select {
		case <-releaseGood:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return validResponse.Copy(), nil
	}
	manager := &rootAnchorManager{
		resolver: resolver,
		config:   &config.Config{Dns: config.DnsConfig{QueryTimeoutMs: 500}},
	}

	type fetchResult struct {
		msg *dns.Msg
		err error
	}
	done := make(chan fetchResult, 1)
	go func() {
		msg, err := manager.fetchRootDNSKEY(context.Background())
		done <- fetchResult{msg: msg, err: err}
	}()
	select {
	case <-badStarted:
	case <-time.After(time.Second):
		t.Fatal("unusable root did not answer")
	}
	select {
	case <-goodStarted:
	case <-time.After(time.Second):
		t.Fatal("usable root query did not start")
	}
	select {
	case result := <-done:
		close(releaseGood)
		t.Fatalf(
			"fetchRootDNSKEY() returned unusable response: %v, %v",
			result.msg,
			result.err,
		)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseGood)
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("fetchRootDNSKEY() error = %v", result.err)
		}
		if len(dnskeysFrom(result.msg.Answer, ".")) != 1 {
			t.Fatalf(
				"fetchRootDNSKEY() response = %v, want root DNSKEY",
				result.msg,
			)
		}
	case <-time.After(time.Second):
		t.Fatal("fetchRootDNSKEY() did not finish")
	}
}

func TestFetchRootDNSKEYSkipsUnauthenticatedResponses(t *testing.T) {
	key, signer := newTestDNSSECKey(t, ".")
	bogusKey, _ := newTestDNSSECKey(t, ".")
	rrset := []dns.RR{key}
	validResponse := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: append(
			rrset,
			signTestRRset(t, ".", key, signer, rrset),
		),
	}
	badStarted := make(chan struct{})
	goodStarted := make(chan struct{})
	releaseGood := make(chan struct{})
	resolver := &Resolver{
		rootHints: map[uint16]map[string][]dns.RR{
			dns.TypeA: {
				"a.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "a.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 1},
					},
				},
				"b.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "b.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 2},
					},
				},
			},
		},
		trustAnchors: map[string][]dns.RR{".": {testDS(t, key)}},
	}
	resolver.exchangeFn = func(
		ctx context.Context,
		_ *dns.Msg,
		address string,
		_ time.Duration,
	) (*dns.Msg, error) {
		if strings.Contains(address, "192.0.2.1") {
			close(badStarted)
			return &dns.Msg{
				MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
				Answer: []dns.RR{bogusKey},
			}, nil
		}
		close(goodStarted)
		select {
		case <-releaseGood:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return validResponse.Copy(), nil
	}
	manager := &rootAnchorManager{
		resolver: resolver,
		config:   &config.Config{Dns: config.DnsConfig{QueryTimeoutMs: 500}},
	}

	type fetchResult struct {
		msg *dns.Msg
		err error
	}
	done := make(chan fetchResult, 1)
	go func() {
		msg, err := manager.fetchRootDNSKEY(context.Background())
		done <- fetchResult{msg: msg, err: err}
	}()
	select {
	case <-badStarted:
	case <-time.After(time.Second):
		t.Fatal("unauthenticated root did not answer")
	}
	select {
	case <-goodStarted:
	case <-time.After(time.Second):
		t.Fatal("authenticated root query did not start")
	}
	select {
	case result := <-done:
		close(releaseGood)
		t.Fatalf(
			"fetchRootDNSKEY() returned unauthenticated response: %v, %v",
			result.msg,
			result.err,
		)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseGood)
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("fetchRootDNSKEY() error = %v", result.err)
		}
		keys := dnskeysFrom(result.msg.Answer, ".")
		if len(keys) != 1 || rootAnchorKey(keys[0]) != rootAnchorKey(key) {
			t.Fatalf(
				"fetchRootDNSKEY() response = %v, want authenticated key",
				result.msg,
			)
		}
	case <-time.After(time.Second):
		t.Fatal("fetchRootDNSKEY() did not finish")
	}
}

func TestFetchRootDNSKEYBoundsConcurrentQueries(t *testing.T) {
	key, signer := newTestDNSSECKey(t, ".")
	rrset := []dns.RR{key}
	validResponse := &dns.Msg{
		MsgHdr: dns.MsgHdr{Rcode: dns.RcodeSuccess},
		Answer: append(
			rrset,
			signTestRRset(t, ".", key, signer, rrset),
		),
	}
	resolver := &Resolver{
		rootHints: map[uint16]map[string][]dns.RR{
			dns.TypeA: {
				"a.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "a.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 1},
					},
				},
				"b.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "b.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 2},
					},
				},
				"c.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "c.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 3},
					},
				},
				"d.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "d.root-test.",
							Rrtype: dns.TypeA,
						},
						A: []byte{192, 0, 2, 4},
					},
				},
			},
		},
		trustAnchors: map[string][]dns.RR{".": {testDS(t, key)}},
	}
	started := make(chan struct{}, 4)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	resolver.exchangeFn = func(
		ctx context.Context,
		_ *dns.Msg,
		_ string,
		_ time.Duration,
	) (*dns.Msg, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return validResponse.Copy(), nil
	}
	manager := &rootAnchorManager{
		resolver: resolver,
		config:   &config.Config{Dns: config.DnsConfig{QueryTimeoutMs: 500}},
	}

	done := make(chan error, 1)
	go func() {
		_, err := manager.fetchRootDNSKEY(context.Background())
		done <- err
	}()
	for range maxConcurrentNameserverQueries {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("bounded root DNSKEY exchanges did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("root trust-anchor refresh exceeded its concurrency limit")
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("fetchRootDNSKEY() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("fetchRootDNSKEY() did not finish")
	}
}

func TestRootAnchorStatePersistsAcrossRestart(t *testing.T) {
	loadIsolatedTestState(t)
	key, _ := newTestDNSSECKey(t, ".")
	cfg := *config.GetConfig()
	cfg.Dns.DNSSEC.Enabled = true
	cfg.Dns.DNSSEC.RootAnchorHoldDown = time.Hour
	resolver := &Resolver{
		trustAnchors: map[string][]dns.RR{".": {testDS(t, key)}},
	}
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
		t.Fatalf(
			"loaded state = %v, want hold-down timestamp preserved",
			loaded.anchors,
		)
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
