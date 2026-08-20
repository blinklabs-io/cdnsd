// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	rootAnchorPendingAdd    = "add_pending"
	rootAnchorValid         = "valid"
	rootAnchorPendingRemove = "remove_pending"
)

var metricRootAnchorTransitions = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "dnssec_root_anchor_transition_total",
		Help: "root trust-anchor state transitions",
	},
	[]string{"state"},
)

var metricRootAnchorActive = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "dnssec_root_anchor_active",
		Help: "number of active learned root trust anchors",
	},
)

type persistedRootAnchor struct {
	Record    string    `json:"record"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
}

type persistedRootAnchorState struct {
	Version     int                   `json:"version"`
	Anchors     []persistedRootAnchor `json:"anchors"`
	LastRefresh time.Time             `json:"last_refresh"`
}

type rootAnchorManager struct {
	resolver    *Resolver
	config      *config.Config
	holdDown    time.Duration
	mu          sync.RWMutex
	anchors     []persistedRootAnchor
	lastRefresh time.Time

	// fetch is replaceable in tests. Production refreshes query a root server
	// selected from the configured root hints.
	fetch func(context.Context) (*dns.Msg, error)
}

func newRootAnchorManager(
	resolver *Resolver,
	cfg *config.Config,
) *rootAnchorManager {
	manager := &rootAnchorManager{
		resolver: resolver,
		config:   cfg,
		holdDown: cfg.Dns.DNSSEC.RootAnchorHoldDown,
	}
	manager.fetch = manager.fetchRootDNSKEY
	manager.load()
	manager.updateMetrics()
	return manager
}

func (m *rootAnchorManager) load() {
	value, err := state.GetState().GetDNSSECRootAnchorState()
	if err != nil {
		if !errors.Is(err, state.ErrStateNotLoaded) {
			slog.Warn(
				"failed to load persisted DNSSEC root trust-anchor state",
				"error",
				err,
			)
		}
		return
	}
	if len(value) == 0 {
		return
	}
	var persisted persistedRootAnchorState
	if err := json.Unmarshal(value, &persisted); err != nil ||
		persisted.Version != 1 {
		slog.Warn(
			"ignoring invalid persisted DNSSEC root trust-anchor state",
			"error",
			err,
		)
		return
	}
	for _, anchor := range persisted.Anchors {
		rr, err := dns.NewRR(anchor.Record)
		invalidStatus := anchor.Status != rootAnchorPendingAdd &&
			anchor.Status != rootAnchorValid &&
			anchor.Status != rootAnchorPendingRemove
		if err != nil || !supportedTrustAnchor(rr) || invalidStatus {
			slog.Warn(
				"ignoring invalid persisted DNSSEC root trust anchor",
				"record",
				anchor.Record,
			)
			continue
		}
		m.anchors = append(m.anchors, anchor)
	}
	m.lastRefresh = persisted.LastRefresh
}

func (m *rootAnchorManager) fetchRootDNSKEY(
	ctx context.Context,
) (*dns.Msg, error) {
	addresses := m.resolver.rootServers()
	if len(addresses) == 0 {
		return nil, errors.New(
			"no root server available for trust-anchor refresh",
		)
	}
	timeout := time.Duration(m.config.Dns.QueryTimeoutMs) * time.Millisecond
	queryCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		response *dns.Msg
		err      error
	}
	jobs := make(chan string, len(addresses))
	results := make(chan result)
	for _, address := range addresses {
		jobs <- address
	}
	close(jobs)
	workerCount := min(maxConcurrentNameserverQueries, len(addresses))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for address := range jobs {
				query := new(dns.Msg)
				query.SetQuestion(".", dns.TypeDNSKEY)
				response, err := m.resolver.exchange(
					queryCtx,
					dnssecQuery(query),
					address,
					timeout,
				)
				select {
				case results <- result{response: response, err: err}:
				case <-queryCtx.Done():
					return
				}
			}
		}()
	}
	go func() {
		workers.Wait()
		close(results)
	}()
	var errs []error
	for result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}
		if err := m.authenticateRootDNSKEYResponse(result.response); err != nil {
			errs = append(errs, err)
			continue
		}
		cancel()
		return result.response, nil
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(
			"all root servers failed: %w",
			errors.Join(errs...),
		)
	}
	return nil, errors.New(
		"all root servers returned unusable DNSKEY responses",
	)
}

func usableRootDNSKEYResponse(response *dns.Msg) bool {
	return response != nil &&
		response.Rcode == dns.RcodeSuccess &&
		len(dnskeysFrom(response.Answer, ".")) > 0
}

func (m *rootAnchorManager) authenticateRootDNSKEYResponse(
	response *dns.Msg,
) error {
	if !usableRootDNSKEYResponse(response) {
		return fmt.Errorf(
			"root server returned unusable DNSKEY response: %s",
			rcodeString(response),
		)
	}
	keys := dnskeysFrom(response.Answer, ".")
	if err := authenticateDNSKEYSet(
		toRRs(keys),
		signaturesFor(response.Answer, ".", dns.TypeDNSKEY),
		keys,
		m.currentAnchors(),
	); err != nil {
		return fmt.Errorf(
			"root server returned unauthenticated DNSKEY response: %w",
			err,
		)
	}
	return nil
}

func (m *rootAnchorManager) currentAnchors() []dns.RR {
	anchors := slices.Clone(m.resolver.trustAnchors["."])
	return append(anchors, m.learnedAnchors()...)
}

func (m *rootAnchorManager) learnedAnchors() []dns.RR {
	var anchors []dns.RR
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, persisted := range m.anchors {
		if persisted.Status != rootAnchorValid &&
			persisted.Status != rootAnchorPendingRemove {
			continue
		}
		rr, err := dns.NewRR(persisted.Record)
		if err == nil && supportedTrustAnchor(rr) {
			anchors = append(anchors, rr)
		}
	}
	return anchors
}

func rootAnchorKey(key *dns.DNSKEY) string {
	if key == nil {
		return ""
	}
	normalized := *key
	normalized.Flags &^= dns.REVOKE
	return fmt.Sprintf(
		"%d/%d/%s",
		normalized.KeyTag(),
		normalized.Algorithm,
		normalized.PublicKey,
	)
}

func rootAnchorRecord(key *dns.DNSKEY) string {
	copy := *key
	copy.Hdr.Ttl = 0
	return copy.String()
}

func parseRootAnchor(record string) (*dns.DNSKEY, error) {
	rr, err := dns.NewRR(record)
	if err != nil {
		return nil, err
	}
	key, ok := rr.(*dns.DNSKEY)
	if !ok || canonicalDNSName(key.Hdr.Name) != "." {
		return nil, errors.New("root trust anchor is not a root DNSKEY")
	}
	return key, nil
}

func (m *rootAnchorManager) refresh(ctx context.Context) error {
	resp, err := m.fetch(ctx)
	if err != nil {
		metricRootAnchorTransitions.WithLabelValues("failure").Inc()
		return fmt.Errorf("fetch root DNSKEY: %w", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		metricRootAnchorTransitions.WithLabelValues("failure").Inc()
		return fmt.Errorf("root DNSKEY query returned %s", rcodeString(resp))
	}
	keys := dnskeysFrom(resp.Answer, ".")
	if len(keys) == 0 {
		metricRootAnchorTransitions.WithLabelValues("failure").Inc()
		return errors.New("root DNSKEY response contained no DNSKEY records")
	}
	if err := authenticateDNSKEYSet(
		toRRs(keys),
		signaturesFor(resp.Answer, ".", dns.TypeDNSKEY),
		keys,
		m.currentAnchors(),
	); err != nil {
		metricRootAnchorTransitions.WithLabelValues("failure").Inc()
		return fmt.Errorf("authenticate root DNSKEY response: %w", err)
	}

	now := time.Now().UTC()
	m.mu.Lock()
	changed, err := m.apply(keys, now)
	if err == nil {
		m.lastRefresh = now
	}
	m.mu.Unlock()
	if err != nil {
		metricRootAnchorTransitions.WithLabelValues("failure").Inc()
		return err
	}
	if changed || m.lastRefresh.Equal(now) {
		if err := m.persist(); err != nil {
			metricRootAnchorTransitions.WithLabelValues("failure").Inc()
			return fmt.Errorf("persist root trust-anchor state: %w", err)
		}
	}
	m.updateMetrics()
	slog.Info(
		"authenticated root DNSSEC trust-anchor refresh",
		"active",
		m.activeCount(),
	)
	return nil
}

func toRRs(keys []*dns.DNSKEY) []dns.RR {
	ret := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		ret = append(ret, key)
	}
	return ret
}

func (m *rootAnchorManager) apply(
	keys []*dns.DNSKEY,
	now time.Time,
) (bool, error) {
	byID := make(map[string]*dns.DNSKEY, len(keys))
	revoked := make(map[string]struct{})
	for _, key := range keys {
		if key.Flags&dns.SEP == 0 {
			continue
		}
		if key.Flags&dns.REVOKE != 0 {
			revoked[rootAnchorKey(key)] = struct{}{}
		} else {
			byID[rootAnchorKey(key)] = key
		}
	}
	known := make(map[string]struct{}, len(m.anchors))
	changed := false
	for idx := 0; idx < len(m.anchors); {
		anchor := &m.anchors[idx]
		key, err := parseRootAnchor(anchor.Record)
		if err != nil {
			return false, err
		}
		id := rootAnchorKey(key)
		known[id] = struct{}{}
		if _, isRevoked := revoked[id]; isRevoked {
			m.anchors = append(m.anchors[:idx], m.anchors[idx+1:]...)
			changed = true
			metricRootAnchorTransitions.WithLabelValues("revoked").Inc()
			slog.Warn(
				"root DNSSEC trust anchor revoked",
				"key_tag",
				key.KeyTag(),
			)
			continue
		}
		candidate, present := byID[id]
		if present {
			if anchor.Status == rootAnchorPendingAdd &&
				now.Sub(anchor.FirstSeen) >= m.holdDown {
				anchor.Status = rootAnchorValid
				changed = true
				metricRootAnchorTransitions.WithLabelValues(rootAnchorValid).
					Inc()
				slog.Info(
					"root DNSSEC trust anchor accepted after hold-down",
					"key_tag",
					candidate.KeyTag(),
				)
			} else if anchor.Status == rootAnchorPendingRemove {
				anchor.Status = rootAnchorValid
				changed = true
				metricRootAnchorTransitions.WithLabelValues(rootAnchorValid).Inc()
			}
			idx++
			continue
		}
		switch anchor.Status {
		case rootAnchorPendingAdd:
			m.anchors = append(m.anchors[:idx], m.anchors[idx+1:]...)
			changed = true
			metricRootAnchorTransitions.WithLabelValues("add_failed").Inc()
			continue
		case rootAnchorValid:
			anchor.Status = rootAnchorPendingRemove
			anchor.FirstSeen = now
			changed = true
			metricRootAnchorTransitions.WithLabelValues(rootAnchorPendingRemove).
				Inc()
		case rootAnchorPendingRemove:
			if now.Sub(anchor.FirstSeen) >= m.holdDown {
				m.anchors = append(m.anchors[:idx], m.anchors[idx+1:]...)
				changed = true
				metricRootAnchorTransitions.WithLabelValues("removed").Inc()
				continue
			}
		}
		idx++
	}
	for _, key := range keys {
		if key.Flags&dns.SEP == 0 || key.Flags&dns.REVOKE != 0 {
			continue
		}
		id := rootAnchorKey(key)
		if _, ok := known[id]; ok {
			continue
		}
		m.anchors = append(m.anchors, persistedRootAnchor{
			Record:    rootAnchorRecord(key),
			Status:    rootAnchorPendingAdd,
			FirstSeen: now,
		})
		changed = true
		metricRootAnchorTransitions.WithLabelValues(rootAnchorPendingAdd).Inc()
		slog.Info(
			"new root DNSSEC trust anchor observed; hold-down started",
			"key_tag",
			key.KeyTag(),
		)
	}
	return changed, nil
}

func (m *rootAnchorManager) persist() error {
	m.mu.RLock()
	persisted := persistedRootAnchorState{
		Version:     1,
		Anchors:     slices.Clone(m.anchors),
		LastRefresh: m.lastRefresh,
	}
	m.mu.RUnlock()
	value, err := json.Marshal(persisted)
	if err != nil {
		return err
	}
	if err := state.GetState().SetDNSSECRootAnchorState(value); err != nil {
		if errors.Is(err, state.ErrStateNotLoaded) {
			return nil
		}
		return err
	}
	return nil
}

func (m *rootAnchorManager) activeCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, anchor := range m.anchors {
		if anchor.Status == rootAnchorValid ||
			anchor.Status == rootAnchorPendingRemove {
			count++
		}
	}
	return count
}

func (m *rootAnchorManager) updateMetrics() {
	metricRootAnchorActive.Set(float64(m.activeCount()))
}

func (m *rootAnchorManager) start() func() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		refresh := func() {
			refreshCtx, refreshCancel := context.WithTimeout(
				ctx,
				time.Duration(m.config.Dns.QueryTimeoutMs)*time.Millisecond,
			)
			if err := m.refresh(refreshCtx); err != nil {
				slog.Warn(
					"DNSSEC root trust-anchor refresh failed",
					"error",
					err,
				)
			}
			refreshCancel()
		}
		refresh()
		ticker := time.NewTicker(m.config.Dns.DNSSEC.RootAnchorRefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
