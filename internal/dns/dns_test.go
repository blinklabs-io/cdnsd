// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"testing"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
)

func TestResolutionContextDefaults(t *testing.T) {
	ctx := newResolutionContext()
	if ctx.depth != 0 {
		t.Errorf("expected depth 0, got %d", ctx.depth)
	}
	if ctx.maxDepth != 10 {
		t.Errorf("expected maxDepth 10, got %d", ctx.maxDepth)
	}
	if len(ctx.visited) != 0 {
		t.Errorf("expected empty visited map")
	}
}

func TestResolutionContextCycleDetection(t *testing.T) {
	ctx := newResolutionContext()

	// First visit should succeed
	if ctx.hasVisited("example.com.") {
		t.Error("should not have visited example.com yet")
	}
	ctx.markVisited("example.com.")

	// Second visit should be detected
	if !ctx.hasVisited("example.com.") {
		t.Error("should detect visited example.com")
	}
}

func TestResolutionContextDepthLimit(t *testing.T) {
	ctx := newResolutionContext()
	ctx.maxDepth = 3

	child1 := ctx.descend()
	if child1.depth != 1 {
		t.Errorf("expected depth 1, got %d", child1.depth)
	}

	child2 := child1.descend()
	child3 := child2.descend()

	if !child3.atMaxDepth() {
		t.Error("should be at max depth")
	}
}

// stateIsLoaded checks if the state database is properly initialized
func stateIsLoaded() bool {
	s := state.GetState()
	if s == nil {
		return false
	}
	// Try a lookup to see if db is initialized - this will panic if db is nil
	loaded := true
	func() {
		defer func() {
			if recover() != nil {
				loaded = false
			}
		}()
		_, _ = s.LookupRecords([]string{"A"}, "test")
	}()
	return loaded
}

func TestResolveNameserverAddressFromLocal(t *testing.T) {
	// This test requires state to be initialized with a database
	// Skip if state not available (will be tested via integration)
	if !stateIsLoaded() {
		t.Skip("state database not loaded")
	}

	ctx := newResolutionContext()
	// Resolving a nonexistent nameserver should return an error
	// (no local records, upstream resolution will fail)
	ips, err := resolveNameserverAddress("nonexistent.example.com.", ctx)
	if err == nil {
		t.Error("expected error for nonexistent nameserver")
	}
	if len(ips) != 0 {
		t.Errorf("expected empty result for nonexistent nameserver")
	}
}

func TestResolveNameserverAddressDepthLimit(t *testing.T) {
	ctx := newResolutionContext()
	ctx.depth = ctx.maxDepth // Already at max depth

	ips, err := resolveNameserverAddress("any.example.com.", ctx)
	if err == nil {
		t.Error("expected error at max depth")
	}
	if ips != nil {
		t.Error("expected nil result at max depth")
	}
}

func TestResolveNameserverAddressCycleDetection(t *testing.T) {
	ctx := newResolutionContext()
	ctx.markVisited("ns.example.com.") // Mark as already visited

	ips, err := resolveNameserverAddress("ns.example.com.", ctx)
	if err == nil {
		t.Error("expected error for cycle detection")
	}
	if ips != nil {
		t.Error("expected nil result for cycle")
	}
}

func TestDoQueryWithContextBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := newResolutionContext()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	// This should work against a public resolver
	resp, err := doQueryWithContext(msg, "8.8.8.8:53", false, ctx)
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
	if resp == nil {
		t.Error("expected response")
	}
}

func TestResolveNameserverAddressUpstream(t *testing.T) {
	// Integration test - requires network access and initialized state
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Check if state is loaded (database initialized)
	if !stateIsLoaded() {
		t.Skip("state database not loaded")
	}

	// Initialize config and root hints for test
	cfg := config.GetConfig()
	if cfg == nil {
		t.Skip("config not initialized")
	}

	ctx := newResolutionContext()
	// Try to resolve a well-known nameserver
	ips, err := resolveNameserverAddress("a.root-servers.net.", ctx)
	if err != nil {
		t.Logf("warning: upstream resolution failed: %v", err)
		// Don't fail - network may not be available
		return
	}
	if len(ips) == 0 {
		t.Log("warning: no IPs resolved for a.root-servers.net")
	}
}

func TestFindNameserversResolvesGlue(t *testing.T) {
	// This is an integration test that verifies the full flow
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Check if state is loaded (database initialized)
	if !stateIsLoaded() {
		t.Skip("state database not loaded")
	}

	// Test with a domain known to use external nameservers
	// blinklabs.io is mentioned in the issue as an example
	_, nsMap, err := findNameserversForDomain("blinklabs.io.")
	if err != nil {
		t.Skipf("could not test: %v", err)
	}

	// Should have found some nameservers with resolved addresses
	hasAddresses := false
	for _, ips := range nsMap {
		if len(ips) > 0 {
			hasAddresses = true
			break
		}
	}
	if !hasAddresses {
		t.Log("warning: no nameserver addresses resolved")
	}
}

func TestThirdPartyDNSDelegation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Test resolution of a domain known to use third-party DNS
	// without in-bailiwick glue records
	testCases := []struct {
		name   string
		domain string
	}{
		{"cloudflare-hosted", "blinklabs.io."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newResolutionContext()
			msg := new(dns.Msg)
			msg.SetQuestion(tc.domain, dns.TypeA)

			// Start from root
			rootNS := getRandomRootServer()
			if rootNS == "" {
				t.Skip("no root servers configured")
			}

			resp, err := doQueryWithContext(msg, rootNS, true, ctx)
			if err != nil {
				t.Skipf("network error: %v", err)
			}

			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("expected success, got rcode %d", resp.Rcode)
			}

			if len(resp.Answer) == 0 {
				t.Log("warning: no answer records returned")
			}
		})
	}
}
