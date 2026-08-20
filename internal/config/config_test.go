package config

import (
	"slices"
	"testing"
)

func TestDNSRecursionDefaultsAreLocalOnly(t *testing.T) {
	want := []string{"127.0.0.0/8", "::1/128"}
	if !slices.Equal(defaultRecursionAllowlist, want) {
		t.Fatalf(
			"default recursion allowlist = %v, want %v",
			defaultRecursionAllowlist,
			want,
		)
	}
	if !slices.Equal(DefaultDNSRecursionAllowlist(), want) {
		t.Fatalf("DefaultDNSRecursionAllowlist() = %v, want %v", DefaultDNSRecursionAllowlist(), want)
	}
}

func TestLoadClampsPositiveDNSQueryTimeouts(t *testing.T) {
	original := *globalConfig
	original.Dns.RecursionAllowlist = slices.Clone(
		globalConfig.Dns.RecursionAllowlist,
	)
	original.Profiles = slices.Clone(globalConfig.Profiles)
	t.Cleanup(func() {
		*globalConfig = original
	})
	t.Setenv("DNS_QUERY_TIMEOUT_MS", "1")
	t.Setenv("DNS_RECURSION_TIMEOUT_MS", "1")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Dns.QueryTimeoutMs != 5000 {
		t.Fatalf(
			"QueryTimeoutMs = %d, want minimum 5000",
			cfg.Dns.QueryTimeoutMs,
		)
	}
	if cfg.Dns.RecursionTimeoutMs != 10000 {
		t.Fatalf(
			"RecursionTimeoutMs = %d, want minimum 10000",
			cfg.Dns.RecursionTimeoutMs,
		)
	}
}
