package config

import (
	"slices"
	"testing"
)

func TestDNSRecursionDefaultsAreLocalOnly(t *testing.T) {
	cfg := GetConfig()
	if cfg.Dns.RecursionEnabled {
		t.Fatal("recursion should be disabled by default")
	}
	want := []string{"127.0.0.0/8", "::1/128"}
	if !slices.Equal(cfg.Dns.RecursionAllowlist, want) {
		t.Fatalf(
			"default recursion allowlist = %v, want %v",
			cfg.Dns.RecursionAllowlist,
			want,
		)
	}
}
