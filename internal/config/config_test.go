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
