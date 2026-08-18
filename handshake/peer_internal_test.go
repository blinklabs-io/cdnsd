// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"math/big"
	"strings"
	"testing"
)

func validateHeaderChain(headers []*BlockHeader, previous [32]byte) error {
	return validateHeaderChainFromLocators(
		headers,
		[][32]byte{previous},
		NetworkMainnet,
	)
}

func TestValidateHeaderChainRejectsBrokenParent(t *testing.T) {
	var previous [32]byte
	var wrongParent [32]byte
	wrongParent[0] = 1
	if err := validateHeaderChain(
		[]*BlockHeader{{PrevBlock: wrongParent}},
		previous,
	); err == nil {
		t.Fatal("validateHeaderChain accepted a header with the wrong parent")
	}
}

func TestValidateHeaderChainRejectsNilHeader(t *testing.T) {
	if err := validateHeaderChain([]*BlockHeader{nil}, [32]byte{}); err == nil {
		t.Fatal("validateHeaderChain accepted a nil header")
	}
}

func TestValidateHeaderChainRejectsTargetAboveNetworkLimit(t *testing.T) {
	if err := validateHeaderChain(
		[]*BlockHeader{{Bits: 0x1d00ffff}},
		[32]byte{},
	); err == nil {
		t.Fatal("validateHeaderChain accepted a target above the network limit")
	}
}

// TestValidateHeaderChainUsesExplicitPowLimit covers a network that configures
// PowLimit directly and leaves the compact PowLimitBits at its zero value.
// PowLimit is what the per-header check enforces, so deriving the limit from
// PowLimitBits unconditionally would reject every header batch on such a
// network: CompactToTargetChecked refuses a zero encoding.
func TestValidateHeaderChainUsesExplicitPowLimit(t *testing.T) {
	network := Network{
		Name:     "explicit-powlimit",
		PowLimit: CompactToTarget(0x1d00ffff),
		// PowLimitBits deliberately left zero.
	}
	// A target at the configured limit must be accepted by the limit check.
	// ValidatePoW still applies, so assert on the limit error specifically
	// rather than on overall success.
	err := validateHeaderChainFromLocators(
		[]*BlockHeader{{Bits: 0x1d00ffff}},
		[][32]byte{{}},
		network,
	)
	if err != nil && strings.Contains(err.Error(), "invalid network PoW limit") {
		t.Fatalf("explicit PowLimit was ignored in favour of zero PowLimitBits: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "exceeds network PoW limit") {
		t.Fatalf("target at the configured limit was rejected: %v", err)
	}

	// A target above the configured limit must still be refused.
	err = validateHeaderChainFromLocators(
		[]*BlockHeader{{Bits: 0x1e00ffff}},
		[][32]byte{{}},
		network,
	)
	if err == nil || !strings.Contains(err.Error(), "exceeds network PoW limit") {
		t.Fatalf("target above the configured PowLimit: want a limit error, got %v", err)
	}
}

// TestValidateHeaderChainRejectsUnusableNetworkPowLimit is the companion: with
// neither PowLimit nor a valid PowLimitBits there is no limit to enforce, so
// validation must fail loudly rather than proceed without a ceiling.
func TestValidateHeaderChainRejectsUnusableNetworkPowLimit(t *testing.T) {
	err := validateHeaderChainFromLocators(
		[]*BlockHeader{{Bits: 0x1d00ffff}},
		[][32]byte{{}},
		Network{Name: "no-powlimit"},
	)
	if err == nil || !strings.Contains(err.Error(), "invalid network PoW limit") {
		t.Fatalf("network with no usable PoW limit: want an invalid-limit error, got %v", err)
	}
}

// TestValidateHeaderChainRejectsInvalidExplicitPowLimit covers a malformed
// explicit PowLimit. It bypasses the compact decoder, so it needs the same
// bounds check: a non-positive limit rejects every header and stalls sync, and
// one wider than 256 bits cannot constrain any hash, silently disabling the
// gate that stops a peer choosing its own difficulty.
func TestValidateHeaderChainRejectsInvalidExplicitPowLimit(t *testing.T) {
	oversized := new(big.Int).Lsh(big.NewInt(1), 256)
	for name, limit := range map[string]*big.Int{
		"zero":      big.NewInt(0),
		"negative":  big.NewInt(-1),
		"oversized": oversized,
	} {
		t.Run(name, func(t *testing.T) {
			err := validateHeaderChainFromLocators(
				[]*BlockHeader{{Bits: 0x1d00ffff}},
				[][32]byte{{}},
				Network{Name: "bad-powlimit", PowLimit: limit},
			)
			if err == nil || !strings.Contains(err.Error(), "invalid network PoW limit") {
				t.Fatalf("PowLimit %s: want an invalid-limit error, got %v", limit, err)
			}
		})
	}
}
