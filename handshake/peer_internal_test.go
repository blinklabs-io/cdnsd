// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import "testing"

func validateHeaderChain(headers []*BlockHeader, previous [32]byte) error {
	return validateHeaderChainFromLocators(
		headers,
		[][32]byte{previous},
		NetworkMainnet.PowLimitBits,
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
