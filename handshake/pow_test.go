// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/blinklabs-io/cdnsd/handshake"
)

func TestCompactToTarget(t *testing.T) {
	testDefs := []struct {
		bits     uint32
		expected string
	}{
		{
			// 0x1d00ffff (Bitcoin genesis-style)
			bits:     0x1d00ffff,
			expected: "00000000ffff0000000000000000000000000000000000000000000000000000",
		},
		{
			// Exponent 3, mantissa 0x030000
			bits:     0x03030000,
			expected: "030000",
		},
		{
			// Exponent 1 (shift right case)
			bits:     0x01003456,
			expected: "00",
		},
		{
			// Exponent 4, mantissa 0x123456
			bits:     0x04123456,
			expected: "12345600",
		},
	}
	for _, td := range testDefs {
		target := handshake.CompactToTarget(td.bits)
		got := hex.EncodeToString(target.Bytes())
		// big.Int.Bytes() strips leading zeros, so compare
		// numerical values
		expectedInt := new(big.Int)
		expectedInt.SetString(td.expected, 16)
		if target.Cmp(expectedInt) != 0 {
			t.Fatalf(
				"CompactToTarget(0x%08x): got %s, want %s",
				td.bits,
				got,
				td.expected,
			)
		}
	}
}

func TestValidatePoW(t *testing.T) {
	// Use known-good blocks from block_test.go test data
	for _, testDef := range blockTestDefs {
		blockBytes, err := hex.DecodeString(testDef.blockHex)
		if err != nil {
			t.Fatalf("unexpected error decoding hex: %s", err)
		}
		br := bytes.NewReader(blockBytes)
		block, err := handshake.NewBlockFromReader(br)
		if err != nil {
			t.Fatalf(
				"unexpected error deserializing block: %s",
				err,
			)
		}
		// Verify the hash matches expectations first
		blockHash := block.Hash()
		blockHashHex := hex.EncodeToString(blockHash[:])
		if blockHashHex != testDef.expectedHash {
			t.Fatalf(
				"hash mismatch: got %s, want %s",
				blockHashHex,
				testDef.expectedHash,
			)
		}
		// Validate PoW - real blocks must pass
		if err := block.ValidatePoW(); err != nil {
			t.Fatalf(
				"ValidatePoW failed for block %s: %s",
				testDef.expectedHash,
				err,
			)
		}
	}
}

func TestValidatePoWBadBlock(t *testing.T) {
	// Take a valid block and corrupt the nonce to break PoW
	blockBytes, err := hex.DecodeString(blockTestDefs[0].blockHex)
	if err != nil {
		t.Fatalf("unexpected error decoding hex: %s", err)
	}
	br := bytes.NewReader(blockBytes)
	block, err := handshake.NewBlockFromReader(br)
	if err != nil {
		t.Fatalf(
			"unexpected error deserializing block: %s",
			err,
		)
	}
	// Corrupt the nonce
	block.Header.Nonce = 0
	if err := block.ValidatePoW(); err == nil {
		t.Fatal(
			"expected ValidatePoW to fail for corrupted block",
		)
	}
}
