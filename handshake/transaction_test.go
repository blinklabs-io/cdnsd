// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/blinklabs-io/cdnsd/handshake"
)

func TestTransactionHash(t *testing.T) {
	// From TX 1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570 on mainnet
	testTxBytes := decodeHex(
		"00000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3b2cf8140134369b3b00000000001498c8297a67eb81ec36253828b5621a601ba2328a0000a62204000306566961425443087c524fd539e1eab8080000000000000000",
	)
	expectedHash := "1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570"
	expectedWitnessHash := "d36b1e9861dd504629b053d14d9801b295667a4c7002c9d2836be502bfdb3b3a"
	br := bytes.NewReader(testTxBytes)
	tmpTx, err := handshake.NewTransactionFromReader(br)
	if err != nil {
		t.Fatalf("unexpected error decoding transaction: %s", err)
	}
	tmpTxHash := hex.EncodeToString(tmpTx.Hash())
	if tmpTxHash != expectedHash {
		t.Fatalf(
			"did not get expected TX hash: got %s, wanted %s",
			tmpTxHash,
			expectedHash,
		)
	}
	tmpTxWitnessHash := hex.EncodeToString(tmpTx.WitnessHash())
	if tmpTxWitnessHash != expectedWitnessHash {
		t.Fatalf(
			"did not get expected TX witness hash: got %s, wanted %s",
			tmpTxWitnessHash,
			expectedWitnessHash,
		)
	}
}
