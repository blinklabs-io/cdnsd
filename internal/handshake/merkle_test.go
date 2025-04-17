// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake_test

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/blinklabs-io/cdnsd/internal/handshake"
)

func TestMerkleBlockDecode(t *testing.T) {
	// From TX 1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570 on mainnet
	testProofBytes := decodeHex("c29fc32ba934ec67000000000000000000000008fb98a534f78c6594b9c5581d6e7ca688efebca93e3567d980b5cc7b8bb7632532df5d5adc0af9f2a830fcb72b2595cd7c4e34e6371465f17c907ca66957417a200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045779eb2591efda24b4e502cb186d6b7b3d786bb8b247180205b8e8edc70ec6c7daf23875654e512d4235898dfda96202d6a11f0314945c9835f60b8d14a64cc0000000070930919000000000000000000000000000000000000000000000000000000000000000002000000021881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d635707c3f700bbc507cd288fc33b433d872991cfe97e7e0c70c0ca6d1075026ae073b0103")
	expectedBlock := handshake.MerkleBlock{
		Header: handshake.BlockHeader{
			Nonce: 734240706,
			Time:  1743533225,
			PrevBlock: [32]byte(
				decodeHex(
					"0000000000000008fb98a534f78c6594b9c5581d6e7ca688efebca93e3567d98",
				),
			),
			NameRoot: [32]byte(
				decodeHex(
					"0b5cc7b8bb7632532df5d5adc0af9f2a830fcb72b2595cd7c4e34e6371465f17",
				),
			),
			ExtraNonce: [24]byte(
				decodeHex("c907ca66957417a200000000000000000000000000000000"),
			),
			WitnessRoot: [32]byte(
				decodeHex(
					"45779eb2591efda24b4e502cb186d6b7b3d786bb8b247180205b8e8edc70ec6c",
				),
			),
			MerkleRoot: [32]byte(
				decodeHex(
					"7daf23875654e512d4235898dfda96202d6a11f0314945c9835f60b8d14a64cc",
				),
			),
			Version: 0,
			Bits:    420057968,
		},
		TxCount: 2,
		Hashes: [][]byte{
			decodeHex("1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570"),
			decodeHex("7c3f700bbc507cd288fc33b433d872991cfe97e7e0c70c0ca6d1075026ae073b"),
		},
		Flags: []byte{0x03},
	}
	br := bytes.NewReader(testProofBytes)
	block, err := handshake.NewMerkleBlockFromReader(br)
	if err != nil {
		t.Fatalf("unexpected error decoding merkle block: %s", err)
	}
	if !reflect.DeepEqual(block.Header, expectedBlock.Header) {
		t.Errorf(
			"did not get expected block header:\n     got: %#v\n  wanted: %#v",
			block.Header,
			expectedBlock.Header,
		)
	}
	if block.TxCount != expectedBlock.TxCount {
		t.Errorf(
			"did not get expected TX count: got %d, wanted %d",
			block.TxCount,
			expectedBlock.TxCount,
		)
	}
	if !reflect.DeepEqual(block.Hashes, expectedBlock.Hashes) {
		var tmpHashes, expectedHashes string
		for _, hash := range block.Hashes {
			if tmpHashes != "" {
				tmpHashes += ", "
			}
			tmpHashes += hex.EncodeToString(hash)
		}
		for _, hash := range expectedBlock.Hashes {
			if expectedHashes != "" {
				expectedHashes += ", "
			}
			expectedHashes += hex.EncodeToString(hash)
		}
		t.Errorf(
			"did not get expected hashes:\n     got: %#v\n  wanted: %#v",
			tmpHashes,
			expectedHashes,
		)
	}
	if !reflect.DeepEqual(block.Flags, expectedBlock.Flags) {
		t.Errorf(
			"did not get expected flags: got: %x, wanted: %x",
			block.Flags,
			expectedBlock.Flags,
		)
	}
}
