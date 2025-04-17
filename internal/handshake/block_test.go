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

func decodeHex(hexData string) []byte {
	ret, _ := hex.DecodeString(hexData)
	return ret
}

func TestDecodeHandshakeBlock(t *testing.T) {
	// Block 0000000000000000aaeb53f05d5d6f9ec895f3ab7858c8a6b5911e41e410ebc7 from Handshake mainnet
	testBlockHex := "c29fc32ba934ec67000000000000000000000008fb98a534f78c6594b9c5581d6e7ca688efebca93e3567d980b5cc7b8bb7632532df5d5adc0af9f2a830fcb72b2595cd7c4e34e6371465f17c907ca66957417a200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045779eb2591efda24b4e502cb186d6b7b3d786bb8b247180205b8e8edc70ec6c7daf23875654e512d4235898dfda96202d6a11f0314945c9835f60b8d14a64cc000000007093091900000000000000000000000000000000000000000000000000000000000000000200000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3b2cf8140134369b3b00000000001498c8297a67eb81ec36253828b5621a601ba2328a0000a62204000306566961425443087c524fd539e1eab808000000000000000000000000021b6c08ea3b56b781a821c5e5f01e93db09409bacb2c8fdbbc50659ba135ec66d00000000ffffffff74bcb7fae5c29b149c278e0b78afd22dcdfea1339ce28af0ff68a46a716d03fa05000000ffffffff02000000000000000000145ad99a3052017938562ede6e228b68ca50c14663080320c89c49ce327748244702f481f35097199cca2f7c2549a33ecacbdf973690e53404bf1e01002000000000000000020db257ed6d1c3b47b6e2299fbfcbef58996dcd6a30e9d86837107fe90d0000000014fb7148b38057231e023ce04e52a0d1d067a9100c0000000000000241cd37781b3ec75e9960e191825a5540aba2555a64c8efc58002f3b1163240f01b6696f298b1823c206223427738c81c79e6de38ac47138a005422b9a816354dab012102042f296a2e27a712cf445e05c5085e3e6eb7a0d1cdb2989f9259c1307e3de30c02418920c4adbced17aaa59ab3848789870ef0ef00d83eb608f622242d6f4347040f3de5ff8198c3716cdb66915f83936fdcc6a5d31aa00e2b8f2ac2bd290229f58d012103b5c60aea8ec43bb6a8574caf5817be3ac376ca46ca0db22d330cbd5909a1d8f1"
	expectedBlock := handshake.Block{
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
		Transactions: []handshake.Transaction{
			{
				Version:  0,
				LockTime: 271014,
				Inputs: []handshake.TransactionInput{
					{
						PrevOutpoint: handshake.Outpoint{
							Index: 0xffffffff,
						},
						Sequence: 351808571,
						Witness: [][]byte{
							decodeHex("566961425443"),
							decodeHex("7c524fd539e1eab8"),
							decodeHex("0000000000000000"),
						},
					},
				},
				Outputs: []handshake.TransactionOutput{
					{
						Value: 1000027700,
						Address: handshake.Address{
							Version: 0,
							Hash: decodeHex(
								"98c8297a67eb81ec36253828b5621a601ba2328a",
							),
						},
					},
				},
			},
			{
				Version: 0,
				Inputs: []handshake.TransactionInput{
					{
						PrevOutpoint: handshake.Outpoint{
							Hash: [32]byte(
								decodeHex(
									"1b6c08ea3b56b781a821c5e5f01e93db09409bacb2c8fdbbc50659ba135ec66d",
								),
							),
							Index: 0,
						},
						Sequence: 0xffffffff,
						Witness: [][]byte{
							decodeHex(
								"cd37781b3ec75e9960e191825a5540aba2555a64c8efc58002f3b1163240f01b6696f298b1823c206223427738c81c79e6de38ac47138a005422b9a816354dab01",
							),
							decodeHex(
								"02042f296a2e27a712cf445e05c5085e3e6eb7a0d1cdb2989f9259c1307e3de30c",
							),
						},
					},
					{
						PrevOutpoint: handshake.Outpoint{
							Hash: [32]byte(
								decodeHex(
									"74bcb7fae5c29b149c278e0b78afd22dcdfea1339ce28af0ff68a46a716d03fa",
								),
							),
							Index: 5,
						},
						Sequence: 0xffffffff,
						Witness: [][]byte{
							decodeHex(
								"8920c4adbced17aaa59ab3848789870ef0ef00d83eb608f622242d6f4347040f3de5ff8198c3716cdb66915f83936fdcc6a5d31aa00e2b8f2ac2bd290229f58d01",
							),
							decodeHex(
								"03b5c60aea8ec43bb6a8574caf5817be3ac376ca46ca0db22d330cbd5909a1d8f1",
							),
						},
					},
				},
				Outputs: []handshake.TransactionOutput{
					{
						Value: 0,
						Address: handshake.Address{
							Version: 0,
							Hash: decodeHex(
								"5ad99a3052017938562ede6e228b68ca50c14663",
							),
						},
						Covenant: handshake.GenericCovenant{
							Type: 8,
							Items: [][]byte{
								decodeHex(
									"c89c49ce327748244702f481f35097199cca2f7c2549a33ecacbdf973690e534",
								),
								decodeHex("bf1e0100"),
								decodeHex(
									"00000000000000020db257ed6d1c3b47b6e2299fbfcbef58996dcd6a30e9d868",
								),
							},
						},
					},
					{
						Value: 59751993399,
						Address: handshake.Address{
							Version: 0,
							Hash: decodeHex(
								"fb7148b38057231e023ce04e52a0d1d067a9100c",
							),
						},
					},
				},
			},
		},
	}
	testBlockBytes, err := hex.DecodeString(testBlockHex)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	br := bytes.NewReader(testBlockBytes)
	block, err := handshake.NewBlockFromReader(br)
	if err != nil {
		t.Fatalf("unexpected error deserializing block: %s", err)
	}
	if !reflect.DeepEqual(block.Header, expectedBlock.Header) {
		t.Fatalf(
			"did not get expected block header:\n     got: %#v\n  wanted: %#v",
			block.Header,
			expectedBlock.Header,
		)
	}
	if len(block.Transactions) != len(expectedBlock.Transactions) {
		t.Fatalf(
			"did not get expected TX count: got %d, wanted %d",
			len(block.Transactions),
			len(expectedBlock.Transactions),
		)
	}
	for idx, testTx := range block.Transactions {
		expectedTx := expectedBlock.Transactions[idx]
		// Compare inputs
		if !reflect.DeepEqual(testTx.Inputs, expectedTx.Inputs) {
			t.Fatalf(
				"did not get expected TX inputs:\n     got: %#v\n  wanted: %#v",
				testTx.Inputs,
				expectedTx.Inputs,
			)
		}
		// Compare outputs
		if !reflect.DeepEqual(testTx.Outputs, expectedTx.Outputs) {
			t.Fatalf(
				"did not get expected TX outputs:\n     got: %#v\n  wanted: %#v",
				testTx.Outputs,
				expectedTx.Outputs,
			)
		}
		// Compare lock time
		if testTx.LockTime != expectedTx.LockTime {
			t.Fatalf(
				"did not get expected TX lock time: got %d, wanted %d",
				testTx.LockTime,
				expectedTx.LockTime,
			)
		}
	}
}
