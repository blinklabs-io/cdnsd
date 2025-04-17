// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake_test

import (
	"bytes"
	"testing"

	"github.com/blinklabs-io/cdnsd/internal/handshake"
)

func TestVerifySpvProof(t *testing.T) {
	testDefs := []struct {
		proof  []byte
		txHash []byte
	}{
		// From TX 1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570 on mainnet
		{
			txHash: decodeHex("1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570"),
			proof:  decodeHex("c29fc32ba934ec67000000000000000000000008fb98a534f78c6594b9c5581d6e7ca688efebca93e3567d980b5cc7b8bb7632532df5d5adc0af9f2a830fcb72b2595cd7c4e34e6371465f17c907ca66957417a200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000045779eb2591efda24b4e502cb186d6b7b3d786bb8b247180205b8e8edc70ec6c7daf23875654e512d4235898dfda96202d6a11f0314945c9835f60b8d14a64cc0000000070930919000000000000000000000000000000000000000000000000000000000000000002000000021881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d635707c3f700bbc507cd288fc33b433d872991cfe97e7e0c70c0ca6d1075026ae073b0103"),
		},
		// From TX 605f607dd492648096efe5218c6285470b52cb8108ada8a78e56fe7eadf06263 on mainnet
		{
			txHash: decodeHex("605f607dd492648096efe5218c6285470b52cb8108ada8a78e56fe7eadf06263"),
			proof:  decodeHex("a29479d8b192026800000000000000000000000181df7760f90ebea9e332e348fbd359516da507a8e8b71af75979a83096631d122fe509f4ae34298a4d1c1bc0e77bc3e17510c529da5a341c644cd524a3e20758000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000526a036bde2b0311a2dea3a0f8d7f109bed9077876103dd92cb272ff06d0a6099fec34edfa0bc2dd3891ed5fac20c3cb83fdf37eba18917acaee8bc00c9f9a8a0000000049a20a190000000000000000000000000000000000000000000000000000000000000000030000000220e2f669d5700e2d7a5243c35a1f32e7e939d0761fc3de2896d80bfca9aef369605f607dd492648096efe5218c6285470b52cb8108ada8a78e56fe7eadf06263010d"),
		},
	}
	for _, testDef := range testDefs {
		br := bytes.NewReader(testDef.proof)
		block, err := handshake.NewMerkleBlockFromReader(br)
		if err != nil {
			t.Fatalf("unexpected error decoding merkle block: %s", err)
		}
		if err := handshake.VerifySpvProof(testDef.txHash, block); err != nil {
			t.Fatalf("unexpected error verifying SPV proof: %s", err)
		}
	}

	/*
		data := [][]byte{
			decodeHex("1881afbe757f9d433144edf49e29c7f6bbfdbc1941d06792dc5ee13020d63570"),
			decodeHex("b35bfe73f0034af8deb3c5df7961bf23919b520cd83541ed4749c7a7b81b7ccc"),
		}
		tree, err := merkletree.New(data)
		if err != nil {
			panic(err)
		}
		root := tree.Root()
		fmt.Printf("root = %x\n", root)
		testVal := data[0]
		// Generate a proof for first TX hash
		proof, err := tree.GenerateProof(testVal, 0)
		if err != nil {
			panic(err)
		}
		fmt.Printf("proof = %#v\n", proof)
		verified, err := merkletree.VerifyProof(testVal, false, proof, [][]byte{root})
		if err != nil {
			panic(err)
		}
		if !verified {
			panic("failed to verify proof")
		}
	*/
}
