// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package genesis

import (
	"encoding/json"
	"strconv"
	"strings"
)

var raw = []byte(`{
	"main": {
	  "version": 0,
	  "hash": "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
	  "prev_block": "0000000000000000000000000000000000000000000000000000000000000000",
	  "merkle_root": "8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15",
	  "witness_root": "1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351",
	  "tree_root": "0000000000000000000000000000000000000000000000000000000000000000",
	  "reserved_root": "0000000000000000000000000000000000000000000000000000000000000000",
	  "time": 1580745078,
	  "bits": "0x1c00ffff",
	  "nonce": 0,
	  "mask": "0000000000000000000000000000000000000000000000000000000000000000",
	  "extra_nonce": "000000000000000000000000000000000000000000000000",
	  "height": 0,
	  "magic": 1533997779,
	  "data_b64": "AAAAAHZBOF4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGixguUOSBpOPjXgjeCq9uLIRpXQx6cm2pjZdjUKJM1GOTJdW/vKtEDdfNg4FYPzHWH61Ij3fjNfH4G5goRQLFQAAAAD//wAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP//////////AdBMV3cAAAAAABTwI3ri6Phg99eRJPxRPwEuWqqNIwAAAAAAAAQgULiTf8Xe8I+fPL2n5fCMcG7bgKuliAwAAAAAAAAAAAAgLV3lhgnUlw+1SPha0HqH20DgVONMyByVHKmVpY9nTbcgENdI7aG5xnuU0yROAhFndhiptLMp6JatkEMfn0gDS60g4sApmh5GZ3NRZlXwmmSx4WsleVMN5sSlnOVlTepFGA8="
	}
  }`)

var (
	Main     Net
	Maindata string
)

type netDisk struct {
	Version      uint32 `json:"version"`
	Hash         string `json:"hash"`
	PrevBlock    string `json:"prev_block"`
	MerkleRoot   string `json:"merkle_root"`
	WitnessRoot  string `json:"witness_root"`
	TreeRoot     string `json:"tree_root"`
	ReservedRoot string `json:"reserved_root"`
	Time         uint32 `json:"time"`
	Bits         string `json:"bits"`
	Nonce        uint32 `json:"nonce"`
	Mask         string `json:"mask"`
	ExtraNonce   string `json:"extra_nonce"`
	Height       uint32 `json:"height"`
	Magic        uint32 `json:"magic"`
	DataB64      string `json:"data_b64"`
}

type disk struct {
	Main netDisk `json:"main"`
}

// Net holds the parsed genesis info for a network.
type Net struct {
	Version      uint32
	Hash         string
	PrevBlock    string
	MerkleRoot   string
	WitnessRoot  string
	TreeRoot     string
	ReservedRoot string
	Time         uint32
	Bits         uint32
	Nonce        uint32
	Mask         string
	ExtraNonce   string
	Height       uint32
	Magic        uint32
	DataB64      string
}

func mustParseBits(s string) uint32 {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 32)
		if err != nil {
			panic("genesis: invalid hex bits: " + s)
		}
		return uint32(v)
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		panic("genesis: invalid decimal bits: " + s)
	}
	return uint32(v)
}

func init() {
	var d disk
	if err := json.Unmarshal(raw, &d); err != nil {
		panic("genesis: invalid embedded JSON: " + err.Error())
	}
	Main = Net{
		Version:      d.Main.Version,
		Hash:         strings.ToLower(d.Main.Hash),
		PrevBlock:    strings.ToLower(d.Main.PrevBlock),
		MerkleRoot:   strings.ToLower(d.Main.MerkleRoot),
		WitnessRoot:  strings.ToLower(d.Main.WitnessRoot),
		TreeRoot:     strings.ToLower(d.Main.TreeRoot),
		ReservedRoot: strings.ToLower(d.Main.ReservedRoot),
		Time:         d.Main.Time,
		Bits:         mustParseBits(d.Main.Bits),
		Nonce:        d.Main.Nonce,
		Mask:         strings.ToLower(d.Main.Mask),
		ExtraNonce:   strings.ToLower(d.Main.ExtraNonce),
		Height:       d.Main.Height,
		Magic:        d.Main.Magic,
	}
	Maindata = d.Main.DataB64
}
