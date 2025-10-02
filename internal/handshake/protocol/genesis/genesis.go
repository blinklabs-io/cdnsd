package genesis

import (
	"encoding/json"
	"strconv"
	"strings"
)

var raw []byte

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

var Main Net
var Maindata string

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
