// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"

	"golang.org/x/crypto/blake2b"
)

const (
	ProofTypeDeadend   uint8 = 0
	ProofTypeShort     uint8 = 1
	ProofTypeCollision uint8 = 2
	ProofTypeExists    uint8 = 3
	ProofTypeUnknown   uint8 = 4
)

var (
	ProofSkip     = []byte{0x02}
	ProofInternal = []byte{0x01}
	ProofLeaf     = []byte{0x00}
)

type ProofNode struct {
	Prefix     []byte
	PrefixSize uint16
	Node       []byte
}

func (n *ProofNode) UnmarshalJSON(data []byte) error {
	var tmpData []string
	if err := json.Unmarshal(data, &tmpData); err != nil {
		return err
	}
	tmpDataPrefix, tmpDataNode := tmpData[0], tmpData[1]
	tmpPrefix, prefixSize, err := decodePrefixFromString(tmpDataPrefix)
	if err != nil {
		return err
	}
	n.Prefix = tmpPrefix
	n.PrefixSize = prefixSize
	node, err := hex.DecodeString(tmpDataNode)
	if err != nil {
		return err
	}
	n.Node = node
	return nil
}

type Proof struct {
	Type       uint8
	Depth      uint16
	Nodes      []ProofNode
	Prefix     []byte
	PrefixSize uint16
	Left       []byte
	Right      []byte
	NxKey      []byte
	NxHash     []byte
	Value      []byte
}

func NewProofFromJson(data []byte) (*Proof, error) {
	var ret Proof
	if err := json.Unmarshal(data, &ret); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (p *Proof) Decode(r *bytes.Buffer) error {
	var field uint16
	if err := binary.Read(r, binary.LittleEndian, &field); err != nil {
		return err
	}
	// Highest 2 bits are the type
	p.Type = uint8(field >> 14) // nolint:gosec
	// Depth is everything except the highest 2 bytes
	p.Depth = field & ^uint16(3<<14)
	if p.Depth > 256 {
		return errors.New("proof depth too large")
	}
	var count uint16
	if err := binary.Read(r, binary.LittleEndian, &count); err != nil {
		return err
	}
	if count > 256 {
		return errors.New("count too large")
	}
	bitMapSize := (count + 7) / 8
	bitMap := make([]byte, bitMapSize)
	if err := binary.Read(r, binary.LittleEndian, &bitMap); err != nil {
		return err
	}
	p.Nodes = make([]ProofNode, count)
	for i := range int(count) {
		item := &ProofNode{}
		if hasBit(bitMap, i) {
			bits, bytes, err := readBitlen(r)
			if err != nil {
				return err
			}
			item.PrefixSize = bits
			item.Prefix = make([]byte, bytes)
			if err := binary.Read(r, binary.LittleEndian, &item.Prefix); err != nil {
				return err
			}
		}
		item.Node = make([]byte, 32)
		if err := binary.Read(r, binary.LittleEndian, &item.Node); err != nil {
			return err
		}
	}
	switch p.Type {
	case ProofTypeDeadend:
		// Do nothing
	case ProofTypeShort:
		bits, bytes, err := readBitlen(r)
		if err != nil {
			return err
		}
		p.Prefix = make([]byte, bytes)
		p.PrefixSize = bits
		if err := binary.Read(r, binary.LittleEndian, &p.Prefix); err != nil {
			return err
		}
		p.Left = make([]byte, 32)
		if err := binary.Read(r, binary.LittleEndian, &p.Left); err != nil {
			return err
		}
		p.Right = make([]byte, 32)
		if err := binary.Read(r, binary.LittleEndian, &p.Right); err != nil {
			return err
		}
	case ProofTypeCollision:
		p.NxKey = make([]byte, 32)
		if err := binary.Read(r, binary.LittleEndian, &p.NxKey); err != nil {
			return err
		}
		p.NxHash = make([]byte, 32)
		if err := binary.Read(r, binary.LittleEndian, &p.NxHash); err != nil {
			return err
		}
	case ProofTypeExists:
		var valSize uint16
		if err := binary.Read(r, binary.LittleEndian, &valSize); err != nil {
			return err
		}
		p.Value = make([]byte, valSize)
		if err := binary.Read(r, binary.LittleEndian, &p.Value); err != nil {
			return err
		}
	default:
		return errors.New("unknown proof type")
	}
	return nil
}

func (p *Proof) UnmarshalJSON(data []byte) error {
	var tmpData struct {
		Type   string      `json:"type"`
		Depth  uint16      `json:"depth"`
		Nodes  []ProofNode `json:"nodes"`
		Prefix string      `json:"prefix"`
		Left   string      `json:"left"`
		Right  string      `json:"right"`
		Key    string      `json:"key"`
		Hash   string      `json:"hash"`
		Value  string      `json:"value"`
	}
	var err error
	if err = json.Unmarshal(data, &tmpData); err != nil {
		return err
	}
	switch tmpData.Type {
	case "TYPE_DEADEND":
		p.Type = ProofTypeDeadend
	case "TYPE_SHORT":
		p.Type = ProofTypeShort
	case "TYPE_COLLISION":
		p.Type = ProofTypeCollision
	case "TYPE_EXISTS":
		p.Type = ProofTypeExists
	default:
		p.Type = ProofTypeUnknown
	}
	p.Depth = tmpData.Depth
	p.Nodes = tmpData.Nodes
	tmpPrefix, prefixSize, err := decodePrefixFromString(tmpData.Prefix)
	if err != nil {
		return err
	}
	p.Prefix = tmpPrefix
	p.PrefixSize = prefixSize
	p.Left, err = hex.DecodeString(tmpData.Left)
	if err != nil {
		return err
	}
	p.Right, err = hex.DecodeString(tmpData.Right)
	if err != nil {
		return err
	}
	p.NxKey, err = hex.DecodeString(tmpData.Key)
	if err != nil {
		return err
	}
	p.NxHash, err = hex.DecodeString(tmpData.Hash)
	if err != nil {
		return err
	}
	p.Value, err = hex.DecodeString(tmpData.Value)
	if err != nil {
		return err
	}
	return nil
}

func (p *Proof) hashInternal(
	prefix []byte,
	prefixSize uint16,
	left []byte,
	right []byte,
) []byte {
	h, _ := blake2b.New256(nil)
	if len(prefix) == 0 {
		h.Write(ProofInternal)
		h.Write(left)
		h.Write(right)
	} else {
		size := make([]byte, 2)
		binary.LittleEndian.PutUint16(size, prefixSize)
		h.Write(ProofSkip)
		h.Write(size)
		h.Write(prefix)
		h.Write(left)
		h.Write(right)
	}
	return h.Sum(nil)
}

func (p *Proof) hashLeaf(key []byte, hash []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(ProofLeaf)
	h.Write(key)
	h.Write(hash)
	return h.Sum(nil)
}

func (p *Proof) hashValue(key []byte, value []byte) []byte {
	h, _ := blake2b.New256(nil)
	h.Write(value)
	tmpSum := h.Sum(nil)
	return p.hashLeaf(key, tmpSum)
}

func (p *Proof) has(
	prefix []byte,
	prefixSize uint16,
	key []byte,
	depth uint16,
) bool {
	tmpLen := min(
		prefixSize,
		uint16(256-depth),
	)
	x := 0
	y := depth
	var c uint16
	for range int(tmpLen) {
		if hasBit(prefix, int(x)) != hasBit(key, int(y)) {
			break
		}
		x += 1
		y += 1
		c += 1
	}
	return c == prefixSize
}

func (p *Proof) parseNamestate(data []byte) ([]byte, error) {
	r := bytes.NewBuffer(data)
	var nameSize uint8
	if err := binary.Read(r, binary.LittleEndian, &nameSize); err != nil {
		return nil, err
	}
	name := make([]byte, nameSize)
	if err := binary.Read(r, binary.LittleEndian, &name); err != nil {
		return nil, err
	}
	var resSize uint16
	if err := binary.Read(r, binary.LittleEndian, &resSize); err != nil {
		return nil, err
	}
	res := make([]byte, nameSize)
	if err := binary.Read(r, binary.LittleEndian, &res); err != nil {
		return nil, err
	}
	return res, nil
}

func (p *Proof) Verify(
	root []byte,
	key []byte,
) ([]byte, error) {
	// Recreate the leaf
	leaf := make([]byte, 32)
	switch p.Type {
	case ProofTypeDeadend:
		// Do nothing
	case ProofTypeShort:
		if p.has(p.Prefix, p.PrefixSize, key, p.Depth) {
			return nil, errors.New("same path")
		}
		copy(
			leaf,
			p.hashInternal(p.Prefix, p.PrefixSize, p.Left, p.Right),
		)
	case ProofTypeCollision:
		if string(p.NxKey) == string(key) {
			return nil, errors.New("same key")
		}
		copy(leaf, p.hashLeaf(p.NxKey, p.NxHash))
	case ProofTypeExists:
		copy(leaf, p.hashValue(key, p.Value))
	default:
		return nil, errors.New("unknown proof type")
	}
	next := leaf
	depth := p.Depth
	for i := len(p.Nodes) - 1; i >= 0; i-- {
		item := &p.Nodes[i]
		if p.Depth < item.PrefixSize+1 {
			return nil, errors.New("negative depth")
		}
		depth -= 1
		if hasBit(key, int(depth)) {
			copy(
				next,
				p.hashInternal(item.Prefix, item.PrefixSize, item.Node, next),
			)
		} else {
			copy(next, p.hashInternal(item.Prefix, item.PrefixSize, next, item.Node))
		}
		depth -= item.PrefixSize
		if !p.has(item.Prefix, item.PrefixSize, key, depth) {
			return nil, errors.New("path mismatch")
		}
	}
	if depth != 0 {
		return nil, errors.New("too deep")
	}
	if string(next) != string(root) {
		return nil, errors.New("hash mismatch")
	}
	if p.Type == ProofTypeExists {
		ret, err := p.parseNamestate(p.Value)
		if err != nil {
			return nil, err
		}
		return ret, nil
	}
	return nil, nil
}

func hasBit(bitMap []byte, bitPos int) bool {
	// Determine byte within bitmap for the desired bit
	bytePos := bitPos / 8
	// Determine bit position within byte
	byteBitPos := 7 - (bitPos & 7)
	// Extract bit value
	bitVal := bitMap[bytePos] >> byteBitPos
	// Check if lower bit is set
	return (bitVal & 1) > 0
}

func readBitlen(r *bytes.Buffer) (uint16, int, error) {
	var tmpByte byte
	if err := binary.Read(r, binary.LittleEndian, &tmpByte); err != nil {
		return 0, 0, err
	}
	size := uint16(tmpByte)
	if size&0x80 > 0 {
		size &= ^uint16(0x80)
		size <<= 8
		if err := binary.Read(r, binary.LittleEndian, &tmpByte); err != nil {
			return 0, 0, err
		}
		size |= uint16(tmpByte)
	}
	if size == 0 || size > 256 {
		return 0, 0, errors.New("invalid size")
	}
	retBytes := (size + 7) / 8
	return size, int(retBytes), nil
}

func decodePrefixFromString(prefix string) ([]byte, uint16, error) {
	if len(prefix) == 0 {
		return []byte{}, 0, nil
	}
	if len(prefix) > math.MaxUint16 {
		return nil, 0, errors.New("prefix is too large")
	}
	prefixSize := uint16(len(prefix)) // nolint:gosec
	// Pad out the prefix with zeroes
	if prefixSize < 8 {
		prefix = fmt.Sprintf("%08s", prefix)
	} else if prefixSize < 16 {
		prefix = fmt.Sprintf("%016s", prefix)
	}
	// Reverse the prefix string
	prefixSlice := []byte(prefix)
	slices.Reverse(prefixSlice)
	prefix = string(prefixSlice)
	// Decode binary
	var tmpPrefix []byte
	for i := len(prefix); i > 0; i -= 8 {
		var bitgroup string
		if i-8 < 0 {
			bitgroup = string(prefix[0:i])
		} else {
			bitgroup = string(prefix[i-8 : i])
		}
		tmpByte, err := strconv.ParseUint(bitgroup, 2, 8)
		if err != nil {
			return nil, 0, err
		}
		tmpPrefix = append(
			[]byte{byte(tmpByte)},
			tmpPrefix...,
		)
	}
	return tmpPrefix, prefixSize, nil
}
