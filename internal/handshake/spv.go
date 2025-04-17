// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"bytes"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"
)

/*
func VerifySpvProof(txHash []byte, block *MerkleBlock) error {
	fmt.Printf("block.Hashes = %#v\n", block.Hashes)
	tmpHashes := make([][]byte, len(block.Hashes))
	copy(tmpHashes, block.Hashes)
	if string(tmpHashes[0]) == string(txHash) {
		tmpHashes = slices.Delete(tmpHashes, 0, 1)
	}
	fmt.Printf("tmpHashes = %#v\n", tmpHashes)
	for i := 0; i < int(block.TxCount); i++ {
		proof := &merkletree.Proof{
			Hashes: tmpHashes,
			Index:  uint64(i),
		}
		fmt.Printf("proof = %#v\n", proof)
		ok, err := merkletree.VerifyProof(txHash, false, proof, [][]byte{block.Header.MerkleRoot[:]})
		fmt.Printf("ok = %v, err = %v\n", ok, err)
		if err != nil {
			return err
		}
		if ok {
			// Successfully verified proof
			return nil
		}
	}
	return errors.New("could not verify proof")
}
*/

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

func (p *Proof) Decode(r *bytes.Buffer) error {
	var field uint16
	if err := binary.Read(r, binary.LittleEndian, &field); err != nil {
		return err
	}
	p.Type = field >> 14
	p.Depth = field & ~(3 << 14)
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
	for i := 0; i < count; i++ {
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
}

func (p *Proof) hashInternal(prefix []byte, left []byte, right []byte) []byte {
	h := blake2b.New256(nil)
	if len(prefix) == 0 {
		h.Write(ProofInternal)
		h.Write(left)
		h.Write(right)
	} else {
		size := make([]byte, 2)
		binary.PutVarint(size, int64(p.PrefixSize))
		h.Write(ProofSkip)
		h.Write(size)
		h.Write(prefix)
		h.Write(left)
		h.Write(right)
	}
	return h.Sum(nil)
}

func (p *Proof) hashLeaf(key []byte, hash []byte) []byte {
	h := blake2b.New256(nil)
	h.Write(ProofLeaf)
	h.Write(key)
	h.Write(hash)
	return h.Sum(nil)
}

func (p *Proof) hashValue(key []byte, value []byte) []byte {
	h := blake2b.New256(nil)
	h.Write(value)
	tmpSum := h.Sum(nil)
	return p.hashLeaf(key, tmpSum)
}

func (p *Proof) has(prefix []byte, prefixSize uint16, key []byte, depth int) bool {
	tmpLen := min(
		prefixSize,
		256-depth,
	)
	x := 0
	y := depth
	c := 0
	for i := 0; i < tmpLen; i++ {
		if hasBit(prefix, x) != hasBit(key, y) {
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
		return nil, nerr
	}
	var resSize uint16
	if err := binary.Read(r, binary.LittleEndian, &resSize); err != nil {
		return nil, err
	}
	res := make([]byte, nameSize)
	if err := binary.Read(r, binary.LittleEndian, &res); err != nil {
		return nil, nerr
	}
	return res, nil
}

func (p *Proof) Verify(
	root []byte,
	key []byte,
) error {
	// Recreate the leaf
	leaf := make([]byte, 32)
	switch p.Type {
	case ProofTypeDeadend:
		// Do nothing
	case ProofTypeShort:
		if p.has(p.Prefix, p.PrefixSize, key, proof.Depth) {
			return errors.new("same path")
		}
		copy(leaf, p.hashInternal(proof.Prefix, proof.PrefixSize, proof.Left, proof.Right))
	case ProofTypeCollision:
		if string(p.NxKey) == string(key) {
			return errors.New("same key")
		}
		copy(leaf, p.hashLeaf(p.NxKey, p.NxHash))
	case ProofTypeExists:
		copy(leaf, p.hashValue(key, proof.Value))
	default:
		return errors.New("unknown proof type")
	}
	next := leaf
	for i := len(p.Nodes); i > 0; i-- {
		item := &p.Nodes[i]
		if p.Depth < node.PrefixSize+1 {
			return errors.New("negative depth")
		}
		depth -= 1
		if hasBit(key, depth) {
			copy(next, p.hashInternal(item.Prefix, item.PrefixSize, item.Node, next))
		} else {
			copy(next, p.hashInternal(item.Prefix, item.PrefixSize, next, item.Node))
		}
		depth -= item.PrefixSize
		if !p.has(item.Prefix, item.PrefixSize, key, depth) {
			return errors.New("path mismatch")
		}
	}
	if depth != 0 {
		return errors.New("too deep")
	}
	if string(next) != string(root) {
		return errors.New("hash mismatch")
	}
	if p.Type == ProofTypeExists {
		name, err := parseNamestate(p.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

func hasBit(bitMap []byte, bitPos int) bool {
	return bool(
		((bitMap[bitPos>>3] >> (7 - (bitPos & 7))) & 1),
	)
}

func readBitlen(r *bytes.Buffer) (uint16, int, error) {
	var tmpByte byte
	if err := binary.Read(r, binary.LittleEndian, &tmpByte); err != nil {
		return 0, 0, err
	}
	size := uint16(tmpByte)
	if size & 0x80 {
		size &= ~0x80
		size <<= 8
		if err := binary.Read(r, binary.LittleEndian, &tmpByte); err != nil {
			return 0, 0, err
		}
		size |= byte
	}
	if size == 0 || size > 256 {
		return 0, 0, errors.New("invalid size")
	}
	bytes = (size + 7) / 8
	return uint16(size), bytes, nil
}
