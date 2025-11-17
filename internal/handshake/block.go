// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"bytes"
	"crypto/sha3"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/blake2b"
)

const (
	BlockHeaderSize = 236
)

type Block struct {
	Header       BlockHeader
	Transactions []Transaction
}

func NewBlockFromReader(r io.Reader) (*Block, error) {
	// Read entire input into a bytes.Buffer
	tmpData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(tmpData)
	// Decode block
	var tmpBlock Block
	if err := tmpBlock.Decode(buf); err != nil {
		return nil, err
	}
	return &tmpBlock, err
}

func (b *Block) Decode(r *bytes.Buffer) error {
	// Decode header
	if err := b.Header.Decode(r); err != nil {
		return err
	}
	// Transactions
	txCount, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for range txCount {
		var tmpTx Transaction
		if err := tmpTx.Decode(r); err != nil {
			return err
		}
		b.Transactions = append(b.Transactions, tmpTx)
	}
	return nil
}

func (b *Block) Hash() [32]byte {
	return b.Header.Hash()
}

type BlockHeader struct {
	Nonce        uint32
	Time         uint64
	PrevBlock    [32]byte
	NameRoot     [32]byte
	ExtraNonce   [24]byte
	ReservedRoot [32]byte
	WitnessRoot  [32]byte
	MerkleRoot   [32]byte
	Version      uint32
	Bits         uint32
	Mask         [32]byte
}

func NewBlockHeaderFromReader(r io.Reader) (*BlockHeader, error) {
	// Read entire input into a bytes.Buffer
	tmpData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(tmpData)
	// Decode block header
	var tmpBlockHeader BlockHeader
	if err := tmpBlockHeader.Decode(buf); err != nil {
		return nil, err
	}
	return &tmpBlockHeader, err
}

func (h *BlockHeader) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, h); err != nil {
		return err
	}
	return nil
}

func (h *BlockHeader) Encode() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, h)
	return buf.Bytes()
}

func (h *BlockHeader) Hash() [32]byte {
	return h.powHash()
}

func (h *BlockHeader) subhead() []byte {
	buf := new(bytes.Buffer)
	_, _ = buf.Write(h.ExtraNonce[:])
	_, _ = buf.Write(h.ReservedRoot[:])
	_, _ = buf.Write(h.WitnessRoot[:])
	_, _ = buf.Write(h.MerkleRoot[:])
	_ = binary.Write(buf, binary.LittleEndian, h.Version)
	_ = binary.Write(buf, binary.LittleEndian, h.Bits)
	return buf.Bytes()
}

func (h *BlockHeader) subHash() [32]byte {
	return blake2b.Sum256(h.subhead())
}

func (h *BlockHeader) maskHash() [32]byte {
	buf := new(bytes.Buffer)
	_, _ = buf.Write(h.PrevBlock[:])
	_, _ = buf.Write(h.Mask[:])
	return blake2b.Sum256(buf.Bytes())
}

func (h *BlockHeader) commitHash() [32]byte {
	buf := new(bytes.Buffer)
	subHash := h.subHash()
	_, _ = buf.Write(subHash[:])
	maskHash := h.maskHash()
	_, _ = buf.Write(maskHash[:])
	return blake2b.Sum256(buf.Bytes())
}

func (h *BlockHeader) prehead() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, h.Nonce)
	_ = binary.Write(buf, binary.LittleEndian, h.Time)
	_, _ = buf.Write(h.padding(20))
	_, _ = buf.Write(h.PrevBlock[:])
	_, _ = buf.Write(h.NameRoot[:])
	commitHash := h.commitHash()
	_, _ = buf.Write(commitHash[:])
	return buf.Bytes()
}

func (h *BlockHeader) shareHash() [32]byte {
	data := h.prehead()
	left := blake2b.Sum512(data)
	sha3Hasher := sha3.New256()
	_, _ = sha3Hasher.Write(data)
	_, _ = sha3Hasher.Write(h.padding(8))
	right := sha3Hasher.Sum(nil)
	finalHasher, _ := blake2b.New256(nil)
	_, _ = finalHasher.Write(left[:])
	_, _ = finalHasher.Write(h.padding(32))
	_, _ = finalHasher.Write(right[:])
	return [32]byte(finalHasher.Sum(nil))
}

func (h *BlockHeader) powHash() [32]byte {
	hash := h.shareHash()
	for i := range 32 {
		// nolint:gosec // This isn't actually an issue, but the latest gosec is giving false positives
		hash[i] ^= h.Mask[i]
	}
	return hash
}

func (h *BlockHeader) padding(size int) []byte {
	ret := make([]byte, size)
	for i := range size {
		ret[i] = h.PrevBlock[i%32] ^ h.NameRoot[i%32]
	}
	return ret
}
