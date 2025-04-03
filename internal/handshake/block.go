// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"encoding/binary"
	"io"
)

type Block struct {
	Header       BlockHeader
	Transactions []Transaction
}

func (b *Block) Decode(r io.Reader) error {
	// Decode header
	if err := b.Header.Decode(r); err != nil {
		return err
	}
	// Transactions
	txCount, err := binary.ReadUvarint(r.(io.ByteReader))
	if err != nil {
		return err
	}
	for i := uint64(0); i < txCount; i++ {
		var tmpTx Transaction
		if err := tmpTx.Decode(r); err != nil {
			return err
		}
		b.Transactions = append(b.Transactions, tmpTx)
	}
	return nil
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

func (h *BlockHeader) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, h); err != nil {
		return err
	}
	return nil
}
