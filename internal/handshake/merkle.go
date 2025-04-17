// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"bytes"
	"encoding/binary"
	"io"
)

type MerkleBlock struct {
	Header  BlockHeader
	TxCount uint32
	Hashes  [][]byte
	Flags   []byte
}

func NewMerkleBlockFromReader(r io.Reader) (*MerkleBlock, error) {
	// Read entire input into a bytes.Buffer
	tmpData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(tmpData)
	// Decode block
	var tmpBlock MerkleBlock
	if err := tmpBlock.Decode(buf); err != nil {
		return nil, err
	}
	return &tmpBlock, err
}

func (b *MerkleBlock) Decode(r *bytes.Buffer) error {
	// Decode header
	if err := b.Header.Decode(r); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &b.TxCount); err != nil {
		return err
	}
	hashCount, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for i := 0; i < int(hashCount); i++ { // nolint:gosec
		tmpHash := make([]byte, 32)
		if err := binary.Read(r, binary.LittleEndian, &tmpHash); err != nil {
			return err
		}
		b.Hashes = append(b.Hashes, tmpHash)
	}
	flagsSize, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	b.Flags = make([]byte, flagsSize)
	if err := binary.Read(r, binary.LittleEndian, &b.Flags); err != nil {
		return err
	}
	// TODO
	/*
	   this.totalTX = br.readU32();

	   const count = br.readVarint();

	   for (let i = 0; i < count; i++)
	     this.hashes.push(br.readHash());

	   this.flags = br.readVarBytes();
	*/
	/*
		// Transactions
		txCount, err := binary.ReadUvarint(r)
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
	*/
	return nil
}
