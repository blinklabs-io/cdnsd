// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"encoding/binary"
	"errors"
	"io"
)

type Transaction struct {
	Version  uint32
	Inputs   []TransactionInput
	Outputs  []TransactionOutput
	LockTime uint32
}

func (t *Transaction) Decode(r io.Reader) error {
	var err error
	if err = binary.Read(r, binary.LittleEndian, &t.Version); err != nil {
		return err
	}
	// Inputs
	inCount, err := binary.ReadUvarint(r.(io.ByteReader))
	if err != nil {
		return err
	}
	for i := uint64(0); i < inCount; i++ {
		var tmpInput TransactionInput
		if err := tmpInput.Decode(r); err != nil {
			return err
		}
		t.Inputs = append(t.Inputs, tmpInput)
	}
	// Outputs
	outCount, err := binary.ReadUvarint(r.(io.ByteReader))
	if err != nil {
		return err
	}
	for i := uint64(0); i < outCount; i++ {
		var tmpOutput TransactionOutput
		if err := tmpOutput.Decode(r); err != nil {
			return err
		}
		t.Outputs = append(t.Outputs, tmpOutput)
	}
	// Lock time
	if err := binary.Read(r, binary.LittleEndian, &t.LockTime); err != nil {
		return err
	}
	// Witnesses
	for i := uint64(0); i < inCount; i++ {
		if err := t.Inputs[i].DecodeWitness(r); err != nil {
			return err
		}
	}
	return nil
}

type TransactionInput struct {
	PrevOutpoint Outpoint
	Sequence     uint32
	Witness      [][]byte
}

func (i *TransactionInput) Decode(r io.Reader) error {
	if err := i.PrevOutpoint.Decode(r); err != nil {
		return err
	}
	if err := binary.Read(r, binary.LittleEndian, &i.Sequence); err != nil {
		return err
	}
	return nil
}

func (i *TransactionInput) DecodeWitness(r io.Reader) error {
	witnessCount, err := binary.ReadUvarint(r.(io.ByteReader))
	if err != nil {
		return err
	}
	i.Witness = make([][]byte, witnessCount)
	for j := uint64(0); j < witnessCount; j++ {
		itemLength, err := binary.ReadUvarint(r.(io.ByteReader))
		if err != nil {
			return err
		}
		i.Witness[j] = make([]byte, itemLength)
		if err := binary.Read(r, binary.LittleEndian, &i.Witness[j]); err != nil {
			return err
		}
	}
	return nil
}

type TransactionOutput struct {
	Value    uint64
	Address  Address
	Covenant GenericCovenant
}

func (o *TransactionOutput) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &o.Value); err != nil {
		return err
	}
	if err := o.Address.Decode(r); err != nil {
		return err
	}
	if err := o.Covenant.Decode(r); err != nil {
		return err
	}
	return nil
}

type Outpoint struct {
	Hash  [32]byte
	Index uint32
}

func (o *Outpoint) Decode(r io.Reader) error {
	return binary.Read(r, binary.LittleEndian, o)
}

type Address struct {
	Version uint8
	Hash    []byte
}

func (a *Address) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &a.Version); err != nil {
		return err
	}
	if a.Version > 31 {
		return errors.New("bad address program version")
	}
	var hashSize uint8
	if err := binary.Read(r, binary.LittleEndian, &hashSize); err != nil {
		return err
	}
	if hashSize < 2 || hashSize > 40 {
		return errors.New("invalid address hash size")
	}
	if a.Version == 0 {
		if hashSize != 20 && hashSize != 32 {
			return errors.New("witness program hash is the wrong size")
		}
	}
	a.Hash = make([]byte, hashSize)
	if err := binary.Read(r, binary.LittleEndian, &a.Hash); err != nil {
		return err
	}
	return nil
}
