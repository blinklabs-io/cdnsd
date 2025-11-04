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
	"io"

	"golang.org/x/crypto/blake2b"
)

type Transaction struct {
	Version     uint32
	Inputs      []TransactionInput
	Outputs     []TransactionOutput
	LockTime    uint32
	hash        []byte
	witnessHash []byte
}

func NewTransactionFromReader(r io.Reader) (*Transaction, error) {
	// Read entire input into a bytes.Buffer
	tmpData, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(tmpData)
	// Decode TX
	var tmpTransaction Transaction
	if err := tmpTransaction.Decode(buf); err != nil {
		return nil, err
	}
	return &tmpTransaction, err
}

func (t *Transaction) Decode(r *bytes.Buffer) error {
	// Save original buffer
	// This is needed to capture TX bytes
	origData := make([]byte, r.Len())
	copy(origData, r.Bytes())
	// Version
	if err := binary.Read(r, binary.LittleEndian, &t.Version); err != nil {
		return err
	}
	// Inputs
	inCount, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for range inCount {
		var tmpInput TransactionInput
		if err := tmpInput.Decode(r); err != nil {
			return err
		}
		t.Inputs = append(t.Inputs, tmpInput)
	}
	// Outputs
	outCount, err := binary.ReadUvarint(r)
	if err != nil {
		return err
	}
	for range outCount {
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
	// Capture original TX bytes
	txBytes := origData[:len(origData)-r.Len()]
	// Generate TX hash
	tmpHash := blake2b.Sum256(txBytes)
	t.hash = make([]byte, len(tmpHash))
	copy(t.hash, tmpHash[:])
	// Save remaining data
	// This is needed for capturing the witness data bytes
	origData = make([]byte, r.Len())
	copy(origData, r.Bytes())
	// Witnesses
	for i := range inCount {
		if err := t.Inputs[i].DecodeWitness(r); err != nil {
			return err
		}
	}
	// Capture original bytes for witness data
	witnessDataBytes := origData[:len(origData)-r.Len()]
	// Generate witness data hash
	witnessDataHash := blake2b.Sum256(witnessDataBytes)
	// Generate TX hash with witness data
	h, err := blake2b.New256(nil)
	if err != nil {
		return err
	}
	h.Write(t.hash)
	h.Write(witnessDataHash[:])
	t.witnessHash = h.Sum(nil)
	return nil
}

func (t *Transaction) Hash() []byte {
	ret := make([]byte, len(t.hash))
	copy(ret, t.hash)
	return ret
}

func (t *Transaction) WitnessHash() []byte {
	ret := make([]byte, len(t.witnessHash))
	copy(ret, t.witnessHash)
	return ret
}

type TransactionInput struct {
	PrevOutpoint Outpoint
	Sequence     uint32
	Witness      [][]byte
}

func (i *TransactionInput) Decode(r *bytes.Buffer) error {
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
	for j := range witnessCount {
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

func (o *TransactionOutput) Decode(r *bytes.Buffer) error {
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

func (o *Outpoint) Decode(r *bytes.Buffer) error {
	return binary.Read(r, binary.LittleEndian, o)
}

type Address struct {
	Version uint8
	Hash    []byte
}

func (a *Address) Decode(r *bytes.Buffer) error {
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
