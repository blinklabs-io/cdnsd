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

// Covenant types
const (
	CovenantTypeNone     = 0
	CovenantTypeClaim    = 1
	CovenantTypeOpen     = 2
	CovenantTypeBid      = 3
	CovenantTypeReveal   = 4
	CovenantTypeRedeem   = 5
	CovenantTypeRegister = 6
	CovenantTypeUpdate   = 7
	CovenantTypeRenew    = 8
	CovenantTypeTransfer = 9
	CovenantTypeFinalize = 10
	CovenantTypeRevoke   = 11
)

type Covenant interface {
	isCovenant()
}

type GenericCovenant struct {
	Type  uint8
	Items [][]byte
}

func (*GenericCovenant) isCovenant() {}

func (c *GenericCovenant) Decode(r io.Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &c.Type); err != nil {
		return err
	}
	itemCount, err := ReadUvarintReader(r)
	if err != nil {
		return err
	}
	for range itemCount {
		itemLength, err := ReadUvarintReader(r)
		if err != nil {
			return err
		}
		item := make([]byte, itemLength)
		if err := binary.Read(r, binary.LittleEndian, &item); err != nil {
			return err
		}
		c.Items = append(c.Items, item)
	}
	return nil
}

func (c *GenericCovenant) Covenant() Covenant {
	switch c.Type {
	case CovenantTypeRegister:
		ret, err := NewRegisterCovenantFromGeneric(c)
		if err != nil {
			panic("can't convert generic covenant to Register")
		}
		return ret
	case CovenantTypeUpdate:
		ret, err := NewUpdateCovenantFromGeneric(c)
		if err != nil {
			panic("can't convert generic covenant to Update")
		}
		return ret
	}
	// Return generic covenant (ourselves)
	return c
}

type RegisterCovenant struct {
	NameHash     []byte
	Height       uint32
	ResourceData DomainResourceData
	BlockHash    []byte
}

func (RegisterCovenant) isCovenant() {}

func NewRegisterCovenantFromGeneric(
	gc *GenericCovenant,
) (*RegisterCovenant, error) {
	if gc.Type != CovenantTypeRegister {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 4 {
		return nil, errors.New("incorrect items length")
	}
	ret := &RegisterCovenant{
		NameHash:  make([]byte, len(gc.Items[0])),
		BlockHash: make([]byte, len(gc.Items[3])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.BlockHash, gc.Items[3])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	// Decode resource data
	tmpData, err := NewDomainResourceDataFromBytes(gc.Items[2])
	if err != nil {
		return nil, err
	}
	ret.ResourceData = *tmpData
	return ret, nil
}

type UpdateCovenant struct {
	NameHash     []byte
	Height       uint32
	ResourceData DomainResourceData
	BlockHash    []byte
}

func (UpdateCovenant) isCovenant() {}

func NewUpdateCovenantFromGeneric(
	gc *GenericCovenant,
) (*UpdateCovenant, error) {
	if gc.Type != CovenantTypeUpdate {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 4 {
		return nil, errors.New("incorrect items length")
	}
	ret := &UpdateCovenant{
		NameHash:  make([]byte, len(gc.Items[0])),
		BlockHash: make([]byte, len(gc.Items[3])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.BlockHash, gc.Items[3])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	// Decode resource data
	tmpData, err := NewDomainResourceDataFromBytes(gc.Items[2])
	if err != nil {
		return nil, err
	}
	ret.ResourceData = *tmpData
	return ret, nil
}
