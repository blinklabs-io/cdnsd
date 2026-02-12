// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"encoding/binary"
	"errors"
	"fmt"
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
	case CovenantTypeNone:
		ret, err := NewNoneCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf("can't convert generic covenant to None: %s", err),
			)
		}
		return ret
	case CovenantTypeClaim:
		ret, err := NewClaimCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf("can't convert generic covenant to Claim: %s", err),
			)
		}
		return ret
	case CovenantTypeOpen:
		ret, err := NewOpenCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf("can't convert generic covenant to Open: %s", err),
			)
		}
		return ret
	case CovenantTypeBid:
		ret, err := NewBidCovenantFromGeneric(c)
		if err != nil {
			panic(fmt.Sprintf("can't convert generic covenant to Bid: %s", err))
		}
		return ret
	case CovenantTypeReveal:
		ret, err := NewRevealCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf(
					"can't convert generic covenant to Reveal: %s",
					err,
				),
			)
		}
		return ret
	case CovenantTypeRedeem:
		ret, err := NewRedeemCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf(
					"can't convert generic covenant to Redeem: %s",
					err,
				),
			)
		}
		return ret
	case CovenantTypeRegister:
		ret, err := NewRegisterCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf(
					"can't convert generic covenant to Register: %s",
					err,
				),
			)
		}
		return ret
	case CovenantTypeUpdate:
		ret, err := NewUpdateCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf(
					"can't convert generic covenant to Update: %s",
					err,
				),
			)
		}
		return ret
	case CovenantTypeRenew:
		ret, err := NewRenewCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf("can't convert generic covenant to Renew: %s", err),
			)
		}
		return ret
	case CovenantTypeTransfer:
		ret, err := NewTransferCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf(
					"can't convert generic covenant to Transfer: %s",
					err,
				),
			)
		}
		return ret
	case CovenantTypeFinalize:
		ret, err := NewFinalizeCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf(
					"can't convert generic covenant to Finalize: %s",
					err,
				),
			)
		}
		return ret
	case CovenantTypeRevoke:
		ret, err := NewRevokeCovenantFromGeneric(c)
		if err != nil {
			panic(
				fmt.Sprintf(
					"can't convert generic covenant to Revoke: %s",
					err,
				),
			)
		}
		return ret
	default:
		panic(fmt.Sprintf("unknown covenant type: %d", c.Type))
	}
}

type NoneCovenant struct{}

func (NoneCovenant) isCovenant() {}

func NewNoneCovenantFromGeneric(
	gc *GenericCovenant,
) (*NoneCovenant, error) {
	if gc.Type != CovenantTypeNone {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 0 {
		return nil, errors.New("incorrect items length")
	}
	ret := &NoneCovenant{}
	return ret, nil
}

type ClaimCovenant struct {
	NameHash     []byte
	Height       uint32
	RawName      string
	Flags        uint8
	CommitHash   []byte
	CommitHeight uint32
}

func (ClaimCovenant) isCovenant() {}

func NewClaimCovenantFromGeneric(
	gc *GenericCovenant,
) (*ClaimCovenant, error) {
	if gc.Type != CovenantTypeClaim {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 6 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 || len(gc.Items[5]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	if len(gc.Items[3]) != 1 {
		return nil, errors.New("incorrect length for uint8 value")
	}
	ret := &ClaimCovenant{
		NameHash:   make([]byte, len(gc.Items[0])),
		CommitHash: make([]byte, len(gc.Items[4])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.CommitHash, gc.Items[4])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	ret.CommitHeight = binary.LittleEndian.Uint32(gc.Items[5])
	// Flags
	ret.Flags = gc.Items[3][0]
	// Raw name
	ret.RawName = string(gc.Items[2])
	return ret, nil
}

type OpenCovenant struct {
	NameHash []byte
	RawName  string
}

func (OpenCovenant) isCovenant() {}

func NewOpenCovenantFromGeneric(
	gc *GenericCovenant,
) (*OpenCovenant, error) {
	if gc.Type != CovenantTypeOpen {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 3 {
		return nil, errors.New("incorrect items length")
	}
	ret := &OpenCovenant{
		NameHash: make([]byte, len(gc.Items[0])),
	}
	// Copy hash
	copy(ret.NameHash, gc.Items[0])
	// NOTE: purposely ignoring index 1, which always contains 0
	// Raw name
	ret.RawName = string(gc.Items[2])
	return ret, nil
}

type BidCovenant struct {
	NameHash []byte
	Height   uint32
	RawName  string
	Blind    []byte
}

func (BidCovenant) isCovenant() {}

func NewBidCovenantFromGeneric(
	gc *GenericCovenant,
) (*BidCovenant, error) {
	if gc.Type != CovenantTypeBid {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 4 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	ret := &BidCovenant{
		NameHash: make([]byte, len(gc.Items[0])),
		Blind:    make([]byte, len(gc.Items[3])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.Blind, gc.Items[3])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	// Raw name
	ret.RawName = string(gc.Items[2])
	return ret, nil
}

type RevealCovenant struct {
	NameHash []byte
	Height   uint32
	Nonce    []byte
}

func (RevealCovenant) isCovenant() {}

func NewRevealCovenantFromGeneric(
	gc *GenericCovenant,
) (*RevealCovenant, error) {
	if gc.Type != CovenantTypeReveal {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 3 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	ret := &RevealCovenant{
		NameHash: make([]byte, len(gc.Items[0])),
		Nonce:    make([]byte, len(gc.Items[2])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.Nonce, gc.Items[2])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	return ret, nil
}

type RedeemCovenant struct {
	NameHash []byte
	Height   uint32
}

func (RedeemCovenant) isCovenant() {}

func NewRedeemCovenantFromGeneric(
	gc *GenericCovenant,
) (*RedeemCovenant, error) {
	if gc.Type != CovenantTypeRedeem {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 2 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	ret := &RedeemCovenant{
		NameHash: make([]byte, len(gc.Items[0])),
	}
	// Copy hash
	copy(ret.NameHash, gc.Items[0])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	return ret, nil
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
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
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
	if len(gc.Items[2]) > 0 {
		tmpData, err := NewDomainResourceDataFromBytes(gc.Items[2])
		if err != nil {
			return nil, err
		}
		ret.ResourceData = *tmpData
	}
	return ret, nil
}

type UpdateCovenant struct {
	NameHash     []byte
	Height       uint32
	ResourceData DomainResourceData
}

func (UpdateCovenant) isCovenant() {}

func NewUpdateCovenantFromGeneric(
	gc *GenericCovenant,
) (*UpdateCovenant, error) {
	if gc.Type != CovenantTypeUpdate {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 3 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	ret := &UpdateCovenant{
		NameHash: make([]byte, len(gc.Items[0])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	// Decode resource data
	if len(gc.Items[2]) > 0 {
		tmpData, err := NewDomainResourceDataFromBytes(gc.Items[2])
		if err != nil {
			return nil, fmt.Errorf("decode domain resource data: %w", err)
		}
		ret.ResourceData = *tmpData
	}
	return ret, nil
}

type RenewCovenant struct {
	NameHash  []byte
	Height    uint32
	BlockHash []byte
}

func (RenewCovenant) isCovenant() {}

func NewRenewCovenantFromGeneric(
	gc *GenericCovenant,
) (*RenewCovenant, error) {
	if gc.Type != CovenantTypeRenew {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 3 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	ret := &RenewCovenant{
		NameHash:  make([]byte, len(gc.Items[0])),
		BlockHash: make([]byte, len(gc.Items[2])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.BlockHash, gc.Items[2])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	return ret, nil
}

type TransferCovenant struct {
	NameHash    []byte
	Height      uint32
	AddrVersion uint8
	AddrHash    []byte
}

func (TransferCovenant) isCovenant() {}

func NewTransferCovenantFromGeneric(
	gc *GenericCovenant,
) (*TransferCovenant, error) {
	if gc.Type != CovenantTypeTransfer {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 4 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	if len(gc.Items[2]) != 1 {
		return nil, errors.New("incorrect length for uint8 value")
	}
	ret := &TransferCovenant{
		NameHash: make([]byte, len(gc.Items[0])),
		AddrHash: make([]byte, len(gc.Items[3])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.AddrHash, gc.Items[3])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	// Address version
	ret.AddrVersion = gc.Items[2][0]
	return ret, nil
}

type FinalizeCovenant struct {
	NameHash  []byte
	Height    uint32
	RawName   string
	Flags     uint8
	Claimed   uint32
	Renewals  uint32
	BlockHash []byte
}

func (FinalizeCovenant) isCovenant() {}

func NewFinalizeCovenantFromGeneric(
	gc *GenericCovenant,
) (*FinalizeCovenant, error) {
	if gc.Type != CovenantTypeFinalize {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 7 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 || len(gc.Items[4]) != 4 || len(gc.Items[5]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	if len(gc.Items[3]) != 1 {
		return nil, errors.New("incorrect length for uint8 value")
	}
	ret := &FinalizeCovenant{
		NameHash:  make([]byte, len(gc.Items[0])),
		BlockHash: make([]byte, len(gc.Items[6])),
	}
	// Copy hashes
	copy(ret.NameHash, gc.Items[0])
	copy(ret.BlockHash, gc.Items[6])
	// Decode height and other values from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	ret.Claimed = binary.LittleEndian.Uint32(gc.Items[4])
	ret.Renewals = binary.LittleEndian.Uint32(gc.Items[5])
	// Flags
	ret.Flags = gc.Items[3][0]
	// Raw name
	ret.RawName = string(gc.Items[2])
	return ret, nil
}

type RevokeCovenant struct {
	NameHash []byte
	Height   uint32
}

func (RevokeCovenant) isCovenant() {}

func NewRevokeCovenantFromGeneric(
	gc *GenericCovenant,
) (*RevokeCovenant, error) {
	if gc.Type != CovenantTypeRevoke {
		return nil, errors.New("wrong covenant type")
	}
	if len(gc.Items) != 2 {
		return nil, errors.New("incorrect items length")
	}
	if len(gc.Items[1]) != 4 {
		return nil, errors.New("incorrect length for uint32 value")
	}
	ret := &RevokeCovenant{
		NameHash: make([]byte, len(gc.Items[0])),
	}
	// Copy hash
	copy(ret.NameHash, gc.Items[0])
	// Decode height from bytes
	ret.Height = binary.LittleEndian.Uint32(gc.Items[1])
	return ret, nil
}
