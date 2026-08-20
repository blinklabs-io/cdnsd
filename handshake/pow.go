// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"errors"
	"fmt"
	"math/big"
)

var (
	errCompactTargetZero         = errors.New("compact target is zero")
	errCompactTargetNegative     = errors.New("compact target is negative")
	errCompactTargetOverflow     = errors.New("compact target exceeds 256 bits")
	errCompactTargetNonCanonical = errors.New("compact target is not canonical")
)

// CompactToTarget converts a Bitcoin compact (nBits) value to a
// 256-bit target. The first byte is the exponent, the next 3
// bytes are the mantissa. Target = mantissa * 2^(8*(exp-3)).
//
// This function retains the permissive conversion behavior for callers that
// need to inspect an encoded value. Consensus-sensitive code must use
// CompactToTargetChecked instead.
func CompactToTarget(bits uint32) *big.Int {
	exp := bits >> 24
	mantissa := bits & 0x007fffff
	target := new(big.Int).SetUint64(uint64(mantissa))
	if exp <= 3 {
		target.Rsh(target, uint(8*(3-exp)))
	} else {
		target.Lsh(target, uint(8*(exp-3)))
	}
	return target
}

// CompactToTargetChecked converts a compact target and rejects encodings that
// cannot be used for proof-of-work. Handshake's consensus verifier accepts
// positive targets that fit in 256 bits; it does not accept a negative, zero,
// overflowing, or non-canonical encoding.
//
// Rejecting non-canonical encodings is stricter than hsd's decode-side rules,
// which accept any compact form that decodes to a usable target. It cannot
// reject a real block: the retarget algorithm computes a target and encodes it,
// and that encoding is canonical by construction, so no honestly-produced
// header carries a non-canonical Bits value. The stricter rule only removes
// encoding freedom from a peer feeding us fabricated headers.
func CompactToTargetChecked(bits uint32) (*big.Int, error) {
	if bits&0x00800000 != 0 {
		return nil, errCompactTargetNegative
	}
	mantissa := bits & 0x007fffff
	if mantissa == 0 {
		return nil, errCompactTargetZero
	}
	target := CompactToTarget(bits)
	if target.Sign() <= 0 {
		return nil, errCompactTargetZero
	}
	if target.BitLen() > 256 {
		return nil, errCompactTargetOverflow
	}
	if targetToCompact(target) != bits {
		return nil, errCompactTargetNonCanonical
	}
	return target, nil
}

// targetToCompact returns the canonical compact representation used by
// Handshake for a positive target.
func targetToCompact(target *big.Int) uint32 {
	if target.Sign() <= 0 {
		return 0
	}

	exponent := (target.BitLen() + 7) / 8
	compact := new(big.Int).Set(target)
	if exponent <= 3 {
		compact.Lsh(compact, uint(8*(3-exponent)))
	} else {
		compact.Rsh(compact, uint(8*(exponent-3)))
	}
	mantissaValue := compact.Uint64()
	if mantissaValue > uint64(^uint32(0)) || exponent > 0xff {
		return 0
	}
	mantissa := uint32(mantissaValue) // #nosec G115 -- explicitly bounded above.
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		exponent++
	}
	return uint32(exponent)<<24 | (mantissa & 0x007fffff) // #nosec G115 -- exponent is bounded above.
}

// ValidatePoW checks that the block hash satisfies the proof-of-work target
// derived from the header Bits field. The block hash (big-endian) must be <=
// target.
func (h *BlockHeader) ValidatePoW() error {
	if h == nil {
		return errors.New("cannot validate PoW for nil block header")
	}
	target, err := CompactToTargetChecked(h.Bits)
	if err != nil {
		return fmt.Errorf("invalid compact target 0x%08x: %w", h.Bits, err)
	}
	hash := h.Hash()
	hashInt := new(big.Int).SetBytes(hash[:])
	if hashInt.Cmp(target) > 0 {
		return fmt.Errorf(
			"block PoW hash %x exceeds target %x",
			hash,
			target.Bytes(),
		)
	}
	return nil
}

// ValidatePoW checks that the block hash satisfies the
// proof-of-work target derived from the header Bits field.
// The block hash (big-endian) must be <= target.
func (b *Block) ValidatePoW() error {
	if b == nil {
		return errors.New("cannot validate PoW for nil block")
	}
	return b.Header.ValidatePoW()
}
