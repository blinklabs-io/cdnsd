// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"fmt"
	"math/big"
)

// CompactToTarget converts a Bitcoin compact (nBits) value to a
// 256-bit target. The first byte is the exponent, the next 3
// bytes are the mantissa. Target = mantissa * 2^(8*(exp-3)).
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

// ValidatePoW checks that the block hash satisfies the
// proof-of-work target derived from the header Bits field.
// The block hash (big-endian) must be <= target.
func (b *Block) ValidatePoW() error {
	target := CompactToTarget(b.Header.Bits)
	hash := b.Hash()
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
