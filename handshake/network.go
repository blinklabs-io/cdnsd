// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import "math/big"

type Network struct {
	Name         string
	Magic        uint32
	GenesisHash  string
	PowLimit     *big.Int
	PowLimitBits uint32
}

var NetworkMainnet = Network{
	Name:         "mainnet",
	Magic:        1533997779,
	GenesisHash:  "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
	PowLimit:     CompactToTarget(0x1c00ffff),
	PowLimitBits: 0x1c00ffff,
}
