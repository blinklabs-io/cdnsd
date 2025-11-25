// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

type Network struct {
	Name        string
	Magic       uint32
	GenesisHash string
}

var NetworkMainnet = Network{
	Name:        "mainnet",
	Magic:       1533997779,
	GenesisHash: "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
}
