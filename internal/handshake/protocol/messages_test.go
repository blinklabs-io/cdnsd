// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package protocol

import (
	"encoding/hex"
	"net"
	"reflect"
	"testing"
)

func TestMsgVersionEncodeDecode(t *testing.T) {
	testDefs := []struct {
		message   Message
		binaryHex string
	}{
		// Captured from hsd
		{
			binaryHex: "030000000100000000000000e690136900000000e69013690000000000000000000000000000000000000000000000ffff60e6a250000000000000000000000000000000000000000046c40000000000000000000000000000000000000000000000000000000000000000002de918cb7d2b6e6e0b2f6873643a382e302e302f1ca0040000",
			message: &MsgVersion{
				Version:  0x3,
				Services: 0x1,
				Time:     0x691390e6,
				Remote: NetAddress{
					Time:     0x691390e6,
					Services: 0x0,
					Host:     net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x60, 0xe6, 0xa2, 0x50},
					Port:     0x46c4,
					Key:      [33]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}},
				Nonce:   [8]uint8{0x2d, 0xe9, 0x18, 0xcb, 0x7d, 0x2b, 0x6e, 0x6e},
				Agent:   "/hsd:8.0.0/",
				Height:  0x4a01c,
				NoRelay: false,
			},
		},
		// Captured from our own Version message
		{
			binaryHex: "0100000000000000000000003f9e1369000000003f9e13690000000000000000000000000000000000000000000000ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000054990d22ec7e7401072f63646e73642f0000000001",
			message: &MsgVersion{
				Version:  1,
				Services: 0,
				Time:     0x69139e3f,
				Remote: NetAddress{
					Time:     0x69139e3f,
					Services: 0,
					Host:     net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0},
					Port:     0,
				},
				Nonce:   [8]byte{0x54, 0x99, 0xd, 0x22, 0xec, 0x7e, 0x74, 0x1},
				Agent:   "/cdnsd/",
				Height:  0,
				NoRelay: true,
			},
		},
	}
	for _, testDef := range testDefs {
		binaryData, err := hex.DecodeString(testDef.binaryHex)
		if err != nil {
			t.Fatalf("unexpected error decoding hex: %s", err)
		}
		testMsg := new(MsgVersion)
		if err := testMsg.Decode(binaryData); err != nil {
			t.Fatalf("unexpected error decoding message: %s", err)
		}
		if !reflect.DeepEqual(testMsg, testDef.message) {
			t.Fatalf("did not get expected message after decode:\n     got: %#v\n  wanted: %#v", testMsg, testDef.message)
		}
		testEncoded := testMsg.Encode()
		testEncodedHex := hex.EncodeToString(testEncoded)
		if testEncodedHex != testDef.binaryHex {
			t.Fatalf("did not get expected binary hex after encode:\n     got: %s\n  wanted: %s", testEncodedHex, testDef.binaryHex)
		}
	}
}

func TestMsgAddrEncodeDecode(t *testing.T) {
	testDefs := []struct {
		message   Message
		binaryHex string
	}{
		// Modified (truncated) from data captured from hsd
		{
			binaryHex: "015757fc680000000003000000000000000000000000000000000000ffff2d4f5fe40000000000000000000000000000000000000000062f000000000000000000000000000000000000000000000000000000000000000000",
			message: &MsgAddr{
				Peers: []NetAddress{
					{
						Time:     0x68fc5757,
						Services: 0x3,
						Host:     net.IP{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x2d, 0x4f, 0x5f, 0xe4},
						Port:     0x62f,
					},
				},
			},
		},
	}
	for _, testDef := range testDefs {
		binaryData, err := hex.DecodeString(testDef.binaryHex)
		if err != nil {
			t.Fatalf("unexpected error decoding hex: %s", err)
		}
		testMsg := new(MsgAddr)
		if err := testMsg.Decode(binaryData); err != nil {
			t.Fatalf("unexpected error decoding message: %s", err)
		}
		if !reflect.DeepEqual(testMsg, testDef.message) {
			t.Fatalf("did not get expected message after decode:\n     got: %#v\n  wanted: %#v", testMsg, testDef.message)
		}
		testEncoded := testMsg.Encode()
		testEncodedHex := hex.EncodeToString(testEncoded)
		if testEncodedHex != testDef.binaryHex {
			t.Fatalf("did not get expected binary hex after encode:\n     got: %s\n  wanted: %s", testEncodedHex, testDef.binaryHex)
		}
	}
}
