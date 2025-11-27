// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake_test

import (
	"net"
	"reflect"
	"testing"

	"github.com/blinklabs-io/cdnsd/internal/handshake"
)

func TestCovenantRegisterFromGeneric(t *testing.T) {
	// This data comes from mainnet TX 63ba84b6362724aa8fd484d3616c8d1bdea68240c8e0cd6a104fcf85a35d52fb
	testGenericCovenant := &handshake.GenericCovenant{
		Type: handshake.CovenantTypeRegister,
		Items: [][]byte{
			decodeHex(
				"62a90ce374b1499d0b67b1e4e6164b18acacbd16be905a6ffee593d48d4e0a82",
			),
			decodeHex("8d1e0400"),
			decodeHex(
				"0002036e73310a69727677696c6c69616d002ce706b701c00202036e7332c00636d688f601c01a00d5580d0114402ed0125506f35ba249265f39b988d7028a28c300d5580d02200c6c45064c26b529b4ac074dff5de60a99d6025d5b0d7f32c2b8c7d40ec8b3de00d5580d043071cb0417852b08b965413f3b871b033996159d121a585e35111a335d4cfb79b67e49a99c3829f6a1f42e100f7f33d7d9",
			),
			decodeHex(
				"0000000000000000153c62dbcabb762c254fb4104ab7cdd779926b79b34601fc",
			),
		},
	}
	expectedCovenant := &handshake.RegisterCovenant{
		NameHash: decodeHex(
			"62a90ce374b1499d0b67b1e4e6164b18acacbd16be905a6ffee593d48d4e0a82",
		),
		Height: 269965,
		ResourceData: handshake.DomainResourceData{
			Version: 0,
			Records: []handshake.DomainRecord{
				&handshake.Glue4DomainRecord{
					Name:    "ns1.irvwilliam.",
					Address: net.ParseIP("44.231.6.183").To4(),
				},
				&handshake.NsDomainRecord{
					Name: "ns1.irvwilliam.",
				},
				&handshake.Glue4DomainRecord{
					Name:    "ns2.irvwilliam.",
					Address: net.ParseIP("54.214.136.246").To4(),
				},
				&handshake.NsDomainRecord{
					Name: "ns2.irvwilliam.",
				},
				&handshake.DsDomainRecord{
					KeyTag:     54616,
					Algorithm:  13,
					DigestType: 1,
					Digest: decodeHex(
						"402ed0125506f35ba249265f39b988d7028a28c3",
					),
				},
				&handshake.DsDomainRecord{
					KeyTag:     54616,
					Algorithm:  13,
					DigestType: 2,
					Digest: decodeHex(
						"0c6c45064c26b529b4ac074dff5de60a99d6025d5b0d7f32c2b8c7d40ec8b3de",
					),
				},
				&handshake.DsDomainRecord{
					KeyTag:     54616,
					Algorithm:  13,
					DigestType: 4,
					Digest: decodeHex(
						"71cb0417852b08b965413f3b871b033996159d121a585e35111a335d4cfb79b67e49a99c3829f6a1f42e100f7f33d7d9",
					),
				},
			},
		},
		BlockHash: decodeHex(
			"0000000000000000153c62dbcabb762c254fb4104ab7cdd779926b79b34601fc",
		),
	}
	tmpCovenant, err := handshake.NewRegisterCovenantFromGeneric(
		testGenericCovenant,
	)
	if err != nil {
		t.Fatalf(
			"unexpected error creating RegisterCovenant from GenericCovenant: %s",
			err,
		)
	}
	if !reflect.DeepEqual(tmpCovenant, expectedCovenant) {
		t.Fatalf(
			"did not get expected covenant:\n     got: %#v\n  wanted: %#v",
			tmpCovenant,
			expectedCovenant,
		)
	}
}

func TestCovenantUpdateFromGeneric(t *testing.T) {
	// This data comes from mainnet TX 63ba84b6362724aa8fd484d3616c8d1bdea68240c8e0cd6a104fcf85a35d52fb
	testGenericCovenant := &handshake.GenericCovenant{
		Type: handshake.CovenantTypeUpdate,
		Items: [][]byte{
			decodeHex(
				"62a90ce374b1499d0b67b1e4e6164b18acacbd16be905a6ffee593d48d4e0a82",
			),
			decodeHex("8d1e0400"),
			decodeHex(
				"0002036e73310a69727677696c6c69616d002ce706b701c00202036e7332c00636d688f601c01a00d5580d0114402ed0125506f35ba249265f39b988d7028a28c300d5580d02200c6c45064c26b529b4ac074dff5de60a99d6025d5b0d7f32c2b8c7d40ec8b3de00d5580d043071cb0417852b08b965413f3b871b033996159d121a585e35111a335d4cfb79b67e49a99c3829f6a1f42e100f7f33d7d9",
			),
		},
	}
	expectedCovenant := &handshake.UpdateCovenant{
		NameHash: decodeHex(
			"62a90ce374b1499d0b67b1e4e6164b18acacbd16be905a6ffee593d48d4e0a82",
		),
		Height: 269965,
		ResourceData: handshake.DomainResourceData{
			Version: 0,
			Records: []handshake.DomainRecord{
				&handshake.Glue4DomainRecord{
					Name:    "ns1.irvwilliam.",
					Address: net.ParseIP("44.231.6.183").To4(),
				},
				&handshake.NsDomainRecord{
					Name: "ns1.irvwilliam.",
				},
				&handshake.Glue4DomainRecord{
					Name:    "ns2.irvwilliam.",
					Address: net.ParseIP("54.214.136.246").To4(),
				},
				&handshake.NsDomainRecord{
					Name: "ns2.irvwilliam.",
				},
				&handshake.DsDomainRecord{
					KeyTag:     54616,
					Algorithm:  13,
					DigestType: 1,
					Digest: decodeHex(
						"402ed0125506f35ba249265f39b988d7028a28c3",
					),
				},
				&handshake.DsDomainRecord{
					KeyTag:     54616,
					Algorithm:  13,
					DigestType: 2,
					Digest: decodeHex(
						"0c6c45064c26b529b4ac074dff5de60a99d6025d5b0d7f32c2b8c7d40ec8b3de",
					),
				},
				&handshake.DsDomainRecord{
					KeyTag:     54616,
					Algorithm:  13,
					DigestType: 4,
					Digest: decodeHex(
						"71cb0417852b08b965413f3b871b033996159d121a585e35111a335d4cfb79b67e49a99c3829f6a1f42e100f7f33d7d9",
					),
				},
			},
		},
	}
	tmpCovenant, err := handshake.NewUpdateCovenantFromGeneric(
		testGenericCovenant,
	)
	if err != nil {
		t.Fatalf(
			"unexpected error creating UpdateCovenant from GenericCovenant: %s",
			err,
		)
	}
	if !reflect.DeepEqual(tmpCovenant, expectedCovenant) {
		t.Fatalf(
			"did not get expected covenant:\n     got: %#v\n  wanted: %#v",
			tmpCovenant,
			expectedCovenant,
		)
	}
}
