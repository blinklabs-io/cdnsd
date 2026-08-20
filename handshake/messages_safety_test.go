// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import "testing"

func TestMsgVersionDecodeRejectsMalformedInput(t *testing.T) {
	badAgentLength := make([]byte, 123)
	badAgentLength[116] = 2
	for _, data := range [][]byte{
		{},
		make([]byte, 121),
		badAgentLength,
	} {
		msg := new(MsgVersion)
		if err := msg.Decode(data); err == nil {
			t.Errorf("MsgVersion.Decode accepted malformed payload of length %d", len(data))
		}
	}
}

func TestMsgHeadersDecodeRejectsOversizedBatch(t *testing.T) {
	data := WriteUvarint(maxBlockHeaders + 1)
	msg := new(MsgHeaders)
	if err := msg.Decode(data); err == nil {
		t.Fatal("MsgHeaders.Decode accepted more than the protocol header batch limit")
	}
}
