// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Message types
const (
	MessageVersion     = 0
	MessageVerack      = 1
	MessagePing        = 2
	MessagePong        = 3
	MessageGetAddr     = 4
	MessageAddr        = 5
	MessageGetHeaders  = 10
	MessageHeaders     = 11
	MessageSendHeaders = 12
	MessageGetProof    = 26
	MessageProof       = 27
)

const (
	messageHeaderLength     = 9
	messageMaxPayloadLength = 8 * 1000 * 1000
)

type Message interface {
	Encode() []byte
	Decode([]byte) error
}

func encodeMessage(msgType uint8, payload []byte, networkMagic uint32) ([]byte, error) {
	if len(payload) > messageMaxPayloadLength {
		return nil, errors.New("payload is too large")
	}
	msg := make([]byte, messageHeaderLength+len(payload))
	header := &msgHeader{
		NetworkMagic:  networkMagic,
		MessageType:   msgType,
		PayloadLength: uint32(len(payload)), // nolint:gosec
	}
	encodedHeader := header.Encode()
	copy(msg[0:messageHeaderLength], encodedHeader)
	// Payload
	copy(msg[9:], payload)
	return msg, nil
}

func decodeMessage(header *msgHeader, payload []byte) (Message, error) {
	var ret Message
	switch header.MessageType {
	case MessageVersion:
		ret = &MsgVersion{}
	case MessageVerack:
		ret = &MsgVerack{}
	default:
		return nil, fmt.Errorf("unsupported message type: %d", header.MessageType)
	}
	if err := ret.Decode(payload); err != nil {
		return nil, fmt.Errorf("decode message: %w", err)
	}
	return ret, nil
}

type msgHeader struct {
	NetworkMagic  uint32
	MessageType   uint8
	PayloadLength uint32
}

func (h *msgHeader) Encode() []byte {
	msgHeader := make([]byte, messageHeaderLength)
	// Network magic number
	binary.LittleEndian.PutUint32(msgHeader[0:4], h.NetworkMagic)
	// Message type
	msgHeader[4] = h.MessageType
	// Payload length
	binary.LittleEndian.PutUint32(msgHeader[5:9], uint32(h.PayloadLength))
	return msgHeader
}

func (h *msgHeader) Decode(data []byte) error {
	if len(data) != messageHeaderLength {
		return errors.New("header data is incorrect size")
	}
	h.NetworkMagic = binary.LittleEndian.Uint32(data[0:4])
	h.MessageType = data[4]
	h.PayloadLength = binary.LittleEndian.Uint32(data[5:9])
	return nil
}

type MsgVersion struct {
	Version  uint32
	Services uint64
	Time     uint64
	Remote   NetAddress
	Nonce    [8]byte
	Agent    string
	Height   uint32
	NoRelay  bool
}

func (m *MsgVersion) Encode() []byte {
	buf := new(bytes.Buffer)
	// Protocol version
	_ = binary.Write(buf, binary.LittleEndian, m.Version)
	// Services
	_ = binary.Write(buf, binary.LittleEndian, m.Services)
	// Timestamp
	_ = binary.Write(buf, binary.LittleEndian, m.Time)
	// Remote address
	encodedRemote := m.Remote.Encode()
	_, _ = buf.Write(encodedRemote)
	// Nonce
	_ = binary.Write(buf, binary.LittleEndian, m.Nonce[:])
	// User agent string length
	_ = buf.WriteByte(byte(len(m.Agent)))
	// User agent string
	_, _ = buf.WriteString(m.Agent)
	// Block height
	_ = binary.Write(buf, binary.LittleEndian, m.Height)
	// No relay
	if m.NoRelay {
		_ = buf.WriteByte(1)
	} else {
		_ = buf.WriteByte(0)
	}
	return buf.Bytes()
}

func (m *MsgVersion) Decode(data []byte) error {
	m.Version = binary.LittleEndian.Uint32(data[0:4])
	m.Services = binary.LittleEndian.Uint64(data[4:12])
	m.Time = binary.LittleEndian.Uint64(data[12:20])
	if err := m.Remote.Decode(data[20:108]); err != nil {
		return err
	}
	m.Nonce = [8]byte(data[108:116])
	userAgentLength := int(data[116])
	m.Agent = string(data[117 : 117+userAgentLength])
	m.Height = binary.LittleEndian.Uint32(data[117+userAgentLength : 117+userAgentLength+4])
	noRelayByte := data[117+userAgentLength+4]
	m.NoRelay = false
	if noRelayByte == 1 {
		m.NoRelay = true
	}
	return nil
}

type NetAddress struct {
	Time     uint64
	Services uint64
	Host     net.IP
	Reserved [20]byte
	Port     uint16
	Key      [33]byte
}

func (n *NetAddress) Encode() []byte {
	buf := new(bytes.Buffer)
	// Time
	_ = binary.Write(buf, binary.LittleEndian, n.Time)
	// Services
	_ = binary.Write(buf, binary.LittleEndian, n.Services)
	// Address type
	buf.WriteByte(0)
	// Address
	if n.Host.To4() != nil {
		// IPv4
		buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff})
		buf.Write(n.Host.To4())
	} else {
		// IPv6
		buf.Write(n.Host.To16())
	}
	// Reserved
	buf.Write(n.Reserved[:])
	// Port
	_ = binary.Write(buf, binary.BigEndian, n.Port)
	// Key
	buf.Write(n.Key[:])
	return buf.Bytes()
}

func (n *NetAddress) Decode(data []byte) error {
	if len(data) != 88 {
		return errors.New("invalid NetAddress length")
	}
	n.Time = binary.LittleEndian.Uint64(data[0:8])
	n.Services = binary.LittleEndian.Uint64(data[8:16])
	// NOTE: purposely skipping byte at index 16 for address type
	n.Host = net.IP(data[17:33])
	copy(n.Reserved[:], data[33:53])
	n.Port = binary.BigEndian.Uint16(data[53:55])
	copy(n.Key[:], data[55:88])
	return nil
}

type MsgVerack struct{}

func (*MsgVerack) Encode() []byte {
	// No payload
	return []byte{}
}

func (*MsgVerack) Decode(data []byte) error {
	// No payload
	return nil
}

type MsgPing struct{}

type MsgPong struct{}

type MsgGetAddr struct{}

type MsgAddr struct{}

type MsgGetHeaders struct{}

type MsgHeaders struct{}

type MsgSendHeaders struct{}

type MsgGetProof struct{}

type MsgProof struct{}
