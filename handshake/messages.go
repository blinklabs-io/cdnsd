// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

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
	MessageGetData     = 7
	MessageGetHeaders  = 10
	MessageHeaders     = 11
	MessageSendHeaders = 12
	MessageBlock       = 13
	MessageGetProof    = 26
	MessageProof       = 27
)

const (
	messageHeaderLength     = 9
	netAddressLength        = 88
	messageMaxPayloadLength = 8 * 1000 * 1000
)

type UnsupportedMessageTypeError struct {
	MessageType uint8
}

func (e UnsupportedMessageTypeError) Error() string {
	return fmt.Sprintf("unsupported message type: %d", e.MessageType)
}

type Message interface {
	Encode() []byte
	Decode([]byte) error
}

func encodeMessage(
	msgType uint8,
	payload []byte,
	networkMagic uint32,
) ([]byte, error) {
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
	case MessagePing:
		ret = &MsgPing{}
	case MessagePong:
		ret = &MsgPong{}
	case MessageGetAddr:
		ret = &MsgGetAddr{}
	case MessageAddr:
		ret = &MsgAddr{}
	case MessageGetData:
		ret = &MsgGetData{}
	case MessageGetHeaders:
		ret = &MsgGetHeaders{}
	case MessageHeaders:
		ret = &MsgHeaders{}
	case MessageBlock:
		ret = &MsgBlock{}
	case MessageGetProof:
		ret = &MsgGetProof{}
	case MessageProof:
		ret = &MsgProof{}
	default:
		return nil, UnsupportedMessageTypeError{MessageType: header.MessageType}
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
	m.Height = binary.LittleEndian.Uint32(
		data[117+userAgentLength : 117+userAgentLength+4],
	)
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
	// This is always zero
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
	if len(data) != netAddressLength {
		return errors.New("invalid NetAddress length")
	}
	n.Time = binary.LittleEndian.Uint64(data[0:8])
	n.Services = binary.LittleEndian.Uint64(data[8:16])
	// NOTE: purposely skipping byte at index 16 for address type, it's always zero
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

type MsgPing struct {
	Nonce uint64
}

func (m *MsgPing) Encode() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, m.Nonce)
	return buf.Bytes()
}

func (m *MsgPing) Decode(data []byte) error {
	if len(data) != 8 {
		return errors.New("invalid payload length")
	}
	m.Nonce = binary.LittleEndian.Uint64(data)
	return nil
}

type MsgPong struct {
	Nonce uint64
}

func (m *MsgPong) Encode() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, m.Nonce)
	return buf.Bytes()
}

func (m *MsgPong) Decode(data []byte) error {
	if len(data) != 8 {
		return errors.New("invalid payload length")
	}
	m.Nonce = binary.LittleEndian.Uint64(data)
	return nil
}

type MsgGetAddr struct{}

func (*MsgGetAddr) Encode() []byte {
	// No payload
	return []byte{}
}

func (*MsgGetAddr) Decode(data []byte) error {
	// No payload
	return nil
}

type MsgAddr struct {
	Peers []NetAddress
}

func (m *MsgAddr) Encode() []byte {
	buf := new(bytes.Buffer)
	uvarCount := WriteUvarint(uint64(len(m.Peers)))
	_, _ = buf.Write(uvarCount)
	for _, peer := range m.Peers {
		peerBytes := peer.Encode()
		_, _ = buf.Write(peerBytes)
	}
	return buf.Bytes()
}

func (m *MsgAddr) Decode(data []byte) error {
	count, bytesRead, err := ReadUvarint(data)
	if err != nil {
		return err
	}
	data = data[bytesRead:]
	if len(data) != int(count*netAddressLength) { // nolint:gosec
		return errors.New("invalid payload length")
	}
	m.Peers = make([]NetAddress, count)
	for i := range count {
		if err := m.Peers[i].Decode(data[:netAddressLength]); err != nil {
			return err
		}
		data = data[netAddressLength:]
	}
	return nil
}

type MsgGetData struct {
	Inventory []InvItem
}

func (m *MsgGetData) Encode() []byte {
	buf := new(bytes.Buffer)
	uvarCount := WriteUvarint(uint64(len(m.Inventory)))
	_, _ = buf.Write(uvarCount)
	for _, inv := range m.Inventory {
		invBytes := inv.Encode()
		_, _ = buf.Write(invBytes)
	}
	return buf.Bytes()
}

func (m *MsgGetData) Decode(data []byte) error {
	count, bytesRead, err := ReadUvarint(data)
	if err != nil {
		return err
	}
	data = data[bytesRead:]
	if len(data) != int(count)*36 { // nolint:gosec
		return errors.New("invalid payload length")
	}
	m.Inventory = make([]InvItem, count)
	for i := range count {
		if err := m.Inventory[i].Decode(data[0:36]); err != nil {
			return err
		}
		data = data[36:]
	}
	return nil
}

type MsgGetHeaders struct {
	Locator  [][32]byte
	StopHash [32]byte
}

func (m *MsgGetHeaders) Encode() []byte {
	buf := new(bytes.Buffer)
	locatorCount := WriteUvarint(uint64(len(m.Locator)))
	_, _ = buf.Write(locatorCount)
	for _, loc := range m.Locator {
		_, _ = buf.Write(loc[:])
	}
	_, _ = buf.Write(m.StopHash[:])
	return buf.Bytes()
}

func (m *MsgGetHeaders) Decode(data []byte) error {
	count, bytesRead, err := ReadUvarint(data)
	if err != nil {
		return err
	}
	data = data[bytesRead:]
	if len(data) != int(((count * 32) + 32)) { // nolint:gosec
		return errors.New("invalid payload length")
	}
	m.Locator = make([][32]byte, count)
	for i := range count {
		loc := data[0:32]
		m.Locator[i] = [32]byte(loc)
		data = data[32:]
	}
	m.StopHash = [32]byte(data[0:32])
	return nil
}

type MsgHeaders struct {
	Headers []*BlockHeader
}

func (m *MsgHeaders) Encode() []byte {
	buf := new(bytes.Buffer)
	headerCount := WriteUvarint(uint64(len(m.Headers)))
	_, _ = buf.Write(headerCount)
	for _, header := range m.Headers {
		_, _ = buf.Write(header.Encode())
	}
	return buf.Bytes()
}

func (m *MsgHeaders) Decode(data []byte) error {
	count, bytesRead, err := ReadUvarint(data)
	if err != nil {
		return err
	}
	data = data[bytesRead:]
	if len(data) != int(count*BlockHeaderSize) { // nolint:gosec
		return errors.New("invalid payload length")
	}
	m.Headers = make([]*BlockHeader, count)
	for i := range count {
		tmpReader := bytes.NewReader(data[0:BlockHeaderSize])
		tmpHeader, err := NewBlockHeaderFromReader(tmpReader)
		if err != nil {
			return err
		}
		m.Headers[i] = tmpHeader
		data = data[BlockHeaderSize:]
	}
	return nil
}

type MsgSendHeaders struct{}

type MsgBlock struct {
	Block *Block
}

func (m *MsgBlock) Encode() []byte {
	// NOTE: this isn't implemented because we don't have block encoding implemented
	return []byte{}
}

func (m *MsgBlock) Decode(data []byte) error {
	blk, err := NewBlockFromReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	m.Block = blk
	return nil
}

type MsgGetProof struct {
	Root [32]byte
	Key  [32]byte
}

func (m *MsgGetProof) Encode() []byte {
	buf := new(bytes.Buffer)
	_, _ = buf.Write(m.Root[:])
	_, _ = buf.Write(m.Key[:])
	return buf.Bytes()
}

func (m *MsgGetProof) Decode(data []byte) error {
	if len(data) != 2*32 {
		return errors.New("invalid payload length")
	}
	m.Root = [32]byte(data[0:32])
	m.Key = [32]byte(data[32:64])
	return nil
}

type MsgProof struct {
	Root  [32]byte
	Key   [32]byte
	Proof *Proof
}

func (m *MsgProof) Encode() []byte {
	// NOTE: this is not implemented because proof encoding is not implemented
	return []byte{}
}

func (m *MsgProof) Decode(data []byte) error {
	// The payload should be much more than 64 bytes, but we don't know the size of the proof
	if len(data) < 64 {
		return errors.New("invalid payload length")
	}
	m.Root = [32]byte(data[0:32])
	m.Key = [32]byte(data[32:64])
	var tmpProof Proof
	if err := tmpProof.Decode(bytes.NewBuffer(data[64:])); err != nil {
		return err
	}
	m.Proof = &tmpProof
	return nil
}

const (
	InvTypeTx            = 1
	InvTypeBlock         = 2
	InvTypeFilteredBlock = 3
	InvTypeCmpctBlock    = 4
	InvTypeClaim         = 5
	InvTypeAirDrop       = 6
)

type InvItem struct {
	Type uint32
	Hash [32]byte
}

func (i *InvItem) Encode() []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.LittleEndian, i.Type)
	_, _ = buf.Write(i.Hash[:])
	return buf.Bytes()
}

func (i *InvItem) Decode(data []byte) error {
	if len(data) != 36 {
		return errors.New("invalid payload length")
	}
	i.Type = binary.LittleEndian.Uint32(data[0:4])
	i.Hash = [32]byte(data[4:])
	return nil
}
