// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package protocol

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/handshake"
)

const (
	dialTimeout = 5 * time.Second

	protocolVersion            = 1
	protocolUserAgent          = "/cdnsd/"
	protocolServicesNoServices = 0
)

// Peer represents a connection with a network peer
type Peer struct {
	address      string
	conn         net.Conn
	networkMagic uint32
}

// NewPeer returns a new Peer using an existing connection (if provided) and the specified network magic. If a connection is provided,
// the handshake process will be performed
func NewPeer(conn net.Conn, networkMagic uint32) (*Peer, error) {
	p := &Peer{
		conn:         conn,
		networkMagic: networkMagic,
	}
	if conn != nil {
		p.address = conn.RemoteAddr().String()
		if err := p.handshake(); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Connect establishes a connection with a peer and performs the handshake process
func (p *Peer) Connect(address string) error {
	if p.conn != nil {
		return errors.New("connection already established")
	}
	var err error
	p.conn, err = net.DialTimeout("tcp", address, dialTimeout)
	if err != nil {
		return err
	}
	p.address = address
	if err := p.handshake(); err != nil {
		return err
	}
	return nil
}

// Close closes an active connection with a network peer
func (p *Peer) Close() error {
	if p.conn == nil {
		return errors.New("connection is not established")
	}
	if err := p.conn.Close(); err != nil {
		return err
	}
	return nil
}

// sendMessage encodes and sends a message with the given type and payload
func (p *Peer) sendMessage(msgType uint8, msgPayload Message) error {
	if p.conn == nil {
		return errors.New("connection is not established")
	}
	var payload []byte
	if msgPayload != nil {
		payload = msgPayload.Encode()
	}
	rawMsg, err := encodeMessage(msgType, payload, p.networkMagic)
	if err != nil {
		return err
	}
	_, err = p.conn.Write(rawMsg)
	if err != nil {
		return err
	}
	return nil
}

// receiveMessage receives and decodes messages from the active connection
func (p *Peer) receiveMessage() (Message, error) {
	headerBuf := make([]byte, messageHeaderLength)
	if _, err := io.ReadFull(p.conn, headerBuf); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	header := new(msgHeader)
	if err := header.Decode(headerBuf); err != nil {
		return nil, fmt.Errorf("header decode: %w", err)
	}
	if header.NetworkMagic != p.networkMagic {
		return nil, fmt.Errorf("invalid network magic: %d", header.NetworkMagic)
	}
	if header.PayloadLength > messageMaxPayloadLength {
		return nil, errors.New("payload is too large")
	}
	payload := make([]byte, header.PayloadLength)
	if _, err := io.ReadFull(p.conn, payload); err != nil {
		return nil, fmt.Errorf("read payload: %w", err)
	}
	msg, err := decodeMessage(header, payload)
	if err != nil {
		// Discard unsupported messages and try to get another message
		// This is a bit of a hack
		var unsupportedErr UnsupportedMessageTypeError
		if errors.As(err, &unsupportedErr) {
			return p.receiveMessage()
		}
		return nil, err
	}
	return msg, nil
}

// handshake performs the handshake process, which involves exchanging Version messages with the network peer
func (p *Peer) handshake() error {
	// Construct and send Version message
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	timeNow := uint64(time.Now().Unix()) // nolint:gosec
	versionMsg := &MsgVersion{
		Version:  protocolVersion,
		Services: protocolServicesNoServices,
		Time:     timeNow,
		Remote: NetAddress{
			Time:     timeNow,
			Services: protocolServicesNoServices,
			Host:     net.ParseIP("0.0.0.0"),
			Port:     0,
		},
		Nonce:   [8]byte(nonce),
		Agent:   protocolUserAgent,
		Height:  0,
		NoRelay: true,
	}
	if err := p.sendMessage(MessageVersion, versionMsg); err != nil {
		return err
	}
	// Wait for Verack response
	msg, err := p.receiveMessage()
	if err != nil {
		return err
	}
	if _, ok := msg.(*MsgVerack); !ok {
		return fmt.Errorf("unexpected message: %T", msg)
	}
	// Wait for Version from peer
	msg, err = p.receiveMessage()
	if err != nil {
		return err
	}
	if _, ok := msg.(*MsgVersion); !ok {
		return fmt.Errorf("unexpected message: %T", msg)
	}
	// Send Verack
	if err := p.sendMessage(MessageVerack, nil); err != nil {
		return err
	}
	return nil
}

// GetPeers requests a list of peers from the network peer
func (p *Peer) GetPeers() ([]NetAddress, error) {
	if err := p.sendMessage(MessageGetAddr, nil); err != nil {
		return nil, err
	}
	// Wait for Addr response
	msg, err := p.receiveMessage()
	if err != nil {
		return nil, err
	}
	msgAddr, ok := msg.(*MsgAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected message: %T", msg)
	}
	return msgAddr.Peers, nil
}

// GetHeaders requests a list of headers from the network peer
func (p *Peer) GetHeaders(locator [][32]byte, stopHash [32]byte) ([]*handshake.BlockHeader, error) {
	getHeadersMsg := &MsgGetHeaders{
		Locator:  locator,
		StopHash: stopHash,
	}
	if err := p.sendMessage(MessageGetHeaders, getHeadersMsg); err != nil {
		return nil, err
	}
	// Wait for Headers response
	msg, err := p.receiveMessage()
	if err != nil {
		return nil, err
	}
	msgHeaders, ok := msg.(*MsgHeaders)
	if !ok {
		return nil, fmt.Errorf("unexpected message: %T", msg)
	}
	return msgHeaders.Headers, nil
}
