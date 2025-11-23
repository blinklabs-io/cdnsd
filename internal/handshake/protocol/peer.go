// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package protocol

import (
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
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
	mu           sync.Mutex
	sendMu       sync.Mutex
	hasConnected bool
	doneCh       chan struct{}
	errorCh      chan error
	handshakeCh  chan Message
	headersCh    chan Message
	blockCh      chan Message
	addrCh       chan Message
	proofCh      chan Message
}

// NewPeer returns a new Peer using an existing connection (if provided) and the specified network magic. If a connection is provided,
// the handshake process will be performed
func NewPeer(conn net.Conn, networkMagic uint32) (*Peer, error) {
	p := &Peer{
		conn:         conn,
		networkMagic: networkMagic,
		doneCh:       make(chan struct{}),
		errorCh:      make(chan error, 5),
	}
	if conn != nil {
		p.conn = conn
		p.address = conn.RemoteAddr().String()
		p.hasConnected = true
		if err := p.setupConnection(); err != nil {
			_ = p.conn.Close()
			return nil, err
		}
	}
	return p, nil
}

// Connect establishes a connection with a peer and performs the handshake process
func (p *Peer) Connect(address string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn != nil {
		return errors.New("connection already established")
	}
	if p.hasConnected {
		return errors.New("peer cannot be reused after disconnect")
	}
	var err error
	p.conn, err = net.DialTimeout("tcp", address, dialTimeout)
	if err != nil {
		return err
	}
	p.address = address
	p.hasConnected = true
	if err := p.setupConnection(); err != nil {
		_ = p.conn.Close()
		return err
	}
	return nil
}

// Close closes an active connection with a network peer
func (p *Peer) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		return errors.New("connection is not established")
	}
	if err := p.conn.Close(); err != nil {
		return err
	}
	p.conn = nil
	close(p.doneCh)
	return nil
}

// ErrorChan returns the async error channel
func (p *Peer) ErrorChan() <-chan error {
	return p.errorCh
}

// setupConnection runs the initial handshake and starts the receive loop
func (p *Peer) setupConnection() error {
	// Init channels for async messages
	p.handshakeCh = make(chan Message, 10)
	p.headersCh = make(chan Message, 10)
	p.blockCh = make(chan Message, 10)
	p.addrCh = make(chan Message, 10)
	p.proofCh = make(chan Message, 10)
	// Start receive loop
	go p.recvLoop()
	// Start handshake
	if err := p.handshake(); err != nil {
		return err
	}
	return nil
}

// sendMessage encodes and sends a message with the given type and payload
func (p *Peer) sendMessage(msgType uint8, msgPayload Message) error {
	p.sendMu.Lock()
	defer p.sendMu.Unlock()
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

// recvLoop receives and decodes messages from the active connection
func (p *Peer) recvLoop() {
	err := func() error {
		// Assign to local var to avoid nil deref panic on shutdown
		conn := p.conn
		for {
			headerBuf := make([]byte, messageHeaderLength)
			if _, err := io.ReadFull(conn, headerBuf); err != nil {
				return fmt.Errorf("read header: %w", err)
			}
			header := new(msgHeader)
			if err := header.Decode(headerBuf); err != nil {
				return fmt.Errorf("header decode: %w", err)
			}
			if header.NetworkMagic != p.networkMagic {
				return fmt.Errorf("invalid network magic: %d", header.NetworkMagic)
			}
			if header.PayloadLength > messageMaxPayloadLength {
				return errors.New("payload is too large")
			}
			payload := make([]byte, header.PayloadLength)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return fmt.Errorf("read payload: %w", err)
			}
			msg, err := decodeMessage(header, payload)
			if err != nil {
				// Discard unsupported messages and try to get another message
				// This is a bit of a hack
				var unsupportedErr UnsupportedMessageTypeError
				if errors.As(err, &unsupportedErr) {
					continue
				}
				return fmt.Errorf("decode message: %w", err)
			}
			if err := p.handleMessage(msg); err != nil {
				return fmt.Errorf("handle message: %w", err)
			}
		}
	}()
	if err != nil {
		p.errorCh <- err
		_ = p.Close()
	}
}

func (p *Peer) handleMessage(msg Message) error {
	switch m := msg.(type) {
	case *MsgVersion, *MsgVerack:
		p.handshakeCh <- msg
	case *MsgAddr:
		p.addrCh <- msg
	case *MsgHeaders:
		p.headersCh <- msg
	case *MsgBlock:
		p.blockCh <- msg
	case *MsgProof:
		p.proofCh <- msg
	case *MsgPing:
		return p.handlePing(m)
	default:
		return fmt.Errorf("unknown message type: %T", msg)
	}
	return nil
}

// handlePing responds to Ping messages with a Pong message containing the same nonce value
func (p *Peer) handlePing(msg *MsgPing) error {
	pongMsg := &MsgPong{
		Nonce: msg.Nonce,
	}
	if err := p.sendMessage(MessagePong, pongMsg); err != nil {
		return err
	}
	return nil
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
	select {
	case msg := <-p.handshakeCh:
		if _, ok := msg.(*MsgVerack); !ok {
			return fmt.Errorf("unexpected message: %T", msg)
		}
	case err := <-p.errorCh:
		return fmt.Errorf("handshake failed: %w", err)
	case <-time.After(1 * time.Second):
		return errors.New("handshake timed out")
	}
	// Wait for Version from peer
	select {
	case msg := <-p.handshakeCh:
		if _, ok := msg.(*MsgVersion); !ok {
			return fmt.Errorf("unexpected message: %T", msg)
		}
	case err := <-p.errorCh:
		return fmt.Errorf("handshake failed: %w", err)
	case <-p.doneCh:
		return errors.New("connection has shut down")
	case <-time.After(1 * time.Second):
		return errors.New("handshake timed out")
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
	select {
	case msg := <-p.addrCh:
		msgAddr, ok := msg.(*MsgAddr)
		if !ok {
			return nil, fmt.Errorf("unexpected message: %T", msg)
		}
		return msgAddr.Peers, nil
	case <-p.doneCh:
		return nil, errors.New("connection has shut down")
	case <-time.After(5 * time.Second):
		return nil, errors.New("timed out")
	}
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
	select {
	case msg := <-p.headersCh:
		msgHeaders, ok := msg.(*MsgHeaders)
		if !ok {
			return nil, fmt.Errorf("unexpected message: %T", msg)
		}
		return msgHeaders.Headers, nil
	case <-p.doneCh:
		return nil, errors.New("connection has shut down")
	case <-time.After(5 * time.Second):
		return nil, errors.New("timed out")
	}
}

// GetProof requests a proof for a domain name from the network peer
func (p *Peer) GetProof(name string, rootHash [32]byte) (*handshake.Proof, error) {
	key := sha3.Sum256([]byte(name))
	getProofMsg := &MsgGetProof{
		Root: rootHash,
		Key:  key,
	}
	if err := p.sendMessage(MessageGetProof, getProofMsg); err != nil {
		return nil, err
	}
	// Wait for Proof response
	select {
	case msg := <-p.proofCh:
		msgProof, ok := msg.(*MsgProof)
		if !ok {
			return nil, fmt.Errorf("unexpected message: %T", msg)
		}
		return msgProof.Proof, nil
	case <-p.doneCh:
		return nil, errors.New("connection has shut down")
	case <-time.After(5 * time.Second):
		return nil, errors.New("timed out")
	}
}

// GetBlock requests the specified block from the network peer
func (p *Peer) GetBlock(hash [32]byte) (*handshake.Block, error) {
	getDataMsg := &MsgGetData{
		Inventory: []InvItem{
			{
				Type: InvTypeBlock,
				Hash: hash,
			},
		},
	}
	if err := p.sendMessage(MessageGetData, getDataMsg); err != nil {
		return nil, err
	}
	// Wait for Block response
	select {
	case msg := <-p.blockCh:
		msgBlock, ok := msg.(*MsgBlock)
		if !ok {
			return nil, fmt.Errorf("unexpected message: %T", msg)
		}
		return msgBlock.Block, nil
	case <-p.doneCh:
		return nil, errors.New("connection has shut down")
	case <-time.After(5 * time.Second):
		return nil, errors.New("timed out")
	}
}
