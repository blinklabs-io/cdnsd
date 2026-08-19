// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestPeerHandshakeAcceptsVersionBeforeVerack(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	peerCh := make(chan struct {
		peer *Peer
		err  error
	}, 1)
	go func() {
		peer, err := NewPeer(client, NetworkMainnet)
		peerCh <- struct {
			peer *Peer
			err  error
		}{peer: peer, err: err}
	}()

	if _, err := readPeerMessage(server); err != nil {
		t.Fatalf("read client version: %v", err)
	}
	peerVersion := &MsgVersion{
		Version:  1,
		Agent:    "/handshaked/",
		Remote:   NetAddress{Host: net.ParseIP("0.0.0.0")},
		NoRelay:  true,
		Services: protocolServicesNoServices,
	}
	if err := writePeerMessage(server, MessageVersion, peerVersion); err != nil {
		t.Fatalf("write peer version: %v", err)
	}
	msg, err := readPeerMessage(server)
	if err != nil {
		t.Fatalf("read client verack: %v", err)
	}
	if _, ok := msg.(*MsgVerack); !ok {
		t.Fatalf("client sent %T after peer version, want *MsgVerack", msg)
	}
	if err := writePeerMessage(server, MessageVerack, nil); err != nil {
		t.Fatalf("write peer verack: %v", err)
	}

	result := <-peerCh
	if result.err != nil {
		t.Fatalf("NewPeer() error = %v", result.err)
	}
	if result.peer == nil {
		t.Fatal("NewPeer() returned a nil peer")
	}
	_ = result.peer.Close()
}

func TestPeerHandshakeAcceptsVerackBeforeVersion(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	peerCh := make(chan struct {
		peer *Peer
		err  error
	}, 1)
	go func() {
		peer, err := NewPeer(client, NetworkMainnet)
		peerCh <- struct {
			peer *Peer
			err  error
		}{peer: peer, err: err}
	}()

	if _, err := readPeerMessage(server); err != nil {
		t.Fatalf("read client version: %v", err)
	}
	if err := writePeerMessage(server, MessageVerack, nil); err != nil {
		t.Fatalf("write peer verack: %v", err)
	}
	peerVersion := &MsgVersion{
		Version:  1,
		Agent:    "/handshaked/",
		Remote:   NetAddress{Host: net.ParseIP("0.0.0.0")},
		NoRelay:  true,
		Services: protocolServicesNoServices,
	}
	if err := writePeerMessage(server, MessageVersion, peerVersion); err != nil {
		t.Fatalf("write peer version: %v", err)
	}
	msg, err := readPeerMessage(server)
	if err != nil {
		t.Fatalf("read client verack: %v", err)
	}
	if _, ok := msg.(*MsgVerack); !ok {
		t.Fatalf("client sent %T after peer version, want *MsgVerack", msg)
	}

	result := <-peerCh
	if result.err != nil {
		t.Fatalf("NewPeer() error = %v", result.err)
	}
	if result.peer == nil {
		t.Fatal("NewPeer() returned a nil peer")
	}
	_ = result.peer.Close()
}

func readPeerMessage(conn net.Conn) (Message, error) {
	headerBytes := make([]byte, messageHeaderLength)
	if _, err := io.ReadFull(conn, headerBytes); err != nil {
		return nil, err
	}
	header := new(msgHeader)
	if err := header.Decode(headerBytes); err != nil {
		return nil, err
	}
	payload := make([]byte, header.PayloadLength)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return decodeMessage(header, payload)
}

func writePeerMessage(conn net.Conn, msgType uint8, msg Message) error {
	var payload []byte
	if msg != nil {
		payload = msg.Encode()
	}
	raw, err := encodeMessage(msgType, payload, NetworkMainnet.Magic)
	if err != nil {
		return err
	}
	_, err = conn.Write(raw)
	return err
}

// newSyncTestPeer returns a handshaked Peer along with the remote end of its
// connection, so a test can drive Sync from the peer side.
func newSyncTestPeer(t *testing.T) (*Peer, net.Conn) {
	t.Helper()
	client, server := net.Pipe()
	type peerResult struct {
		peer *Peer
		err  error
	}
	peerCh := make(chan peerResult, 1)
	go func() {
		peer, err := NewPeer(client, NetworkMainnet)
		peerCh <- peerResult{peer: peer, err: err}
	}()
	if err := server.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := readPeerMessage(server); err != nil {
		t.Fatalf("read client version: %v", err)
	}
	peerVersion := &MsgVersion{
		Version:  1,
		Agent:    "/handshaked/",
		Remote:   NetAddress{Host: net.ParseIP("0.0.0.0")},
		NoRelay:  true,
		Services: protocolServicesNoServices,
	}
	if err := writePeerMessage(server, MessageVersion, peerVersion); err != nil {
		t.Fatalf("write peer version: %v", err)
	}
	msg, err := readPeerMessage(server)
	if err != nil {
		t.Fatalf("read client verack: %v", err)
	}
	if _, ok := msg.(*MsgVerack); !ok {
		t.Fatalf("client sent %T after peer version, want *MsgVerack", msg)
	}
	if err := writePeerMessage(server, MessageVerack, nil); err != nil {
		t.Fatalf("write peer verack: %v", err)
	}
	result := <-peerCh
	if result.err != nil {
		t.Fatalf("NewPeer() error = %v", result.err)
	}
	if result.peer == nil {
		t.Fatal("NewPeer() returned a nil peer")
	}
	return result.peer, server
}

// readPeerFrame reads one wire frame and returns its message type with a
// best-effort decode. Sync sends SendHeaders, which decodeMessage does not
// support, so the frame type has to be observable without a decoded message.
func readPeerFrame(conn net.Conn) (uint8, Message, error) {
	headerBytes := make([]byte, messageHeaderLength)
	if _, err := io.ReadFull(conn, headerBytes); err != nil {
		return 0, nil, err
	}
	header := new(msgHeader)
	if err := header.Decode(headerBytes); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, header.PayloadLength)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return 0, nil, err
	}
	msg, err := decodeMessage(header, payload)
	var unsupportedErr UnsupportedMessageTypeError
	if err != nil && !errors.As(err, &unsupportedErr) {
		return header.MessageType, nil, err
	}
	return header.MessageType, msg, nil
}

// expectGetHeaders requires the next frame to be a GetHeaders for the given
// locator. A closed connection surfaces here as a read error, which is how a
// Sync teardown is distinguished from an in-protocol re-request.
func expectGetHeaders(t *testing.T, conn net.Conn, locator [][32]byte) {
	t.Helper()
	msgType, msg, err := readPeerFrame(conn)
	if err != nil {
		t.Fatalf("read GetHeaders: %v", err)
	}
	if msgType != MessageGetHeaders {
		t.Fatalf("frame type = %d, want MessageGetHeaders (%d)", msgType, MessageGetHeaders)
	}
	getHeaders, ok := msg.(*MsgGetHeaders)
	if !ok {
		t.Fatalf("frame decoded to %T, want *MsgGetHeaders", msg)
	}
	if len(getHeaders.Locator) != len(locator) {
		t.Fatalf("GetHeaders locator length = %d, want %d", len(getHeaders.Locator), len(locator))
	}
	for idx := range locator {
		if getHeaders.Locator[idx] != locator[idx] {
			t.Fatalf(
				"GetHeaders locator[%d] = %x, want %x",
				idx,
				getHeaders.Locator[idx],
				locator[idx],
			)
		}
	}
}

// expectSendHeadersThenGetHeaders consumes the two frames Sync always emits
// before it waits for a header batch.
func expectSendHeadersThenGetHeaders(
	t *testing.T,
	conn net.Conn,
	locator [][32]byte,
) {
	t.Helper()
	msgType, _, err := readPeerFrame(conn)
	if err != nil {
		t.Fatalf("read SendHeaders: %v", err)
	}
	if msgType != MessageSendHeaders {
		t.Fatalf("frame type = %d, want MessageSendHeaders (%d)", msgType, MessageSendHeaders)
	}
	expectGetHeaders(t, conn, locator)
}

// TestSyncRecoversWhenHeaderBatchDoesNotExtendLocator pins the in-protocol
// recovery path: a batch whose first header does not build on the current
// locator is not a validation failure, it means we asked from the wrong point.
// Sync must drop back to catch-up mode and re-request headers rather than
// pushing an error and closing the connection, which would force a full
// reconnect and re-handshake on every reorg.
func TestSyncRecoversWhenHeaderBatchDoesNotExtendLocator(t *testing.T) {
	peer, server := newSyncTestPeer(t)
	defer server.Close()

	locatorHash := [32]byte{0xaa}
	locator := [][32]byte{locatorHash}
	// Sync writes SendHeaders synchronously on an unbuffered pipe, so it has
	// to run off the goroutine that drains the pipe.
	syncErrCh := make(chan error, 1)
	go func() {
		syncErrCh <- peer.Sync(locator, func(*Block) error {
			return errors.New(
				"syncFunc called for a batch that does not extend the locator",
			)
		})
	}()
	expectSendHeadersThenGetHeaders(t, server, locator)
	if err := <-syncErrCh; err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// First header builds on something else entirely.
	if err := writePeerMessage(server, MessageHeaders, &MsgHeaders{
		Headers: []*BlockHeader{{PrevBlock: [32]byte{0xbb}}},
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	// The recovery is observable as a second GetHeaders for the same locator.
	expectGetHeaders(t, server, locator)

	select {
	case err := <-peer.ErrorChan():
		t.Fatalf("Sync reported a fatal error for a recoverable batch: %v", err)
	case <-peer.DoneChan():
		t.Fatal("Sync closed the peer for a recoverable batch")
	default:
	}
	_ = peer.Close()
}

// TestSyncStopsWhenHeaderBatchTargetExceedsNetworkPowLimit is the companion
// negative case. The batch does extend the locator, so the recovery path must
// not swallow it: a header claiming a target easier than the network PoW limit
// is a validation failure and has to tear the peer down.
func TestSyncStopsWhenHeaderBatchTargetExceedsNetworkPowLimit(t *testing.T) {
	peer, server := newSyncTestPeer(t)
	defer server.Close()

	locatorHash := [32]byte{0xaa}
	locator := [][32]byte{locatorHash}
	syncErrCh := make(chan error, 1)
	go func() {
		syncErrCh <- peer.Sync(locator, func(*Block) error {
			return errors.New("syncFunc called for a batch that fails validation")
		})
	}()
	expectSendHeadersThenGetHeaders(t, server, locator)
	if err := <-syncErrCh; err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	// mainnet PowLimit is 0x1c00ffff, so 0x1d00ffff is 256 times easier.
	if err := writePeerMessage(server, MessageHeaders, &MsgHeaders{
		Headers: []*BlockHeader{{PrevBlock: locatorHash, Bits: 0x1d00ffff}},
	}); err != nil {
		t.Fatalf("write headers: %v", err)
	}

	select {
	case err := <-peer.ErrorChan():
		if !strings.Contains(err.Error(), "invalid header batch") {
			t.Fatalf("Sync error = %v, want an invalid header batch error", err)
		}
		if !strings.Contains(err.Error(), "exceeds network PoW limit") {
			t.Fatalf("Sync error = %v, want a network PoW limit error", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Sync did not reject a header batch above the network PoW limit")
	}
	select {
	case <-peer.DoneChan():
	case <-time.After(15 * time.Second):
		t.Fatal("Sync did not close the peer after a validation failure")
	}
}
