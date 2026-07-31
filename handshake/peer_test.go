// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake

import (
	"io"
	"net"
	"testing"
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
