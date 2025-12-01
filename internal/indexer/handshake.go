// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package indexer

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/handshake"
	"github.com/blinklabs-io/cdnsd/internal/state"
)

type handshakeState struct {
	peer             *handshake.Peer
	peerAddress      string
	peerBackoffDelay time.Duration
	blockHeight      int
}

func (i *Indexer) startHandshake() error {
	cfg := config.GetConfig()
	if cfg.Indexer.HandshakeAddress == "" {
		return nil
	}
	i.handshakeState.peerAddress = cfg.Indexer.HandshakeAddress
	// Start peer (re)connect loop
	go i.handshakeReconnectPeer()
	return nil
}

func (i *Indexer) handshakeConnectPeer() error {
	slog.Info("connecting to Handshake peer", "address", i.handshakeState.peerAddress)
	p, err := handshake.NewPeer(nil, handshake.NetworkMainnet)
	if err != nil {
		return err
	}
	i.handshakeState.peer = p
	if err := i.handshakeState.peer.Connect(i.handshakeState.peerAddress); err != nil {
		return err
	}
	// Async error handler
	go func() {
		select {
		case err := <-i.handshakeState.peer.ErrorChan():
			slog.Error(
				"Handshake peer disconnected",
				"error",
				err,
			)
		case <-i.handshakeState.peer.DoneChan():
			// Stop waiting on connection shutdown
		}
	}()
	// Start sync
	if err := i.handshakeState.peer.Sync(nil, i.handshakeHandleSync); err != nil {
		_ = i.handshakeState.peer.Close()
		return err
	}
	return nil
}

func (i *Indexer) handshakeReconnectPeer() {
	var err error
	// Try reconnecting to peer until we are successful
	for {
		err = i.handshakeConnectPeer()
		if err == nil {
			// Reset backoff delay
			i.handshakeState.peerBackoffDelay = 0
			// Wait for connection close
			<-i.handshakeState.peer.DoneChan()
			continue
		}
		if i.handshakeState.peerBackoffDelay == 0 {
			// Set initial backoff delay
			i.handshakeState.peerBackoffDelay = 1 * time.Second
		} else {
			// Double backoff delay
			i.handshakeState.peerBackoffDelay *= 2
		}
		// Don't delay longer than 2m
		if i.handshakeState.peerBackoffDelay > 120*time.Second {
			i.handshakeState.peerBackoffDelay = 120 * time.Second
		}
		slog.Error(
			"connection to Handshake peer failed",
			"error",
			err,
			"delay",
			i.handshakeState.peerBackoffDelay.String(),
		)
		time.Sleep(i.handshakeState.peerBackoffDelay)
	}
}

func (i *Indexer) handshakeHandleSync(block *handshake.Block) error {
	i.handshakeState.blockHeight++
	slog.Debug(
		"synced Handshake block",
		"height", i.handshakeState.blockHeight,
		"hash", fmt.Sprintf("%x", block.Hash()),
		"prevHash", fmt.Sprintf("%x", block.Header.PrevBlock),
	)
	// Process transactions
	for _, tx := range block.Transactions {
		// Process outputs
		for _, output := range tx.Outputs {
			cov := output.Covenant.Covenant()
			switch c := cov.(type) {
			case *handshake.OpenCovenant:
				if err := state.GetState().AddHandshakeName(c.RawName); err != nil {
					return err
				}
			case *handshake.ClaimCovenant:
				if err := state.GetState().AddHandshakeName(c.RawName); err != nil {
					return err
				}
			case *handshake.RegisterCovenant:
				name, err := state.GetState().GetHandshakeNameByHash(c.NameHash)
				if err != nil {
					return err
				}
				slog.Debug("Handshake domain registration", "name", name, "resdata", c.ResourceData)
			case *handshake.UpdateCovenant:
				name, err := state.GetState().GetHandshakeNameByHash(c.NameHash)
				if err != nil {
					return err
				}
				slog.Debug("Handshake domain update", "name", name, "resdata", c.ResourceData)
			}
		}
	}
	return nil
}
