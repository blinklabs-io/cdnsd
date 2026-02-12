// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package indexer

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/blinklabs-io/cdnsd/handshake"
	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
)

type handshakeState struct {
	peer             *handshake.Peer
	peerAddress      string
	peerBackoffDelay time.Duration
	lastBlockHash    [32]byte
	hasLastBlock     bool
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
	slog.Info(
		"connecting to Handshake peer",
		"address",
		i.handshakeState.peerAddress,
	)
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
	var locator [][32]byte = nil
	cursorBlockHash, err := state.GetState().GetHandshakeCursor()
	if err != nil {
		return err
	}
	if cursorBlockHash != "" {
		slog.Info(
			"found previous Handshake cursor: " + cursorBlockHash,
		)
		hashBytes, err := hex.DecodeString(cursorBlockHash)
		if err != nil {
			return err
		}
		if len(hashBytes) != 32 {
			// This isn't a condition we can really recover from, since it implies database corruption
			slog.Error(
				fmt.Sprintf("bad Handshake cursor block hash: %x", hashBytes),
			)
			return errors.New("bad Handshake locator")
		}
		locator = [][32]byte{[32]byte(hashBytes)}
		i.handshakeState.lastBlockHash = [32]byte(hashBytes)
		i.handshakeState.hasLastBlock = true
	}
	// Start sync
	if err := i.handshakeState.peer.Sync(locator, i.handshakeHandleSync); err != nil {
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
	slog.Debug(
		"synced Handshake block",
		"hash", fmt.Sprintf("%x", block.Hash()),
		"prevHash", fmt.Sprintf(
			"%x",
			block.Header.PrevBlock,
		),
	)
	// Verify PrevBlock hash continuity
	if i.handshakeState.hasLastBlock {
		if block.Header.PrevBlock != i.handshakeState.lastBlockHash {
			return fmt.Errorf(
				"block PrevBlock %x does not match last block hash %x",
				block.Header.PrevBlock,
				i.handshakeState.lastBlockHash,
			)
		}
	}
	// Validate proof-of-work
	if err := block.ValidatePoW(); err != nil {
		return fmt.Errorf(
			"block PoW validation failed: %w",
			err,
		)
	}
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
				records, err := handshakeResourceDataToDomainRecords(name, c.ResourceData)
				if err != nil {
					return err
				}
				if err := state.GetState().UpdateHandshakeDomain(name, records); err != nil {
					return err
				}
			case *handshake.UpdateCovenant:
				name, err := state.GetState().GetHandshakeNameByHash(c.NameHash)
				if err != nil {
					return err
				}
				slog.Debug("Handshake domain update", "name", name, "resdata", c.ResourceData)
				records, err := handshakeResourceDataToDomainRecords(name, c.ResourceData)
				if err != nil {
					return err
				}
				if err := state.GetState().UpdateHandshakeDomain(name, records); err != nil {
					return err
				}
			}
		}
	}
	// Update cursor
	blockHash := block.Hash()
	if err := state.GetState().UpdateHandshakeCursor(
		hex.EncodeToString(blockHash[:]),
	); err != nil {
		return err
	}
	// Track last block hash for continuity checks
	i.handshakeState.lastBlockHash = blockHash
	i.handshakeState.hasLastBlock = true
	return nil
}

func handshakeResourceDataToDomainRecords(
	domainName string,
	resData handshake.DomainResourceData,
) ([]state.DomainRecord, error) {
	// The return may be larger than this, but it will be at least as large
	ret := make([]state.DomainRecord, 0, len(resData.Records))
	for _, record := range resData.Records {
		switch r := record.(type) {
		case *handshake.DsDomainRecord:
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(domainName),
					Type: "DS",
					Rhs: fmt.Sprintf(
						"%d %d %d %x",
						r.KeyTag,
						r.Algorithm,
						r.DigestType,
						r.Digest,
					),
				},
			)
		case *handshake.NsDomainRecord:
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(domainName),
					Type: "NS",
					Rhs:  r.Name,
				},
			)
		case *handshake.Glue4DomainRecord:
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(domainName),
					Type: "NS",
					Rhs:  r.Name,
				},
			)
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(r.Name),
					Type: "A",
					Rhs:  r.Address.String(),
				},
			)
		case *handshake.Glue6DomainRecord:
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(domainName),
					Type: "NS",
					Rhs:  r.Name,
				},
			)
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(r.Name),
					Type: "AAAA",
					Rhs:  r.Address.String(),
				},
			)
		case *handshake.Synth4DomainRecord:
			ip4 := r.Address.To4()
			if ip4 == nil {
				return nil, fmt.Errorf("Synth4 record has invalid IPv4 address: %s", r.Address.String())
			}
			base32Enc := base32.HexEncoding.WithPadding(base32.NoPadding)
			nsName := fmt.Sprintf(
				"_%s._synth.",
				strings.ToLower(
					base32Enc.EncodeToString(
						ip4,
					),
				),
			)
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(domainName),
					Type: "NS",
					Rhs:  nsName,
				},
			)
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  nsName,
					Type: "A",
					Rhs:  r.Address.String(),
				},
			)
		case *handshake.Synth6DomainRecord:
			base32Enc := base32.HexEncoding.WithPadding(base32.NoPadding)
			nsName := fmt.Sprintf(
				"_%s._synth.",
				strings.ToLower(
					base32Enc.EncodeToString(
						r.Address,
					),
				),
			)
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(domainName),
					Type: "NS",
					Rhs:  nsName,
				},
			)
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  nsName,
					Type: "AAAA",
					Rhs:  r.Address.String(),
				},
			)
		case *handshake.TextDomainRecord:
			var txtVal string
			for _, item := range r.Items {
				if txtVal != "" {
					txtVal += " "
				}
				txtVal += `"` + string(item) + `"`
			}
			ret = append(
				ret,
				state.DomainRecord{
					Lhs:  dns.CanonicalName(domainName),
					Type: "TXT",
					Rhs:  txtVal,
				},
			)
		default:
			return nil, fmt.Errorf("unsupported record type: %T", record)
		}
	}
	return ret, nil
}
