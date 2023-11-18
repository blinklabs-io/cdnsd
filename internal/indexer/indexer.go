// Copyright 2023 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package indexer

import (
	"encoding/hex"
	"strings"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/logging"
	"github.com/blinklabs-io/cdnsd/internal/state"

	models "github.com/blinklabs-io/cardano-models"
	"github.com/blinklabs-io/gouroboros/cbor"
	ocommon "github.com/blinklabs-io/gouroboros/protocol/common"
	"github.com/blinklabs-io/snek/event"
	filter_chainsync "github.com/blinklabs-io/snek/filter/chainsync"
	filter_event "github.com/blinklabs-io/snek/filter/event"
	input_chainsync "github.com/blinklabs-io/snek/input/chainsync"
	output_embedded "github.com/blinklabs-io/snek/output/embedded"
	"github.com/blinklabs-io/snek/pipeline"
)

type Domain struct {
	Name        string
	Nameservers map[string]string
}

type Indexer struct {
	pipeline   *pipeline.Pipeline
	domains    map[string]Domain
	tipReached bool
}

// Singleton indexer instance
var globalIndexer = &Indexer{
	domains: make(map[string]Domain),
}

func (i *Indexer) Start() error {
	cfg := config.GetConfig()
	logger := logging.GetLogger()
	// Create pipeline
	i.pipeline = pipeline.New()
	// Configure pipeline input
	inputOpts := []input_chainsync.ChainSyncOptionFunc{
		input_chainsync.WithStatusUpdateFunc(
			func(status input_chainsync.ChainSyncStatus) {
				if err := state.GetState().UpdateCursor(status.SlotNumber, status.BlockHash); err != nil {
					logger.Errorf("failed to update cursor: %s", err)
				}
				if !i.tipReached && status.TipReached {
					i.tipReached = true
					logger.Infof("caught up to chain tip")
				}
			},
		),
		input_chainsync.WithBulkMode(true),
		input_chainsync.WithAutoReconnect(true),
		input_chainsync.WithLogger(logger),
	}
	if cfg.Indexer.NetworkMagic > 0 {
		inputOpts = append(
			inputOpts,
			input_chainsync.WithNetworkMagic(cfg.Indexer.NetworkMagic),
		)
	} else {
		inputOpts = append(
			inputOpts,
			input_chainsync.WithNetwork(cfg.Indexer.Network),
		)
	}
	cursorSlotNumber, cursorBlockHash, err := state.GetState().GetCursor()
	if err != nil {
		return err
	}
	if cursorSlotNumber > 0 {
		logger.Infof(
			"found previous chainsync cursor: %d, %s",
			cursorSlotNumber,
			cursorBlockHash,
		)
		hashBytes, err := hex.DecodeString(cursorBlockHash)
		if err != nil {
			return err
		}
		inputOpts = append(
			inputOpts,
			input_chainsync.WithIntersectPoints(
				[]ocommon.Point{
					{
						Hash: hashBytes,
						Slot: cursorSlotNumber,
					},
				},
			),
		)
	} else if cfg.Indexer.InterceptHash != "" && cfg.Indexer.InterceptSlot > 0 {
		logger.Infof("starting new chainsync at configured location: %d, %s", cfg.Indexer.InterceptSlot, cfg.Indexer.InterceptHash)
		hashBytes, err := hex.DecodeString(cfg.Indexer.InterceptHash)
		if err != nil {
			return err
		}
		inputOpts = append(
			inputOpts,
			input_chainsync.WithIntersectPoints(
				[]ocommon.Point{
					{
						Hash: hashBytes,
						Slot: cfg.Indexer.InterceptSlot,
					},
				},
			),
		)
	}
	input := input_chainsync.New(
		inputOpts...,
	)
	i.pipeline.AddInput(input)
	// Configure pipeline filters
	// We only care about transaction events
	filterEvent := filter_event.New(
		filter_event.WithTypes([]string{"chainsync.transaction"}),
	)
	i.pipeline.AddFilter(filterEvent)
	// We only care about transactions on a certain address
	filterChainsync := filter_chainsync.New(
		filter_chainsync.WithAddresses([]string{cfg.Indexer.ScriptAddress}),
	)
	i.pipeline.AddFilter(filterChainsync)
	// Configure pipeline output
	output := output_embedded.New(
		output_embedded.WithCallbackFunc(i.handleEvent),
	)
	i.pipeline.AddOutput(output)
	// Start pipeline
	if err := i.pipeline.Start(); err != nil {
		logger.Fatalf("failed to start pipeline: %s\n", err)
	}
	// Start error handler
	go func() {
		err, ok := <-i.pipeline.ErrorChan()
		if ok {
			logger.Fatalf("pipeline failed: %s\n", err)
		}
	}()
	return nil
}

func (i *Indexer) handleEvent(evt event.Event) error {
	logger := logging.GetLogger()
	eventTx := evt.Payload.(input_chainsync.TransactionEvent)
	eventCtx := evt.Context.(input_chainsync.TransactionContext)
	for _, txOutput := range eventTx.Outputs {
		datum := txOutput.Datum()
		if datum != nil {
			var dnsDomain models.CardanoDnsDomain
			if _, err := cbor.Decode(datum.Cbor(), &dnsDomain); err != nil {
				logger.Warnf(
					"error decoding TX (%s) output datum: %s",
					eventCtx.TransactionHash,
					err,
				)
				// Stop processing TX output if we can't parse the datum
				continue
			}
			domainName := string(dnsDomain.Origin)
			nameServers := map[string]string{}
			for _, record := range dnsDomain.Records {
				// NOTE: we're losing information here, but we need to revamp the storage
				// format before we can use it. We're also making the assumption that all
				// records are for nameservers
				switch strings.ToUpper(string(record.Type)) {
				case "A", "AAAA":
					nameServers[string(record.Lhs)] = string(record.Rhs)
				default:
					continue
				}
			}
			if err := state.GetState().UpdateDomain(domainName, nameServers); err != nil {
				return err
			}
			logger.Infof(
				"found updated registration for domain: %s",
				domainName,
			)
		}
	}
	return nil
}

func (i *Indexer) LookupDomain(name string) *Domain {
	if domain, ok := i.domains[name]; ok {
		return &domain
	}
	return nil
}

// GetIndexer returns the global indexer instance
func GetIndexer() *Indexer {
	return globalIndexer
}
