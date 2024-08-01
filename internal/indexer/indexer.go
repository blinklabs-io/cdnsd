// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package indexer

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"

	"github.com/blinklabs-io/adder/event"
	filter_chainsync "github.com/blinklabs-io/adder/filter/chainsync"
	filter_event "github.com/blinklabs-io/adder/filter/event"
	input_chainsync "github.com/blinklabs-io/adder/input/chainsync"
	output_embedded "github.com/blinklabs-io/adder/output/embedded"
	"github.com/blinklabs-io/adder/pipeline"
	models "github.com/blinklabs-io/cardano-models"
	"github.com/blinklabs-io/gouroboros/cbor"
	ocommon "github.com/blinklabs-io/gouroboros/protocol/common"
	"github.com/miekg/dns"
)

const (
	syncStatusLogInterval = 30 * time.Second
)

type Domain struct {
	Name        string
	Nameservers map[string]string
}

type Indexer struct {
	pipeline     *pipeline.Pipeline
	domains      map[string]Domain
	tipReached   bool
	syncLogTimer *time.Timer
	syncStatus   input_chainsync.ChainSyncStatus
}

// Singleton indexer instance
var globalIndexer = &Indexer{
	domains: make(map[string]Domain),
}

func (i *Indexer) Start() error {
	cfg := config.GetConfig()
	// Create pipeline
	i.pipeline = pipeline.New()
	// Configure pipeline input
	inputOpts := []input_chainsync.ChainSyncOptionFunc{
		input_chainsync.WithStatusUpdateFunc(
			func(status input_chainsync.ChainSyncStatus) {
				i.syncStatus = status
				if err := state.GetState().UpdateCursor(status.SlotNumber, status.BlockHash); err != nil {
					slog.Error(
						fmt.Sprintf("failed to update cursor: %s", err),
					)
				}
				if !i.tipReached && status.TipReached {
					if i.syncLogTimer != nil {
						i.syncLogTimer.Stop()
					}
					i.tipReached = true
					slog.Info("caught up to chain tip")
				}
			},
		),
		input_chainsync.WithBulkMode(true),
		input_chainsync.WithAutoReconnect(true),
		input_chainsync.WithLogger(NewAdderLogger()),
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
		slog.Info(
			fmt.Sprintf(
				"found previous chainsync cursor: %d, %s",
				cursorSlotNumber,
				cursorBlockHash,
			),
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
		slog.Info(
			fmt.Sprintf("starting new chainsync at configured location: %d, %s", cfg.Indexer.InterceptSlot, cfg.Indexer.InterceptHash),
		)
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
	var filterAddresses []string
	for _, profile := range config.GetProfiles() {
		filterAddresses = append(filterAddresses, profile.ScriptAddress)
	}
	filterChainsync := filter_chainsync.New(
		filter_chainsync.WithAddresses(filterAddresses),
	)
	i.pipeline.AddFilter(filterChainsync)
	// Configure pipeline output
	output := output_embedded.New(
		output_embedded.WithCallbackFunc(i.handleEvent),
	)
	i.pipeline.AddOutput(output)
	// Start pipeline
	if err := i.pipeline.Start(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start pipeline: %s\n", err),
		)
		os.Exit(1)
	}
	// Start error handler
	go func() {
		err, ok := <-i.pipeline.ErrorChan()
		if ok {
			slog.Error(
				fmt.Sprintf("pipeline failed: %s\n", err),
			)
			os.Exit(1)
		}
	}()
	// Schedule periodic catch-up sync log messages
	i.scheduleSyncStatusLog()
	return nil
}

func (i *Indexer) handleEvent(evt event.Event) error {
	cfg := config.GetConfig()
	eventTx := evt.Payload.(input_chainsync.TransactionEvent)
	eventCtx := evt.Context.(input_chainsync.TransactionContext)
	for _, txOutput := range eventTx.Outputs {
		for _, profile := range config.GetProfiles() {
			if txOutput.Address().String() != profile.ScriptAddress {
				continue
			}
			datum := txOutput.Datum()
			if datum != nil {
				var dnsDomain models.CardanoDnsDomain
				if _, err := cbor.Decode(datum.Cbor(), &dnsDomain); err != nil {
					slog.Warn(
						fmt.Sprintf(
							"error decoding TX (%s) output datum: %s",
							eventCtx.TransactionHash,
							err,
						),
					)
					// Stop processing TX output if we can't parse the datum
					continue
				}
				origin := string(dnsDomain.Origin)
				// Convert origin to canonical form for consistency
				// This mostly means adding a trailing period if it doesn't have one
				domainName := dns.CanonicalName(origin)
				// We want an empty value for the TLD root for convenience
				if domainName == `.` {
					domainName = ``
				}
				// Append TLD
				domainName = dns.CanonicalName(
					domainName + profile.Tld,
				)
				if cfg.Indexer.Verify {
					// Look for asset matching domain origin and TLD policy ID
					if txOutput.Assets() == nil {
						slog.Warn(
							fmt.Sprintf(
								"ignoring datum for domain %q with no matching asset",
								domainName,
							),
						)
						continue
					}
					foundAsset := false
					for _, policyId := range txOutput.Assets().Policies() {
						for _, assetName := range txOutput.Assets().Assets(policyId) {
							if policyId.String() == profile.PolicyId {
								if string(assetName) == string(origin) {
									foundAsset = true
								} else {
									slog.Warn(
										fmt.Sprintf(
											"ignoring datum for domain %q with no matching asset",
											domainName,
										),
									)
								}
							} else {
								slog.Warn(
									fmt.Sprintf(
										"ignoring datum for domain %q with no matching asset",
										domainName,
									),
								)
							}
						}
					}
					if !foundAsset {
						continue
					}
					// Make sure all records are for specified origin domain
					badRecordName := false
					for _, record := range dnsDomain.Records {
						recordName := dns.CanonicalName(
							string(record.Lhs),
						)
						if !strings.HasSuffix(recordName, domainName) {
							slog.Warn(
								fmt.Sprintf(
									"ignoring datum with record %q outside of origin domain (%s)",
									recordName,
									domainName,
								),
							)
							badRecordName = true
							break
						}
					}
					if badRecordName {
						continue
					}
				}
				// Convert domain records into our storage format
				tmpRecords := []state.DomainRecord{}
				for _, record := range dnsDomain.Records {
					tmpRecord := state.DomainRecord{
						Lhs:  string(record.Lhs),
						Type: string(record.Type),
						Rhs:  string(record.Rhs),
					}
					if record.Ttl.HasValue() {
						tmpRecord.Ttl = int(record.Ttl.Value)
					}
					tmpRecords = append(tmpRecords, tmpRecord)
				}
				if err := state.GetState().UpdateDomain(domainName, tmpRecords); err != nil {
					return err
				}
				slog.Info(
					fmt.Sprintf(
						"found updated registration for domain: %s",
						domainName,
					),
				)
			}
		}
	}
	return nil
}

func (i *Indexer) scheduleSyncStatusLog() {
	i.syncLogTimer = time.AfterFunc(syncStatusLogInterval, i.syncStatusLog)
}

func (i *Indexer) syncStatusLog() {
	slog.Info(
		fmt.Sprintf(
			"catch-up sync in progress: at %d.%s (current tip slot is %d)",
			i.syncStatus.SlotNumber,
			i.syncStatus.BlockHash,
			i.syncStatus.TipSlotNumber,
		),
	)
	i.scheduleSyncStatusLog()
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

// TODO: remove the below once we switch adder to slog

// AdderLogger is a wrapper type to give our logger the expected interface
type AdderLogger struct{}

func NewAdderLogger() *AdderLogger {
	return &AdderLogger{}
}

func (a *AdderLogger) Infof(msg string, args ...any) {
	slog.Info(
		fmt.Sprintf(msg, args...),
	)
}

func (a *AdderLogger) Warnf(msg string, args ...any) {
	slog.Warn(
		fmt.Sprintf(msg, args...),
	)
}

func (a *AdderLogger) Debugf(msg string, args ...any) {
	slog.Debug(
		fmt.Sprintf(msg, args...),
	)
}

func (a *AdderLogger) Errorf(msg string, args ...any) {
	slog.Error(
		fmt.Sprintf(msg, args...),
	)
}

func (a *AdderLogger) Fatalf(msg string, args ...any) {
	slog.Error(
		fmt.Sprintf(msg, args...),
	)
	os.Exit(1)
}
