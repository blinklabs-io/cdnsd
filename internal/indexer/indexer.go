package indexer

import (
	"encoding/hex"

	"github.com/blinklabs-io/chnsd/internal/config"
	"github.com/blinklabs-io/chnsd/internal/logging"

	"github.com/blinklabs-io/gouroboros/cbor"
	ocommon "github.com/blinklabs-io/gouroboros/protocol/common"
	"github.com/blinklabs-io/snek/event"
	filter_chainsync "github.com/blinklabs-io/snek/filter/chainsync"
	filter_event "github.com/blinklabs-io/snek/filter/event"
	input_chainsync "github.com/blinklabs-io/snek/input/chainsync"
	output_embedded "github.com/blinklabs-io/snek/output/embedded"
	"github.com/blinklabs-io/snek/pipeline"
	"github.com/miekg/dns"
)

type Domain struct {
	name    string
	records map[string]map[string][]DomainRecord
}

type DomainRecord struct {
	Name  string
	Value string
}

type Indexer struct {
	pipeline *pipeline.Pipeline
	domains  map[string]Domain
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
		//input_chainsync.WithIntersectTip(true),
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
	if cfg.Indexer.InterceptHash != "" && cfg.Indexer.InterceptSlot > 0 {
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
		filter_event.WithType("chainsync.transaction"),
	)
	i.pipeline.AddFilter(filterEvent)
	// We only care about transactions on a certain address
	filterChainsync := filter_chainsync.New(
		filter_chainsync.WithAddress(cfg.Indexer.ScriptAddress),
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
	for _, txOutput := range eventTx.Outputs {
		datum := txOutput.Datum()
		if datum != nil {
			if _, err := datum.Decode(); err != nil {
				logger.Warnf("error decoding TX (%s) output datum: %s", eventTx.TransactionHash, err)
				return err
			}
			datumFields := datum.Value().(cbor.Constructor).Fields()
			domainName := string(datumFields[0].(cbor.ByteString).Bytes()) + `.`
			for _, record := range datumFields[1].([]any) {
				nameServer := string(record.(cbor.ByteString).Bytes()) + `.`
				// Create NS record for domain
				i.addRecord(domainName, domainName, "NS", nameServer)
				// Create A record for name server
				// We use a dummy IP address for now, since the on-chain data doesn't contain the IP yet
				i.addRecord(domainName, nameServer, "A", "1.2.3.4")
			}
			logger.Infof("found updated registration for domain: %s", domainName)
		}
	}
	return nil
}

func (i *Indexer) LookupRecords(name string, recordType string) []DomainRecord {
	for domainName, domain := range i.domains {
		if dns.IsSubDomain(domainName, name) {
			if records, ok := domain.records[name]; ok {
				if record, ok := records[recordType]; ok {
					return record
				} else {
					return nil
				}
			} else {
				return nil
			}
		}
	}
	return nil
}

func (i *Indexer) addRecord(domainName string, recordName string, recordType string, value string) {
	// Create initial domain record
	if _, ok := i.domains[domainName]; !ok {
		i.domains[domainName] = Domain{
			name:    domainName,
			records: make(map[string]map[string][]DomainRecord),
		}
	}
	// Create initial list for record type
	if _, ok := i.domains[domainName].records[recordName]; !ok {
		i.domains[domainName].records[recordName] = make(map[string][]DomainRecord)
		if _, ok := i.domains[domainName].records[recordName][recordType]; !ok {
			i.domains[domainName].records[recordName][recordType] = make([]DomainRecord, 0)
		}
	}
	// Create record
	i.domains[domainName].records[recordName][recordType] = append(
		i.domains[domainName].records[recordName][recordType],
		DomainRecord{
			Name:  recordName,
			Value: value,
		},
	)
}

// GetIndexer returns the global indexer instance
func GetIndexer() *Indexer {
	return globalIndexer
}
