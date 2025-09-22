package protocol

// Shapes only: constants & configs from hsd's protocol/networks.js.
// No sockets, no consensus logic.

import (
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"
)

type NetworkType string

const (
	Mainnet NetworkType = "main"
	Testnet NetworkType = "testnet"
	Regtest NetworkType = "regtest"
	Simnet  NetworkType = "simnet"
)

type TimeSource interface {
	Now() time.Time
	Ms() int64
}

type systemTime struct{}

func (t *systemTime) Now() time.Time {
	return time.Now()
}

func (t *systemTime) Ms() int64 {
	return time.Now().UnixMilli()
}

type Checkpoint struct {
	Height uint32
	Hash   string
}

type Deployment struct {
	Name      string
	Bit       uint32
	StartTime uint32
	Timeout   uint32
	Threshold int32
	Window    int32
	Required  bool
	Force     bool
}

type KeyPrefix struct {
	Privkey    uint32
	XPubKey    uint32
	XPrivKey   uint32
	XPubKey58  string
	XPrivKey58 string
}

type POWParams struct {
	Limit          *big.Int
	Bits           uint32
	Chainwork      *big.Int
	TargetWindow   uint32
	TargetSpacing  uint32
	BlocksPerDay   uint32
	TargetTimespan uint32
	MinActual      uint32
	MaxActual      uint32
	TargetReset    bool
	NoRetargeting  bool
}

type BlockLimits struct {
	PruneAfterHeight uint32
	KeepBlocks       uint32
	MaxTipAge        uint32
	SlowHeight       uint32
}

type NamesParams struct {
	AuctionStart      uint32
	RolloutInterval   uint32
	LockupPeriod      uint32
	RenewalWindow     uint32
	RenewalPeriod     uint32
	RenewalMaturity   uint32
	ClaimPeriod       uint32
	AlexaLockupPeriod uint32
	ClaimFrequency    uint32
	BiddingPeriod     uint32
	RevealPeriod      uint32
	TreeInterval      uint32
	TransferLockup    uint32
	AuctionMaturity   uint32
	NoRollout         bool
	NoReserved        bool
}

type Network struct {
	Type           string
	Seeds          []string
	Magic          uint32
	Port           uint16
	BrontidePort   uint16
	CheckpointMap  map[uint32]string
	LastCheckpoint uint32
	Checkpoints    []Checkpoint

	HalvingInterval  uint32
	CoinbaseMaturity uint32
	GenesisHash      string
	GenesisBlockHex  string
	UnknownBitsMask  uint32

	POW        POWParams
	Names      NamesParams
	GoosigStop uint32
	Block      BlockLimits

	ActivationThreshold uint32
	MinerWindow         uint32

	Deployments map[string]Deployment
	Deploys     []Deployment

	KeyPrefix     KeyPrefix
	AddressPrefix string
	ClaimPrefix   string

	RequireStandard bool
	MinRelay        uint32
	FeeRate         uint32
	MaxFeeRate      uint32

	RPCPort    uint16
	WalletPort uint16
	NSPort     uint16
	RSPort     uint16

	IdentityKeyHex string
	SelfConnect    bool
	RequestMempool bool

	DeflationHeight uint32
	TxStartHeight   uint32
	timeSource      TimeSource
	onceInit        sync.Once
}

func (n *Network) init() {
	n.onceInit.Do(func() {
		var mask uint32
		for _, d := range n.Deploys {
			if d.Bit >= 0 && d.Bit < 32 {
				mask |= (1 << uint32(d.Bit))
			}
		}
		n.UnknownBitsMask = ^mask
		n.Checkpoints = n.checkpointsFromMap()
		sort.Slice(n.Checkpoints, func(i, j int) bool {
			return n.Checkpoints[i].Height < n.Checkpoints[j].Height
		})
	})
}

func (n *Network) checkpointsFromMap() []Checkpoint {
	if len(n.CheckpointMap) == 0 {
		return nil
	}
	out := make([]Checkpoint, 0, len(n.CheckpointMap))
	for h, hash := range n.CheckpointMap {
		out = append(out, Checkpoint{Height: h, Hash: strings.ToLower(hash)})
	}
	return out
}

func (n *Network) ByBit(bit uint32) *Deployment {
	for i := range n.Deploys {
		if n.Deploys[i].Bit == bit {
			return &n.Deploys[i]
		}
	}
	return nil
}

func (n *Network) Now() time.Time {
	return n.timeSource.Now()
}

func (n *Network) Ms() int64 {
	return n.timeSource.Ms()
}
