package protocol

// Shapes only - constants & configs from hsd's protocol/networks.js.

import (
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	gen "github.com/blinklabs-io/cdnsd/internal/handshake/protocol/genesis"
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
	CoinType   uint32
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
	Genesis          gen.Net
	GenesisBlock     string
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
		if n.timeSource == nil {
			n.timeSource = &systemTime{}
		}
		var mask uint32
		for _, d := range n.Deploys {
			if d.Bit < 32 {
				mask |= (1 << d.Bit)
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

func (n *Network) ensureTime() {
	if n.timeSource == nil {
		n.timeSource = &systemTime{}
	}
}

func (n *Network) SetTimeSource(ts TimeSource) {
	n.timeSource = ts
}

func (n *Network) Now() time.Time {
	n.ensureTime()
	return n.timeSource.Now()
}

func (n *Network) Ms() int64 {
	n.ensureTime()
	return n.timeSource.Ms()
}

func bi(hex string) *big.Int {
	n := new(big.Int)
	if _, ok := n.SetString(hex, 16); !ok {
		panic("invalid hex for big.Int: " + hex)
	}
	return n
}

var Networks = map[NetworkType]*Network{
	Mainnet: mainNet(),
	Testnet: testNet(),
	Regtest: regTest(),
	Simnet:  simNet(),
}

func SelectNetwork(t NetworkType) *Network {
	return Networks[t]
}

func testNet() *Network {
	const (
		targetSpacing = uint32(10 * 60)
		targetWindow  = uint32(144)
	)
	blocksPerDay := uint32((24 * 60 * 60) / targetSpacing)
	targetTimespan := targetWindow * targetSpacing

	n := &Network{
		Type:  "testnet",
		Seeds: []string{"hs-testnet.bcoin.ninja"},
		Magic: 2974944722, // Need to modify from genesis.testnet.magic

		// TODO: Need to implement Genesis & GenesisBlock in genesis.go & import here.
		// Genesis:  "b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901",
		Port:         13038,
		BrontidePort: 45806,

		CheckpointMap:  map[uint32]string{},
		LastCheckpoint: 0,

		HalvingInterval:  170000,
		CoinbaseMaturity: 100,

		POW: POWParams{
			Limit:          bi("00000000ffff0000000000000000000000000000000000000000000000000000"),
			Bits:           0x1d00ffff,
			Chainwork:      bi("0000000000000000000000000000000000000000000000000000000000000000"),
			TargetWindow:   targetWindow,
			TargetSpacing:  targetSpacing,
			BlocksPerDay:   blocksPerDay,
			TargetTimespan: targetTimespan,
			MinActual:      targetTimespan / 4,
			MaxActual:      targetTimespan * 4,
			TargetReset:    true,
			NoRetargeting:  false,
		},

		Names: NamesParams{
			AuctionStart:      uint32(0.25 * float32(blocksPerDay)),
			RolloutInterval:   uint32(0.25 * float32(blocksPerDay)),
			LockupPeriod:      uint32(0.25 * float32(blocksPerDay)),
			RenewalWindow:     30 * blocksPerDay,
			RenewalPeriod:     7 * blocksPerDay,
			RenewalMaturity:   1 * blocksPerDay,
			ClaimPeriod:       90 * blocksPerDay,
			AlexaLockupPeriod: 180 * blocksPerDay,
			ClaimFrequency:    2 * blocksPerDay,
			BiddingPeriod:     1 * blocksPerDay,
			RevealPeriod:      2 * blocksPerDay,
			TreeInterval:      blocksPerDay >> 2,
			TransferLockup:    2 * blocksPerDay,
			AuctionMaturity:   (1 + 2 + 4) * blocksPerDay,
			NoRollout:         false,
			NoReserved:        false,
		},

		Block: BlockLimits{
			PruneAfterHeight: 1000,
			KeepBlocks:       10000,
			MaxTipAge:        12 * 60 * 60,
			SlowHeight:       0,
		},

		GoosigStop:          20 * blocksPerDay,
		ActivationThreshold: 1512,
		MinerWindow:         2016,

		Deployments: map[string]Deployment{
			"hardening":   {Name: "hardening", Bit: 0, StartTime: 1581638400, Timeout: 1707868800, Threshold: -1, Window: -1, Required: false, Force: false},
			"icannlockup": {Name: "icannlockup", Bit: 1, StartTime: 1691625600, Timeout: 1703980800, Threshold: -1, Window: -1, Required: false, Force: false},
			"airstop":     {Name: "airstop", Bit: 2, StartTime: 1751328000, Timeout: 1759881600, Threshold: -1, Window: -1, Required: false, Force: false},
			"testdummy":   {Name: "testdummy", Bit: 28, StartTime: 1199145601, Timeout: 1230767999, Threshold: -1, Window: -1, Required: false, Force: true},
		},
		Deploys: []Deployment{
			{Name: "hardening", Bit: 0, StartTime: 1581638400, Timeout: 1707868800, Threshold: -1, Window: -1, Required: false, Force: false},
			{Name: "icannlockup", Bit: 1, StartTime: 1691625600, Timeout: 1703980800, Threshold: -1, Window: -1, Required: false, Force: false},
			{Name: "airstop", Bit: 2, StartTime: 1751328000, Timeout: 1759881600, Threshold: -1, Window: -1, Required: false, Force: false},
			{Name: "testdummy", Bit: 28, StartTime: 1199145601, Timeout: 1230767999, Threshold: -1, Window: -1, Required: false, Force: true},
		},

		KeyPrefix: KeyPrefix{
			Privkey:    0xef,
			XPubKey:    0x043587cf,
			XPrivKey:   0x04358394,
			XPubKey58:  "tpub",
			XPrivKey58: "tprv",
			CoinType:   5354,
		},
		AddressPrefix:   "ts",
		ClaimPrefix:     "hns-testnet:",
		RequireStandard: false,

		RPCPort:    13037,
		WalletPort: 13039,
		NSPort:     15349,
		RSPort:     15350,

		MinRelay:   1000,
		FeeRate:    20000,
		MaxFeeRate: 60000,

		IdentityKeyHex: "",
		SelfConnect:    false,
		RequestMempool: true,

		DeflationHeight: 0,
		TxStartHeight:   0,
	}
	n.ensureTime()
	n.init()
	return n
}

func mainNet() *Network {
	const (
		targetSpacing = uint32(10 * 60) // 10 minutes
		targetWindow  = uint32(144)
	)
	blocksPerDay := uint32((24 * 60 * 60) / targetSpacing)
	targetTimespan := targetWindow * targetSpacing

	n := &Network{
		Type:         "main",
		Seeds:        []string{"hs-mainnet.bcoin.ninja", "seed.htools.work"},
		Magic:        gen.Main.Magic,
		Genesis:      gen.Main,
		GenesisBlock: gen.Maindata,
		Port:         12038,
		BrontidePort: 44806,

		CheckpointMap: map[uint32]string{
			1008:   "0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e",
			2016:   "0000000000000424ee6c2a5d6e0da5edfc47a4a10328c1792056ee48303c3e40",
			10000:  "00000000000001a86811a6f520bf67cefa03207dc84fd315f58153b28694ec51",
			20000:  "0000000000000162c7ac70a582256f59c189b5c90d8e9861b3f374ed714c58de",
			30000:  "0000000000000004f790862846b23c3a81585aea0fa79a7d851b409e027bcaa7",
			40000:  "0000000000000002966206a40b10a575cb46531253b08dae8e1b356cfa277248",
			50000:  "00000000000000020c7447e7139feeb90549bfc77a7f18d4ff28f327c04f8d6e",
			56880:  "0000000000000001d4ef9ea6908bb4eb970d556bd07cbd7d06a634e1cd5bbf4e",
			61043:  "00000000000000015b84385e0307370f8323420eaa27ef6e407f2d3162f1fd05",
			100000: "000000000000000136d7d3efa688072f40d9fdd71bd47bb961694c0f38950246",
			130000: "0000000000000005ee5106df9e48bcd232a1917684ac344b35ddd9b9e4101096",
			160000: "00000000000000021e723ce5aedc021ab4f85d46a6914e40148f01986baa46c9",
			200000: "000000000000000181ebc18d6c34442ffef3eedca90c57ca8ecc29016a1cfe16",
			225000: "00000000000000021f0be013ebad018a9ef97c8501766632f017a778781320d5",
			258026: "0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95",
		},
		LastCheckpoint: 258026,

		HalvingInterval:  170000,
		CoinbaseMaturity: 100,

		POW: POWParams{
			Limit:          bi("0000000000ffff00000000000000000000000000000000000000000000000000"),
			Bits:           0x1c00ffff,
			Chainwork:      bi("00000000000000000000000000000000000000000000000075b5a2b7bf522d45"),
			TargetWindow:   targetWindow,
			TargetSpacing:  targetSpacing,
			BlocksPerDay:   blocksPerDay,
			TargetTimespan: targetTimespan,
			MinActual:      targetTimespan / 4,
			MaxActual:      targetTimespan * 4,
			TargetReset:    false,
			NoRetargeting:  false,
		},

		Names: NamesParams{
			AuctionStart:      14 * blocksPerDay,
			RolloutInterval:   7 * blocksPerDay,
			LockupPeriod:      30 * blocksPerDay,
			RenewalWindow:     (2 * 365) * blocksPerDay,
			RenewalPeriod:     182 * blocksPerDay,
			RenewalMaturity:   30 * blocksPerDay,
			ClaimPeriod:       (4 * 365) * blocksPerDay,
			AlexaLockupPeriod: (8 * 365) * blocksPerDay,
			ClaimFrequency:    2 * blocksPerDay,
			BiddingPeriod:     5 * blocksPerDay,
			RevealPeriod:      10 * blocksPerDay,
			TreeInterval:      blocksPerDay >> 2,
			TransferLockup:    2 * blocksPerDay,
			AuctionMaturity:   (5 + 10 + 14) * blocksPerDay,
			NoRollout:         false,
			NoReserved:        false,
		},

		Block: BlockLimits{
			PruneAfterHeight: 1000,
			KeepBlocks:       288,
			MaxTipAge:        12 * 60 * 60,
			SlowHeight:       0,
		},

		GoosigStop:          (365 + 30) * blocksPerDay,
		ActivationThreshold: 1916,
		MinerWindow:         2016,

		Deployments: map[string]Deployment{
			"hardening":   {Name: "hardening", Bit: 0, StartTime: 1581638400, Timeout: 1707868800, Threshold: -1, Window: -1, Required: false, Force: false},
			"icannlockup": {Name: "icannlockup", Bit: 1, StartTime: 1691625600, Timeout: 1703980800, Threshold: -1, Window: -1, Required: false, Force: false},
			"airstop":     {Name: "airstop", Bit: 2, StartTime: 1751328000, Timeout: 1759881600, Threshold: -1, Window: -1, Required: false, Force: false},
			"testdummy":   {Name: "testdummy", Bit: 28, StartTime: 1199145601, Timeout: 1230767999, Threshold: -1, Window: -1, Required: false, Force: true},
		},
		Deploys: []Deployment{
			{Name: "hardening", Bit: 0, StartTime: 1581638400, Timeout: 1707868800, Threshold: -1, Window: -1, Required: false, Force: false},
			{Name: "icannlockup", Bit: 1, StartTime: 1691625600, Timeout: 1703980800, Threshold: -1, Window: -1, Required: false, Force: false},
			{Name: "airstop", Bit: 2, StartTime: 1751328000, Timeout: 1759881600, Threshold: -1, Window: -1, Required: false, Force: false},
			{Name: "testdummy", Bit: 28, StartTime: 1199145601, Timeout: 1230767999, Threshold: -1, Window: -1, Required: false, Force: true},
		},

		KeyPrefix: KeyPrefix{
			Privkey:    0x80,
			XPubKey:    0x0488b21e,
			XPrivKey:   0x0488ade4,
			XPubKey58:  "xpub",
			XPrivKey58: "xprv",
			CoinType:   5353,
		},
		AddressPrefix:   "hs",
		ClaimPrefix:     "hns-claim:",
		RequireStandard: true,

		RPCPort:    12037,
		WalletPort: 12039,
		NSPort:     5349,
		RSPort:     5350,

		MinRelay:   1000,
		FeeRate:    100000,
		MaxFeeRate: 400000,

		IdentityKeyHex: "",
		SelfConnect:    false,
		RequestMempool: true,

		DeflationHeight: 61043,
		TxStartHeight:   14 * blocksPerDay,
	}
	n.ensureTime()
	n.init()
	return n
}

func regTest() *Network {
	// Need to implement
	return &Network{}
}

func simNet() *Network {
	// Need to implement
	return &Network{}
}
