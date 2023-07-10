package config

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

// Per-network script address for Handshake
var networkScriptAddresses = map[string]string{
	"preprod": "addr_test1wqhlsl9dsny9d2hdc9uyx4ktj0ty0s8kxev4y9futq4qt4s5anczn",
}

// Per-network intercept points for starting the chain-sync
// We start the sync somewhere near where we expect the first data to appear to save time
// during the initial sync
var networkInterceptPoints = map[string]struct {
	Hash string
	Slot uint64
}{
	"preprod": {
		Hash: "f5366caf6cc87383a33fece0968c3c8c3b25ec496829ab3ba324f7dce5a89c5d",
		Slot: 29852950,
	},
}

type Config struct {
	Logging LoggingConfig `yaml:"logging"`
	Metrics MetricsConfig `yaml:"metrics"`
	Dns     DnsConfig     `yaml:"dns"`
	Debug   DebugConfig   `yaml:"debug"`
	Indexer IndexerConfig `yaml:"indexer"`
}

type LoggingConfig struct {
	Healthchecks bool   `yaml:"healthchecks" envconfig:"LOGGING_HEALTHCHECKS"`
	Level        string `yaml:"level" envconfig:"LOGGING_LEVEL"`
}

type DnsConfig struct {
	ListenAddress string `yaml:"address" envconfig:"DNS_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port" envconfig:"DNS_LISTEN_PORT"`
}

type DebugConfig struct {
	ListenAddress string `yaml:"address" envconfig:"DEBUG_ADDRESS"`
	ListenPort    uint   `yaml:"port" envconfig:"DEBUG_PORT"`
}

type MetricsConfig struct {
	ListenAddress string `yaml:"address" envconfig:"METRICS_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port" envconfig:"METRICS_LISTEN_PORT"`
}

type IndexerConfig struct {
	Network       string `yaml:"network" envconfig:"INDEXER_NETWORK"`
	NetworkMagic  uint32 `yaml:"networkMagic" envconfig:"INDEXER_NETWORK_MAGIC"`
	Address       string `yaml:"address" envconfig:"INDEXER_TCP_ADDRESS"`
	SocketPath    string `yaml:"socketPath" envconfig:"INDEXER_SOCKET_PATH"`
	ScriptAddress string `yaml:"scriptAddress" envconfig:"INDEXER_SCRIPT_ADDRESS"`
	InterceptHash string `yaml:"interceptHash" envconfig:"INDEXER_INTERCEPT_HASH"`
	InterceptSlot uint64 `yaml:"interceptSlot" envconfig:"INDEXER_INTERCEPT_SLOT"`
}

// Singleton config instance with default values
var globalConfig = &Config{
	Logging: LoggingConfig{
		Level:        "info",
		Healthchecks: false,
	},
	Dns: DnsConfig{
		ListenAddress: "",
		ListenPort:    8053,
	},
	Debug: DebugConfig{
		ListenAddress: "localhost",
		ListenPort:    0,
	},
	Metrics: MetricsConfig{
		ListenAddress: "",
		ListenPort:    8081,
	},
	Indexer: IndexerConfig{
		Network: "preprod",
	},
}

func Load(configFile string) (*Config, error) {
	// Load config file as YAML if provided
	if configFile != "" {
		buf, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("error reading config file: %s", err)
		}
		err = yaml.Unmarshal(buf, globalConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing config file: %s", err)
		}
	}
	// Load config values from environment variables
	// We use "dummy" as the app name here to (mostly) prevent picking up env
	// vars that we hadn't explicitly specified in annotations above
	err := envconfig.Process("dummy", globalConfig)
	if err != nil {
		return nil, fmt.Errorf("error processing environment: %s", err)
	}
	// Provide default script address for named network
	if scriptAddress, ok := networkScriptAddresses[globalConfig.Indexer.Network]; ok {
		globalConfig.Indexer.ScriptAddress = scriptAddress
	} else {
		return nil, fmt.Errorf("no built-in script address for specified network, please provide one")
	}
	// Provide default intercept point for named network
	if interceptPoint, ok := networkInterceptPoints[globalConfig.Indexer.Network]; ok {
		globalConfig.Indexer.InterceptHash = interceptPoint.Hash
		globalConfig.Indexer.InterceptSlot = interceptPoint.Slot
	}
	return globalConfig, nil
}

// GetConfig returns the global config instance
func GetConfig() *Config {
	return globalConfig
}
