// Copyright 2023 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package config

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Logging LoggingConfig `yaml:"logging"`
	Metrics MetricsConfig `yaml:"metrics"`
	Dns     DnsConfig     `yaml:"dns"`
	Debug   DebugConfig   `yaml:"debug"`
	Indexer IndexerConfig `yaml:"indexer"`
	State   StateConfig   `yaml:"state"`
	Profile string        `yaml:"profile" envconfig:"PROFILE"`
}

type LoggingConfig struct {
	Healthchecks bool   `yaml:"healthchecks" envconfig:"LOGGING_HEALTHCHECKS"`
	Level        string `yaml:"level"        envconfig:"LOGGING_LEVEL"`
	QueryLog     bool   `yaml:"queryLog"     envconfig:"LOGGING_QUERY_LOG"`
}

type DnsConfig struct {
	ListenAddress    string   `yaml:"address"          envconfig:"DNS_LISTEN_ADDRESS"`
	ListenPort       uint     `yaml:"port"             envconfig:"DNS_LISTEN_PORT"`
	RecursionEnabled bool     `yaml:"recursionEnabled" envconfig:"DNS_RECURSION"`
	FallbackServers  []string `yaml:"fallbackServers"  envconfig:"DNS_FALLBACK_SERVERS"`
}

type DebugConfig struct {
	ListenAddress string `yaml:"address" envconfig:"DEBUG_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"DEBUG_PORT"`
}

type MetricsConfig struct {
	ListenAddress string `yaml:"address" envconfig:"METRICS_LISTEN_ADDRESS"`
	ListenPort    uint   `yaml:"port"    envconfig:"METRICS_LISTEN_PORT"`
}

type IndexerConfig struct {
	Network       string `yaml:"network"       envconfig:"INDEXER_NETWORK"`
	NetworkMagic  uint32 `yaml:"networkMagic"  envconfig:"INDEXER_NETWORK_MAGIC"`
	Address       string `yaml:"address"       envconfig:"INDEXER_TCP_ADDRESS"`
	SocketPath    string `yaml:"socketPath"    envconfig:"INDEXER_SOCKET_PATH"`
	ScriptAddress string `yaml:"scriptAddress" envconfig:"INDEXER_SCRIPT_ADDRESS"`
	InterceptHash string `yaml:"interceptHash" envconfig:"INDEXER_INTERCEPT_HASH"`
	InterceptSlot uint64 `yaml:"interceptSlot" envconfig:"INDEXER_INTERCEPT_SLOT"`
	Tld           string `yaml:"tld" envconfig:"INDEXER_TLD"`
	PolicyId      string `yaml:"policyId" envconfig:"INDEXER_POLICY_ID"`
	Verify        bool   `yaml:"verify" envconfig:"INDEXER_VERIFY"`
}

type StateConfig struct {
	Directory string `yaml:"dir" envconfig:"STATE_DIR"`
}

// Singleton config instance with default values
var globalConfig = &Config{
	Logging: LoggingConfig{
		Level:        "info",
		Healthchecks: false,
		QueryLog:     true,
	},
	Dns: DnsConfig{
		ListenAddress: "",
		ListenPort:    8053,
		// hdns.io
		FallbackServers: []string{
			"103.196.38.38",
			"103.196.38.39",
			"103.196.38.40",
		},
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
		Verify:  true,
	},
	State: StateConfig{
		Directory: "./.state",
	},
	Profile: "cardano-preprod-testing",
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
	// Check profile
	profile, ok := Profiles[globalConfig.Profile]
	if !ok {
		return nil, fmt.Errorf("unknown profile: %s", globalConfig.Profile)
	}
	// Provide default network
	if globalConfig.Indexer.Network != "" {
		if profile.Network != "" {
			globalConfig.Indexer.Network = profile.Network
		} else {
			return nil, fmt.Errorf("no built-in network name for specified profile, please provide one")
		}
	}
	// Provide default script address from profile
	if globalConfig.Indexer.ScriptAddress == "" {
		if profile.ScriptAddress != "" {
			globalConfig.Indexer.ScriptAddress = profile.ScriptAddress
		} else {
			return nil, fmt.Errorf("no built-in script address for specified profile, please provide one")
		}
	}
	// Provide default intercept point from profile
	if globalConfig.Indexer.InterceptSlot == 0 || globalConfig.Indexer.InterceptHash == "" {
		if profile.InterceptHash != "" && profile.InterceptSlot > 0 {
			globalConfig.Indexer.InterceptHash = profile.InterceptHash
			globalConfig.Indexer.InterceptSlot = profile.InterceptSlot
		}
	}
	// Provide default TLD and Policy ID from profile
	if globalConfig.Indexer.Tld == "" || globalConfig.Indexer.PolicyId == "" {
		if profile.Tld != "" && profile.PolicyId != "" {
			globalConfig.Indexer.Tld = profile.Tld
			globalConfig.Indexer.PolicyId = profile.PolicyId
		} else {
			return nil, fmt.Errorf("no built-in TLD and/or policy ID for specified profile, please provide one")
		}
	}
	return globalConfig, nil
}

// GetConfig returns the global config instance
func GetConfig() *Config {
	return globalConfig
}
