// Copyright 2023 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package config

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Logging  LoggingConfig `yaml:"logging"`
	Metrics  MetricsConfig `yaml:"metrics"`
	Dns      DnsConfig     `yaml:"dns"`
	Debug    DebugConfig   `yaml:"debug"`
	Indexer  IndexerConfig `yaml:"indexer"`
	State    StateConfig   `yaml:"state"`
	Tls      TlsConfig     `yaml:"tls"`
	Profiles []string      `yaml:"profiles" envconfig:"PROFILES"`
}

type LoggingConfig struct {
	Debug    bool `yaml:"debug"    envconfig:"LOGGING_DEBUG"`
	QueryLog bool `yaml:"queryLog" envconfig:"LOGGING_QUERY_LOG"`
}

type DnsConfig struct {
	ListenAddress    string   `yaml:"address"          envconfig:"DNS_LISTEN_ADDRESS"`
	ListenPort       uint     `yaml:"port"             envconfig:"DNS_LISTEN_PORT"`
	ListenTlsPort    uint     `yaml:"tlsPort"          envconfig:"DNS_LISTEN_TLS_PORT"`
	RecursionEnabled bool     `yaml:"recursionEnabled" envconfig:"DNS_RECURSION"`
	RootHints        string   `yaml:"rootHints"        envconfig:"DNS_ROOT_HINTS"`
	RootHintsFile    string   `yaml:"rootHintsFile"    envconfig:"DNS_ROOT_HINTS_FILE"`
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
	Network          string `yaml:"network"          envconfig:"INDEXER_NETWORK"`
	NetworkMagic     uint32 `yaml:"networkMagic"     envconfig:"INDEXER_NETWORK_MAGIC"`
	Address          string `yaml:"address"          envconfig:"INDEXER_TCP_ADDRESS"`
	SocketPath       string `yaml:"socketPath"       envconfig:"INDEXER_SOCKET_PATH"`
	InterceptHash    string `yaml:"interceptHash"    envconfig:"INDEXER_INTERCEPT_HASH"`
	InterceptSlot    uint64 `yaml:"interceptSlot"    envconfig:"INDEXER_INTERCEPT_SLOT"`
	Verify           bool   `yaml:"verify"           envconfig:"INDEXER_VERIFY"`
	HandshakeAddress string `yaml:"handshakeAddress" envconfig:"INDEXER_HANDSHAKE_ADDRESS"`
}

type StateConfig struct {
	Directory string `yaml:"dir" envconfig:"STATE_DIR"`
}

type TlsConfig struct {
	CertFilePath string `yaml:"certFilePath" envconfig:"TLS_CERT_FILE_PATH"`
	KeyFilePath  string `yaml:"keyFilePath"  envconfig:"TLS_KEY_FILE_PATH"`
}

//go:embed named.root
var defaultRootHints []byte

// Singleton config instance with default values
var globalConfig = &Config{
	Logging: LoggingConfig{
		QueryLog: true,
	},
	Dns: DnsConfig{
		ListenAddress: "",
		ListenPort:    8053,
		ListenTlsPort: 8853,
		RootHints:     string(defaultRootHints),
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
		Verify: true,
	},
	State: StateConfig{
		Directory: "./.state",
	},
	Profiles: []string{
		// NOTE: this is here because .ada wasn't added to the discovery address when it was originally deployed
		"ada-preprod",
		"auto-preprod",
	},
}

func Load(configFile string) (*Config, error) {
	// Load config file as YAML if provided
	if configFile != "" {
		buf, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
		err = yaml.Unmarshal(buf, globalConfig)
		if err != nil {
			return nil, fmt.Errorf("error parsing config file: %w", err)
		}
	}
	// Load config values from environment variables
	// We use "dummy" as the app name here to (mostly) prevent picking up env
	// vars that we hadn't explicitly specified in annotations above
	err := envconfig.Process("dummy", globalConfig)
	if err != nil {
		return nil, fmt.Errorf("error processing environment: %w", err)
	}
	// Check profiles
	availableProfiles := GetAvailableProfiles()
	var interceptSlot uint64
	var interceptHash string
	for _, profile := range globalConfig.Profiles {
		foundProfile := false
		for _, availableProfile := range availableProfiles {
			if profile == availableProfile {
				profileData := Profiles[profile]
				// Provide default network
				if profileData.Network != "" {
					if globalConfig.Indexer.Network == "" {
						globalConfig.Indexer.Network = profileData.Network
					} else {
						if globalConfig.Indexer.Network != profileData.Network {
							return nil, fmt.Errorf("conflicting networks configured: %s and %s", globalConfig.Indexer.Network, profileData.Network)
						}
					}
				}
				// Update intercept slot/hash if earlier than any other profiles so far
				if interceptSlot == 0 ||
					profileData.InterceptSlot < interceptSlot {
					interceptSlot = profileData.InterceptSlot
					interceptHash = profileData.InterceptHash
				}
				foundProfile = true
				break
			}
		}
		if !foundProfile {
			return nil, fmt.Errorf(
				"unknown profile: %s: available profiles: %s",
				profile,
				strings.Join(availableProfiles, ","),
			)
		}
	}
	// Provide default intercept point from profile(s)
	if globalConfig.Indexer.InterceptSlot == 0 ||
		globalConfig.Indexer.InterceptHash == "" {
		if interceptHash != "" && interceptSlot > 0 {
			globalConfig.Indexer.InterceptHash = interceptHash
			globalConfig.Indexer.InterceptSlot = interceptSlot
		}
	}
	// Load root hints
	if globalConfig.Dns.RootHintsFile != "" {
		hintsContent, err := os.ReadFile(globalConfig.Dns.RootHintsFile)
		if err != nil {
			return nil, err
		}
		globalConfig.Dns.RootHints = string(hintsContent)
	}
	return globalConfig, nil
}

// GetConfig returns the global config instance
func GetConfig() *Config {
	return globalConfig
}
