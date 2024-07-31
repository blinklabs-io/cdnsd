// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"

	_ "go.uber.org/automaxprocs"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/dns"
	"github.com/blinklabs-io/cdnsd/internal/indexer"
	"github.com/blinklabs-io/cdnsd/internal/logging"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/blinklabs-io/cdnsd/internal/version"
)

var cmdlineFlags struct {
	configFile string
}

func main() {
	flag.StringVar(
		&cmdlineFlags.configFile,
		"config",
		"",
		"path to config file to load",
	)
	flag.Parse()

	// Load config
	cfg, err := config.Load(cmdlineFlags.configFile)
	if err != nil {
		fmt.Printf("Failed to load config: %s\n", err)
		os.Exit(1)
	}

	// Configure logging
	logging.Setup()
	logger := logging.GetLogger()
	// Sync logger on exit
	defer func() {
		if err := logger.Sync(); err != nil {
			// We don't actually care about the error here, but we have to do something
			// to appease the linter
			return
		}
	}()

	logger.Info(
		fmt.Sprintf("cdnsd %s started", version.GetVersionString()),
	)

	// Load state
	if err := state.GetState().Load(); err != nil {
		logger.Fatalf("failed to load state: %s", err)
	}

	// Start debug listener
	if cfg.Debug.ListenPort > 0 {
		logger.Infof(
			"starting debug listener on %s:%d",
			cfg.Debug.ListenAddress,
			cfg.Debug.ListenPort,
		)
		go func() {
			err := http.ListenAndServe(
				fmt.Sprintf(
					"%s:%d",
					cfg.Debug.ListenAddress,
					cfg.Debug.ListenPort,
				),
				nil,
			)
			if err != nil {
				logger.Fatalf("failed to start debug listener: %s", err)
			}
		}()
	}

	// Start indexer
	if err := indexer.GetIndexer().Start(); err != nil {
		logger.Fatalf("failed to start indexer: %s", err)
	}

	// Start DNS listener
	logger.Infof(
		"starting DNS listener on %s:%d",
		cfg.Dns.ListenAddress,
		cfg.Dns.ListenPort,
	)
	if err := dns.Start(); err != nil {
		logger.Fatalf("failed to start DNS listener: %s", err)
	}

	// Wait forever
	select {}
}
