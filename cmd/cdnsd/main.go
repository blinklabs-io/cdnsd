// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	_ "go.uber.org/automaxprocs"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/dns"
	"github.com/blinklabs-io/cdnsd/internal/indexer"
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

	// Configure logger
	logLevel := slog.LevelInfo
	if cfg.Logging.Debug {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(
		slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: logLevel,
		}),
	)
	slog.SetDefault(logger)

	slog.Info(
		fmt.Sprintf("cdnsd %s started", version.GetVersionString()),
	)

	// Load state
	if err := state.GetState().Load(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to load state: %s", err),
		)
		os.Exit(1)
	}

	// Start debug listener
	if cfg.Debug.ListenPort > 0 {
		slog.Info(
			fmt.Sprintf(
				"starting debug listener on %s:%d",
				cfg.Debug.ListenAddress,
				cfg.Debug.ListenPort,
			),
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
				slog.Error(
					fmt.Sprintf("failed to start debug listener: %s", err),
				)
				os.Exit(1)
			}
		}()
	}

	// Start metrics listener
	if cfg.Metrics.ListenPort > 0 {
		metricsListenAddr := fmt.Sprintf(
			"%s:%d",
			cfg.Metrics.ListenAddress,
			cfg.Metrics.ListenPort,
		)
		slog.Info(
			fmt.Sprintf(
				"starting listener for prometheus metrics connections on %s",
				metricsListenAddr,
			),
		)
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		metricsSrv := &http.Server{
			Addr:         metricsListenAddr,
			WriteTimeout: 10 * time.Second,
			ReadTimeout:  10 * time.Second,
			Handler:      metricsMux,
		}
		go func() {
			if err := metricsSrv.ListenAndServe(); err != nil {
				slog.Error(
					fmt.Sprintf("failed to start metrics listener: %s", err),
				)
				os.Exit(1)
			}
		}()
	}

	// Start indexer
	if err := indexer.GetIndexer().Start(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start indexer: %s", err),
		)
		os.Exit(1)
	}

	// Start DNS listener
	slog.Info(
		fmt.Sprintf(
			"starting DNS listener on %s:%d",
			cfg.Dns.ListenAddress,
			cfg.Dns.ListenPort,
		),
	)
	if err := dns.Start(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start DNS listener: %s", err),
		)
		os.Exit(1)
	}

	// Wait forever
	select {}
}
