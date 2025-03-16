// Copyright 2025 Blink Labs Software
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
	_ "net/http/pprof" // #nosec G108
	"os"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/dns"
	"github.com/blinklabs-io/cdnsd/internal/indexer"
	"github.com/blinklabs-io/cdnsd/internal/logging"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/blinklabs-io/cdnsd/internal/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/automaxprocs/maxprocs"
)

var cmdlineFlags struct {
	configFile string
}

func slogPrintf(format string, v ...any) {
	slog.Info(fmt.Sprintf(format, v...))
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
	logging.Configure()
	logger := logging.GetLogger()
	slog.SetDefault(logger)

	// Configure max processes with our logger wrapper, toss undo func
	_, err = maxprocs.Set(maxprocs.Logger(slogPrintf))
	if err != nil {
		// If we hit this, something really wrong happened
		logger.Error(err.Error())
		os.Exit(1)
	}

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
			debugger := &http.Server{
				Addr: fmt.Sprintf(
					"%s:%d",
					cfg.Debug.ListenAddress,
					cfg.Debug.ListenPort,
				),
				ReadHeaderTimeout: 60 * time.Second,
			}
			err := debugger.ListenAndServe()
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
			"starting listener for prometheus metrics connections on " + metricsListenAddr,
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
	if err := dns.Start(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start DNS listener: %s", err),
		)
		os.Exit(1)
	}

	// Wait forever
	select {}
}
