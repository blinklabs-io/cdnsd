// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof" // #nosec G108
	"os"
	"os/signal"
	"syscall"
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

const shutdownTimeout = 15 * time.Second

func slogPrintf(format string, v ...any) {
	slog.Info(fmt.Sprintf(format, v...))
}

func main() {
	os.Exit(run())
}

func run() int {
	flag.StringVar(
		&cmdlineFlags.configFile,
		"config",
		"",
		"path to config file to load",
	)
	flag.Parse()

	signalCtx, stopSignals := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stopSignals()
	signalReceived := func() bool {
		select {
		case <-signalCtx.Done():
			return true
		default:
			return false
		}
	}

	// Load config
	cfg, err := config.Load(cmdlineFlags.configFile)
	if err != nil {
		fmt.Printf("Failed to load config: %s\n", err)
		return 1
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
		return 1
	}

	slog.Info(
		fmt.Sprintf("cdnsd %s started", version.GetVersionString()),
	)

	// Load state
	stateStore := state.GetState()
	if err := stateStore.Load(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to load state: %s", err),
		)
		return 1
	}

	asyncErrCh := make(chan error, 8)
	indexerSvc := indexer.GetIndexer()
	var dnsSrv *dns.Server
	var debugSrv *http.Server
	var metricsSrv *http.Server
	shutdown := func() error {
		shutdownCtx, cancel := context.WithTimeout(
			context.Background(),
			shutdownTimeout,
		)
		defer cancel()
		return shutdownServices(
			shutdownCtx,
			dnsSrv,
			debugSrv,
			metricsSrv,
			indexerSvc,
			stateStore,
		)
	}
	shutdownAfterSignal := func() int {
		slog.Info("shutdown signal received")
		stopSignals()
		if err := shutdown(); err != nil {
			slog.Error("shutdown failed", "error", err)
			return 1
		}
		return 0
	}
	if signalReceived() {
		return shutdownAfterSignal()
	}

	// Start debug listener
	if cfg.Debug.ListenPort > 0 {
		debugListenAddr := fmt.Sprintf(
			"%s:%d",
			cfg.Debug.ListenAddress,
			cfg.Debug.ListenPort,
		)
		slog.Info(
			fmt.Sprintf(
				"starting debug listener on %s:%d",
				cfg.Debug.ListenAddress,
				cfg.Debug.ListenPort,
			),
		)
		debugSrv = &http.Server{
			Addr:              debugListenAddr,
			ReadHeaderTimeout: 60 * time.Second,
		}
		if err := startHTTPServer("debug", debugSrv, asyncErrCh); err != nil {
			slog.Error(err.Error())
			_ = shutdown()
			return 1
		}
		if signalReceived() {
			return shutdownAfterSignal()
		}
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
		metricsSrv = &http.Server{
			Addr:         metricsListenAddr,
			WriteTimeout: 10 * time.Second,
			ReadTimeout:  10 * time.Second,
			Handler:      metricsMux,
		}
		if err := startHTTPServer("metrics", metricsSrv, asyncErrCh); err != nil {
			slog.Error(err.Error())
			_ = shutdown()
			return 1
		}
		if signalReceived() {
			return shutdownAfterSignal()
		}
	}

	// Start indexer
	if err := indexerSvc.Start(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start indexer: %s", err),
		)
		_ = shutdown()
		return 1
	}
	if signalReceived() {
		return shutdownAfterSignal()
	}

	// Start DNS listener
	dnsSrv, err = dns.Start()
	if err != nil {
		slog.Error(
			fmt.Sprintf("failed to start DNS listener: %s", err),
		)
		_ = shutdown()
		return 1
	}
	if signalReceived() {
		return shutdownAfterSignal()
	}

	var runtimeErr error
	select {
	case <-signalCtx.Done():
		slog.Info("shutdown signal received")
	case err := <-asyncErrCh:
		runtimeErr = err
		slog.Error("runtime failure", "error", err)
	case err := <-indexerSvc.Errors():
		runtimeErr = err
		slog.Error("runtime failure", "error", err)
	case err := <-dnsSrv.Errors():
		runtimeErr = err
		slog.Error("runtime failure", "error", err)
	}
	stopSignals()

	if err := shutdown(); err != nil {
		slog.Error("shutdown failed", "error", err)
		if runtimeErr == nil {
			runtimeErr = err
		}
	}
	if runtimeErr != nil {
		return 1
	}
	return 0
}

func startHTTPServer(
	name string,
	srv *http.Server,
	errCh chan<- error,
) error {
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("failed to start %s listener: %w", name, err)
	}
	go func() {
		if err := srv.Serve(listener); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			reportAsyncErr(
				errCh,
				fmt.Errorf("%s listener failed: %w", name, err),
			)
		}
	}()
	return nil
}

func reportAsyncErr(errCh chan<- error, err error) {
	select {
	case errCh <- err:
	default:
		slog.Error("runtime failure", "error", err)
	}
}

func shutdownServices(
	ctx context.Context,
	dnsSrv *dns.Server,
	debugSrv *http.Server,
	metricsSrv *http.Server,
	indexerSvc *indexer.Indexer,
	stateStore *state.State,
) error {
	var errs []error
	if dnsSrv != nil {
		if err := dnsSrv.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop DNS listener: %w", err))
		}
	}
	if debugSrv != nil {
		if err := debugSrv.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop debug listener: %w", err))
		}
	}
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stop metrics listener: %w", err))
		}
	}
	if indexerSvc != nil {
		if err := indexerSvc.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("stop indexer: %w", err))
		}
	}
	if stateStore != nil {
		if err := stateStore.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close state: %w", err))
		}
	}
	return errors.Join(errs...)
}
