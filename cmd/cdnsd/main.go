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
	"strconv"
	"strings"
	"sync/atomic"
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

const (
	httpReadHeaderTimeout = 5 * time.Second
	httpReadTimeout       = 10 * time.Second
	httpWriteTimeout      = 10 * time.Second
	httpIdleTimeout       = 60 * time.Second
	maxHTTPHeaderBytes    = 1 << 20
)

type runtimeStatus struct {
	ready atomic.Bool
}

func (s *runtimeStatus) healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *runtimeStatus) readinessHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if !s.ready.Load() {
		http.Error(w, "not ready\n", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (s *runtimeStatus) setReady(ready bool) {
	s.ready.Store(ready)
}

func observabilityListenAddress(address string) string {
	if strings.TrimSpace(address) == "" {
		return "127.0.0.1"
	}
	return address
}

func httpListenAddress(address string, port uint) string {
	return net.JoinHostPort(
		observabilityListenAddress(address),
		strconv.FormatUint(uint64(port), 10),
	)
}

func newHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		ReadTimeout:       httpReadTimeout,
		WriteTimeout:      httpWriteTimeout,
		IdleTimeout:       httpIdleTimeout,
		MaxHeaderBytes:    maxHTTPHeaderBytes,
	}
}

func newMetricsMux(status *runtimeStatus) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", status.healthHandler)
	mux.HandleFunc("/readyz", status.readinessHandler)
	return mux
}

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
	status := &runtimeStatus{}
	var dnsSrv *dns.Server
	var debugSrv *http.Server
	var metricsSrv *http.Server
	shutdown := func() error {
		status.setReady(false)
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
		debugListenAddr := httpListenAddress(
			cfg.Debug.ListenAddress,
			cfg.Debug.ListenPort,
		)
		slog.Info("starting debug listener on " + debugListenAddr)
		debugSrv = newHTTPServer(debugListenAddr, http.DefaultServeMux)
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
		metricsListenAddr := httpListenAddress(
			cfg.Metrics.ListenAddress,
			cfg.Metrics.ListenPort,
		)
		slog.Info(
			"starting listener for prometheus metrics connections on " + metricsListenAddr,
		)
		metricsSrv = newHTTPServer(metricsListenAddr, newMetricsMux(status))
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
	status.setReady(true)

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
