// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var errMaxReferralDepth = errors.New(
	"maximum referral depth reached",
)

var metricQueryTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "dns_query_total",
	Help: "total DNS queries handled",
})

// Resolver handles DNS queries using configured root hints for
// recursive resolution.
type Resolver struct {
	rootHints         map[uint16]map[string][]dns.RR
	dnssecEnabled     bool
	trustAnchors      map[string][]dns.RR
	rootAnchorManager *rootAnchorManager
	recursionNetworks []*net.IPNet
}

// NewResolver creates a resolver from the provided config.
func NewResolver(cfg *config.Config) (*Resolver, error) {
	resolver := &Resolver{
		dnssecEnabled: cfg.Dns.DNSSEC.Enabled,
	}
	var err error
	resolver.recursionNetworks, err = parseRecursionAllowlist(
		cfg.Dns.RecursionAllowlist,
	)
	if err != nil {
		return nil, err
	}
	if err := resolver.loadRootHints(cfg); err != nil {
		return nil, err
	}
	if err := resolver.loadTrustAnchors(cfg); err != nil {
		return nil, err
	}
	if resolver.dnssecEnabled {
		resolver.rootAnchorManager = newRootAnchorManager(resolver, cfg)
	}
	return resolver, nil
}

// resolutionContext tracks state during recursive DNS resolution
// to prevent infinite loops and limit recursion depth.
type resolutionContext struct {
	depth      int
	maxDepth   int
	visited    map[string]bool
	validation *dnssecValidation
	requestCtx context.Context
}

//nolint:unused // Retained as a context-free compatibility helper for tests.
func newResolutionContext() *resolutionContext {
	return newResolutionContextWithContext(context.Background())
}

//nolint:contextcheck // The context is stored for downstream DNS exchanges.
func newResolutionContextWithContext(requestCtx context.Context) *resolutionContext {
	if requestCtx == nil {
		requestCtx = context.Background()
	}
	return &resolutionContext{
		depth:      0,
		maxDepth:   10,
		visited:    make(map[string]bool),
		requestCtx: requestCtx,
	}
}

func parseRecursionAllowlist(entries []string) ([]*net.IPNet, error) {
	if len(entries) == 0 {
		entries = config.DefaultDNSRecursionAllowlist()
	}
	networks := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			networks = append(networks, &net.IPNet{
				IP:   ip,
				Mask: net.CIDRMask(bits, bits),
			})
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid DNS recursion allowlist entry %q: %w", entry, err)
		}
		networks = append(networks, network)
	}
	if len(networks) == 0 {
		return nil, errors.New("DNS recursion allowlist contains no usable entries")
	}
	return networks, nil
}

func (r *Resolver) recursionAllowed(w dns.ResponseWriter) bool {
	if r == nil || w == nil {
		return false
	}
	remote := w.RemoteAddr()
	if remote == nil {
		return false
	}
	host, _, err := net.SplitHostPort(remote.String())
	if err != nil {
		host = remote.String()
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, network := range r.recursionNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func requestContext(ctx *resolutionContext) context.Context {
	if ctx == nil || ctx.requestCtx == nil {
		return context.Background()
	}
	return ctx.requestCtx
}

func configuredDuration(milliseconds int, fallback, maximum time.Duration) time.Duration {
	if milliseconds <= 0 {
		return fallback
	}
	duration := time.Duration(milliseconds) * time.Millisecond
	if duration > maximum {
		return maximum
	}
	return duration
}

func (c *resolutionContext) hasVisited(name string) bool {
	return c.visited[name]
}

func (c *resolutionContext) markVisited(name string) {
	c.visited[name] = true
}

func (c *resolutionContext) atMaxDepth() bool {
	return c.depth >= c.maxDepth
}

func (c *resolutionContext) descend() *resolutionContext {
	newVisited := make(map[string]bool, len(c.visited))
	maps.Copy(newVisited, c.visited)
	return &resolutionContext{
		depth:      c.depth + 1,
		maxDepth:   c.maxDepth,
		visited:    newVisited,
		validation: c.validation,
		requestCtx: c.requestCtx,
	}
}

// resolveNameserverAddress attempts to resolve A/AAAA records for a nameserver.
// It first checks local storage (Cardano/Handshake), then falls back to
// recursive resolution via upstream nameservers.
func (r *Resolver) resolveNameserverAddress(
	nsName string,
	ctx *resolutionContext,
) ([]net.IP, error) {
	if ctx == nil {
		ctx = newResolutionContextWithContext(requestContext(ctx))
	}
	if err := requestContext(ctx).Err(); err != nil {
		return nil, err
	}
	nsName = canonicalDNSName(nsName)
	if ctx.atMaxDepth() {
		return nil, fmt.Errorf(
			"max resolution depth exceeded resolving %s",
			nsName,
		)
	}

	if ctx.hasVisited(nsName) {
		return nil, fmt.Errorf("cycle detected resolving %s", nsName)
	}
	ctx.markVisited(nsName)

	var ips []net.IP

	if stateAvailable() {
		// Try local Cardano records first
		aRecords, err := state.GetState().LookupRecords(
			[]string{"A", "AAAA"},
			nsName,
		)
		if err != nil {
			return nil, err
		}
		for _, record := range aRecords {
			if ip := net.ParseIP(record.Rhs); ip != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}

		// Try local Handshake records
		hsRecords, err := state.GetState().LookupHandshakeRecords(
			[]string{"A", "AAAA"},
			nsName,
		)
		if err != nil {
			return nil, err
		}
		for _, record := range hsRecords {
			if ip := net.ParseIP(record.Rhs); ip != nil {
				ips = append(ips, ip)
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
	}

	// Not found locally - resolve via upstream using root hints
	childCtx := ctx.descend()
	if r.dnssecEnabled {
		validation, err := r.dnssecContextForZone(".", false)
		if err != nil {
			return nil, err
		}
		childCtx.validation = validation
	}

	// Start from root hints and resolve iteratively. Keep IPv4 roots first for
	// the usual case, but query all root addresses concurrently so a network
	// that silently drops IPv4 packets can still use an IPv6 root promptly.
	rootServers := r.rootServers()
	if len(rootServers) == 0 {
		return nil, errors.New("no root servers available")
	}

	rootCtx, cancel := context.WithCancel(requestContext(ctx))
	defer cancel()
	type rootResult struct {
		ips []net.IP
		err error
	}
	results := make(chan rootResult, len(rootServers))
	for _, rootNS := range rootServers {
		go func(rootNS string) {
			rootChildCtx := *childCtx
			rootChildCtx.validation = childCtx.validation.clone()
			rootChildCtx.requestCtx = rootCtx
			var rootIPs []net.IP
			var lastErr error
			// Query both address families. A nameserver may be IPv6-only,
			// and dual-stack glue is useful for transport failover.
			for _, queryType := range []uint16{dns.TypeA, dns.TypeAAAA} {
				if err := rootCtx.Err(); err != nil {
					results <- rootResult{err: err}
					return
				}
				msg := new(dns.Msg)
				msg.SetQuestion(nsName, queryType)
				msg.RecursionDesired = true
				// rootChildCtx carries rootCtx through the resolution context.
				resp, err := r.doQueryWithContext(msg, rootNS, true, &rootChildCtx) //nolint:contextcheck
				if err != nil {
					lastErr = fmt.Errorf("query root %s for %s: %w", rootNS, nsName, err)
					continue
				}
				if resp == nil {
					lastErr = fmt.Errorf("received nil response for %s", nsName)
					continue
				}
				for _, rr := range resp.Answer {
					switch v := rr.(type) {
					case *dns.A:
						rootIPs = append(rootIPs, v.A)
					case *dns.AAAA:
						rootIPs = append(rootIPs, v.AAAA)
					}
				}
			}
			results <- rootResult{ips: rootIPs, err: lastErr}
		}(rootNS)
	}

	var lastErr error
	for range rootServers {
		result := <-results
		if len(result.ips) > 0 {
			return result.ips, nil
		}
		if result.err != nil {
			lastErr = result.err
		}
	}

	if len(ips) == 0 && lastErr != nil {
		return nil, fmt.Errorf("upstream resolution failed for %s: %w", nsName, lastErr)
	}
	return nil, fmt.Errorf("no A/AAAA records in upstream response for %s", nsName)
}

// Server owns the DNS listeners started by Start.
type Server struct {
	servers         []*dns.Server
	errCh           chan error
	stopRootAnchors func()

	stopOnce sync.Once
	stopErr  error
}

// Errors returns asynchronous listener failures.
func (s *Server) Errors() <-chan error {
	if s == nil {
		return nil
	}
	return s.errCh
}

// Shutdown gracefully stops all DNS listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.stopOnce.Do(func() {
		var errs []error
		if s.stopRootAnchors != nil {
			s.stopRootAnchors()
		}
		for _, server := range s.servers {
			if err := server.ShutdownContext(ctx); err != nil && !isServerNotStarted(err) {
				errs = append(errs, err)
			}
		}
		s.stopErr = errors.Join(errs...)
	})
	return s.stopErr
}

// Close stops all DNS listeners without a deadline.
func (s *Server) Close() error {
	return s.Shutdown(context.Background())
}

func (s *Server) reportError(err error) {
	select {
	case s.errCh <- err:
	default:
		slog.Error("DNS listener error", "error", err)
	}
}

func isServerNotStarted(err error) bool {
	return err != nil && strings.Contains(err.Error(), "server not started")
}

func (r *Resolver) rootServers() []string {
	if r == nil || r.rootHints == nil {
		return nil
	}
	ipv4Servers := make([]string, 0)
	ipv6Servers := make([]string, 0)
	for _, rrs := range r.rootHints[dns.TypeA] {
		for _, rr := range rrs {
			if address, ok := rr.(*dns.A); ok {
				ipv4Servers = append(ipv4Servers, net.JoinHostPort(address.A.String(), "53"))
			}
		}
	}
	for _, rrs := range r.rootHints[dns.TypeAAAA] {
		for _, rr := range rrs {
			if address, ok := rr.(*dns.AAAA); ok {
				ipv6Servers = append(ipv6Servers, net.JoinHostPort(address.AAAA.String(), "53"))
			}
		}
	}
	// Shuffle each family independently, preserving IPv4-first fallback.
	shuffleStrings(ipv4Servers)
	shuffleStrings(ipv6Servers)
	return append(ipv4Servers, ipv6Servers...)
}

// getRandomRootServer returns a root server address from hints.
//
//nolint:unused // Retained as a compatibility helper for package tests.
func (r *Resolver) getRandomRootServer() string {
	servers := r.rootServers()
	if len(servers) == 0 {
		return ""
	}
	return servers[0]
}

// generateSyntheticSOA creates a SOA record for a blockchain
// zone using configured values and a date-based serial.
func generateSyntheticSOA(zone string) *dns.SOA {
	cfg := config.GetConfig()
	soaCfg := cfg.Dns.SOA
	// Generate serial as YYYYMMDD00
	serial, err := strconv.ParseUint(
		time.Now().UTC().Format("20060102")+"00",
		10,
		32,
	)
	if err != nil {
		// Fallback to a reasonable default
		serial = 2026010100
	}
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soaCfg.Minimum,
		},
		Ns:      soaCfg.Mname,
		Mbox:    soaCfg.Rname,
		Serial:  uint32(serial),
		Refresh: soaCfg.Refresh,
		Retry:   soaCfg.Retry,
		Expire:  soaCfg.Expire,
		Minttl:  soaCfg.Minimum,
	}
}

// isBlockchainTLD checks whether the given name (without trailing
// dot) is a known blockchain TLD from discovered addresses or
// configured profiles.
func isBlockchainTLD(name string) bool {
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)

	// Check configured profiles first (no state needed)
	for _, profile := range config.GetProfiles() {
		if strings.EqualFold(profile.Tld, name) {
			return true
		}
	}

	// Check discovered TLDs and Handshake records from state
	if !stateAvailable() {
		return false
	}

	discovered, err := state.GetState().
		GetDiscoveredAddresses()
	if err != nil {
		slog.Debug(
			fmt.Sprintf(
				"failed to get discovered addresses: %s",
				err,
			),
		)
	}
	for _, addr := range discovered {
		if strings.EqualFold(addr.TldName, name) {
			return true
		}
	}

	// Check Handshake TLDs by looking up any record for
	// the name
	hsRecords, err := state.GetState().
		LookupHandshakeRecords(
			[]string{
				"NS", "A", "AAAA",
				"CNAME", "TXT", "SOA",
			},
			name,
		)
	if err != nil {
		slog.Debug(
			fmt.Sprintf(
				"failed to lookup handshake records: %s",
				err,
			),
		)
	}
	return len(hsRecords) > 0
}

// stateAvailable checks if the state database is accessible
// without panicking.
func stateAvailable() bool {
	available := true
	func() {
		defer func() {
			if recover() != nil {
				available = false
			}
		}()
		_, err := state.GetState().
			LookupRecords([]string{"A"}, "__probe__")
		if err != nil {
			available = false
		}
	}()
	return available
}

// findZoneForName walks the labels of a DNS name to find the
// blockchain TLD zone it belongs to. Returns empty string if no
// blockchain zone is found.
func findZoneForName(name string) string {
	labels := dns.SplitDomainName(name)
	if labels == nil {
		return ""
	}
	// Walk from TLD towards the full name for efficiency
	for i := len(labels) - 1; i >= 0; i-- {
		candidate := strings.Join(labels[i:], ".")
		if isBlockchainTLD(candidate) {
			return dns.Fqdn(candidate)
		}
	}
	return ""
}

func Start() (*Server, error) {
	cfg := config.GetConfig()
	listenAddr := fmt.Sprintf(
		"%s:%d",
		cfg.Dns.ListenAddress,
		cfg.Dns.ListenPort,
	)
	slog.Info(
		"starting DNS listener on " + listenAddr,
	)
	resolver, err := NewResolver(cfg)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := loadConfiguredTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", resolver.handleQuery)
	servers := []*dns.Server{}
	// UDP listener
	serverUdp := &dns.Server{
		Addr:       listenAddr,
		Net:        "udp",
		Handler:    mux,
		TsigSecret: nil,
		ReusePort:  true,
	}
	servers = append(servers, serverUdp)
	// TCP listener
	serverTcp := &dns.Server{
		Addr:       listenAddr,
		Net:        "tcp",
		Handler:    mux,
		TsigSecret: nil,
		ReusePort:  true,
	}
	servers = append(servers, serverTcp)
	// TLS listener
	if tlsConfig != nil {
		listenTlsAddr := fmt.Sprintf(
			"%s:%d",
			cfg.Dns.ListenAddress,
			cfg.Dns.ListenTlsPort,
		)
		serverTls := &dns.Server{
			Addr:       listenTlsAddr,
			Net:        "tcp-tls",
			Handler:    mux,
			TsigSecret: nil,
			TLSConfig:  tlsConfig,
			ReusePort:  false,
		}
		servers = append(servers, serverTls)
	}
	server := &Server{
		servers: servers,
		errCh:   make(chan error, len(servers)),
	}
	if resolver.rootAnchorManager != nil {
		server.stopRootAnchors = resolver.rootAnchorManager.start()
	}
	if err := startDNSListeners(server, servers); err != nil {
		if server.stopRootAnchors != nil {
			server.stopRootAnchors()
		}
		return nil, err
	}
	return server, nil
}

func startDNSListeners(server *Server, servers []*dns.Server) error {
	startedServers := make([]*dns.Server, 0, len(servers))
	for _, listener := range servers {
		readyCh := make(chan struct{})
		startupErrCh := make(chan error, 1)
		var readyOnce sync.Once
		listener.NotifyStartedFunc = func() {
			readyOnce.Do(func() {
				close(readyCh)
			})
		}
		go startListener(server, listener, readyCh, startupErrCh)
		select {
		case <-readyCh:
			startedServers = append(startedServers, listener)
		case err := <-startupErrCh:
			server.servers = startedServers
			_ = server.Close()
			return err
		}
	}
	return nil
}

func loadConfiguredTLSConfig(cfg *config.Config) (*tls.Config, error) {
	if cfg.Tls.CertFilePath == "" && cfg.Tls.KeyFilePath == "" {
		slog.Info(
			"TLS listener disabled: TLS certificate and key file paths are not configured",
		)
		return nil, nil
	}
	if cfg.Tls.CertFilePath == "" || cfg.Tls.KeyFilePath == "" {
		return nil, errors.New(
			"TLS certificate and key file paths must both be configured",
		)
	}
	return loadTLSConfig(
		cfg.Tls.CertFilePath,
		cfg.Tls.KeyFilePath,
	)
}

func loadTLSConfig(
	certFilePath string,
	keyFilePath string,
) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (r *Resolver) loadRootHints(cfg *config.Config) error {
	r.rootHints = make(map[uint16]map[string][]dns.RR)
	for line := range strings.SplitSeq(cfg.Dns.RootHints, "\n") {
		tmpRR, err := dns.NewRR(line)
		if err != nil {
			return fmt.Errorf("load root hints: %w", err)
		}
		if tmpRR == nil {
			continue
		}
		rrType := tmpRR.Header().Rrtype
		if _, ok := r.rootHints[rrType]; !ok {
			r.rootHints[rrType] = make(map[string][]dns.RR)
		}
		name := canonicalDNSName(tmpRR.Header().Name)
		r.rootHints[rrType][name] = append(
			r.rootHints[rrType][name],
			tmpRR,
		)
	}
	return nil
}

func startListener(
	server *Server,
	listener *dns.Server,
	readyCh <-chan struct{},
	startupErrCh chan<- error,
) {
	if err := listener.ListenAndServe(); err != nil {
		err = fmt.Errorf("DNS %s listener failed: %w", listener.Net, err)
		select {
		case <-readyCh:
			server.reportError(err)
		default:
			select {
			case startupErrCh <- err:
			default:
				server.reportError(err)
			}
		}
	}
}

func (r *Resolver) handleQuery(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil {
		return
	}
	if len(req.Question) != 1 {
		writeFormatError(w, req, config.GetConfig().Dns.RecursionEnabled)
		return
	}

	cfg := config.GetConfig()
	question := req.Question[0]
	if question.Qclass != dns.ClassINET {
		writeRcode(w, req, dns.RcodeNotImplemented, cfg.Dns.RecursionEnabled)
		return
	}
	canonicalName := canonicalDNSName(question.Name)
	lookupName := strings.TrimSuffix(canonicalName, ".")
	m := new(dns.Msg)
	m.RecursionAvailable = cfg.Dns.RecursionEnabled

	if cfg.Logging.QueryLog {
		for _, q := range req.Question {
			slog.Info(
				fmt.Sprintf("query: name: %s, type: %s, class: %s",
					q.Name,
					dns.Type(q.Qtype).String(),
					dns.Class(q.Qclass).String(),
				),
			)
		}
	}
	// Increment query total metric
	metricQueryTotal.Inc()

	// Check for known record from local storage
	lookupRecordTypes := []uint16{question.Qtype}
	switch question.Qtype {
	case dns.TypeA, dns.TypeAAAA:
		// If the query is for A/AAAA, also try looking up matching CNAME records
		lookupRecordTypes = append(lookupRecordTypes, dns.TypeCNAME)
	}
	for _, lookupRecordType := range lookupRecordTypes {
		fromHandshake := false
		// Try Cardano
		records, err := state.GetState().LookupRecords(
			[]string{dns.Type(lookupRecordType).String()},
			lookupName,
		)
		if err != nil {
			slog.Error(
				fmt.Sprintf("failed to lookup records in state: %s", err),
			)
			return
		}
		// Try Handshake
		if records == nil {
			records, err = state.GetState().LookupHandshakeRecords(
				[]string{dns.Type(lookupRecordType).String()},
				lookupName,
			)
			if err != nil {
				slog.Error(
					fmt.Sprintf("failed to lookup records in state: %s", err),
				)
				return
			}
			fromHandshake = records != nil
		}
		if records != nil {
			// Assemble response
			m.SetReply(req)
			m.RecursionAvailable = cfg.Dns.RecursionEnabled
			m.Authoritative = true
			for _, tmpRecord := range records {
				tmpRR, err := stateRecordToDnsRR(tmpRecord)
				if err != nil {
					slog.Error(
						fmt.Sprintf(
							"failed to convert state record to dns.RR: %s",
							err,
						),
					)
					return
				}
				m.Answer = append(m.Answer, tmpRR)
			}
			if wantsDNSSEC(req) && question.Qtype != dns.TypeRRSIG {
				signatures, err := lookupLocalSignatures(
					lookupName,
					fromHandshake,
					m.Answer,
				)
				if err != nil {
					slog.Error(
						fmt.Sprintf(
							"failed to lookup DNSSEC signatures: %s",
							err,
						),
					)
					return
				}
				m.Answer = append(m.Answer, signatures...)
			}
			// Send response
			if err := w.WriteMsg(m); err != nil {
				slog.Error(
					fmt.Sprintf("failed to write response: %s", err),
				)
			}
			// We found our answer, to return from handler
			return
		}
	}

	// Handle SOA queries for blockchain TLDs when no explicit
	// on-chain SOA was found
	if question.Qtype == dns.TypeSOA {
		zone := findZoneForName(canonicalName)
		if zone != "" {
			m.SetReply(req)
			m.RecursionAvailable = cfg.Dns.RecursionEnabled
			m.Authoritative = true
			soa := generateSyntheticSOA(zone)
			m.Answer = append(
				m.Answer,
				soa,
			)
			if err := w.WriteMsg(m); err != nil {
				slog.Error(
					fmt.Sprintf(
						"failed to write response: %s",
						err,
					),
				)
			}
			return
		}
	}

	recursiveRequested := cfg.Dns.RecursionEnabled && req.RecursionDesired
	if recursiveRequested && !r.recursionAllowed(w) {
		writeRcode(w, req, dns.RcodeRefused, true)
		return
	}
	requestCtx := context.Background()
	if recursiveRequested {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(
			context.Background(),
			configuredDuration(cfg.Dns.RecursionTimeoutMs, 10*time.Second, 2*time.Minute),
		)
		defer cancel()
	}

	// Check for any NS records for parent domains from local storage. Missing
	// glue is resolved only when this request is actually allowed to recurse.
	nameserverDomain, nameservers, err := r.findNameserversForDomainWithContext(
		canonicalName,
		requestCtx,
		recursiveRequested,
	)
	if err != nil {
		slog.Error(
			fmt.Sprintf(
				"failed to lookup nameservers for %s: %s",
				req.Question[0].Name,
				err,
			),
		)
	}
	if len(nameservers) > 0 && (recursiveRequested || nameserverDomain != ".") {
		// Assemble response
		m.SetReply(req)
		m.RecursionAvailable = cfg.Dns.RecursionEnabled
		if recursiveRequested {
			ctx := newResolutionContextWithContext(requestCtx)
			if r.dnssecEnabled && !req.CheckingDisabled {
				validation, validationErr := r.dnssecContextForZone(
					nameserverDomain,
					nameserverDomain != ".",
				)
				if validationErr != nil {
					m.SetRcode(req, dns.RcodeServerFailure)
					m.RecursionAvailable = cfg.Dns.RecursionEnabled
					if writeErr := w.WriteMsg(m); writeErr != nil {
						slog.Error(
							fmt.Sprintf(
								"failed to write response: %s",
								writeErr,
							),
						)
					}
					slog.Error(
						"failed to load DNSSEC trust anchors",
						"zone",
						nameserverDomain,
						"error",
						validationErr,
					)
					return
				}
				ctx.validation = validation
			}

			// Try all nameservers with retry and failover
			resp, err := r.queryMultipleNameservers(
				req,
				nameservers,
				true,
				ctx,
			)
			if err != nil {
				// Send failure response
				m.SetRcode(req, dns.RcodeServerFailure)
				m.RecursionAvailable = cfg.Dns.RecursionEnabled
				if err := w.WriteMsg(m); err != nil {
					slog.Error(
						fmt.Sprintf(
							"failed to write response: %s",
							err,
						),
					)
				}
				slog.Error(
					fmt.Sprintf(
						"recursive query failed: domain=%s, error=%s",
						req.Question[0].Name,
						err,
					),
				)
				return
			}
			copyResponse(req, resp, m)
			m.RecursionAvailable = cfg.Dns.RecursionEnabled
			// Send response
			if err := w.WriteMsg(m); err != nil {
				slog.Error(
					fmt.Sprintf(
						"failed to write response: %s",
						err,
					),
				)
			}
			return
		} else {
			for nameserver, addresses := range nameservers {
				// NS record
				ns := &dns.NS{
					Hdr: dns.RR_Header{Name: (nameserverDomain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 999},
					Ns:  nameserver,
				}
				m.Ns = append(m.Ns, ns)
				for _, address := range addresses {
					// A or AAAA record
					if address.To4() != nil {
						// IPv4
						a := &dns.A{
							Hdr: dns.RR_Header{Name: nameserver, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 999},
							A:   address,
						}
						m.Extra = append(m.Extra, a)
					} else {
						// IPv6
						aaaa := &dns.AAAA{
							Hdr:  dns.RR_Header{Name: nameserver, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 999},
							AAAA: address,
						}
						m.Extra = append(m.Extra, aaaa)
					}
				}
			}
		}
		// Send response
		if err := w.WriteMsg(m); err != nil {
			slog.Error(
				fmt.Sprintf("failed to write response: %s", err),
			)
		}
		// We found our answer, to return from handler
		return
	}

	// Only blockchain zones are authoritative for negative answers. REFUSED
	// avoids poisoning a client's negative cache for unrelated names.
	zone := findZoneForName(canonicalName)
	if zone == "" {
		writeRcode(w, req, dns.RcodeRefused, cfg.Dns.RecursionEnabled)
		return
	}
	m.SetRcode(req, dns.RcodeNameError)
	m.RecursionAvailable = cfg.Dns.RecursionEnabled
	if zone != "" {
		m.Authoritative = true
		fromHandshake, sourceErr := localZoneUsesHandshake(zone)
		if sourceErr != nil {
			slog.Error(
				"failed to determine local zone source",
				"zone",
				zone,
				"error",
				sourceErr,
			)
			return
		}
		soa, storedSOA, soaErr := lookupLocalSOA(zone, fromHandshake)
		if soaErr != nil {
			slog.Error(
				"failed to lookup local SOA",
				"zone",
				zone,
				"error",
				soaErr,
			)
			return
		}
		m.Ns = append(m.Ns, soa)
		if wantsDNSSEC(req) && storedSOA {
			rcode, proof, err := lookupLocalNegativeProof(
				question,
				zone,
				soa,
				fromHandshake,
			)
			if err != nil {
				slog.Error(
					"failed to lookup local DNSSEC denial proof",
					"zone",
					zone,
					"error",
					err,
				)
				return
			}
			if len(proof) > 0 {
				m.Rcode = rcode
				m.Ns = append(m.Ns, proof...)
			}
		}
	}
	if err := w.WriteMsg(m); err != nil {
		slog.Error(
			fmt.Sprintf("failed to write response: %s", err),
		)
	}
}

func writeFormatError(w dns.ResponseWriter, r *dns.Msg, recursionAvailable bool) {
	if w == nil || r == nil {
		return
	}
	m := new(dns.Msg)
	m.SetRcodeFormatError(r)
	m.RecursionAvailable = recursionAvailable
	if err := w.WriteMsg(m); err != nil {
		slog.Error(
			fmt.Sprintf("failed to write response: %s", err),
		)
	}
}

func writeRcode(
	w dns.ResponseWriter,
	r *dns.Msg,
	rcode int,
	recursionAvailable bool,
) {
	if w == nil || r == nil {
		return
	}
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = recursionAvailable
	if err := w.WriteMsg(m); err != nil {
		slog.Error(
			fmt.Sprintf("failed to write response: %s", err),
		)
	}
}

func stateRecordToDnsRR(record state.DomainRecord) (dns.RR, error) {
	tmpTtl := ""
	if record.Ttl > 0 {
		tmpTtl = strconv.Itoa(record.Ttl)
	}
	tmpRR := fmt.Sprintf(
		"%s %s IN %s %s",
		record.Lhs,
		tmpTtl,
		record.Type,
		record.Rhs,
	)
	return dns.NewRR(tmpRR)
}

func lookupLocalSignatures(
	recordName string,
	fromHandshake bool,
	answer []dns.RR,
) ([]dns.RR, error) {
	var (
		records []state.DomainRecord
		err     error
	)
	if fromHandshake {
		records, err = state.GetState().LookupHandshakeRecords(
			[]string{"RRSIG"},
			recordName,
		)
	} else {
		records, err = state.GetState().LookupRecords(
			[]string{"RRSIG"},
			recordName,
		)
	}
	if err != nil {
		return nil, err
	}

	answerTypes := make(map[uint16]struct{}, len(answer))
	for _, rr := range answer {
		answerTypes[rr.Header().Rrtype] = struct{}{}
	}
	var ret []dns.RR
	for _, record := range records {
		rr, err := stateRecordToDnsRR(record)
		if err != nil {
			return nil, err
		}
		sig, ok := rr.(*dns.RRSIG)
		if !ok {
			continue
		}
		if _, ok := answerTypes[sig.TypeCovered]; ok {
			ret = append(ret, sig)
		}
	}
	return ret, nil
}

func lookupLocalZoneDNSSECRecords(
	zone string,
	fromHandshake bool,
) ([]dns.RR, error) {
	recordTypes := []string{"NSEC", "NSEC3", "RRSIG"}
	var (
		records []state.DomainRecord
		err     error
	)
	if fromHandshake {
		records, err = state.GetState().LookupHandshakeRecordsInZone(
			recordTypes,
			zone,
		)
	} else {
		records, err = state.GetState().LookupRecordsInZone(
			recordTypes,
			zone,
		)
	}
	if err != nil {
		return nil, err
	}
	ret := make([]dns.RR, 0, len(records))
	for _, record := range records {
		rr, err := stateRecordToDnsRR(record)
		if err != nil {
			return nil, err
		}
		ret = append(ret, rr)
	}
	return ret, nil
}

func localZoneUsesHandshake(zone string) (bool, error) {
	recordName := strings.TrimSuffix(canonicalDNSName(zone), ".")
	cardanoNS, err := state.GetState().LookupRecords(
		[]string{"NS"},
		recordName,
	)
	if err != nil {
		return false, err
	}
	if len(cardanoNS) > 0 {
		return false, nil
	}
	handshakeNS, err := state.GetState().LookupHandshakeRecords(
		[]string{"NS"},
		recordName,
	)
	if err != nil {
		return false, err
	}
	return len(handshakeNS) > 0, nil
}

func lookupLocalSOA(
	zone string,
	fromHandshake bool,
) (*dns.SOA, bool, error) {
	recordName := strings.TrimSuffix(canonicalDNSName(zone), ".")
	var (
		records []state.DomainRecord
		err     error
	)
	if fromHandshake {
		records, err = state.GetState().LookupHandshakeRecords(
			[]string{"SOA"},
			recordName,
		)
	} else {
		records, err = state.GetState().LookupRecords(
			[]string{"SOA"},
			recordName,
		)
	}
	if err != nil {
		return nil, false, err
	}
	if len(records) == 0 {
		return generateSyntheticSOA(zone), false, nil
	}
	if len(records) != 1 {
		return nil, false, fmt.Errorf(
			"zone %s has %d SOA records, want exactly one",
			zone,
			len(records),
		)
	}
	rr, err := stateRecordToDnsRR(records[0])
	if err != nil {
		return nil, false, err
	}
	soa, ok := rr.(*dns.SOA)
	if !ok {
		return nil, false, fmt.Errorf(
			"stored SOA record for %s parsed as %T",
			zone,
			rr,
		)
	}
	return soa, true, nil
}

func lookupLocalNegativeProof(
	question dns.Question,
	zone string,
	soa *dns.SOA,
	fromHandshake bool,
) (int, []dns.RR, error) {
	records, err := lookupLocalZoneDNSSECRecords(zone, fromHandshake)
	if err != nil {
		return 0, nil, err
	}
	soaSignatures := signaturesFor(records, soa.Hdr.Name, dns.TypeSOA)
	if len(soaSignatures) == 0 {
		return 0, nil, nil
	}

	qname := canonicalDNSName(question.Name)
	rcode := dns.RcodeSuccess
	proof := nodataProofRecords(qname, question.Qtype, records)
	if len(proof) == 0 {
		rcode = dns.RcodeNameError
		proof = nxdomainProofRecords(qname, records)
	}
	if len(proof) == 0 {
		return 0, nil, nil
	}

	ret := make([]dns.RR, 0, len(proof)*2+len(soaSignatures))
	for _, signature := range soaSignatures {
		ret = append(ret, signature)
	}
	type rrsetKey struct {
		name   string
		rrType uint16
	}
	seen := make(map[rrsetKey]struct{}, len(proof))
	for _, rr := range proof {
		key := rrsetKey{
			name:   canonicalDNSName(rr.Header().Name),
			rrType: rr.Header().Rrtype,
		}
		if _, ok := seen[key]; ok {
			continue
		}
		rrset := rrsetFrom(records, key.name, key.rrType)
		signatures := signaturesFor(records, key.name, key.rrType)
		if len(rrset) == 0 || len(signatures) == 0 {
			return 0, nil, nil
		}
		seen[key] = struct{}{}
		ret = append(ret, rrset...)
		for _, signature := range signatures {
			ret = append(ret, signature)
		}
	}
	return rcode, ret, nil
}

func copyResponse(req *dns.Msg, srcResp *dns.Msg, destResp *dns.Msg) {
	if srcResp == nil {
		return
	}
	// Copy relevant data from original request and source response into destination response
	destResp.SetRcode(req, srcResp.Rcode)
	destResp.RecursionDesired = req.RecursionDesired
	destResp.RecursionAvailable = srcResp.RecursionAvailable
	destResp.AuthenticatedData = srcResp.AuthenticatedData &&
		(wantsDNSSEC(req) || req.AuthenticatedData)
	if srcResp.Ns != nil {
		destResp.Ns = append(destResp.Ns, srcResp.Ns...)
	}
	if srcResp.Answer != nil {
		destResp.Answer = append(destResp.Answer, srcResp.Answer...)
	}
	if srcResp.Extra != nil {
		destResp.Extra = append(destResp.Extra, srcResp.Extra...)
	}
	if !wantsDNSSEC(req) {
		requestedType := req.Question[0].Qtype
		destResp.Answer = filterDNSSECRecords(
			destResp.Answer,
			requestedType,
		)
		destResp.Ns = filterDNSSECRecords(
			destResp.Ns,
			requestedType,
		)
		destResp.Extra = filterDNSSECRecords(
			destResp.Extra,
			requestedType,
		)
	}
}

// queryWithRetry executes a query function with retries
// and exponential backoff.
//
//nolint:unused // Kept as a compatibility helper for package-level tests.
func queryWithRetry(
	queryFn func() (*dns.Msg, error),
	maxRetries int,
	baseDelay time.Duration,
) (*dns.Msg, error) {
	return queryWithRetryContext(
		context.Background(),
		queryFn,
		maxRetries,
		baseDelay,
	)
}

//nolint:contextcheck // The callback is intentionally context-free; exchanges use ctx directly.
func queryWithRetryContext(
	ctx context.Context,
	queryFn func() (*dns.Msg, error),
	maxRetries int,
	baseDelay time.Duration,
) (*dns.Msg, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if maxRetries <= 0 {
		maxRetries = 1
	}
	if maxRetries > 10 {
		maxRetries = 10
	}
	if baseDelay < 0 {
		baseDelay = 0
	}
	if baseDelay > 10*time.Second {
		baseDelay = 10 * time.Second
	}
	const maxRetryBackoff = 30 * time.Second
	var lastErr error
	for attempt := range maxRetries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		result, err := queryFn()
		if err == nil {
			return result, nil
		}
		lastErr = err
		// Don't sleep after the last attempt
		if attempt < maxRetries-1 {
			// Exponential backoff: baseDelay * 2^attempt
			delay := baseDelay * time.Duration(1<<attempt)
			if delay > maxRetryBackoff || delay < 0 {
				delay = maxRetryBackoff
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return nil, fmt.Errorf(
		"query failed after %d attempts: %w",
		maxRetries,
		lastErr,
	)
}

// queryMultipleNameservers tries multiple nameservers until
// one succeeds, using the default DNS port (53).
func (r *Resolver) queryMultipleNameservers(
	msg *dns.Msg,
	nameservers map[string][]net.IP,
	recursive bool,
	ctx *resolutionContext,
) (*dns.Msg, error) {
	return r.queryMultipleNameserversWithPort(
		msg,
		nameservers,
		recursive,
		ctx,
		"53",
	)
}

// queryMultipleNameserversWithPort tries multiple nameservers
// until one succeeds. It shuffles the nameserver order and
// uses retry logic for each server.
func (r *Resolver) queryMultipleNameserversWithPort(
	msg *dns.Msg,
	nameservers map[string][]net.IP,
	recursive bool,
	ctx *resolutionContext,
	port string,
) (*dns.Msg, error) {
	cfg := config.GetConfig()
	queryCtx := requestContext(ctx)

	// Flatten nameservers into a list of addresses,
	// preferring IPv4 over IPv6
	ipv4Addrs := make([]string, 0)
	ipv6Addrs := make([]string, 0)
	for _, ips := range nameservers {
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				ipv4Addrs = append(
					ipv4Addrs,
					net.JoinHostPort(ip.String(), port),
				)
			} else {
				ipv6Addrs = append(
					ipv6Addrs,
					net.JoinHostPort(ip.String(), port),
				)
			}
		}
	}

	// Shuffle each group independently to distribute load
	// while preserving IPv4-first preference
	shuffleStrings(ipv4Addrs)
	shuffleStrings(ipv6Addrs)

	// Prefer IPv4, fall back to IPv6 if all IPv4 fail
	addresses := make(
		[]string,
		0,
		len(ipv4Addrs)+len(ipv6Addrs),
	)
	addresses = append(addresses, ipv4Addrs...)
	addresses = append(addresses, ipv6Addrs...)

	if len(addresses) == 0 {
		return nil, errors.New("no nameserver addresses available")
	}

	var lastErr error
	retryCount := cfg.Dns.RetryCount
	if retryCount <= 0 {
		retryCount = 1
	}
	if retryCount > 10 {
		retryCount = 10
	}
	baseDelay := configuredDuration(cfg.Dns.RetryDelayMs, 0, 10*time.Second)
	timeout := configuredDuration(
		cfg.Dns.QueryTimeoutMs,
		5*time.Second,
		30*time.Second,
	)

	for _, addr := range addresses {
		if err := queryCtx.Err(); err != nil {
			return nil, err
		}
		exchangeTimeout := timeout
		if deadline, ok := queryCtx.Deadline(); ok {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				if err := queryCtx.Err(); err != nil {
					return nil, err
				}
				return nil, context.DeadlineExceeded
			}
			if remaining < exchangeTimeout {
				exchangeTimeout = remaining
			}
		}
		if r.dnssecEnabled && !msg.CheckingDisabled {
			if err := r.ensureDNSSECKeys(
				queryCtx,
				ctx.validation,
				addr,
				exchangeTimeout,
			); err != nil {
				slog.Debug(
					"DNSSEC key authentication failed",
					"address",
					addr,
					"error",
					err,
				)
				lastErr = err
				continue
			}
		}
		queryFn := func() (*dns.Msg, error) {
			outbound := msg
			if r.dnssecEnabled || wantsDNSSEC(msg) {
				outbound = dnssecQuery(msg)
			}
			resp, exchangeErr := exchangeDNS(
				queryCtx,
				outbound,
				addr,
				exchangeTimeout,
			)
			if exchangeErr != nil {
				return nil, exchangeErr
			}
			if resp == nil {
				return nil, fmt.Errorf(
					"nil response from %s",
					addr,
				)
			}
			// Treat SERVFAIL/REFUSED as retryable errors
			if resp.Rcode == dns.RcodeServerFailure ||
				resp.Rcode == dns.RcodeRefused {
				return nil, fmt.Errorf(
					"server %s returned %s",
					addr,
					dns.RcodeToString[resp.Rcode],
				)
			}
			return resp, nil
		}

		resp, err := queryWithRetryContext(
			queryCtx,
			queryFn,
			retryCount,
			baseDelay,
		)
		if err != nil {
			slog.Debug(
				fmt.Sprintf(
					"nameserver query failed: address=%s, error=%s",
					addr,
					err,
				),
			)
			lastErr = err
			continue
		}
		if resp == nil {
			lastErr = fmt.Errorf("nameserver %s returned a nil response", addr)
			continue
		}

		// If recursive and got a referral, follow it
		if recursive &&
			!resp.Authoritative &&
			len(getNameserversFromResponse(resp)) > 0 {
			result, referralErr := r.handleReferral(
				msg,
				resp,
				ctx,
			)
			if referralErr == nil {
				return result, nil
			}
			slog.Debug(
				fmt.Sprintf(
					"referral failed: address=%s, error=%s",
					addr,
					referralErr,
				),
			)
			lastErr = referralErr
			continue
		}

		if r.dnssecEnabled && !msg.CheckingDisabled {
			authenticated, validationErr := r.validateFinalResponse(
				msg,
				resp,
				ctx.validation,
			)
			if validationErr != nil {
				slog.Debug(
					"DNSSEC response validation failed",
					"address",
					addr,
					"error",
					validationErr,
				)
				lastErr = validationErr
				continue
			}
			resp.AuthenticatedData = authenticated
		} else {
			resp.AuthenticatedData = false
		}
		return resp, nil
	}

	return nil, fmt.Errorf(
		"all nameservers failed: %w",
		lastErr,
	)
}

// shuffleStrings randomly reorders a slice of strings
// using crypto/rand.
func shuffleStrings(s []string) {
	for i := len(s) - 1; i > 0; i-- {
		n, err := rand.Int(
			rand.Reader,
			big.NewInt(int64(i+1)),
		)
		if err != nil || n == nil {
			continue
		}
		j := n.Int64()
		s[i], s[j] = s[j], s[i]
	}
}

// handleReferral processes a DNS referral response and
// follows the delegation.
func (r *Resolver) handleReferral(
	msg *dns.Msg,
	resp *dns.Msg,
	ctx *resolutionContext,
) (*dns.Msg, error) {
	if ctx.atMaxDepth() {
		return nil, errMaxReferralDepth
	}

	nameservers := getNameserversFromResponse(resp)
	if len(nameservers) == 0 {
		return resp, nil
	}

	childCtx := ctx.descend()
	if r.dnssecEnabled && !msg.CheckingDisabled {
		validation, err := r.validationForReferral(
			resp,
			ctx.validation,
			msg.Question[0].Name,
		)
		if err != nil {
			return nil, err
		}
		childCtx.validation = validation
	}

	// Resolve missing glue records
	for nsName, nsIPs := range nameservers {
		if len(nsIPs) == 0 {
			resolvedIPs, err := r.resolveNameserverAddress(
				nsName,
				childCtx,
			)
			if err != nil {
				slog.Debug(
					fmt.Sprintf(
						"failed to resolve NS glue: ns=%s, error=%s",
						nsName,
						err,
					),
				)
				continue
			}
			nameservers[nsName] = resolvedIPs
		}
	}

	return r.queryMultipleNameservers(
		msg,
		nameservers,
		true,
		childCtx,
	)
}

// doQueryWithContext performs a DNS query with resolution
// context for depth tracking. It uses retry logic and
// configurable timeouts.
func (r *Resolver) doQueryWithContext(
	msg *dns.Msg,
	address string,
	recursive bool,
	ctx *resolutionContext,
) (*dns.Msg, error) {
	if ctx == nil {
		ctx = newResolutionContextWithContext(requestContext(ctx))
	}
	if err := requestContext(ctx).Err(); err != nil {
		return nil, err
	}
	if ctx.atMaxDepth() {
		return nil, errors.New("max resolution depth exceeded")
	}

	// Parse host and port, defaulting to port 53
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// No port specified, treat as host-only
		host = address
		port = "53"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf(
			"invalid IP address: %s",
			host,
		)
	}

	// Create nameserver map with single entry
	nameservers := map[string][]net.IP{
		"initial": {ip},
	}

	return r.queryMultipleNameserversWithPort(
		msg,
		nameservers,
		recursive,
		ctx,
		port,
	)
}

//nolint:unused // Compatibility wrapper for callers that do not need cancellation.
func (r *Resolver) findNameserversForDomain(
	recordName string,
) (string, map[string][]net.IP, error) {
	return r.findNameserversForDomainWithContext(
		recordName,
		context.Background(),
		true,
	)
}

//nolint:contextcheck // The context is propagated through resolutionContext.
func (r *Resolver) findNameserversForDomainWithContext(
	recordName string,
	requestCtx context.Context,
	resolveGlue bool,
) (string, map[string][]net.IP, error) {
	if requestCtx == nil {
		requestCtx = context.Background()
	}
	// Split record name into labels and lookup each domain and parent until we get a hit
	queryLabels := dns.SplitDomainName(canonicalDNSName(recordName))

	// Special case for root domain
	if queryLabels == nil {
		queryLabels = append(queryLabels, "")
	}

	// Check on-chain domains first
	for startLabelIdx := range queryLabels {
		lookupDomainName := strings.Join(queryLabels[startLabelIdx:], ".")
		// Convert to canonical form for consistency
		lookupDomainName = dns.CanonicalName(lookupDomainName)
		// Try Cardano
		nsRecords, err := state.GetState().
			LookupRecords([]string{"NS"}, lookupDomainName)
		if err != nil {
			return "", nil, err
		}
		if len(nsRecords) > 0 {
			ret := map[string][]net.IP{}
			for _, nsRecord := range nsRecords {
				nsName := canonicalDNSName(nsRecord.Rhs)
				var nsIPs []net.IP

				// Get matching A/AAAA records for NS entry from local storage
				aRecords, err := state.GetState().
					LookupRecords([]string{"A", "AAAA"}, strings.TrimSuffix(nsName, "."))
				if err != nil {
					return "", nil, err
				}
				for _, aRecord := range aRecords {
					tmpIp := net.ParseIP(aRecord.Rhs)
					// Skip duplicate IPs
					if slices.ContainsFunc(nsIPs, func(x net.IP) bool {
						return x.Equal(tmpIp)
					}) {
						continue
					}
					nsIPs = append(nsIPs, tmpIp)
				}

				// If no local records, try to resolve via upstream
				if len(nsIPs) == 0 && resolveGlue {
					ctx := newResolutionContextWithContext(requestCtx)
					resolvedIPs, resolveErr := r.resolveNameserverAddress(
						nsName,
						ctx,
					)
					if resolveErr != nil {
						slog.Debug(
							fmt.Sprintf(
								"failed to resolve NS glue: ns=%s, error=%s",
								nsName,
								resolveErr,
							),
						)
					} else {
						nsIPs = resolvedIPs
					}
				}

				ret[nsName] = nsIPs
			}
			return dns.Fqdn(lookupDomainName), ret, nil
		}
		// Try Handshake
		nsRecords, err = state.GetState().
			LookupHandshakeRecords([]string{"NS"}, lookupDomainName)
		if err != nil {
			return "", nil, err
		}
		if len(nsRecords) > 0 {
			ret := map[string][]net.IP{}
			for _, nsRecord := range nsRecords {
				nsName := canonicalDNSName(nsRecord.Rhs)
				var nsIPs []net.IP

				// Get matching A/AAAA records for NS entry from local storage
				aRecords, err := state.GetState().
					LookupHandshakeRecords([]string{"A", "AAAA"}, strings.TrimSuffix(nsName, "."))
				if err != nil {
					return "", nil, err
				}
				for _, aRecord := range aRecords {
					tmpIp := net.ParseIP(aRecord.Rhs)
					// Skip duplicate IPs
					if slices.ContainsFunc(nsIPs, func(x net.IP) bool {
						return x.Equal(tmpIp)
					}) {
						continue
					}
					nsIPs = append(nsIPs, tmpIp)
				}

				// If no local records, try to resolve via upstream
				if len(nsIPs) == 0 && resolveGlue {
					ctx := newResolutionContextWithContext(requestCtx)
					resolvedIPs, resolveErr := r.resolveNameserverAddress(
						nsName,
						ctx,
					)
					if resolveErr != nil {
						slog.Debug(
							fmt.Sprintf(
								"failed to resolve NS glue: ns=%s, error=%s",
								nsName,
								resolveErr,
							),
						)
					} else {
						nsIPs = resolvedIPs
					}
				}

				ret[nsName] = nsIPs
			}
			return dns.Fqdn(lookupDomainName), ret, nil
		}
	}
	// Return root hints
	ret := map[string][]net.IP{}
	if r != nil && r.rootHints != nil && r.rootHints[dns.TypeNS] != nil {
		for _, tmpRecord := range r.rootHints[dns.TypeNS][`.`] {
			nsRec := canonicalDNSName(tmpRecord.(*dns.NS).Ns)
			if r.rootHints[dns.TypeA] != nil {
				for _, aRecord := range r.rootHints[dns.TypeA][nsRec] {
					if aRecord, ok := aRecord.(*dns.A); ok {
						ret[nsRec] = append(ret[nsRec], aRecord.A)
					}
				}
			}
			if r.rootHints[dns.TypeAAAA] != nil {
				for _, aaaaRecord := range r.rootHints[dns.TypeAAAA][nsRec] {
					if aaaaRecord, ok := aaaaRecord.(*dns.AAAA); ok {
						ret[nsRec] = append(ret[nsRec], aaaaRecord.AAAA)
					}
				}
			}
		}
	}
	return `.`, ret, nil
}

func getNameserversFromResponse(msg *dns.Msg) map[string][]net.IP {
	if msg == nil || len(msg.Ns) == 0 {
		return nil
	}
	ret := map[string][]net.IP{}
	for _, ns := range msg.Ns {
		// TODO: handle SOA
		switch v := ns.(type) {
		case *dns.NS:
			nsName := canonicalDNSName(v.Ns)
			ret[nsName] = []net.IP{}
			// Glue is only authoritative when the nameserver is
			// beneath the delegated zone. Out-of-bailiwick address
			// records must be resolved independently.
			if !dns.IsSubDomain(
				canonicalDNSName(v.Hdr.Name),
				nsName,
			) {
				continue
			}
			for _, extra := range msg.Extra {
				if canonicalDNSName(extra.Header().Name) != nsName {
					continue
				}
				switch v := extra.(type) {
				case *dns.A:
					ret[nsName] = append(
						ret[nsName],
						v.A,
					)
				case *dns.AAAA:
					ret[nsName] = append(
						ret[nsName],
						v.AAAA,
					)
				}
			}
		}
	}
	return ret
}
