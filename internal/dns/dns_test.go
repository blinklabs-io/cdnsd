// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
)

func TestStartReturnsShutdownHandle(t *testing.T) {
	cfg := config.GetConfig()
	oldDNS := cfg.Dns
	oldTLS := cfg.Tls
	cfg.Dns.ListenAddress = "127.0.0.1"
	cfg.Dns.ListenPort = 0
	cfg.Dns.ListenTlsPort = 0
	cfg.Tls.CertFilePath = ""
	cfg.Tls.KeyFilePath = ""
	t.Cleanup(func() {
		cfg.Dns = oldDNS
		cfg.Tls = oldTLS
	})

	srv, err := Start()
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if srv == nil {
		t.Fatal("Start() returned nil server")
	}

	select {
	case err := <-srv.Errors():
		t.Fatalf("unexpected listener error: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() after Shutdown() error = %v", err)
	}
}

func TestStartDNSListenersIgnoresUnrelatedRuntimeError(t *testing.T) {
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {})
	servers := []*dns.Server{
		{
			Addr:    "127.0.0.1:0",
			Net:     "udp",
			Handler: handler,
		},
		{
			Addr:    "127.0.0.1:0",
			Net:     "tcp",
			Handler: handler,
		},
	}
	srv := &Server{
		servers: servers,
		errCh:   make(chan error, len(servers)+1),
	}
	runtimeErr := errors.New("previous listener failed")
	srv.errCh <- runtimeErr

	if err := startDNSListeners(srv, servers); err != nil {
		t.Fatalf("startDNSListeners() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	select {
	case err := <-srv.Errors():
		if !errors.Is(err, runtimeErr) {
			t.Fatalf("unexpected runtime error = %v", err)
		}
	default:
		t.Fatal("expected runtime error to remain pending")
	}
}

func TestResolutionContextDefaults(t *testing.T) {
	ctx := newResolutionContext()
	if ctx.depth != 0 {
		t.Errorf("expected depth 0, got %d", ctx.depth)
	}
	if ctx.maxDepth != 10 {
		t.Errorf("expected maxDepth 10, got %d", ctx.maxDepth)
	}
	if len(ctx.visited) != 0 {
		t.Errorf("expected empty visited map")
	}
}

func TestResolutionContextCycleDetection(t *testing.T) {
	ctx := newResolutionContext()

	// First visit should succeed
	if ctx.hasVisited("example.com.") {
		t.Error("should not have visited example.com yet")
	}
	ctx.markVisited("example.com.")

	// Second visit should be detected
	if !ctx.hasVisited("example.com.") {
		t.Error("should detect visited example.com")
	}
}

func TestResolutionContextDepthLimit(t *testing.T) {
	ctx := newResolutionContext()
	ctx.maxDepth = 3

	child1 := ctx.descend()
	if child1.depth != 1 {
		t.Errorf("expected depth 1, got %d", child1.depth)
	}

	child2 := child1.descend()
	child3 := child2.descend()

	if !child3.atMaxDepth() {
		t.Error("should be at max depth")
	}
}

func TestLoadTLSConfig(t *testing.T) {
	certFilePath, keyFilePath := writeTestCertificateFiles(t)

	tlsConfig, err := loadTLSConfig(certFilePath, keyFilePath)
	if err != nil {
		t.Fatalf("unexpected error loading TLS config: %v", err)
	}
	if tlsConfig == nil {
		t.Fatal("expected non-nil TLS config")
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf(
			"expected one TLS certificate, got %d",
			len(tlsConfig.Certificates),
		)
	}
	if len(tlsConfig.Certificates[0].Certificate) == 0 {
		t.Error("expected parsed certificate data")
	}
}

func TestLoadTLSConfigReturnsLoadError(t *testing.T) {
	dir := t.TempDir()
	certFilePath := filepath.Join(dir, "cert.pem")
	keyFilePath := filepath.Join(dir, "missing-key.pem")
	if err := os.WriteFile(
		certFilePath,
		[]byte("invalid certificate"),
		0o600,
	); err != nil {
		t.Fatalf("failed to write test cert: %v", err)
	}

	tlsConfig, err := loadTLSConfig(certFilePath, keyFilePath)
	if err == nil {
		t.Fatal("expected error loading invalid TLS config")
	}
	if tlsConfig != nil {
		t.Fatal("expected nil TLS config on load error")
	}
	if !strings.Contains(err.Error(), "load TLS certificate") {
		t.Fatalf("expected wrapped load error, got %v", err)
	}
}

func TestLoadConfiguredTLSConfigReturnsErrorForPartialPaths(t *testing.T) {
	testCases := []struct {
		name         string
		certFilePath string
		keyFilePath  string
	}{
		{
			name:         "cert only",
			certFilePath: "cert.pem",
		},
		{
			name:        "key only",
			keyFilePath: "key.pem",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tlsConfig, err := loadConfiguredTLSConfig(
				&config.Config{
					Tls: config.TlsConfig{
						CertFilePath: tc.certFilePath,
						KeyFilePath:  tc.keyFilePath,
					},
				},
			)
			if err == nil {
				t.Fatal("expected error for partial TLS config")
			}
			if tlsConfig != nil {
				t.Fatal("expected nil TLS config on partial TLS config")
			}
			if !strings.Contains(
				err.Error(),
				"must both be configured",
			) {
				t.Fatalf("expected partial TLS config error, got %v", err)
			}
		})
	}
}

func TestLoadConfiguredTLSConfigLogsInfoWhenPathsEmpty(t *testing.T) {
	var logOutput bytes.Buffer
	originalLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logOutput, nil)))
	t.Cleanup(func() {
		slog.SetDefault(originalLogger)
	})

	tlsConfig, err := loadConfiguredTLSConfig(&config.Config{})
	if err != nil {
		t.Fatalf("unexpected error for empty TLS config: %v", err)
	}
	if tlsConfig != nil {
		t.Fatal("expected nil TLS config for empty TLS config")
	}
	if !strings.Contains(logOutput.String(), "TLS listener disabled") {
		t.Fatalf("expected TLS disabled log, got %q", logOutput.String())
	}
	if !strings.Contains(logOutput.String(), "level=INFO") {
		t.Fatalf(
			"expected TLS disabled log at info level, got %q",
			logOutput.String(),
		)
	}
	if strings.Contains(logOutput.String(), "level=WARN") {
		t.Fatalf(
			"expected TLS disabled log not to warn, got %q",
			logOutput.String(),
		)
	}
}

func writeTestCertificateFiles(t *testing.T) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&privateKey.PublicKey,
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	dir := t.TempDir()
	certFilePath := filepath.Join(dir, "cert.pem")
	keyFilePath := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	if err := os.WriteFile(certFilePath, certPEM, 0o600); err != nil {
		t.Fatalf("failed to write certificate: %v", err)
	}
	if err := os.WriteFile(keyFilePath, keyPEM, 0o600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	return certFilePath, keyFilePath
}

// stateIsLoaded checks if the state database is properly initialized
func stateIsLoaded() bool {
	s := state.GetState()
	if s == nil {
		return false
	}
	// Try a lookup to see if db is initialized - this will panic if db is nil
	loaded := true
	func() {
		defer func() {
			if recover() != nil {
				loaded = false
			}
		}()
		_, err := s.LookupRecords([]string{"A"}, "test")
		if err != nil {
			loaded = false
		}
	}()
	return loaded
}

type captureResponseWriter struct {
	msg    *dns.Msg
	raw    []byte
	remote net.Addr
}

// doQueryWithContext is a test helper for exercising the nameserver query
// path with one explicitly addressed server.
func (r *Resolver) doQueryWithContext(
	msg *dns.Msg,
	address string,
	recursive bool,
	ctx *resolutionContext,
) (*dns.Msg, error) {
	if ctx == nil {
		ctx = newResolutionContext()
	}
	if err := requestContext(ctx).Err(); err != nil {
		return nil, err
	}
	if ctx.atMaxDepth() {
		return nil, errors.New("max resolution depth exceeded")
	}

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "53"
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", host)
	}
	return r.queryMultipleNameserversWithPort(
		msg,
		map[string][]net.IP{"initial": {ip}},
		recursive,
		ctx,
		port,
	)
}

func (w *captureResponseWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (w *captureResponseWriter) RemoteAddr() net.Addr {
	if w.remote != nil {
		return w.remote
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func (w *captureResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.msg = msg.Copy()
	return nil
}

func (w *captureResponseWriter) Write(raw []byte) (int, error) {
	w.raw = append([]byte(nil), raw...)
	return len(raw), nil
}

func (w *captureResponseWriter) Close() error {
	return nil
}

func (w *captureResponseWriter) TsigStatus() error {
	return nil
}

func (w *captureResponseWriter) TsigTimersOnly(bool) {}

func (w *captureResponseWriter) Hijack() {}

func TestHandleQueryMalformedQuestionCounts(t *testing.T) {
	resolver := &Resolver{}
	question := dns.Question{
		Name:   "example.com.",
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}
	testCases := []struct {
		name      string
		questions []dns.Question
	}{
		{
			name:      "nil questions",
			questions: nil,
		},
		{
			name:      "empty questions",
			questions: []dns.Question{},
		},
		{
			name: "multiple questions",
			questions: []dns.Question{
				question,
				{
					Name:   "example.net.",
					Qtype:  dns.TypeAAAA,
					Qclass: dns.ClassINET,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id:               1234,
					RecursionDesired: true,
				},
				Question: tc.questions,
			}
			w := &captureResponseWriter{}

			resolver.handleQuery(w, req)

			if w.msg == nil {
				t.Fatal("expected response")
			}
			if w.msg.Id != req.Id {
				t.Errorf(
					"expected response id %d, got %d",
					req.Id,
					w.msg.Id,
				)
			}
			if !w.msg.Response {
				t.Error("expected response bit to be set")
			}
			if w.msg.Rcode != dns.RcodeFormatError {
				t.Errorf(
					"expected FORMERR, got %s",
					dns.RcodeToString[w.msg.Rcode],
				)
			}
			if len(w.msg.Question) != 0 {
				t.Errorf(
					"expected no echoed questions, got %d",
					len(w.msg.Question),
				)
			}
		})
	}
}

func TestHandleQueryNilRequestDoesNotPanic(t *testing.T) {
	resolver := &Resolver{}
	w := &captureResponseWriter{}
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("handleQuery panicked: %v", err)
		}
		if w.msg != nil {
			t.Fatal("expected no response for nil request")
		}
	}()

	resolver.handleQuery(w, nil)
}

func TestRecursionAllowlist(t *testing.T) {
	cfg := *config.GetConfig()
	cfg.Dns.RecursionAllowlist = []string{"192.0.2.0/24", "2001:db8::1"}
	resolver, err := NewResolver(&cfg)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	if !resolver.recursionAllowed(&captureResponseWriter{
		remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 53},
	}) {
		t.Error("allowlisted IPv4 client was rejected")
	}
	if !resolver.recursionAllowed(&captureResponseWriter{
		remote: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 53},
	}) {
		t.Error("allowlisted IPv6 client was rejected")
	}
	if resolver.recursionAllowed(&captureResponseWriter{
		remote: &net.UDPAddr{IP: net.ParseIP("198.51.100.1"), Port: 53},
	}) {
		t.Error("non-allowlisted client was accepted")
	}
}

func TestNonAllowlistedClientStillReceivesAuthoritativeResponses(t *testing.T) {
	loadIsolatedTestState(t)
	cfg := config.GetConfig()
	originalDNS := cfg.Dns
	cfg.Dns.RecursionEnabled = true
	cfg.Dns.RecursionAllowlist = []string{"127.0.0.0/8"}
	t.Cleanup(func() { cfg.Dns = originalDNS })

	resolver, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	var exchanges atomic.Int32
	resolver.exchangeFn = func(
		context.Context,
		*dns.Msg,
		string,
		time.Duration,
	) (*dns.Msg, error) {
		exchanges.Add(1)
		return nil, errors.New("unexpected upstream exchange")
	}
	if err := state.GetState().UpdateDomain(
		"delegated.ada",
		[]state.DomainRecord{
			{
				Lhs:  "delegated.ada.",
				Type: "NS",
				Ttl:  300,
				Rhs:  "ns.delegated.ada.",
			},
			{
				Lhs:  "ns.delegated.ada.",
				Type: "A",
				Ttl:  300,
				Rhs:  "192.0.2.53",
			},
		},
	); err != nil {
		t.Fatalf("UpdateDomain() error = %v", err)
	}

	remote := &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 53000}
	t.Run("delegation referral", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("www.delegated.ada.", dns.TypeA)
		req.RecursionDesired = true
		writer := &captureResponseWriter{remote: remote}

		resolver.handleQuery(writer, req)

		if writer.msg == nil {
			t.Fatal("handleQuery() wrote no response")
		}
		if writer.msg.Rcode != dns.RcodeSuccess || len(writer.msg.Ns) == 0 {
			t.Fatalf("response = %v, want authoritative referral", writer.msg)
		}
		if writer.msg.RecursionAvailable {
			t.Fatal("referral advertised recursion to a disallowed client")
		}
	})

	t.Run("authoritative negative", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("missing.ada.", dns.TypeA)
		req.RecursionDesired = true
		writer := &captureResponseWriter{remote: remote}

		resolver.handleQuery(writer, req)

		if writer.msg == nil {
			t.Fatal("handleQuery() wrote no response")
		}
		if writer.msg.Rcode != dns.RcodeNameError || !writer.msg.Authoritative {
			t.Fatalf("response = %v, want authoritative NXDOMAIN", writer.msg)
		}
		if writer.msg.RecursionAvailable {
			t.Fatal(
				"negative response advertised recursion to a disallowed client",
			)
		}
	})

	t.Run("unrelated name refused", func(t *testing.T) {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		req.RecursionDesired = true
		writer := &captureResponseWriter{remote: remote}

		resolver.handleQuery(writer, req)

		if writer.msg == nil {
			t.Fatal("handleQuery() wrote no response")
		}
		if writer.msg.Rcode != dns.RcodeRefused {
			t.Fatalf("response = %v, want REFUSED", writer.msg)
		}
		if writer.msg.RecursionAvailable {
			t.Fatal("refusal advertised recursion to a disallowed client")
		}
	})

	if got := exchanges.Load(); got != 0 {
		t.Fatalf("disallowed client triggered %d upstream exchanges", got)
	}
}

func TestResolveNameserverAddressBoundsConcurrentRootQueries(t *testing.T) {
	resolver := &Resolver{
		rootHints: map[uint16]map[string][]dns.RR{
			dns.TypeA: {
				"a.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "a.root-test.",
							Rrtype: dns.TypeA,
						},
						A: net.ParseIP("192.0.2.1"),
					},
				},
				"b.root-test.": {
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   "b.root-test.",
							Rrtype: dns.TypeA,
						},
						A: net.ParseIP("192.0.2.2"),
					},
				},
			},
			dns.TypeAAAA: {
				"a.root-test.": {
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   "a.root-test.",
							Rrtype: dns.TypeAAAA,
						},
						AAAA: net.ParseIP("2001:db8::1"),
					},
				},
				"b.root-test.": {
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   "b.root-test.",
							Rrtype: dns.TypeAAAA,
						},
						AAAA: net.ParseIP("2001:db8::2"),
					},
				},
			},
		},
	}
	started := make(chan struct{}, 8)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	resolver.exchangeFn = func(
		ctx context.Context,
		msg *dns.Msg,
		_ string,
		_ time.Duration,
	) (*dns.Msg, error) {
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Authoritative = true
		if msg.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   msg.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
				},
				A: net.ParseIP("192.0.2.53"),
			}}
		} else {
			resp.Answer = []dns.RR{&dns.AAAA{
				Hdr:  dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET},
				AAAA: net.ParseIP("2001:db8::53"),
			}}
		}
		return resp, nil
	}

	done := make(chan error, 1)
	go func() {
		_, err := resolver.resolveNameserverAddress(
			"ns.example.",
			newResolutionContext(),
		)
		done <- err
	}()
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("two root exchanges did not start")
		}
	}
	select {
	case <-started:
		t.Error("more than two root exchanges started concurrently")
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("resolveNameserverAddress() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("resolveNameserverAddress() did not finish")
	}
}

func TestNameserverQueryLimitIsSharedAcrossReferrals(t *testing.T) {
	resolver := &Resolver{}
	started := make(chan string, 4)
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	resolver.exchangeFn = func(
		ctx context.Context,
		query *dns.Msg,
		address string,
		_ time.Duration,
	) (*dns.Msg, error) {
		if address == "192.0.2.1:53" {
			response := new(dns.Msg)
			response.SetReply(query)
			response.Ns = []dns.RR{
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:   "example.",
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
					},
					Ns: "ns1.example.",
				},
				&dns.NS{
					Hdr: dns.RR_Header{
						Name:   "example.",
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
					},
					Ns: "ns2.example.",
				},
			}
			response.Extra = []dns.RR{
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "ns1.example.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.ParseIP("198.51.100.1"),
				},
				&dns.A{
					Hdr: dns.RR_Header{
						Name:   "ns2.example.",
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
					},
					A: net.ParseIP("198.51.100.2"),
				},
			}
			return response, nil
		}

		started <- address
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		response := new(dns.Msg)
		response.SetReply(query)
		response.Authoritative = true
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:   query.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: net.ParseIP("203.0.113.10"),
		}}
		return response, nil
	}

	query := new(dns.Msg)
	query.SetQuestion("www.example.", dns.TypeA)
	done := make(chan error, 1)
	go func() {
		_, err := resolver.queryNameserverAddresses(
			query,
			[]string{"192.0.2.1:53", "192.0.2.2:53"},
			true,
			newResolutionContext(),
		)
		done <- err
	}()
	for range maxConcurrentNameserverQueries {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("parent and child exchanges did not start")
		}
	}
	select {
	case address := <-started:
		t.Fatalf("nested referral exceeded query limit at %s", address)
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("queryNameserverAddresses() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("queryNameserverAddresses() did not finish")
	}
}

func TestUnsupportedClassReturnsNotImplementedAndRA(t *testing.T) {
	cfg := config.GetConfig()
	original := cfg.Dns.RecursionEnabled
	cfg.Dns.RecursionEnabled = true
	t.Cleanup(func() { cfg.Dns.RecursionEnabled = original })

	req := new(dns.Msg)
	req.SetQuestion("example.", dns.TypeA)
	req.Question[0].Qclass = dns.ClassCHAOS
	w := &captureResponseWriter{}
	resolver, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	resolver.handleQuery(w, req)
	if w.msg == nil {
		t.Fatal("expected response")
	}
	if w.msg.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("rcode = %s, want NOTIMP", dns.RcodeToString[w.msg.Rcode])
	}
	if !w.msg.RecursionAvailable {
		t.Error("expected RA when recursion is enabled")
	}
}

func TestNewResolverLoadsRootHints(t *testing.T) {
	cfg := *config.GetConfig()
	cfg.Dns.RootHints = strings.Join(
		[]string{
			". 3600000 IN NS A.ROOT-TEST.",
			"A.ROOT-TEST. 3600000 IN A 192.0.2.1",
			"A.ROOT-TEST. 3600000 IN AAAA 2001:db8::1",
		},
		"\n",
	)

	resolver, err := NewResolver(&cfg)
	if err != nil {
		t.Fatalf("unexpected resolver error: %v", err)
	}
	if resolver.rootHints == nil {
		t.Fatal("expected root hints to be initialized")
	}
	if len(resolver.rootHints[dns.TypeNS]["."]) != 1 {
		t.Errorf("expected one root NS hint")
	}
	if len(resolver.rootHints[dns.TypeA]["a.root-test."]) != 1 {
		t.Errorf("expected one root A hint")
	}
	if len(resolver.rootHints[dns.TypeAAAA]["a.root-test."]) != 1 {
		t.Errorf("expected one root AAAA hint")
	}
	if rootNS := resolver.getRandomRootServer(); rootNS != "192.0.2.1:53" {
		t.Errorf("expected IPv4 root server, got %q", rootNS)
	}
	rootServers := resolver.rootServers()
	if len(rootServers) != 2 || rootServers[0] != "192.0.2.1:53" ||
		rootServers[1] != "[2001:db8::1]:53" {
		t.Errorf(
			"root server order = %v, want IPv4 followed by IPv6",
			rootServers,
		)
	}
}

func TestResolveNameserverAddressFromLocal(t *testing.T) {
	// This test requires state to be initialized with a database
	// Skip if state not available (will be tested via integration)
	if !stateIsLoaded() {
		t.Skip("state database not loaded")
	}

	resolver := &Resolver{}
	ctx := newResolutionContext()
	// Resolving a nonexistent nameserver should return an error
	// (no local records, upstream resolution will fail)
	ips, err := resolver.resolveNameserverAddress(
		"nonexistent.example.com.",
		ctx,
	)
	if err == nil {
		t.Error("expected error for nonexistent nameserver")
	}
	if len(ips) != 0 {
		t.Errorf("expected empty result for nonexistent nameserver")
	}
}

func TestResolveNameserverAddressDepthLimit(t *testing.T) {
	resolver := &Resolver{}
	ctx := newResolutionContext()
	ctx.depth = ctx.maxDepth // Already at max depth

	ips, err := resolver.resolveNameserverAddress("any.example.com.", ctx)
	if err == nil {
		t.Error("expected error at max depth")
	}
	if ips != nil {
		t.Error("expected nil result at max depth")
	}
}

func TestResolveNameserverAddressCycleDetection(t *testing.T) {
	resolver := &Resolver{}
	ctx := newResolutionContext()
	ctx.markVisited("ns.example.com.") // Mark as already visited

	ips, err := resolver.resolveNameserverAddress("ns.example.com.", ctx)
	if err == nil {
		t.Error("expected error for cycle detection")
	}
	if ips != nil {
		t.Error("expected nil result for cycle")
	}
}

func TestResolveNameserverAddressWithoutState(t *testing.T) {
	resolver := &Resolver{}
	ctx := newResolutionContext()
	ips, err := resolver.resolveNameserverAddress("ns.example.com.", ctx)
	if err == nil {
		t.Fatal("expected error without state or root hints")
	}
	if len(ips) != 0 {
		t.Errorf("expected no IPs, got %v", ips)
	}
}

func TestDoQueryWithContextBasic(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := newResolutionContext()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resolver := &Resolver{}
	// This should work against a public resolver
	resp, err := resolver.doQueryWithContext(msg, "8.8.8.8:53", false, ctx)
	if err != nil {
		t.Skipf("network unavailable: %v", err)
	}
	if resp == nil {
		t.Error("expected response")
	}
}

func TestResolveNameserverAddressUpstream(t *testing.T) {
	// Integration test - requires network access and initialized state
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Check if state is loaded (database initialized)
	if !stateIsLoaded() {
		t.Skip("state database not loaded")
	}

	// Initialize config and root hints for test
	cfg := config.GetConfig()
	if cfg == nil {
		t.Skip("config not initialized")
	}

	resolver, err := NewResolver(cfg)
	if err != nil {
		t.Fatalf("unexpected resolver error: %v", err)
	}
	ctx := newResolutionContext()
	// Try to resolve a well-known nameserver
	ips, err := resolver.resolveNameserverAddress("a.root-servers.net.", ctx)
	if err != nil {
		t.Logf("warning: upstream resolution failed: %v", err)
		// Don't fail - network may not be available
		return
	}
	if len(ips) == 0 {
		t.Log("warning: no IPs resolved for a.root-servers.net")
	}
}

func TestFindNameserversResolvesGlue(t *testing.T) {
	// This is an integration test that verifies the full flow
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Check if state is loaded (database initialized)
	if !stateIsLoaded() {
		t.Skip("state database not loaded")
	}

	// Test with a domain known to use external nameservers
	// blinklabs.io is mentioned in the issue as an example
	resolver := &Resolver{}
	_, nsMap, err := resolver.findNameserversForDomain("blinklabs.io.")
	if err != nil {
		t.Skipf("could not test: %v", err)
	}

	// Should have found some nameservers with resolved addresses
	hasAddresses := false
	for _, ips := range nsMap {
		if len(ips) > 0 {
			hasAddresses = true
			break
		}
	}
	if !hasAddresses {
		t.Log("warning: no nameserver addresses resolved")
	}
}

func TestThirdPartyDNSDelegation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Test resolution of a domain known to use third-party DNS
	// without in-bailiwick glue records
	testCases := []struct {
		name   string
		domain string
	}{
		{"cloudflare-hosted", "blinklabs.io."},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.GetConfig()
			if cfg == nil {
				t.Skip("config not initialized")
			}
			resolver, err := NewResolver(cfg)
			if err != nil {
				t.Fatalf("unexpected resolver error: %v", err)
			}
			ctx := newResolutionContext()
			queryCtx, cancel := context.WithTimeout(
				ctx.requestCtx,
				10*time.Second,
			)
			defer cancel()
			ctx.requestCtx = queryCtx
			msg := new(dns.Msg)
			msg.SetQuestion(tc.domain, dns.TypeA)

			// Start from root
			rootNS := resolver.getRandomRootServer()
			if rootNS == "" {
				t.Skip("no root servers configured")
			}

			resp, err := resolver.doQueryWithContext(msg, rootNS, true, ctx)
			if err != nil {
				t.Skipf("network error: %v", err)
			}

			if resp.Rcode != dns.RcodeSuccess {
				t.Errorf("expected success, got rcode %d", resp.Rcode)
			}

			if len(resp.Answer) == 0 {
				t.Log("warning: no answer records returned")
			}
		})
	}
}

func TestGetNameserversAcceptsOnlyInBailiwickGlue(t *testing.T) {
	msg := new(dns.Msg)
	msg.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
			Ns: "NS.EXAMPLE.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
			},
			Ns: "ns.external.",
		},
	}
	msg.Extra = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "ns.example.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: net.ParseIP("192.0.2.1"),
		},
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "ns.external.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: net.ParseIP("192.0.2.2"),
		},
	}

	got := getNameserversFromResponse(msg)
	if len(got["ns.example."]) != 1 ||
		!got["ns.example."][0].Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("in-bailiwick glue = %v, want 192.0.2.1", got)
	}
	if len(got["ns.external."]) != 0 {
		t.Fatalf("accepted out-of-bailiwick glue: %v", got)
	}
}

func TestHandleReferralWithoutGlueSkipsUnloadedState(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.test.", dns.TypeA)

	referral := new(dns.Msg)
	referral.SetReply(msg)
	referral.Ns = []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.test.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ns: "ns.external.test.",
		},
	}

	resolver := &Resolver{}
	ctx := newResolutionContext()
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("handleReferral panicked: %v", err)
		}
	}()

	resp, err := resolver.handleReferral(msg, referral, ctx)
	if err == nil {
		t.Fatal("expected referral resolution error with no root hints")
	}
	if resp != nil {
		t.Fatal("expected nil response when referral resolution fails")
	}
}

func TestGenerateSyntheticSOA(t *testing.T) {
	soa := generateSyntheticSOA("ada.")
	if soa == nil {
		t.Fatal("expected non-nil SOA record")
	}
	if soa.Hdr.Name != "ada." {
		t.Errorf(
			"expected zone name ada., got %s",
			soa.Hdr.Name,
		)
	}
	if soa.Hdr.Rrtype != dns.TypeSOA {
		t.Errorf(
			"expected SOA rrtype, got %d",
			soa.Hdr.Rrtype,
		)
	}
	if soa.Hdr.Class != dns.ClassINET {
		t.Errorf(
			"expected INET class, got %d",
			soa.Hdr.Class,
		)
	}
	// Verify config defaults are used
	cfg := config.GetConfig()
	soaCfg := cfg.Dns.SOA
	if soa.Ns != soaCfg.Mname {
		t.Errorf(
			"expected mname %s, got %s",
			soaCfg.Mname,
			soa.Ns,
		)
	}
	if soa.Mbox != soaCfg.Rname {
		t.Errorf(
			"expected rname %s, got %s",
			soaCfg.Rname,
			soa.Mbox,
		)
	}
	if soa.Refresh != soaCfg.Refresh {
		t.Errorf(
			"expected refresh %d, got %d",
			soaCfg.Refresh,
			soa.Refresh,
		)
	}
	if soa.Retry != soaCfg.Retry {
		t.Errorf(
			"expected retry %d, got %d",
			soaCfg.Retry,
			soa.Retry,
		)
	}
	if soa.Expire != soaCfg.Expire {
		t.Errorf(
			"expected expire %d, got %d",
			soaCfg.Expire,
			soa.Expire,
		)
	}
	if soa.Minttl != soaCfg.Minimum {
		t.Errorf(
			"expected minimum %d, got %d",
			soaCfg.Minimum,
			soa.Minttl,
		)
	}
	// Verify serial is date-based (YYYYMMDD00)
	if soa.Serial == 0 {
		t.Error("expected non-zero serial")
	}
	// Capture time before and after to handle midnight
	// rollover
	now := time.Now().UTC()
	serialFull := fmt.Sprintf("%d", soa.Serial)
	todayPrefix := now.Format("20060102")
	yesterdayPrefix := now.AddDate(0, 0, -1).
		Format("20060102")
	if !strings.HasPrefix(serialFull, todayPrefix) &&
		!strings.HasPrefix(serialFull, yesterdayPrefix) {
		t.Errorf(
			"expected serial to start with %s or %s, got %s",
			todayPrefix,
			yesterdayPrefix,
			serialFull,
		)
	}
	if !strings.HasSuffix(serialFull, "00") {
		t.Errorf(
			"expected serial to end with 00, got %s",
			serialFull,
		)
	}
}

func TestGenerateSyntheticSOAFqdnHandling(t *testing.T) {
	// Test with non-FQDN input
	soa := generateSyntheticSOA("ada")
	if soa.Hdr.Name != "ada." {
		t.Errorf(
			"expected FQDN ada., got %s",
			soa.Hdr.Name,
		)
	}
	// Test with already-FQDN input
	soa = generateSyntheticSOA("cardano.")
	if soa.Hdr.Name != "cardano." {
		t.Errorf(
			"expected FQDN cardano., got %s",
			soa.Hdr.Name,
		)
	}
}

func TestFindZoneForNameFromProfiles(t *testing.T) {
	// Profiles should work even without state loaded.
	// ada is a configured profile TLD.
	zone := findZoneForName("test.ada.")
	if zone != "ada." {
		t.Errorf(
			"expected ada. zone, got %q",
			zone,
		)
	}
}

func TestFindZoneForNameEmpty(t *testing.T) {
	// Root domain should return empty
	zone := findZoneForName(".")
	if zone != "" {
		t.Errorf(
			"expected empty zone for root, got %q",
			zone,
		)
	}
}

func TestIsBlockchainTLDFromProfiles(t *testing.T) {
	if !stateIsLoaded() {
		// Without state, isBlockchainTLD panics on
		// state.GetState().GetDiscoveredAddresses()
		// so skip this test
		t.Skip("state database not loaded")
	}

	testCases := []struct {
		name     string
		tld      string
		expected bool
	}{
		{"ada profile", "ada", true},
		{"cardano profile", "cardano", true},
		{"hydra profile", "hydra", true},
		{"unknown tld", "unknown", false},
		{"with trailing dot", "ada.", true},
		{"case insensitive", "ADA", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isBlockchainTLD(tc.tld)
			if result != tc.expected {
				t.Errorf(
					"isBlockchainTLD(%q) = %v, want %v",
					tc.tld,
					result,
					tc.expected,
				)
			}
		})
	}
}

func TestSOAConfigDefaults(t *testing.T) {
	cfg := config.GetConfig()
	soaCfg := cfg.Dns.SOA
	if soaCfg.Mname == "" {
		t.Error("expected non-empty SOA mname default")
	}
	if soaCfg.Rname == "" {
		t.Error("expected non-empty SOA rname default")
	}
	if soaCfg.Refresh == 0 {
		t.Error("expected non-zero SOA refresh default")
	}
	if soaCfg.Retry == 0 {
		t.Error("expected non-zero SOA retry default")
	}
	if soaCfg.Expire == 0 {
		t.Error("expected non-zero SOA expire default")
	}
	if soaCfg.Minimum == 0 {
		t.Error("expected non-zero SOA minimum default")
	}
}

func TestQueryWithRetry(t *testing.T) {
	attempts := 0
	mockQuery := func() (*dns.Msg, error) {
		attempts++
		if attempts < 3 {
			return nil, fmt.Errorf(
				"simulated failure %d",
				attempts,
			)
		}
		return &dns.Msg{}, nil
	}

	result, err := queryWithRetry(
		mockQuery,
		3,
		10*time.Millisecond,
	)
	if err != nil {
		t.Errorf(
			"expected success after retries, got: %v",
			err,
		)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestQueryWithRetryExhausted(t *testing.T) {
	attempts := 0
	mockQuery := func() (*dns.Msg, error) {
		attempts++
		return nil, fmt.Errorf("always fails")
	}

	result, err := queryWithRetry(
		mockQuery,
		3,
		10*time.Millisecond,
	)
	if err == nil {
		t.Error("expected error when retries exhausted")
	}
	if result != nil {
		t.Error("expected nil result on failure")
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestQueryWithRetryFirstAttemptSuccess(t *testing.T) {
	attempts := 0
	mockQuery := func() (*dns.Msg, error) {
		attempts++
		return &dns.Msg{}, nil
	}

	result, err := queryWithRetry(
		mockQuery,
		3,
		10*time.Millisecond,
	)
	if err != nil {
		t.Errorf("expected success, got: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestQueryWithRetryContextCancelsBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := make(chan struct{})
	var once sync.Once
	go func() {
		<-started
		cancel()
	}()

	_, err := queryWithRetryContext(ctx, func() (*dns.Msg, error) {
		once.Do(func() { close(started) })
		return nil, errors.New("temporary failure")
	}, 3, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

// startTestDNSServer starts a local UDP DNS server on the
// given address with the given handler and returns its IP
// and port. The server is shut down when the test completes.
// Use "127.0.0.1:0" for a random port or specify a port.
func startTestDNSServer(
	t *testing.T,
	addr string,
	handler dns.Handler,
) (net.IP, string) {
	t.Helper()
	srv := &dns.Server{
		Net:     "udp",
		Handler: handler,
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen on %s: %v", addr, err)
	}
	srv.PacketConn = pc
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { srv.Shutdown() })

	localAddr := pc.LocalAddr()
	if localAddr == nil {
		t.Fatal("failed to get local address")
	}
	host, port, err := net.SplitHostPort(
		localAddr.String(),
	)
	if err != nil {
		t.Fatalf("failed to parse address: %v", err)
	}
	return net.ParseIP(host), port
}

// successHandler returns a DNS handler that responds with
// a single A record for any query.
func successHandler() dns.Handler {
	return dns.HandlerFunc(
		func(w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   r.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("127.0.0.1"),
			})
			_ = w.WriteMsg(resp)
		},
	)
}

func TestQueryMultipleNameservers(t *testing.T) {
	ip1, port1 := startTestDNSServer(
		t, "127.0.0.1:0", successHandler(),
	)
	// Start second server on same port but different IP
	ip2, _ := startTestDNSServer(
		t, "127.0.0.2:"+port1, successHandler(),
	)

	nameservers := map[string][]net.IP{
		"resolver1.": {ip1},
		"resolver2.": {ip2},
	}

	ctx := newResolutionContext()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resolver := &Resolver{}
	resp, err := resolver.queryMultipleNameserversWithPort(
		msg,
		nameservers,
		false,
		ctx,
		port1,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp == nil {
		t.Error("expected response")
	}
}

func TestQueryMultipleNameserversFailover(t *testing.T) {
	// Failing server: returns SERVFAIL
	badHandler := dns.HandlerFunc(
		func(w dns.ResponseWriter, r *dns.Msg) {
			resp := new(dns.Msg)
			resp.SetReply(r)
			resp.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(resp)
		},
	)

	badIP, port := startTestDNSServer(
		t, "127.0.0.1:0", badHandler,
	)
	goodIP, _ := startTestDNSServer(
		t, "127.0.0.2:"+port, successHandler(),
	)

	nameservers := map[string][]net.IP{
		"bad.":  {badIP},
		"good.": {goodIP},
	}

	cfg := config.GetConfig()
	origTimeout := cfg.Dns.QueryTimeoutMs
	origRetry := cfg.Dns.RetryCount
	cfg.Dns.QueryTimeoutMs = 500
	cfg.Dns.RetryCount = 1
	defer func() {
		cfg.Dns.QueryTimeoutMs = origTimeout
		cfg.Dns.RetryCount = origRetry
	}()

	ctx := newResolutionContext()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resolver := &Resolver{}
	resp, err := resolver.queryMultipleNameserversWithPort(
		msg,
		nameservers,
		false,
		ctx,
		port,
	)
	if err != nil {
		t.Fatalf("expected fallback success, got: %v", err)
	}
	if resp == nil {
		t.Error("expected response from fallback nameserver")
	}
}

func TestQueryMultipleNameserversNoAddresses(t *testing.T) {
	ctx := newResolutionContext()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	nameservers := map[string][]net.IP{}

	resolver := &Resolver{}
	_, err := resolver.queryMultipleNameservers(
		msg,
		nameservers,
		false,
		ctx,
	)
	if err == nil {
		t.Error("expected error with no nameservers")
	}
}

func TestQueryTimeoutRespected(t *testing.T) {
	cfg := config.GetConfig()
	origTimeout := cfg.Dns.QueryTimeoutMs
	origRetry := cfg.Dns.RetryCount
	origDelay := cfg.Dns.RetryDelayMs
	cfg.Dns.QueryTimeoutMs = 100
	cfg.Dns.RetryCount = 1
	cfg.Dns.RetryDelayMs = 10
	defer func() {
		cfg.Dns.QueryTimeoutMs = origTimeout
		cfg.Dns.RetryCount = origRetry
		cfg.Dns.RetryDelayMs = origDelay
	}()

	ctx := newResolutionContext()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	start := time.Now()
	resolver := &Resolver{}
	_, err := resolver.doQueryWithContext(
		msg,
		"192.0.2.1:53",
		false,
		ctx,
	)
	elapsed := time.Since(start)

	if err == nil {
		t.Skip(
			"unexpectedly got response from TEST-NET address",
		)
	}

	// Should timeout within reasonable time
	maxExpected := 2 * time.Second
	if elapsed > maxExpected {
		t.Errorf(
			"query took too long: %v (expected < %v)",
			elapsed,
			maxExpected,
		)
	}
}

func TestServfailRetriedBeforeFailover(t *testing.T) {
	var attempts atomic.Int32
	// Start a DNS server that returns SERVFAIL once,
	// then succeeds on retry.
	handler := dns.HandlerFunc(
		func(w dns.ResponseWriter, r *dns.Msg) {
			n := attempts.Add(1)
			resp := new(dns.Msg)
			resp.SetReply(r)
			if n < 2 {
				resp.Rcode = dns.RcodeServerFailure
			}
			_ = w.WriteMsg(resp)
		},
	)

	srv := &dns.Server{
		Addr:    "127.0.0.1:0",
		Net:     "udp",
		Handler: handler,
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	srv.PacketConn = pc
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	localAddr := pc.LocalAddr()
	if localAddr == nil {
		t.Fatal("failed to get local address")
	}
	addr := localAddr.String()

	cfg := config.GetConfig()
	origTimeout := cfg.Dns.QueryTimeoutMs
	origRetry := cfg.Dns.RetryCount
	origDelay := cfg.Dns.RetryDelayMs
	cfg.Dns.QueryTimeoutMs = 1000
	cfg.Dns.RetryCount = 3
	cfg.Dns.RetryDelayMs = 10
	defer func() {
		cfg.Dns.QueryTimeoutMs = origTimeout
		cfg.Dns.RetryCount = origRetry
		cfg.Dns.RetryDelayMs = origDelay
	}()

	ctx := newResolutionContext()
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	resolver := &Resolver{}
	resp, err := resolver.doQueryWithContext(
		msg,
		addr,
		false,
		ctx,
	)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Errorf(
			"expected NOERROR, got %s",
			dns.RcodeToString[resp.Rcode],
		)
	}
	finalAttempts := attempts.Load()
	if finalAttempts < 2 {
		t.Errorf(
			"expected at least 2 attempts, got %d",
			finalAttempts,
		)
	}
}

func TestShuffleStrings(t *testing.T) {
	// Verify shuffle doesn't lose elements
	input := []string{"a", "b", "c", "d", "e"}
	original := make([]string, len(input))
	copy(original, input)

	shuffleStrings(input)

	if len(input) != len(original) {
		t.Errorf(
			"shuffle changed length: got %d, want %d",
			len(input),
			len(original),
		)
	}

	// Verify all elements still present
	seen := make(map[string]bool, len(input))
	for _, s := range input {
		seen[s] = true
	}
	for _, s := range original {
		if !seen[s] {
			t.Errorf("element %q lost after shuffle", s)
		}
	}
}
