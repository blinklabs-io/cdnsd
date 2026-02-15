// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"math/big"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var metricQueryTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "dns_query_total",
	Help: "total DNS queries handled",
})

// resolutionContext tracks state during recursive DNS resolution
// to prevent infinite loops and limit recursion depth.
type resolutionContext struct {
	depth    int
	maxDepth int
	visited  map[string]bool
}

func newResolutionContext() *resolutionContext {
	return &resolutionContext{
		depth:    0,
		maxDepth: 10,
		visited:  make(map[string]bool),
	}
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
		depth:    c.depth + 1,
		maxDepth: c.maxDepth,
		visited:  newVisited,
	}
}

// resolveNameserverAddress attempts to resolve A/AAAA records for a nameserver.
// It first checks local storage (Cardano/Handshake), then falls back to
// recursive resolution via upstream nameservers.
func resolveNameserverAddress(
	nsName string,
	ctx *resolutionContext,
) ([]net.IP, error) {
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

	// Not found locally - resolve via upstream using root hints
	childCtx := ctx.descend()

	// Build a DNS query for the nameserver's A record
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(nsName), dns.TypeA)
	msg.RecursionDesired = true

	// Start from root hints and resolve iteratively
	rootNS := getRandomRootServer()
	if rootNS == "" {
		return nil, errors.New("no root servers available")
	}

	resp, err := doQueryWithContext(msg, rootNS, true, childCtx)
	if err != nil {
		return nil, fmt.Errorf(
			"upstream resolution failed for %s: %w",
			nsName,
			err,
		)
	}

	// Extract A/AAAA records from response
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A)
		case *dns.AAAA:
			ips = append(ips, v.AAAA)
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf(
			"no A/AAAA records in upstream response for %s",
			nsName,
		)
	}

	return ips, nil
}

var rootHints map[uint16]map[string][]dns.RR

// getRandomRootServer returns a random root server address from hints
func getRandomRootServer() string {
	if rootHints == nil {
		return ""
	}
	if rootHints[dns.TypeA] == nil {
		return ""
	}
	// Collect all A records
	var servers []string
	for _, rrs := range rootHints[dns.TypeA] {
		for _, rr := range rrs {
			if a, ok := rr.(*dns.A); ok {
				servers = append(servers, net.JoinHostPort(a.A.String(), "53"))
			}
		}
	}
	if len(servers) == 0 {
		return ""
	}
	// Select one at random
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(servers))))
	if err != nil {
		return servers[0] // Fallback to first if random fails
	}
	return servers[n.Int64()]
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
		_, _ = state.GetState().
			LookupRecords([]string{"A"}, "__probe__")
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

func Start() error {
	cfg := config.GetConfig()
	listenAddr := fmt.Sprintf(
		"%s:%d",
		cfg.Dns.ListenAddress,
		cfg.Dns.ListenPort,
	)
	slog.Info(
		"starting DNS listener on " + listenAddr,
	)
	// Load root hints
	if err := loadRootHints(cfg); err != nil {
		return err
	}
	// Setup handler
	dns.HandleFunc(".", handleQuery)
	// UDP listener
	serverUdp := &dns.Server{
		Addr:       listenAddr,
		Net:        "udp",
		TsigSecret: nil,
		ReusePort:  true,
	}
	go startListener(serverUdp)
	// TCP listener
	serverTcp := &dns.Server{
		Addr:       listenAddr,
		Net:        "tcp",
		TsigSecret: nil,
		ReusePort:  true,
	}
	go startListener(serverTcp)
	// TLS listener
	if cfg.Tls.CertFilePath != "" && cfg.Tls.KeyFilePath != "" {
		listenTlsAddr := fmt.Sprintf(
			"%s:%d",
			cfg.Dns.ListenAddress,
			cfg.Dns.ListenTlsPort,
		)
		serverTls := &dns.Server{
			Addr:       listenTlsAddr,
			Net:        "tcp-tls",
			TsigSecret: nil,
			ReusePort:  false,
		}
		go startListener(serverTls)
	}
	return nil
}

func loadRootHints(cfg *config.Config) error {
	rootHints = make(map[uint16]map[string][]dns.RR)
	for line := range strings.SplitSeq(cfg.Dns.RootHints, "\n") {
		tmpRR, err := dns.NewRR(line)
		if err != nil {
			return fmt.Errorf("load root hints: %w", err)
		}
		if tmpRR == nil {
			continue
		}
		rrType := tmpRR.Header().Rrtype
		if _, ok := rootHints[rrType]; !ok {
			rootHints[rrType] = make(map[string][]dns.RR)
		}
		rootHints[rrType][tmpRR.Header().Name] = append(
			rootHints[rrType][tmpRR.Header().Name],
			tmpRR,
		)
	}
	return nil
}

func startListener(server *dns.Server) {
	if err := server.ListenAndServe(); err != nil {
		slog.Error(
			fmt.Sprintf("failed to start DNS listener: %s", err),
		)
		os.Exit(1)
	}
}

func handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	if r.Question == nil {
		return
	}
	cfg := config.GetConfig()
	m := new(dns.Msg)

	if cfg.Logging.QueryLog {
		for _, q := range r.Question {
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
	lookupRecordTypes := []uint16{r.Question[0].Qtype}
	switch r.Question[0].Qtype {
	case dns.TypeA, dns.TypeAAAA:
		// If the query is for A/AAAA, also try looking up matching CNAME records
		lookupRecordTypes = append(lookupRecordTypes, dns.TypeCNAME)
	}
	for _, lookupRecordType := range lookupRecordTypes {
		// Try Cardano
		records, err := state.GetState().LookupRecords(
			[]string{dns.Type(lookupRecordType).String()},
			strings.TrimSuffix(r.Question[0].Name, "."),
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
				strings.TrimSuffix(r.Question[0].Name, "."),
			)
			if err != nil {
				slog.Error(
					fmt.Sprintf("failed to lookup records in state: %s", err),
				)
				return
			}
		}
		if records != nil {
			// Assemble response
			m.SetReply(r)
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
	if r.Question[0].Qtype == dns.TypeSOA {
		zone := findZoneForName(r.Question[0].Name)
		if zone != "" {
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = append(
				m.Answer,
				generateSyntheticSOA(zone),
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

	// Check for any NS records for parent domains from local storage
	nameserverDomain, nameservers, err := findNameserversForDomain(
		r.Question[0].Name,
	)
	if err != nil {
		slog.Error(
			fmt.Sprintf(
				"failed to lookup nameservers for %s: %s",
				r.Question[0].Name,
				err,
			),
		)
	}
	if nameservers != nil {
		// Assemble response
		m.SetReply(r)
		if cfg.Dns.RecursionEnabled {
			ctx := newResolutionContext()

			// Try all nameservers with retry and failover
			resp, err := queryMultipleNameservers(
				r,
				nameservers,
				true,
				ctx,
			)
			if err != nil {
				// Send failure response
				m.SetRcode(r, dns.RcodeServerFailure)
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
						r.Question[0].Name,
						err,
					),
				)
				return
			}
			copyResponse(r, resp, m)
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

	// Return NXDOMAIN if we have no information about the
	// requested domain or any of its parents
	m.SetRcode(r, dns.RcodeNameError)
	// Include SOA in authority section for blockchain zones
	zone := findZoneForName(r.Question[0].Name)
	if zone != "" {
		m.Ns = append(m.Ns, generateSyntheticSOA(zone))
	}
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

func copyResponse(req *dns.Msg, srcResp *dns.Msg, destResp *dns.Msg) {
	if srcResp == nil {
		return
	}
	// Copy relevant data from original request and source response into destination response
	destResp.SetRcode(req, srcResp.Rcode)
	destResp.RecursionDesired = req.RecursionDesired
	destResp.RecursionAvailable = srcResp.RecursionAvailable
	if srcResp.Ns != nil {
		destResp.Ns = append(destResp.Ns, srcResp.Ns...)
	}
	if srcResp.Answer != nil {
		destResp.Answer = append(destResp.Answer, srcResp.Answer...)
	}
	if srcResp.Extra != nil {
		destResp.Extra = append(destResp.Extra, srcResp.Extra...)
	}
}

// queryWithRetry executes a query function with retries
// and exponential backoff.
func queryWithRetry(
	queryFn func() (*dns.Msg, error),
	maxRetries int,
	baseDelay time.Duration,
) (*dns.Msg, error) {
	if maxRetries <= 0 {
		maxRetries = 1
	}
	var lastErr error
	for attempt := range maxRetries {
		result, err := queryFn()
		if err == nil {
			return result, nil
		}
		lastErr = err
		// Don't sleep after the last attempt
		if attempt < maxRetries-1 {
			// Exponential backoff: baseDelay * 2^attempt
			delay := baseDelay * time.Duration(1<<attempt)
			time.Sleep(delay)
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
func queryMultipleNameservers(
	msg *dns.Msg,
	nameservers map[string][]net.IP,
	recursive bool,
	ctx *resolutionContext,
) (*dns.Msg, error) {
	return queryMultipleNameserversWithPort(
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
func queryMultipleNameserversWithPort(
	msg *dns.Msg,
	nameservers map[string][]net.IP,
	recursive bool,
	ctx *resolutionContext,
	port string,
) (*dns.Msg, error) {
	cfg := config.GetConfig()

	// Flatten nameservers into a list of addresses,
	// preferring IPv4 over IPv6
	var ipv4Addrs []string
	var ipv6Addrs []string
	for _, ips := range nameservers {
		for _, ip := range ips {
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
	baseDelay := time.Duration(
		cfg.Dns.RetryDelayMs,
	) * time.Millisecond
	timeout := time.Duration(
		cfg.Dns.QueryTimeoutMs,
	) * time.Millisecond

	for _, addr := range addresses {
		client := &dns.Client{
			Timeout: timeout,
		}
		queryFn := func() (*dns.Msg, error) {
			resp, _, exchangeErr := client.Exchange(
				msg,
				addr,
			)
			if exchangeErr == nil && resp == nil {
				return nil, fmt.Errorf(
					"nil response from %s",
					addr,
				)
			}
			return resp, exchangeErr
		}

		resp, err := queryWithRetry(
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

		// Treat SERVFAIL/REFUSED as failures and try next
		if resp.Rcode == dns.RcodeServerFailure ||
			resp.Rcode == dns.RcodeRefused {
			slog.Debug(
				fmt.Sprintf(
					"nameserver returned error rcode: address=%s, rcode=%s",
					addr,
					dns.RcodeToString[resp.Rcode],
				),
			)
			lastErr = fmt.Errorf(
				"server %s returned %s",
				addr,
				dns.RcodeToString[resp.Rcode],
			)
			continue
		}

		// If recursive and got a referral, follow it
		if recursive &&
			!resp.Authoritative &&
			len(resp.Ns) > 0 {
			result, referralErr := handleReferral(
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
		if err != nil {
			continue
		}
		j := n.Int64()
		s[i], s[j] = s[j], s[i]
	}
}

// handleReferral processes a DNS referral response and
// follows the delegation.
func handleReferral(
	msg *dns.Msg,
	resp *dns.Msg,
	ctx *resolutionContext,
) (*dns.Msg, error) {
	if ctx.atMaxDepth() {
		return resp, nil // Return referral as-is if at max depth
	}

	nameservers := getNameserversFromResponse(resp)

	// Resolve missing glue records
	childCtx := ctx.descend()
	for nsName, nsIPs := range nameservers {
		if len(nsIPs) == 0 {
			resolvedIPs, err := resolveNameserverAddress(
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

	return queryMultipleNameservers(
		msg,
		nameservers,
		true,
		childCtx,
	)
}

// doQueryWithContext performs a DNS query with resolution
// context for depth tracking. It uses retry logic and
// configurable timeouts.
func doQueryWithContext(
	msg *dns.Msg,
	address string,
	recursive bool,
	ctx *resolutionContext,
) (*dns.Msg, error) {
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

	return queryMultipleNameserversWithPort(
		msg,
		nameservers,
		recursive,
		ctx,
		port,
	)
}

func findNameserversForDomain(
	recordName string,
) (string, map[string][]net.IP, error) {
	// Split record name into labels and lookup each domain and parent until we get a hit
	queryLabels := dns.SplitDomainName(recordName)

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
				nsName := dns.Fqdn(nsRecord.Rhs)
				var nsIPs []net.IP

				// Get matching A/AAAA records for NS entry from local storage
				aRecords, err := state.GetState().
					LookupRecords([]string{"A", "AAAA"}, nsRecord.Rhs)
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
				if len(nsIPs) == 0 {
					ctx := newResolutionContext()
					resolvedIPs, resolveErr := resolveNameserverAddress(
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
				nsName := dns.Fqdn(nsRecord.Rhs)
				var nsIPs []net.IP

				// Get matching A/AAAA records for NS entry from local storage
				aRecords, err := state.GetState().
					LookupHandshakeRecords([]string{"A", "AAAA"}, nsRecord.Rhs)
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
				if len(nsIPs) == 0 {
					ctx := newResolutionContext()
					resolvedIPs, resolveErr := resolveNameserverAddress(
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
	if rootHints != nil && rootHints[dns.TypeNS] != nil {
		for _, tmpRecord := range rootHints[dns.TypeNS][`.`] {
			nsRec := tmpRecord.(*dns.NS).Ns
			if rootHints[dns.TypeA] != nil {
				for _, aRecord := range rootHints[dns.TypeA][nsRec] {
					ret[nsRec] = append(ret[nsRec], aRecord.(*dns.A).A)
				}
			}
			if rootHints[dns.TypeAAAA] != nil {
				for _, aaaaRecord := range rootHints[dns.TypeAAAA][nsRec] {
					ret[nsRec] = append(ret[nsRec], aaaaRecord.(*dns.AAAA).AAAA)
				}
			}
		}
	}
	return `.`, ret, nil
}

func getNameserversFromResponse(msg *dns.Msg) map[string][]net.IP {
	if len(msg.Ns) == 0 {
		return nil
	}
	ret := map[string][]net.IP{}
	for _, ns := range msg.Ns {
		// TODO: handle SOA
		switch v := ns.(type) {
		case *dns.NS:
			nsName := v.Ns
			ret[nsName] = []net.IP{}
			for _, extra := range msg.Extra {
				if extra.Header().Name != nsName {
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
