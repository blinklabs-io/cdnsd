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
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"

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
			// Pick random nameserver for domain
			tmpNameserver := randomNameserverAddress(nameservers)
			if tmpNameserver == nil {
				m.SetRcode(r, dns.RcodeServerFailure)
				if err := w.WriteMsg(m); err != nil {
					slog.Error(
						"unable to get nameserver",
					)
				}
				slog.Error(
					"unable to get nameserver",
				)
				return
			}
			// Query the random domain nameserver we picked above
			resp, err := doQuery(r, tmpNameserver.String(), true)
			if err != nil {
				// Send failure response
				m.SetRcode(r, dns.RcodeServerFailure)
				if err := w.WriteMsg(m); err != nil {
					slog.Error(
						fmt.Sprintf("failed to write response: %s", err),
					)
				}
				slog.Error(
					fmt.Sprintf("failed to query domain nameserver: %s", err),
				)
				return
			} else {
				copyResponse(r, resp, m)
				// Send response
				if err := w.WriteMsg(m); err != nil {
					slog.Error(
						fmt.Sprintf("failed to write response: %s", err),
					)
				}
				return
			}
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

	// Query fallback servers, if configured
	if len(cfg.Dns.FallbackServers) > 0 {
		// Pick random fallback server
		fallbackServer := randomFallbackServer()
		// Pass along query to chosen fallback server
		resp, err := doQuery(r, fallbackServer, false)
		if err != nil {
			// Send failure response
			m.SetRcode(r, dns.RcodeServerFailure)
			if err := w.WriteMsg(m); err != nil {
				slog.Error(
					fmt.Sprintf("failed to write response: %s", err),
				)
			}
			slog.Error(
				fmt.Sprintf("failed to query domain nameserver: %s", err),
			)
			return
		} else {
			copyResponse(r, resp, m)
			// Send response
			if err := w.WriteMsg(m); err != nil {
				slog.Error(
					fmt.Sprintf("failed to write response: %s", err),
				)
			}
			return
		}
	}

	// Return NXDOMAIN if we have no information about the requested domain or any of its parents
	m.SetRcode(r, dns.RcodeNameError)
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

func randomNameserverAddress(nameservers map[string][]net.IP) net.IP {
	// Put all namserver addresses in single list
	tmpNameservers := []net.IP{}
	for _, addresses := range nameservers {
		tmpNameservers = append(tmpNameservers, addresses...)
	}
	if len(tmpNameservers) > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(tmpNameservers))))
		if err != nil {
			return nil
		}
		tmpNameserver := tmpNameservers[n.Int64()]
		return tmpNameserver
	}
	return nil
}

func doQuery(msg *dns.Msg, address string, recursive bool) (*dns.Msg, error) {
	// Default to a random fallback server if no address is specified
	if address == "" {
		address = randomFallbackServer()
	}
	// Add default port to address if there is none
	if !strings.Contains(address, ":") {
		address = address + `:53`
	}
	slog.Debug(
		fmt.Sprintf(
			"querying %s: %s",
			address,
			formatMessageQuestionSection(msg.Question),
		),
	)
	resp, err := dns.Exchange(msg, address)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("dns response empty")
	}
	slog.Debug(
		fmt.Sprintf(
			"response: rcode=%s, authoritative=%v, authority=%s, answer=%s, extra=%s",
			dns.RcodeToString[resp.Rcode],
			resp.Authoritative,
			formatMessageAnswerSection(resp.Ns),
			formatMessageAnswerSection(resp.Answer),
			formatMessageAnswerSection(resp.Extra),
		),
	)
	// Immediately return authoritative response
	if resp.Authoritative {
		return resp, nil
	}
	if recursive {
		if len(resp.Ns) > 0 {
			nameservers := getNameserversFromResponse(resp)
			randNsName, randNsAddress := randomNameserver(nameservers)
			if randNsAddress == "" {
				m := createQuery(randNsName, dns.TypeA)
				// XXX: should this query the fallback servers or the server that gave us the NS response?
				resp, err := doQuery(m, "", false)
				if err != nil {
					return nil, err
				}
				randNsAddress = getAddressForNameFromResponse(resp, randNsName)
				if randNsAddress == "" {
					// Return the current response if we couldn't get an address for the nameserver
					return resp, nil
				}
			}
			// Perform recursive query
			return doQuery(msg, randNsAddress, true)
		} else {
			// Return the current response if there is no authority information
			return resp, nil
		}
	}
	return resp, nil
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
		nsRecords, err := state.GetState().
			LookupRecords([]string{"NS"}, lookupDomainName)
		if err != nil {
			return "", nil, err
		}
		if len(nsRecords) > 0 {
			ret := map[string][]net.IP{}
			for _, nsRecord := range nsRecords {
				// Get matching A/AAAA records for NS entry
				aRecords, err := state.GetState().
					LookupRecords([]string{"A", "AAAA"}, nsRecord.Rhs)
				if err != nil {
					return "", nil, err
				}
				for _, aRecord := range aRecords {
					ret[nsRecord.Rhs] = append(
						ret[nsRecord.Rhs],
						net.ParseIP(aRecord.Rhs),
					)
				}
			}
			return dns.Fqdn(lookupDomainName), ret, nil
		}
	}

	return "", nil, nil
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

func getAddressForNameFromResponse(msg *dns.Msg, recordName string) string {
	var retRR dns.RR
	for _, answer := range msg.Answer {
		if answer.Header().Name == recordName {
			retRR = answer
			break
		}
	}
	if retRR == nil {
		for _, extra := range msg.Extra {
			if extra.Header().Name == recordName {
				retRR = extra
				break
			}
		}
	}
	if retRR == nil {
		return ""
	}
	switch v := retRR.(type) {
	case *dns.A:
		if v.A != nil {
			return v.A.String()
		}
	case *dns.AAAA:
		if v.AAAA != nil {
			return v.AAAA.String()
		}
	}
	return ""
}

func randomNameserver(nameservers map[string][]net.IP) (string, string) {
	mapKeys := []string{}
	for k := range nameservers {
		mapKeys = append(mapKeys, k)
	}
	if len(mapKeys) > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(mapKeys))))
		if err != nil {
			return "", ""
		}
		randNsName := mapKeys[n.Int64()]
		randNsAddresses := nameservers[randNsName]
		if randNsAddresses == nil {
			return "", ""
		}
		n, err = rand.Int(rand.Reader, big.NewInt(int64(len(randNsAddresses))))
		if err != nil {
			return "", ""
		}
		randNsAddress := randNsAddresses[n.Int64()].String()
		return randNsName, randNsAddress
	}
	return "", ""
}

func createQuery(recordName string, recordType uint16) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(recordName, recordType)
	m.RecursionDesired = false
	return m
}

func randomFallbackServer() string {
	cfg := config.GetConfig()
	n, err := rand.Int(
		rand.Reader,
		big.NewInt(int64(len(cfg.Dns.FallbackServers))),
	)
	if err != nil {
		return ""
	}
	return cfg.Dns.FallbackServers[n.Int64()]
}

func formatMessageAnswerSection(section []dns.RR) string {
	ret := "[ "
	for idx, rr := range section {
		ret += fmt.Sprintf(
			"< %s >",
			strings.ReplaceAll(
				strings.TrimPrefix(
					rr.String(),
					";",
				),
				"\t",
				" ",
			),
		)
		if idx != len(section)-1 {
			ret += `,`
		}
		ret += ` `
	}
	ret += "]"
	return ret
}

func formatMessageQuestionSection(section []dns.Question) string {
	ret := "[ "
	for idx, question := range section {
		ret += fmt.Sprintf(
			"< %s >",
			strings.ReplaceAll(
				strings.TrimPrefix(
					question.String(),
					";",
				),
				"\t",
				" ",
			),
		)
		if idx != len(section)-1 {
			ret += `,`
		}
		ret += ` `
	}
	ret += "]"
	return ret
}
