// Copyright 2023 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/logging"
	"github.com/blinklabs-io/cdnsd/internal/state"

	"github.com/miekg/dns"
)

func Start() error {
	cfg := config.GetConfig()
	listenAddr := fmt.Sprintf(
		"%s:%d",
		cfg.Dns.ListenAddress,
		cfg.Dns.ListenPort,
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
	return nil
}

func startListener(server *dns.Server) {
	if err := server.ListenAndServe(); err != nil {
		logging.GetLogger().Fatalf("failed to start DNS listener: %s", err)
	}
}

func handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	logger := logging.GetLogger()
	cfg := config.GetConfig()
	m := new(dns.Msg)

	if cfg.Logging.QueryLog {
		for _, q := range r.Question {
			logger.Infof("query: name: %s, type: %s, class: %s",
				q.Name,
				dns.Type(q.Qtype).String(),
				dns.Class(q.Qclass).String(),
			)
		}
	}

	// Check for known record for domain nameserver
	records, err := state.GetState().LookupNameserverRecord(
		strings.TrimSuffix(r.Question[0].Name, "."),
	)
	if err != nil {
		logger.Errorf("failed to lookup record in state: %s", err)
		return
	}
	if records != nil {
		// Assemble response
		m.SetReply(r)
		for k, v := range records {
			k = dns.Fqdn(k)
			address := net.ParseIP(v)
			// A or AAAA record
			if address.To4() != nil {
				// IPv4
				a := &dns.A{
					Hdr: dns.RR_Header{
						Name:   k,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    999,
					},
					A: address,
				}
				m.Answer = append(m.Answer, a)
			} else {
				// IPv6
				aaaa := &dns.AAAA{
					Hdr:  dns.RR_Header{Name: k, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 999},
					AAAA: address,
				}
				m.Answer = append(m.Answer, aaaa)
			}
		}
		// Send response
		if err := w.WriteMsg(m); err != nil {
			logger.Errorf("failed to write response: %s", err)
		}
		// We found our answer, to return from handler
		return
	}

	nameserverDomain, nameservers, err := findNameserversForDomain(
		r.Question[0].Name,
	)
	if err != nil {
		logger.Errorf(
			"failed to lookup nameservers for %s: %s",
			r.Question[0].Name,
			err,
		)
	}
	if nameservers != nil {
		// Assemble response
		m.SetReply(r)
		if cfg.Dns.RecursionEnabled {
			// Pick random nameserver for domain
			tmpNameserver := randomNameserverAddress(nameservers)
			// Query the random domain nameserver we picked above
			resp, err := doQuery(r, tmpNameserver.String(), true)
			if err != nil {
				// Send failure response
				m.SetRcode(r, dns.RcodeServerFailure)
				if err := w.WriteMsg(m); err != nil {
					logger.Errorf("failed to write response: %s", err)
				}
				logger.Errorf("failed to query domain nameserver: %s", err)
				return
			} else {
				copyResponse(r, resp, m)
				// Send response
				if err := w.WriteMsg(m); err != nil {
					logger.Errorf("failed to write response: %s", err)
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
			logger.Errorf("failed to write response: %s", err)
		}
		// We found our answer, to return from handler
		return
	}

	// Return NXDOMAIN if we have no information about the requested domain or any of its parents
	m.SetRcode(r, dns.RcodeNameError)
	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("failed to write response: %s", err)
	}
}

func copyResponse(req *dns.Msg, srcResp *dns.Msg, destResp *dns.Msg) {
	// Copy relevant data from original request and source response into destination response
	destResp.SetRcode(req, srcResp.MsgHdr.Rcode)
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
		tmpNameserver := tmpNameservers[rand.Intn(len(tmpNameservers))]
		return tmpNameserver
	}
	return nil
}

func doQuery(msg *dns.Msg, address string, recursive bool) (*dns.Msg, error) {
	logger := logging.GetLogger()
	// Default to a random fallback server if no address is specified
	if address == "" {
		address = randomFallbackServer()
	}
	// Add default port to address if there is none
	if !strings.Contains(address, ":") {
		address = address + `:53`
	}
	logger.Debugf(
		"querying %s: %s",
		address,
		formatMessageQuestionSection(msg.Question),
	)
	resp, err := dns.Exchange(msg, address)
	if err != nil {
		return nil, err
	}
	logger.Debugf(
		"response: rcode=%s, authoritative=%v, authority=%s, answer=%s, extra=%s",
		dns.RcodeToString[resp.Rcode],
		resp.Authoritative,
		formatMessageAnswerSection(resp.Ns),
		formatMessageAnswerSection(resp.Answer),
		formatMessageAnswerSection(resp.Extra),
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
	cfg := config.GetConfig()

	// Split record name into labels and lookup each domain and parent until we get a hit
	queryLabels := dns.SplitDomainName(recordName)

	// Special case for root domain
	if queryLabels == nil {
		queryLabels = append(queryLabels, "")
	}

	// Check on-chain domains first
	for startLabelIdx := 0; startLabelIdx < len(queryLabels); startLabelIdx++ {
		lookupDomainName := strings.Join(queryLabels[startLabelIdx:], ".")
		nameservers, err := state.GetState().LookupDomain(lookupDomainName)
		if err != nil {
			return "", nil, err
		}
		if nameservers != nil {
			ret := map[string][]net.IP{}
			for k, v := range nameservers {
				k = k + `.`
				ret[k] = append(ret[k], net.ParseIP(v))
			}
			return dns.Fqdn(lookupDomainName), ret, nil
		}
	}

	// Query fallback servers, if configured
	if len(cfg.Dns.FallbackServers) > 0 {
		// Pick random fallback server
		fallbackServer := randomFallbackServer()
		for startLabelIdx := 0; startLabelIdx < len(queryLabels); startLabelIdx++ {
			lookupDomainName := dns.Fqdn(
				strings.Join(queryLabels[startLabelIdx:], "."),
			)
			m := createQuery(lookupDomainName, dns.TypeNS)
			in, err := doQuery(m, fallbackServer, false)
			if err != nil {
				return "", nil, err
			}
			if in.Rcode == dns.RcodeSuccess {
				if len(in.Answer) > 0 {
					ret := map[string][]net.IP{}
					for _, answer := range in.Answer {
						switch v := answer.(type) {
						case *dns.NS:
							ns := v.Ns
							ret[ns] = make([]net.IP, 0)
							// Query for matching A/AAAA records
							m2 := createQuery(ns, dns.TypeA)
							in2, err := doQuery(m2, fallbackServer, false)
							if err != nil {
								return "", nil, err
							}
							for _, answer2 := range in2.Answer {
								switch v := answer2.(type) {
								case *dns.A:
									ret[ns] = append(ret[ns], v.A)
								case *dns.AAAA:
									ret[ns] = append(ret[ns], v.AAAA)
								}
							}
						}
					}
					if len(ret) > 0 {
						return lookupDomainName, ret, nil
					}
				}
			}
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
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	}
	return ""
}

func randomNameserver(nameservers map[string][]net.IP) (string, string) {
	mapKeys := []string{}
	for k := range nameservers {
		mapKeys = append(mapKeys, k)
	}
	if len(mapKeys) > 0 {
		randNsName := mapKeys[rand.Intn(len(mapKeys))]
		randNsAddresses := nameservers[randNsName]
		randNsAddress := randNsAddresses[rand.Intn(len(randNsAddresses))].String()
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
	return cfg.Dns.FallbackServers[rand.Intn(
		len(cfg.Dns.FallbackServers),
	)]
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
