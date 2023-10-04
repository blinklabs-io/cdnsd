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
	listenAddr := fmt.Sprintf("%s:%d", cfg.Dns.ListenAddress, cfg.Dns.ListenPort)
	// Setup handler
	dns.HandleFunc(".", handleQuery)
	// UDP listener
	serverUdp := &dns.Server{Addr: listenAddr, Net: "udp", TsigSecret: nil, ReusePort: true}
	go startListener(serverUdp)
	// TCP listener
	serverTcp := &dns.Server{Addr: listenAddr, Net: "tcp", TsigSecret: nil, ReusePort: true}
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

	nameserverDomain, nameservers, err := findNameserversForDomain(r.Question[0].Name)
	if err != nil {
		logger.Errorf("failed to lookup nameservers for %s: %s", r.Question[0].Name, err)
	}
	if nameservers != nil {
		// Assemble response
		m.SetReply(r)
		if cfg.Dns.RecursionEnabled {
			// Pick random nameserver for domain
			tmpNameserver := randomNameserverAddress(nameservers)
			// Query the random domain nameserver we picked above
			resp, err := queryServer(r, tmpNameserver.String())
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

	// Query fallback servers if recursion is enabled
	if cfg.Dns.RecursionEnabled {
		// Pick random fallback server
		fallbackServer := cfg.Dns.FallbackServers[rand.Intn(len(cfg.Dns.FallbackServers))]
		// Query chosen server
		fallbackResp, err := queryServer(r, fallbackServer)
		if err != nil {
			// Send failure response
			m.SetRcode(r, dns.RcodeServerFailure)
			if err := w.WriteMsg(m); err != nil {
				logger.Errorf("failed to write response: %s", err)
			}
			logger.Errorf("failed to query fallback server: %s", err)
			return
		} else {
			copyResponse(r, fallbackResp, m)
			// Send response
			if err := w.WriteMsg(m); err != nil {
				logger.Errorf("failed to write response: %s", err)
			}
			return
		}
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

func queryServer(req *dns.Msg, nameserver string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = req.RecursionDesired
	m.Question = append(m.Question, req.Question...)
	in, err := dns.Exchange(m, fmt.Sprintf("%s:53", nameserver))
	return in, err
}

func randomNameserverAddress(nameservers map[string][]net.IP) net.IP {
	// Put all namserver addresses in single list
	tmpNameservers := []net.IP{}
	for _, addresses := range nameservers {
		tmpNameservers = append(tmpNameservers, addresses...)
	}
	tmpNameserver := tmpNameservers[rand.Intn(len(tmpNameservers))]
	return tmpNameserver
}

func doQuery(msg *dns.Msg, address string) (*dns.Msg, error) {
	logger := logging.GetLogger()
	logger.Debugf("querying %s: %s %s", address, dns.Type(msg.Question[0].Qtype).String(), msg.Question[0].Name)
	resp, err := dns.Exchange(msg, address)
	return resp, err
}

func findNameserversForDomain(recordName string) (string, map[string][]net.IP, error) {
	cfg := config.GetConfig()

	// Split record name into labels and lookup each domain and parent until we get a hit
	queryLabels := dns.SplitDomainName(recordName)

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
		fallbackServer := cfg.Dns.FallbackServers[rand.Intn(len(cfg.Dns.FallbackServers))]
		serverWithPort := fmt.Sprintf("%s:53", fallbackServer)
		for startLabelIdx := 0; startLabelIdx < len(queryLabels); startLabelIdx++ {
			lookupDomainName := dns.Fqdn(strings.Join(queryLabels[startLabelIdx:], "."))
			m := new(dns.Msg)
			m.SetQuestion(lookupDomainName, dns.TypeNS)
			m.RecursionDesired = false
			in, err := doQuery(m, serverWithPort)
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
							m2 := new(dns.Msg)
							m2.SetQuestion(ns, dns.TypeA)
							m2.RecursionDesired = false
							in2, err := doQuery(m2, serverWithPort)
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
