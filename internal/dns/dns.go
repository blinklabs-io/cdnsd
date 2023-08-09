package dns

import (
	"fmt"
	"math/rand"
	"net"
	"strings"

	"github.com/blinklabs-io/chnsd/internal/config"
	"github.com/blinklabs-io/chnsd/internal/logging"
	"github.com/blinklabs-io/chnsd/internal/state"

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
	m := new(dns.Msg)

	// Split query name into labels and lookup each domain and parent until we get a hit
	queryLabels := dns.SplitDomainName(r.Question[0].Name)
	for startLabelIdx := 0; startLabelIdx < len(queryLabels); startLabelIdx++ {
		lookupDomainName := strings.Join(queryLabels[startLabelIdx:], ".")
		nameServers, err := state.GetState().LookupDomain(lookupDomainName)
		if err != nil {
			logger.Errorf("failed to lookup domain: %s", err)
		}
		if nameServers == nil {
			continue
		}
		// Assemble response
		m.SetReply(r)
		for nameserver, ipAddress := range nameServers {
			// Add trailing dot to make everybody happy
			nameserver = nameserver + `.`
			// NS record
			ns := &dns.NS{
				Hdr: dns.RR_Header{Name: (lookupDomainName + `.`), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 999},
				Ns:  nameserver,
			}
			m.Ns = append(m.Ns, ns)
			// A or AAAA record
			ipAddr := net.ParseIP(ipAddress)
			if ipAddr.To4() != nil {
				// IPv4
				a := &dns.A{
					Hdr: dns.RR_Header{Name: nameserver, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 999},
					A:   ipAddr,
				}
				m.Extra = append(m.Extra, a)
			} else {
				// IPv6
				aaaa := &dns.AAAA{
					Hdr:  dns.RR_Header{Name: nameserver, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 999},
					AAAA: ipAddr,
				}
				m.Extra = append(m.Extra, aaaa)
			}
		}
		// Send response
		if err := w.WriteMsg(m); err != nil {
			logger.Errorf("failed to write response: %s", err)
		}
		// We found our answer, to return from handler
		return
	}

	// Query fallback servers
	fallbackResp, err := queryFallbackServer(r)
	if err != nil {
		// Send failure response
		m.SetRcode(r, dns.RcodeServerFailure)
		if err := w.WriteMsg(m); err != nil {
			logger.Errorf("failed to write response: %s", err)
		}
		logger.Errorf("failed to query fallback server: %s", err)
		return
	} else {
		// Copy relevant data from fallback response into our response
		m.SetRcode(r, fallbackResp.MsgHdr.Rcode)
		m.RecursionDesired = r.RecursionDesired
		m.RecursionAvailable = fallbackResp.RecursionAvailable
		if fallbackResp.Ns != nil {
			m.Ns = append(m.Ns, fallbackResp.Ns...)
		}
		if fallbackResp.Answer != nil {
			m.Answer = append(m.Answer, fallbackResp.Answer...)
		}
		if fallbackResp.Extra != nil {
			m.Extra = append(m.Extra, fallbackResp.Extra...)
		}
		// Send response
		if err := w.WriteMsg(m); err != nil {
			logger.Errorf("failed to write response: %s", err)
		}
		return
	}

	// Return NXDOMAIN if we have no information about the requested domain or any of its parents
	m.SetRcode(r, dns.RcodeNameError)
	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("failed to write response: %s", err)
	}
}

func queryFallbackServer(req *dns.Msg) (*dns.Msg, error) {
	// Pick random fallback server
	cfg := config.GetConfig()
	fallbackServer := cfg.Dns.FallbackServers[rand.Intn(len(cfg.Dns.FallbackServers))]
	// Query chosen server
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = req.RecursionDesired
	m.Question = append(m.Question, req.Question...)
	in, err := dns.Exchange(m, fmt.Sprintf("%s:53", fallbackServer))
	return in, err
}
