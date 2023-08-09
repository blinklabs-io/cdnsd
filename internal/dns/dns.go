package dns

import (
	"fmt"
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

	// Return NXDOMAIN if we have no information about the requested domain or any of its parents
	m.SetRcode(r, dns.RcodeNameError)
	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("failed to write response: %s", err)
	}
}
