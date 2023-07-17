package dns

import (
	"fmt"
	"net"

	"github.com/blinklabs-io/chnsd/internal/config"
	"github.com/blinklabs-io/chnsd/internal/indexer"
	"github.com/blinklabs-io/chnsd/internal/logging"

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

	switch r.Question[0].Qtype {
	default:
		// Return a SERVFAIL response for unsupported record types
		m.SetRcode(r, dns.RcodeServerFailure)
	case dns.TypeA, dns.TypeNS:
		records := indexer.GetIndexer().LookupRecords(r.Question[0].Name, dns.Type(r.Question[0].Qtype).String())
		if len(records) == 0 {
			// Send NXDOMAIN
			m.SetRcode(r, dns.RcodeNameError)
		} else {
			// Send response
			m.SetReply(r)
			for _, record := range records {
				switch r.Question[0].Qtype {
				case dns.TypeA:
					ipAddr := net.ParseIP(record.Value)
					a := &dns.A{
						Hdr: dns.RR_Header{Name: record.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 999},
						A:   ipAddr,
					}
					m.Answer = append(m.Answer, a)
				case dns.TypeNS:
					ns := &dns.NS{
						Hdr: dns.RR_Header{Name: record.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 999},
						Ns:  record.Value,
					}
					m.Answer = append(m.Answer, ns)
				default:

				}
			}
		}
	}

	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("failed to write response: %s", err)
	}
}
