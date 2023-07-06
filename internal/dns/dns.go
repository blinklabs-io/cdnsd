package dns

import (
	"fmt"

	"github.com/blinklabs-io/chnsd/internal/config"
	"github.com/blinklabs-io/chnsd/internal/logging"

	"github.com/miekg/dns"
)

func Start() error {
	cfg := config.GetConfig()
	listenAddr := fmt.Sprintf("%s:%d", cfg.Dns.ListenAddress, cfg.Dns.ListenPort)
	// Setup handler
	dns.HandleFunc(".", handleTest)
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

func handleTest(w dns.ResponseWriter, r *dns.Msg) {
	logger := logging.GetLogger()
	m := new(dns.Msg)
	m.SetReply(r)

	queryStr := fmt.Sprintf(
		"%s %s",
		dns.Type(r.Question[0].Qtype).String(),
		r.Question[0].Name,
	)

	logger.Infof("request: %s", queryStr)

	t := &dns.TXT{
		Hdr: dns.RR_Header{Name: "test.zone.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
		Txt: []string{queryStr},
	}

	m.Answer = append(m.Answer, t)
	if err := w.WriteMsg(m); err != nil {
		logger.Errorf("failed to write response: %s", err)
	}
}
