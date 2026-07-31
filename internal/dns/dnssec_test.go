// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"crypto"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
)

func TestDefaultDNSSECTrustAnchors(t *testing.T) {
	cfg := *config.GetConfig()
	cfg.Dns.DNSSEC.Enabled = true

	resolver, err := NewResolver(&cfg)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	anchors := resolver.configuredTrustAnchors(".")
	if len(anchors) == 0 {
		t.Fatal("got no root anchors")
	}
	for _, anchor := range anchors {
		if _, ok := anchor.(*dns.DS); !ok {
			t.Fatalf("root anchor has type %T, want *dns.DS", anchor)
		}
	}
}

func TestLoadTrustAnchorsRejectsOtherRecordTypes(t *testing.T) {
	cfg := *config.GetConfig()
	cfg.Dns.DNSSEC.Enabled = true
	cfg.Dns.DNSSEC.TrustAnchors = ". 300 IN A 192.0.2.1"

	_, err := NewResolver(&cfg)
	if err == nil || !strings.Contains(err.Error(), "unsupported record type") {
		t.Fatalf("NewResolver() error = %v, want unsupported type", err)
	}
}

func TestLoadTrustAnchorsRejectsUnsupportedAlgorithms(t *testing.T) {
	cfg := *config.GetConfig()
	cfg.Dns.DNSSEC.Enabled = true
	cfg.Dns.DNSSEC.TrustAnchors = strings.Join(
		[]string{
			". 300 IN DS 12345 5 2 " +
				strings.Repeat("00", 32),
			"",
		},
		"\n",
	)

	_, err := NewResolver(&cfg)
	if err == nil ||
		!strings.Contains(err.Error(), "unsupported DS trust anchor") {
		t.Fatalf("NewResolver() error = %v, want unsupported anchor", err)
	}
}

func TestDNSSECQuerySetsDOAndCD(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.", dns.TypeA)
	got := dnssecQuery(msg)

	if got.IsEdns0() == nil || !got.IsEdns0().Do() {
		t.Fatal("dnssecQuery() did not set the EDNS DO bit")
	}
	if !got.CheckingDisabled {
		t.Fatal("dnssecQuery() did not set CD for local validation")
	}
	if msg.IsEdns0() != nil || msg.CheckingDisabled {
		t.Fatal("dnssecQuery() mutated the caller's message")
	}
}

func TestDNSSECSecurityFilters(t *testing.T) {
	key, signer := newTestDNSSECKey(t, "test.")
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "outside.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("192.0.2.1"),
	}
	rrset := []dns.RR{a}
	sig := signTestRRset(t, "test.", key, signer, rrset)
	if err := verifyRRSet(
		rrset,
		[]*dns.RRSIG{sig},
		[]*dns.DNSKEY{key},
	); !errors.Is(err, errNoSignature) {
		t.Fatalf("verifyRRSet() error = %v, want no signature", err)
	}
	signedA := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www.test.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("192.0.2.2"),
	}
	signedRRset := []dns.RR{signedA}
	signedSig := signTestRRset(t, "test.", key, signer, signedRRset)
	signedA.Hdr.Ttl = 3600
	signedSig.Hdr.Ttl = 3600
	if err := verifyRRSet(
		signedRRset,
		[]*dns.RRSIG{signedSig},
		[]*dns.DNSKEY{key},
	); err != nil {
		t.Fatalf("verifyRRSet() with inflated TTL error = %v", err)
	}
	if signedA.Hdr.Ttl != 300 || signedSig.Hdr.Ttl != 300 {
		t.Fatalf(
			"validated TTLs = %d, %d; want 300",
			signedA.Hdr.Ttl,
			signedSig.Hdr.Ttl,
		)
	}

	revoked := *key
	revoked.Flags |= dns.REVOKE
	unsupported := *key
	unsupported.Algorithm = dns.DSA
	active := activeDNSSECKeys([]*dns.DNSKEY{
		key,
		&revoked,
		&unsupported,
	})
	if len(active) != 1 || active[0] != key {
		t.Fatalf("activeDNSSECKeys() = %v, want only active key", active)
	}
	if !supportedDNSSECAlgorithm(dns.RSASHA1) ||
		!supportedDNSSECAlgorithm(dns.RSASHA1NSEC3SHA1) {
		t.Fatal("legacy SHA-1 signature validation is not supported")
	}
	if supportedDSAlgorithm(dns.RSASHA1) ||
		supportedDSAlgorithm(dns.RSASHA1NSEC3SHA1) {
		t.Fatal("deprecated SHA-1 DS algorithm is supported")
	}
	if !supportedDSDigest(dns.SHA1) {
		t.Fatal("legacy SHA-1 DS digest validation is not supported")
	}
	if supportedDSDigest(dns.SHA512) {
		t.Fatal("non-standard SHA-512 DS digest is supported")
	}
	tooExpensive := testNSEC3(
		"name.test.",
		"test.",
		0,
		nil,
	)
	tooExpensive.Iterations = 501
	if validNSEC3(tooExpensive) {
		t.Fatal("NSEC3 record above iteration limit is supported")
	}
}

func TestValidatingQuerySetsAuthenticatedData(t *testing.T) {
	zone := "secure.test."
	key, signer := newTestDNSSECKey(t, zone)
	anchor := testDS(t, key)
	var sawDO atomic.Bool

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if opt := req.IsEdns0(); opt != nil && opt.Do() {
			sawDO.Store(true)
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		switch req.Question[0].Qtype {
		case dns.TypeDNSKEY:
			rrset := []dns.RR{key}
			resp.Answer = append(resp.Answer, rrset...)
			resp.Answer = append(
				resp.Answer,
				signTestRRset(t, zone, key, signer, rrset),
			)
		case dns.TypeA:
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   zone,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("192.0.2.10"),
			}
			rrset := []dns.RR{a}
			resp.Answer = append(resp.Answer, rrset...)
			resp.Answer = append(
				resp.Answer,
				signTestRRset(t, zone, key, signer, rrset),
			)
		}
		if err := w.WriteMsg(resp); err != nil {
			t.Errorf("WriteMsg() error = %v", err)
		}
	})
	ip, port := startTestDNSServer(t, "127.0.0.1:0", handler)

	resolver := &Resolver{dnssecEnabled: true}
	ctx := newResolutionContext()
	ctx.validation = &dnssecValidation{
		zone:    zone,
		anchors: []dns.RR{anchor},
	}
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeA)
	msg.SetEdns0(1232, true)
	resp, err := resolver.queryMultipleNameserversWithPort(
		msg,
		map[string][]net.IP{"ns.secure.test.": {ip}},
		false,
		ctx,
		port,
	)
	if err != nil {
		t.Fatalf("queryMultipleNameserversWithPort() error = %v", err)
	}
	if !resp.AuthenticatedData {
		t.Fatal("validated response did not have the AD bit")
	}
	if !sawDO.Load() {
		t.Fatal("authoritative server did not receive the DO bit")
	}
}

func TestValidatingQueryRejectsBogusAnswer(t *testing.T) {
	zone := "bogus.test."
	key, signer := newTestDNSSECKey(t, zone)
	anchor := testDS(t, key)

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		switch req.Question[0].Qtype {
		case dns.TypeDNSKEY:
			rrset := []dns.RR{key}
			resp.Answer = append(resp.Answer, rrset...)
			resp.Answer = append(
				resp.Answer,
				signTestRRset(t, zone, key, signer, rrset),
			)
		case dns.TypeA:
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   zone,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				A: net.ParseIP("192.0.2.20"),
			}
			// The answer deliberately has no RRSIG.
			resp.Answer = append(resp.Answer, a)
		}
		_ = w.WriteMsg(resp)
	})
	ip, port := startTestDNSServer(t, "127.0.0.1:0", handler)

	resolver := &Resolver{dnssecEnabled: true}
	ctx := newResolutionContext()
	ctx.validation = &dnssecValidation{
		zone:    zone,
		anchors: []dns.RR{anchor},
	}
	msg := new(dns.Msg)
	msg.SetQuestion(zone, dns.TypeA)
	_, err := resolver.queryMultipleNameserversWithPort(
		msg,
		map[string][]net.IP{"ns.bogus.test.": {ip}},
		false,
		ctx,
		port,
	)
	if err == nil || !strings.Contains(err.Error(), errDNSSECBogus.Error()) {
		t.Fatalf("query error = %v, want DNSSEC validation failure", err)
	}
}

func TestValidationCoversAuthoritySection(t *testing.T) {
	zone := "secure.test."
	key, signer := newTestDNSSECKey(t, zone)
	query := new(dns.Msg)
	query.SetQuestion("www."+zone, dns.TypeA)
	answer := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "www." + zone,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: net.ParseIP("192.0.2.10"),
	}
	ns := &dns.NS{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeNS,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns: "ns." + zone,
	}
	resp := new(dns.Msg)
	resp.SetReply(query)
	resp.Answer = []dns.RR{
		answer,
		signTestRRset(
			t,
			zone,
			key,
			signer,
			[]dns.RR{answer},
		),
	}
	resp.Ns = []dns.RR{ns}
	validation := &dnssecValidation{
		zone: zone,
		keys: []*dns.DNSKEY{key},
	}

	if valid, err := (&Resolver{dnssecEnabled: true}).
		validateFinalResponse(query, resp, validation); err == nil || valid {
		t.Fatalf(
			"validateFinalResponse() = %v, %v; want unsigned authority rejected",
			valid,
			err,
		)
	}

	resp.Ns = append(
		resp.Ns,
		signTestRRset(t, zone, key, signer, []dns.RR{ns}),
	)
	if valid, err := (&Resolver{dnssecEnabled: true}).
		validateFinalResponse(query, resp, validation); err != nil || !valid {
		t.Fatalf(
			"validateFinalResponse() = %v, %v; want fully signed response",
			valid,
			err,
		)
	}
}

func TestValidationForSignedDelegation(t *testing.T) {
	parentZone := "test."
	childZone := "child.test."
	parentKey, parentSigner := newTestDNSSECKey(t, parentZone)
	childKey, _ := newTestDNSSECKey(t, childZone)
	childDS := testDS(t, childKey)
	dsRRset := []dns.RR{childDS}

	resp := new(dns.Msg)
	resp.Ns = append(resp.Ns,
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   childZone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ns: "ns.child.test.",
		},
		childDS,
		signTestRRset(
			t,
			parentZone,
			parentKey,
			parentSigner,
			dsRRset,
		),
	)

	resolver := &Resolver{dnssecEnabled: true}
	got, err := resolver.validationForReferral(
		resp,
		&dnssecValidation{
			zone: parentZone,
			keys: []*dns.DNSKEY{parentKey},
		},
		childZone,
	)
	if err != nil {
		t.Fatalf("validationForReferral() error = %v", err)
	}
	if got.zone != childZone || got.insecure || len(got.anchors) != 1 {
		t.Fatalf("child validation = %#v", got)
	}
}

func TestValidationForProvenUnsignedDelegation(t *testing.T) {
	parentZone := "test."
	childZone := "unsigned.test."
	parentKey, parentSigner := newTestDNSSECKey(t, parentZone)
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   childZone,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: "unsigned0.test.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC},
	}
	nsecRRset := []dns.RR{nsec}

	resp := new(dns.Msg)
	resp.Ns = append(resp.Ns,
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   childZone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ns: "ns.unsigned.test.",
		},
		nsec,
		signTestRRset(
			t,
			parentZone,
			parentKey,
			parentSigner,
			nsecRRset,
		),
	)

	resolver := &Resolver{dnssecEnabled: true}
	got, err := resolver.validationForReferral(
		resp,
		&dnssecValidation{
			zone: parentZone,
			keys: []*dns.DNSKEY{parentKey},
		},
		childZone,
	)
	if err != nil {
		t.Fatalf("validationForReferral() error = %v", err)
	}
	if got.zone != childZone || !got.insecure {
		t.Fatalf("child validation = %#v, want insecure", got)
	}
}

func TestValidationForNSEC3OptOutDelegation(t *testing.T) {
	parentZone := "test."
	childZone := "deep.unsigned.test."
	parentKey, parentSigner := newTestDNSSECKey(t, parentZone)
	optOut := testNSEC3(
		"cover.test.",
		parentZone,
		1,
		nil,
	)
	closest := testNSEC3(
		parentZone,
		parentZone,
		0,
		[]uint16{dns.TypeNS, dns.TypeSOA},
	)
	resp := new(dns.Msg)
	resp.Ns = append(
		resp.Ns,
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   childZone,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Ns: "ns.deep.unsigned.test.",
		},
		optOut,
		signTestRRset(
			t,
			parentZone,
			parentKey,
			parentSigner,
			[]dns.RR{optOut},
		),
		closest,
		signTestRRset(
			t,
			parentZone,
			parentKey,
			parentSigner,
			[]dns.RR{closest},
		),
	)

	got, err := (&Resolver{dnssecEnabled: true}).validationForReferral(
		resp,
		&dnssecValidation{
			zone: parentZone,
			keys: []*dns.DNSKEY{parentKey},
		},
		childZone,
	)
	if err != nil {
		t.Fatalf("validationForReferral() error = %v", err)
	}
	if got.zone != childZone || !got.insecure {
		t.Fatalf("child validation = %#v, want insecure", got)
	}
}

func TestValidationForReferralRejectsUnrelatedOwners(t *testing.T) {
	tests := map[string][]dns.RR{
		"multiple NS owners": {
			&dns.NS{
				Hdr: dns.RR_Header{
					Name:   "child.test.",
					Rrtype: dns.TypeNS,
				},
			},
			&dns.NS{
				Hdr: dns.RR_Header{
					Name:   "other.test.",
					Rrtype: dns.TypeNS,
				},
			},
		},
		"outside parent": {
			&dns.NS{
				Hdr: dns.RR_Header{
					Name:   "unrelated.",
					Rrtype: dns.TypeNS,
				},
			},
		},
		"outside query": {
			&dns.NS{
				Hdr: dns.RR_Header{
					Name:   "sibling.test.",
					Rrtype: dns.TypeNS,
				},
			},
		},
	}
	for name, authority := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := (&Resolver{dnssecEnabled: true}).
				validationForReferral(
					&dns.Msg{Ns: authority},
					&dnssecValidation{
						zone:     "test.",
						insecure: true,
					},
					"host.child.test.",
				)
			if !errors.Is(err, errDNSSECBogus) {
				t.Fatalf("validationForReferral() error = %v, want bogus", err)
			}
		})
	}
}

func TestValidateAuthenticatedNegativeResponses(t *testing.T) {
	zone := "secure.test."
	key, signer := newTestDNSSECKey(t, zone)
	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Ns:      "ns.secure.test.",
		Mbox:    "hostmaster.secure.test.",
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  300,
	}

	t.Run("NODATA", func(t *testing.T) {
		name := "present.secure.test."
		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			NextDomain: "z.secure.test.",
			TypeBitMap: []uint16{
				dns.TypeA,
				dns.TypeRRSIG,
				dns.TypeNSEC,
			},
		}
		resp := signedNegativeResponse(
			t,
			dns.RcodeSuccess,
			zone,
			key,
			signer,
			soa,
			nsec,
		)
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeAAAA)
		valid, err := (&Resolver{}).validateFinalResponse(
			query,
			resp,
			&dnssecValidation{
				zone: zone,
				keys: []*dns.DNSKEY{key},
			},
		)
		if err != nil || !valid {
			t.Fatalf(
				"validateFinalResponse() = %v, %v; want true, nil",
				valid,
				err,
			)
		}
	})

	t.Run("NXDOMAIN", func(t *testing.T) {
		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			NextDomain: "z.secure.test.",
			TypeBitMap: []uint16{
				dns.TypeNS,
				dns.TypeSOA,
				dns.TypeRRSIG,
				dns.TypeNSEC,
			},
		}
		resp := signedNegativeResponse(
			t,
			dns.RcodeNameError,
			zone,
			key,
			signer,
			soa,
			nsec,
		)
		query := new(dns.Msg)
		query.SetQuestion("missing.secure.test.", dns.TypeA)
		valid, err := (&Resolver{}).validateFinalResponse(
			query,
			resp,
			&dnssecValidation{
				zone: zone,
				keys: []*dns.DNSKEY{key},
			},
		)
		if err != nil || !valid {
			t.Fatalf(
				"validateFinalResponse() = %v, %v; want true, nil",
				valid,
				err,
			)
		}
	})

	t.Run("NSEC empty non-terminal", func(t *testing.T) {
		name := "empty.secure.test."
		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   "a.secure.test.",
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			NextDomain: "child.empty.secure.test.",
			TypeBitMap: []uint16{dns.TypeRRSIG, dns.TypeNSEC},
		}
		assertValidNegativeResponse(
			t,
			zone,
			key,
			signer,
			soa,
			dns.RcodeSuccess,
			name,
			dns.TypeAAAA,
			nsec,
		)
	})

	t.Run("NSEC wildcard NODATA", func(t *testing.T) {
		name := "host.wild.secure.test."
		cover := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   zone,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			NextDomain: "z.secure.test.",
			TypeBitMap: []uint16{
				dns.TypeNS,
				dns.TypeSOA,
				dns.TypeRRSIG,
				dns.TypeNSEC,
			},
		}
		wildcard := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   "*.wild.secure.test.",
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			NextDomain: "z.wild.secure.test.",
			TypeBitMap: []uint16{
				dns.TypeA,
				dns.TypeRRSIG,
				dns.TypeNSEC,
			},
		}
		assertValidNegativeResponse(
			t,
			zone,
			key,
			signer,
			soa,
			dns.RcodeSuccess,
			name,
			dns.TypeAAAA,
			cover,
			wildcard,
		)
	})

	t.Run("NSEC3 NODATA", func(t *testing.T) {
		name := "present.secure.test."
		nsec3 := testNSEC3(
			name,
			zone,
			0,
			[]uint16{dns.TypeA},
		)
		assertValidNegativeResponse(
			t,
			zone,
			key,
			signer,
			soa,
			dns.RcodeSuccess,
			name,
			dns.TypeAAAA,
			nsec3,
		)
	})

	t.Run("NSEC3 NXDOMAIN", func(t *testing.T) {
		name := "missing.secure.test."
		closest := testNSEC3(
			zone,
			zone,
			0,
			[]uint16{dns.TypeNS, dns.TypeSOA},
		)
		if !provesNXDOMAIN(name, []dns.RR{closest}) {
			t.Fatal("provesNXDOMAIN() rejected closest-encloser proof")
		}
		assertValidNegativeResponse(
			t,
			zone,
			key,
			signer,
			soa,
			dns.RcodeNameError,
			name,
			dns.TypeA,
			closest,
		)
	})

	t.Run("NSEC3 wildcard NODATA", func(t *testing.T) {
		name := "host.wild.secure.test."
		closestName := "wild.secure.test."
		closest := testNSEC3(
			closestName,
			zone,
			0,
			nil,
		)
		wildcard := testNSEC3(
			wildcardName(closestName),
			zone,
			0,
			[]uint16{dns.TypeA},
		)
		assertValidNegativeResponse(
			t,
			zone,
			key,
			signer,
			soa,
			dns.RcodeSuccess,
			name,
			dns.TypeAAAA,
			closest,
			wildcard,
		)
	})

	t.Run("NSEC3 opt-out empty non-terminal", func(t *testing.T) {
		name := "empty.delegation.secure.test."
		closest := testNSEC3(
			zone,
			zone,
			1,
			[]uint16{dns.TypeNS, dns.TypeSOA},
		)
		assertValidNegativeResponse(
			t,
			zone,
			key,
			signer,
			soa,
			dns.RcodeSuccess,
			name,
			dns.TypeAAAA,
			closest,
		)
	})

	t.Run("NSEC3 signed but non-proving", func(t *testing.T) {
		name := "missing.secure.test."
		nonProof := testNSEC3(name, zone, 0, nil)
		resp := signedNegativeResponse(
			t,
			dns.RcodeNameError,
			zone,
			key,
			signer,
			soa,
			nonProof,
		)
		query := new(dns.Msg)
		query.SetQuestion(name, dns.TypeA)
		valid, err := (&Resolver{}).validateFinalResponse(
			query,
			resp,
			&dnssecValidation{
				zone: zone,
				keys: []*dns.DNSKEY{key},
			},
		)
		if err == nil || valid {
			t.Fatalf(
				"validateFinalResponse() = %v, %v; want false, error",
				valid,
				err,
			)
		}
	})
}

func TestOnChainDSBecomesTrustAnchor(t *testing.T) {
	loadIsolatedTestState(t)

	key, _ := newTestDNSSECKey(t, "chainroot.")
	ds := testDS(t, key)
	if err := state.GetState().UpdateHandshakeDomain(
		"chainroot.",
		[]state.DomainRecord{
			{
				Lhs:  "chainroot.",
				Type: "DS",
				Ttl:  300,
				Rhs: fmt.Sprintf(
					"%d %d %d %s",
					ds.KeyTag,
					ds.Algorithm,
					ds.DigestType,
					ds.Digest,
				),
			},
		},
	); err != nil {
		t.Fatalf("UpdateHandshakeDomain() error = %v", err)
	}

	resolver := &Resolver{
		dnssecEnabled: true,
		trustAnchors:  make(map[string][]dns.RR),
	}
	anchors, err := resolver.trustAnchorsForZone("chainroot.")
	if err != nil {
		t.Fatalf("trustAnchorsForZone() error = %v", err)
	}
	if len(anchors) != 1 {
		t.Fatalf("anchor count = %d, want 1", len(anchors))
	}
	got, ok := anchors[0].(*dns.DS)
	if !ok || got.KeyTag != ds.KeyTag ||
		!strings.EqualFold(got.Digest, ds.Digest) {
		t.Fatalf("on-chain anchor = %#v, want %s", anchors[0], ds)
	}

	// A same-named Cardano delegation takes precedence and must not
	// inherit the Handshake anchor from a different root.
	if err := state.GetState().UpdateDomain(
		"chainroot.",
		[]state.DomainRecord{
			{
				Lhs:  "chainroot.",
				Type: "NS",
				Ttl:  300,
				Rhs:  "ns.chainroot.",
			},
		},
	); err != nil {
		t.Fatalf("UpdateDomain() error = %v", err)
	}
	anchors, err = resolver.trustAnchorsForZone("chainroot.")
	if err != nil {
		t.Fatalf("trustAnchorsForZone() error = %v", err)
	}
	if len(anchors) != 0 {
		t.Fatalf(
			"Cardano delegation inherited %d Handshake anchors",
			len(anchors),
		)
	}
}

func loadIsolatedTestState(t testing.TB) {
	t.Helper()
	cfg := config.GetConfig()
	oldDirectory := cfg.State.Directory
	wasLoaded := stateIsLoaded()
	if err := state.GetState().Close(); err != nil {
		t.Fatalf("state.Close() error = %v", err)
	}
	cfg.State.Directory = t.TempDir()
	if err := state.GetState().Load(); err != nil {
		t.Fatalf("state.Load() error = %v", err)
	}
	t.Cleanup(func() {
		if err := state.GetState().Close(); err != nil {
			t.Errorf("state.Close() error = %v", err)
		}
		cfg.State.Directory = oldDirectory
		if wasLoaded {
			if err := state.GetState().Load(); err != nil {
				t.Errorf("restore state.Load() error = %v", err)
			}
		}
	})
}

func BenchmarkLocalDNSSECProofLookupDoesNotRescanCachedZone(b *testing.B) {
	for _, unrelatedRecords := range []int{1, 1024} {
		b.Run(fmt.Sprintf("unrelated-%d", unrelatedRecords), func(b *testing.B) {
			loadIsolatedTestState(b)
			zone := fmt.Sprintf("bench-%d.", unrelatedRecords)
			records := make([]state.DomainRecord, 0, unrelatedRecords)
			for idx := range unrelatedRecords {
				records = append(records, state.DomainRecord{
					Lhs:  fmt.Sprintf("n%d.%s", idx, zone),
					Type: "NSEC",
					Rhs:  fmt.Sprintf("z.%s NSEC", zone),
				})
			}
			if err := state.GetState().UpdateDomain(zone, records); err != nil {
				b.Fatalf("UpdateDomain() error = %v", err)
			}
			if _, err := lookupCachedLocalZoneDNSSECRecords(zone, false); err != nil {
				b.Fatalf("warm cache lookup error = %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if _, err := lookupCachedLocalZoneDNSSECRecords(zone, false); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestLocalAuthenticatedDenialResponses(t *testing.T) {
	loadIsolatedTestState(t)
	zone := "ada."
	key, signer := newTestDNSSECKey(t, zone)
	soa := generateSyntheticSOA(zone)
	nsec := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    soa.Hdr.Ttl,
		},
		NextDomain: "z.ada.",
		TypeBitMap: []uint16{
			dns.TypeSOA,
			dns.TypeRRSIG,
			dns.TypeNSEC,
		},
	}
	records := []state.DomainRecord{
		testStateRecord(t, soa),
		testStateRecord(t, nsec),
		testStateRecord(
			t,
			signTestRRset(
				t,
				zone,
				key,
				signer,
				[]dns.RR{nsec},
			),
		),
		testStateRecord(
			t,
			signTestRRset(
				t,
				zone,
				key,
				signer,
				[]dns.RR{soa},
			),
		),
	}
	if err := state.GetState().UpdateDomain(zone, records); err != nil {
		t.Fatalf("UpdateDomain() error = %v", err)
	}

	resolver := &Resolver{}
	req := new(dns.Msg)
	req.SetQuestion("missing.ada.", dns.TypeA)
	req.SetEdns0(1232, true)
	writer := new(captureResponseWriter)
	resolver.handleQuery(writer, req)
	if writer.msg == nil {
		t.Fatal("handleQuery() wrote no NXDOMAIN response")
	}
	if writer.msg.Rcode != dns.RcodeNameError {
		t.Fatalf("response = %v, want NXDOMAIN", writer.msg)
	}
	if !writer.msg.Authoritative {
		t.Fatal("local NXDOMAIN response is not authoritative")
	}
	if len(rrsetFrom(writer.msg.Ns, zone, dns.TypeSOA)) != 1 ||
		len(signaturesFor(writer.msg.Ns, zone, dns.TypeSOA)) != 1 ||
		len(rrsetFrom(writer.msg.Ns, zone, dns.TypeNSEC)) != 1 ||
		len(signaturesFor(writer.msg.Ns, zone, dns.TypeNSEC)) != 1 {
		t.Fatalf("authenticated denial authority = %v", writer.msg.Ns)
	}
	valid, err := resolver.validateFinalResponse(
		req,
		writer.msg,
		&dnssecValidation{
			zone: zone,
			keys: []*dns.DNSKEY{key},
		},
	)
	if err != nil || !valid {
		t.Fatalf(
			"validateFinalResponse(local denial) = %v, %v",
			valid,
			err,
		)
	}

	req = new(dns.Msg)
	req.SetQuestion(zone, dns.TypeSOA)
	req.SetEdns0(1232, true)
	writer = new(captureResponseWriter)
	resolver.handleQuery(writer, req)
	if writer.msg == nil {
		t.Fatal("handleQuery() wrote no SOA response")
	}
	if len(rrsetFrom(writer.msg.Answer, zone, dns.TypeSOA)) != 1 ||
		len(signaturesFor(writer.msg.Answer, zone, dns.TypeSOA)) != 1 {
		t.Fatalf("signed stored SOA answer = %v", writer.msg.Answer)
	}
	valid, err = resolver.validateFinalResponse(
		req,
		writer.msg,
		&dnssecValidation{
			zone: zone,
			keys: []*dns.DNSKEY{key},
		},
	)
	if err != nil || !valid {
		t.Fatalf(
			"validateFinalResponse(local SOA) = %v, %v",
			valid,
			err,
		)
	}

	if err := state.GetState().UpdateDomain(zone, nil); err != nil {
		t.Fatalf("clear UpdateDomain() error = %v", err)
	}
	req = new(dns.Msg)
	req.SetQuestion("unsigned.ada.", dns.TypeA)
	req.SetEdns0(1232, true)
	writer = new(captureResponseWriter)
	resolver.handleQuery(writer, req)
	if writer.msg == nil {
		t.Fatal("handleQuery() wrote no unsigned response")
	}
	if len(writer.msg.Ns) != 1 ||
		writer.msg.Ns[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("unsigned authority = %v, want only SOA", writer.msg.Ns)
	}
}

func TestLocalDNSSECRecordsDoNotMixRoots(t *testing.T) {
	loadIsolatedTestState(t)
	zone := "hns."
	handshakeNSEC := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   zone,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
		},
		NextDomain: "z.hns.",
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeNSEC},
	}
	cardanoNSEC := &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   "poison.hns.",
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
		},
		NextDomain: "z.hns.",
		TypeBitMap: []uint16{dns.TypeNSEC},
	}
	if err := state.GetState().UpdateHandshakeDomain(
		zone,
		[]state.DomainRecord{
			{
				Lhs:  zone,
				Type: "NS",
				Rhs:  "ns.hns.",
			},
			testStateRecord(t, handshakeNSEC),
		},
	); err != nil {
		t.Fatalf("UpdateHandshakeDomain() error = %v", err)
	}
	if err := state.GetState().UpdateDomain(
		"poison.hns.",
		[]state.DomainRecord{testStateRecord(t, cardanoNSEC)},
	); err != nil {
		t.Fatalf("UpdateDomain() error = %v", err)
	}

	fromHandshake, err := localZoneUsesHandshake(zone)
	if err != nil || !fromHandshake {
		t.Fatalf(
			"localZoneUsesHandshake() = %v, %v; want Handshake",
			fromHandshake,
			err,
		)
	}
	records, err := lookupLocalZoneDNSSECRecords(zone, fromHandshake)
	if err != nil {
		t.Fatalf("lookupLocalZoneDNSSECRecords() error = %v", err)
	}
	if len(records) != 1 ||
		canonicalDNSName(records[0].Header().Name) != zone {
		t.Fatalf("local DNSSEC records crossed roots: %v", records)
	}
}

func TestLocalDNSSECProofCacheInvalidatesAndIsConcurrent(t *testing.T) {
	loadIsolatedTestState(t)
	zone := "cache."
	record := state.DomainRecord{
		Lhs:  zone,
		Type: "NSEC",
		Rhs:  "z.cache. NSEC",
	}
	if err := state.GetState().UpdateDomain(zone, []state.DomainRecord{record}); err != nil {
		t.Fatalf("UpdateDomain() error = %v", err)
	}
	records, err := lookupLocalZoneDNSSECRecords(zone, false)
	if err != nil || len(records) != 1 {
		t.Fatalf("initial cached lookup = %v, %v; want one record", records, err)
	}

	const queryCount = 16
	errCh := make(chan error, queryCount)
	for range queryCount {
		go func() {
			got, lookupErr := lookupLocalZoneDNSSECRecords(zone, false)
			if lookupErr != nil {
				errCh <- lookupErr
				return
			}
			if len(got) != 1 {
				errCh <- fmt.Errorf("concurrent cached lookup returned %d records", len(got))
				return
			}
			errCh <- nil
		}()
	}
	for range queryCount {
		if err := <-errCh; err != nil {
			t.Fatal(err)
		}
	}

	if err := state.GetState().UpdateDomain(zone, nil); err != nil {
		t.Fatalf("remove UpdateDomain() error = %v", err)
	}
	records, err = lookupLocalZoneDNSSECRecords(zone, false)
	if err != nil || len(records) != 0 {
		t.Fatalf("lookup after removal = %v, %v; want empty result", records, err)
	}
}

func TestCopyResponseDNSSECVisibility(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("secure.test.", dns.TypeA)
	src := new(dns.Msg)
	src.SetReply(req)
	src.AuthenticatedData = true
	src.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "secure.test.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: net.ParseIP("192.0.2.30"),
		},
		&dns.RRSIG{
			Hdr: dns.RR_Header{
				Name:   "secure.test.",
				Rrtype: dns.TypeRRSIG,
				Class:  dns.ClassINET,
			},
			TypeCovered: dns.TypeA,
		},
	}
	dest := new(dns.Msg)
	copyResponse(req, src, dest)
	if dest.AuthenticatedData {
		t.Fatal("copyResponse() preserved AD without an AD or DO request")
	}
	if len(dest.Answer) != 1 {
		t.Fatalf("answer count without DO = %d, want 1", len(dest.Answer))
	}

	req.AuthenticatedData = true
	dest = new(dns.Msg)
	copyResponse(req, src, dest)
	if !dest.AuthenticatedData {
		t.Fatal("copyResponse() did not preserve requested AD without DO")
	}
	if len(dest.Answer) != 1 {
		t.Fatalf("answer count with AD request = %d, want 1", len(dest.Answer))
	}

	req.SetEdns0(1232, true)
	dest = new(dns.Msg)
	copyResponse(req, src, dest)
	if !dest.AuthenticatedData {
		t.Fatal("copyResponse() did not preserve AD with DO")
	}
	if len(dest.Answer) != 2 {
		t.Fatalf("answer count with DO = %d, want 2", len(dest.Answer))
	}

	records := slices.Clone(src.Answer)
	if len(records) != 2 {
		t.Fatalf("copied source records = %v, want two records", records)
	}
	filtered := filterDNSSECRecords(records, dns.TypeA)
	if len(filtered) != 1 ||
		filtered[0].Header().Rrtype != dns.TypeA ||
		records[1].Header().Rrtype != dns.TypeRRSIG {
		t.Fatalf(
			"filterDNSSECRecords() mutated input: records=%v filtered=%v",
			records,
			filtered,
		)
	}

	filtered = filterDNSSECRecords(records[1:], dns.TypeRRSIG)
	if len(filtered) != 1 ||
		filtered[0].Header().Rrtype != dns.TypeRRSIG {
		t.Fatalf("explicit RRSIG answer was filtered: %v", filtered)
	}
}

func testDS(t *testing.T, key *dns.DNSKEY) *dns.DS {
	t.Helper()
	ds := key.ToDS(dns.SHA256)
	if ds == nil {
		t.Fatal("DNSKEY.ToDS() returned nil")
	}
	return ds
}

func testStateRecord(t *testing.T, rr dns.RR) state.DomainRecord {
	t.Helper()
	fields := strings.SplitN(rr.String(), "\t", 5)
	if len(fields) != 5 {
		t.Fatalf("unexpected RR presentation: %q", rr)
	}
	return state.DomainRecord{
		Lhs:  fields[0],
		Type: fields[3],
		Rhs:  fields[4],
	}
}

func testNSEC3(
	name string,
	zone string,
	flags uint8,
	types []uint16,
) *dns.NSEC3 {
	hash := dns.HashName(name, dns.SHA1, 0, "")
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   hash + "." + dns.Fqdn(zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Flags:      flags,
		NextDomain: hash,
		TypeBitMap: types,
	}
}

func assertValidNegativeResponse(
	t *testing.T,
	zone string,
	key *dns.DNSKEY,
	signer crypto.Signer,
	soa *dns.SOA,
	rcode int,
	name string,
	qtype uint16,
	denials ...dns.RR,
) {
	t.Helper()
	resp := signedNegativeResponse(
		t,
		rcode,
		zone,
		key,
		signer,
		soa,
		denials...,
	)
	query := new(dns.Msg)
	query.SetQuestion(name, qtype)
	valid, err := (&Resolver{}).validateFinalResponse(
		query,
		resp,
		&dnssecValidation{
			zone: zone,
			keys: []*dns.DNSKEY{key},
		},
	)
	if err != nil || !valid {
		t.Fatalf(
			"validateFinalResponse() = %v, %v; want true, nil",
			valid,
			err,
		)
	}
}

func newTestDNSSECKey(
	t *testing.T,
	zone string,
) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Flags:     dns.ZONE | dns.SEP,
		Protocol:  3,
		Algorithm: dns.ED25519,
	}
	privateKey, err := key.Generate(256)
	if err != nil {
		t.Fatalf("DNSKEY.Generate() error = %v", err)
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		t.Fatalf("private key has type %T, want crypto.Signer", privateKey)
	}
	return key, signer
}

func signTestRRset(
	t *testing.T,
	zone string,
	key *dns.DNSKEY,
	signer crypto.Signer,
	rrset []dns.RR,
) *dns.RRSIG {
	t.Helper()
	if len(rrset) == 0 {
		t.Fatal("cannot sign empty RRset")
	}
	now := time.Now()
	sig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   rrset[0].Header().Name,
			Rrtype: dns.TypeRRSIG,
			Class:  rrset[0].Header().Class,
			Ttl:    rrset[0].Header().Ttl,
		},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(now.Add(time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  dns.Fqdn(zone),
	}
	if err := sig.Sign(signer, rrset); err != nil {
		t.Fatalf("RRSIG.Sign(%s) error = %v", fmt.Sprint(rrset), err)
	}
	return sig
}

func signedNegativeResponse(
	t *testing.T,
	rcode int,
	zone string,
	key *dns.DNSKEY,
	signer crypto.Signer,
	soa *dns.SOA,
	denials ...dns.RR,
) *dns.Msg {
	t.Helper()
	soaRRset := []dns.RR{soa}
	ret := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response:      true,
			Authoritative: true,
			Rcode:         rcode,
		},
		Ns: []dns.RR{
			soa,
			signTestRRset(t, zone, key, signer, soaRRset),
		},
	}
	type rrsetKey struct {
		name   string
		rrType uint16
	}
	rrsets := make(map[rrsetKey][]dns.RR)
	for _, rr := range denials {
		ret.Ns = append(ret.Ns, rr)
		rrset := rrsetKey{
			name:   canonicalDNSName(rr.Header().Name),
			rrType: rr.Header().Rrtype,
		}
		rrsets[rrset] = append(rrsets[rrset], rr)
	}
	for _, rrset := range rrsets {
		ret.Ns = append(
			ret.Ns,
			signTestRRset(t, zone, key, signer, rrset),
		)
	}
	return ret
}
