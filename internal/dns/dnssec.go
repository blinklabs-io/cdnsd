// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package dns

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/blinklabs-io/cdnsd/internal/config"
	"github.com/blinklabs-io/cdnsd/internal/state"
	"github.com/miekg/dns"
)

var (
	errDNSSECBogus = errors.New("DNSSEC validation failed")
	errNoSignature = errors.New("no valid DNSSEC signature")
)

// dnssecValidation is the security state for the nameservers at the
// current point in an iterative lookup. An empty anchor set means the
// delegation is securely known to be unsigned (or has no configured
// authentication path).
type dnssecValidation struct {
	zone     string
	anchors  []dns.RR
	keys     []*dns.DNSKEY
	insecure bool
}

func (v *dnssecValidation) clone() *dnssecValidation {
	if v == nil {
		return nil
	}
	clone := *v
	clone.anchors = slices.Clone(v.anchors)
	clone.keys = slices.Clone(v.keys)
	return &clone
}

func (r *Resolver) loadTrustAnchors(cfg *config.Config) error {
	r.trustAnchors = make(map[string][]dns.RR)
	if !cfg.Dns.DNSSEC.Enabled {
		return nil
	}
	for line := range strings.SplitSeq(
		cfg.Dns.DNSSEC.TrustAnchors,
		"\n",
	) {
		rr, err := dns.NewRR(line)
		if err != nil {
			return fmt.Errorf("load DNSSEC trust anchors: %w", err)
		}
		if rr == nil {
			continue
		}
		switch rr.(type) {
		case *dns.DS, *dns.DNSKEY:
		default:
			return fmt.Errorf(
				"load DNSSEC trust anchors: unsupported record type %s",
				dns.Type(rr.Header().Rrtype),
			)
		}
		if !supportedTrustAnchor(rr) {
			return fmt.Errorf(
				"load DNSSEC trust anchors: unsupported %s trust anchor for %s",
				dns.Type(rr.Header().Rrtype),
				rr.Header().Name,
			)
		}
		zone := canonicalDNSName(rr.Header().Name)
		r.trustAnchors[zone] = append(r.trustAnchors[zone], rr)
	}
	return nil
}

func canonicalDNSName(name string) string {
	return strings.ToLower(dns.CanonicalName(name))
}

func (r *Resolver) configuredTrustAnchors(zone string) []dns.RR {
	if r == nil || !r.dnssecEnabled {
		return nil
	}
	zone = canonicalDNSName(zone)
	anchors := slices.Clone(r.trustAnchors[zone])
	if zone == "." && r.rootAnchorManager != nil {
		anchors = append(anchors, r.rootAnchorManager.learnedAnchors()...)
	}
	return anchors
}

// trustAnchorsForZone combines operator-configured anchors with DS
// records authenticated by the Cardano or Handshake chain. This is
// the key multi-root property: each blockchain root can establish its
// own DNSSEC island without pretending to descend from the ICANN root.
func (r *Resolver) trustAnchorsForZone(zone string) ([]dns.RR, error) {
	anchors := r.configuredTrustAnchors(zone)
	if !r.dnssecEnabled || !stateAvailable() {
		return anchors, nil
	}

	recordName := strings.TrimSuffix(canonicalDNSName(zone), ".")
	cardanoNS, err := state.GetState().LookupRecords(
		[]string{"NS"},
		recordName,
	)
	if err != nil {
		return nil, err
	}
	handshakeNS, err := state.GetState().LookupHandshakeRecords(
		[]string{"NS"},
		recordName,
	)
	if err != nil {
		return nil, err
	}

	var records []state.DomainRecord
	switch {
	case cardanoNS != nil:
		// Cardano records take precedence throughout the resolver.
		// Do not accidentally pair that delegation with a same-named
		// Handshake DS record from another root.
		records, err = state.GetState().LookupRecords(
			[]string{"DS"},
			recordName,
		)
	case handshakeNS != nil:
		records, err = state.GetState().LookupHandshakeRecords(
			[]string{"DS"},
			recordName,
		)
	default:
		records, err = state.GetState().LookupRecords(
			[]string{"DS"},
			recordName,
		)
		if err == nil && records == nil {
			records, err = state.GetState().LookupHandshakeRecords(
				[]string{"DS"},
				recordName,
			)
		}
	}
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		rr, err := stateRecordToDnsRR(record)
		if err != nil {
			return nil, fmt.Errorf(
				"parse on-chain DNSSEC anchor for %s: %w",
				zone,
				err,
			)
		}
		if _, ok := rr.(*dns.DS); !ok ||
			!supportedTrustAnchor(rr) {
			continue
		}
		anchors = append(anchors, rr)
	}
	return anchors, nil
}

func (r *Resolver) dnssecContextForZone(
	zone string,
	includeOnChain bool,
) (*dnssecValidation, error) {
	if r == nil || !r.dnssecEnabled {
		return nil, nil
	}
	var (
		anchors []dns.RR
		err     error
	)
	if includeOnChain {
		anchors, err = r.trustAnchorsForZone(zone)
	} else {
		anchors = r.configuredTrustAnchors(zone)
	}
	if err != nil {
		return nil, err
	}
	return &dnssecValidation{
		zone:     canonicalDNSName(zone),
		anchors:  anchors,
		insecure: len(anchors) == 0,
	}, nil
}

func dnssecQuery(msg *dns.Msg) *dns.Msg {
	ret := msg.Copy()
	ret.AuthenticatedData = false
	// We perform validation locally and do not want an upstream
	// recursive server to suppress data it considers bogus.
	ret.CheckingDisabled = true
	opt := ret.IsEdns0()
	if opt == nil {
		ret.SetEdns0(1232, true)
	} else {
		opt.SetDo()
		if opt.UDPSize() < 512 {
			opt.SetUDPSize(1232)
		}
	}
	return ret
}

func wantsDNSSEC(msg *dns.Msg) bool {
	if msg == nil {
		return false
	}
	opt := msg.IsEdns0()
	return opt != nil && opt.Do()
}

func exchangeDNS(
	ctx context.Context,
	msg *dns.Msg,
	address string,
	timeout time.Duration,
) (*dns.Msg, error) {
	client := &dns.Client{Timeout: timeout}
	resp, _, err := client.ExchangeContext(ctx, msg, address)
	if err != nil {
		return nil, err
	}
	if resp == nil || !resp.Truncated {
		return resp, nil
	}
	tcpClient := &dns.Client{
		Net:     "tcp",
		Timeout: timeout,
	}
	resp, _, err = tcpClient.ExchangeContext(ctx, msg, address)
	return resp, err
}

func (r *Resolver) ensureDNSSECKeys(
	ctx context.Context,
	validation *dnssecValidation,
	address string,
	timeout time.Duration,
) error {
	if validation == nil || validation.insecure ||
		len(validation.keys) > 0 {
		return nil
	}
	if len(validation.anchors) == 0 {
		validation.insecure = true
		return nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion(validation.zone, dns.TypeDNSKEY)
	resp, err := r.exchange(ctx, dnssecQuery(msg), address, timeout)
	if err != nil {
		return fmt.Errorf("%w: fetch DNSKEY for %s: %w",
			errDNSSECBogus,
			validation.zone,
			err,
		)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return fmt.Errorf(
			"%w: DNSKEY query for %s returned %s",
			errDNSSECBogus,
			validation.zone,
			rcodeString(resp),
		)
	}

	keys := dnskeysFrom(resp.Answer, validation.zone)
	if len(keys) == 0 {
		return fmt.Errorf(
			"%w: no DNSKEY records for %s",
			errDNSSECBogus,
			validation.zone,
		)
	}
	rrset := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		rrset = append(rrset, key)
	}
	sigs := signaturesFor(
		resp.Answer,
		validation.zone,
		dns.TypeDNSKEY,
	)
	if err := authenticateDNSKEYSet(
		rrset,
		sigs,
		keys,
		validation.anchors,
	); err != nil {
		return fmt.Errorf(
			"%w: authenticate DNSKEY for %s: %w",
			errDNSSECBogus,
			validation.zone,
			err,
		)
	}
	validation.keys = activeDNSSECKeys(keys)
	if len(validation.keys) == 0 {
		return fmt.Errorf(
			"%w: no active DNSKEY records for %s",
			errDNSSECBogus,
			validation.zone,
		)
	}
	return nil
}

func activeDNSSECKeys(keys []*dns.DNSKEY) []*dns.DNSKEY {
	return slices.DeleteFunc(
		slices.Clone(keys),
		func(key *dns.DNSKEY) bool {
			return key == nil ||
				key.Protocol != 3 ||
				key.Flags&dns.ZONE == 0 ||
				key.Flags&dns.REVOKE != 0 ||
				!supportedDNSSECAlgorithm(key.Algorithm)
		},
	)
}

func rcodeString(msg *dns.Msg) string {
	if msg == nil {
		return "nil response"
	}
	if name, ok := dns.RcodeToString[msg.Rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", msg.Rcode)
}

func dnskeysFrom(section []dns.RR, zone string) []*dns.DNSKEY {
	zone = canonicalDNSName(zone)
	var ret []*dns.DNSKEY
	for _, rr := range section {
		key, ok := rr.(*dns.DNSKEY)
		if ok && canonicalDNSName(key.Hdr.Name) == zone {
			ret = append(ret, key)
		}
	}
	return ret
}

func signaturesFor(
	section []dns.RR,
	name string,
	rrType uint16,
) []*dns.RRSIG {
	name = canonicalDNSName(name)
	var ret []*dns.RRSIG
	for _, rr := range section {
		sig, ok := rr.(*dns.RRSIG)
		if !ok ||
			sig.TypeCovered != rrType ||
			canonicalDNSName(sig.Hdr.Name) != name {
			continue
		}
		ret = append(ret, sig)
	}
	return ret
}

func authenticateDNSKEYSet(
	rrset []dns.RR,
	sigs []*dns.RRSIG,
	keys []*dns.DNSKEY,
	anchors []dns.RR,
) error {
	var trustedKeys []*dns.DNSKEY
	for _, key := range keys {
		for _, anchor := range anchors {
			if dnskeyMatchesAnchor(key, anchor) {
				trustedKeys = append(trustedKeys, key)
				break
			}
		}
	}
	if len(trustedKeys) == 0 {
		return errors.New("no DNSKEY matches a trust anchor")
	}
	return verifyRRSet(rrset, sigs, trustedKeys)
}

func dnskeyMatchesAnchor(key *dns.DNSKEY, anchor dns.RR) bool {
	if key == nil || anchor == nil ||
		canonicalDNSName(key.Hdr.Name) !=
			canonicalDNSName(anchor.Header().Name) {
		return false
	}
	switch value := anchor.(type) {
	case *dns.DS:
		if value.KeyTag != key.KeyTag() ||
			value.Algorithm != key.Algorithm {
			return false
		}
		derived := key.ToDS(value.DigestType)
		return derived != nil &&
			strings.EqualFold(derived.Digest, value.Digest)
	case *dns.DNSKEY:
		return value.Flags == key.Flags &&
			value.Protocol == key.Protocol &&
			value.Algorithm == key.Algorithm &&
			value.PublicKey == key.PublicKey
	default:
		return false
	}
}

func verifyRRSet(
	rrset []dns.RR,
	sigs []*dns.RRSIG,
	keys []*dns.DNSKEY,
) error {
	if len(rrset) == 0 {
		return errors.New("empty RRset")
	}
	now := time.Now()
	for _, sig := range sigs {
		if sig == nil ||
			sig.TypeCovered != rrset[0].Header().Rrtype ||
			!supportedDNSSECAlgorithm(sig.Algorithm) ||
			!dns.IsSubDomain(
				sig.SignerName,
				rrset[0].Header().Name,
			) ||
			!sig.ValidityPeriod(now) {
			continue
		}
		for _, key := range keys {
			if key == nil ||
				key.Protocol != 3 ||
				key.Flags&dns.ZONE == 0 ||
				key.Flags&dns.REVOKE != 0 ||
				!supportedDNSSECAlgorithm(key.Algorithm) ||
				sig.KeyTag != key.KeyTag() ||
				sig.Algorithm != key.Algorithm ||
				canonicalDNSName(sig.SignerName) !=
					canonicalDNSName(key.Hdr.Name) {
				continue
			}
			if err := sig.Verify(key, rrset); err == nil {
				normalizeValidatedTTL(rrset, sigs, sig, now)
				return nil
			}
		}
	}
	return errNoSignature
}

func normalizeValidatedTTL(
	rrset []dns.RR,
	sigs []*dns.RRSIG,
	validSig *dns.RRSIG,
	now time.Time,
) {
	ttl := validSig.OrigTtl
	const serialPeriod = int64(1 << 31)
	nowUnix := now.UTC().Unix()
	expiration := int64(validSig.Expiration)
	expiration += (expiration - nowUnix) / serialPeriod * serialPeriod
	remaining := expiration - nowUnix
	if remaining >= 0 && remaining < int64(ttl) {
		// remaining is non-negative and less than the uint32 TTL.
		// #nosec G115 -- the bounds check above makes the cast safe.
		ttl = uint32(remaining)
	}
	for _, rr := range rrset {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	for _, sig := range sigs {
		if sig != nil && sig.Hdr.Ttl < ttl {
			ttl = sig.Hdr.Ttl
		}
	}
	for _, rr := range rrset {
		rr.Header().Ttl = ttl
	}
	for _, sig := range sigs {
		if sig != nil {
			sig.Hdr.Ttl = ttl
		}
	}
}

func delegationZone(resp *dns.Msg) (string, error) {
	if resp == nil {
		return "", errors.New("referral has no delegation zone")
	}
	var zone string
	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			owner := canonicalDNSName(ns.Hdr.Name)
			if zone != "" && owner != zone {
				return "", fmt.Errorf(
					"%w: referral has multiple delegation zones",
					errDNSSECBogus,
				)
			}
			zone = owner
		}
	}
	if zone == "" {
		return "", errors.New("referral has no delegation zone")
	}
	return zone, nil
}

func (r *Resolver) validationForReferral(
	resp *dns.Msg,
	parent *dnssecValidation,
	qname string,
) (*dnssecValidation, error) {
	childZone, err := delegationZone(resp)
	if err != nil {
		return nil, err
	}
	if parent == nil ||
		childZone == canonicalDNSName(parent.zone) ||
		!dns.IsSubDomain(parent.zone, childZone) ||
		!dns.IsSubDomain(childZone, qname) {
		return nil, fmt.Errorf(
			"%w: unrelated delegation zone %s",
			errDNSSECBogus,
			childZone,
		)
	}

	// An explicit anchor starts (or re-establishes) an island of
	// security even when its parent root is unrelated or unsigned.
	configured := r.configuredTrustAnchors(childZone)
	if parent.insecure {
		return &dnssecValidation{
			zone:     childZone,
			anchors:  configured,
			insecure: len(configured) == 0,
		}, nil
	}
	if len(parent.keys) == 0 {
		return nil, errors.New("parent DNSKEY set is not authenticated")
	}

	dsRRset := rrsetFrom(resp.Ns, childZone, dns.TypeDS)
	if len(dsRRset) > 0 {
		sigs := signaturesFor(resp.Ns, childZone, dns.TypeDS)
		if err := verifyRRSet(dsRRset, sigs, parent.keys); err != nil {
			return nil, fmt.Errorf(
				"%w: invalid DS RRset for %s: %w",
				errDNSSECBogus,
				childZone,
				err,
			)
		}
		supportedAnchors := supportedDSAnchors(dsRRset)
		if len(supportedAnchors) == 0 {
			return &dnssecValidation{
				zone:     childZone,
				insecure: true,
			}, nil
		}
		return &dnssecValidation{
			zone:    childZone,
			anchors: supportedAnchors,
		}, nil
	}

	if len(configured) > 0 {
		return &dnssecValidation{
			zone:    childZone,
			anchors: configured,
		}, nil
	}
	if err := validateNoDSProof(
		childZone,
		resp.Ns,
		parent.keys,
	); err != nil {
		return nil, fmt.Errorf(
			"%w: unauthenticated unsigned delegation for %s: %w",
			errDNSSECBogus,
			childZone,
			err,
		)
	}
	return &dnssecValidation{
		zone:     childZone,
		insecure: true,
	}, nil
}

func rrsetFrom(
	section []dns.RR,
	name string,
	rrType uint16,
) []dns.RR {
	name = canonicalDNSName(name)
	var ret []dns.RR
	for _, rr := range section {
		if rr.Header().Rrtype == rrType &&
			canonicalDNSName(rr.Header().Name) == name {
			ret = append(ret, rr)
		}
	}
	return ret
}

func validateNoDSProof(
	childZone string,
	section []dns.RR,
	keys []*dns.DNSKEY,
) error {
	proofs := denialProofRecords(section)
	if err := validateSectionRRsets(proofs, keys); err != nil {
		return err
	}
	var nsec3s []*dns.NSEC3
	for _, rr := range proofs {
		if nsec3, ok := rr.(*dns.NSEC3); ok {
			nsec3s = append(nsec3s, nsec3)
		}
	}
	for _, rr := range section {
		switch value := rr.(type) {
		case *dns.NSEC:
			if canonicalDNSName(value.Hdr.Name) ==
				canonicalDNSName(childZone) &&
				hasType(value.TypeBitMap, dns.TypeNS) &&
				!hasType(value.TypeBitMap, dns.TypeDS) &&
				!hasType(value.TypeBitMap, dns.TypeSOA) {
				return nil
			}
		case *dns.NSEC3:
			if validNSEC3(value) && value.Match(childZone) {
				if hasType(value.TypeBitMap, dns.TypeNS) &&
					!hasType(value.TypeBitMap, dns.TypeDS) &&
					!hasType(value.TypeBitMap, dns.TypeSOA) {
					return nil
				}
			}
		}
	}
	_, _, nextCloserProof := nsec3ClosestEncloserProof(
		childZone,
		nsec3s,
	)
	if nextCloserProof != nil && nextCloserProof.Flags&1 != 0 {
		return nil
	}
	return errors.New("missing signed NSEC/NSEC3 no-DS proof")
}

func hasType(types []uint16, rrType uint16) bool {
	return slices.Contains(types, rrType)
}

func supportedDSAnchors(records []dns.RR) []dns.RR {
	var ret []dns.RR
	for _, rr := range records {
		ds, ok := rr.(*dns.DS)
		if !ok ||
			!supportedDSAlgorithm(ds.Algorithm) ||
			!supportedDSDigest(ds.DigestType) {
			continue
		}
		ret = append(ret, ds)
	}
	return ret
}

func supportedTrustAnchor(anchor dns.RR) bool {
	switch value := anchor.(type) {
	case *dns.DS:
		return value != nil &&
			supportedDSAlgorithm(value.Algorithm) &&
			supportedDSDigest(value.DigestType)
	case *dns.DNSKEY:
		return value != nil &&
			value.Protocol == 3 &&
			value.Flags&dns.ZONE != 0 &&
			value.Flags&dns.REVOKE == 0 &&
			supportedDNSSECAlgorithm(value.Algorithm)
	default:
		return false
	}
}

func supportedDNSSECAlgorithm(algorithm uint8) bool {
	switch algorithm {
	case dns.RSASHA1,
		dns.RSASHA1NSEC3SHA1,
		dns.RSASHA256,
		dns.RSASHA512,
		dns.ECDSAP256SHA256,
		dns.ECDSAP384SHA384,
		dns.ED25519:
		return true
	default:
		return false
	}
}

func supportedDSAlgorithm(algorithm uint8) bool {
	// RFC 9905 requires RSASHA1 DS records to be treated as
	// insecure, while implementations must retain support for
	// validating legacy RSASHA1 DNSKEY/RRSIG records.
	return algorithm != dns.RSASHA1 &&
		algorithm != dns.RSASHA1NSEC3SHA1 &&
		supportedDNSSECAlgorithm(algorithm)
}

func supportedDSDigest(digest uint8) bool {
	switch digest {
	case dns.SHA1, dns.SHA256, dns.SHA384:
		return true
	default:
		return false
	}
}

func (r *Resolver) validateFinalResponse(
	query *dns.Msg,
	resp *dns.Msg,
	validation *dnssecValidation,
) (bool, error) {
	if validation == nil || validation.insecure ||
		query.CheckingDisabled {
		return false, nil
	}
	if len(validation.keys) == 0 {
		return false, fmt.Errorf(
			"%w: no authenticated keys for %s",
			errDNSSECBogus,
			validation.zone,
		)
	}

	// RRSIG records do not themselves form a signed RRset. Answering
	// an explicit RRSIG query is therefore valid, but cannot carry AD
	// without separately fetching every covered RRset.
	if len(query.Question) == 1 &&
		query.Question[0].Qtype == dns.TypeRRSIG {
		return false, nil
	}

	if len(resp.Answer) > 0 {
		if err := validateSectionRRsets(
			resp.Answer,
			validation.keys,
		); err != nil {
			return false, fmt.Errorf("%w: %w", errDNSSECBogus, err)
		}
		if len(resp.Ns) > 0 {
			if err := validateSectionRRsets(
				resp.Ns,
				validation.keys,
			); err != nil {
				return false, fmt.Errorf(
					"%w: validate authority section: %w",
					errDNSSECBogus,
					err,
				)
			}
		}
		if err := validateWildcardProofs(
			resp,
			validation.keys,
		); err != nil {
			return false, fmt.Errorf("%w: %w", errDNSSECBogus, err)
		}
		return true, nil
	}

	if resp.Rcode != dns.RcodeSuccess &&
		resp.Rcode != dns.RcodeNameError {
		return false, nil
	}
	if len(query.Question) != 1 {
		return false, errors.New("DNSSEC query has no question")
	}
	if err := validateNegativeResponse(
		query.Question[0],
		resp,
		validation.keys,
	); err != nil {
		return false, fmt.Errorf("%w: %w", errDNSSECBogus, err)
	}
	return true, nil
}

func validateSectionRRsets(
	section []dns.RR,
	keys []*dns.DNSKEY,
) error {
	type rrsetKey struct {
		name   string
		rrType uint16
		class  uint16
	}
	rrsets := make(map[rrsetKey][]dns.RR)
	for _, rr := range section {
		if rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		key := rrsetKey{
			name:   canonicalDNSName(rr.Header().Name),
			rrType: rr.Header().Rrtype,
			class:  rr.Header().Class,
		}
		rrsets[key] = append(rrsets[key], rr)
	}
	for key, rrset := range rrsets {
		sigs := signaturesFor(section, key.name, key.rrType)
		if err := verifyRRSet(rrset, sigs, keys); err != nil {
			return fmt.Errorf(
				"validate %s/%s: %w",
				key.name,
				dns.Type(key.rrType),
				err,
			)
		}
	}
	if len(rrsets) == 0 {
		return errors.New("response contains no signed RRsets")
	}
	return nil
}

func validateWildcardProofs(
	resp *dns.Msg,
	keys []*dns.DNSKEY,
) error {
	for _, rr := range resp.Answer {
		sig, ok := rr.(*dns.RRSIG)
		if !ok ||
			int(sig.Labels) >= dns.CountLabel(sig.Hdr.Name) {
			continue
		}
		rrset := rrsetFrom(
			resp.Answer,
			sig.Hdr.Name,
			sig.TypeCovered,
		)
		if err := verifyRRSet(
			rrset,
			[]*dns.RRSIG{sig},
			keys,
		); err != nil {
			// Another valid signature may cover this RRset without
			// wildcard expansion.
			continue
		}

		proofs := denialProofRecords(resp.Ns)
		if err := validateSectionRRsets(proofs, keys); err != nil {
			return fmt.Errorf(
				"validate wildcard denial proof for %s: %w",
				sig.Hdr.Name,
				err,
			)
		}
		closest, nextCloser := wildcardClosestNames(
			sig.Hdr.Name,
			int(sig.Labels),
		)
		nsecProves := false
		var nsec3s []*dns.NSEC3
		for _, proof := range proofs {
			switch value := proof.(type) {
			case *dns.NSEC:
				nsecProves = nsecProves ||
					nsecCovers(value, nextCloser)
			case *dns.NSEC3:
				if validNSEC3(value) {
					nsec3s = append(nsec3s, value)
				}
			}
		}
		nsec3Proves := false
		for _, closestProof := range nsec3s {
			if !closestProof.Match(closest) {
				continue
			}
			for _, nextCloserProof := range nsec3s {
				if sameNSEC3Parameters(
					closestProof,
					nextCloserProof,
				) && nextCloserProof.Cover(nextCloser) {
					nsec3Proves = true
					break
				}
			}
		}
		if !nsecProves && !nsec3Proves {
			return fmt.Errorf(
				"denial records do not authenticate wildcard answer for %s",
				sig.Hdr.Name,
			)
		}
	}
	return nil
}

func denialProofRecords(section []dns.RR) []dns.RR {
	var ret []dns.RR
	for _, rr := range section {
		switch rr.Header().Rrtype {
		case dns.TypeNSEC, dns.TypeNSEC3:
			ret = append(ret, rr)
		case dns.TypeRRSIG:
			sig, ok := rr.(*dns.RRSIG)
			if ok && (sig.TypeCovered == dns.TypeNSEC ||
				sig.TypeCovered == dns.TypeNSEC3) {
				ret = append(ret, rr)
			}
		}
	}
	return ret
}

func wildcardClosestNames(name string, labels int) (string, string) {
	nameLabels := dns.SplitDomainName(name)
	if len(nameLabels) == 0 {
		return ".", canonicalDNSName(name)
	}
	if labels < 0 {
		labels = 0
	}
	if labels > len(nameLabels) {
		labels = len(nameLabels)
	}
	closest := "."
	if labels > 0 {
		closest = dns.Fqdn(
			strings.Join(nameLabels[len(nameLabels)-labels:], "."),
		)
	}
	return closest, nextCloserName(name, closest)
}

func validateNegativeResponse(
	question dns.Question,
	resp *dns.Msg,
	keys []*dns.DNSKEY,
) error {
	// The SOA and denial records must all be authentic. Semantic
	// checks below then ensure they actually prove this question.
	var denialRecords []dns.RR
	for _, rr := range resp.Ns {
		switch rr.Header().Rrtype {
		case dns.TypeSOA, dns.TypeNSEC, dns.TypeNSEC3:
			denialRecords = append(denialRecords, rr)
		case dns.TypeRRSIG:
			sig, ok := rr.(*dns.RRSIG)
			if ok && (sig.TypeCovered == dns.TypeSOA ||
				sig.TypeCovered == dns.TypeNSEC ||
				sig.TypeCovered == dns.TypeNSEC3) {
				denialRecords = append(denialRecords, rr)
			}
		}
	}
	if err := validateSectionRRsets(resp.Ns, keys); err != nil {
		return err
	}

	qname := canonicalDNSName(question.Name)
	if resp.Rcode == dns.RcodeSuccess {
		if provesNODATA(qname, question.Qtype, denialRecords) {
			return nil
		}
		return errors.New("denial records do not prove NODATA")
	}

	if !provesNXDOMAIN(qname, denialRecords) {
		return errors.New("denial records do not prove NXDOMAIN")
	}
	return nil
}

func provesNODATA(name string, qtype uint16, records []dns.RR) bool {
	return len(nodataProofRecords(name, qtype, records)) > 0
}

func nodataProofRecords(
	name string,
	qtype uint16,
	records []dns.RR,
) []dns.RR {
	var (
		nsecs  []*dns.NSEC
		nsec3s []*dns.NSEC3
	)
	for _, rr := range records {
		switch value := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, value)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, value)
		}
	}

	typeAbsent := func(types []uint16) bool {
		return !hasType(types, qtype) &&
			!hasType(types, dns.TypeCNAME)
	}
	for _, rr := range nsecs {
		if canonicalDNSName(rr.Hdr.Name) == name &&
			typeAbsent(rr.TypeBitMap) {
			return []dns.RR{rr}
		}
		// RFC 8198 Appendix B identifies an empty non-terminal when
		// a covering NSEC's next name is beneath the queried name.
		if nsecCovers(rr, name) &&
			dns.IsSubDomain(name, rr.NextDomain) &&
			canonicalDNSName(rr.NextDomain) != name {
			return []dns.RR{rr}
		}
	}
	for _, wildcard := range nsecs {
		owner := canonicalDNSName(wildcard.Hdr.Name)
		if !strings.HasPrefix(owner, "*.") ||
			!typeAbsent(wildcard.TypeBitMap) {
			continue
		}
		closest := strings.TrimPrefix(owner, "*.")
		if !dns.IsSubDomain(closest, name) {
			continue
		}
		if slices.ContainsFunc(
			nsecs,
			func(rr *dns.NSEC) bool { return nsecCovers(rr, name) },
		) {
			for _, cover := range nsecs {
				if nsecCovers(cover, name) {
					return uniqueDenialRecords(wildcard, cover)
				}
			}
		}
	}

	for _, rr := range nsec3s {
		if validNSEC3(rr) && rr.Match(name) &&
			typeAbsent(rr.TypeBitMap) {
			return []dns.RR{rr}
		}
	}
	closest, closestProof, nextCloserProof := nsec3ClosestEncloserProof(
		name,
		nsec3s,
	)
	if nextCloserProof == nil {
		return nil
	}
	// Verified RFC 5155 erratum 3441 permits an opt-out closest
	// encloser proof for an empty non-terminal.
	if nextCloserProof.Flags&1 != 0 {
		return uniqueDenialRecords(closestProof, nextCloserProof)
	}
	wildcard := wildcardName(closest)
	for _, rr := range nsec3s {
		if sameNSEC3Parameters(rr, nextCloserProof) &&
			rr.Match(wildcard) &&
			typeAbsent(rr.TypeBitMap) {
			return uniqueDenialRecords(
				closestProof,
				nextCloserProof,
				rr,
			)
		}
	}
	return nil
}

func provesNXDOMAIN(name string, records []dns.RR) bool {
	return len(nxdomainProofRecords(name, records)) > 0
}

func nxdomainProofRecords(name string, records []dns.RR) []dns.RR {
	var (
		nsecs  []*dns.NSEC
		nsec3s []*dns.NSEC3
	)
	for _, rr := range records {
		switch value := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, value)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, value)
		}
	}

	ancestors := nameAncestors(name)
	for _, closest := range ancestors {
		exists := false
		for _, rr := range nsecs {
			if canonicalDNSName(rr.Hdr.Name) ==
				canonicalDNSName(closest) {
				exists = true
				break
			}
		}
		if !exists {
			continue
		}
		nameDenied := slices.ContainsFunc(
			nsecs,
			func(rr *dns.NSEC) bool { return nsecCovers(rr, name) },
		)
		wildcard := wildcardName(closest)
		wildcardDenied := slices.ContainsFunc(
			nsecs,
			func(rr *dns.NSEC) bool {
				return nsecCovers(rr, wildcard)
			},
		)
		if nameDenied && wildcardDenied {
			var ret []dns.RR
			for _, rr := range nsecs {
				if canonicalDNSName(rr.Hdr.Name) ==
					canonicalDNSName(closest) ||
					nsecCovers(rr, name) ||
					nsecCovers(rr, wildcard) {
					ret = append(ret, rr)
				}
			}
			return uniqueDenialRecords(ret...)
		}
		break
	}

	closest, closestProof, nextCloserProof := nsec3ClosestEncloserProof(
		name,
		nsec3s,
	)
	if nextCloserProof != nil {
		wildcard := wildcardName(closest)
		for _, rr := range nsec3s {
			if sameNSEC3Parameters(rr, nextCloserProof) &&
				rr.Cover(wildcard) {
				return uniqueDenialRecords(
					closestProof,
					nextCloserProof,
					rr,
				)
			}
		}
	}
	return nil
}

func uniqueDenialRecords(records ...dns.RR) []dns.RR {
	ret := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		if rr == nil || slices.Contains(ret, rr) {
			continue
		}
		ret = append(ret, rr)
	}
	return ret
}

func nsec3ClosestEncloserProof(
	name string,
	records []*dns.NSEC3,
) (string, *dns.NSEC3, *dns.NSEC3) {
	for _, closest := range nameAncestors(name) {
		for _, match := range records {
			if !validNSEC3(match) || !match.Match(closest) ||
				hasType(match.TypeBitMap, dns.TypeDNAME) ||
				(hasType(match.TypeBitMap, dns.TypeNS) &&
					!hasType(match.TypeBitMap, dns.TypeSOA)) {
				continue
			}
			nextCloser := nextCloserName(name, closest)
			for _, cover := range records {
				if sameNSEC3Parameters(match, cover) &&
					cover.Cover(nextCloser) {
					return closest, match, cover
				}
			}
		}
	}
	return "", nil, nil
}

func validNSEC3(rr *dns.NSEC3) bool {
	// RFC 9276 identifies 500 as an interoperable SERVFAIL
	// threshold and warns that accepting the uint16 maximum exposes
	// public resolvers to CPU exhaustion.
	const maxNSEC3Iterations = 500
	return rr != nil &&
		rr.Hash == dns.SHA1 &&
		rr.Flags <= 1 &&
		rr.Iterations <= maxNSEC3Iterations
}

func sameNSEC3Parameters(left *dns.NSEC3, right *dns.NSEC3) bool {
	return validNSEC3(left) &&
		validNSEC3(right) &&
		left.Hash == right.Hash &&
		left.Iterations == right.Iterations &&
		strings.EqualFold(left.Salt, right.Salt)
}

func nameAncestors(name string) []string {
	labels := dns.SplitDomainName(name)
	ret := make([]string, 0, len(labels))
	for i := 1; i < len(labels); i++ {
		ret = append(
			ret,
			dns.Fqdn(strings.Join(labels[i:], ".")),
		)
	}
	ret = append(ret, ".")
	return ret
}

func nextCloserName(name string, closest string) string {
	nameLabels := dns.SplitDomainName(name)
	closestLabels := dns.SplitDomainName(closest)
	if len(nameLabels) <= len(closestLabels) {
		return canonicalDNSName(name)
	}
	start := len(nameLabels) - len(closestLabels) - 1
	return dns.Fqdn(strings.Join(nameLabels[start:], "."))
}

func wildcardName(closest string) string {
	if canonicalDNSName(closest) == "." {
		return "*."
	}
	return dns.Fqdn("*." + closest)
}

func nsecCovers(rr *dns.NSEC, name string) bool {
	if rr == nil {
		return false
	}
	owner := canonicalDNSName(rr.Hdr.Name)
	next := canonicalDNSName(rr.NextDomain)
	name = canonicalDNSName(name)
	if owner == name {
		return false
	}
	if canonicalNameLess(owner, next) {
		return canonicalNameLess(owner, name) &&
			canonicalNameLess(name, next)
	}
	// The final NSEC RR wraps around to the start of the zone.
	return canonicalNameLess(owner, name) ||
		canonicalNameLess(name, next)
}

// canonicalNameLess implements the DNSSEC canonical name ordering
// from RFC 4034 section 6.1: compare labels from the root outwards.
func canonicalNameLess(left string, right string) bool {
	lhs := dns.SplitDomainName(strings.ToLower(left))
	rhs := dns.SplitDomainName(strings.ToLower(right))
	for len(lhs) > 0 && len(rhs) > 0 {
		leftLabel := lhs[len(lhs)-1]
		rightLabel := rhs[len(rhs)-1]
		if leftLabel != rightLabel {
			return leftLabel < rightLabel
		}
		lhs = lhs[:len(lhs)-1]
		rhs = rhs[:len(rhs)-1]
	}
	return len(lhs) < len(rhs)
}

func filterDNSSECRecords(
	records []dns.RR,
	requestedType uint16,
) []dns.RR {
	ret := make([]dns.RR, 0, len(records))
	for _, rr := range records {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
			if rr.Header().Rrtype != requestedType {
				continue
			}
		default:
			ret = append(ret, rr)
			continue
		}
		ret = append(ret, rr)
	}
	return ret
}
