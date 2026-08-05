// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package indexer

import (
	"math"
	"strings"
	"testing"

	models "github.com/blinklabs-io/cardano-models"
)

func TestNameWithinZoneUsesDNSLabelBoundaries(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want bool
	}{
		{name: "alice.cardano.", zone: "alice.cardano.", want: true},
		{name: "www.alice.cardano.", zone: "alice.cardano.", want: true},
		{name: "notalice.cardano.", zone: "alice.cardano.", want: false},
		{name: "alice.cardano2.", zone: "alice.cardano.", want: false},
		{name: `foo\.alice.cardano.`, zone: "alice.cardano.", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := nameWithinZone(test.name, test.zone); got != test.want {
				t.Fatalf("nameWithinZone(%q, %q) = %v, want %v", test.name, test.zone, got, test.want)
			}
		})
	}
}

func TestValidateAndConvertRecordsRejectsUnsafeData(t *testing.T) {
	validRecord := func(recordType, lhs, rhs string) models.CardanoDnsDomainRecord {
		return models.CardanoDnsDomainRecord{
			Lhs:  []byte(lhs),
			Type: []byte(recordType),
			Rhs:  []byte(rhs),
		}
	}
	tests := []struct {
		name   string
		record models.CardanoDnsDomainRecord
	}{
		{
			name:   "sibling name",
			record: validRecord("A", "notalice.cardano.", "192.0.2.1"),
		},
		{
			name:   "unsupported type",
			record: validRecord("NOT-A-DNS-TYPE", "alice.cardano.", "value"),
		},
		{
			name:   "unsupported meta type",
			record: validRecord("ANY", "alice.cardano.", ""),
		},
		{
			name:   "malformed address",
			record: validRecord("A", "alice.cardano.", "999.0.2.1"),
		},
		{
			name:   "unquoted zone-file comment",
			record: validRecord("A", "alice.cardano.", "192.0.2.1;garbage"),
		},
		{
			name: "malformed RRSIG signature",
			record: validRecord(
				"RRSIG",
				"alice.cardano.",
				"A 8 2 300 20270101000000 20260101000000 12345 alice.cardano. not-base64",
			),
		},
		{
			name:   "malformed DNSKEY public key",
			record: validRecord("DNSKEY", "alice.cardano.", "257 3 8 not-base64"),
		},
		{
			name:   "malformed DS digest",
			record: validRecord("DS", "alice.cardano.", "12345 8 2 not-hex"),
		},
		{
			name:   "malformed NSEC3 salt",
			record: validRecord("NSEC3", "alice.cardano.", "1 0 0 not-hex ABCD A"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := validateAndConvertRecords("alice.cardano.", []models.CardanoDnsDomainRecord{test.record})
			if err == nil {
				t.Fatal("expected invalid record to be rejected")
			}
		})
	}

	records, err := validateAndConvertRecords(
		"alice.cardano.",
		[]models.CardanoDnsDomainRecord{
			validRecord("A", "alice.cardano.", "192.0.2.1"),
			validRecord("AAAA", "www.alice.cardano.", "2001:db8::1"),
		},
	)
	if err != nil {
		t.Fatalf("valid records rejected: %v", err)
	}
	if len(records) != 2 || records[0].Type != "A" || records[1].Type != "AAAA" {
		t.Fatalf("unexpected converted records: %#v", records)
	}

	if _, err := validateAndConvertRecords(".", nil); err == nil {
		t.Fatal("root domain should be rejected")
	}
	if _, err := validateAndConvertRecords(
		"alice.cardano.",
		[]models.CardanoDnsDomainRecord{validRecord("A", "", "192.0.2.1")},
	); err == nil {
		t.Fatal("empty record owner should be rejected")
	}
	if _, err := validateAndConvertRecords(
		"alice.cardano.",
		[]models.CardanoDnsDomainRecord{validRecord("TXT", "alice.cardano.", "line\r\nbreak")},
	); err == nil {
		t.Fatal("record data containing a line break should be rejected")
	}
	if _, err := validateAndConvertRecords(
		"alice.cardano.",
		[]models.CardanoDnsDomainRecord{validRecord(
			"DS", "alice.cardano.", "12345 8 2 00",
		)},
	); err == nil || !strings.Contains(err.Error(), "DS digest has length") {
		t.Fatalf("wrong-length DS digest error = %v", err)
	}
	if _, err := validateAndConvertRecords(
		"alice.cardano.",
		[]models.CardanoDnsDomainRecord{validRecord(
			"NSEC3", "alice.cardano.", "1 0 0 - ABCD A",
		)},
	); err == nil || !strings.Contains(err.Error(), "NSEC3 next owner hash has length") {
		t.Fatalf("wrong-length NSEC3 hash error = %v", err)
	}
	ttlRecord := validRecord("A", "alice.cardano.", "192.0.2.1")
	ttlRecord.Ttl = models.NewCardanoDnsMaybe[models.CardanoDnsTtl](
		models.CardanoDnsTtl(math.MaxInt32 + 1),
	)
	if _, err := validateAndConvertRecords(
		"alice.cardano.",
		[]models.CardanoDnsDomainRecord{ttlRecord},
	); err == nil {
		t.Fatal("TTL above the DNS wire limit should be rejected")
	}

	quotedComment, err := validateAndConvertRecords(
		"alice.cardano.",
		[]models.CardanoDnsDomainRecord{validRecord(
			"TXT",
			"alice.cardano.",
			`"hello;world"`,
		)},
	)
	if err != nil {
		t.Fatalf("quoted semicolon rejected: %v", err)
	}
	if quotedComment[0].Rhs != `"hello;world"` {
		t.Fatalf("quoted semicolon was changed: %q", quotedComment[0].Rhs)
	}
}
