// Copyright 2026 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package indexer

import (
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
			name:   "malformed address",
			record: validRecord("A", "alice.cardano.", "999.0.2.1"),
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
	if len(records) != 2 || !strings.EqualFold(records[0].Type, "A") {
		t.Fatalf("unexpected converted records: %#v", records)
	}
}
