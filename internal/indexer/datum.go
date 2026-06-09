// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package indexer

import (
	"fmt"

	"github.com/blinklabs-io/gouroboros/cbor"
)

// DNSReferenceRefScriptDatum represents the auto-discovery datum type for scripts that handle DNS records
type DNSReferenceRefScriptDatum struct {
	cbor.StructAsArray
	TldName    []byte
	SymbolDrat []byte
	SymbolHns  []byte
}

func (d *DNSReferenceRefScriptDatum) UnmarshalCBOR(cborData []byte) error {
	var tmpData cbor.ConstructorDecoder
	if _, err := cbor.Decode(cborData, &tmpData); err != nil {
		return err
	}
	if tmpData.Tag() != 3 {
		return fmt.Errorf(
			"unexpected outer constructor index: %d",
			tmpData.Tag(),
		)
	}
	tmpDataFields, err := tmpData.ParsedFields()
	if err != nil {
		return err
	}
	if len(tmpDataFields) != 1 {
		return fmt.Errorf(
			"unexpected inner field count: expected 1, got %d",
			len(tmpDataFields),
		)
	}
	fieldInner, ok := tmpDataFields[0].(cbor.ConstructorDecoder)
	if !ok {
		return fmt.Errorf(
			"unexpected data type %T for outer constructor field",
			tmpDataFields[0],
		)
	}
	var tmpDataInner cbor.ConstructorDecoder
	if _, err := cbor.Decode(fieldInner.Cbor(), &tmpDataInner); err != nil {
		return err
	}
	if tmpDataInner.Tag() != 1 {
		return fmt.Errorf(
			"unexpected inner constructor index: %d",
			tmpDataInner.Tag(),
		)
	}
	// Decode constr field data without using our custom decode function
	type tDNSReferenceRefScriptDatum DNSReferenceRefScriptDatum
	var tmpScriptDatum tDNSReferenceRefScriptDatum
	if _, err := cbor.Decode(tmpDataInner.Fields(), &tmpScriptDatum); err != nil {
		return err
	}
	*d = DNSReferenceRefScriptDatum(tmpScriptDatum)
	return nil
}
