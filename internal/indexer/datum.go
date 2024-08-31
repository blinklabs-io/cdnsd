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
	// This allows the type to be used with cbor.DecodeGeneric
	cbor.StructAsArray
	TldName    []byte
	SymbolDrat []byte
	SymbolHns  []byte
}

func (d *DNSReferenceRefScriptDatum) UnmarshalCBOR(cborData []byte) error {
	var tmpData cbor.Constructor
	if _, err := cbor.Decode(cborData, &tmpData); err != nil {
		return err
	}
	if tmpData.Constructor() != 3 {
		return fmt.Errorf(
			"unexpected outer constructor index: %d",
			tmpData.Constructor(),
		)
	}
	tmpDataFields := tmpData.Fields()
	if len(tmpDataFields) != 1 {
		return fmt.Errorf(
			"unexpected inner field count: expected 1, got %d",
			len(tmpDataFields),
		)
	}
	fieldInner, ok := tmpDataFields[0].(cbor.Constructor)
	if !ok {
		return fmt.Errorf(
			"unexpected data type %T for outer constructor field",
			tmpDataFields[0],
		)
	}
	var tmpDataInner cbor.Constructor
	if _, err := cbor.Decode(fieldInner.Cbor(), &tmpDataInner); err != nil {
		return err
	}
	if tmpDataInner.Constructor() != 1 {
		return fmt.Errorf(
			"unexpected inner constructor index: %d",
			tmpDataInner.Constructor(),
		)
	}
	return cbor.DecodeGeneric(tmpDataInner.FieldsCbor(), d)
}
