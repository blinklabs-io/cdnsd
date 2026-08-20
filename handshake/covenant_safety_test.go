// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake_test

import (
	"testing"

	"github.com/blinklabs-io/cdnsd/handshake"
)

func TestCheckedCovenantRejectsMalformedInput(t *testing.T) {
	testCases := []*handshake.GenericCovenant{
		{Type: handshake.CovenantTypeOpen},
		{Type: 255},
	}
	for _, covenant := range testCases {
		if _, err := covenant.CheckedCovenant(); err == nil {
			t.Fatalf("CheckedCovenant accepted malformed covenant %#v", covenant)
		}
	}
}
