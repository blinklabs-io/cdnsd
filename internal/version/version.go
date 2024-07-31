// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package version

import (
	"fmt"
)

// These are populated at build time
var Version string
var CommitHash string

func GetVersionString() string {
	if Version != "" {
		return fmt.Sprintf("%s (commit %s)", Version, CommitHash)
	} else {
		return fmt.Sprintf("devel (commit %s)", CommitHash)
	}
}
