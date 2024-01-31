// Copyright 2023 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package config

type Profile struct {
	Network       string // Cardano network name
	Tld           string // Top-level domain
	PolicyId      string // Verification asset policy ID
	ScriptAddress string // Address to follow
	InterceptSlot uint64 // Chain-sync initial intercept slot
	InterceptHash string // Chain-sync initial intercept hash
}

var Profiles = map[string]Profile{
	// This (default) profile corresponds to the values specified in:
	// https://github.com/blinklabs-io/cardano-dns/blob/main/README.md
	"cardano-preprod-testing": Profile{
		Network:       "preprod",
		Tld:           "cardano",
		PolicyId:      "6af60c2a7a06551ef09b3810a41d086b26ca26f926d22e462103194d",
		ScriptAddress: "addr_test1vr75xezmpxastymx985l3gamuxrwqdwcfrcnjlygs55aynsqu3edq",
		InterceptSlot: 50844079,
		InterceptHash: "81325118471fddb00a20327572b371aee7cce13b846a18500d011b9cefd2a34c",
	},
}
