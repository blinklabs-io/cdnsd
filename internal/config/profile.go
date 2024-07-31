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

func GetProfiles() []Profile {
	var ret []Profile
	for k, profile := range Profiles {
		for _, tmpProfile := range globalConfig.Profiles {
			if k == tmpProfile {
				ret = append(ret, profile)
				break
			}
		}
	}
	return ret
}

func GetAvailableProfiles() []string {
	var ret []string
	for k := range Profiles {
		ret = append(ret, k)
	}
	return ret
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
	"ada-preprod": Profile{
		Network:       "preprod",
		Tld:           "ada",
		PolicyId:      "32c89cdb9c73b904ae0fd230770ee082d6e5fe090b20eaa08ee70dd3",
		ScriptAddress: "addr_test1xzqg5fr7v4ee3p2xehpnm44ad5hu485jnsn4f78566evl7qrdufu8hy0xgpxma2wyt4mtcwgt0td0rtx5ku0vxll3yns632tph",
		// The intercept slot/hash correspond to the block before the first TX on the above address
		InterceptSlot: 65308876,
		InterceptHash: "435703531e57bfe9b4d309e7360efc43e04d06531c9393530c57bebf029ec634",
	},
}
