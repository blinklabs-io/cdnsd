// Copyright 2024 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package config

import "slices"

type Profile struct {
	Network          string // Cardano network name
	Tld              string // Top-level domain
	PolicyId         string // Verification asset policy ID
	ScriptAddress    string // Address to follow
	InterceptSlot    uint64 // Chain-sync initial intercept slot
	InterceptHash    string // Chain-sync initial intercept hash
	DiscoveryAddress string // Auto-discovery address to follow
}

func GetProfiles() []Profile {
	var ret []Profile
	for k, profile := range Profiles {
		if slices.Contains(globalConfig.Profiles, k) {
			ret = append(ret, profile)
		}
	}
	return ret
}

func GetAvailableProfiles() []string {
	ret := make([]string, 0, len(Profiles))
	for k := range Profiles {
		ret = append(ret, k)
	}
	return ret
}

var Profiles = map[string]Profile{
	// This (default) profile corresponds to the values specified in:
	// https://github.com/blinklabs-io/cardano-dns/blob/main/README.md
	"cardano-preprod-testing": {
		Network:       "preprod",
		Tld:           "cardano",
		PolicyId:      "6af60c2a7a06551ef09b3810a41d086b26ca26f926d22e462103194d",
		ScriptAddress: "addr_test1vr75xezmpxastymx985l3gamuxrwqdwcfrcnjlygs55aynsqu3edq",
		InterceptSlot: 50844079,
		InterceptHash: "81325118471fddb00a20327572b371aee7cce13b846a18500d011b9cefd2a34c",
	},
	"ada-preprod": {
		Network:       "preprod",
		Tld:           "ada",
		PolicyId:      "32c89cdb9c73b904ae0fd230770ee082d6e5fe090b20eaa08ee70dd3",
		ScriptAddress: "addr_test1xzqg5fr7v4ee3p2xehpnm44ad5hu485jnsn4f78566evl7qrdufu8hy0xgpxma2wyt4mtcwgt0td0rtx5ku0vxll3yns632tph",
		// The intercept slot/hash correspond to the block before the first TX on the above address
		InterceptSlot: 65308876,
		InterceptHash: "435703531e57bfe9b4d309e7360efc43e04d06531c9393530c57bebf029ec634",
	},
	"hydra-preprod": {
		Network:       "preprod",
		Tld:           "hydra",
		PolicyId:      "f5f8228a4bd56704ad3c612ecc74e5d2e5d15292b8cae3aaa8065fc1",
		ScriptAddress: "addr_test1xq65et2tuw48genyy2hj7d84awfvah2k28enantddllq03vgc3uvcfh3r3kaa5gyk5l2vgdl8vj8cstslf4w2ajuy0wsx37n83",
		// The intercept slot/hash correspond to the block before the first TX on the above address
		InterceptSlot: 67799029,
		InterceptHash: "4815dae9cd8f492ab51b109ba87d091ae85a0999af33ac459d8504122cb911f7",
	},
	"auto-preprod": {
		Network:          "preprod",
		PolicyId:         "63cdaef8b84702282c3454ae130ada94a9b200e32be21abd47fc636b",
		DiscoveryAddress: "addr_test1xrhqrug2hnc9az4ru02kp9rlfcppl464gl4yc8s8jm5p8kygc3uvcfh3r3kaa5gyk5l2vgdl8vj8cstslf4w2ajuy0wsp5fm89",
		// The intercept slot/hash correspond to the block before the first TX on the above address
		InterceptSlot: 67778432,
		InterceptHash: "6db5cdcfa1ee9cc137b0b238ff9251d4481c23bf49ad6272cb833b034a003cbe",
	},
}
