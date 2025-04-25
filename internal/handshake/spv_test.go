// Copyright 2025 Blink Labs Software
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

package handshake_test

import (
	"testing"

	"github.com/blinklabs-io/cdnsd/internal/handshake"
)

func TestVerifySpvProof(t *testing.T) {
	testDefs := []struct {
		root      []byte
		key       []byte
		proofJson string
	}{
		// Domain "name"
		{
			root: decodeHex(
				"5174d1e0d32c4a31b79c71f4e9e26904a813ec19a76087758f71e99f9f90e393",
			),
			key: decodeHex(
				"859cbd19b98e068fe07e440cb69f824d74fc8d5715f272d6dccf464fe0aa6c71",
			),
			proofJson: `
			{
			      "type": "TYPE_SHORT",
			      "depth": 22,
			      "nodes": [
			        [
			          "",
			          "d3f7f3c2401a012a886883913d0461e91f783a608d280d326b9a93f6679c1e90"
			        ],
			        [
			          "",
			          "bed01cf164214d9c95d3a892614e9f0f6145f95a5699af9a33afc9c92eb2ba1a"
			        ],
			        [
			          "",
			          "652ba1f7f41ecce0d4dc13fc1a9c769b6bc3965f3a48f1e12e8872997b055eb2"
			        ],
			        [
			          "",
			          "c673a6ce3c7ea3ed35dba5b35f2ea687c6a8fef599e3eef44ad7988a28020535"
			        ],
			        [
			          "",
			          "49198b9d32fe185d6dc2fc68c1485d98cdec7d3615b58ddef4e584e9d696a820"
			        ],
			        [
			          "",
			          "56238265ba91ad31cad2168bf75e87a8dc457604598d87ac3451d8bd9dc00623"
			        ],
			        [
			          "",
			          "5edecdc405d71fa621baffd2b2f232a58be7a46c9e7c1b1621a3bb977a229a3c"
			        ],
			        [
			          "",
			          "416fee35ff277b50f67b793f927eb5116a54a3cb9105da59daa12efe3c92557b"
			        ],
			        [
			          "",
			          "10fbe37392fc229d3b208ac95d525cc157072a906864dff68e15d1e1ab122337"
			        ],
			        [
			          "",
			          "06736bc32830e18e6ff47d48bf42db6c764fe0b6206ede12a75122a8036e6ee2"
			        ],
			        [
			          "",
			          "2add231da52fe6b7f0dc45e5126c2aca30a910dbcc06e1faa6bcb4141f877aaf"
			        ],
			        [
			          "",
			          "065296a9cd001cc48d30a541a2336aeceb879f1e752f3b13d4cfd8d6dca8817c"
			        ],
			        [
			          "",
			          "42e38378659cdce8b8f0673eb20a2d303fcba021f6c230589f9fec894fbc4f7d"
			        ],
			        [
			          "",
			          "ba1eccfc9bdb698de73149958cb1eba225f3ebe4bcab898bf812bc21cb367ee6"
			        ],
			        [
			          "",
			          "0abae1aa05588462e1827b344556bbdd7b53c4a9894d8121e076d188386f5882"
			        ],
			        [
			          "",
			          "fa37539c63f26aac0b10286e1abde8bdc79d76c2b1647809f6f6582e653badcb"
			        ],
			        [
			          "",
			          "6996e7f04f301126ced7d180ff734886fab0b7ced0da25c5c883ba48f618e6e3"
			        ],
			        [
			          "",
			          "19f4659fd4a9fe390c96ed00d2743ab389304fbf1d746b4c0f63b801e416f875"
			        ],
			        [
			          "",
			          "c2fd00c5dc84ec7721a27d1a6c16f2f6763b3abacd38897b70d25752baa50cbd"
			        ],
			        [
			          "",
			          "0a459f379c5c31ee1237c7cfee8a6255b094113c01fe0638ede725f0d69f6b9a"
			        ],
			        [
			          "",
			          "aa5956c32c7f7d84e41bcdfe4d808e797ae19831b60f7eb4b149f7d044ddd17c"
			        ],
			        [
			          "",
			          "275e850f8e3c54be4bbc7303546a57714ff0c8a335aecb14b11232ac3cc225cb"
			        ]
			      ],
			      "prefix": "1",
			      "left": "c6ace3b9205956fa87dc5ae1addf315d364129a9495e7acb77ecca0ba4f89815",
			      "right": "6fb437a56db52c98f5b55526d05e45e6887c88c89c8995c2a542e1d16a3cc60e"
			}`,
		},
		// Domain "trees"
		{
			root: decodeHex(
				"5174d1e0d32c4a31b79c71f4e9e26904a813ec19a76087758f71e99f9f90e393",
			),
			key: decodeHex(
				"92ec68524dbcc44bc3ff4847ed45e3a86789009d862499ce558c793498413cec",
			),
			proofJson: `
			{
			      "type": "TYPE_EXISTS",
			      "depth": 30,
			      "nodes": [
			        [
			          "",
			          "d3f7f3c2401a012a886883913d0461e91f783a608d280d326b9a93f6679c1e90"
			        ],
			        [
			          "",
			          "bed01cf164214d9c95d3a892614e9f0f6145f95a5699af9a33afc9c92eb2ba1a"
			        ],
			        [
			          "",
			          "652ba1f7f41ecce0d4dc13fc1a9c769b6bc3965f3a48f1e12e8872997b055eb2"
			        ],
			        [
			          "",
			          "b392d029cab23d7a88d9adbfec9605721744dca0aed941baa03331bde02f937f"
			        ],
			        [
			          "",
			          "469f2440ba7efe6850e2741ca4ec549c2bc701badd6b219eb93b72f244322aa8"
			        ],
			        [
			          "",
			          "5d63fae2571be9334d97f00aef4474b7b4f18aaf720db1976ce5363844a3b158"
			        ],
			        [
			          "",
			          "ab0164d5d00dc7491804594bf40edc6ef49600703335173a778a40a17c78b69a"
			        ],
			        [
			          "",
			          "c867693ec3edc13f2b31c4b8f2d8db73462a410e8734e9357a78e600d37c0578"
			        ],
			        [
			          "",
			          "c53e750c6926520a21ab5f3c397bc54fd4276b8aceb7aaff4251d50c67baabcb"
			        ],
			        [
			          "",
			          "decd684b3c1cc62d5a2d536746d07e085fd1827368778efe16eebcfb0e70ef9c"
			        ],
			        [
			          "",
			          "084cfb694dc6d60625cc705f5f14bed7875408463e55467c8d63ffeb0facbf6a"
			        ],
			        [
			          "",
			          "afe946a3da4340a8ef0f6091516f5f78201e5e5f52afca59ef456c39a3b83093"
			        ],
			        [
			          "",
			          "da43ec43520a9d78604335eff49285283905db862556fe10c5abaadad78cce14"
			        ],
			        [
			          "",
			          "cd63fc6b186ce3403f73d69a7d248e2b45f2009ca641b43747d7ec4021eac852"
			        ],
			        [
			          "",
			          "b92b81102689e9a3e3292a0049f22657285270beab97ad96c8281850338f2edf"
			        ],
			        [
			          "",
			          "4b4162da75d6a4233a768517d92f639f516fff2d33c8311308a3e4526664fddc"
			        ],
			        [
			          "",
			          "449d893d9d42e6a3bfd57921d96d8f89eb4d7975b8ea43286bc0213aaa277609"
			        ],
			        [
			          "",
			          "fc478fcd981cd478ef976d113d9bcaf674f5b4dbf6523ff1ce3da83ac8a38d64"
			        ],
			        [
			          "",
			          "927ca127500b4bf85018c0bbe5fc8a3a8df73eae097b0ac117af52241d7eef51"
			        ],
			        [
			          "",
			          "3dd9038ee98c7d0dcd7d811d3dd5577175dbce47338620d14a548f93264c58d5"
			        ],
			        [
			          "",
			          "b3602d3a2b94012064d3ea4ca92259100d20878f43137ea144c59f67e34f139c"
			        ],
			        [
			          "",
			          "8dcd30139a998e5f32dc02de030489d1fa622e862fbd56f400b6351a7c0e23e6"
			        ],
			        [
			          "",
			          "97f6ed8f86936fc7a31b2398ae90cbcbccec369e36b0f5aaae1c706fe08be38c"
			        ],
			        [
			          "",
			          "7e47aa6c6f17b6b5815f24dd0dc7c21748515f33cdc948492c8457c549cead43"
			        ],
			        [
			          "0",
			          "4fba6d35ae5af519d8b247d93b82ac9a76e97fa129661b6471193537b8f79e68"
			        ],
			        [
			          "0",
			          "71d5803145ea1263f5c539221905234f80cdb479595d0c3c0120ce08da2e3c44"
			        ],
			        [
			          "0",
			          "7b30467c3262dcf17f57ee17c51f29c5849e616888c63ee1c4a82d17039a68e6"
			        ]
			      ],
			      "value": "057472656573010000e80700008ced0200c700df14fedcd5f4392742a97ceb68b82e8d674f2912e305cb280f14ce4f7aa34fb400fe00cb280cfe0065cd1d02"
			}`,
		},
		// Domain "blinklabs"
		{
			root: decodeHex(
				"5174d1e0d32c4a31b79c71f4e9e26904a813ec19a76087758f71e99f9f90e393",
			),
			key: decodeHex(
				"66d0eae73152781048a2d83dd103a6dc155d162e72fba88d055f32d99580cef8",
			),
			proofJson: `
			{
			      "type": "TYPE_EXISTS",
			      "depth": 24,
			      "nodes": [
			        [
			          "",
			          "723a992db190e7478826acfdf3d300b15ba93194bcaa1061e2facca8af711d5c"
			        ],
			        [
			          "",
			          "78ad14bed40925b85f4949b586a70202f8ee94361cc402fc1b3c2295a3771fb9"
			        ],
			        [
			          "",
			          "451ba591ed49ce6a17ab261a1ed2e5dfa319a9668ca1f752f33a74aaf25b8ef1"
			        ],
			        [
			          "",
			          "4523ac748f85648dadb5928d80e97365ad15da74d7945bc57c721e0c6ae4c3d1"
			        ],
			        [
			          "",
			          "4b6a11c8cf8693a741f06b1b086fe6fdbf1c330419e2108ab431be12e63c841c"
			        ],
			        [
			          "",
			          "c97ca87f95f8e3e9728bca5dd65ab2432b9f814368b5e26935ba01f5f75b6baa"
			        ],
			        [
			          "",
			          "ee49600ad475454cde8ea979ab0bfb2837b1b937c49a8a61f2a0596e4827e44f"
			        ],
			        [
			          "",
			          "196df0aee57ee6e765f5bf4115ea02ab363fd28b963e0606775932160551bdf4"
			        ],
			        [
			          "",
			          "9dadc7c40a95287042e0d254469f592ff170b7284a4ed3ee5e5af7007374f00f"
			        ],
			        [
			          "",
			          "9e4890ed99f7b255ac2052db789cad62c6ef27c973ff5ca2e0c18197982af2f9"
			        ],
			        [
			          "",
			          "b5bc9650b545f83b5e579eb85acb82a33aa08cb9949f89880c382a2952ac8465"
			        ],
			        [
			          "",
			          "babc937aec10e31180dedda6d98bc454a463b755f1e8821bc23dbfa01932e7f6"
			        ],
			        [
			          "",
			          "e5705254b8f7323f908283cdc961fd0bf9a5c34fea7ff8c103c8609c41d13061"
			        ],
			        [
			          "",
			          "4b34372d57c805501e75556587753c2d9491c553557abcf8b19c2d5b6e614a1c"
			        ],
			        [
			          "",
			          "4a24b6c927cc411fc0b0139cd25f31bc241462ed1d940ca838fe8a7540d3ae77"
			        ],
			        [
			          "",
			          "94783587290eeff3d90bac0e42b13f8cbef0c2a8f4c4d653ad96345615206be5"
			        ],
			        [
			          "",
			          "5d3bc37e2cea4541082ab8af39da723e6a06593c853a319673621c3921a76d73"
			        ],
			        [
			          "",
			          "e03c52fb2f6a82ad73b053218940fc946972c6416f4a209226e6b5ac18f7bafb"
			        ],
			        [
			          "",
			          "8ed3ed55835320261bdab55566b584f5e8ac962edb971ba91ccdcf47945c19d4"
			        ],
			        [
			          "",
			          "c8ab841e1cada58d6c74de5926d4413f4f65c40bb1616000d86b9311f19ee435"
			        ],
			        [
			          "",
			          "d2ca43a264066fd01556f67f9ddaa7e6982d66fa66e41188bdc36c9dc58458a5"
			        ],
			        [
			          "",
			          "89eb8d6b945fa645724ac1a74e3730fbc8b27ecebda1bfc2ad978bad0d9c7865"
			        ],
			        [
			          "",
			          "491ab739a91ce983578ce0cc9041665fe6ec66efa17bb3247633e2225ce9f747"
			        ],
			        [
			          "",
			          "3091fcdc6274b571526591f258923a751b934820452969e985cdb6d2027402a5"
			        ]
			      ],
			      "value": "09626c696e6b6c6162739c000002036e733109626c696e6b6c616273002ce706b701c00202036e7332c00636d688f601c0190004540d01145747d830104f8141a8c53509139e046a710d8f240004540d0220cc882da6a93a4e4a28c38aba03cc67a2fe9d2f91ae1a7beac984d7c7cccd93cb0004540d043056fda1e9a04479c4162770a2c8e757c1e38efba4d4f6ecd4f446e10642ebc258f93b28e5e8251dc2eefa411e0293ad54137002006d020400c5007eaeeeb921f0ba0a7ff5671c27a34570dbfef257cd1a204ba74aabf824aa9fd45fff000fe2080100000001"
			}`,
		},
	}
	for _, testDef := range testDefs {
		proof, err := handshake.NewProofFromJson([]byte(testDef.proofJson))
		if err != nil {
			t.Fatalf("unexpected error decoding proof from JSON: %s", err)
		}
		if _, err := proof.Verify(testDef.root, testDef.key); err != nil {
			t.Fatalf("unexpected error verifying SPV proof: %s", err)
		}
	}
}
