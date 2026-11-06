package recovery

import (
	"reflect"
	"testing"

	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/derive"
	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/vault"
)

// Demo-root regression pins; each address was checked against Trust Wallet Core.
func TestRecoverZcashFixtures(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		inputs []vault.FileInput
		want   derive.CoinKey
	}{
		{
			name:   "dkls",
			scheme: "dkls",
			inputs: []vault.FileInput{
				{Name: "TestDKLS1of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS1of2.vult")},
				{Name: "TestDKLS2of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS2of2.vult")},
			},
			want: derive.CoinKey{
				Name:          "zcash",
				DerivePath:    "m/44'/133'/0'/0/0",
				Address:       "t1QPipxS1gZZDmthpUJeSFjcuP4PRmPsFV6",
				HexPrivateKey: "ca3d6900b44538d09124b91a2a1a1ba1599380bcd7bc33b9cee24fee1875dd32",
				HexPublicKey:  "03f8f007a2b4f47785ec86342437cda35e4fa25acbe1c0f5da89c73d80522b6cc0",
				WIFPrivateKey: "L3zqbw6m3WKfmBJVK5Ghjch4Ywzax8FbU7oxMnkBmU1ti14fj74G",
			},
		},
		{
			name:   "gg20",
			scheme: "gg20",
			inputs: []vault.FileInput{
				{Name: "Test-part1of2.vult", Content: readTestFile(t, "../../testdata/Test-part1of2.vult")},
				{Name: "Test-part2of2.vult", Content: readTestFile(t, "../../testdata/Test-part2of2.vult")},
			},
			want: derive.CoinKey{
				Name:          "zcash",
				DerivePath:    "m/44'/133'/0'/0/0",
				Address:       "t1ZiDZcAQMkRPQMEZTkJFAi7oZSJjn73Shb",
				HexPrivateKey: "1f7b701e20b23945e9f38074f4470683cf9d23a9f4b3fc6bc032710304a7dd60",
				HexPublicKey:  "028be64fafe325a3c2a90ee24cc030bd8526454f798325304eba91e6bbd55d2bdc",
				WIFPrivateKey: "KxGudBcqev9VK97cN3uP7q2617XuQZ4pmvSCk2kNJhTj6GmYCkrZ",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Recover(tt.inputs, []string{"", ""}, tt.scheme)
			if err != nil {
				t.Fatalf("recovery failed: %v", err)
			}
			if !result.Success {
				t.Fatalf("expected success, got error: %s", result.Error)
			}

			var got *derive.CoinKey
			for i := range result.ECDSAKeys {
				if result.ECDSAKeys[i].Name == "zcash" {
					got = &result.ECDSAKeys[i]
				}
			}
			if got == nil {
				t.Fatal("zcash key missing from recovery result")
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("zcash key mismatch:\n got %+v\nwant %+v", *got, tt.want)
			}
		})
	}
}
