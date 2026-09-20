package recovery

import (
	"reflect"
	"testing"

	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/derive"
	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/vault"
)

// Demo-root regression pins. Encoding oracle is the Dash Core vector in pkg/derive.
// Same construction as src/derive.js (P2PKH 0x4c, compressed WIF 0xcc); JS was not executed.
func TestRecoverDashFixtures(t *testing.T) {
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
				Name:          "dash",
				DerivePath:    "m/44'/5'/0'/0/0",
				Address:       "XrVAxS1Q6fZ8mxAB5wPwRdQgyk5Wv18VNz",
				HexPrivateKey: "a051fbff3fc8c8b4b06b400eaf24fde2c2b1c3b584fcc220ec548b8618f91d74",
				HexPublicKey:  "029a2a0f6cf0b4a297ea058b9490393375e419eec82757540010057c00cd6b076d",
				WIFPrivateKey: "XGfGrL5dnyEg4rt52ftUTnvFSDhiXiBHNuvGcAwvkhXqmxh7H6FN",
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
				Name:          "dash",
				DerivePath:    "m/44'/5'/0'/0/0",
				Address:       "XkoQBncrZgAmHSYYhkjZqMF7NhPTBhbWbC",
				HexPrivateKey: "2d522a79b70b06f5ac41a1fd22f0eed9866b236fc63942895d486b4a3d2d8c3d",
				HexPublicKey:  "03e7bab1197c1bbc276af737f95932d57dfe26ac4d9af5b5bf9496235cb367bcc2",
				WIFPrivateKey: "XCojKgPwHDkw4d7KL4pYirAjjTmy4UrHGMuLW4LCxmEXo3hEK1mS",
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
				if result.ECDSAKeys[i].Name == "dash" {
					got = &result.ECDSAKeys[i]
				}
			}
			if got == nil {
				t.Fatal("dash key missing from recovery result")
			}
			if !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("dash key mismatch:\n got %+v\nwant %+v", *got, tt.want)
			}
		})
	}
}
