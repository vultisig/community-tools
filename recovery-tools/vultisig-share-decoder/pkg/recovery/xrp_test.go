package recovery

import (
	"reflect"
	"testing"

	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/derive"
	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/vault"
)

// Expected keys are browser parity literals (src/derive.js deriveECDSACoins on the same public
// demo roots), not an independent oracle.
func TestRecoverXRPFixtures(t *testing.T) {
	tests := []struct {
		name   string
		files  []string
		scheme string
		want   derive.CoinKey
	}{
		{
			"dkls two share",
			[]string{"TestDKLS1of2.vult", "TestDKLS2of2.vult"},
			"dkls",
			derive.CoinKey{
				Name:          "ripple",
				DerivePath:    "m/44'/144'/0'/0/0",
				Address:       "rDLY568PwDwGGzi7qVRg1KVPj7AV2qsCCt",
				HexPrivateKey: "094ea5c1ca3362304f6df9eb7da54b7d5f3c03b2ab304949cb815c7afe51f90a",
				HexPublicKey:  "029985020e3121b41657ac3126abb0d4c7c915eab9260f1503ed2647876d11449d",
			},
		},
		{
			"gg20 two share",
			[]string{"Test-part1of2.vult", "Test-part2of2.vult"},
			"gg20",
			derive.CoinKey{
				Name:          "ripple",
				DerivePath:    "m/44'/144'/0'/0/0",
				Address:       "rGTGquwCY7NbSAtso48uwbKYSnGfxCfnqd",
				HexPrivateKey: "b01bfcc40b6b98b87bce2876b7c9084e68059db815ad6d6e1a5d8e1a3f818d99",
				HexPublicKey:  "02a9186a54898b0ceb37b7bf45a71f23fb5036d1fe73eb24cde806d342dcc3de9d",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := make([]vault.FileInput, 0, len(tt.files))
			for _, name := range tt.files {
				inputs = append(inputs, vault.FileInput{Name: name, Content: readTestFile(t, "../../testdata/"+name)})
			}

			result, err := Recover(inputs, []string{"", ""}, tt.scheme)
			if err != nil {
				t.Fatalf("recovery failed: %v", err)
			}
			if !result.Success {
				t.Fatalf("expected success, got error: %s", result.Error)
			}

			var ripple []derive.CoinKey
			for _, k := range result.ECDSAKeys {
				if k.Name == "ripple" {
					ripple = append(ripple, k)
				}
			}
			if len(ripple) != 1 {
				t.Fatalf("expected exactly one ripple key, got %d", len(ripple))
			}
			// The full struct compare also pins WIFPrivateKey to empty.
			if !reflect.DeepEqual(ripple[0], tt.want) {
				t.Errorf("ripple key mismatch:\n got %+v\nwant %+v", ripple[0], tt.want)
			}
		})
	}
}
