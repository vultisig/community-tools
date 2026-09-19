package derive

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// Fixture from Dash Core src/test/key_tests.cpp (compressed key strSecret1C/addr1C).
func TestDeriveDashVector(t *testing.T) {
	privKey, _ := hex.DecodeString("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")
	pubKey, _ := hex.DecodeString("030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744")

	if got := secp256k1.PrivKeyFromBytes(privKey).PubKey().SerializeCompressed(); !bytes.Equal(got, pubKey) {
		t.Fatalf("fixture pubkey does not match privkey: got %x, want %x", got, pubKey)
	}

	key, err := deriveDash(privKey, pubKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.Address != "XxV9h4Xmv6Pup8tVAQmH97K6grzvDwMG9F" {
		t.Errorf("dash address mismatch: %s", key.Address)
	}
	if key.WIFPrivateKey != "XBuxZHH6TqXUuaSjbVTFR1DQSYecxCB9QA1Koyx5tTc3ddhqEnhm" {
		t.Errorf("dash WIF mismatch: %s", key.WIFPrivateKey)
	}
	if key.HexPrivateKey != "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747" {
		t.Errorf("dash hex private key mismatch: %s", key.HexPrivateKey)
	}
	if key.HexPublicKey != "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744" {
		t.Errorf("dash hex public key mismatch: %s", key.HexPublicKey)
	}
}

func TestDeriveECDSACoinsIncludesDash(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601")
	chainCodeBytes, _ := hex.DecodeString("e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac")

	keys, err := DeriveECDSACoins(privKeyBytes, chainCodeBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, k := range keys {
		if k.Name != "dash" {
			continue
		}
		if k.DerivePath != "m/44'/5'/0'/0/0" {
			t.Errorf("dash derive path mismatch: %s", k.DerivePath)
		}
		// Browser-parity pin for the demo-root fixture; the encoding oracle is the Dash Core vector above.
		if k.Address != "XrVAxS1Q6fZ8mxAB5wPwRdQgyk5Wv18VNz" {
			t.Errorf("dash address mismatch: %s", k.Address)
		}
		if k.WIFPrivateKey != "XGfGrL5dnyEg4rt52ftUTnvFSDhiXiBHNuvGcAwvkhXqmxh7H6FN" {
			t.Errorf("dash WIF mismatch: %s", k.WIFPrivateKey)
		}
		return
	}
	t.Fatal("missing coin: dash")
}
