package derive

import (
	"encoding/hex"
	"testing"
)

// Encoding oracle: Trust Wallet Core AnyAddress(zcash) for this pubkey, and an
// independent base58check of 0x80||priv||0x01 for the WIF. Key from Dash Core key_tests.cpp.
func TestDeriveZcashVector(t *testing.T) {
	privKey, _ := hex.DecodeString("12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747")
	pubKey, _ := hex.DecodeString("030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744")

	key, err := deriveZcash(privKey, pubKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if key.Address != "t1ffus9J1vhxvFqLoExGBRPjE7BcJxiSCTC" {
		t.Errorf("zcash address mismatch: %s", key.Address)
	}
	if key.WIFPrivateKey != "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw" {
		t.Errorf("zcash WIF mismatch: %s", key.WIFPrivateKey)
	}
	if key.HexPrivateKey != "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747" {
		t.Errorf("zcash hex private key mismatch: %s", key.HexPrivateKey)
	}
	if key.HexPublicKey != "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744" {
		t.Errorf("zcash hex public key mismatch: %s", key.HexPublicKey)
	}
}

func TestDeriveECDSACoinsIncludesZcash(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601")
	chainCodeBytes, _ := hex.DecodeString("e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac")

	keys, err := DeriveECDSACoins(privKeyBytes, chainCodeBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, k := range keys {
		if k.Name != "zcash" {
			continue
		}
		// Path from Trust Wallet Core CoinTypeExt.derivationPath(zcash), which the apps use.
		if k.DerivePath != "m/44'/133'/0'/0/0" {
			t.Errorf("zcash derive path mismatch: %s", k.DerivePath)
		}
		// Browser-parity pin (src/derive.test.js); address checked against Trust Wallet Core.
		if k.Address != "t1QPipxS1gZZDmthpUJeSFjcuP4PRmPsFV6" {
			t.Errorf("zcash address mismatch: %s", k.Address)
		}
		if k.WIFPrivateKey != "L3zqbw6m3WKfmBJVK5Ghjch4Ywzax8FbU7oxMnkBmU1ti14fj74G" {
			t.Errorf("zcash WIF mismatch: %s", k.WIFPrivateKey)
		}
		return
	}
	t.Fatal("missing coin: zcash")
}
