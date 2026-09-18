package derive

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// xrpl.js ripple-keypairs fixtures — upstream TEST keys only:
// https://raw.githubusercontent.com/XRPLF/xrpl.js/main/packages/ripple-keypairs/test/fixtures/api.json
const (
	XRP_FIXTURE_PRIV = "d78b9735c3f26501c7337b8a5727fd53a6efdbc6aa55984f098488561f985e23"
	XRP_FIXTURE_PUB  = "030d58eb48b4420b1f7b9df55087e0e29fef0e8468f9a6825b01ca2c361042d435"
	XRP_FIXTURE_ADDR = "rU6K7V3Po4snVhBBaU29sesqs2qTQJWDw1"

	LEADING_ZERO_PRIV = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	LEADING_ZERO_PUB  = "036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2"
	LEADING_ZERO_ADDR = "raZbRYVpCr44u4Q9EDYy7MUpdrcjGSpGsL"
)

func TestDeriveRippleVector(t *testing.T) {
	tests := []struct {
		name string
		priv string
		pub  string
		addr string
	}{
		{"xrpl.js fixture", XRP_FIXTURE_PRIV, XRP_FIXTURE_PUB, XRP_FIXTURE_ADDR},
		{"leading zero private key", LEADING_ZERO_PRIV, LEADING_ZERO_PUB, LEADING_ZERO_ADDR},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey := mustDecodeHex(t, tt.priv)
			pubKey := mustDecodeHex(t, tt.pub)
			computed := secp256k1.PrivKeyFromBytes(privKey).PubKey().SerializeCompressed()
			if hex.EncodeToString(computed) != tt.pub {
				t.Fatalf("public key %s does not match private key, got %s", tt.pub, hex.EncodeToString(computed))
			}

			key, err := deriveRipple(privKey, pubKey)
			if err != nil {
				t.Fatalf("deriveRipple failed: %v", err)
			}
			if key.Address != tt.addr {
				t.Errorf("address = %s, want %s", key.Address, tt.addr)
			}
			if key.HexPrivateKey != tt.priv {
				t.Errorf("private key = %s, want %s", key.HexPrivateKey, tt.priv)
			}
			if key.HexPublicKey != tt.pub {
				t.Errorf("public key = %s, want %s", key.HexPublicKey, tt.pub)
			}
			if key.WIFPrivateKey != "" {
				t.Errorf("ripple must not carry a WIF, got %s", key.WIFPrivateKey)
			}
		})
	}
}

func TestDeriveECDSACoinsIncludesRipple(t *testing.T) {
	privKeyBytes := mustDecodeHex(t, "0806a352d32950671e711225514a5fd53d6411dc9f4525d7bad11ef73956c601")
	chainCodeBytes := mustDecodeHex(t, "e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac")

	keys, err := DeriveECDSACoins(privKeyBytes, chainCodeBytes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var ripple []CoinKey
	for _, k := range keys {
		if k.Name == "ripple" {
			ripple = append(ripple, k)
		}
	}
	if len(ripple) != 1 {
		t.Fatalf("expected exactly one ripple key among %d coins, got %d", len(keys), len(ripple))
	}

	if ripple[0].DerivePath != "m/44'/144'/0'/0/0" {
		t.Errorf("ripple path mismatch: %s", ripple[0].DerivePath)
	}
	// Browser parity literal (src/derive.js deriveECDSACoins on the same demo root).
	if ripple[0].Address != "rDLY568PwDwGGzi7qVRg1KVPj7AV2qsCCt" {
		t.Errorf("ripple address mismatch: %s", ripple[0].Address)
	}
	if ripple[0].WIFPrivateKey != "" {
		t.Errorf("ripple must not carry a WIF, got %s", ripple[0].WIFPrivateKey)
	}
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", value, err)
	}
	return decoded
}
