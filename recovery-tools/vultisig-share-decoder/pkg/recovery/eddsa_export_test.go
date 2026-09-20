//go:build !wasm

package recovery

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/vault"
)

const (
	demoEdDSAPublicKey       = "20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9"
	demoEdDSASolanaAddress   = "3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8"
	demoEdDSACanonicalScalar = "071e632a7f73f8b3cb8d2aa528bd0a50119f62f2fdd0d81773e416b10ca03d73"
)

func demoEdDSAInputs(t *testing.T) []vault.FileInput {
	t.Helper()
	return []vault.FileInput{
		{Name: "TestDKLS1of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS1of2.vult")},
		{Name: "TestDKLS2of2.vult", Content: readTestFile(t, "../../testdata/TestDKLS2of2.vult")},
	}
}

func TestVerifyDemoEdDSAExport(t *testing.T) {
	inputs := demoEdDSAInputs(t)

	v, err := vault.ParseVaultFromFile(inputs[0].Content, inputs[0].Name, "", vault.CommandLine)
	if err != nil {
		t.Fatalf("failed to parse vault file: %v", err)
	}
	if v.PublicKeyEddsa != demoEdDSAPublicKey {
		t.Errorf("vault EdDSA public key %s != demo public key %s", v.PublicKeyEddsa, demoEdDSAPublicKey)
	}

	keyshares, err := extractDKLSKeyshares(inputs, []string{"", ""})
	if err != nil {
		t.Fatalf("failed to extract DKLS keyshares: %v", err)
	}
	exported, err := exportEdDSAKey(keyshares.EdDSAKeyshares, keyshares.PartyIDs)
	if err != nil {
		t.Fatalf("failed to export EdDSA key: %v", err)
	}

	exportPubHex := hex.EncodeToString(exported.PublicKey)
	t.Logf("export public key: %s", exportPubHex)
	if exportPubHex != demoEdDSAPublicKey {
		t.Errorf("export public key %s != demo public key %s", exportPubHex, demoEdDSAPublicKey)
	}

	result, err := Recover(inputs, []string{"", ""}, "dkls")
	if err != nil {
		t.Fatalf("recovery failed: %v", err)
	}

	t.Logf("recovered EdDSA public key: %s", result.PublicKeys.EdDSA)
	if result.PublicKeys.EdDSA != exportPubHex {
		t.Errorf("recovered EdDSA public key %s != export public key %s", result.PublicKeys.EdDSA, exportPubHex)
	}
	if result.RootKeyInfo.HexPubKeyEdDSA != exportPubHex {
		t.Errorf("root key info EdDSA public key %s != export public key %s", result.RootKeyInfo.HexPubKeyEdDSA, exportPubHex)
	}

	var solanaAddr string
	for _, k := range result.EdDSAKeys {
		if k.Name == "solana" {
			solanaAddr = k.Address
		}
	}
	t.Logf("recovered Solana address: %s", solanaAddr)
	if solanaAddr != demoEdDSASolanaAddress {
		t.Errorf("solana address %s != demo address %s", solanaAddr, demoEdDSASolanaAddress)
	}
}

func TestEdDSAKeyFromExportFailsClosed(t *testing.T) {
	inputs := demoEdDSAInputs(t)
	keyshares, err := extractDKLSKeyshares(inputs, []string{"", ""})
	if err != nil {
		t.Fatalf("failed to extract DKLS keyshares: %v", err)
	}
	exported, err := exportEdDSAKey(keyshares.EdDSAKeyshares, keyshares.PartyIDs)
	if err != nil {
		t.Fatalf("failed to export EdDSA key: %v", err)
	}

	privKey, pubKey, err := edDSAKeyFromExport(exported.PrivateKey, demoEdDSAPublicKey)
	if err != nil {
		t.Fatalf("valid export rejected: %v", err)
	}
	if got := hex.EncodeToString(privKey.Serialize()); got != demoEdDSACanonicalScalar {
		t.Errorf("recovered scalar %s != canonical big-endian scalar %s", got, demoEdDSACanonicalScalar)
	}
	if got := hex.EncodeToString(pubKey.Serialize()); got != demoEdDSAPublicKey {
		t.Errorf("derived public key %s != demo public key %s", got, demoEdDSAPublicKey)
	}

	if _, _, err := edDSAKeyFromExport(exported.PrivateKey, "ff"+demoEdDSAPublicKey[2:]); err == nil {
		t.Error("expected mismatched public key to be rejected")
	}
	if _, _, err := edDSAKeyFromExport(exported.PrivateKey[:edwards.PrivScalarSize-1], demoEdDSAPublicKey); err == nil {
		t.Errorf("expected %d-byte secret to be rejected", edwards.PrivScalarSize-1)
	}
	if _, _, err := edDSAKeyFromExport(make([]byte, edwards.PrivScalarSize), demoEdDSAPublicKey); err == nil {
		t.Error("expected zero scalar to be rejected")
	}
}

func TestEdDSACanonicalScalarPad(t *testing.T) {
	scalar, err := hex.DecodeString(demoEdDSACanonicalScalar)
	if err != nil {
		t.Fatalf("failed to decode demo scalar: %v", err)
	}

	short := scalar[1:] // big.Int.Bytes() drops the leading zero byte
	padded := make([]byte, edwards.PrivScalarSize)
	copy(padded[edwards.PrivScalarSize-len(short):], short)

	shortPriv, shortPub, err := edDSAKeyFromScalar(short, "")
	if err != nil {
		t.Fatalf("short scalar rejected: %v", err)
	}
	paddedPriv, paddedPub, err := edDSAKeyFromScalar(padded, "")
	if err != nil {
		t.Fatalf("padded scalar rejected: %v", err)
	}

	if got, want := hex.EncodeToString(shortPriv.Serialize()), hex.EncodeToString(paddedPriv.Serialize()); got != want {
		t.Errorf("short scalar private key %s != padded private key %s", got, want)
	}
	if got, want := hex.EncodeToString(shortPub.Serialize()), hex.EncodeToString(paddedPub.Serialize()); got != want {
		t.Errorf("short scalar public key %s != padded public key %s", got, want)
	}

	if _, _, err := edDSAKeyFromScalar(make([]byte, edwards.PrivScalarSize), demoEdDSAPublicKey); err == nil {
		t.Error("expected zero scalar to be rejected")
	}
	if _, _, err := edDSAKeyFromScalar(padded, "ff"+demoEdDSAPublicKey[2:]); err == nil {
		t.Error("expected wrong expected public key to be rejected")
	}
}
