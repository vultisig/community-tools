package recovery

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/edwards/v2"
)

// edDSAKeyFromScalar takes a big-endian Ed25519 scalar of up to 32 bytes, as produced by
// reduceEdDSAScalar or by big.Int.Bytes() (which drops leading zero bytes), and rebuilds
// the key pair. When expectedPubHex is set the derived public key must match it.
func edDSAKeyFromScalar(scalar []byte, expectedPubHex string) (*edwards.PrivateKey, *edwards.PublicKey, error) {
	if len(scalar) > edwards.PrivScalarSize {
		return nil, nil, fmt.Errorf("EdDSA scalar is %d bytes, want at most %d", len(scalar), edwards.PrivScalarSize)
	}

	padded := make([]byte, edwards.PrivScalarSize)
	copy(padded[edwards.PrivScalarSize-len(scalar):], scalar)

	if new(big.Int).SetBytes(padded).Sign() == 0 {
		return nil, nil, fmt.Errorf("EdDSA scalar is zero")
	}

	privKey, pubKey, err := edwards.PrivKeyFromScalar(padded)
	if err != nil {
		return nil, nil, fmt.Errorf("EdDSA scalar is invalid: %w", err)
	}

	if expectedPubHex == "" {
		return privKey, pubKey, nil
	}

	pubHex := hex.EncodeToString(pubKey.Serialize())
	expected, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(expectedPubHex, "0x"), "0X"))
	if err != nil {
		return nil, nil, fmt.Errorf("vault EdDSA public key %q is not hex: %w", expectedPubHex, err)
	}
	if !bytes.Equal(pubKey.Serialize(), expected) {
		return nil, nil, fmt.Errorf("recovered EdDSA public key %s does not match vault public key %s", pubHex, expectedPubHex)
	}

	return privKey, pubKey, nil
}

// resolveEdDSAPublicKey returns the EdDSA public key all vault files agree on, ignoring
// empty entries. Disagreeing files are mixed vaults, so no key can be trusted.
func resolveEdDSAPublicKey(pubs []string) (string, error) {
	resolved := ""
	for _, pub := range pubs {
		if pub == "" {
			continue
		}
		if resolved == "" {
			resolved = pub
			continue
		}
		if resolved != pub {
			return "", fmt.Errorf("vault EdDSA public key %s does not match %s in another share file", resolved, pub)
		}
	}
	return resolved, nil
}
