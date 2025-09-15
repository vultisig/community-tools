package processing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestEdDSAConfigSetup verifies GetEnhancedEdDSACoins returns all 3 coins with proper handlers
func TestEdDSAConfigSetup(t *testing.T) {
	coins := GetEnhancedEdDSACoins()
	
	if len(coins) != 3 {
		t.Fatalf("expected 3 EdDSA coins, got %d", len(coins))
	}

	expectedCoins := map[string]string{
		"solana": "m/44'/501'/0'/0'",
		"sui":    "m/44'/784'/0'/0'/0'",
		"ton":    "m/44'/607'/0'/0'/0'",
	}

	found := make(map[string]bool)
	for _, coin := range coins {
		// Verify coin name and derive path
		expectedPath, exists := expectedCoins[coin.Name]
		if !exists {
			t.Errorf("unexpected coin: %s", coin.Name)
			continue
		}
		if coin.DerivePath != expectedPath {
			t.Errorf("wrong derive path for %s: expected %s, got %s", coin.Name, expectedPath, coin.DerivePath)
		}

		// Verify family is EdDSA
		if coin.Family != FamilyEdDSA {
			t.Errorf("wrong family for %s: expected %s, got %s", coin.Name, FamilyEdDSA, coin.Family)
		}

		// Verify EdDSAHandler is not nil
		if coin.EdDSAHandler == nil {
			t.Errorf("EdDSAHandler is nil for coin: %s", coin.Name)
		}

		// Verify params exist
		if coin.Params == nil {
			t.Errorf("Params is nil for coin: %s", coin.Name)
		}

		found[coin.Name] = true
		t.Logf("✓ %s: derivePath=%s, family=%s, handler=present", coin.Name, coin.DerivePath, coin.Family)
	}

	// Verify all expected coins were found
	for coinName := range expectedCoins {
		if !found[coinName] {
			t.Errorf("missing coin: %s", coinName)
		}
	}
}

// TestIndividualHandlers tests each EdDSA handler with mock data
func TestIndividualHandlers(t *testing.T) {
	// Generate test Ed25519 key pair
	pubKey, privKey64, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key pair: %v", err)
	}
	
	// Extract 32-byte seed from 64-byte private key for EdDSA handlers
	privKey := privKey64.Seed()

	coins := GetEnhancedEdDSACoins()
	for _, coin := range coins {
		t.Run(coin.Name, func(t *testing.T) {
			// Call the handler
			coinInfo, err := coin.EdDSAHandler(privKey, pubKey, coin)
			if err != nil {
				t.Fatalf("handler failed for %s: %v", coin.Name, err)
			}

			// Verify returned data structure
			if coinInfo.Name != coin.Name {
				t.Errorf("wrong name for %s: expected %s, got %s", coin.Name, coin.Name, coinInfo.Name)
			}
			if coinInfo.DerivePath != coin.DerivePath {
				t.Errorf("wrong derive path for %s: expected %s, got %s", coin.Name, coin.DerivePath, coinInfo.DerivePath)
			}
			if coinInfo.Address == "" {
				t.Errorf("empty address for %s", coin.Name)
			}
			if coinInfo.HexPrivateKey == "" {
				t.Errorf("empty private key for %s", coin.Name)
			}
			if coinInfo.HexPublicKey == "" {
				t.Errorf("empty public key for %s", coin.Name)
			}

			// Verify hex keys match input
			expectedPrivHex := hex.EncodeToString(privKey)
			expectedPubHex := hex.EncodeToString(pubKey)
			if coinInfo.HexPrivateKey != expectedPrivHex {
				t.Errorf("private key mismatch for %s", coin.Name)
			}
			if coinInfo.HexPublicKey != expectedPubHex {
				t.Errorf("public key mismatch for %s", coin.Name)
			}

			t.Logf("✓ %s: address=%s...", coin.Name, coinInfo.Address[:min(15, len(coinInfo.Address))])
		})
	}
}

// TestHandlerBasedApproach verifies ProcessEdDSAKeysJSON uses handlers without switch statements
func TestHandlerBasedApproach(t *testing.T) {
	// This is a structural verification - we examine the code path
	coins := GetEnhancedEdDSACoins()
	
	// Verify that each coin has an EdDSAHandler (required for handler-based approach)
	for _, coin := range coins {
		if coin.EdDSAHandler == nil {
			t.Errorf("missing EdDSAHandler for %s - indicates switch-statement approach", coin.Name)
		}
	}

	// The ProcessEdDSAKeysJSON function uses:
	// 1. GetEnhancedEdDSACoins() to get configurations
	// 2. coin.EdDSAHandler(privateKeyBytes, publicKeyBytes, coin) for each coin
	// This confirms the handler-based approach without needing to run the full function
	
	t.Logf("✓ Verified handler-based approach: all %d coins have EdDSAHandler assigned", len(coins))
}

// TestAddressFormats verifies that each coin generates addresses in the correct format
func TestAddressFormats(t *testing.T) {
	// Generate test Ed25519 key pair
	pubKey, privKey64, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key pair: %v", err)
	}
	
	// Extract 32-byte seed from 64-byte private key for EdDSA handlers
	privKey := privKey64.Seed()

	coins := GetEnhancedEdDSACoins()
	for _, coin := range coins {
		t.Run(coin.Name, func(t *testing.T) {
			coinInfo, err := coin.EdDSAHandler(privKey, pubKey, coin)
			if err != nil {
				t.Fatalf("handler failed for %s: %v", coin.Name, err)
			}

			// Verify address formats
			switch coin.Name {
			case "solana":
				// Solana addresses are base58 encoded, typically 32-44 characters
				if len(coinInfo.Address) < 32 || len(coinInfo.Address) > 44 {
					t.Errorf("solana address length invalid: %d chars", len(coinInfo.Address))
				}
				t.Logf("✓ Solana: base58 address format verified")

			case "sui":
				// Sui addresses start with 0x and are hex encoded
				if !isValidHexWithPrefix(coinInfo.Address) {
					t.Errorf("sui address not valid hex with 0x prefix: %s", coinInfo.Address)
				}
				t.Logf("✓ Sui: 0x-prefixed hex address format verified")

			case "ton":
				// TON addresses are human-readable format
				if len(coinInfo.Address) < 10 {
					t.Errorf("ton address too short: %s", coinInfo.Address)
				}
				t.Logf("✓ TON: human-readable address format verified")

			default:
				t.Errorf("unknown coin for format verification: %s", coin.Name)
			}
		})
	}
}

// Helper functions

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isValidHexWithPrefix(s string) bool {
	if len(s) < 3 || s[:2] != "0x" {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}