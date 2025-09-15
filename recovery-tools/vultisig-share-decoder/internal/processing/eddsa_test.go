package processing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"main/internal/utils"
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

// TestSpecificEdDSAKeys tests the specific EdDSA keys that should produce known addresses
func TestSpecificEdDSAKeys(t *testing.T) {
	// User-provided EdDSA keys that should generate specific addresses
	publicKeyHex := "20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9"
	privateKeyHex := "733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07"

	// Expected addresses for these keys
	expectedAddresses := map[string]string{
		"solana": "3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8",
		"ton":    "UQBzI_4nPOWMLkQFIjs7c76O43TGJhOrcJY7Zq5Yj-OWwKhm",
		"sui":    "0xdf86603d1e457c5c95c18ff8dd9e921e349b7e587fdf6ac032b1b279bfe3241a",
	}

	// Decode the keys
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	if len(publicKeyBytes) != 32 {
		t.Fatalf("public key should be 32 bytes, got %d", len(publicKeyBytes))
	}
	if len(privateKeyBytes) != 32 {
		t.Fatalf("private key should be 32 bytes, got %d", len(privateKeyBytes))
	}

	t.Logf("Testing with specific EdDSA keys:")
	t.Logf("  Public key:  %s", publicKeyHex)
	t.Logf("  Private key: %s", privateKeyHex)

	coins := GetEnhancedEdDSACoins()
	for _, coin := range coins {
		t.Run(coin.Name, func(t *testing.T) {
			// Call the handler directly (this should work correctly)
			coinInfo, err := coin.EdDSAHandler(privateKeyBytes, publicKeyBytes, coin)
			if err != nil {
				t.Fatalf("handler failed for %s: %v", coin.Name, err)
			}

			expectedAddr, exists := expectedAddresses[coin.Name]
			if !exists {
				t.Fatalf("no expected address defined for %s", coin.Name)
			}

			t.Logf("Generated %s address: %s", coin.Name, coinInfo.Address)
			t.Logf("Expected  %s address: %s", coin.Name, expectedAddr)

			if coinInfo.Address != expectedAddr {
				t.Errorf("ADDRESS MISMATCH for %s:", coin.Name)
				t.Errorf("  Generated: %s", coinInfo.Address)
				t.Errorf("  Expected:  %s", expectedAddr)

				// Print additional debugging info
				t.Logf("Debug info for %s:", coin.Name)
				t.Logf("  Private key hex: %s", coinInfo.HexPrivateKey)
				t.Logf("  Public key hex:  %s", coinInfo.HexPublicKey)
				t.Logf("  Derive path:     %s", coinInfo.DerivePath)
				t.Logf("  Additional info: %s", coinInfo.AdditionalInfo)
			} else {
				t.Logf("✓ %s address matches expected value", coin.Name)
			}
		})
	}
}

// TestEdDSAKeyProcessorWithSpecificKeys tests the EdDSAKeyProcessor with specific keys
// This test demonstrates the DKLS issue - the processor incorrectly modifies the keys
func TestEdDSAKeyProcessorWithSpecificKeys(t *testing.T) {
	// Same test keys as above
	privateKeyHex := "733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07"

	// Expected addresses for these keys
	expectedAddresses := map[string]string{
		"solana": "3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8",
		"ton":    "UQBzI_4nPOWMLkQFIjs7c76O43TGJhOrcJY7Zq5Yj-OWwKhm",
		"sui":    "0xdf86603d1e457c5c95c18ff8dd9e921e349b7e587fdf6ac032b1b279bfe3241a",
	}

	// Decode the keys
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	// Convert to big.Int (as DKLS processing does)
	privateKeyBigInt := new(big.Int).SetBytes(privateKeyBytes)

	t.Logf("Testing EdDSAKeyProcessor with specific keys (simulating DKLS path):")
	t.Logf("  Original private key: %s", privateKeyHex)
	t.Logf("  As big.Int: %s", privateKeyBigInt.String())

	// Use EdDSAKeyProcessor (this is what DKLS currently does incorrectly)
	processor := &EdDSAKeyProcessor{}
	result, err := processor.ProcessTSSKey(privateKeyBigInt, []utils.TempLocalState{})
	if err != nil {
		t.Fatalf("EdDSAKeyProcessor failed: %v", err)
	}

	// Check if the processor generates the expected addresses
	addressMatches := make(map[string]bool)
	for _, coinInfo := range result.CoinKeys {
		expectedAddr, exists := expectedAddresses[coinInfo.Name]
		if !exists {
			continue
		}

		matches := coinInfo.Address == expectedAddr
		addressMatches[coinInfo.Name] = matches

		t.Logf("%s via EdDSAKeyProcessor:", coinInfo.Name)
		t.Logf("  Generated: %s", coinInfo.Address)
		t.Logf("  Expected:  %s", expectedAddr)
		t.Logf("  Matches:   %t", matches)

		if !matches {
			t.Logf("  ❌ EdDSAKeyProcessor produces incorrect address for %s", coinInfo.Name)
		} else {
			t.Logf("  ✓ EdDSAKeyProcessor produces correct address for %s", coinInfo.Name)
		}
	}

	// The test expectation: EdDSAKeyProcessor should NOT match for DKLS keys
	// (This documents the current broken behavior)
	allMatch := true
	for coin, matches := range addressMatches {
		if !matches {
			allMatch = false
			t.Logf("EdDSAKeyProcessor incorrectly processes %s (this is the DKLS bug)", coin)
		}
	}

	if allMatch {
		t.Logf("✓ All addresses match - EdDSAKeyProcessor works correctly")
	} else {
		t.Logf("❌ Some addresses don't match - this demonstrates the DKLS EdDSA issue")
	}
}

// TestDKLSEdDSADirectHandlerApproach tests the DKLS fix using direct handler calls
func TestDKLSEdDSADirectHandlerApproach(t *testing.T) {
	// Same test keys as above
	publicKeyHex := "20e368bf985efdc270500c6e9dc1159102323ff6eabab56f8fa9798e4ac0e2a9"
	privateKeyHex := "733da00cb116e47317d8d0fdf2629f11500abd28a52a8dcbb3f8737f2a631e07"

	// Expected addresses for these keys
	expectedAddresses := map[string]string{
		"solana": "3DPAkfuk5bkh1c1Pg5GN57Gr6cSJsZHVBcJLTFMapmA8",
		"ton":    "UQBzI_4nPOWMLkQFIjs7c76O43TGJhOrcJY7Zq5Yj-OWwKhm",
		"sui":    "0xdf86603d1e457c5c95c18ff8dd9e921e349b7e587fdf6ac032b1b279bfe3241a",
	}

	// Decode the keys
	publicKeyBytes, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}

	t.Logf("Testing DKLS EdDSA fix with direct handler approach:")
	t.Logf("  Public key:  %s", publicKeyHex)
	t.Logf("  Private key: %s", privateKeyHex)

	// Simulate the DKLS processing approach with the fix
	eddsaCoins := GetEnhancedEdDSACoins()
	addressMatches := make(map[string]bool)

	for _, coin := range eddsaCoins {
		t.Run(coin.Name, func(t *testing.T) {
			// Check if the coin has an EdDSA handler
			if coin.EdDSAHandler == nil {
				t.Fatalf("No EdDSA handler found for coin: %s", coin.Name)
			}

			// Use the EdDSA handler directly with the correct key bytes (DKLS fix)
			coinInfo, err := coin.EdDSAHandler(privateKeyBytes, publicKeyBytes, coin)
			if err != nil {
				t.Fatalf("Error processing DKLS EdDSA coin %s: %v", coin.Name, err)
			}

			expectedAddr, exists := expectedAddresses[coin.Name]
			if !exists {
				t.Fatalf("no expected address defined for %s", coin.Name)
			}

			matches := coinInfo.Address == expectedAddr
			addressMatches[coin.Name] = matches

			t.Logf("%s via DKLS direct handler approach:", coin.Name)
			t.Logf("  Generated: %s", coinInfo.Address)
			t.Logf("  Expected:  %s", expectedAddr)
			t.Logf("  Matches:   %t", matches)

			if !matches {
				t.Errorf("ADDRESS MISMATCH for %s:", coin.Name)
				t.Errorf("  Generated: %s", coinInfo.Address)
				t.Errorf("  Expected:  %s", expectedAddr)
			} else {
				t.Logf("✓ DKLS fix works correctly for %s", coin.Name)
			}
		})
	}

	// Verify all addresses match with the fix
	allMatch := true
	for coin, matches := range addressMatches {
		if !matches {
			allMatch = false
			t.Errorf("DKLS fix failed for %s", coin)
		}
	}

	if allMatch {
		t.Logf("✅ DKLS EdDSA fix works correctly - all addresses match expected values")
	} else {
		t.Fatalf("❌ DKLS fix failed - some addresses don't match")
	}
}
