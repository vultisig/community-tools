package processing

import (
	"encoding/json"
	"io/ioutil"
	"path/filepath"
	"testing"

	"main/internal/utils"
)

// TestGG20Integration tests the complete GG20 processing pipeline using example files
func TestGG20Integration(t *testing.T) {
	// Expected results from the user
	expectedResults := struct {
		BitcoinAddress       string
		EthereumAddress     string
		ECDSAPublicKey      string
		EdDSAPublicKey      string
		ExtendedPrivateKey  string
	}{
		BitcoinAddress:      "bc1qvn203p8pp30fk945eywrjey937qpaanha8hc4r",
		EthereumAddress:     "0x55a7Ea16A40f8c908CbC935D229eBe4C6658e90D",
		ECDSAPublicKey:      "0267db81657a956f364167c3986a426b448a74ac0db2092f6665c4c202b37f6f1d",
		EdDSAPublicKey:      "c6da2ad7b18728f6481d747a7335fd52a5eed82f3c3d95a51deed03399c5c0b6",
		ExtendedPrivateKey:  "xprv9s21ZrQH143K4TfFdqRZMZ6KMdtE1qCYw8rQfHg2qezThKeEja525YECWLLaMb1aSYTV1aWfeSB87vXGi2LQC6Gf7oEUMLU5R2aKQ99ifMQ",
	}

	t.Run("ProcessGG20ExampleFiles", func(t *testing.T) {
		// Read example files from disk
		file1Path := filepath.Join("..", "..", "examples", "GG20_1of2.vult")
		file2Path := filepath.Join("..", "..", "examples", "GG20_2of2.vult")

		file1Data, err := ioutil.ReadFile(file1Path)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", file1Path, err)
		}

		file2Data, err := ioutil.ReadFile(file2Path)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", file2Path, err)
		}

		// Create FileInfo objects
		fileInfos := []utils.FileInfo{
			{
				Name:    "GG20_1of2.vult",
				Content: file1Data,
			},
			{
				Name:    "GG20_2of2.vult",
				Content: file2Data,
			},
		}

		// Process files with empty passwords (example files are unencrypted)
		passwords := []string{"", ""}

		// Call the processing function directly
		result, err := ProcessFileContentJSON(fileInfos, passwords, utils.Web)
		if err != nil {
			t.Fatalf("ProcessFileContentJSON failed: %v", err)
		}

		// Validate the result structure
		if !result.Success {
			t.Fatalf("Processing failed: %s", result.Error)
		}

		t.Logf("✅ Processing successful - found %d coin keys", len(result.CoinKeys))

		// Validate public keys
		if result.PublicKeys.ECDSA != expectedResults.ECDSAPublicKey {
			t.Errorf("ECDSA public key mismatch:\nExpected: %s\nGot:      %s", 
				expectedResults.ECDSAPublicKey, result.PublicKeys.ECDSA)
		} else {
			t.Logf("✅ ECDSA public key matches: %s", result.PublicKeys.ECDSA)
		}

		if result.PublicKeys.EdDSA != expectedResults.EdDSAPublicKey {
			t.Errorf("EdDSA public key mismatch:\nExpected: %s\nGot:      %s", 
				expectedResults.EdDSAPublicKey, result.PublicKeys.EdDSA)
		} else {
			t.Logf("✅ EdDSA public key matches: %s", result.PublicKeys.EdDSA)
		}

		// Validate root key info
		if result.RootKeyInfo == nil {
			t.Fatalf("RootKeyInfo is nil")
		}

		if result.RootKeyInfo.ExtendedPrivKey != expectedResults.ExtendedPrivateKey {
			t.Errorf("Extended private key mismatch:\nExpected: %s\nGot:      %s", 
				expectedResults.ExtendedPrivateKey, result.RootKeyInfo.ExtendedPrivKey)
		} else {
			t.Logf("✅ Extended private key matches")
		}

		// Find and validate Bitcoin address
		bitcoinFound := false
		for _, coinKey := range result.CoinKeys {
			if coinKey.Name == "bitcoin" {
				bitcoinFound = true
				if coinKey.Address != expectedResults.BitcoinAddress {
					t.Errorf("Bitcoin address mismatch:\nExpected: %s\nGot:      %s", 
						expectedResults.BitcoinAddress, coinKey.Address)
				} else {
					t.Logf("✅ Bitcoin address matches: %s", coinKey.Address)
				}
				break
			}
		}
		if !bitcoinFound {
			t.Error("Bitcoin coin key not found in results")
		}

		// Find and validate Ethereum address
		ethereumFound := false
		for _, coinKey := range result.CoinKeys {
			if coinKey.Name == "ethereum" {
				ethereumFound = true
				if coinKey.Address != expectedResults.EthereumAddress {
					t.Errorf("Ethereum address mismatch:\nExpected: %s\nGot:      %s", 
						expectedResults.EthereumAddress, coinKey.Address)
				} else {
					t.Logf("✅ Ethereum address matches: %s", coinKey.Address)
				}
				break
			}
		}
		if !ethereumFound {
			t.Error("Ethereum coin key not found in results")
		}

		// Validate that we have both ECDSA and EdDSA coins
		ecdsaCoins := 0
		eddsaCoins := 0
		for _, coinKey := range result.CoinKeys {
			// ECDSA coins: Bitcoin, Ethereum, Cosmos chains, etc.
			if isECDSACoin(coinKey.Name) {
				ecdsaCoins++
			}
			// EdDSA coins: Solana, Sui, TON
			if isEdDSACoin(coinKey.Name) {
				eddsaCoins++
			}
		}

		if ecdsaCoins == 0 {
			t.Error("No ECDSA coins found in results")
		} else {
			t.Logf("✅ Found %d ECDSA coins", ecdsaCoins)
		}

		if eddsaCoins == 0 {
			t.Error("No EdDSA coins found in results")
		} else {
			t.Logf("✅ Found %d EdDSA coins", eddsaCoins)
		}

		// Log all generated coins for verification
		t.Logf("📋 Complete coin list (%d total):", len(result.CoinKeys))
		for _, coinKey := range result.CoinKeys {
			t.Logf("   %s: %s", coinKey.Name, coinKey.Address)
		}
	})
}

// TestGG20JSONOutput tests that the JSON output is properly structured
func TestGG20JSONOutput(t *testing.T) {
	// Read example files
	file1Path := filepath.Join("..", "..", "examples", "GG20_1of2.vult")
	file2Path := filepath.Join("..", "..", "examples", "GG20_2of2.vult")

	file1Data, err := ioutil.ReadFile(file1Path)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", file1Path, err)
	}

	file2Data, err := ioutil.ReadFile(file2Path)
	if err != nil {
		t.Fatalf("Failed to read %s: %v", file2Path, err)
	}

	fileInfos := []utils.FileInfo{
		{Name: "GG20_1of2.vult", Content: file1Data},
		{Name: "GG20_2of2.vult", Content: file2Data},
	}

	// Process and convert to JSON
	result, err := ProcessFileContentJSON(fileInfos, []string{"", ""}, utils.Web)
	if err != nil {
		t.Fatalf("ProcessFileContentJSON failed: %v", err)
	}

	// Convert to JSON and back to validate structure
	jsonData, err := ToJSON(result)
	if err != nil {
		t.Fatalf("Failed to convert result to JSON: %v", err)
	}

	// Parse JSON back to ensure it's valid
	var parsedResult ProcessResult
	err = json.Unmarshal([]byte(jsonData), &parsedResult)
	if err != nil {
		t.Fatalf("Failed to parse JSON result: %v", err)
	}

	// Validate JSON structure
	if !parsedResult.Success {
		t.Fatalf("Parsed result shows failure: %s", parsedResult.Error)
	}

	if len(parsedResult.CoinKeys) == 0 {
		t.Error("No coin keys in parsed JSON result")
	}

	if parsedResult.PublicKeys.ECDSA == "" {
		t.Error("ECDSA public key missing in JSON result")
	}

	if parsedResult.PublicKeys.EdDSA == "" {
		t.Error("EdDSA public key missing in JSON result")
	}

	t.Logf("✅ JSON output structure is valid with %d coins", len(parsedResult.CoinKeys))
}

// Helper functions to categorize coins
func isECDSACoin(name string) bool {
	ecdsaCoins := map[string]bool{
		"bitcoin": true, "bitcoinCash": true, "dogecoin": true, "litecoin": true, "dash": true, "zcash": true,
		"ethereum": true, "tron": true,
		"thorchain": true, "mayachain": true, "atom": true, "kujira": true, "dydx": true, "terra-classic": true, "terra": true,
	}
	return ecdsaCoins[name]
}

func isEdDSACoin(name string) bool {
	eddsaCoins := map[string]bool{
		"solana": true, "sui": true, "ton": true,
	}
	return eddsaCoins[name]
}