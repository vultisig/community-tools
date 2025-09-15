package processing

import (
        "testing"

        "github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// Test data provided by the user - same private key for all tests
const testPrivKeyHex = "1bbfb2b193244ec30a4ec90401808675569c9a8eec76f69dbe9451c3504298fc"

// setupTestKeyPair creates the test key pair and extended key for testing using proper BIP44 derivation
func setupTestKeyPair(t *testing.T, derivePath string) (*ECKeyPair, *hdkeychain.ExtendedKey) {
        // Use the actual root extended private key provided by user
        rootExtendedKey, err := hdkeychain.NewKeyFromString("xprv9s21ZrQH143K4TfFdqRZMZ6KMdtE1qCYw8rQfHg2qezThKeEja525YECWLLaMb1aSYTV1aWfeSB87vXGi2LQC6Gf7oEUMLU5R2aKQ99ifMQ")
        if err != nil {
                t.Fatalf("failed to create root extended key: %v", err)
        }

        // Derive the specific key for this coin using the BIP44 path
        derivedKey, err := GetDerivedPrivateKeys(derivePath, rootExtendedKey)
        if err != nil {
                t.Fatalf("failed to derive key for path %s: %v", derivePath, err)
        }

        // Extract the key pair from the derived key
        keyPair, err := ExtractECKeys(derivedKey)
        if err != nil {
                t.Fatalf("failed to extract keys: %v", err)
        }

        return keyPair, derivedKey
}

// TestBitcoinAddressGeneration tests Bitcoin address generation
func TestBitcoinAddressGeneration(t *testing.T) {
        expectedAddress := "bc1qvn203p8pp30fk945eywrjey937qpaanha8hc4r"
        
        keyPair, extendedKey := setupTestKeyPair(t, "m/84'/0'/0'/0/0")

        config := EnhancedCoinConfig{
                Name:       "bitcoin",
                DerivePath: "m/84'/0'/0'/0/0",
                Family:     FamilyUTXO,
                Params: CoinParams{
                        "addressType": "p2wpkh",
                        "network":     "mainnet",
                        "compressed":  true,
                },
                Handler: UTXOHandler,
        }

        builder := InitializeCoinBuilder(config, extendedKey, keyPair)
        builder.SetNetworkParams("mainnet")

        result, err := processBitcoin(builder, keyPair)
        if err != nil {
                t.Fatalf("processBitcoin failed: %v", err)
        }

        if result.Address != expectedAddress {
                t.Errorf("Bitcoin address mismatch:\nExpected: %s\nGot:      %s", expectedAddress, result.Address)
        }

        // Verify other fields
        if result.Name != "bitcoin" {
                t.Errorf("Expected name to be 'bitcoin', got '%s'", result.Name)
        }
        if result.WIFPrivateKey == "" {
                t.Error("WIF private key should not be empty")
        }
        if result.HexPrivateKey == "" {
                t.Error("Hex private key should not be empty")
        }

        t.Logf("✓ Bitcoin test passed - Address: %s", result.Address)
}

// TestDogecoinAddressGeneration tests Dogecoin address generation
func TestDogecoinAddressGeneration(t *testing.T) {
        expectedAddress := "DBMQ8aectXEd264wa7UoHT8YsghnXoxyrC"
        
        keyPair, extendedKey := setupTestKeyPair(t, "m/44'/3'/0'/0/0")

        config := EnhancedCoinConfig{
                Name:       "dogecoin",
                DerivePath: "m/44'/3'/0'/0/0",
                Family:     FamilyUTXO,
                Params: CoinParams{
                        "addressType": "p2pkh",
                        "network":     "mainnet",
                        "compressed":  true,
                },
                Handler: UTXOHandler,
        }

        builder := InitializeCoinBuilder(config, extendedKey, keyPair)
        builder.SetNetworkParams("mainnet")

        result, err := processDogecoin(builder, keyPair)
        if err != nil {
                t.Fatalf("processDogecoin failed: %v", err)
        }

        if result.Address != expectedAddress {
                t.Errorf("Dogecoin address mismatch:\nExpected: %s\nGot:      %s", expectedAddress, result.Address)
        }

        // Verify other fields
        if result.Name != "dogecoin" {
                t.Errorf("Expected name to be 'dogecoin', got '%s'", result.Name)
        }
        if result.WIFPrivateKey == "" {
                t.Error("WIF private key should not be empty")
        }
        if result.HexPrivateKey == "" {
                t.Error("Hex private key should not be empty")
        }

        t.Logf("✓ Dogecoin test passed - Address: %s", result.Address)
}

// TestLitecoinAddressGeneration tests Litecoin address generation
func TestLitecoinAddressGeneration(t *testing.T) {
        expectedAddress := "ltc1qkgguledp08hpmcqsccxvwgr7xvhj7422qyz0l7"
        
        keyPair, extendedKey := setupTestKeyPair(t, "m/84'/2'/0'/0/0")

        config := EnhancedCoinConfig{
                Name:       "litecoin",
                DerivePath: "m/84'/2'/0'/0/0",
                Family:     FamilyUTXO,
                Params: CoinParams{
                        "addressType": "p2wpkh",
                        "network":     "mainnet",
                        "compressed":  true,
                },
                Handler: UTXOHandler,
        }

        builder := InitializeCoinBuilder(config, extendedKey, keyPair)
        builder.SetNetworkParams("mainnet")

        result, err := processLitecoin(builder, keyPair)
        if err != nil {
                t.Fatalf("processLitecoin failed: %v", err)
        }

        if result.Address != expectedAddress {
                t.Errorf("Litecoin address mismatch:\nExpected: %s\nGot:      %s", expectedAddress, result.Address)
        }

        // Verify other fields
        if result.Name != "litecoin" {
                t.Errorf("Expected name to be 'litecoin', got '%s'", result.Name)
        }
        if result.WIFPrivateKey == "" {
                t.Error("WIF private key should not be empty")
        }
        if result.HexPrivateKey == "" {
                t.Error("Hex private key should not be empty")
        }

        t.Logf("✓ Litecoin test passed - Address: %s", result.Address)
}

// TestBitcoinCashAddressGeneration tests Bitcoin Cash address generation
func TestBitcoinCashAddressGeneration(t *testing.T) {
        expectedAddress := "qp6379srrchrk2mfs32d2czxkx9wz2gx4qekc0x4xx"
        
        keyPair, extendedKey := setupTestKeyPair(t, "m/44'/145'/0'/0/0")

        config := EnhancedCoinConfig{
                Name:       "bitcoinCash",
                DerivePath: "m/44'/145'/0'/0/0",
                Family:     FamilyUTXO,
                Params: CoinParams{
                        "addressType": "p2pkh",
                        "network":     "mainnet",
                        "compressed":  true,
                },
                Handler: UTXOHandler,
        }

        builder := InitializeCoinBuilder(config, extendedKey, keyPair)
        builder.SetNetworkParams("mainnet")

        result, err := processBitcoinCash(builder, keyPair)
        if err != nil {
                t.Fatalf("processBitcoinCash failed: %v", err)
        }

        if result.Address != expectedAddress {
                t.Errorf("Bitcoin Cash address mismatch:\nExpected: %s\nGot:      %s", expectedAddress, result.Address)
        }

        // Verify other fields
        if result.Name != "bitcoinCash" {
                t.Errorf("Expected name to be 'bitcoinCash', got '%s'", result.Name)
        }
        if result.WIFPrivateKey == "" {
                t.Error("WIF private key should not be empty")
        }
        if result.HexPrivateKey == "" {
                t.Error("Hex private key should not be empty")
        }

        t.Logf("✓ Bitcoin Cash test passed - Address: %s", result.Address)
}

// TestDashAddressGeneration tests Dash address generation
func TestDashAddressGeneration(t *testing.T) {
        expectedAddress := "XkoQBncrZgAmHSYYhkjZqMF7NhPTBhbWbC"
        
        keyPair, extendedKey := setupTestKeyPair(t, "m/44'/5'/0'/0/0")

        config := EnhancedCoinConfig{
                Name:       "dash",
                DerivePath: "m/44'/5'/0'/0/0",
                Family:     FamilyUTXO,
                Params: CoinParams{
                        "addressType": "p2pkh",
                        "network":     "mainnet",
                        "compressed":  true,
                },
                Handler: UTXOHandler,
        }

        builder := InitializeCoinBuilder(config, extendedKey, keyPair)
        builder.SetNetworkParams("mainnet")

        result, err := processDash(builder, keyPair)
        if err != nil {
                t.Fatalf("processDash failed: %v", err)
        }

        if result.Address != expectedAddress {
                t.Errorf("Dash address mismatch:\nExpected: %s\nGot:      %s", expectedAddress, result.Address)
        }

        // Verify other fields
        if result.Name != "dash" {
                t.Errorf("Expected name to be 'dash', got '%s'", result.Name)
        }
        if result.WIFPrivateKey == "" {
                t.Error("WIF private key should not be empty")
        }
        if result.HexPrivateKey == "" {
                t.Error("Hex private key should not be empty")
        }

        t.Logf("✓ Dash test passed - Address: %s", result.Address)
}

// TestZcashAddressGeneration tests Zcash address generation
func TestZcashAddressGeneration(t *testing.T) {
        expectedAddress := "t1ZiDZcAQMkRPQMEZTkJFAi7oZSJjn73Shb"
        
        keyPair, extendedKey := setupTestKeyPair(t, "m/44'/133'/0'/0/0")

        config := EnhancedCoinConfig{
                Name:       "zcash",
                DerivePath: "m/44'/133'/0'/0/0",
                Family:     FamilyUTXO,
                Params: CoinParams{
                        "addressType": "p2pkh",
                        "network":     "mainnet",
                        "compressed":  true,
                },
                Handler: UTXOHandler,
        }

        builder := InitializeCoinBuilder(config, extendedKey, keyPair)
        builder.SetNetworkParams("mainnet")

        // Test direct processZcash call
        result, err := processZcash(builder, keyPair)
        if err != nil {
                t.Fatalf("processZcash failed: %v", err)
        }

        if result.Address != expectedAddress {
                t.Errorf("Zcash address mismatch:\nExpected: %s\nGot:      %s", expectedAddress, result.Address)
        }
        if result.Address == "" {
                t.Error("❌ CRITICAL: Zcash address is EMPTY!")
        }

        // Test UTXOHandler routing to Zcash  
        result2, err := UTXOHandler(extendedKey, config)
        if err != nil {
                t.Fatalf("UTXOHandler failed for Zcash: %v", err)
        }
        if result2.Address != expectedAddress {
                t.Errorf("UTXOHandler Zcash address mismatch:\nExpected: %s\nGot:      %s", expectedAddress, result2.Address)
        }
        if result2.Address == "" {
                t.Error("❌ CRITICAL: UTXOHandler Zcash address is EMPTY!")
        }

        // Verify other fields
        if result.Name != "zcash" {
                t.Errorf("Expected name to be 'zcash', got '%s'", result.Name)
        }
        if result.WIFPrivateKey == "" {
                t.Error("WIF private key should not be empty")
        }
        if result.HexPrivateKey == "" {
                t.Error("Hex private key should not be empty")
        }

        t.Logf("✓ Zcash test passed - Address: %s", result.Address)
        t.Logf("✓ UTXOHandler Zcash test passed - Address: %s", result2.Address)
}

// TestAllUTXOCoinsConfigSetup verifies all UTXO coins are properly configured
func TestAllUTXOCoinsConfigSetup(t *testing.T) {
        coins := GetEnhancedECDSACoins()
        
        expectedCoins := map[string]string{
                "bitcoin":     "m/84'/0'/0'/0/0",
                "bitcoinCash": "m/44'/145'/0'/0/0",
                "dogecoin":    "m/44'/3'/0'/0/0",
                "litecoin":    "m/84'/2'/0'/0/0",
                "dash":        "m/44'/5'/0'/0/0",
                "zcash":       "m/44'/133'/0'/0/0",
        }
        
        found := make(map[string]bool)
        
        for _, coin := range coins {
                if expectedPath, exists := expectedCoins[coin.Name]; exists {
                        found[coin.Name] = true
                        
                        if coin.DerivePath != expectedPath {
                                t.Errorf("Wrong derive path for %s: expected %s, got %s", coin.Name, expectedPath, coin.DerivePath)
                        }
                        if coin.Family != FamilyUTXO {
                                t.Errorf("Wrong family for %s: expected %s, got %s", coin.Name, FamilyUTXO, coin.Family)
                        }
                        if coin.Handler == nil {
                                t.Errorf("Handler is nil for %s", coin.Name)
                        }
                }
        }
        
        // Verify all expected coins were found
        for coinName := range expectedCoins {
                if !found[coinName] {
                        t.Errorf("Missing coin configuration: %s", coinName)
                }
        }
        
        t.Logf("✓ All %d UTXO coins configurations found and validated", len(expectedCoins))
}

// TestUTXOHandlerWithAllCoins tests the UTXOHandler with all UTXO coins
func TestUTXOHandlerWithAllCoins(t *testing.T) {
        // Create a test extended key
        extendedKey, err := hdkeychain.NewKeyFromString("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi")
        if err != nil {
                t.Fatalf("failed to create extended key: %v", err)
        }

        testCases := []struct {
                name           string
                coinName       string
                derivePath     string
                addressType    string
        }{
                {
                        name:        "Bitcoin",
                        coinName:    "bitcoin",
                        derivePath:  "m/84'/0'/0'/0/0",
                        addressType: "p2wpkh",
                },
                {
                        name:        "Bitcoin Cash",
                        coinName:    "bitcoinCash",
                        derivePath:  "m/44'/145'/0'/0/0",
                        addressType: "p2pkh",
                },
                {
                        name:        "Dogecoin",
                        coinName:    "dogecoin",
                        derivePath:  "m/44'/3'/0'/0/0",
                        addressType: "p2pkh",
                },
                {
                        name:        "Litecoin",
                        coinName:    "litecoin",
                        derivePath:  "m/84'/2'/0'/0/0",
                        addressType: "p2wpkh",
                },
                {
                        name:        "Dash",
                        coinName:    "dash",
                        derivePath:  "m/44'/5'/0'/0/0",
                        addressType: "p2pkh",
                },
                {
                        name:        "Zcash",
                        coinName:    "zcash",
                        derivePath:  "m/44'/133'/0'/0/0",
                        addressType: "p2pkh",
                },
        }

        for _, tc := range testCases {
                t.Run(tc.name, func(t *testing.T) {
                        config := EnhancedCoinConfig{
                                Name:       tc.coinName,
                                DerivePath: tc.derivePath,
                                Family:     FamilyUTXO,
                                Params: CoinParams{
                                        "addressType": tc.addressType,
                                        "network":     "mainnet",
                                        "compressed":  true,
                                },
                                Handler: UTXOHandler,
                        }

                        result, err := UTXOHandler(extendedKey, config)
                        if err != nil {
                                t.Fatalf("UTXOHandler failed for %s: %v", tc.coinName, err)
                        }

                        // Verify basic fields are populated
                        if result.Name != tc.coinName {
                                t.Errorf("Expected name to be '%s', got '%s'", tc.coinName, result.Name)
                        }
                        if result.Address == "" {
                                t.Error("Address should not be empty")
                        }
                        if result.WIFPrivateKey == "" {
                                t.Error("WIF private key should not be empty")
                        }
                        if result.HexPrivateKey == "" {
                                t.Error("Hex private key should not be empty")
                        }
                        if result.HexPublicKey == "" {
                                t.Error("Hex public key should not be empty")
                        }

                        t.Logf("✓ %s UTXOHandler test passed - Address: %s", tc.name, result.Address)
                })
        }
}