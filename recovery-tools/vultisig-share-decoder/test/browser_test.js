// Comprehensive test script for enhanced configuration system
// This script tests all aspects of the unified architecture

console.log("🚀 Starting Enhanced Configuration System Tests...");

// Test data for key derivation (sample test values)
const TEST_PRIVATE_KEY = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
const TEST_CHAIN_CODE = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef";
const TEST_EDDSA_PRIVATE = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
const TEST_EDDSA_PUBLIC = "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";

// Test 1: GetSupportedCoinsJSON Endpoint
async function testGetSupportedCoins() {
    console.log("\n📋 Test 1: GetSupportedCoinsJSON Endpoint");
    console.log("Testing if all 16 coins are returned correctly (13 ECDSA + 3 EdDSA)...");
    
    try {
        // Wait for WASM to be ready
        if (typeof window.GetSupportedCoinsJSON !== 'function') {
            throw new Error("GetSupportedCoinsJSON function not available");
        }
        
        const result = window.GetSupportedCoinsJSON();
        console.log("Raw result:", result);
        
        const data = JSON.parse(result);
        console.log("Parsed data:", data);
        
        if (!data.success) {
            throw new Error(`GetSupportedCoinsJSON failed: ${data.error}`);
        }
        
        const ecdsaCoins = data.ecdsaCoins || [];
        const eddsaCoins = data.eddsaCoins || [];
        
        console.log(`✅ Found ${ecdsaCoins.length} ECDSA coins`);
        console.log(`✅ Found ${eddsaCoins.length} EdDSA coins`);
        
        // Expected ECDSA coins
        const expectedECDSA = [
            "bitcoin", "bitcoinCash", "dogecoin", "litecoin", // UTXO
            "thorchain", "mayachain", "atom", "kujira", "dydx", "terra-classic", "terra", // Cosmos
            "ethereum", "tron" // EVM
        ];
        
        // Expected EdDSA coins
        const expectedEdDSA = ["solana", "sui", "ton"];
        
        // Verify all expected ECDSA coins are present
        const ecdsaCoinNames = ecdsaCoins.map(coin => coin.name);
        for (const expected of expectedECDSA) {
            if (!ecdsaCoinNames.includes(expected)) {
                throw new Error(`Missing ECDSA coin: ${expected}`);
            }
        }
        
        // Verify all expected EdDSA coins are present
        const eddsaCoinNames = eddsaCoins.map(coin => coin.name);
        for (const expected of expectedEdDSA) {
            if (!eddsaCoinNames.includes(expected)) {
                throw new Error(`Missing EdDSA coin: ${expected}`);
            }
        }
        
        // Check that we have exactly the expected counts
        if (ecdsaCoins.length !== 13) {
            console.warn(`⚠️ Expected 13 ECDSA coins, found ${ecdsaCoins.length}`);
        }
        if (eddsaCoins.length !== 3) {
            console.warn(`⚠️ Expected 3 EdDSA coins, found ${eddsaCoins.length}`);
        }
        
        console.log("✅ All expected coins found!");
        
        // Display coin families
        console.log("\n📊 ECDSA Coins by Family:");
        const utxoCoins = ecdsaCoins.filter(c => ["bitcoin", "bitcoinCash", "dogecoin", "litecoin"].includes(c.name));
        const cosmosCoins = ecdsaCoins.filter(c => ["thorchain", "mayachain", "atom", "kujira", "dydx", "terra-classic", "terra"].includes(c.name));
        const evmCoins = ecdsaCoins.filter(c => ["ethereum", "tron"].includes(c.name));
        
        console.log(`  UTXO: ${utxoCoins.length} coins - ${utxoCoins.map(c => c.name).join(', ')}`);
        console.log(`  Cosmos: ${cosmosCoins.length} coins - ${cosmosCoins.map(c => c.name).join(', ')}`);
        console.log(`  EVM: ${evmCoins.length} coins - ${evmCoins.map(c => c.name).join(', ')}`);
        
        console.log("\n📊 EdDSA Coins:");
        console.log(`  ${eddsaCoins.map(c => c.name).join(', ')}`);
        
        return { success: true, ecdsaCoins, eddsaCoins };
        
    } catch (error) {
        console.error("❌ Test 1 failed:", error.message);
        return { success: false, error: error.message };
    }
}

// Test 2: ECDSA Key Derivation for Multiple Coin Families
async function testECDSAKeyDerivation() {
    console.log("\n🔑 Test 2: ECDSA Key Derivation for Multiple Coin Families");
    console.log("Testing UTXO, Cosmos, and EVM coin families...");
    
    try {
        if (typeof window.DeriveAndShowKeysJSON !== 'function') {
            throw new Error("DeriveAndShowKeysJSON function not available");
        }
        
        const result = window.DeriveAndShowKeysJSON(TEST_PRIVATE_KEY, TEST_CHAIN_CODE, "", "");
        console.log("Derivation result length:", result.length);
        
        const data = JSON.parse(result);
        
        if (!data.success) {
            throw new Error(`Key derivation failed: ${data.error}`);
        }
        
        const ecdsaKeys = data.ecdsaKeys || [];
        console.log(`✅ Derived keys for ${ecdsaKeys.length} ECDSA coins`);
        
        // Test specific coin families
        const utxoSample = ecdsaKeys.find(k => k.name === "bitcoin");
        const cosmosSample = ecdsaKeys.find(k => k.name === "thorchain");
        const evmSample = ecdsaKeys.find(k => k.name === "ethereum");
        
        if (!utxoSample) throw new Error("Bitcoin (UTXO) key derivation failed");
        if (!cosmosSample) throw new Error("THORChain (Cosmos) key derivation failed");
        if (!evmSample) throw new Error("Ethereum (EVM) key derivation failed");
        
        // Verify key structure for each family
        console.log("\n🔍 Verifying key structures:");
        
        // UTXO coins should have WIF private keys and addresses
        if (!utxoSample.wifPrivateKey) {
            throw new Error("Bitcoin missing WIF private key");
        }
        if (!utxoSample.address) {
            throw new Error("Bitcoin missing address");
        }
        console.log(`  ✅ Bitcoin: WIF=${utxoSample.wifPrivateKey.substring(0, 10)}..., Address=${utxoSample.address.substring(0, 10)}...`);
        
        // Cosmos coins should have bech32 addresses
        if (!cosmosSample.address || !cosmosSample.address.startsWith("thor")) {
            throw new Error("THORChain missing proper bech32 address");
        }
        console.log(`  ✅ THORChain: Address=${cosmosSample.address.substring(0, 15)}...`);
        
        // EVM coins should have 0x addresses
        if (!evmSample.address || !evmSample.address.startsWith("0x")) {
            throw new Error("Ethereum missing proper 0x address");
        }
        console.log(`  ✅ Ethereum: Address=${evmSample.address.substring(0, 10)}...`);
        
        return { success: true, ecdsaKeys };
        
    } catch (error) {
        console.error("❌ Test 2 failed:", error.message);
        return { success: false, error: error.message };
    }
}

// Test 3: EdDSA Key Derivation for All 3 Coins
async function testEdDSAKeyDerivation() {
    console.log("\n🔐 Test 3: EdDSA Key Derivation for All 3 Coins");
    console.log("Testing Solana, Sui, and TON...");
    
    try {
        if (typeof window.DeriveAndShowKeysJSON !== 'function') {
            throw new Error("DeriveAndShowKeysJSON function not available");
        }
        
        const result = window.DeriveAndShowKeysJSON(TEST_PRIVATE_KEY, TEST_CHAIN_CODE, TEST_EDDSA_PRIVATE, TEST_EDDSA_PUBLIC);
        const data = JSON.parse(result);
        
        if (!data.success) {
            throw new Error(`EdDSA key derivation failed: ${data.error}`);
        }
        
        const eddsaKeys = data.eddsaKeys || [];
        console.log(`✅ Derived keys for ${eddsaKeys.length} EdDSA coins`);
        
        // Test all three EdDSA coins
        const solanaKey = eddsaKeys.find(k => k.name === "solana");
        const suiKey = eddsaKeys.find(k => k.name === "sui");
        const tonKey = eddsaKeys.find(k => k.name === "ton");
        
        if (!solanaKey) throw new Error("Solana key derivation failed");
        if (!suiKey) throw new Error("Sui key derivation failed");
        if (!tonKey) throw new Error("TON key derivation failed");
        
        console.log("\n🔍 Verifying EdDSA key structures:");
        
        // Solana addresses should be base58 encoded
        if (!solanaKey.address) {
            throw new Error("Solana missing address");
        }
        console.log(`  ✅ Solana: Address=${solanaKey.address.substring(0, 10)}...`);
        
        // Sui addresses should be 0x prefixed
        if (!suiKey.address || !suiKey.address.startsWith("0x")) {
            throw new Error("Sui missing proper 0x address");
        }
        console.log(`  ✅ Sui: Address=${suiKey.address.substring(0, 15)}...`);
        
        // TON addresses should be present
        if (!tonKey.address) {
            throw new Error("TON missing address");
        }
        console.log(`  ✅ TON: Address=${tonKey.address.substring(0, 15)}...`);
        
        return { success: true, eddsaKeys };
        
    } catch (error) {
        console.error("❌ Test 3 failed:", error.message);
        return { success: false, error: error.message };
    }
}

// Test 4: Verify Enhanced Configuration Registry
async function testEnhancedConfigRegistry() {
    console.log("\n⚙️ Test 4: Enhanced Configuration Registry");
    console.log("Verifying handlers and parameters are properly configured...");
    
    try {
        // This test verifies the configuration through the GetSupportedCoinsJSON output
        const supportedResult = await testGetSupportedCoins();
        if (!supportedResult.success) {
            throw new Error("Could not get supported coins for registry test");
        }
        
        const { ecdsaCoins, eddsaCoins } = supportedResult;
        
        // Verify each ECDSA coin has proper derive path and algorithm
        for (const coin of ecdsaCoins) {
            if (!coin.derivePath || !coin.derivePath.startsWith("m/")) {
                throw new Error(`${coin.name} missing proper derive path`);
            }
            if (coin.algorithm !== "ECDSA") {
                throw new Error(`${coin.name} should have ECDSA algorithm`);
            }
        }
        
        // Verify each EdDSA coin has proper derive path and algorithm
        for (const coin of eddsaCoins) {
            if (!coin.derivePath || !coin.derivePath.startsWith("m/")) {
                throw new Error(`${coin.name} missing proper derive path`);
            }
            if (coin.algorithm !== "EdDSA") {
                throw new Error(`${coin.name} should have EdDSA algorithm`);
            }
        }
        
        console.log("✅ All coins have proper configuration");
        
        // Test that derivation actually works (integration test)
        const derivationResult = await testECDSAKeyDerivation();
        if (!derivationResult.success) {
            throw new Error("Registry configuration failed integration test");
        }
        
        console.log("✅ Registry configuration passed integration test");
        
        return { success: true };
        
    } catch (error) {
        console.error("❌ Test 4 failed:", error.message);
        return { success: false, error: error.message };
    }
}

// Main test runner
async function runAllTests() {
    console.log("🧪 Enhanced Configuration System - Comprehensive Test Suite");
    console.log("=" * 60);
    
    const results = {
        test1: await testGetSupportedCoins(),
        test2: await testECDSAKeyDerivation(),
        test3: await testEdDSAKeyDerivation(),
        test4: await testEnhancedConfigRegistry()
    };
    
    console.log("\n📊 Test Results Summary:");
    console.log("=" * 40);
    
    let passedTests = 0;
    const totalTests = 4;
    
    for (const [testName, result] of Object.entries(results)) {
        const status = result.success ? "✅ PASS" : "❌ FAIL";
        const testNum = testName.replace('test', '');
        console.log(`Test ${testNum}: ${status}`);
        if (!result.success) {
            console.log(`  Error: ${result.error}`);
        } else {
            passedTests++;
        }
    }
    
    console.log("\n" + "=" * 40);
    console.log(`Final Score: ${passedTests}/${totalTests} tests passed`);
    
    if (passedTests === totalTests) {
        console.log("🎉 All tests passed! Enhanced configuration system is working correctly.");
    } else {
        console.log("⚠️ Some tests failed. Review the errors above.");
    }
    
    return results;
}

// Auto-run tests when script loads
if (typeof window !== 'undefined') {
    // Wait for WASM to be ready
    let attempts = 0;
    const maxAttempts = 50;
    
    function waitForWASM() {
        attempts++;
        if (typeof window.GetSupportedCoinsJSON === 'function') {
            console.log("✅ WASM functions detected, starting tests...");
            runAllTests();
        } else if (attempts < maxAttempts) {
            console.log(`⏳ Waiting for WASM... (${attempts}/${maxAttempts})`);
            setTimeout(waitForWASM, 1000);
        } else {
            console.error("❌ Timeout waiting for WASM functions to load");
        }
    }
    
    // Start checking for WASM readiness
    setTimeout(waitForWASM, 1000);
}

// Export functions for manual testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        runAllTests,
        testGetSupportedCoins,
        testECDSAKeyDerivation,
        testEdDSAKeyDerivation,
        testEnhancedConfigRegistry
    };
}