// Integration Test for DKLS and GG20 Processing
// This test uses actual vault files from examples/ directory to validate processing

console.log("🚀 Starting Integration Tests for Vault Processing...");

// Helper function to load example files from the examples directory
async function loadExampleFile(fileName) {
    try {
        const response = await fetch(`../examples/${fileName}`);
        if (!response.ok) {
            throw new Error(`Failed to load ${fileName}: ${response.status} ${response.statusText}`);
        }
        const arrayBuffer = await response.arrayBuffer();
        return new Uint8Array(arrayBuffer);
    } catch (error) {
        console.error(`Error loading example file ${fileName}:`, error);
        throw error;
    }
}

// Test 1: DKLS Processing Integration Test
async function testDKLSIntegration() {
    console.log("\n🔷 Integration Test 1: DKLS Processing");
    console.log("Testing DKLS vault processing with example files...");
    
    try {
        // Load DKLS example files
        console.log("📁 Loading DKLS example files...");
        const dkls1Data = await loadExampleFile('DKLS_1of2.vult');
        const dkls2Data = await loadExampleFile('DKLS_2of2.vult');
        
        const files = [dkls1Data, dkls2Data];
        const passwords = ["", ""]; // No passwords for these test files
        const fileNames = ['DKLS_1of2.vult', 'DKLS_2of2.vult'];
        
        console.log(`✅ Loaded ${files.length} DKLS files successfully`);
        console.log(`   File 1: ${files[0].length} bytes`);
        console.log(`   File 2: ${files[1].length} bytes`);
        
        // Check WASM module availability
        if (!window.vsWasmModule) {
            throw new Error("vs_wasm module not available - ECDSA processing will fail");
        }
        if (!window.vsSchnorrWasmModule) {
            throw new Error("vs_schnorr_wasm module not available - EdDSA processing will fail");
        }
        
        console.log("✅ Both WASM modules are available");
        console.log(`   ECDSA module classes: ${Object.keys(window.vsWasmModule).join(', ')}`);
        console.log(`   EdDSA module classes: ${Object.keys(window.vsSchnorrWasmModule).join(', ')}`);
        
        // Test DKLS processing with WASM method
        console.log("\n🔧 Testing DKLS WASM Processing...");
        let wasmResult;
        try {
            wasmResult = await processDKLSWithWASM(files, passwords, fileNames);
            console.log("✅ DKLS WASM processing completed successfully");
        } catch (wasmError) {
            console.error("❌ DKLS WASM processing failed:", wasmError.message);
            console.error("Full error:", wasmError);
            throw new Error(`DKLS WASM processing failed: ${wasmError.message}`);
        }
        
        // Test DKLS processing with JSON method
        console.log("\n🔧 Testing DKLS JSON Processing...");
        let jsonResult;
        try {
            jsonResult = await processDKLSWithJSON(files, passwords, fileNames);
            console.log("✅ DKLS JSON processing completed successfully");
        } catch (jsonError) {
            console.error("❌ DKLS JSON processing failed:", jsonError.message);
            console.error("Full error:", jsonError);
            throw new Error(`DKLS JSON processing failed: ${jsonError.message}`);
        }
        
        console.log("✅ DKLS integration test passed!");
        return { success: true, wasmResult, jsonResult };
        
    } catch (error) {
        console.error("❌ DKLS integration test failed:", error.message);
        console.error("Stack trace:", error.stack);
        return { success: false, error: error.message };
    }
}

// Test 2: GG20 Processing Integration Test (Regression Test)
async function testGG20Integration() {
    console.log("\n🔷 Integration Test 2: GG20 Processing (Regression Test)");
    console.log("Testing GG20 vault processing with example files...");
    
    try {
        // Load GG20 example files
        console.log("📁 Loading GG20 example files...");
        const gg20_1Data = await loadExampleFile('GG20_1of2.vult');
        const gg20_2Data = await loadExampleFile('GG20_2of2.vult');
        
        const files = [gg20_1Data, gg20_2Data];
        const passwords = ["", ""]; // No passwords for these test files
        const fileNames = ['GG20_1of2.vult', 'GG20_2of2.vult'];
        
        console.log(`✅ Loaded ${files.length} GG20 files successfully`);
        console.log(`   File 1: ${files[0].length} bytes`);
        console.log(`   File 2: ${files[1].length} bytes`);
        
        // Test GG20 processing (should use existing recoverKeys function)
        console.log("\n🔧 Testing GG20 processing via Go WASM...");
        let gg20Result;
        try {
            // Check if Go WASM functions are available
            if (!window.ProcessFileContentJSON) {
                throw new Error("ProcessFileContentJSON function not available");
            }
            
            console.log("✅ GG20 processing functions are available");
            
            // Test with Go WASM function
            const gg20JsonResult = window.ProcessFileContentJSON(files, passwords, fileNames, 'gg20');
            console.log("Raw GG20 result:", gg20JsonResult);
            
            const parsedResult = JSON.parse(gg20JsonResult);
            if (!parsedResult.success) {
                throw new Error(`GG20 processing failed: ${parsedResult.error}`);
            }
            
            console.log("✅ GG20 processing completed successfully");
            
        } catch (gg20Error) {
            console.error("❌ GG20 processing failed:", gg20Error.message);
            return { success: false, error: gg20Error.message };
        }
        
        console.log("✅ GG20 integration test passed!");
        return { success: true };
        
    } catch (error) {
        console.error("❌ GG20 integration test failed:", error.message);
        return { success: false, error: error.message };
    }
}

// Test 3: EdDSA Module Debugging Test
async function testEdDSAModuleDebug() {
    console.log("\n🔷 Integration Test 3: EdDSA Module Debugging");
    console.log("Debugging EdDSA processing step by step...");
    
    try {
        // Check EdDSA module in detail
        if (!window.vsSchnorrWasmModule) {
            throw new Error("vsSchnorrWasmModule not available");
        }
        
        const { Keyshare, KeyExportSession, Message } = window.vsSchnorrWasmModule;
        
        // Test class availability
        console.log("🔍 Testing EdDSA class availability...");
        if (!Keyshare) throw new Error("EdDSA Keyshare class not available");
        if (!KeyExportSession) throw new Error("EdDSA KeyExportSession class not available");
        if (!Message) throw new Error("EdDSA Message class not available");
        
        console.log("✅ All EdDSA classes are available");
        
        // Load a single DKLS file for detailed debugging
        console.log("📁 Loading single DKLS file for detailed analysis...");
        const dklsData = await loadExampleFile('DKLS_1of2.vult');
        
        // Test vault parsing
        console.log("🔍 Testing vault parsing...");
        const password = "";
        let keyshareData;
        
        try {
            keyshareData = await parseAndDecryptVault(dklsData, password);
            console.log(`✅ Vault parsed successfully, keyshare data length: ${keyshareData.length} bytes`);
        } catch (parseError) {
            console.error("❌ Vault parsing failed:", parseError.message);
            throw parseError;
        }
        
        // Test EdDSA keyshare creation
        console.log("🔍 Testing EdDSA keyshare creation...");
        let eddsaKeyshare;
        try {
            eddsaKeyshare = Keyshare.fromBytes(keyshareData);
            if (!eddsaKeyshare) {
                throw new Error("EdDSA Keyshare.fromBytes returned null/undefined");
            }
            console.log("✅ EdDSA keyshare created successfully");
        } catch (keyshareError) {
            console.error("❌ EdDSA keyshare creation failed:", keyshareError.message);
            throw keyshareError;
        }
        
        // Test EdDSA session creation
        console.log("🔍 Testing EdDSA session creation...");
        try {
            const partyIds = ['party1'];
            const session = KeyExportSession.new(eddsaKeyshare, partyIds);
            if (!session) {
                throw new Error("EdDSA KeyExportSession.new returned null/undefined");
            }
            console.log("✅ EdDSA session created successfully");
            
            // Test setup property
            const setup = session.setup;
            if (!setup) {
                throw new Error("EdDSA session.setup returned null/undefined");
            }
            console.log(`✅ EdDSA session setup available, length: ${setup.length} bytes`);
            
        } catch (sessionError) {
            console.error("❌ EdDSA session creation failed:", sessionError.message);
            throw sessionError;
        }
        
        console.log("✅ EdDSA module debugging test passed!");
        return { success: true };
        
    } catch (error) {
        console.error("❌ EdDSA module debugging test failed:", error.message);
        console.error("Stack trace:", error.stack);
        return { success: false, error: error.message, stack: error.stack };
    }
}

// Test 4: Full DKLS Processing Step-by-Step Debug
async function testDKLSStepByStep() {
    console.log("\n🔷 Integration Test 4: DKLS Step-by-Step Processing Debug");
    console.log("Testing complete DKLS processing pipeline with detailed logging...");
    
    try {
        // Load DKLS files
        console.log("📁 Loading DKLS files...");
        const dkls1Data = await loadExampleFile('DKLS_1of2.vult');
        const dkls2Data = await loadExampleFile('DKLS_2of2.vult');
        const files = [dkls1Data, dkls2Data];
        const passwords = ["", ""];
        const fileNames = ['DKLS_1of2.vult', 'DKLS_2of2.vult'];
        
        console.log("✅ Files loaded successfully");
        
        // Test vault parsing for both files
        console.log("🔍 Testing vault parsing for both files...");
        const vaultInfos = [];
        const keyshares = [];
        
        for (let i = 0; i < files.length; i++) {
            console.log(`\n--- Processing File ${i + 1}: ${fileNames[i]} ---`);
            
            // Parse vault info
            try {
                let vaultContainerData = files[i];
                try {
                    const base64String = new TextDecoder().decode(files[i]);
                    const decoded = fromBase64(base64String);
                    if (decoded.length > 100) {
                        vaultContainerData = decoded;
                    }
                } catch (e) {
                    // Not base64, use raw data
                }

                const vaultContainer = parseVaultContainer(vaultContainerData);
                let vaultData;
                if (vaultContainer.isEncrypted) {
                    const encryptedVaultBytes = fromBase64(vaultContainer.vault);
                    vaultData = await decryptWithAesGcm({
                        key: passwords[i],
                        value: encryptedVaultBytes
                    });
                } else {
                    vaultData = fromBase64(vaultContainer.vault);
                }

                const vault = parseVault(vaultData);
                vaultInfos.push({
                    name: vault.name || fileNames[i],
                    localPartyId: vault.localPartyId || `party${i + 1}`,
                    resharePrefix: vault.resharePrefix || '',
                    filename: fileNames[i],
                    publicKeyEddsa: vault.publicKeyEddsa || '',
                    libType: vault.libType
                });
                
                console.log(`✅ Vault ${i + 1} info parsed successfully`);
                console.log(`   Vault name: ${vault.name}`);
                console.log(`   Party ID: ${vault.localPartyId}`);
                console.log(`   EdDSA public key present: ${!!vault.publicKeyEddsa}`);
                console.log(`   LibType: ${vault.libType}`);
                
            } catch (vaultParseError) {
                console.error(`❌ Failed to parse vault ${i + 1}:`, vaultParseError.message);
                throw vaultParseError;
            }
            
            // Parse keyshare data
            try {
                const keyshareData = await parseAndDecryptVault(files[i], passwords[i]);
                console.log(`✅ Keyshare data extracted for file ${i + 1}, length: ${keyshareData.length} bytes`);
                keyshares.push(keyshareData);
            } catch (keyshareError) {
                console.error(`❌ Failed to extract keyshare data from file ${i + 1}:`, keyshareError.message);
                throw keyshareError;
            }
        }
        
        // Test ECDSA keyshare processing
        console.log("\n🔍 Testing ECDSA keyshare processing...");
        const { Keyshare: EcdsaKeyshare, KeyExportSession: EcdsaSession } = window.vsWasmModule;
        
        const ecdsaKeyshares = [];
        for (let i = 0; i < keyshares.length; i++) {
            const keyshare = EcdsaKeyshare.fromBytes(keyshares[i]);
            if (!keyshare) {
                throw new Error(`ECDSA keyshare creation failed for file ${i + 1}`);
            }
            ecdsaKeyshares.push(keyshare);
            console.log(`✅ ECDSA keyshare ${i + 1} created successfully`);
        }
        
        // Test EdDSA keyshare processing
        console.log("\n🔍 Testing EdDSA keyshare processing...");
        const { Keyshare: EddsaKeyshare, KeyExportSession: EddsaSession } = window.vsSchnorrWasmModule;
        
        const eddsaKeyshares = [];
        for (let i = 0; i < keyshares.length; i++) {
            const keyshare = EddsaKeyshare.fromBytes(keyshares[i]);
            if (!keyshare) {
                throw new Error(`EdDSA keyshare creation failed for file ${i + 1}`);
            }
            eddsaKeyshares.push(keyshare);
            console.log(`✅ EdDSA keyshare ${i + 1} created successfully`);
        }
        
        console.log("✅ DKLS step-by-step debug test passed!");
        return { success: true, vaultInfos, ecdsaKeyshares, eddsaKeyshares };
        
    } catch (error) {
        console.error("❌ DKLS step-by-step debug test failed:", error.message);
        console.error("Stack trace:", error.stack);
        return { success: false, error: error.message, stack: error.stack };
    }
}

// Main integration test runner
async function runIntegrationTests() {
    console.log("🧪 Vault Processing Integration Test Suite");
    console.log("=".repeat(60));
    
    // Wait for WASM to be ready
    console.log("⏳ Waiting for WASM modules to be ready...");
    let attempts = 0;
    const maxAttempts = 30;
    
    while (attempts < maxAttempts) {
        if (window.vsWasmModule && window.vsSchnorrWasmModule && window.ProcessFileContentJSON) {
            console.log("✅ All required modules are ready");
            break;
        }
        attempts++;
        if (attempts >= maxAttempts) {
            console.error("❌ Timeout waiting for WASM modules to load");
            return { success: false, error: "WASM modules not ready" };
        }
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    const results = {
        eddsaDebug: await testEdDSAModuleDebug(),
        dklsStepByStep: await testDKLSStepByStep(),
        dklsIntegration: await testDKLSIntegration(),
        gg20Integration: await testGG20Integration()
    };
    
    console.log("\n📊 Integration Test Results Summary:");
    console.log("=".repeat(50));
    
    let passedTests = 0;
    const totalTests = 4;
    
    for (const [testName, result] of Object.entries(results)) {
        const status = result.success ? "✅ PASS" : "❌ FAIL";
        console.log(`${testName}: ${status}`);
        if (!result.success) {
            console.log(`  Error: ${result.error}`);
            if (result.stack) {
                console.log(`  Stack: ${result.stack}`);
            }
        } else {
            passedTests++;
        }
    }
    
    console.log("\n" + "=".repeat(50));
    console.log(`Final Score: ${passedTests}/${totalTests} integration tests passed`);
    
    if (passedTests === totalTests) {
        console.log("🎉 All integration tests passed! Vault processing is working correctly.");
    } else {
        console.log("⚠️ Some integration tests failed. Check the errors above for debugging.");
    }
    
    return results;
}

// Auto-run integration tests when script loads
if (typeof window !== 'undefined') {
    // Add a button to manually trigger tests
    window.runIntegrationTests = runIntegrationTests;
    
    // Auto-run after a delay to ensure everything is loaded
    setTimeout(() => {
        console.log("🎯 Starting integration tests automatically...");
        runIntegrationTests();
    }, 3000);
}

// Export for manual testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        runIntegrationTests,
        testDKLSIntegration,
        testGG20Integration,
        testEdDSAModuleDebug,
        testDKLSStepByStep
    };
}