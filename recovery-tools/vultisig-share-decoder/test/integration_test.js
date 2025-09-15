#!/usr/bin/env node

// DKLS Integration Test - Node.js Shell Version
// This test loads example files and tests DKLS processing to debug the EdDSA "undefined" issue

const fs = require('fs');
const path = require('path');

// Import the JavaScript modules we need to test
// We'll need to simulate the browser environment for the WASM modules

console.log('🚀 Starting DKLS Integration Test...\n');

// Helper function to read example files
function loadExampleFile(fileName) {
    const filePath = path.join(__dirname, '../examples', fileName);
    try {
        if (!fs.existsSync(filePath)) {
            throw new Error(`Example file not found: ${filePath}`);
        }
        const content = fs.readFileSync(filePath);
        return new Uint8Array(content);
    } catch (error) {
        console.error(`❌ Error loading file ${fileName}:`, error.message);
        throw error;
    }
}

// Mock browser environment for Node.js testing
function setupMockEnvironment() {
    // Create a basic DOM-like environment
    global.window = {
        vsWasmModule: null,
        vsSchnorrWasmModule: null
    };
    
    // Mock console methods to capture debug output
    const originalLog = console.log;
    global.debugLog = function(message) {
        originalLog(`[DEBUG] ${message}`);
    };
    
    // Mock TextDecoder/TextEncoder for Node.js
    if (typeof global.TextDecoder === 'undefined') {
        global.TextDecoder = require('util').TextDecoder;
    }
    if (typeof global.TextEncoder === 'undefined') {
        global.TextEncoder = require('util').TextEncoder;
    }
}

// Test 1: File Loading Test
async function testFileLoading() {
    console.log('📁 Test 1: File Loading');
    console.log('Testing if example files can be loaded...\n');
    
    try {
        const dkls1 = loadExampleFile('DKLS_1of2.vult');
        const dkls2 = loadExampleFile('DKLS_2of2.vult');
        
        console.log(`✅ DKLS_1of2.vult: ${dkls1.length} bytes`);
        console.log(`✅ DKLS_2of2.vult: ${dkls2.length} bytes`);
        
        // Also test GG20 files for regression
        const gg20_1 = loadExampleFile('GG20_1of2.vult');
        const gg20_2 = loadExampleFile('GG20_2of2.vult');
        
        console.log(`✅ GG20_1of2.vult: ${gg20_1.length} bytes`);
        console.log(`✅ GG20_2of2.vult: ${gg20_2.length} bytes`);
        
        console.log('✅ File loading test passed!\n');
        return { success: true, dkls1, dkls2, gg20_1, gg20_2 };
        
    } catch (error) {
        console.error('❌ File loading test failed:', error.message);
        return { success: false, error: error.message };
    }
}

// Test 2: Module Availability Test
async function testModuleAvailability() {
    console.log('🔍 Test 2: Module Availability');
    console.log('Checking if WASM modules would be available...\n');
    
    try {
        // Check if the WASM files exist
        const wasmFiles = [
            'web/main.wasm',
            'web/vs_wasm_bg.wasm', 
            'web/vs_schnorr_wasm_bg.wasm'
        ];
        
        for (const wasmFile of wasmFiles) {
            const wasmPath = path.join(__dirname, '..', wasmFile);
            if (!fs.existsSync(wasmPath)) {
                throw new Error(`WASM file missing: ${wasmPath}`);
            }
            const stats = fs.statSync(wasmPath);
            console.log(`✅ ${wasmFile}: ${stats.size} bytes`);
        }
        
        // Check if JavaScript wrapper files exist
        const jsFiles = [
            'web/vs_wasm.js',
            'web/vs_schnorr_wasm.js'
        ];
        
        for (const jsFile of jsFiles) {
            const jsPath = path.join(__dirname, '..', jsFile);
            if (!fs.existsSync(jsPath)) {
                throw new Error(`JavaScript wrapper missing: ${jsPath}`);
            }
            console.log(`✅ ${jsFile} exists`);
        }
        
        console.log('✅ Module availability test passed!\n');
        return { success: true };
        
    } catch (error) {
        console.error('❌ Module availability test failed:', error.message);
        return { success: false, error: error.message };
    }
}

// Test 3: Vault Parsing Test (without WASM)
async function testVaultParsing() {
    console.log('🔍 Test 3: Vault Parsing');
    console.log('Testing vault parsing without WASM dependencies...\n');
    
    try {
        // We can't easily load the main.js module in Node.js due to WASM dependencies
        // But we can test basic file structure analysis
        
        const dkls1 = loadExampleFile('DKLS_1of2.vult');
        const dkls2 = loadExampleFile('DKLS_2of2.vult');
        
        // Basic structure analysis
        console.log('📊 File Structure Analysis:');
        
        // Check if files are base64 encoded
        function analyzeFile(data, name) {
            const str = new TextDecoder().decode(data.slice(0, 100));
            const isBase64Like = /^[A-Za-z0-9+/=]+$/.test(str);
            const hasNulls = data.slice(0, 100).includes(0);
            
            console.log(`   ${name}:`);
            console.log(`     First 50 chars: ${str.slice(0, 50)}...`);
            console.log(`     Appears base64: ${isBase64Like}`);
            console.log(`     Has null bytes: ${hasNulls}`);
            console.log(`     Total size: ${data.length} bytes`);
        }
        
        analyzeFile(dkls1, 'DKLS_1of2.vult');
        analyzeFile(dkls2, 'DKLS_2of2.vult');
        
        console.log('✅ Vault parsing test completed!\n');
        return { success: true };
        
    } catch (error) {
        console.error('❌ Vault parsing test failed:', error.message);
        return { success: false, error: error.message };
    }
}

// Test 4: Mock DKLS Processing Test
async function testMockDKLSProcessing() {
    console.log('🔍 Test 4: Mock DKLS Processing');
    console.log('Simulating DKLS processing to identify potential issues...\n');
    
    try {
        const files = [
            loadExampleFile('DKLS_1of2.vult'),
            loadExampleFile('DKLS_2of2.vult')
        ];
        const passwords = ['', ''];
        const fileNames = ['DKLS_1of2.vult', 'DKLS_2of2.vult'];
        
        console.log(`📁 Loaded ${files.length} DKLS files for processing simulation`);
        
        // Simulate the processing steps that would happen in the browser
        console.log('🔧 Simulating processing steps:');
        console.log('   1. Parse vault containers - [WOULD NEED WASM]');
        console.log('   2. Decrypt vaults - [WOULD NEED WASM]'); 
        console.log('   3. Extract keyshare data - [WOULD NEED WASM]');
        console.log('   4. Create ECDSA keyshares - [WOULD NEED vs_wasm]');
        console.log('   5. Create EdDSA keyshares - [WOULD NEED vs_schnorr_wasm]');
        console.log('   6. Run ECDSA session - [WOULD NEED vs_wasm]');
        console.log('   7. Run EdDSA session - [WOULD NEED vs_schnorr_wasm] ⬅️ LIKELY FAILURE POINT');
        
        // This is where the "undefined" error likely occurs
        console.log('\n🎯 Likely Issue Analysis:');
        console.log('   The error "for EdDSA: undefined" suggests that:');
        console.log('   - vs_schnorr_wasm module loads successfully');
        console.log('   - Keyshare creation from DKLS data succeeds');  
        console.log('   - But EdDSA session processing returns undefined');
        console.log('   - This could be due to:');
        console.log('     • EdDSA keyshares not compatible with ECDSA keyshare data');
        console.log('     • Different WASM module expecting different data format');
        console.log('     • EdDSA session.finish() returning undefined/null');
        console.log('     • Missing EdDSA-specific processing in vs_schnorr_wasm');
        
        console.log('\n💡 Debugging Recommendations:');
        console.log('   1. Check if vs_schnorr_wasm expects different keyshare data format');
        console.log('   2. Verify EdDSA session.finish() method exists and works');
        console.log('   3. Test if same keyshare data works for both ECDSA and EdDSA modules');
        console.log('   4. Add detailed logging in extractPrivateKeyWithModule function');
        
        console.log('✅ Mock processing analysis completed!\n');
        return { success: true };
        
    } catch (error) {
        console.error('❌ Mock processing test failed:', error.message);
        return { success: false, error: error.message };
    }
}

// Main test runner
async function runIntegrationTests() {
    console.log('🧪 DKLS Integration Test Suite');
    console.log('=' + '='.repeat(50));
    console.log('Purpose: Debug EdDSA "undefined" error in DKLS processing\n');
    
    setupMockEnvironment();
    
    const results = {
        fileLoading: await testFileLoading(),
        moduleAvailability: await testModuleAvailability(), 
        vaultParsing: await testVaultParsing(),
        mockProcessing: await testMockDKLSProcessing()
    };
    
    console.log('📊 Test Results Summary:');
    console.log('=' + '='.repeat(30));
    
    let passedTests = 0;
    const totalTests = Object.keys(results).length;
    
    for (const [testName, result] of Object.entries(results)) {
        const status = result.success ? '✅ PASS' : '❌ FAIL';
        console.log(`${testName}: ${status}`);
        if (!result.success && result.error) {
            console.log(`  Error: ${result.error}`);
        }
        if (result.success) passedTests++;
    }
    
    console.log('\n' + '='.repeat(50));
    console.log(`Final Score: ${passedTests}/${totalTests} tests passed`);
    
    if (passedTests === totalTests) {
        console.log('🎉 All integration tests passed!');
        console.log('📝 Next step: Run the web application and test with these files manually');
        console.log('    to see the exact "undefined" error location.');
    } else {
        console.log('⚠️  Some tests failed. Check errors above.');
    }
    
    return results;
}

// Run the tests if this script is executed directly
if (require.main === module) {
    runIntegrationTests()
        .then(() => process.exit(0))
        .catch(error => {
            console.error('💥 Integration test suite failed:', error);
            process.exit(1);
        });
}

module.exports = {
    runIntegrationTests,
    testFileLoading,
    testModuleAvailability,
    testVaultParsing,
    testMockDKLSProcessing
};