let fileGroupCounter = 1;

function hideLoader() {
    document.getElementById('loader').style.display = 'none';
    document.getElementById('content').style.display = 'block';
    debugLog("UI initialized and ready");
}

function debugLog(message) {
    const debugOutput = document.getElementById('debugOutput');
    const timestamp = new Date().toISOString();
    debugOutput.textContent += `${timestamp}: ${message}\n`;
}

// Import vanilla JS protobuf functions
import { parseVaultContainer, parseVault, LibType } from './vault_pb.js';
import { decryptWithAesGcm, fromBase64 } from './aes_gcm.js';

// Initialize WASM modules
const go = new Go();

// Initialize main.wasm (Go WASM) with cache-busting
const cacheBuster = Date.now();
const initMainWasm = WebAssembly.instantiateStreaming(fetch(`main.wasm?v=${cacheBuster}`), go.importObject)
    .then((result) => {
        go.run(result.instance);
        debugLog("Main WASM initialized successfully");
        return result;
    });

// Initialize vs_wasm_bg.wasm (additional WASM module)
const initVsWasm = (async () => {
    try {
        debugLog("Starting vs_wasm module import...");

        // Import the vs_wasm module as ES6 module
        const vsWasmModule = await import('./vs_wasm.js');
        debugLog("vs_wasm module imported successfully");

        // Initialize the WASM module with proper path
        debugLog("Initializing WASM binary...");
        await vsWasmModule.default('./vs_wasm_bg.wasm');
        debugLog("vs_wasm WASM binary initialized successfully");

        // Verify classes are available
        if (!vsWasmModule.Keyshare || !vsWasmModule.KeyExportSession) {
            throw new Error("Required WASM classes (Keyshare, KeyExportSession) not found in module");
        }

        // Set up the module classes
        window.vsWasmModule = {
            Keyshare: vsWasmModule.Keyshare,
            KeyExportSession: vsWasmModule.KeyExportSession,
            Message: vsWasmModule.Message
        };

        debugLog("vs_wasm classes configured successfully");
        debugLog(`Available classes: ${Object.keys(window.vsWasmModule).join(', ')}`);
        return window.vsWasmModule;
    } catch (error) {
        debugLog(`vs_wasm initialization failed: ${error.message}`);
        debugLog(`Error stack: ${error.stack}`);
        debugLog("Note: vs_wasm is optional for DKLS processing");
        return null;
    }
})();

// Initialize vs_schnorr_wasm_bg.wasm (EdDSA/Schnorr WASM module)
const initVsSchnorrWasm = (async () => {
    try {
        debugLog("Starting vs_schnorr_wasm module import...");

        // Import the vs_schnorr_wasm module as ES6 module
        const vsSchnorrWasmModule = await import('./vs_schnorr_wasm.js');
        debugLog("vs_schnorr_wasm module imported successfully");

        // Initialize the WASM module with proper path
        debugLog("Initializing Schnorr WASM binary...");
        await vsSchnorrWasmModule.default('./vs_schnorr_wasm_bg.wasm');
        debugLog("vs_schnorr_wasm WASM binary initialized successfully");

        // Verify classes are available
        if (!vsSchnorrWasmModule.Keyshare || !vsSchnorrWasmModule.KeyExportSession) {
            throw new Error("Required Schnorr WASM classes (Keyshare, KeyExportSession) not found in module");
        }

        // Set up the module classes
        window.vsSchnorrWasmModule = {
            Keyshare: vsSchnorrWasmModule.Keyshare,
            KeyExportSession: vsSchnorrWasmModule.KeyExportSession,
            Message: vsSchnorrWasmModule.Message,
            SignSession: vsSchnorrWasmModule.SignSession,
            KeygenSession: vsSchnorrWasmModule.KeygenSession
        };

        debugLog("vs_schnorr_wasm classes configured successfully");
        debugLog(`Available Schnorr classes: ${Object.keys(window.vsSchnorrWasmModule).join(', ')}`);
        return window.vsSchnorrWasmModule;
    } catch (error) {
        debugLog(`vs_schnorr_wasm initialization failed: ${error.message}`);
        debugLog(`Error stack: ${error.stack}`);
        debugLog("Note: vs_schnorr_wasm is optional for EdDSA/Schnorr processing");
        return null;
    }
})();

// Wait for all three WASM modules to initialize
Promise.all([initMainWasm, initVsWasm, initVsSchnorrWasm])
    .then((results) => {
        const [mainResult, vsResult, vsSchnorrResult] = results;
        if (mainResult) {
            debugLog("Main WASM module initialized successfully");
        }
        if (vsResult) {
            debugLog("vs_wasm module initialized successfully");
        } else {
            debugLog("vs_wasm module failed to initialize - continuing without it");
        }
        if (vsSchnorrResult) {
            debugLog("vs_schnorr_wasm module initialized successfully");
        } else {
            debugLog("vs_schnorr_wasm module failed to initialize - continuing without it");
        }
        debugLog("Application initialization complete");
        hideLoader();
    })
    .catch(err => {
        debugLog(`WASM initialization error: ${err}`);
        // Try to continue with just the main WASM module
        initMainWasm.then(() => {
            debugLog("Continuing with main WASM only");
            hideLoader();
        }).catch(mainErr => {
            debugLog(`Critical error - main WASM failed: ${mainErr}`);
            document.querySelector('.loader-container').innerHTML = 
                `<div style="color: var(--error-color);">Error loading application: ${mainErr}</div>`;
        });
    });



function addFileInput() {
    const container = document.getElementById('fileInputs');
    const groupDiv = document.createElement('div');
    groupDiv.className = 'file-group';
    groupDiv.id = `fileGroup${fileGroupCounter}`;

    groupDiv.innerHTML = `
        <div class="input-wrapper">
            <input type="file" accept=".bak,.vult" class="file-input" />
            <input type="password" placeholder="Password (optional)" class="password-input" />
        </div>
        <button class="btn remove-file-btn" onclick="removeFileInput(${fileGroupCounter})">
            <span class="btn-icon">×</span>
        </button>
    `;

    container.appendChild(groupDiv);
    fileGroupCounter++;
    debugLog(`Added new file input group ${fileGroupCounter}`);
}

function removeFileInput(id) {
    const element = document.getElementById(`fileGroup${id}`);
    if (element) {
        element.remove();
        debugLog(`Removed file input group ${id}`);
    }
}

// Make functions globally available for HTML onclick handlers
window.addFileInput = addFileInput;
window.removeFileInput = removeFileInput;
window.recoverKeys = recoverKeys;
window.toggleSection = toggleSection;
window.checkBalance = checkBalance;
window.copyToClipboard = copyToClipboard;

// Parse and decrypt vault container following the reference implementation pattern
async function parseAndDecryptVault(fileData, password) {
    debugLog("Starting vault container parsing and decryption...");

    try {
        // Step 1: Try to decode as base64 if it's a string
        let vaultContainerData = fileData;
        try {
            const base64String = new TextDecoder().decode(fileData);
            const decoded = fromBase64(base64String);
            if (decoded.length > 100) {
                vaultContainerData = decoded;
                debugLog("Successfully decoded base64 vault container data");
            }
        } catch (e) {
            debugLog("Not base64 encoded, using raw data");
        }

        // Step 2: Parse as VaultContainer (encrypted vault)
        let vaultContainer;
        try {
            vaultContainer = parseVaultContainer(vaultContainerData);
            debugLog(`Parsed VaultContainer - version: ${vaultContainer.version}, encrypted: ${vaultContainer.isEncrypted}`);
        } catch (error) {
            debugLog(`Failed to parse as VaultContainer: ${error.message}`);
            throw new Error("Could not parse file as VaultContainer");
        }

        // Step 3: Handle both encrypted and unencrypted vaults
        let vaultData;
        if (vaultContainer.isEncrypted) {
            // Step 4a: Decrypt the vault using password
            try {
                const encryptedVaultBytes = fromBase64(vaultContainer.vault);
                vaultData = await decryptWithAesGcm({
                    key: password,
                    value: encryptedVaultBytes
                });
                debugLog(`Successfully decrypted vault, ${vaultData.length} bytes`);
            } catch (error) {
                debugLog(`Decryption failed: ${error.message}`);
                throw new Error(`Failed to decrypt vault: ${error.message}`);
            }
        } else {
            // Step 4b: Use vault data directly (unencrypted)
            try {
                vaultData = fromBase64(vaultContainer.vault);
                debugLog(`Using unencrypted vault data, ${vaultData.length} bytes`);
            } catch (error) {
                debugLog(`Failed to decode unencrypted vault: ${error.message}`);
                throw new Error(`Failed to decode unencrypted vault: ${error.message}`);
            }
        }

        // Step 5: Parse the vault protobuf to extract keyshare
        let vault;
        try {
            vault = parseVault(vaultData);
            debugLog(`Parsed vault: ${vault.name}, keyshares: ${vault.keyShares.length}, libType: ${vault.libType}`);
        } catch (error) {
            debugLog(`Failed to parse vault protobuf: ${error.message}`);
            throw new Error("Could not parse vault protobuf");
        }

        // Step 6: Extract keyshare data for DKLS
        if (vault.keyShares.length === 0) {
            throw new Error("No keyshares found in vault");
        }

        // For DKLS, we need the keyshare string (which should be hex or base64 encoded)
        const keyshareString = vault.keyShares[0].keyshare;
        if (!keyshareString) {
            throw new Error("No keyshare data found");
        }

        debugLog(`Found keyshare string: ${keyshareString.length} characters`);
        // debugLog(`Keyshare preview: ${keyshareString.substring(0, 100)}...`); // REMOVED: Sensitive data logging

        // Try to decode the keyshare string as hex first, then base64
        let keyshareData;
        try {
            if (/^[0-9a-fA-F]+$/.test(keyshareString.trim())) {
                // Hex encoded
                const hexStr = keyshareString.trim();
                keyshareData = new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
                debugLog(`Decoded keyshare from hex, length: ${keyshareData.length}`);
            } else if (/^[A-Za-z0-9+/]+=*$/.test(keyshareString.trim())) {
                // Base64 encoded
                keyshareData = fromBase64(keyshareString.trim());
                debugLog(`Decoded keyshare from base64, length: ${keyshareData.length}`);
            } else {
                // Use raw string bytes as fallback
                keyshareData = new TextEncoder().encode(keyshareString);
                debugLog(`Using raw keyshare string bytes, length: ${keyshareData.length}`);
            }
        } catch (e) {
            // Use raw string bytes as fallback
            keyshareData = new TextEncoder().encode(keyshareString);
            debugLog(`Decoding failed, using raw string bytes, length: ${keyshareData.length}`);
        }

        if (keyshareData.length < 100) {
            throw new Error("Keyshare data too small, likely invalid");
        }

        debugLog(`Successfully extracted keyshare data, length: ${keyshareData.length} bytes`);
        // debugLog(`First 32 bytes: ${Array.from(keyshareData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`); // REMOVED: Sensitive data logging

        return keyshareData;

    } catch (error) {
        debugLog(`Vault parsing failed: ${error.message}`);
        throw new Error(`Failed to parse vault: ${error.message}`);
    }
}

// New function to process DKLS files and return structured JSON (same format as GG20)
async function processDKLSWithJSON(files, passwords, fileNames) {
    debugLog("Starting DKLS processing with structured JSON output to extract both ECDSA and EdDSA keys...");

    if (files.length < 2) {
        throw new Error("DKLS requires at least 2 keyshare files.");
    }

    // Check that both WASM modules are available
    if (!window.vsWasmModule || !window.vsSchnorrWasmModule) {
        throw new Error("Both ECDSA and EdDSA WASM modules are required for DKLS processing. Please reload the page.");
    }

    const ecdsaModule = window.vsWasmModule;
    const eddsaModule = window.vsSchnorrWasmModule;
    
    if (!ecdsaModule.Keyshare || !ecdsaModule.KeyExportSession) {
        throw new Error("ECDSA WASM classes not properly initialized");
    }
    
    if (!eddsaModule.Keyshare || !eddsaModule.KeyExportSession) {
        throw new Error("EdDSA WASM classes not properly initialized");
    }

    // Parse vault infos
    const vaultInfos = [];
    for (let i = 0; i < files.length; i++) {
        debugLog(`Pre-processing file ${i + 1}: ${fileNames[i]}`);
        const password = passwords[i] || "";

        try {
            // Parse and decrypt vault container to get vault info
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
                    key: password,
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
        } catch (error) {
            debugLog(`Failed to parse file ${i + 1}: ${error.message}`);
            throw new Error(`Failed to parse vault ${i + 1}: ${error.message}`);
        }
    }

    // Helper function to extract private key using a specific WASM module (reused from processDKLSWithWASM)
    async function extractPrivateKeyWithModule(module, moduleType) {
        debugLog(`Starting ${moduleType} key extraction for JSON processing...`);
        
        // Use explicit module references instead of shared destructuring to avoid naming conflicts
        let KeyExportSessionClass, KeyshareClass;
        if (moduleType === "ECDSA") {
            KeyExportSessionClass = window.vsWasmModule.KeyExportSession;
            KeyshareClass = window.vsWasmModule.Keyshare;
            debugLog(`Using ECDSA-specific classes from vs_wasm module`);
        } else if (moduleType === "EdDSA") {
            KeyExportSessionClass = window.vsSchnorrWasmModule.KeyExportSession;
            KeyshareClass = window.vsSchnorrWasmModule.Keyshare;
            debugLog(`Using EdDSA-specific classes from vs_schnorr_wasm module`);
        } else {
            throw new Error(`Unknown module type: ${moduleType}`);
        }
        
        // Verify classes exist
        if (!KeyExportSessionClass || !KeyshareClass) {
            const error = `${moduleType} WASM classes not available (KeyExportSession: ${!!KeyExportSessionClass}, Keyshare: ${!!KeyshareClass})`;
            debugLog(error);
            if (moduleType === "EdDSA") {
                return {
                    failed: true,
                    error: error,
                    moduleType: moduleType
                };
            } else {
                throw new Error(error);
            }
        }
        
        // Use distinct variable names for each algorithm to prevent cross-contamination
        const algorithmKeyshares = [];
        const algorithmKeyIds = [];
        
        // Extract keyshare data and create WASM keyshares
        for (let i = 0; i < files.length; i++) {
            debugLog(`Extracting keyshare data from file ${i + 1} for ${moduleType}: ${fileNames[i]}`);
            const password = passwords[i] || "";

            try {
                const keyshareData = await parseAndDecryptVault(files[i], password);
                debugLog(`Extracted keyshare data for file ${i + 1}, length: ${keyshareData.length} bytes`);

                // Use distinct data copy for each module to prevent cross-contamination
                const keyshareDataCopy = new Uint8Array(keyshareData);
                debugLog(`Creating ${moduleType} keyshare from isolated data copy`);

                // Use explicit class reference, not shared destructured variable
                const algorithmKeyshare = KeyshareClass.fromBytes(keyshareDataCopy);
                if (!algorithmKeyshare) {
                    if (moduleType === "EdDSA") {
                        debugLog(`${moduleType} keyshare creation failed for file ${i + 1} - this may be expected for certain vault types`);
                        debugLog(`EdDSA KeyshareClass.fromBytes returned null/undefined - keyshare data may not contain EdDSA format`);
                        // For EdDSA, continue with next file or return failure object if no keyshares work
                        continue;
                    } else {
                        throw new Error(`Failed to create ${moduleType} keyshare from file ${i + 1}`);
                    }
                }

                algorithmKeyshares.push(algorithmKeyshare);
                debugLog(`Successfully created ${moduleType} keyshare ${i + 1} using explicit class reference`);

                // Get the key ID for this keyshare
                let algorithmKeyId;
                try {
                    algorithmKeyId = algorithmKeyshare.keyId();
                    if (!algorithmKeyId) {
                        throw new Error(`keyId() returned null/undefined`);
                    }
                } catch (keyIdError) {
                    debugLog(`Error getting keyId: ${keyIdError.message}`);
                    throw new Error(`Failed to get key ID for ${moduleType} keyshare ${i + 1}: ${keyIdError.message}`);
                }

                // Convert keyId to string
                let algorithmKeyIdStr;
                if (algorithmKeyId instanceof Uint8Array) {
                    algorithmKeyIdStr = Array.from(algorithmKeyId).map(b => b.toString(16).padStart(2, '0')).join('');
                } else if (typeof algorithmKeyId === 'string') {
                    algorithmKeyIdStr = algorithmKeyId;
                } else {
                    algorithmKeyIdStr = String(algorithmKeyId);
                }

                algorithmKeyIds.push(algorithmKeyIdStr);
                debugLog(`Created ${moduleType} keyshare ${i + 1} with ID: ${algorithmKeyIdStr}`);

            } catch (error) {
                debugLog(`Error processing file ${i + 1} for ${moduleType}: ${error.message}`);
                if (moduleType === "EdDSA") {
                    debugLog(`${moduleType} processing failed for file ${i + 1}, continuing with next file...`);
                    // For EdDSA, log the error but continue trying other files
                    continue;
                } else {
                    throw new Error(`Failed to process file ${fileNames[i]} for ${moduleType}: ${error.message}`);
                }
            }
        }

        if (algorithmKeyshares.length === 0) {
            if (moduleType === "EdDSA") {
                debugLog(`No valid ${moduleType} keyshares were created - returning failure object`);
                return {
                    failed: true,
                    error: `No valid ${moduleType} keyshares were created`,
                    moduleType: moduleType
                };
            } else {
                throw new Error(`No valid ${moduleType} keyshares were created`);
            }
        }

        debugLog(`Successfully created ${algorithmKeyshares.length} ${moduleType} keyshares`);
        
        const algorithmPartyIds = algorithmKeyshares.map((_, index) => `party${index + 1}`);
        debugLog(`Using ${moduleType} party IDs: ${algorithmPartyIds.join(', ')}`);
        
        // Create session using explicit class reference
        let algorithmSession;
        try {
            debugLog(`Creating ${moduleType} session with first keyshare and party IDs using explicit class...`);
            algorithmSession = KeyExportSessionClass.new(algorithmKeyshares[0], algorithmPartyIds);
            if (!algorithmSession) {
                throw new Error(`${moduleType} KeyExportSession.new returned null/undefined`);
            }
            debugLog(`${moduleType} session created successfully using explicit class reference`);
        } catch (sessionError) {
            debugLog(`${moduleType} session creation failed: ${sessionError.message}`);
            if (moduleType === "EdDSA") {
                debugLog(`${moduleType} session creation failed - returning failure object`);
                return {
                    failed: true,
                    error: `Failed to create ${moduleType} KeyExportSession: ${sessionError.message}`,
                    moduleType: moduleType
                };
            } else {
                throw new Error(`Failed to create ${moduleType} KeyExportSession: ${sessionError.message}`);
            }
        }

        // Get setup message
        debugLog(`Getting ${moduleType} setup message...`);
        let algorithmSetupMessage;
        try {
            algorithmSetupMessage = algorithmSession.setup;
            if (!algorithmSetupMessage) {
                throw new Error(`${moduleType} setup property returned null/undefined`);
            }
            debugLog(`${moduleType} setup message obtained, length: ${algorithmSetupMessage.length} bytes`);
        } catch (setupError) {
            debugLog(`${moduleType} setup message retrieval failed: ${setupError.message}`);
            if (moduleType === "EdDSA") {
                debugLog(`${moduleType} setup message retrieval failed - returning failure object`);
                return {
                    failed: true,
                    error: `Failed to get ${moduleType} setup message: ${setupError.message}`,
                    moduleType: moduleType
                };
            } else {
                throw new Error(`Failed to get ${moduleType} setup message: ${setupError.message}`);
            }
        }

        // Process remaining keyshares
        debugLog(`Processing remaining ${moduleType} keyshares...`);
        for (let i = 1; i < algorithmKeyshares.length; i++) {
            debugLog(`Processing ${moduleType} keyshare ${i + 1} with party ID: ${algorithmPartyIds[i]}...`);
            
            try {
                let algorithmMessage;
                try {
                    // Use explicit class reference for exportShare
                    algorithmMessage = KeyExportSessionClass.exportShare(algorithmSetupMessage, algorithmPartyIds[i], algorithmKeyshares[i]);
                    debugLog(`${moduleType} exportShare call completed for keyshare ${i + 1}`);
                } catch (exportError) {
                    debugLog(`${moduleType} exportShare call failed: ${exportError.message}`);
                    throw exportError;
                }

                if (!algorithmMessage || !algorithmMessage.body) {
                    throw new Error(`${moduleType} exportShare returned invalid message for keyshare ${i + 1}`);
                }

                const algorithmMessageBody = algorithmMessage.body;
                debugLog(`${moduleType} keyshare ${i + 1} exported message, length: ${algorithmMessageBody.length} bytes`);

                const isComplete = algorithmSession.inputMessage(algorithmMessageBody);
                debugLog(`${moduleType} message ${i + 1} processed, session complete: ${isComplete}`);

            } catch (shareError) {
                debugLog(`Error processing ${moduleType} keyshare ${i + 1}: ${shareError.message}`);
                if (moduleType === "EdDSA") {
                    debugLog(`${moduleType} keyshare ${i + 1} processing failed - returning failure object`);
                    return {
                        failed: true,
                        error: `Failed to process ${moduleType} keyshare ${i + 1}: ${shareError.message}`,
                        moduleType: moduleType
                    };
                } else {
                    throw new Error(`Failed to process ${moduleType} keyshare ${i + 1}: ${shareError.message}`);
                }
            }
        }

        // Extract private key
        debugLog(`Finishing ${moduleType} session to extract private key...`);
        let algorithmPrivateKeyBytes;
        try {
            debugLog(`Calling algorithmSession.finish() for ${moduleType}...`);
            algorithmPrivateKeyBytes = algorithmSession.finish();
            debugLog(`${moduleType} session.finish() returned:`, algorithmPrivateKeyBytes);
            debugLog(`${moduleType} privateKeyBytes type: ${typeof algorithmPrivateKeyBytes}`);
            if (algorithmPrivateKeyBytes) {
                debugLog(`${moduleType} privateKeyBytes length: ${algorithmPrivateKeyBytes.length}`);
            } else {
                debugLog(`${moduleType} session.finish() returned null/undefined!`);
            }
        } catch (finishError) {
            debugLog(`${moduleType} session finish failed: ${finishError.message}`);
            if (moduleType === "EdDSA") {
                debugLog(`${moduleType} session finish failed - returning failure object`);
                return {
                    failed: true,
                    error: `Failed to finish ${moduleType} DKLS session: ${finishError.message}`,
                    moduleType: moduleType
                };
            } else {
                throw new Error(`Failed to finish ${moduleType} DKLS session: ${finishError.message}`);
            }
        }

        if (!algorithmPrivateKeyBytes || algorithmPrivateKeyBytes.length === 0) {
            const errorMsg = `${moduleType} session finished but returned ${algorithmPrivateKeyBytes === null ? 'null' : algorithmPrivateKeyBytes === undefined ? 'undefined' : 'empty'} private key`;
            debugLog(errorMsg);
            
            if (moduleType === "EdDSA") {
                // For EdDSA, this is a known issue - return a special error object instead of throwing
                debugLog("EdDSA processing failed - this is a known compatibility issue with DKLS keyshares");
                return {
                    failed: true,
                    error: errorMsg,
                    moduleType: "EdDSA"
                };
            } else {
                // For ECDSA, this is unexpected - throw the error
                throw new Error(errorMsg);
            }
        }

        const algorithmPrivateKeyHex = Array.from(algorithmPrivateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        debugLog(`Extracted ${moduleType} private key (${algorithmPrivateKeyBytes.length} bytes)`);
        
        // Also get public key and root chain code for reference using distinct keyshare reference
        const algorithmPublicKeyBytes = algorithmKeyshares[0].publicKey();
        const algorithmPublicKeyHex = Array.from(algorithmPublicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        
        const algorithmRootChainCodeBytes = algorithmKeyshares[0].rootChainCode();
        const algorithmRootChainCodeHex = Array.from(algorithmRootChainCodeBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        
        return {
            privateKeyHex: algorithmPrivateKeyHex,
            publicKeyHex: algorithmPublicKeyHex,
            rootChainCodeHex: algorithmRootChainCodeHex
        };
    }

    try {
        debugLog(`Processing ${files.length} DKLS files to extract both ECDSA and EdDSA keys for JSON processing...`);
        
        // Extract both ECDSA and EdDSA keys from the same keyshares
        debugLog("=== EXTRACTING ECDSA KEY ===");
        const ecdsaResult = await extractPrivateKeyWithModule(ecdsaModule, "ECDSA");
        
        debugLog("=== EXTRACTING EDDSA KEY ===");
        const eddsaResult = await extractPrivateKeyWithModule(eddsaModule, "EdDSA");
        
        // Check if EdDSA processing failed
        let eddsaPrivateKeyHex = "";
        let eddsaProcessingFailed = false;
        
        if (eddsaResult.failed) {
            debugLog(`EdDSA processing failed: ${eddsaResult.error}`);
            debugLog("Continuing with ECDSA-only processing. EdDSA coins (Solana, Sui, TON) will not be available.");
            eddsaProcessingFailed = true;
        } else {
            debugLog("Successfully extracted both ECDSA and EdDSA keys from DKLS keyshares");
            eddsaPrivateKeyHex = eddsaResult.privateKeyHex;
        }
        
        // Use extracted keys
        const privateKeyHex = ecdsaResult.privateKeyHex;
        const publicKeyHex = ecdsaResult.publicKeyHex;
        const rootChainCodeHex = ecdsaResult.rootChainCodeHex;
        
        debugLog("Getting EdDSA public key from vault...");
        const eddsaPublicKey = vaultInfos[0] ? vaultInfos.find(v => v.publicKeyEddsa)?.publicKeyEddsa || '' : '';
        if (eddsaPublicKey) {
            debugLog(`EdDSA Public Key from vault: ${eddsaPublicKey}`);
        } else {
            debugLog("No EdDSA public key found in vault");
        }

        // Now call the new ProcessDKLSFileContentJSON function with both extracted keys
        debugLog("Calling ProcessDKLSFileContentJSON function with both ECDSA and EdDSA keys...");
        
        // Check if the new JSON function is available
        if (!window.ProcessDKLSFileContentJSON) {
            throw new Error("ProcessDKLSFileContentJSON function not available. Please reload the page.");
        }

        const jsonResult = window.ProcessDKLSFileContentJSON(files, passwords, fileNames, privateKeyHex, rootChainCodeHex, eddsaPublicKey, eddsaPrivateKeyHex);
        debugLog(`ProcessDKLSFileContentJSON result: ${jsonResult}`);
        
        let resultData;
        try {
            resultData = JSON.parse(jsonResult);
            debugLog("Successfully parsed ProcessDKLSFileContentJSON result:", resultData);
        } catch (parseError) {
            debugLog(`Error parsing ProcessDKLSFileContentJSON result: ${parseError.message}`);
            throw new Error(`Failed to parse ProcessDKLSFileContentJSON result: ${parseError.message}`);
        }

        if (!resultData.success) {
            debugLog(`ProcessDKLSFileContentJSON failed: ${resultData.error}`);
            throw new Error(`DKLS processing failed: ${resultData.error}`);
        }

        // Display results using the structured JSON approach (same as GG20)
        debugLog("Displaying DKLS results using structured JSON format...");
        displayJSONResults(resultData);

        debugLog("DKLS JSON processing completed successfully");

    } catch (error) {
        const errorMsg = error.message || error || "Unknown error";
        debugLog(`DKLS JSON processing error: ${errorMsg}`);
        throw new Error(`DKLS JSON processing failed: ${errorMsg}`);
    }
}

async function recoverKeys() {
    const fileGroups = document.querySelectorAll('.file-group');
    const files = [];
    const passwords = [];
    const fileNames = [];

    try {
        for (let fileGroup of fileGroups) {
            const fileInput = fileGroup.querySelector('.file-input');
            const passwordInput = fileGroup.querySelector('.password-input');

            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];

                if (fileNames.includes(file.name)) {
                    debugLog(`Duplicate file detected: ${file.name}`);
                }

                const fileData = await file.arrayBuffer();
                files.push(new Uint8Array(fileData));
                passwords.push(passwordInput.value || "");
                fileNames.push(file.name); // Store the filename
            }
        }

        if (files.length === 0) {
            debugLog("Please select at least one file to process.");
            return;
        }

        // Check which scheme is selected
        const selectedScheme = document.querySelector('input[name="scheme"]:checked').value;
        debugLog(`Selected scheme: ${selectedScheme}`);

        if (selectedScheme === 'dkls') {
            debugLog("Processing with DKLS scheme using structured JSON...");
            await processDKLSWithJSON(files, passwords, fileNames);
        } else {
            // Use the new JSON-enabled Go WASM processing for GG20 or auto-detect
            debugLog("Processing with Go WASM (GG20/auto-detect) using JSON...");
            await processWithJSONWASM(files, passwords, fileNames);
        }

    } catch (error) {
        displayResults(`Error: ${error.message}`);
        debugLog(`Error in recoverKeys: ${error.message}`);
    }
}

// New function to process files using JSON-enabled WASM functions
async function processWithJSONWASM(files, passwords, fileNames) {
    try {
        debugLog("Calling ProcessFilesJSON function...");
        
        // Check if JSON function is available
        if (!window.ProcessFilesJSON) {
            throw new Error("ProcessFilesJSON function not available. Please reload the page.");
        }

        const jsonResult = window.ProcessFilesJSON(files, passwords, fileNames);
        debugLog(`Raw JSON result: ${jsonResult}`);

        let resultData;
        try {
            resultData = JSON.parse(jsonResult);
            debugLog("Successfully parsed JSON result:", resultData);
            debugLog("JSON result keys:", Object.keys(resultData));
            debugLog("JSON result structure:", JSON.stringify(resultData, null, 2));
        } catch (parseError) {
            debugLog(`Error parsing JSON: ${parseError.message}`);
            debugLog("Falling back to string display");
            displayResults(jsonResult);
            return;
        }

        if (!resultData.success) {
            debugLog(`Processing failed: ${resultData.error}`);
            displayResults(`Error: ${resultData.error}`);
            return;
        }

        // Display results using the new JSON data structure
        displayJSONResults(resultData);

    } catch (error) {
        debugLog(`Error in processWithJSONWASM: ${error.message}`);
        displayResults(`Error: ${error.message}`);
    }
}

// Function to display results from JSON data structure
function displayJSONResults(resultData) {
    debugLog("Displaying JSON results:", resultData);
    debugLog("Available keys in resultData:", Object.keys(resultData));
    
    // Clear all sections first
    hideAllResultSections();
    
    // Display each section with structured data
    displayShareDetails(resultData.shareDetails || resultData.share_details);
    displayPublicKeys(resultData.publicKeys || resultData.public_keys);
    displayRootKeyInfo(resultData.rootKeyInfo || resultData.root_key_info);
    displayCoinKeys(resultData.coinKeys || resultData.coin_keys);
    
    debugLog("Results displayed successfully");
}

function hideAllResultSections() {
    const sections = ['shareDetailsSection', 'publicKeysSection', 'rootKeySection', 'coinKeysSection'];
    sections.forEach(sectionId => {
        const section = document.getElementById(sectionId);
        if (section) {
            section.style.display = 'none';
        }
    });
}

function displayShareDetails(shareDetails) {
    debugLog("Share details found:", shareDetails);
    
    if (!shareDetails || shareDetails.length === 0) {
        debugLog("No share details found");
        return;
    }
    
    let html = '';
    shareDetails.forEach((shareDetail, index) => {
        debugLog("Processing share detail:", shareDetail);
        html += `
            <div class="share-detail-card">
                <h4>Share ${index + 1}</h4>
                <div class="detail-item">
                    <span class="detail-label">Backup Name:</span>
                    <span class="detail-value">${shareDetail.backupName || shareDetail.backup_name || 'N/A'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">This Share:</span>
                    <span class="detail-value">${shareDetail.thisShare || shareDetail.this_share || 'N/A'}</span>
                </div>
                <div class="detail-item">
                    <span class="detail-label">All Shares:</span>
                    <span class="detail-value">${(shareDetail.allShares || shareDetail.all_shares || []).join(', ')}</span>
                </div>
            </div>
        `;
    });
    
    document.getElementById('shareDetailsContent').innerHTML = html;
    document.getElementById('shareDetailsSection').style.display = 'block';
}

function displayPublicKeys(publicKeys) {
    debugLog("Public keys found:", publicKeys);
    
    if (!publicKeys || (!publicKeys.ecdsa && !publicKeys.eddsa)) {
        debugLog("No public keys found");
        return;
    }
    
    let html = '';
    
    if (publicKeys.ecdsa) {
        html += `
            <div class="key-item">
                <div class="key-label">ECDSA Public Key</div>
                <div class="key-value copyable" onclick="copyToClipboard('${publicKeys.ecdsa}', event)">
                    ${publicKeys.ecdsa}
                    <span class="copy-icon">📋</span>
                </div>
            </div>
        `;
    }
    
    if (publicKeys.eddsa) {
        html += `
            <div class="key-item">
                <div class="key-label">EdDSA Public Key</div>
                <div class="key-value copyable" onclick="copyToClipboard('${publicKeys.eddsa}', event)">
                    ${publicKeys.eddsa}
                    <span class="copy-icon">📋</span>
                </div>
            </div>
        `;
    }
    
    // Add balance check button if ECDSA key is available
    if (publicKeys.ecdsa) {
        html += `
            <div class="action-buttons">
                <button class="btn check-balance-btn" onclick="checkBalance('${publicKeys.ecdsa}', '${publicKeys.eddsa || ''}')">
                    Check Airdrop Balance
                </button>
            </div>
            <div id="balanceDisplay"></div>
        `;
    }
    
    document.getElementById('publicKeysContent').innerHTML = html;
    document.getElementById('publicKeysSection').style.display = 'block';
}

function displayRootKeyInfo(rootKeyInfo) {
    debugLog("Root key info found:", rootKeyInfo);
    
    if (!rootKeyInfo) {
        debugLog("No root key info found");
        return;
    }
    
    let html = '';
    
    if (rootKeyInfo.chainCode || rootKeyInfo.chain_code) {
        html += `
            <div class="key-item sensitive">
                <div class="key-label">Chain Code</div>
                <div class="key-value copyable" onclick="copyToClipboard('${rootKeyInfo.chainCode || rootKeyInfo.chain_code}', event)">
                    ${rootKeyInfo.chainCode || rootKeyInfo.chain_code}
                    <span class="copy-icon">📋</span>
                </div>
            </div>
        `;
    }
    
    if (rootKeyInfo.extendedPrivKey || rootKeyInfo.extendedPrivateKey || rootKeyInfo.extended_private_key) {
        const extPrivKey = rootKeyInfo.extendedPrivKey || rootKeyInfo.extendedPrivateKey || rootKeyInfo.extended_private_key;
        html += `
            <div class="key-item sensitive">
                <div class="key-label">Extended Private Key</div>
                <div class="key-value copyable" onclick="copyToClipboard('${extPrivKey}', event)">
                    ${extPrivKey}
                    <span class="copy-icon">📋</span>
                </div>
            </div>
        `;
    }
    
    if (rootKeyInfo.hexPubKeyECDSA || rootKeyInfo.hex_pub_key_ecdsa) {
        html += `
            <div class="key-item">
                <div class="key-label">ECDSA Root Public Key</div>
                <div class="key-value copyable" onclick="copyToClipboard('${rootKeyInfo.hexPubKeyECDSA || rootKeyInfo.hex_pub_key_ecdsa}', event)">
                    ${rootKeyInfo.hexPubKeyECDSA || rootKeyInfo.hex_pub_key_ecdsa}
                    <span class="copy-icon">📋</span>
                </div>
            </div>
        `;
    }
    
    if (rootKeyInfo.hexPrivKeyECDSA || rootKeyInfo.hex_priv_key_ecdsa) {
        html += `
            <div class="key-item sensitive">
                <div class="key-label">ECDSA Root Private Key</div>
                <div class="key-value copyable" onclick="copyToClipboard('${rootKeyInfo.hexPrivKeyECDSA || rootKeyInfo.hex_priv_key_ecdsa}', event)">
                    ${rootKeyInfo.hexPrivKeyECDSA || rootKeyInfo.hex_priv_key_ecdsa}
                    <span class="copy-icon">📋</span>
                </div>
            </div>
        `;
    }
    
    document.getElementById('rootKeyContentInner').innerHTML = html;
    document.getElementById('rootKeySection').style.display = 'block';
}

// Cryptocurrency icon mapping with smart fallback system
function getCryptoIcon(coinName) {
    // Explicit mapping for special cases (aliases, edge cases, non-standard naming)
    const iconMap = {
        'bitcoincash': 'bitcoin-cash.png',  // Special naming case
        'atom': 'cosmos.png',               // Alias mapping
        'cosmos': 'cosmos.png',             // Alias mapping
        'terraclassic': 'luna-classic.png', // Special naming case
        'luna': 'luna-classic.png'          // Alias mapping
    };
    
    const name = coinName.toLowerCase().replace(/[^a-z]/g, '');
    
    // Try explicit mapping first (for special cases)
    if (iconMap[name]) {
        return `<img src="icons/${iconMap[name]}" class="crypto-icon" alt="${coinName}" />`;
    }
    
    // Smart fallback: try auto-generated filename {coinname}.png
    // This makes the system automatically work for new coins that follow naming convention
    const autoIconFile = `${name}.png`;
    const fallbackId = `fallback-${name}-${Date.now()}`; // Unique ID for fallback element
    
    return `<img src="icons/${autoIconFile}" 
                 class="crypto-icon" 
                 alt="${coinName}"
                 onerror="this.style.display='none'; document.getElementById('${fallbackId}').style.display='inline';" />
            <span id="${fallbackId}" class="crypto-icon-fallback" style="display:none;">🪙</span>`;
}

function displayCoinKeys(coinKeys) {
    debugLog("Coin keys found:", coinKeys);
    
    if (!coinKeys || coinKeys.length === 0) {
        debugLog("No coin keys found");
        return;
    }
    
    let html = '';
    
    coinKeys.forEach((coinKey, index) => {
        debugLog("Processing coin key:", coinKey);
        
        const coinName = coinKey.name || coinKey.coin_name || "Unknown";
        const address = coinKey.address || "N/A";
        const derivePath = coinKey.derivePath || coinKey.derive_path || "";
        const icon = getCryptoIcon(coinName);
        
        // Create expandable coin card
        const coinId = `coin-${index}`;
        html += `
            <div class="coin-card">
                <div class="coin-header" onclick="toggleSection('${coinId}-details')">
                    <div class="coin-title">
                        <div class="coin-name-row">
                            <span class="coin-icon">${icon}</span>
                            <span class="coin-name">${coinName}</span>
                        </div>
                        ${address !== 'N/A' ? `<div class="coin-address">${address}</div>` : ''}
                    </div>
                    <span class="toggle-arrow">▼</span>
                </div>
                <div id="${coinId}-details" class="coin-details content" style="display: none;">
        `;
        
        // Add derivation path in details
        if (derivePath) {
            html += `
                <div class="key-item">
                    <div class="key-label">Derivation Path</div>
                    <div class="key-value">
                        ${derivePath}
                    </div>
                </div>
            `;
        }
        
        // Add coin details
        if (coinKey.address) {
            html += `
                <div class="key-item">
                    <div class="key-label">Address</div>
                    <div class="key-value copyable" onclick="copyToClipboard('${coinKey.address}', event)">
                        ${coinKey.address}
                        <span class="copy-icon">📋</span>
                    </div>
                </div>
            `;
        }
        
        if (coinKey.hexPrivateKey || coinKey.hex_private_key) {
            html += `
                <div class="key-item sensitive">
                    <div class="key-label">Private Key (Hex)</div>
                    <div class="key-value copyable" onclick="copyToClipboard('${coinKey.hexPrivateKey || coinKey.hex_private_key}', event)">
                        ${coinKey.hexPrivateKey || coinKey.hex_private_key}
                        <span class="copy-icon">📋</span>
                    </div>
                </div>
            `;
        }
        
        if (coinKey.wifPrivateKey || coinKey.wif_private_key) {
            html += `
                <div class="key-item sensitive">
                    <div class="key-label">WIF Private Key</div>
                    <div class="key-value copyable" onclick="copyToClipboard('${coinKey.wifPrivateKey || coinKey.wif_private_key}', event)">
                        ${coinKey.wifPrivateKey || coinKey.wif_private_key}
                        <span class="copy-icon">📋</span>
                    </div>
                </div>
            `;
        }
        
        if (coinKey.hexPublicKey || coinKey.hex_public_key) {
            html += `
                <div class="key-item">
                    <div class="key-label">Public Key (Hex)</div>
                    <div class="key-value copyable" onclick="copyToClipboard('${coinKey.hexPublicKey || coinKey.hex_public_key}', event)">
                        ${coinKey.hexPublicKey || coinKey.hex_public_key}
                        <span class="copy-icon">📋</span>
                    </div>
                </div>
            `;
        }
        
        if (coinKey.extendedPrivateKey || coinKey.extended_private_key) {
            html += `
                <div class="key-item sensitive">
                    <div class="key-label">Extended Private Key</div>
                    <div class="key-value copyable" onclick="copyToClipboard('${coinKey.extendedPrivateKey || coinKey.extended_private_key}', event)">
                        ${coinKey.extendedPrivateKey || coinKey.extended_private_key}
                        <span class="copy-icon">📋</span>
                    </div>
                </div>
            `;
        }
        
        if (coinKey.additionalInfo || coinKey.additional_info) {
            html += `
                <div class="key-item">
                    <div class="key-label">Additional Information</div>
                    <div class="key-value">
                        ${(coinKey.additionalInfo || coinKey.additional_info).replace(/\n/g, '<br>')}
                    </div>
                </div>
            `;
        }
        
        html += `
                </div>
            </div>
        `;
    });
    
    document.getElementById('coinKeysContent').innerHTML = html;
    document.getElementById('coinKeysSection').style.display = 'block';
}

// Helper function to format derived keys from JSON data
function formatDerivedKeysFromJSON(jsonKeysData) {
    let output = "";
    
    // Add root key information
    if (jsonKeysData.rootKeyInfo) {
        const rootInfo = jsonKeysData.rootKeyInfo;
        output += `\nhex encoded root pubkey(ECDSA): ${rootInfo.hexPubKeyECDSA}\n`;
        output += `\nhex encoded root privkey(ECDSA): ${rootInfo.hexPrivKeyECDSA}\n`;
        output += `\nchaincode: ${rootInfo.chainCode}\n`;
        output += `\nextended private key full: ${rootInfo.extendedPrivateKey}\n`;
    }
    
    // Add ECDSA coins
    if (jsonKeysData.ecdsaKeys && jsonKeysData.ecdsaKeys.length > 0) {
        for (const coinKey of jsonKeysData.ecdsaKeys) {
            output += `\nRecovering ${coinKey.name} key....\n`;
            if (coinKey.extendedPrivateKey) {
                output += `\nprivate key for ${coinKey.name}: ${coinKey.extendedPrivateKey}\n`;
            }
            if (coinKey.hexPrivateKey) {
                output += `\nhex encoded non-hardened private key for ${coinKey.name}:${coinKey.hexPrivateKey}\n`;
            }
            if (coinKey.hexPublicKey) {
                output += `\nhex encoded non-hardened public key for ${coinKey.name}:${coinKey.hexPublicKey}\n`;
            }
            if (coinKey.address) {
                output += `\naddress:${coinKey.address}\n`;
            }
            if (coinKey.wifPrivateKey) {
                output += `\nWIF private key for ${coinKey.name}: ${coinKey.wifPrivateKey}\n`;
            }
        }
    }
    
    // Add EdDSA coins
    if (jsonKeysData.eddsaKeys && jsonKeysData.eddsaKeys.length > 0) {
        for (const coinKey of jsonKeysData.eddsaKeys) {
            output += `\nRecovering ${coinKey.name} key....\n`;
            if (coinKey.hexPrivateKey) {
                output += `\nhex encoded Ed25519 private key for ${coinKey.name}:${coinKey.hexPrivateKey}\n`;
            }
            if (coinKey.hexPublicKey) {
                output += `\nhex encoded Ed25519 public key for ${coinKey.name}:${coinKey.hexPublicKey}\n`;
            }
            if (coinKey.address) {
                output += `\n${coinKey.name} address:${coinKey.address}\n`;
            }
        }
    }
    
    return output;
}

function parseOutput(rawOutput) {
    const decoded = {
        PrivateKeys: {},
        Addresses: {},
        WIFPrivateKeys: {},
        ShareDetails: '',
        PublicKeyECDSA: '',
        PublicKeyEDDSA: ''
    };

    // Split the output into lines
    const lines = rawOutput.split('\n');
    let currentChain = '';

    for (const line of lines) {
        const trimmedLine = line.trim();

        // Parse backup details
        if (trimmedLine.startsWith('Backup name:') || 
            trimmedLine.startsWith('This Share:') || 
            trimmedLine.startsWith('All Shares:')) {
            decoded.ShareDetails += trimmedLine + '\n';
        }

        // Parse Public Keys
        if (trimmedLine.startsWith('Public Key(ECDSA):')) {
            decoded.PublicKeyECDSA = trimmedLine.split(':')[1].trim();
        } else if (trimmedLine.startsWith('Public Key(EdDSA):')) {
            decoded.PublicKeyEDDSA = trimmedLine.split(':')[1].trim();
        }

        // Track current chain context
        if (trimmedLine.startsWith('Recovering') && trimmedLine.endsWith('key....')) {
            currentChain = trimmedLine
                .replace('Recovering ', '')
                .replace(' key....', '')
                .trim()
                .toLowerCase();
        }

        // Parse WIF private keys
        if (trimmedLine.startsWith('WIF private key for')) {
            const parts = trimmedLine.lastIndexOf(':');
            if (parts !== -1) {
                const chainFull = trimmedLine
                    .substring('WIF private key for '.length, parts)
                    .trim()
                    .toLowerCase();
                const privateKey = trimmedLine.substring(parts + 1).trim();
                decoded.WIFPrivateKeys[chainFull] = privateKey;
            }
            continue;
        }

        // Parse private keys
        if (trimmedLine.startsWith('hex encoded private key for') || 
            trimmedLine.startsWith('hex encoded non-hardened private key for') ||
            trimmedLine.startsWith('hex encoded Ed25519 private key for')) {
            
            let chain;
            let privateKey;
            
            if (trimmedLine.startsWith('hex encoded private key for')) {
                const afterPrefix = trimmedLine.replace('hex encoded private key for ', '');
                const colonIndex = afterPrefix.indexOf(':');
                if (colonIndex !== -1) {
                    chain = afterPrefix.substring(0, colonIndex).trim().toLowerCase();
                    privateKey = afterPrefix.substring(colonIndex + 1).split(' ')[0].trim(); // Take only the hex part before any notes
                }
            } else if (trimmedLine.startsWith('hex encoded non-hardened private key for')) {
                const afterPrefix = trimmedLine.replace('hex encoded non-hardened private key for ', '');
                const colonIndex = afterPrefix.indexOf(':');
                if (colonIndex !== -1) {
                    chain = afterPrefix.substring(0, colonIndex).trim().toLowerCase();
                    privateKey = afterPrefix.substring(colonIndex + 1).split(' ')[0].trim(); // Take only the hex part before any notes
                }
            } else if (trimmedLine.startsWith('hex encoded Ed25519 private key for')) {
                const afterPrefix = trimmedLine.replace('hex encoded Ed25519 private key for ', '');
                const colonIndex = afterPrefix.indexOf(':');
                if (colonIndex !== -1) {
                    chain = afterPrefix.substring(0, colonIndex).trim().toLowerCase();
                    privateKey = afterPrefix.substring(colonIndex + 1).split(' ')[0].trim(); // Take only the hex part before any notes
                }
            }
            
            if (chain && privateKey) {
                decoded.PrivateKeys[chain] = privateKey;
            }
        }

        // Parse addresses - handle both generic and specific formats
        if (trimmedLine.includes('address:')) {
            const colonIndex = trimmedLine.lastIndexOf(':');
            if (colonIndex !== -1) {
                const address = trimmedLine.substring(colonIndex + 1).trim();
                
                if (trimmedLine.startsWith('ethereum address:')) {
                    decoded.Addresses['ethereum'] = address;
                } else if (trimmedLine.startsWith('solana address:')) {
                    decoded.Addresses['solana'] = address;
                } else if (trimmedLine.startsWith('sui address:')) {
                    decoded.Addresses['sui'] = address;
                } else if (trimmedLine.startsWith('ton address:')) {
                    decoded.Addresses['ton'] = address;
                } else if (trimmedLine.startsWith('address:') && currentChain) {
                    decoded.Addresses[currentChain] = address;
                } else {
                    // Try to extract chain name from the address line itself
                    const words = trimmedLine.split(/\s+/);
                    for (let i = 0; i < words.length - 1; i++) {
                        if (words[i + 1] === 'address:') {
                            const chainName = words[i].toLowerCase();
                            decoded.Addresses[chainName] = address;
                            break;
                        }
                    }
                }
            }
        }
    }

    return decoded;
}

// Function to display the parsed results
function displayResults(result) {
    const resultDiv = document.getElementById('results');
    resultDiv.innerHTML = ''; // Clear previous results

    if (typeof result === 'string' && result.toLowerCase().includes('error')) {
        resultDiv.innerHTML = `<div class="error-message">${result}</div>`;
        debugLog(`Error in results: ${result}`);
        return;
    }

    function addCopyButton(text) {
        return `<span class="copy-icon" onclick="copyToClipboard('${text.replace(/'/g, "\\'")}', event)">📋</span>`;
    }

    const parsed = parseOutput(result);

    // Create results HTML
    let html = `
        <h2>Results</h2>
        <div class="result-section">
            <h3>Share Details</h3>
            <pre>${parsed.ShareDetails}</pre>
        </div>`;

    if (parsed.PublicKeyECDSA || parsed.PublicKeyEDDSA) {
        html += `
            <div class="result-section">
                <h3>Public Keys</h3>
                ${parsed.PublicKeyECDSA ? `<pre>ECDSA: ${parsed.PublicKeyECDSA}</pre>` : ''}
                ${parsed.PublicKeyEDDSA ? `<pre>EdDSA: ${parsed.PublicKeyEDDSA} </pre>` : ''}
                <button class="btn check-balance-btn" onclick="checkBalance('${parsed.PublicKeyECDSA}', '${parsed.PublicKeyEDDSA}')">
                    Check Airdrop Balance
                </button>
                <pre id="balanceDisplay"></pre>
            </div>`;
    }

    if (Object.keys(parsed.WIFPrivateKeys).length > 0) {
        html += `
            <div class="result-section">
                <h3>WIF Private Keys</h3>
                ${Object.entries(parsed.WIFPrivateKeys)
                    .map(([chain, key]) => `
                        <div class="copy-wrapper">
                            <pre>${chain}:${key} ${addCopyButton(key)}</pre>
                        </div>`)
                    .join('')}
            </div>`;
    }
    if (Object.keys(parsed.PrivateKeys).length > 0) {
        html += `
            <div class="result-section">
                <h3>Private Keys</h3>
                ${Object.entries(parsed.PrivateKeys)
                    .map(([chain, key]) => `
                        <div class="copy-wrapper">
                            <pre>${chain}: ${key} ${addCopyButton(key)}</pre>
                        </div>`)
                    .join('')}
            </div>`;
    }
    if (Object.keys(parsed.Addresses).length > 0) {
        html += `
            <div class="result-section">
                <h3>Addresses</h3>
                ${Object.entries(parsed.Addresses)
                    .map(([chain, address]) => `
                        <div class="copy-wrapper">
                            <pre>${chain}: ${address} ${addCopyButton(address)}</pre>
                        </div>`)
                    .join('')}
            </div>`;
    }


    resultDiv.innerHTML = html;
    debugLog('Results displayed successfully');
}

function toggleSection(sectionId) {
    const content = document.getElementById(sectionId);
    const arrow = content.previousElementSibling.querySelector('.toggle-arrow');

    if (content.style.display === "block") {
        content.style.display = "none";
        arrow.style.transform = "rotate(0deg)";
    } else {
        content.style.display = "block";
        arrow.style.transform = "rotate(180deg)";
    }
}

async function checkBalance(ecdsaKey, eddsaKey) {
    const display = document.getElementById('balanceDisplay');
    const button = event.target;

    try {
        // Show loading state
        button.disabled = true;
        button.textContent = 'Checking...';
        display.style.display = 'block';
        display.textContent = 'Fetching balance...';

        const response = await fetch(`https://airdrop.vultisig.com/api/vault/${ecdsaKey}/${eddsaKey}`);
        const data = await response.json();

        // Show result with animation
        if (!data || data.balance === undefined) {
            display.textContent = 'Not registered for the airdrop. Sign up for the airdrop here: https://airdrop.vultisig.com/';
        } else {
            display.textContent = `Airdrop Balance: ${data.balance}`;
        }
        display.classList.add('show');
    } catch (error) {
        display.textContent = 'Error fetching balance';
    } finally {
        // Reset button
        button.disabled = false;
        button.textContent = 'Check Airdrop Balance';
    }
}

function copyToClipboard(text, event) {
    event.stopPropagation();
    navigator.clipboard.writeText(text).then(() => {
        // Get the clicked element directly
        const btn = event.currentTarget;
        const originalText = btn.textContent;
        btn.textContent = '✓';
        setTimeout(() => {
            btn.textContent = '📋';
        }, 1000);
    }).catch(err => {
        //console.error('Failed to copy:', err);
    });
}