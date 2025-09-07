let fileGroupCounter = 1;

function hideLoader() {
    document.getElementById('loader').style.display = 'none';
    document.getElementById('content').style.display = 'block';
    debugLog("UI initialized and ready");
}

function debugLog(message) {
    const debugOutput = document.getElementById('debugOutput');
    const timestamp = new Date().toISOString();
    debugOutput.innerHTML += `${timestamp}: ${message}\n`;
}

// Import vanilla JS protobuf functions
import { parseVaultContainer, parseVault, LibType } from './vault_pb.js';
import { decryptWithAesGcm, fromBase64 } from './aes_gcm.js';

// Initialize WASM modules
const go = new Go();

// Initialize main.wasm (Go WASM)
const initMainWasm = WebAssembly.instantiateStreaming(fetch("main.wasm"), go.importObject)
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

// Wait for both WASM modules to initialize
Promise.all([initMainWasm, initVsWasm])
    .then((results) => {
        const [mainResult, vsResult] = results;
        if (mainResult) {
            debugLog("Main WASM module initialized successfully");
        }
        if (vsResult) {
            debugLog("vs_wasm module initialized successfully");
        } else {
            debugLog("vs_wasm module failed to initialize - continuing without it");
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
        debugLog(`Keyshare preview: ${keyshareString.substring(0, 100)}...`);

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
        debugLog(`First 32 bytes: ${Array.from(keyshareData.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join(' ')}`);

        return keyshareData;

    } catch (error) {
        debugLog(`Vault parsing failed: ${error.message}`);
        throw new Error(`Failed to parse vault: ${error.message}`);
    }
}

async function processDKLSWithWASM(files, passwords, fileNames) {
    if (!window.vsWasmModule) {
        throw new Error("DKLS WASM module not available. Please reload the page.");
    }

    debugLog("Starting DKLS processing with vs_wasm...");
    const { KeyExportSession, Keyshare } = window.vsWasmModule;

    if (!Keyshare || !KeyExportSession) {
        throw new Error("WASM classes not properly initialized");
    }

    if (files.length < 2) {
        throw new Error("DKLS requires at least 2 keyshare files.");
    }

    try {
        debugLog(`Processing ${files.length} DKLS files...`);
        const keyshares = [];
        const keyIds = [];

        // Process each vault file and extract vault info
        const vaultInfos = [];
        
        for (let i = 0; i < files.length; i++) {
            debugLog(`Processing file ${i + 1}: ${fileNames[i]}`);
            const password = passwords[i] || "";

            try {
                // Parse and decrypt vault container first to get vault info
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
                
                // Store vault info for later use
                vaultInfos.push({
                    name: vault.name || fileNames[i],
                    localPartyId: vault.localPartyId || `party${i + 1}`,
                    resharePrefix: vault.resharePrefix || '',
                    filename: fileNames[i],
                    publicKeyEddsa: vault.publicKeyEddsa || ''
                });

                // Parse and decrypt vault container for keyshare data
                const keyshareData = await parseAndDecryptVault(files[i], password);
                debugLog(`Extracted keyshare data for file ${i + 1}, length: ${keyshareData.length} bytes`);

                // Create Keyshare from extracted keyshare data
                debugLog(`Creating WASM Keyshare object for file ${i + 1}...`);
                const keyshare = Keyshare.fromBytes(keyshareData);

                if (!keyshare) {
                    throw new Error(`Failed to create keyshare from file ${i + 1}`);
                }

                keyshares.push(keyshare);
                debugLog(`Successfully created keyshare ${i + 1}`);

                // Get the key ID for this keyshare
                let keyId;
                try {
                    keyId = keyshare.keyId();
                    if (!keyId) {
                        throw new Error(`keyId() returned null/undefined`);
                    }
                    debugLog(`Raw keyId type: ${typeof keyId}, value: ${keyId}`);
                } catch (keyIdError) {
                    debugLog(`Error getting keyId: ${keyIdError.message}`);
                    throw new Error(`Failed to get key ID for keyshare ${i + 1}: ${keyIdError.message}`);
                }

                // Convert keyId to string
                let keyIdStr;
                if (keyId instanceof Uint8Array) {
                    keyIdStr = Array.from(keyId).map(b => b.toString(16).padStart(2, '0')).join('');
                } else if (typeof keyId === 'string') {
                    keyIdStr = keyId;
                } else {
                    keyIdStr = String(keyId);
                }

                keyIds.push(keyIdStr);
                debugLog(`Created keyshare ${i + 1} with ID: ${keyIdStr}`);

            } catch (error) {
                debugLog(`Error processing file ${i + 1}: ${error.message}`);
                throw new Error(`Failed to process file ${fileNames[i]}: ${error.message}`);
            }
        }

        if (keyshares.length === 0) {
            throw new Error("No valid keyshares were created");
        }

        debugLog(`Successfully created ${keyshares.length} keyshares`);
        
        // Verify all keyshares have the same key ID (they should be shares of the same key)
        const firstKeyId = keyIds[0];
        for (let i = 1; i < keyIds.length; i++) {
            if (keyIds[i] !== firstKeyId) {
                debugLog(`Key ID mismatch - Share 1: ${firstKeyId}, Share ${i + 1}: ${keyIds[i]}`);
            }
        }

        debugLog("Creating KeyExportSession...");
        debugLog(`Using key IDs: ${keyIds.join(', ')}`);

        // Create the export session with the first keyshare and all party IDs as strings
        // Use simple string party IDs instead of trying to use hex key IDs
        const partyIds = keyshares.map((_, index) => `party${index + 1}`);
        debugLog(`Using party IDs: ${partyIds.join(', ')}`);
        
        let session;
        try {
            debugLog("Creating session with first keyshare and party IDs...");
            session = KeyExportSession.new(keyshares[0], partyIds);
            if (!session) {
                throw new Error("KeyExportSession.new returned null/undefined");
            }
            debugLog("Session created successfully");
        } catch (sessionError) {
            debugLog(`Session creation failed: ${sessionError.message}`);
            throw new Error(`Failed to create KeyExportSession: ${sessionError.message}`);
        }

        debugLog("Getting setup message...");
        let setupMessage;
        try {
            setupMessage = session.setup;
            if (!setupMessage) {
                throw new Error("setup property returned null/undefined");
            }
            debugLog(`Setup message obtained, length: ${setupMessage.length} bytes`);
        } catch (setupError) {
            debugLog(`Setup message retrieval failed: ${setupError.message}`);
            throw new Error(`Failed to get setup message: ${setupError.message}`);
        }
        if (!setupMessage) {
            throw new Error("Failed to get setup message");
        }

        debugLog(`Setup message length: ${setupMessage.length} bytes`);

        // Process remaining keyshares to extract encrypted material
        debugLog("Processing remaining keyshares...");
        for (let i = 1; i < keyshares.length; i++) {
            debugLog(`Processing keyshare ${i + 1} with party ID: ${partyIds[i]}...`);
            
            try {
                // Export the encrypted material from this keyshare using party ID
                debugLog(`Calling exportShare with setup length: ${setupMessage.length}, party ID: "${partyIds[i]}", keyshare type: ${typeof keyshares[i]}`);
                
                let message;
                try {
                    message = KeyExportSession.exportShare(setupMessage, partyIds[i], keyshares[i]);
                    debugLog(`exportShare call completed for keyshare ${i + 1}`);
                } catch (exportError) {
                    debugLog(`exportShare call failed: ${exportError.message}`);
                    debugLog(`Error type: ${exportError.constructor.name}`);
                    debugLog(`Error stack: ${exportError.stack}`);
                    throw exportError;
                }

                if (!message) {
                    throw new Error(`exportShare returned null for keyshare ${i + 1}`);
                }

                if (!message.body) {
                    throw new Error(`exportShare returned message without body for keyshare ${i + 1}`);
                }

                const messageBody = message.body;
                debugLog(`Keyshare ${i + 1} exported message, length: ${messageBody.length} bytes`);

                // Input the encrypted message to the session
                const isComplete = session.inputMessage(messageBody);
                debugLog(`Message ${i + 1} processed, session complete: ${isComplete}`);

            } catch (shareError) {
                debugLog(`Error processing keyshare ${i + 1}: ${shareError.message}`);
                throw new Error(`Failed to process keyshare ${i + 1}: ${shareError.message}`);
            }
        }

        debugLog("Finishing session to extract private key...");
        let privateKeyBytes;
        try {
            privateKeyBytes = session.finish();
        } catch (finishError) {
            debugLog(`Session finish failed: ${finishError.message}`);
            throw new Error(`Failed to finish DKLS session: ${finishError.message}`);
        }

        if (!privateKeyBytes || privateKeyBytes.length === 0) {
            throw new Error("Session finished but returned empty private key");
        }

        const privateKeyHex = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        debugLog(`Extracted private key: ${privateKeyHex}... (${privateKeyBytes.length} bytes)`);

        debugLog("Getting public key...");
        const publicKeyBytes = keyshares[0].publicKey();
        const publicKeyHex = Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        debugLog("Getting EdDSA public key from vault...");
        const eddsaPublicKey = vaultInfos[0] ? vaultInfos.find(v => v.publicKeyEddsa)?.publicKeyEddsa || '' : '';
        if (eddsaPublicKey) {
            debugLog(`EdDSA Public Key: ${eddsaPublicKey}`);
        } else {
            debugLog("No EdDSA public key found in vault");
        }

        debugLog("Getting root chain code...");
        const rootChainCodeBytes = keyshares[0].rootChainCode();
        const rootChainCodeHex = Array.from(rootChainCodeBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        debugLog(`Root Chain Code: ${rootChainCodeHex}`);

        // Call the new JSON WASM function to derive keys for all supported coins
        debugLog("Calling WASM DeriveAndShowKeysJSON function...");
        let derivedKeysOutput = "";
        let jsonKeysData = null;
        
        try {
            if (window.DeriveAndShowKeysJSON) {
                debugLog("Using JSON version of DeriveAndShowKeys");
                const jsonResult = window.DeriveAndShowKeysJSON(privateKeyHex, rootChainCodeHex, "", eddsaPublicKey);
                debugLog(`JSON result: ${jsonResult}`);
                
                try {
                    jsonKeysData = JSON.parse(jsonResult);
                    if (jsonKeysData.success) {
                        derivedKeysOutput = formatDerivedKeysFromJSON(jsonKeysData);
                    } else {
                        derivedKeysOutput = `\nError deriving keys: ${jsonKeysData.error}`;
                    }
                } catch (parseError) {
                    debugLog(`Error parsing JSON result: ${parseError.message}`);
                    derivedKeysOutput = jsonResult; // Fall back to raw output
                }
            } else if (window.DeriveAndShowKeys) {
                debugLog("Using string version of DeriveAndShowKeys (fallback)");
                derivedKeysOutput = window.DeriveAndShowKeys(privateKeyHex, rootChainCodeHex);
                debugLog("Successfully derived keys using WASM");
            } else {
                debugLog("DeriveAndShowKeys function not available");
            }
        } catch (wasmError) {
            debugLog(`WASM key derivation error: ${wasmError.message}`);
            derivedKeysOutput = `\nError deriving keys: ${wasmError.message}`;
        }

        // Collect all party IDs from vault info
        const allPartyIds = vaultInfos.map(info => info.localPartyId).sort();
        
        // Create results in GG20 format
        const results = `
${vaultInfos.map((vaultInfo, i) => {
            return `Backup name: ${vaultInfo.filename}
This Share: ${vaultInfo.localPartyId}
All Shares: [${allPartyIds.join(' ')}]`;
        }).join('\n\n')}

Public Key(ECDSA): ${publicKeyHex}
${eddsaPublicKey ? `Public Key(EdDSA): ${eddsaPublicKey}` : ''}

${derivedKeysOutput}
        `.trim();

        debugLog("DKLS processing completed successfully");
        debugLog("Results:\n")
        debugLog(results)
        displayResults(results);

    } catch (error) {
        const errorMsg = error.message || error || "Unknown error";
        debugLog(`DKLS processing error: ${errorMsg}`);
        throw new Error(`DKLS processing failed: ${errorMsg}`);
    }
}

// New function to process DKLS files and return structured JSON (same format as GG20)
async function processDKLSWithJSON(files, passwords, fileNames) {
    if (!window.vsWasmModule) {
        throw new Error("DKLS WASM module not available. Please reload the page.");
    }

    debugLog("Starting DKLS processing with structured JSON output...");
    const { KeyExportSession, Keyshare } = window.vsWasmModule;

    if (!Keyshare || !KeyExportSession) {
        throw new Error("WASM classes not properly initialized");
    }

    if (files.length < 2) {
        throw new Error("DKLS requires at least 2 keyshare files.");
    }

    try {
        debugLog(`Processing ${files.length} DKLS files...`);
        const keyshares = [];
        const keyIds = [];

        // Process each vault file and extract vault info (same as existing function)
        const vaultInfos = [];
        
        for (let i = 0; i < files.length; i++) {
            debugLog(`Processing file ${i + 1}: ${fileNames[i]}`);
            const password = passwords[i] || "";

            try {
                // Parse and decrypt vault container first to get vault info
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
                
                // Store vault info for later use
                vaultInfos.push({
                    name: vault.name || fileNames[i],
                    localPartyId: vault.localPartyId || `party${i + 1}`,
                    resharePrefix: vault.resharePrefix || '',
                    filename: fileNames[i],
                    publicKeyEddsa: vault.publicKeyEddsa || ''
                });

                // Parse and decrypt vault container for keyshare data
                const keyshareData = await parseAndDecryptVault(files[i], password);
                debugLog(`Extracted keyshare data for file ${i + 1}, length: ${keyshareData.length} bytes`);

                // Create Keyshare from extracted keyshare data
                debugLog(`Creating WASM Keyshare object for file ${i + 1}...`);
                const keyshare = Keyshare.fromBytes(keyshareData);

                if (!keyshare) {
                    throw new Error(`Failed to create keyshare from file ${i + 1}`);
                }

                keyshares.push(keyshare);
                debugLog(`Successfully created keyshare ${i + 1}`);

                // Get the key ID for this keyshare
                let keyId;
                try {
                    keyId = keyshare.keyId();
                    if (!keyId) {
                        throw new Error(`keyId() returned null/undefined`);
                    }
                    debugLog(`Raw keyId type: ${typeof keyId}, value: ${keyId}`);
                } catch (keyIdError) {
                    debugLog(`Error getting keyId: ${keyIdError.message}`);
                    throw new Error(`Failed to get key ID for keyshare ${i + 1}: ${keyIdError.message}`);
                }

                // Convert keyId to string
                let keyIdStr;
                if (keyId instanceof Uint8Array) {
                    keyIdStr = Array.from(keyId).map(b => b.toString(16).padStart(2, '0')).join('');
                } else if (typeof keyId === 'string') {
                    keyIdStr = keyId;
                } else {
                    keyIdStr = String(keyId);
                }

                keyIds.push(keyIdStr);
                debugLog(`Created keyshare ${i + 1} with ID: ${keyIdStr}`);

            } catch (error) {
                debugLog(`Error processing file ${i + 1}: ${error.message}`);
                throw new Error(`Failed to process file ${fileNames[i]}: ${error.message}`);
            }
        }

        if (keyshares.length === 0) {
            throw new Error("No valid keyshares were created");
        }

        debugLog(`Successfully created ${keyshares.length} keyshares`);
        
        // Verify all keyshares have the same key ID (they should be shares of the same key)
        const firstKeyId = keyIds[0];
        for (let i = 1; i < keyIds.length; i++) {
            if (keyIds[i] !== firstKeyId) {
                debugLog(`Key ID mismatch - Share 1: ${firstKeyId}, Share ${i + 1}: ${keyIds[i]}`);
            }
        }

        debugLog("Creating KeyExportSession...");
        debugLog(`Using key IDs: ${keyIds.join(', ')}`);

        // Create the export session with the first keyshare and all party IDs as strings
        const partyIds = keyshares.map((_, index) => `party${index + 1}`);
        debugLog(`Using party IDs: ${partyIds.join(', ')}`);
        
        let session;
        try {
            debugLog("Creating session with first keyshare and party IDs...");
            session = KeyExportSession.new(keyshares[0], partyIds);
            if (!session) {
                throw new Error("KeyExportSession.new returned null/undefined");
            }
            debugLog("Session created successfully");
        } catch (sessionError) {
            debugLog(`Session creation failed: ${sessionError.message}`);
            throw new Error(`Failed to create KeyExportSession: ${sessionError.message}`);
        }

        debugLog("Getting setup message...");
        let setupMessage;
        try {
            setupMessage = session.setup;
            if (!setupMessage) {
                throw new Error("setup property returned null/undefined");
            }
            debugLog(`Setup message obtained, length: ${setupMessage.length} bytes`);
        } catch (setupError) {
            debugLog(`Setup message retrieval failed: ${setupError.message}`);
            throw new Error(`Failed to get setup message: ${setupError.message}`);
        }
        if (!setupMessage) {
            throw new Error("Failed to get setup message");
        }

        debugLog(`Setup message length: ${setupMessage.length} bytes`);

        // Process remaining keyshares to extract encrypted material
        debugLog("Processing remaining keyshares...");
        for (let i = 1; i < keyshares.length; i++) {
            debugLog(`Processing keyshare ${i + 1} with party ID: ${partyIds[i]}...`);
            
            try {
                // Export the encrypted material from this keyshare using party ID
                debugLog(`Calling exportShare with setup length: ${setupMessage.length}, party ID: "${partyIds[i]}", keyshare type: ${typeof keyshares[i]}`);
                
                let message;
                try {
                    message = KeyExportSession.exportShare(setupMessage, partyIds[i], keyshares[i]);
                    debugLog(`exportShare call completed for keyshare ${i + 1}`);
                } catch (exportError) {
                    debugLog(`exportShare call failed: ${exportError.message}`);
                    debugLog(`Error type: ${exportError.constructor.name}`);
                    debugLog(`Error stack: ${exportError.stack}`);
                    throw exportError;
                }

                if (!message) {
                    throw new Error(`exportShare returned null for keyshare ${i + 1}`);
                }

                if (!message.body) {
                    throw new Error(`exportShare returned message without body for keyshare ${i + 1}`);
                }

                const messageBody = message.body;
                debugLog(`Keyshare ${i + 1} exported message, length: ${messageBody.length} bytes`);

                // Input the encrypted message to the session
                const isComplete = session.inputMessage(messageBody);
                debugLog(`Message ${i + 1} processed, session complete: ${isComplete}`);

            } catch (shareError) {
                debugLog(`Error processing keyshare ${i + 1}: ${shareError.message}`);
                throw new Error(`Failed to process keyshare ${i + 1}: ${shareError.message}`);
            }
        }

        debugLog("Finishing session to extract private key...");
        let privateKeyBytes;
        try {
            privateKeyBytes = session.finish();
        } catch (finishError) {
            debugLog(`Session finish failed: ${finishError.message}`);
            throw new Error(`Failed to finish DKLS session: ${finishError.message}`);
        }

        if (!privateKeyBytes || privateKeyBytes.length === 0) {
            throw new Error("Session finished but returned empty private key");
        }

        const privateKeyHex = Array.from(privateKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        debugLog(`Extracted private key: ${privateKeyHex}... (${privateKeyBytes.length} bytes)`);

        debugLog("Getting public key...");
        const publicKeyBytes = keyshares[0].publicKey();
        const publicKeyHex = Array.from(publicKeyBytes).map(b => b.toString(16).padStart(2, '0')).join('');

        debugLog("Getting EdDSA public key from vault...");
        const eddsaPublicKey = vaultInfos[0] ? vaultInfos.find(v => v.publicKeyEddsa)?.publicKeyEddsa || '' : '';
        if (eddsaPublicKey) {
            debugLog(`EdDSA Public Key: ${eddsaPublicKey}`);
        } else {
            debugLog("No EdDSA public key found in vault");
        }

        debugLog("Getting root chain code...");
        const rootChainCodeBytes = keyshares[0].rootChainCode();
        const rootChainCodeHex = Array.from(rootChainCodeBytes).map(b => b.toString(16).padStart(2, '0')).join('');
        debugLog(`Root Chain Code: ${rootChainCodeHex}`);

        // Now call the new ProcessDKLSFileContentJSON function with extracted keys
        debugLog("Calling ProcessDKLSFileContentJSON function...");
        
        // Check if the new JSON function is available
        if (!window.ProcessDKLSFileContentJSON) {
            throw new Error("ProcessDKLSFileContentJSON function not available. Please reload the page.");
        }

        const jsonResult = window.ProcessDKLSFileContentJSON(files, passwords, fileNames, privateKeyHex, rootChainCodeHex, eddsaPublicKey);
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
            debugLog("ProcessFilesJSON function not available, falling back to string version");
            const result = window.ProcessFiles(files, passwords, fileNames);
            if (!result || result === "undefined") {
                debugLog("No results were generated. Reload the page and make sure you are using different shares.");
                return;
            }
            displayResults(result);
            return;
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

// Cryptocurrency icon mapping
function getCryptoIcon(coinName) {
    const iconMap = {
        'bitcoin': 'bitcoin.png',
        'bitcoincash': 'bitcoin-cash.png',
        'ethereum': 'ethereum.png',
        'litecoin': 'litecoin.png',
        'dogecoin': 'dogecoin.png',
        'solana': 'solana.png',
        'tron': 'tron.png',
        'sui': 'sui.png',
        'ton': 'ton.png',
        'thorchain': 'thorchain.png',
        'mayachain': 'mayachain.png',
        'atom': 'cosmos.png',
        'cosmos': 'cosmos.png',
        'kujira': 'kujira.png',
        'dydx': 'dydx.png',
        'terra': 'terra.png',
        'terraclassic': 'luna-classic.png',
        'luna': 'luna-classic.png'
    };
    
    const name = coinName.toLowerCase().replace(/[^a-z]/g, '');
    const iconFile = iconMap[name];
    
    if (iconFile) {
        return `<img src="icons/${iconFile}" class="crypto-icon" alt="${coinName}" />`;
    } else {
        // Fallback to generic crypto symbol for unknown coins
        return '<span class="crypto-icon-fallback">🪙</span>';
    }
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
        PublicKeyEDDSA: '',
        RawOutput: rawOutput
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

    html += `
    <div class="result-section">
        <h3 class="toggle-header" onclick="toggleSection('rawOutput')">
        Full Output <span class="toggle-arrow">▼</span> 
        </h3>
        <div class="content" id="rawOutput"">
            <pre class="debug-output">${parsed.RawOutput}</pre>
        </div>
    </div>`

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