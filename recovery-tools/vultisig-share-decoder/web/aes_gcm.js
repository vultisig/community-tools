
/**
 * Convert a base64 string to a Uint8Array
 * @param {string} base64String - The base64 encoded string
 * @returns {Uint8Array} The decoded bytes
 */
export function fromBase64(base64String) {
    const binaryString = atob(base64String);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

/**
 * Decrypt AES-256-GCM data.
 * 
 * Expected format: [12-byte nonce][ciphertext][16-byte auth tag]
 * - Nonce: First 12 bytes (IV for GCM mode)
 * - Ciphertext + Auth Tag: Remaining bytes (WebCrypto expects them concatenated)
 * - Auth Tag: Last 16 bytes (automatically handled by WebCrypto)
 * 
 * The encryption key is derived by SHA-256 hashing the password string,
 * producing a 32-byte (256-bit) key suitable for AES-256-GCM.
 *
 * @param {{ key: string, value: Uint8Array | string }} params
 *   - key: Password string (will be SHA-256 hashed to produce 32-byte key)
 *   - value: Uint8Array or base64 string containing [nonce + ciphertext + tag]
 * @returns {Promise<Uint8Array>} Decrypted plaintext bytes
 * @throws {TypeError} If value is not a Uint8Array or base64 string
 * @throws {Error} If encrypted data is too short (< 28 bytes)
 * @throws {Error} If decryption fails (wrong password, corrupted data, or invalid auth tag)
 * 
 * @example
 * // With Uint8Array
 * const encrypted = new Uint8Array([...]);
 * const plaintext = await decryptWithAesGcm({ key: 'mypassword', value: encrypted });
 * 
 * @example
 * // With base64 string
 * const encrypted = 'lBVUUrBAYm2R6uiESzrgOaaW0GyiOuf2ki6O18YOEBFnQryTj4s=';
 * const plaintext = await decryptWithAesGcm({ key: 'mypassword', value: encrypted });
 * const text = new TextDecoder().decode(plaintext);
 */
export async function decryptWithAesGcm({ key, value }) {
    // Accept base64 string or Uint8Array
    let bytes;
    if (typeof value === 'string') {
        bytes = fromBase64(value);
    } else if (value instanceof Uint8Array) {
        bytes = value;
    } else {
        throw new TypeError('value must be a Uint8Array or base64 string');
    }

    // Minimum length: 12 bytes (nonce) + 16 bytes (auth tag) = 28 bytes
    if (bytes.length < 28) {
        throw new Error('encrypted data too short (minimum 28 bytes: 12-byte nonce + 16-byte auth tag)');
    }

    // 1) Hash password with SHA-256 to produce a 32-byte key (same as Node's createHash)
    const enc = new TextEncoder();
    const pwUtf8 = enc.encode(key);
    const pwHashBuffer = await crypto.subtle.digest('SHA-256', pwUtf8);

    // 2) Import the hash as a raw AES-GCM key for decryption
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        pwHashBuffer,
        { name: 'AES-GCM' },
        false,
        ['decrypt']
    );

    // 3) Extract nonce and ciphertext+tag
    const iv = bytes.subarray(0, 12); // First 12 bytes
    const ciphertextPlusTag = bytes.subarray(12); // Remainder contains ciphertext + 16-byte tag

    // 4) Decrypt
    // Note: WebCrypto expects the auth tag appended to ciphertext
    // tagLength defaults to 128 bits (16 bytes), which matches our format
    const algo = { name: 'AES-GCM', iv: iv };

    let plainBuffer;
    try {
        plainBuffer = await crypto.subtle.decrypt(algo, cryptoKey, ciphertextPlusTag);
    } catch (err) {
        throw new Error('AES-GCM decryption failed: ' + err.message);
    }

    return new Uint8Array(plainBuffer);
}
