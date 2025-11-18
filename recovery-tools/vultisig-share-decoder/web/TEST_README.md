# AES-GCM Decryption Test Suite

## Overview

This test suite verifies the AES-256-GCM decryption implementation in `aes_gcm.js` with comprehensive coverage including:

- **Cross-language compatibility** with Go backend encryption
- **Input type handling** (base64 strings and Uint8Array)
- **Error handling** (invalid inputs, corrupted data, wrong passwords)
- **Output validation** (correct plaintext, proper byte lengths)

## Test Results

✅ **24 tests passing**
- 3 Go-generated test vectors (proves Go ↔ JavaScript compatibility)
- 3 Node.js-generated test vectors (algorithm verification)
- 5 input type validation tests
- 7 error handling tests
- 2 key handling tests
- 2 output format tests
- 2 base64 utility tests

## Key Format Compatibility

### UTF-8 Password Format (Used by this implementation)
- **Password**: UTF-8 string (e.g., `"mypassword"`)
- **Key Derivation**: `SHA-256(password)` → 32-byte key
- **Compatible with**: Go backend encryption (`internal/utils/encryption.go`)
- **Use case**: User vault encryption with passwords

### Binary Key Format (vultisig-windows SDK)
- **Key**: Raw binary data (often hex-encoded)
- **Key Derivation**: None (binary key used directly)
- **Compatible with**: TypeScript SDK, vultisig-windows repo
- **Use case**: Encryption with pre-derived keys

**Note**: The vultisig-windows reference test (`key='d6022ef...'`) uses the binary key format, which differs from our UTF-8 password approach. This is documented in the test file.

## Test Vector Generation

### Go-Generated Vectors
Generated using `recovery-tools/vultisig-share-decoder/generate_vectors.go`:
```bash
cd recovery-tools/vultisig-share-decoder
go run generate_vectors.go
```

This ensures the JavaScript decryption works with actual Go-encrypted data.

### Node.js-Generated Vectors
Generated using `web/generate_test_vectors.js`:
```bash
cd recovery-tools/vultisig-share-decoder/web
node generate_test_vectors.js
```

Uses the same algorithm (SHA-256 password hashing + AES-256-GCM) to verify consistency.

## Running Tests

```bash
cd recovery-tools/vultisig-share-decoder/web
npm install
npm test
```

For watch mode during development:
```bash
npm run test:watch
```

## Encryption Format

All encrypted data follows this structure:
```
[12-byte nonce][ciphertext][16-byte auth tag]
```

- **Nonce**: Random 12-byte initialization vector (IV)
- **Ciphertext**: Encrypted plaintext
- **Auth Tag**: 16-byte GCM authentication tag

Total minimum size: 28 bytes (12 + 0 + 16 for empty plaintext)

## Security Notes

- **SHA-256 key derivation**: Converts variable-length passwords to 256-bit keys
- **GCM mode**: Provides authenticated encryption (confidentiality + integrity)
- **Proper validation**: Rejects short data, invalid types, and corrupted ciphertext
- **Error messages**: Clear without leaking sensitive information
