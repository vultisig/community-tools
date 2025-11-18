/**
 * AES-GCM Decryption Tests
 * 
 * This test suite covers two key formats:
 * 
 * 1. UTF-8 Password Format (default, used by this implementation and Go backend):
 *    - Password is a UTF-8 string (e.g., "mypassword")
 *    - Password is hashed with SHA-256 to create the 32-byte encryption key
 *    - Used by: Go backend encryption, this JavaScript implementation
 * 
 * 2. Binary Key Format (used by vultisig-windows SDK):
 *    - Key is provided as raw binary data (often hex-encoded, e.g., "d6022ef...")
 *    - The binary key is used directly (NOT hashed)
 *    - Used by: vultisig-windows repo, TypeScript SDK
 * 
 * Note: The vultisig-windows reference test case uses format #2 (binary keys),
 * while our implementation uses format #1 (UTF-8 passwords). This is intentional
 * as our use case matches the Go backend which encrypts vaults with user passwords.
 * 
 * If binary key support is needed, the decryptWithAesGcm function would need to
 * accept an optional parameter to skip password hashing for binary keys.
 */

import { describe, expect, it } from 'vitest'
import { decryptWithAesGcm, fromBase64 } from './aes_gcm.js'

if (typeof global !== 'undefined' && !global.crypto) {
  const { webcrypto } = await import('crypto')
  Object.defineProperty(global, 'crypto', {
    value: webcrypto,
    writable: false,
    configurable: true
  })
}

describe('fromBase64', () => {
  it('should convert base64 string to Uint8Array', () => {
    const base64 = 'SGVsbG8gV29ybGQ='
    const result = fromBase64(base64)
    
    expect(result).toBeInstanceOf(Uint8Array)
    const decoded = new TextDecoder().decode(result)
    expect(decoded).toBe('Hello World')
  })

  it('should handle empty base64 string', () => {
    const result = fromBase64('')
    expect(result).toBeInstanceOf(Uint8Array)
    expect(result.length).toBe(0)
  })
})

describe('decryptWithAesGcm', () => {
  describe('Cross-language compatibility (Go backend encrypted data)', () => {
    it('should decrypt Go-encrypted test vector 1', async () => {
      const password = 'gotest1'
      const encrypted = '6cOGrenCvMlL6ochrS5k+Erdk9q/nX0ujS+8BTTqLydTFp3794G77VE='
      
      const decryptedData = await decryptWithAesGcm({
        key: password,
        value: encrypted
      })
      
      expect(decryptedData).toBeInstanceOf(Uint8Array)
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe('hello from go')
    })

    it('should decrypt Go-encrypted test vector 2', async () => {
      const password = 'gotest2'
      const encrypted = 'ZekBwVd0MoHtHoO85GhpAxM9COplKmodTk4lcytpNiUn1uwywuhz9VDxQQ=='
      
      const decryptedData = await decryptWithAesGcm({
        key: password,
        value: encrypted
      })
      
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe('cross-lang test')
    })

    it('should decrypt Go-encrypted test vector 3', async () => {
      const password = 'gotest3'
      const encrypted = 'VcqeEn7h2K8eu2BVNtYcvsHG2FUyJo0aSOHZgu5bXDsTwSuSFEox9/+g61Ol7KRfrDFI/vSjK0ubX4kW'
      
      const decryptedData = await decryptWithAesGcm({
        key: password,
        value: encrypted
      })
      
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe('Go-to-JS compatibility verified!')
    })
  })

  describe('UTF-8 password decryption (Node.js generated)', () => {
    it('should decrypt data encrypted with UTF-8 password', async () => {
      const password = 'mypassword'
      const encrypted = 'TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q='
      
      const decryptedData = await decryptWithAesGcm({
        key: password,
        value: encrypted
      })
      
      expect(decryptedData).toBeInstanceOf(Uint8Array)
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe('helloworld')
    })

    it('should decrypt test data 2', async () => {
      const password = 'test123'
      const encrypted = 'qwByQe0iLP0XY2jTN55S65peEzSJBzwiQAwcin52tbYc/h1Dlw=='
      
      const decryptedData = await decryptWithAesGcm({
        key: password,
        value: encrypted
      })
      
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe('test data')
    })

    it('should decrypt longer test message', async () => {
      const password = 'SecurePassword123!'
      const encrypted = 'XOHOR39GexbA73dOCgn75POtLj6aeqCbyRYnlXEQIWdrWIvwES4lG+7ajNUDjKy6bikImogGL8995g=='
      
      const decryptedData = await decryptWithAesGcm({
        key: password,
        value: encrypted
      })
      
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe('This is a longer test message.')
    })
  })

  describe('input type handling', () => {
    const testKey = 'mypassword'
    const testData = 'TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q='
    const expectedText = 'helloworld'

    it('should accept base64 string input', async () => {
      const decryptedData = await decryptWithAesGcm({
        key: testKey,
        value: testData
      })
      
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe(expectedText)
    })

    it('should accept Uint8Array input', async () => {
      const bytes = fromBase64(testData)
      const decryptedData = await decryptWithAesGcm({
        key: testKey,
        value: bytes
      })
      
      const text = new TextDecoder().decode(decryptedData)
      expect(text).toBe(expectedText)
    })

    it('should reject invalid input types', async () => {
      await expect(
        decryptWithAesGcm({
          key: testKey,
          value: 12345
        })
      ).rejects.toThrow(TypeError)
      
      await expect(
        decryptWithAesGcm({
          key: testKey,
          value: 12345
        })
      ).rejects.toThrow('value must be a Uint8Array or base64 string')
    })

    it('should reject null input', async () => {
      await expect(
        decryptWithAesGcm({
          key: testKey,
          value: null
        })
      ).rejects.toThrow(TypeError)
    })

    it('should reject undefined input', async () => {
      await expect(
        decryptWithAesGcm({
          key: testKey,
          value: undefined
        })
      ).rejects.toThrow(TypeError)
    })
  })

  describe('error handling', () => {
    const validKey = 'mypassword'

    it('should reject data that is too short (less than 28 bytes)', async () => {
      const shortData = new Uint8Array(27)
      
      await expect(
        decryptWithAesGcm({
          key: validKey,
          value: shortData
        })
      ).rejects.toThrow('encrypted data too short')
    })

    it('should reject data with exactly 27 bytes', async () => {
      const shortData = new Uint8Array(27)
      
      await expect(
        decryptWithAesGcm({
          key: validKey,
          value: shortData
        })
      ).rejects.toThrow('minimum 28 bytes')
    })

    it('should reject base64 data that decodes to less than 28 bytes', async () => {
      const shortBase64 = btoa('short')
      
      await expect(
        decryptWithAesGcm({
          key: validKey,
          value: shortBase64
        })
      ).rejects.toThrow('encrypted data too short')
    })

    it('should fail gracefully with wrong password', async () => {
      const data = 'TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q='
      const wrongKey = 'wrongpassword'
      
      await expect(
        decryptWithAesGcm({
          key: wrongKey,
          value: data
        })
      ).rejects.toThrow('AES-GCM decryption failed')
    })

    it('should fail with corrupted ciphertext', async () => {
      const data = fromBase64('TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q=')
      data[15] ^= 0xFF
      
      await expect(
        decryptWithAesGcm({
          key: validKey,
          value: data
        })
      ).rejects.toThrow('AES-GCM decryption failed')
    })

    it('should fail with corrupted auth tag', async () => {
      const data = fromBase64('TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q=')
      data[data.length - 1] ^= 0xFF
      
      await expect(
        decryptWithAesGcm({
          key: validKey,
          value: data
        })
      ).rejects.toThrow('AES-GCM decryption failed')
    })

    it('should accept minimum valid length (28 bytes)', async () => {
      const minData = new Uint8Array(28)
      
      await expect(
        decryptWithAesGcm({
          key: validKey,
          value: minData
        })
      ).rejects.toThrow('AES-GCM decryption failed')
    })
  })

  describe('key handling', () => {
    const testData = 'TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q='

    it('should work with UTF-8 passwords', async () => {
      const password = 'mypassword'
      
      const decrypted = await decryptWithAesGcm({
        key: password,
        value: testData
      })
      
      const text = new TextDecoder().decode(decrypted)
      expect(text).toBe('helloworld')
    })

    it('should hash the password to create encryption key', async () => {
      const shortPassword = 'test'
      const longPassword = 'this is a very long password with many characters'
      
      const bytes = fromBase64(testData)
      
      await expect(
        decryptWithAesGcm({ key: shortPassword, value: bytes })
      ).rejects.toThrow('AES-GCM decryption failed')
      
      await expect(
        decryptWithAesGcm({ key: longPassword, value: bytes })
      ).rejects.toThrow('AES-GCM decryption failed')
    })
  })

  describe('output format', () => {
    it('should return Uint8Array', async () => {
      const key = 'mypassword'
      const data = 'TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q='
      
      const result = await decryptWithAesGcm({ key, value: data })
      
      expect(result).toBeInstanceOf(Uint8Array)
    })

    it('should return correct byte length', async () => {
      const key = 'mypassword'
      const data = 'TT0iL2KccbhfIhYmj6uR2Af8rW9oxJg0qBAQqMoiOS5Jw5fYH2Q='
      
      const result = await decryptWithAesGcm({ key, value: data })
      
      expect(result.length).toBe(10)
    })
  })
})
