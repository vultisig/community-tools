package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// Test helper to generate test vectors for JavaScript tests
func TestGenerateTestVectors(t *testing.T) {
	testCases := []struct {
		password  string
		plaintext string
	}{
		{"mypassword", "helloworld"},
		{"test123", "test data"},
		{"SecurePassword123!", "This is a longer test message."},
	}

	t.Log("Generated test vectors for JavaScript AES-GCM tests:")
	t.Log("Copy these into your JavaScript test file:")
	t.Log("")

	for _, tc := range testCases {
		// Hash the password to create a key
		hash := sha256.Sum256([]byte(tc.password))
		key := hash[:]

		// Create AES cipher
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("Failed to create cipher: %v", err)
		}

		// Use GCM mode
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatalf("Failed to create GCM: %v", err)
		}

		// Generate random nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatalf("Failed to generate nonce: %v", err)
		}

		// Encrypt - gcm.Seal appends ciphertext+tag to nonce
		ciphertext := gcm.Seal(nonce, nonce, []byte(tc.plaintext), nil)

		// Encode to base64
		encoded := base64.StdEncoding.EncodeToString(ciphertext)

		t.Logf("{ password: '%s', data: '%s', expected: '%s' },", tc.password, encoded, tc.plaintext)
	}
}

// Test that DecryptWithPassword works correctly
func TestDecryptWithPassword(t *testing.T) {
	password := "testpassword123"
	plaintext := "hello from go!"

	// Encrypt using the helper
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("Failed to create GCM: %v", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("Failed to generate nonce: %v", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	// Now decrypt using DecryptWithPassword
	decrypted, err := DecryptWithPassword([]byte(encoded), password)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != plaintext {
		t.Errorf("Decrypted text doesn't match. Got: %s, Expected: %s", string(decrypted), plaintext)
	}
}
