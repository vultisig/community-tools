package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// EncryptWithPassword encrypts data using AES-256-GCM with a password
// This is used to generate test vectors for the JavaScript implementation
func EncryptWithPassword(plaintext []byte, password string) (string, error) {
	// Hash the password to create a key
	hash := sha256.Sum256([]byte(password))
	key := hash[:]

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	// Use GCM (Galois/Counter Mode)
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext
	// gcm.Seal appends the ciphertext and auth tag to the nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	// Encode as base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}
