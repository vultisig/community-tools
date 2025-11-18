package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func main() {
	testCases := []struct {
		password  string
		plaintext string
	}{
		{"gotest1", "hello from go"},
		{"gotest2", "cross-lang test"},
		{"gotest3", "Go-to-JS compatibility verified!"},
	}

	fmt.Println("// Go-generated test vectors for cross-language verification")
	fmt.Println()

	for _, tc := range testCases {
		// Hash the password to create a key (same as DecryptWithPassword)
		hash := sha256.Sum256([]byte(tc.password))
		key := hash[:]

		// Create AES cipher
		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Use GCM mode
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Generate random nonce
		nonce := make([]byte, 12) // GCM standard nonce size
		if _, err := rand.Read(nonce); err != nil {
			fmt.Printf("Error: %v\n", err)
			continue
		}

		// Encrypt - gcm.Seal appends ciphertext+tag to the nonce
		ciphertext := gcm.Seal(nonce, nonce, []byte(tc.plaintext), nil)

		// Encode to base64
		encoded := base64.StdEncoding.EncodeToString(ciphertext)

		fmt.Printf("{ password: '%s', data: '%s', expected: '%s' },\n", tc.password, encoded, tc.plaintext)
	}
}
