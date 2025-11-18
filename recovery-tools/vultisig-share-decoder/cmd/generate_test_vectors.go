package main

import (
	"fmt"
	"main/internal/utils"
)

func main() {
	testCases := []struct {
		password  string
		plaintext string
	}{
		{"mypassword", "helloworld"},
		{"test123", "test data"},
		{"SecurePassword123!", "This is a longer test message with more content."},
	}

	fmt.Println("// Generated test vectors for AES-GCM decryption tests")
	fmt.Println("// Format: { password, base64EncryptedData, expectedPlaintext }")
	fmt.Println()

	for i, tc := range testCases {
		encrypted, err := utils.EncryptWithPassword([]byte(tc.plaintext), tc.password)
		if err != nil {
			fmt.Printf("Error encrypting test case %d: %v\n", i+1, err)
			continue
		}

		fmt.Printf("Test Case %d:\n", i+1)
		fmt.Printf("  Password: '%s'\n", tc.password)
		fmt.Printf("  Plaintext: '%s'\n", tc.plaintext)
		fmt.Printf("  Encrypted (base64): '%s'\n", encrypted)
		fmt.Println()
	}
}
