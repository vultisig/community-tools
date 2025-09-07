package utils
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha256"
    "encoding/base64"
    "encoding/json"
    "fmt"

    "github.com/golang/protobuf/proto"
    v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
    
    "main/internal/crypto"
)

func DecryptWithPassword(encryptedData []byte, password string) ([]byte, error) {
    // First decode the base64 encoded vault data
    vaultData, err := base64.StdEncoding.DecodeString(string(encryptedData))
    if err != nil {
        return nil, fmt.Errorf("failed to decode vault data: %w", err)
    }

    // Hash the password to create a key
    hash := sha256.Sum256([]byte(password))
    key := hash[:]

    // Create a new AES cipher using the key
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, fmt.Errorf("failed to create cipher: %w", err)
    }

    // Use GCM (Galois/Counter Mode)
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, fmt.Errorf("failed to create GCM: %w", err)
    }

    // Get the nonce size
    nonceSize := gcm.NonceSize()
    if len(vaultData) < nonceSize {
        return nil, fmt.Errorf("encrypted data too short")
    }

    // Extract the nonce from the vault
    nonce, ciphertext := vaultData[:nonceSize], vaultData[nonceSize:]

    // Decrypt the vault
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt: %w", err)
    }

    return plaintext, nil
}

func DecryptVaultContent(vaultContainer *v1.VaultContainer, password string, source InputSource) (map[TssKeyType]crypto.LocalState, error) {
  if !vaultContainer.IsEncrypted {
      return nil, fmt.Errorf("vault is not encrypted")
  }
  // Use the provided password directly (web interface collects passwords upfront)
  keyInput := password
  decryptedData, err := DecryptWithPassword([]byte(vaultContainer.Vault), keyInput)
  if err != nil {
      return nil, fmt.Errorf("failed to decrypt vault: %w", err)
  }
  var decryptedVault v1.Vault
  if err := proto.Unmarshal(decryptedData, &decryptedVault); err != nil {
      return nil, fmt.Errorf("failed to unmarshal decrypted data: %w", err)
  }
  localStates := make(map[TssKeyType]crypto.LocalState)
  for _, keyshare := range decryptedVault.KeyShares {
      var localState crypto.LocalState
      if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
          return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
      }
      if keyshare.PublicKey == decryptedVault.PublicKeyEcdsa {
          localStates[ECDSA] = localState
      } else {
          localStates[EdDSA] = localState
      }
  }
  return localStates, nil
}

func DecryptVaultHelper(password string, vault []byte) ([]byte, error) {
  // Hash the password to create a key
  hash := sha256.Sum256([]byte(password))
  key := hash[:]

  // Create a new AES cipher using the key
  block, err := aes.NewCipher(key)
  if err != nil {
    return nil, err
  }

  // Use GCM (Galois/Counter Mode)
  gcm, err := cipher.NewGCM(block)
  if err != nil {
    return nil, err
  }

  // Get the nonce size
  nonceSize := gcm.NonceSize()
  if len(vault) < nonceSize {
    return nil, fmt.Errorf("ciphertext too short")
  }

  // Extract the nonce from the vault
  nonce, ciphertext := vault[:nonceSize], vault[nonceSize:]

  // Decrypt the vault
  plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
  if err != nil {
    return nil, err
  }

  return plaintext, nil
}

func DecryptVault(vaultContainer *v1.VaultContainer, inputFileName string, password string, source InputSource) (*v1.Vault, error) {
  vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
  if err != nil {
    return nil, fmt.Errorf("failed to decode vault: %w", err)
  }

  // Attempt to decrypt the vault using the provided or entered password
  decryptedVaultData, err := DecryptVaultHelper(password, vaultData)
  if err != nil {
    return nil, fmt.Errorf("error decrypting file %s: %w", inputFileName, err)
  }

  var vault v1.Vault
  if err := proto.Unmarshal(decryptedVaultData, &vault); err != nil {
    return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
  }

  return &vault, nil
}