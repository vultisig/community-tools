package utils

import (
        "encoding/base64"
        "encoding/hex"
        "encoding/json"
        "fmt"
        "os"
        "path/filepath"
        "strings"

        "github.com/golang/protobuf/proto"
        "github.com/vultisig/commondata/go/vultisig/vault/v1"

        "main/internal/crypto"
)

func ReadFileContent(fi string) ([]byte, error) {
        return os.ReadFile(fi)
}

func IsBakFile(fileName string) bool {
        return strings.HasSuffix(fileName, ".bak") || strings.HasSuffix(fileName, ".vult")
}

// ParseVaultToProto attempts to parse vault content as protobuf, handling both GG20 and DKLS formats
func ParseVaultToProto(content []byte) (*v1.Vault, error) {
        // Try direct protobuf unmarshaling first
        vault := &v1.Vault{}
        if err := proto.Unmarshal(content, vault); err == nil && vault.Name != "" {
                return vault, nil
        }

        // Try base64 decoding first
        if decoded, err := base64.StdEncoding.DecodeString(string(content)); err == nil {
                if err := proto.Unmarshal(decoded, vault); err == nil && vault.Name != "" {
                        return vault, nil
                }

                // Try as vault container
                var vaultContainer v1.VaultContainer
                if err := proto.Unmarshal(decoded, &vaultContainer); err == nil {
                        // This is an encrypted vault container, needs password
                        return nil, fmt.Errorf("vault is encrypted and requires password")
                }
        }

        return nil, fmt.Errorf("failed to parse vault: unrecognized format")
}

func ReadDataFileContent(inputFilePathName string) ([]byte, error) {
        filePathName, err := filepath.Abs(inputFilePathName)
        if err != nil {
                return nil, fmt.Errorf("error getting absolute path for file %s: %w", inputFilePathName, err)
        }
        _, err = os.Stat(filePathName)
        if err != nil {
                return nil, fmt.Errorf("error reading file %s: %w", inputFilePathName, err)
        }
        fileContent, err := ReadFileContent(filePathName)
        if err != nil {
                return nil, fmt.Errorf("error reading file %s: %w", inputFilePathName, err)
        }
        buf, err := hex.DecodeString(string(fileContent))
        if err == nil {
                return buf, nil
        }
        // File is encrypted and requires a password, but this function no longer prompts
        // The web interface handles password collection through HTML forms
        return nil, fmt.Errorf("file %s appears to be encrypted and requires a password", inputFilePathName)
}

func GetLocalStateFromBak(inputFileName string, password string, source InputSource) (map[TssKeyType]crypto.LocalState, error) {
        filePathName, err := filepath.Abs(inputFileName)
        if err != nil {
                return nil, fmt.Errorf("error getting absolute path for file %s: %w", inputFileName, err)
        }
        _, err = os.Stat(filePathName)
        if err != nil {
                return nil, fmt.Errorf("error reading file %s: %w", inputFileName, err)
        }
        fileContent, err := ReadFileContent(filePathName)
        if err != nil {
                return nil, fmt.Errorf("error reading file %s: %w", inputFileName, err)
        }

        rawContent, err := base64.StdEncoding.DecodeString(string(fileContent))
        if err != nil {
                return nil, fmt.Errorf("error decoding file %s: %w", inputFileName, err)
        }
        var vaultContainer v1.VaultContainer
        if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
                return nil, fmt.Errorf("error unmarshalling file %s: %w", inputFileName, err)
        }

        var decryptedVault *v1.Vault
        if vaultContainer.IsEncrypted {
                decryptedVault, err = DecryptVault(&vaultContainer, inputFileName, password, source)
                if err != nil {
                        return nil, fmt.Errorf("error decrypting file %s: %w", inputFileName, err)
                }
        } else {
                vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
                if err != nil {
                        return nil, fmt.Errorf("failed to decode vault: %w", err)
                }
                var v v1.Vault
                if err := proto.Unmarshal(vaultData, &v); err != nil {
                        return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
                }
                decryptedVault = &v
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

func GetLocalStateFromBakContent(content []byte, password string, source InputSource) (map[TssKeyType]crypto.LocalState, error) {
        rawContent, err := base64.StdEncoding.DecodeString(string(content))
        if err != nil {
                return nil, fmt.Errorf("error decoding content: %w", err)
        }

        var vaultContainer v1.VaultContainer
        if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
                return nil, fmt.Errorf("error unmarshalling content: %w", err)
        }

        localStates := make(map[TssKeyType]crypto.LocalState)
        if vaultContainer.IsEncrypted {
                localStates, err = DecryptVaultContent(&vaultContainer, password, source)
                if err != nil {
                        return nil, fmt.Errorf("error decrypting content: %w", err)
                }
        } else {
                vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
                if err != nil {
                        return nil, fmt.Errorf("failed to decode vault: %w", err)
                }
                var v v1.Vault
                if err := proto.Unmarshal(vaultData, &v); err != nil {
                        return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
                }
                localStates, err = extractLocalStates(&v)
                if err != nil {
                        return nil, fmt.Errorf("failed to parse vault: %w", err)
                }
        }

        return localStates, nil
}

// GetLocalStateFromContent extracts local state from content, handling both GG20 and DKLS detection
func GetLocalStateFromContent(content []byte) (map[TssKeyType]crypto.LocalState, error) {
        return ParseVault(content)
}

func ParseVault(content []byte) (map[TssKeyType]crypto.LocalState, error) {
        // Try direct protobuf unmarshaling first
        vault := &v1.Vault{}
        if err := proto.Unmarshal(content, vault); err == nil && vault.Name != "" {
                return extractLocalStates(vault)
        }

        // Try base64 decoding first
        if decoded, err := base64.StdEncoding.DecodeString(string(content)); err == nil {
                content = decoded
        }

        // Try as vault container
        var vaultContainer v1.VaultContainer
        if err := proto.Unmarshal(content, &vaultContainer); err == nil {
                if vaultContainer.IsEncrypted {
                        return nil, fmt.Errorf("vault is encrypted and requires password")
                }

                // Decode the inner vault
                vaultData, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
                if err != nil {
                        return nil, fmt.Errorf("failed to decode inner vault: %w", err)
                }

                var innerVault v1.Vault
                if err := proto.Unmarshal(vaultData, &innerVault); err != nil {
                        return nil, fmt.Errorf("failed to unmarshal inner vault: %w", err)
                }

                return extractLocalStates(&innerVault)
        }

        // Try JSON parsing
        var jsonVault map[string]interface{}
        if err := json.Unmarshal(content, &jsonVault); err == nil {
                return parseJSONVault(jsonVault)
        }

        return nil, fmt.Errorf("unrecognized vault format")
}

func extractLocalStates(vault *v1.Vault) (map[TssKeyType]crypto.LocalState, error) {
        // Check if this is a DKLS vault by looking for DKLS indicators
        isDKLS := vault.ResharePrefix != "" || len(vault.KeyShares) > 0 && !isJSONString(vault.KeyShares[0].Keyshare)

        if isDKLS {
                // For DKLS vaults, we don't parse keyshares as JSON since they're in a different format
                return nil, fmt.Errorf("DKLS vault detected - keyshares are not in JSON format")
        }

        localStates := make(map[TssKeyType]crypto.LocalState)

        for _, keyshare := range vault.KeyShares {
                var localState crypto.LocalState
                if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
                        return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
                }

                if keyshare.PublicKey == vault.PublicKeyEcdsa {
                        localStates[ECDSA] = localState
                } else {
                        localStates[EdDSA] = localState
                }
        }

        return localStates, nil
}

// isJSONString checks if a string is valid JSON
func isJSONString(s string) bool {
        var js json.RawMessage
        return json.Unmarshal([]byte(s), &js) == nil
}

func GetLocalStateFromFile(file string) (map[TssKeyType]crypto.LocalState, error) {
        var voltixBackup struct {
                Vault struct {
                        Keyshares []struct {
                                Pubkey   string `json:"pubkey"`
                                Keyshare string `json:"keyshare"`
                        } `json:"keyshares"`
                } `json:"vault"`
                Version string `json:"version"`
        }
        fileContent, err := ReadDataFileContent(file)
        if err != nil {
                return nil, err
        }
        err = json.Unmarshal(fileContent, &voltixBackup)
        if err != nil {
                return nil, err
        }
        localStates := make(map[TssKeyType]crypto.LocalState)
        for _, item := range voltixBackup.Vault.Keyshares {
                var localState crypto.LocalState
                if err := json.Unmarshal([]byte(item.Keyshare), &localState); err != nil {
                        return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
                }
                if localState.ECDSALocalData.ShareID != nil {
                        localStates[ECDSA] = localState
                }
                if localState.EDDSALocalData.ShareID != nil {
                        localStates[EdDSA] = localState
                }
        }
        return localStates, nil
}

func ParseVaultContent(vault *v1.Vault) (map[TssKeyType]crypto.LocalState, error) {
        localStates := make(map[TssKeyType]crypto.LocalState)
        for _, keyshare := range vault.KeyShares {
                var localState crypto.LocalState
                if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
                        return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
                }
                if keyshare.PublicKey == vault.PublicKeyEcdsa {
                        localStates[ECDSA] = localState
                } else {
                        localStates[EdDSA] = localState
                }
        }
        return localStates, nil
}

func parseJSONVault(vault map[string]interface{}) (map[TssKeyType]crypto.LocalState, error) {
        // Assuming the JSON vault has a structure similar to the voltixBackup struct
        vaultData, ok := vault["vault"].(map[string]interface{})
        if !ok {
                return nil, fmt.Errorf("vault field not found or not an object")
        }

        keysharesData, ok := vaultData["keyshares"].([]interface{})
        if !ok {
                return nil, fmt.Errorf("keyshares field not found or not an array")
        }

        localStates := make(map[TssKeyType]crypto.LocalState)

        for _, keyshareItem := range keysharesData {
                keyshare, ok := keyshareItem.(map[string]interface{})
                if !ok {
                        continue // Skip if not a valid keyshare object

                }

                keyshareString, ok := keyshare["keyshare"].(string)
                if !ok {
                        continue // Skip if keyshare is not a string
                }

                var localState crypto.LocalState
                if err := json.Unmarshal([]byte(keyshareString), &localState); err != nil {
                        continue // Skip if keyshare cannot be unmarshaled
                }

                // Determine key type based on the presence of ECDSA or EDDSA local data
                if localState.ECDSALocalData.ShareID != nil {
                        localStates[ECDSA] = localState
                } else if localState.EDDSALocalData.ShareID != nil {
                        localStates[EdDSA] = localState
                }
        }

        return localStates, nil
}