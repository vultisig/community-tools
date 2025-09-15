package processing

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/golang/protobuf/proto"
	"github.com/vultisig/commondata/go/vultisig/vault/v1"

	"main/internal/crypto"
	"main/internal/utils"
)

// ReadDataFileContent reads file content with hex decoding support
func ReadDataFileContent(inputFilePathName string) ([]byte, error) {
	filePathName, err := filepath.Abs(inputFilePathName)
	if err != nil {
		return nil, fmt.Errorf("error getting absolute path for file %s: %w", inputFilePathName, err)
	}
	_, err = os.Stat(filePathName)
	if err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", inputFilePathName, err)
	}
	fileContent, err := os.ReadFile(filePathName)
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

// GetLocalStateFromBakContent extracts local state from .bak file content
func GetLocalStateFromBakContent(content []byte, password string, source utils.InputSource) (map[utils.TssKeyType]crypto.LocalState, error) {
	rawContent, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return nil, fmt.Errorf("error decoding content: %w", err)
	}

	var vaultContainer v1.VaultContainer
	if err := proto.Unmarshal(rawContent, &vaultContainer); err != nil {
		return nil, fmt.Errorf("error unmarshalling content: %w", err)
	}

	localStates := make(map[utils.TssKeyType]crypto.LocalState)
	if vaultContainer.IsEncrypted {
		localStates, err = utils.DecryptVaultContent(&vaultContainer, password, source)
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
func GetLocalStateFromContent(content []byte) (map[utils.TssKeyType]crypto.LocalState, error) {
	return ParseVault(content)
}

// ParseVault parses vault content in multiple formats (protobuf, base64, JSON)
func ParseVault(content []byte) (map[utils.TssKeyType]crypto.LocalState, error) {
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

// extractLocalStates extracts local states from a parsed vault object
func extractLocalStates(vault *v1.Vault) (map[utils.TssKeyType]crypto.LocalState, error) {
	// Check if this is a DKLS vault by looking for DKLS indicators
	isDKLS := vault.ResharePrefix != "" || len(vault.KeyShares) > 0 && !isJSONString(vault.KeyShares[0].Keyshare)

	if isDKLS {
		// For DKLS vaults, we don't parse keyshares as JSON since they're in a different format
		return nil, fmt.Errorf("DKLS vault detected - keyshares are not in JSON format")
	}

	localStates := make(map[utils.TssKeyType]crypto.LocalState)

	for _, keyshare := range vault.KeyShares {
		var localState crypto.LocalState
		if err := json.Unmarshal([]byte(keyshare.Keyshare), &localState); err != nil {
			return nil, fmt.Errorf("error unmarshalling keyshare: %w", err)
		}

		if keyshare.PublicKey == vault.PublicKeyEcdsa {
			localStates[utils.ECDSA] = localState
		} else {
			localStates[utils.EdDSA] = localState
		}
	}

	return localStates, nil
}

// isJSONString checks if a string is valid JSON
func isJSONString(s string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(s), &js) == nil
}

// parseJSONVault parses vault content from a JSON object map
func parseJSONVault(vault map[string]interface{}) (map[utils.TssKeyType]crypto.LocalState, error) {
	// Assuming the JSON vault has a structure similar to the voltixBackup struct
	vaultData, ok := vault["vault"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("vault field not found or not an object")
	}

	keysharesData, ok := vaultData["keyshares"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("keyshares field not found or not an array")
	}

	localStates := make(map[utils.TssKeyType]crypto.LocalState)

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
			localStates[utils.ECDSA] = localState
		} else if localState.EDDSALocalData.ShareID != nil {
			localStates[utils.EdDSA] = localState
		}
	}

	return localStates, nil
}