package processing

import (
        "encoding/base64"
        "fmt"
        "io"
        "log"
        "os"
        "strings"

        "github.com/golang/protobuf/proto"
        v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
        "main/internal/utils"
        "main/internal/crypto"

        "encoding/json"
)

func ProcessFileContent(fileInfos []utils.FileInfo, passwords []string, source utils.InputSource) (string, error) {
        var outputBuilder strings.Builder

        if os.Getenv("ENABLE_LOGGING") != "true" {
                log.SetOutput(io.Discard)
        }

        if len(fileInfos) == 0 {
                return "", fmt.Errorf("no files provided")
        }
        
        allSecret := make([]utils.TempLocalState, 0, len(fileInfos))

        // Process each file
        for i, file := range fileInfos {
                contentStr := strings.TrimSpace(string(file.Content))

                log.Printf("Processing file %d, content starts with: %s", i, contentStr[:min(len(contentStr), 50)])

                password := ""
                if i < len(passwords) {
                        password = passwords[i]
                }

                var localStates map[utils.TssKeyType]crypto.LocalState
                var err error

                decodedData, err := base64.StdEncoding.DecodeString(contentStr)
                if err != nil {
                        log.Printf("File %d is not base64 encoded, trying direct parsing", i)
                        decodedData = file.Content
                } else {
                        log.Printf("File %d successfully decoded from base64", i)
                }

                var vaultContainer v1.VaultContainer
                if err := proto.Unmarshal(decodedData, &vaultContainer); err != nil {
                        log.Printf("Failed to unmarshal as protobuf: %v", err)
                        localStates, err = utils.GetLocalStateFromContent(decodedData)
                        if err != nil {
                                // Check if this error indicates a DKLS vault
                                if strings.Contains(err.Error(), "DKLS vault detected") {
                                        log.Printf("File %d detected as DKLS format, skipping GG20 processing", i)
                                        continue // Skip this file for GG20 processing
                                }
                                return "", fmt.Errorf("error processing file %d: %w", i, err)
                        }
                } else {
                        log.Printf("Successfully unmarshalled as protobuf VaultContainer")
                        localStates, err = utils.GetLocalStateFromBakContent([]byte(contentStr), password, source)
                        if err != nil {
                                // Check if this error indicates a DKLS vault
                                if strings.Contains(err.Error(), "DKLS vault detected") {
                                        log.Printf("File %d detected as DKLS format, skipping GG20 processing", i)
                                        continue // Skip this file for GG20 processing
                                }
                                return "", fmt.Errorf("error processing vault container file %d: %w", i, err)
                        }
                }

                // Add share details to output
                outputBuilder.WriteString(fmt.Sprintf("Backup name: %s\n", file.Name))
                if eddsaState, ok := localStates[utils.EdDSA]; ok {
                        outputBuilder.WriteString(fmt.Sprintf("This Share: %s\n", eddsaState.LocalPartyKey))
                        outputBuilder.WriteString(fmt.Sprintf("All Shares: %v\n", eddsaState.KeygenCommitteeKeys))
                }

                allSecret = append(allSecret, utils.TempLocalState{
                        FileName:   fmt.Sprintf("file_%d", i),
                        LocalState: localStates,
                })
        }

        threshold := len(allSecret)
        log.Printf("Using threshold %d for %d secrets", threshold, len(allSecret))

        // Process GG20 files
        if err := GetKeys(threshold, allSecret, utils.ECDSA, &outputBuilder); err != nil {
                return "", fmt.Errorf("error processing ECDSA keys: %w", err)
        }
        if err := GetKeys(threshold, allSecret, utils.EdDSA, &outputBuilder); err != nil {
                return "", fmt.Errorf("error processing EdDSA keys: %w", err)
        }
        return outputBuilder.String(), nil
}

// ProcessFileContentJSON processes files and returns structured JSON data
func ProcessFileContentJSON(fileInfos []utils.FileInfo, passwords []string, source utils.InputSource) (ProcessResult, error) {
        result := ProcessResult{
                Success: true,
                ShareDetails: make([]ShareDetails, 0),
                CoinKeys: make([]CoinKeyInfo, 0),
        }

        if os.Getenv("ENABLE_LOGGING") != "true" {
                log.SetOutput(io.Discard)
        }

        if len(fileInfos) == 0 {
                result.Success = false
                result.Error = "no files provided"
                return result, fmt.Errorf("no files provided")
        }
        
        allSecret := make([]utils.TempLocalState, 0, len(fileInfos))

        // Process each file
        for i, file := range fileInfos {
                contentStr := strings.TrimSpace(string(file.Content))

                log.Printf("Processing file %d, content starts with: %s", i, contentStr[:min(len(contentStr), 50)])

                password := ""
                if i < len(passwords) {
                        password = passwords[i]
                }

                var localStates map[utils.TssKeyType]crypto.LocalState
                var err error

                decodedData, err := base64.StdEncoding.DecodeString(contentStr)
                if err != nil {
                        log.Printf("File %d is not base64 encoded, trying direct parsing", i)
                        decodedData = file.Content
                } else {
                        log.Printf("File %d successfully decoded from base64", i)
                }

                var vaultContainer v1.VaultContainer
                if err := proto.Unmarshal(decodedData, &vaultContainer); err != nil {
                        log.Printf("Failed to unmarshal as protobuf: %v", err)
                        localStates, err = utils.GetLocalStateFromContent(decodedData)
                        if err != nil {
                                // Check if this error indicates a DKLS vault
                                if strings.Contains(err.Error(), "DKLS vault detected") {
                                        log.Printf("File %d detected as DKLS format, skipping GG20 processing", i)
                                        continue // Skip this file for GG20 processing
                                }
                                result.Success = false
                                result.Error = fmt.Sprintf("error processing file %d: %v", i, err)
                                return result, fmt.Errorf("error processing file %d: %w", i, err)
                        }
                } else {
                        log.Printf("Successfully unmarshalled as protobuf VaultContainer")
                        localStates, err = utils.GetLocalStateFromBakContent([]byte(contentStr), password, source)
                        if err != nil {
                                // Check if this error indicates a DKLS vault
                                if strings.Contains(err.Error(), "DKLS vault detected") {
                                        log.Printf("File %d detected as DKLS format, skipping GG20 processing", i)
                                        continue // Skip this file for GG20 processing
                                }
                                result.Success = false
                                result.Error = fmt.Sprintf("error processing vault container file %d: %v", i, err)
                                return result, fmt.Errorf("error processing vault container file %d: %w", i, err)
                        }
                }

                // Add share details to result
                shareDetail := ShareDetails{
                        BackupName: file.Name,
                }
                
                if eddsaState, ok := localStates[utils.EdDSA]; ok {
                        shareDetail.ThisShare = eddsaState.LocalPartyKey
                        shareDetail.AllShares = eddsaState.KeygenCommitteeKeys
                }
                result.ShareDetails = append(result.ShareDetails, shareDetail)

                allSecret = append(allSecret, utils.TempLocalState{
                        FileName:   fmt.Sprintf("file_%d", i),
                        LocalState: localStates,
                })
        }

        threshold := len(allSecret)
        log.Printf("Using threshold %d for %d secrets", threshold, len(allSecret))

        // Process ECDSA keys with proper structuring
        if len(allSecret) > 0 {
                // Reconstruct ECDSA private key and derive coin keys
                rootKeyInfo, coinKeys, err := ProcessECDSAKeysJSON(threshold, allSecret)
                if err != nil {
                        result.Success = false
                        result.Error = fmt.Sprintf("error processing ECDSA keys: %v", err)
                        return result, fmt.Errorf("error processing ECDSA keys: %w", err)
                }
                
                // Set the structured data
                if rootKeyInfo != nil {
                        result.RootKeyInfo = rootKeyInfo
                        result.PublicKeys.ECDSA = rootKeyInfo.HexPubKeyECDSA
                }
                result.CoinKeys = append(result.CoinKeys, coinKeys...)
                
                // Also generate raw output for backward compatibility
                var outputBuilder strings.Builder
                if err := GetKeys(threshold, allSecret, utils.ECDSA, &outputBuilder); err == nil {
                        result.RawOutput += outputBuilder.String()
                }
        }

        // Process EdDSA keys with proper structuring
        if len(allSecret) > 0 {
                eddsaKeys, err := ProcessEdDSAKeysJSON(threshold, allSecret)
                if err != nil {
                        // EdDSA processing might fail if no EdDSA keys present, which is okay
                        log.Printf("EdDSA processing failed (this is okay if no EdDSA keys present): %v", err)
                } else {
                        result.CoinKeys = append(result.CoinKeys, eddsaKeys...)
                        
                        // Try to get EdDSA public key from the first secret
                        if len(allSecret) > 0 {
                                if eddsaState, ok := allSecret[0].LocalState[utils.EdDSA]; ok {
                                        result.PublicKeys.EdDSA = eddsaState.PubKey
                                }
                        }
                }
                
                // Also generate raw output for backward compatibility  
                var outputBuilder strings.Builder
                if err := GetKeys(threshold, allSecret, utils.EdDSA, &outputBuilder); err == nil {
                        result.RawOutput += outputBuilder.String()
                }
        }

        return result, nil
}

// ProcessDKLSFileContentJSON processes DKLS vault files and returns structured JSON data in the same format as GG20
func ProcessDKLSFileContentJSON(fileInfos []utils.FileInfo, passwords []string, privateKeyHex, rootChainCodeHex, eddsaPublicKeyHex string) (ProcessResult, error) {
        result := ProcessResult{
                Success: true,
                ShareDetails: make([]ShareDetails, 0),
                CoinKeys: make([]CoinKeyInfo, 0),
        }

        if os.Getenv("ENABLE_LOGGING") != "true" {
                log.SetOutput(io.Discard)
        }

        if len(fileInfos) == 0 {
                result.Success = false
                result.Error = "no files provided"
                return result, fmt.Errorf("no files provided")
        }

        // Process each file to extract vault information for ShareDetails
        for i, file := range fileInfos {
                contentStr := strings.TrimSpace(string(file.Content))
                log.Printf("Processing DKLS file %d, content starts with: %s", i, contentStr[:min(len(contentStr), 50)])

                password := ""
                if i < len(passwords) {
                        password = passwords[i]
                }
                _ = password // TODO: Use password for vault decryption in future implementation

                // Try to decode as base64 if it's a string
                var vaultContainerData []byte
                decodedData, err := base64.StdEncoding.DecodeString(contentStr)
                if err != nil {
                        log.Printf("File %d is not base64 encoded, using raw data", i)
                        vaultContainerData = file.Content
                } else {
                        log.Printf("File %d successfully decoded from base64", i)
                        vaultContainerData = decodedData
                }

                // Parse as VaultContainer (DKLS vaults are typically encrypted)
                var vaultContainer v1.VaultContainer
                if err := proto.Unmarshal(vaultContainerData, &vaultContainer); err != nil {
                        log.Printf("Failed to unmarshal VaultContainer for file %d: %v", i, err)
                        // Still add basic share detail
                        shareDetail := ShareDetails{
                                BackupName: file.Name,
                                ThisShare:  fmt.Sprintf("party%d", i+1),
                                AllShares:  make([]string, len(fileInfos)),
                        }
                        
                        for j := 0; j < len(fileInfos); j++ {
                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                        }
                        
                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                        continue
                }

                // Parse the inner vault to get vault information
                if vaultContainer.IsEncrypted {
                        // For encrypted vaults, we can't easily extract vault info without password
                        // Use filename and generate party ID
                        shareDetail := ShareDetails{
                                BackupName: file.Name,
                                ThisShare:  fmt.Sprintf("party%d", i+1),
                                AllShares:  make([]string, len(fileInfos)),
                        }
                        
                        // Generate all party IDs
                        for j := 0; j < len(fileInfos); j++ {
                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                        }
                        
                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                } else {
                        // For unencrypted vaults, try to extract more detailed information
                        vaultBytes, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
                        if err != nil {
                                log.Printf("Failed to decode vault data for file %d: %v", i, err)
                                // Still add basic share detail
                                shareDetail := ShareDetails{
                                        BackupName: file.Name,
                                        ThisShare:  fmt.Sprintf("party%d", i+1),
                                        AllShares:  make([]string, len(fileInfos)),
                                }
                                
                                for j := 0; j < len(fileInfos); j++ {
                                        shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                                }
                                
                                result.ShareDetails = append(result.ShareDetails, shareDetail)
                                continue
                        }

                        var vault v1.Vault
                        if err := proto.Unmarshal(vaultBytes, &vault); err != nil {
                                log.Printf("Failed to unmarshal vault for file %d: %v", i, err)
                                // Still add basic share detail
                                shareDetail := ShareDetails{
                                        BackupName: file.Name,
                                        ThisShare:  fmt.Sprintf("party%d", i+1),
                                        AllShares:  make([]string, len(fileInfos)),
                                }
                                
                                for j := 0; j < len(fileInfos); j++ {
                                        shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                                }
                                
                                result.ShareDetails = append(result.ShareDetails, shareDetail)
                                continue
                        }

                        shareDetail := ShareDetails{
                                BackupName:    vault.Name,
                                ThisShare:     vault.LocalPartyId,
                                ResharePrefix: vault.ResharePrefix,
                        }

                        // Generate all party IDs (simplified approach)
                        shareDetail.AllShares = make([]string, len(fileInfos))
                        for j := 0; j < len(fileInfos); j++ {
                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                        }

                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                }
        }

        // Use the existing DeriveAndShowKeysJSON logic to get structured key data
        deriveResult, err := DeriveAndShowKeysJSON(privateKeyHex, rootChainCodeHex, "", eddsaPublicKeyHex)
        if err != nil {
                result.Success = false
                result.Error = fmt.Sprintf("error deriving keys: %v", err)
                return result, fmt.Errorf("error deriving keys: %w", err)
        }

        // Populate the result with the derived key information
        result.RootKeyInfo = &deriveResult.RootKeyInfo
        result.PublicKeys.ECDSA = deriveResult.RootKeyInfo.HexPubKeyECDSA
        if eddsaPublicKeyHex != "" {
                result.PublicKeys.EdDSA = eddsaPublicKeyHex
        }

        // Combine ECDSA and EdDSA keys into a single CoinKeys array
        result.CoinKeys = append(result.CoinKeys, deriveResult.ECDSAKeys...)
        result.CoinKeys = append(result.CoinKeys, deriveResult.EdDSAKeys...)

        // Keep raw output for backward compatibility
        result.RawOutput = deriveResult.RawOutput

        return result, nil
}

func ParseLocalState(content []byte) (map[utils.TssKeyType]crypto.LocalState, error) {
        var vault v1.Vault
        if err := proto.Unmarshal(content, &vault); err != nil {
                return nil, fmt.Errorf("failed to unmarshal vault: %w", err)
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
