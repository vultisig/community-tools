package processing

import (
        "encoding/base64"
        "encoding/hex"
        "fmt"
        "io"
        "log"
        "math/big"
        "os"
        "strings"

        "github.com/golang/protobuf/proto"
        v1 "github.com/vultisig/commondata/go/vultisig/vault/v1"
        "main/internal/utils"
        "main/internal/crypto"

        "encoding/json"
)

// Unified File Processing Pipeline Types and Functions

// FileProcessingContext represents the shared context passed through the processing pipeline
type FileProcessingContext struct {
        FileInfos       []utils.FileInfo
        Passwords       []string
        Source          utils.InputSource
        
        // DKLS-specific fields
        PrivateKeyHex     string
        RootChainCodeHex  string
        EdDSAPublicKeyHex string
        EdDSAPrivateKeyHex string // NEW: EdDSA private key from DKLS extraction
}

// FileProcessingStrategy defines the interface for different vault processing strategies
type FileProcessingStrategy interface {
        ProcessFiles(ctx FileProcessingContext, result *ProcessResult) error
        GetStrategyName() string
}

// FileProcessingConfig configures the unified processing pipeline
type FileProcessingConfig struct {
        StrategyName string
        Strategy     FileProcessingStrategy
}

// Common Validation Functions

// validateFileProcessingInput performs common validation of input parameters
func validateFileProcessingInput(fileInfos []utils.FileInfo) error {
        if len(fileInfos) == 0 {
                return fmt.Errorf("no files provided")
        }
        return nil
}

// initializeProcessingResult creates and initializes a ProcessResult with common setup
func initializeProcessingResult() ProcessResult {
        return ProcessResult{
                Success: true,
                ShareDetails: make([]ShareDetails, 0),
                CoinKeys: make([]CoinKeyInfo, 0),
        }
}

// setupLogging configures logging output based on environment variable
func setupLogging() {
        if os.Getenv("ENABLE_LOGGING") != "true" {
                log.SetOutput(io.Discard)
        }
}

// GG20Strategy implements FileProcessingStrategy for GG20 vault processing
type GG20Strategy struct{}

func (s *GG20Strategy) GetStrategyName() string {
        return "GG20"
}

func (s *GG20Strategy) ProcessFiles(ctx FileProcessingContext, result *ProcessResult) error {
        allSecret := make([]utils.TempLocalState, 0, len(ctx.FileInfos))

        // Process each file
        for i, file := range ctx.FileInfos {
                log.Printf("Processing GG20 file %d, content starts with: %s", i, string(file.Content)[:min(len(file.Content), 50)])

                password := ""
                if i < len(ctx.Passwords) {
                        password = ctx.Passwords[i]
                }

                localStates, isDKLS, err := decodeAndExtractLocalState(file.Content, password, ctx.Source)
                if err != nil {
                        if isDKLS {
                                log.Printf("Warning: File %d (%s) is a DKLS vault and cannot be processed as GG20. Use DKLS processing mode for this file type.", i, file.Name)
                                // Set warning in result but continue processing other files
                                if result.Error == "" {
                                        result.Error = fmt.Sprintf("Warning: Some files are DKLS format and were skipped in GG20 processing (e.g., %s)", file.Name)
                                }
                                continue // Skip this file for GG20 processing
                        }
                        result.Success = false
                        result.Error = fmt.Sprintf("error processing file %d: %v", i, err)
                        return fmt.Errorf("error processing file %d: %w", i, err)
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
                        return fmt.Errorf("error processing ECDSA keys: %w", err)
                }
                
                // Set the structured data
                if rootKeyInfo != nil {
                        result.RootKeyInfo = rootKeyInfo
                        result.PublicKeys.ECDSA = rootKeyInfo.HexPubKeyECDSA
                }
                result.CoinKeys = append(result.CoinKeys, coinKeys...)
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
        }

        return nil
}

// DKLSStrategy implements FileProcessingStrategy for DKLS vault processing
type DKLSStrategy struct{}

func (s *DKLSStrategy) GetStrategyName() string {
        return "DKLS"
}

func (s *DKLSStrategy) ProcessFiles(ctx FileProcessingContext, result *ProcessResult) error {
        // Process each file to extract vault information for ShareDetails
        for i, file := range ctx.FileInfos {
                contentStr := strings.TrimSpace(string(file.Content))
                log.Printf("Processing DKLS file %d, content starts with: %s", i, contentStr[:min(len(contentStr), 50)])

                password := ""
                if i < len(ctx.Passwords) {
                        password = ctx.Passwords[i]
                }

                // Use consolidated parsing function for DKLS files
                _, vaultContainer, err := decodeAndParseVaultContainer(file.Content)
                if err != nil {
                        log.Printf("Failed to unmarshal VaultContainer for file %d: %v", i, err)
                        // Still add basic share detail
                        shareDetail := ShareDetails{
                                BackupName: file.Name,
                                ThisShare:  fmt.Sprintf("party%d", i+1),
                                AllShares:  make([]string, len(ctx.FileInfos)),
                        }
                        
                        for j := 0; j < len(ctx.FileInfos); j++ {
                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                        }
                        
                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                        continue
                }

                // Parse the inner vault to get vault information
                if vaultContainer.IsEncrypted {
                        if password == "" {
                                // No password provided for encrypted vault
                                log.Printf("Encrypted vault requires password for file %d", i)
                                shareDetail := ShareDetails{
                                        BackupName: file.Name,
                                        ThisShare:  fmt.Sprintf("party%d", i+1),
                                        AllShares:  make([]string, len(ctx.FileInfos)),
                                }
                                
                                for j := 0; j < len(ctx.FileInfos); j++ {
                                        shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                                }
                                
                                result.ShareDetails = append(result.ShareDetails, shareDetail)
                        } else {
                                // Decrypt the vault to extract ShareDetails
                                vaultBytes, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
                                if err != nil {
                                        log.Printf("Failed to decode encrypted vault data for file %d: %v", i, err)
                                        shareDetail := ShareDetails{
                                                BackupName: file.Name,
                                                ThisShare:  fmt.Sprintf("party%d", i+1),
                                                AllShares:  make([]string, len(ctx.FileInfos)),
                                        }
                                        
                                        for j := 0; j < len(ctx.FileInfos); j++ {
                                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                                        }
                                        
                                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                                } else {
                                        // Decrypt the vault bytes using the password
                                        decryptedData, err := utils.DecryptWithPassword(vaultBytes, password)
                                        if err != nil {
                                                log.Printf("Failed to decrypt vault for file %d: %v", i, err)
                                                shareDetail := ShareDetails{
                                                        BackupName: file.Name,
                                                        ThisShare:  fmt.Sprintf("party%d", i+1),
                                                        AllShares:  make([]string, len(ctx.FileInfos)),
                                                }
                                                
                                                for j := 0; j < len(ctx.FileInfos); j++ {
                                                        shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                                                }
                                                
                                                result.ShareDetails = append(result.ShareDetails, shareDetail)
                                        } else {
                                                // Parse the decrypted vault to extract proper ShareDetails
                                                var vault v1.Vault
                                                if err := proto.Unmarshal(decryptedData, &vault); err != nil {
                                                        log.Printf("Failed to unmarshal decrypted vault for file %d: %v", i, err)
                                                        shareDetail := ShareDetails{
                                                                BackupName: file.Name,
                                                                ThisShare:  fmt.Sprintf("party%d", i+1),
                                                                AllShares:  make([]string, len(ctx.FileInfos)),
                                                        }
                                                        
                                                        for j := 0; j < len(ctx.FileInfos); j++ {
                                                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                                                        }
                                                        
                                                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                                                } else {
                                                        // Successfully decrypted and parsed - extract proper ShareDetails
                                                        shareDetail := ShareDetails{
                                                                BackupName:    vault.Name,
                                                                ThisShare:     vault.LocalPartyId,
                                                                ResharePrefix: vault.ResharePrefix,
                                                        }

                                                        // Generate all party IDs (simplified approach)
                                                        shareDetail.AllShares = make([]string, len(ctx.FileInfos))
                                                        for j := 0; j < len(ctx.FileInfos); j++ {
                                                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                                                        }

                                                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                                                }
                                        }
                                }
                        }
                } else {
                        // For unencrypted vaults, try to extract more detailed information
                        vaultBytes, err := base64.StdEncoding.DecodeString(vaultContainer.Vault)
                        if err != nil {
                                log.Printf("Failed to decode vault data for file %d: %v", i, err)
                                // Still add basic share detail
                                shareDetail := ShareDetails{
                                        BackupName: file.Name,
                                        ThisShare:  fmt.Sprintf("party%d", i+1),
                                        AllShares:  make([]string, len(ctx.FileInfos)),
                                }
                                
                                for j := 0; j < len(ctx.FileInfos); j++ {
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
                                        AllShares:  make([]string, len(ctx.FileInfos)),
                                }
                                
                                for j := 0; j < len(ctx.FileInfos); j++ {
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
                        shareDetail.AllShares = make([]string, len(ctx.FileInfos))
                        for j := 0; j < len(ctx.FileInfos); j++ {
                                shareDetail.AllShares[j] = fmt.Sprintf("party%d", j+1)
                        }

                        result.ShareDetails = append(result.ShareDetails, shareDetail)
                }
        }

        // Use the unified processing pipeline (same processors as GG20) but bypass TSS reconstruction
        // since DKLS provides reconstructed keys directly
        err := processDKLSKeysWithUnifiedPipeline(ctx, result)
        if err != nil {
                result.Success = false
                result.Error = fmt.Sprintf("error processing DKLS keys: %v", err)
                return fmt.Errorf("error processing DKLS keys: %w", err)
        }
        
        log.Printf("DKLS processing completed successfully with %d coin keys", len(result.CoinKeys))

        return nil
}

// createSyntheticTempLocalStateFromDKLS creates synthetic TempLocalState structures
// from DKLS reconstructed keys to make them compatible with the unified processing pipeline
func createSyntheticTempLocalStateFromDKLS(ctx FileProcessingContext) ([]utils.TempLocalState, error) {
        // Create a single synthetic TempLocalState that contains the chain code for ECDSA processing
        syntheticLocalState := crypto.LocalState{
                ChainCodeHex: ctx.RootChainCodeHex,
                // PubKey intentionally not set - will be computed during ECDSA processing
        }
        
        // Create the LocalState map - only for ECDSA (EdDSA has different chain code requirements)
        localStateMap := make(map[utils.TssKeyType]crypto.LocalState)
        localStateMap[utils.ECDSA] = syntheticLocalState
        // NOTE: EdDSA not included - EdDSA uses different derivation and chain code
        
        // Create synthetic TempLocalState
        syntheticSecret := utils.TempLocalState{
                FileName:   "dkls_synthetic_state",
                LocalState: localStateMap,
                SchemeType: utils.DKLS,
        }
        
        return []utils.TempLocalState{syntheticSecret}, nil
}

// processDKLSKeysWithUnifiedPipeline processes DKLS keys using the same pipeline as GG20
// but bypasses TSS reconstruction since DKLS gives us reconstructed keys directly
func processDKLSKeysWithUnifiedPipeline(ctx FileProcessingContext, result *ProcessResult) error {
        // Create synthetic local state for chain code access
        syntheticSecrets, err := createSyntheticTempLocalStateFromDKLS(ctx)
        if err != nil {
                return fmt.Errorf("failed to create synthetic local state: %w", err)
        }
        
        // Process ECDSA keys if we have the required data
        if ctx.PrivateKeyHex != "" && ctx.RootChainCodeHex != "" {
                ecdsaPrivateKeyBytes, err := hex.DecodeString(ctx.PrivateKeyHex)
                if err != nil {
                        return fmt.Errorf("failed to decode ECDSA private key: %w", err)
                }
                
                // Convert to big.Int for compatibility with processor
                ecdsaPrivateKeyBigInt := new(big.Int).SetBytes(ecdsaPrivateKeyBytes)
                
                // Use the ECDSA processor directly (bypass TSS reconstruction)
                processor := &ECDSAKeyProcessor{}
                ecdsaResult, err := processor.ProcessTSSKey(ecdsaPrivateKeyBigInt, syntheticSecrets)
                if err != nil {
                        log.Printf("ECDSA processing failed: %v", err)
                } else {
                        result.RootKeyInfo = ecdsaResult.RootKeyInfo
                        result.PublicKeys.ECDSA = ecdsaResult.RootKeyInfo.HexPubKeyECDSA
                        result.CoinKeys = append(result.CoinKeys, ecdsaResult.CoinKeys...)
                }
        }
        
        // Process EdDSA keys - NOW IMPLEMENTED with proper EdDSA private key extraction
        if ctx.EdDSAPublicKeyHex != "" && ctx.EdDSAPrivateKeyHex != "" {
                log.Printf("✅ DKLS EdDSA processing - both EdDSA public and private keys available")
                
                eddsaPrivateKeyBytes, err := hex.DecodeString(ctx.EdDSAPrivateKeyHex)
                if err != nil {
                        log.Printf("❌ Failed to decode EdDSA private key: %v", err)
                } else {
                        // Convert to big.Int for compatibility with processor
                        eddsaPrivateKeyBigInt := new(big.Int).SetBytes(eddsaPrivateKeyBytes)
                        
                        // Use the EdDSA processor directly (bypass TSS reconstruction)
                        processor := &EdDSAKeyProcessor{}
                        eddsaResult, err := processor.ProcessTSSKey(eddsaPrivateKeyBigInt, syntheticSecrets)
                        if err != nil {
                                log.Printf("❌ EdDSA processing failed: %v", err)
                        } else {
                                log.Printf("✅ EdDSA processing successful - EdDSA chains (Solana, Sui, TON) now available!")
                                result.PublicKeys.EdDSA = ctx.EdDSAPublicKeyHex
                                result.CoinKeys = append(result.CoinKeys, eddsaResult.CoinKeys...)
                        }
                }
        } else if ctx.EdDSAPublicKeyHex != "" {
                log.Printf("⚠️  DKLS EdDSA public key available but private key missing - EdDSA extraction may have failed")
                result.PublicKeys.EdDSA = ctx.EdDSAPublicKeyHex
        } else {
                log.Printf("ℹ️  No EdDSA keys in DKLS vault - EdDSA chains (Solana, Sui, TON) not available")
        }
        
        return nil
}

// processFileContentGeneric implements the unified processing pipeline
func processFileContentGeneric(ctx FileProcessingContext, config FileProcessingConfig) (ProcessResult, error) {
        log.Printf("Processing files using %s strategy with %d files", config.StrategyName, len(ctx.FileInfos))

        // Step 1: Set up logging
        setupLogging()

        // Step 2: Validate input parameters
        if err := validateFileProcessingInput(ctx.FileInfos); err != nil {
                result := initializeProcessingResult()
                result.Success = false
                result.Error = err.Error()
                return result, err
        }

        // Step 3: Initialize result
        result := initializeProcessingResult()

        // Step 4: Process files using the specific strategy
        if err := config.Strategy.ProcessFiles(ctx, &result); err != nil {
                return result, err
        }

        return result, nil
}

// Helper Functions and Existing Functions

// decodeAndParseVaultContainer consolidates the base64 decode and VaultContainer parsing logic.
// Returns the decoded data and parsed VaultContainer, or error if parsing fails.
func decodeAndParseVaultContainer(fileContent []byte) ([]byte, *v1.VaultContainer, error) {
        contentStr := strings.TrimSpace(string(fileContent))
        
        // Try to decode as base64 first
        decodedData, err := base64.StdEncoding.DecodeString(contentStr)
        if err != nil {
                log.Printf("Content is not base64 encoded, using raw data")
                decodedData = fileContent
        } else {
                log.Printf("Successfully decoded from base64")
        }

        // Try to parse as protobuf VaultContainer
        var vaultContainer v1.VaultContainer
        if err := proto.Unmarshal(decodedData, &vaultContainer); err != nil {
                return decodedData, nil, err
        }
        
        return decodedData, &vaultContainer, nil
}

// decodeAndExtractLocalState consolidates the file parsing logic that was duplicated across functions.
// It handles base64 decoding, protobuf parsing, GG20/DKLS detection, and returns structured results.
func decodeAndExtractLocalState(fileContent []byte, password string, source utils.InputSource) (map[utils.TssKeyType]crypto.LocalState, bool, error) {
        decodedData, _, err := decodeAndParseVaultContainer(fileContent)
        if err != nil {
                log.Printf("Failed to unmarshal as protobuf VaultContainer: %v", err)
                // Fallback to direct local state parsing (GG20 format)
                localStates, err := GetLocalStateFromContent(decodedData)
                if err != nil {
                        // Check if this error indicates a DKLS vault
                        if strings.Contains(err.Error(), "DKLS vault detected") {
                                log.Printf("DKLS vault detected during content parsing")
                                return nil, true, fmt.Errorf("DKLS vault detected: %w", err)
                        }
                        return nil, false, fmt.Errorf("error parsing content: %w", err)
                }
                return localStates, false, nil
        } else {
                log.Printf("Successfully unmarshalled as protobuf VaultContainer")
                // Parse using VaultContainer method (encrypted vault format)
                localStates, err := GetLocalStateFromBakContent(fileContent, password, source)
                if err != nil {
                        // Check if this error indicates a DKLS vault
                        if strings.Contains(err.Error(), "DKLS vault detected") {
                                log.Printf("DKLS vault detected during vault container parsing")
                                return nil, true, fmt.Errorf("DKLS vault detected: %w", err)
                        }
                        return nil, false, fmt.Errorf("error processing vault container: %w", err)
                }
                return localStates, false, nil
        }
}

// ProcessFileContentJSON processes GG20 files and returns structured JSON data using unified pipeline
func ProcessFileContentJSON(fileInfos []utils.FileInfo, passwords []string, source utils.InputSource) (ProcessResult, error) {
        // Create context for GG20 processing
        ctx := FileProcessingContext{
                FileInfos: fileInfos,
                Passwords: passwords,
                Source:    source,
        }

        // Configure pipeline for GG20 processing
        config := FileProcessingConfig{
                StrategyName: "GG20",
                Strategy:     &GG20Strategy{},
        }

        // Process files using the unified pipeline
        return processFileContentGeneric(ctx, config)
}

// ProcessDKLSFileContentJSON processes DKLS vault files and returns structured JSON data using unified pipeline
func ProcessDKLSFileContentJSON(fileInfos []utils.FileInfo, passwords []string, ecdsaPrivateKeyHex, rootChainCodeHex, eddsaPublicKeyHex, eddsaPrivateKeyHex string) (ProcessResult, error) {
        // Create context for DKLS processing
        ctx := FileProcessingContext{
                FileInfos:          fileInfos,
                Passwords:          passwords,
                Source:             utils.Web, // Default source for DKLS
                PrivateKeyHex:      ecdsaPrivateKeyHex,
                RootChainCodeHex:   rootChainCodeHex,
                EdDSAPublicKeyHex:  eddsaPublicKeyHex,
                EdDSAPrivateKeyHex: eddsaPrivateKeyHex, // NEW: Add EdDSA private key
        }

        // Configure pipeline for DKLS processing
        config := FileProcessingConfig{
                StrategyName: "DKLS",
                Strategy:     &DKLSStrategy{},
        }

        // Process files using the unified pipeline
        return processFileContentGeneric(ctx, config)
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
