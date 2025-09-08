package processing

import (
    "encoding/hex"
    "fmt"
    "strings"
    "log"
    // "encoding/json"
    "github.com/bnb-chain/tss-lib/v2/crypto/vss"
    binanceTss "github.com/bnb-chain/tss-lib/v2/tss"
    "github.com/btcsuite/btcd/btcutil/hdkeychain"
    // "github.com/btcsuite/btcutil/base58"
    "github.com/btcsuite/btcd/chaincfg"
    "github.com/decred/dcrd/dcrec/secp256k1/v4"
    "main/internal/utils"
    edwards "github.com/decred/dcrd/dcrec/edwards/v2"

)

func GetKeys(threshold int, allSecrets []utils.TempLocalState, keyType utils.TssKeyType, outputBuilder *strings.Builder) error {
    if len(allSecrets) == 0 {
        return fmt.Errorf("no secrets provided")
    }

    // Check if we're dealing with DKLS scheme
    if len(allSecrets) > 0 && allSecrets[0].SchemeType == utils.DKLS {
        return fmt.Errorf("DKLS scheme should use ProcessDKLSKeys function, not GetKeys")
    }

    // Handle GG20 scheme (original logic)
    switch keyType {
    case utils.ECDSA:
        return ProcessECDSAKeys(threshold, allSecrets, outputBuilder)
    case utils.EdDSA:
        return ProcessEdDSAKeys(threshold, allSecrets, outputBuilder)
    default:
        return fmt.Errorf("unsupported key type: %v", keyType)
    }
}

func ProcessECDSAKeys(threshold int, allSecrets []utils.TempLocalState, outputBuilder *strings.Builder) error {
    log.Printf("Processing ECDSA keys with threshold: %d, number of secrets: %d", threshold, len(allSecrets))

    // Validate input parameters
    if threshold <= 0 {
        return fmt.Errorf("invalid threshold: %d", threshold)
    }
    if len(allSecrets) == 0 {
        return fmt.Errorf("no secrets provided")
    }
    if threshold > len(allSecrets) {
        return fmt.Errorf("threshold (%d) cannot be greater than number of secrets (%d)", threshold, len(allSecrets))
    }
    vssShares := make(vss.Shares, len(allSecrets))
    
    // Output the public key once (they should all be the same for the same vault)
    if len(allSecrets) > 0 {
        if firstState, exists := allSecrets[0].LocalState[utils.ECDSA]; exists {
            fmt.Fprintf(outputBuilder, "\nPublic Key(ECDSA): %v\n", firstState.PubKey)
        }
    }
    
    for i, s := range allSecrets {
        // Check if LocalState exists
        if s.LocalState == nil {
            return fmt.Errorf("localState is nil for secret %d", i)
        }
        // Check if ECDSA key exists
        localState, exists := s.LocalState[utils.ECDSA]
        if !exists {
            return fmt.Errorf("ECDSA key not found in secret %d", i)
        }
        log.Printf("Secret %d - ShareID: %v, Xi: %v", i, 
            localState.ECDSALocalData.ShareID != nil,
            localState.ECDSALocalData.Xi != nil)

        // Validate ShareID and Xi
        if localState.ECDSALocalData.ShareID == nil {
            return fmt.Errorf("ShareID is nil for secret %d", i)
        }
        if localState.ECDSALocalData.Xi == nil {
            return fmt.Errorf("Xi is nil for secret %d", i)
        }
        share := vss.Share{
            Threshold: threshold,
            ID:        localState.ECDSALocalData.ShareID,
            Share:     localState.ECDSALocalData.Xi,
        }
        vssShares[i] = &share
    }
    log.Printf("Created %d vssShares", len(vssShares))
    curve := binanceTss.S256()
    if curve == nil {
        return fmt.Errorf("failed to get S256 curve")
    }
    log.Printf("Attempting to reconstruct with threshold %d from %d shares", threshold, len(vssShares))
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return fmt.Errorf("failed to reconstruct private key: %w", err)
    }
    privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
    publicKey := privateKey.PubKey()

    hexPubKey := hex.EncodeToString(publicKey.SerializeCompressed())
    fmt.Fprintf(outputBuilder, "\nhex encoded root pubkey(ECDSA): %s\n", hexPubKey)
    fmt.Fprintf(outputBuilder, "\nhex encoded root privkey(ECDSA): %s\n", hex.EncodeToString(privateKey.Serialize()))

    // Example for Bitcoin derivation
    net := &chaincfg.MainNetParams
    chaincode := allSecrets[0].LocalState[utils.ECDSA].ChainCodeHex
    fmt.Fprintf(outputBuilder, "\nchaincode: %s\n", chaincode)
    chaincodeBuf, err := hex.DecodeString(chaincode)
    if err != nil {
        return err
    }
    extendedPrivateKey := hdkeychain.NewExtendedKey(net.HDPrivateKeyID[:], privateKey.Serialize(), chaincodeBuf, []byte{0x00, 0x00, 0x00, 0x00}, 0, 0, true)
    fmt.Fprintf(outputBuilder, "\nextended private key full: %s\n", extendedPrivateKey.String())

    supportedCoins := GetSupportedCoins()

    for _, coin := range supportedCoins {
        fmt.Fprintf(outputBuilder, "\nRecovering %s key....\n", coin.Name)
        key, err := GetDerivedPrivateKeys(coin.DerivePath, extendedPrivateKey)
        if err != nil {
            return fmt.Errorf("error deriving private key for %s: %w", coin.Name, err)
        }
        fmt.Fprintf(outputBuilder, "\nprivate key for %s: %s \n", coin.Name, key.String())
        if err := coin.Action(key, outputBuilder); err != nil {
            fmt.Println("error showing keys for", coin.Name, "error:", err)
        }
    }

    return nil
}

func ProcessEdDSAKeys(threshold int, allSecrets []utils.TempLocalState, outputBuilder *strings.Builder) error {
    vssShares := make(vss.Shares, len(allSecrets))
    
    // Output the public key once (they should all be the same for the same vault)
    if len(allSecrets) > 0 {
        fmt.Fprintf(outputBuilder, "\nPublic Key(EdDSA): %v\n", allSecrets[0].LocalState[utils.EdDSA].PubKey)
    }
    
    for i, s := range allSecrets {
        share := vss.Share{
            Threshold: threshold,
            ID:        s.LocalState[utils.EdDSA].EDDSALocalData.ShareID,
            Share:     s.LocalState[utils.EdDSA].EDDSALocalData.Xi,
        }
        vssShares[i] = &share
    }

    curve := binanceTss.Edwards()
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return err
    }
    
    // Generate Ed25519 key pair
    tssPrivateKeyScalar := tssPrivateKey.Bytes()
    privateKey, publicKey, _ := edwards.PrivKeyFromScalar(tssPrivateKeyScalar)
    publicKeyBytes := publicKey.Serialize()
    privateKeyBytes := privateKey.Serialize()

    // Now process EdDSA coins using the reconstructed root keys
    eddsaCoins := GetEdDSACoins()
    return ProcessEdDSAKeyForCoins(privateKeyBytes, publicKeyBytes, eddsaCoins, outputBuilder)
}

// ProcessECDSAKeysJSON reconstructs ECDSA private key and returns structured data
func ProcessECDSAKeysJSON(threshold int, allSecrets []utils.TempLocalState) (*RootKeyInfo, []CoinKeyInfo, error) {
    log.Printf("Processing ECDSA keys for JSON with threshold: %d, number of secrets: %d", threshold, len(allSecrets))

    // Validate input parameters
    if threshold <= 0 {
        return nil, nil, fmt.Errorf("invalid threshold: %d", threshold)
    }
    if len(allSecrets) == 0 {
        return nil, nil, fmt.Errorf("no secrets provided")
    }
    if threshold > len(allSecrets) {
        return nil, nil, fmt.Errorf("threshold (%d) cannot be greater than number of secrets (%d)", threshold, len(allSecrets))
    }

    vssShares := make(vss.Shares, len(allSecrets))
    
    for i, s := range allSecrets {
        // Check if LocalState exists
        if s.LocalState == nil {
            return nil, nil, fmt.Errorf("localState is nil for secret %d", i)
        }
        // Check if ECDSA key exists
        localState, exists := s.LocalState[utils.ECDSA]
        if !exists {
            return nil, nil, fmt.Errorf("ECDSA key not found in secret %d", i)
        }

        // Validate ShareID and Xi
        if localState.ECDSALocalData.ShareID == nil {
            return nil, nil, fmt.Errorf("ShareID is nil for secret %d", i)
        }
        if localState.ECDSALocalData.Xi == nil {
            return nil, nil, fmt.Errorf("Xi is nil for secret %d", i)
        }
        share := vss.Share{
            Threshold: threshold,
            ID:        localState.ECDSALocalData.ShareID,
            Share:     localState.ECDSALocalData.Xi,
        }
        vssShares[i] = &share
    }
    log.Printf("Created %d vssShares", len(vssShares))

    curve := binanceTss.S256()
    if curve == nil {
        return nil, nil, fmt.Errorf("failed to get S256 curve")
    }
    
    log.Printf("Attempting to reconstruct with threshold %d from %d shares", threshold, len(vssShares))
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to reconstruct private key: %w", err)
    }
    
    privateKey := secp256k1.PrivKeyFromBytes(tssPrivateKey.Bytes())
    publicKey := privateKey.PubKey()

    hexPubKey := hex.EncodeToString(publicKey.SerializeCompressed())
    hexPrivKey := hex.EncodeToString(privateKey.Serialize())

    // Get chaincode
    chaincode := allSecrets[0].LocalState[utils.ECDSA].ChainCodeHex
    chaincodeBuf, err := hex.DecodeString(chaincode)
    if err != nil {
        return nil, nil, fmt.Errorf("failed to decode chaincode: %w", err)
    }
    
    // Create extended private key
    net := &chaincfg.MainNetParams
    extendedPrivateKey := hdkeychain.NewExtendedKey(net.HDPrivateKeyID[:], privateKey.Serialize(), chaincodeBuf, []byte{0x00, 0x00, 0x00, 0x00}, 0, 0, true)

    // Create root key info
    rootKeyInfo := &RootKeyInfo{
        HexPubKeyECDSA:      hexPubKey,
        HexPrivKeyECDSA:     hexPrivKey,
        ChainCode:          chaincode,
        ExtendedPrivKey: extendedPrivateKey.String(),
    }

    // Process all supported coins
    supportedCoins := GetSupportedCoins()
    coinKeys := make([]CoinKeyInfo, 0, len(supportedCoins))

    for _, coin := range supportedCoins {
        log.Printf("Processing %s key derivation", coin.Name)
        key, err := GetDerivedPrivateKeys(coin.DerivePath, extendedPrivateKey)
        if err != nil {
            log.Printf("Error deriving private key for %s: %v", coin.Name, err)
            continue
        }

        // Use a string builder to capture the coin handler output
        var coinOutput strings.Builder
        if err := coin.Action(key, &coinOutput); err != nil {
            log.Printf("Error showing keys for %s: %v", coin.Name, err)
            continue
        }

        // Parse the coin handler output to extract structured information
        coinInfo := parseCoinOutput(coin.Name, coin.DerivePath, key.String(), coinOutput.String())
        coinKeys = append(coinKeys, coinInfo)
    }

    return rootKeyInfo, coinKeys, nil
}

// ProcessEdDSAKeysJSON reconstructs EdDSA private key and returns structured data
func ProcessEdDSAKeysJSON(threshold int, allSecrets []utils.TempLocalState) ([]CoinKeyInfo, error) {
    log.Printf("Processing EdDSA keys for JSON with threshold: %d, number of secrets: %d", threshold, len(allSecrets))
    
    // Check if EdDSA keys are available
    if len(allSecrets) == 0 {
        return nil, fmt.Errorf("no secrets provided")
    }
    
    // Check if first secret has EdDSA state
    if _, exists := allSecrets[0].LocalState[utils.EdDSA]; !exists {
        return nil, fmt.Errorf("no EdDSA keys found in secrets")
    }
    
    vssShares := make(vss.Shares, len(allSecrets))
    
    for i, s := range allSecrets {
        eddsaState, exists := s.LocalState[utils.EdDSA]
        if !exists {
            return nil, fmt.Errorf("EdDSA key not found in secret %d", i)
        }
        
        share := vss.Share{
            Threshold: threshold,
            ID:        eddsaState.EDDSALocalData.ShareID,
            Share:     eddsaState.EDDSALocalData.Xi,
        }
        vssShares[i] = &share
    }

    curve := binanceTss.Edwards()
    tssPrivateKey, err := vssShares[:threshold].ReConstruct(curve)
    if err != nil {
        return nil, fmt.Errorf("failed to reconstruct EdDSA private key: %w", err)
    }
    
    // Generate Ed25519 key pair
    tssPrivateKeyScalar := tssPrivateKey.Bytes()
    privateKey, publicKey, err := edwards.PrivKeyFromScalar(tssPrivateKeyScalar)
    if err != nil {
        return nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
    }
    publicKeyBytes := publicKey.Serialize()
    privateKeyBytes := privateKey.Serialize()

    // Process EdDSA coins
    eddsaCoins := GetEdDSACoins()
    coinKeys := make([]CoinKeyInfo, 0, len(eddsaCoins))

    for _, coin := range eddsaCoins {
        log.Printf("Processing EdDSA coin: %s", coin.Name)
        var coinOutput strings.Builder
        
        // Process the coin using the EdDSA key processor 
        if err := ProcessEdDSAKeyForCoins(privateKeyBytes, publicKeyBytes, []CoinConfigEdDSA{coin}, &coinOutput); err != nil {
            log.Printf("Error processing EdDSA coin %s: %v", coin.Name, err)
            continue
        }

        // Parse the coin handler output to extract structured information
        coinInfo := parseCoinOutput(coin.Name, coin.DerivePath, hex.EncodeToString(privateKeyBytes), coinOutput.String())
        coinKeys = append(coinKeys, coinInfo)
    }

    return coinKeys, nil
}

// parseCoinOutput parses the string output from coin handlers and extracts structured information
func parseCoinOutput(coinName, derivePath, privateKey, output string) CoinKeyInfo {
    coinInfo := CoinKeyInfo{
        Name:            coinName,
        DerivePath:      derivePath,
        HexPrivateKey:   privateKey,
    }

    lines := strings.Split(output, "\n")
    for _, line := range lines {
        line = strings.TrimSpace(line)
        if line == "" {
            continue
        }

        // Parse WIF keys (handle various formats)
        if strings.Contains(strings.ToLower(line), "wif private key") {
            // Handle "WIF private key for bitcoin: p2wpkh:Kx..." format - preserve address type
            prefixEnd := strings.Index(strings.ToLower(line), "wif private key")
            if prefixEnd != -1 {
                // Find the colon after the coin name to preserve the address type (p2wpkh:, etc.)
                colonIndex := strings.Index(line[prefixEnd:], ":") + prefixEnd
                if colonIndex > prefixEnd {
                    wif := strings.TrimSpace(line[colonIndex+1:])
                    if wif != "" && coinInfo.WIFPrivateKey == "" {
                        coinInfo.WIFPrivateKey = wif
                    }
                }
            }
        } else if strings.Contains(line, "WIF:") || strings.Contains(line, "wif:") {
            parts := strings.Split(line, ":")
            if len(parts) >= 2 {
                wif := strings.TrimSpace(strings.Join(parts[1:], ":"))
                if wif != "" && coinInfo.WIFPrivateKey == "" {
                    coinInfo.WIFPrivateKey = wif
                }
            }
        } else if (strings.HasPrefix(line, "5") || strings.HasPrefix(line, "K") || strings.HasPrefix(line, "L")) && len(line) >= 50 {
            // Bitcoin-style WIF keys that might not have "WIF:" prefix
            if coinInfo.WIFPrivateKey == "" {
                coinInfo.WIFPrivateKey = line
            }
        }

        // Parse addresses (look for various address formats)
        if strings.Contains(line, "address:") || strings.Contains(line, "Address:") {
            parts := strings.Split(line, ":")
            if len(parts) >= 2 {
                addressStr := strings.TrimSpace(strings.Join(parts[1:], ":"))
                if addressStr != "" && coinInfo.Address == "" {
                    coinInfo.Address = addressStr
                }
            }
        } else if strings.HasPrefix(line, "0x") && len(line) == 42 {
            // Ethereum-style addresses without explicit label
            if coinInfo.Address == "" {
                coinInfo.Address = line
            }
        } else if (strings.HasPrefix(line, "1") || strings.HasPrefix(line, "3") || strings.HasPrefix(line, "bc1")) && 
                 len(line) >= 25 && len(line) <= 62 {
            // Bitcoin-style addresses without explicit label
            if coinInfo.Address == "" {
                coinInfo.Address = line
            }
        }

        // Look for other key information patterns
        if strings.Contains(line, "public key:") || strings.Contains(line, "Public Key:") {
            parts := strings.Split(line, ":")
            if len(parts) >= 2 {
                pubKey := strings.TrimSpace(strings.Join(parts[1:], ":"))
                if pubKey != "" && coinInfo.HexPublicKey == "" {
                    coinInfo.HexPublicKey = pubKey
                }
            }
        }
        
        // Store additional info - prioritize important notes
        shouldStoreAsAdditional := line != coinInfo.Address && 
                                 line != coinInfo.WIFPrivateKey && 
                                 line != coinInfo.HexPrivateKey && 
                                 line != coinInfo.HexPublicKey &&
                                 !strings.Contains(line, "address:") &&
                                 !strings.Contains(line, "public key:")
        
        // Prioritize Ed25519 scalar notes and other important information
        if shouldStoreAsAdditional {
            if strings.Contains(line, "Note:") || strings.Contains(line, "private key scalar") {
                // Ed25519 notes get priority
                if coinInfo.AdditionalInfo == "" {
                    coinInfo.AdditionalInfo = line
                } else {
                    coinInfo.AdditionalInfo = line + "\n" + coinInfo.AdditionalInfo
                }
            } else if coinInfo.AdditionalInfo == "" {
                coinInfo.AdditionalInfo = line
            } else {
                coinInfo.AdditionalInfo += "\n" + line
            }
        }
    }

    return coinInfo
}
