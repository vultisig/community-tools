package processing

import (
        "encoding/hex"
        "encoding/json"
        "fmt"

        "github.com/btcsuite/btcd/btcutil/hdkeychain"
        "github.com/btcsuite/btcd/chaincfg"
        "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// CoinKeyBuilder helps build CoinKeyInfo structs from key derivation
type CoinKeyBuilder struct {
        keyInfo CoinKeyInfo
}

// NewCoinKeyBuilder creates a new builder for a specific coin
func NewCoinKeyBuilder(name, derivePath string) *CoinKeyBuilder {
        return &CoinKeyBuilder{
                keyInfo: CoinKeyInfo{
                        Name:       name,
                        DerivePath: derivePath,
                },
        }
}

// SetExtendedPrivateKey sets the extended private key
func (b *CoinKeyBuilder) SetExtendedPrivateKey(key string) *CoinKeyBuilder {
        b.keyInfo.ExtendedPrivKey = key
        return b
}

// SetHexPrivateKey sets the hex encoded private key
func (b *CoinKeyBuilder) SetHexPrivateKey(key string) *CoinKeyBuilder {
        b.keyInfo.HexPrivateKey = key
        return b
}

// SetHexPublicKey sets the hex encoded public key
func (b *CoinKeyBuilder) SetHexPublicKey(key string) *CoinKeyBuilder {
        b.keyInfo.HexPublicKey = key
        return b
}

// SetAddress sets the cryptocurrency address
func (b *CoinKeyBuilder) SetAddress(address string) *CoinKeyBuilder {
        b.keyInfo.Address = address
        return b
}

// SetWIFPrivateKey sets the WIF private key
func (b *CoinKeyBuilder) SetWIFPrivateKey(wif string) *CoinKeyBuilder {
        b.keyInfo.WIFPrivateKey = wif
        return b
}

// SetNetworkParams sets network parameters info
func (b *CoinKeyBuilder) SetNetworkParams(params string) *CoinKeyBuilder {
        b.keyInfo.NetworkParams = params
        return b
}

// SetAdditionalInfo sets additional information
func (b *CoinKeyBuilder) SetAdditionalInfo(info string) *CoinKeyBuilder {
        b.keyInfo.AdditionalInfo = info
        return b
}

// Build returns the constructed CoinKeyInfo
func (b *CoinKeyBuilder) Build() CoinKeyInfo {
        return b.keyInfo
}

// BuildRootKeyInfoFromBytes creates RootKeyInfo from raw key material
func BuildRootKeyInfoFromBytes(rootPrivateKeyBytes, rootChainCodeBytes []byte) RootKeyInfo {
        privateKey := secp256k1.PrivKeyFromBytes(rootPrivateKeyBytes)
        publicKey := privateKey.PubKey()
        
        net := &chaincfg.MainNetParams
        extendedPrivateKey := hdkeychain.NewExtendedKey(
                net.HDPrivateKeyID[:],
                privateKey.Serialize(),
                rootChainCodeBytes,
                []byte{0x00, 0x00, 0x00, 0x00},
                0,
                0,
                true,
        )

        return RootKeyInfo{
                HexPubKeyECDSA:  hex.EncodeToString(publicKey.SerializeCompressed()),
                HexPrivKeyECDSA: hex.EncodeToString(privateKey.Serialize()),
                ChainCode:       hex.EncodeToString(rootChainCodeBytes),
                ExtendedPrivKey: extendedPrivateKey.String(),
        }
}

// ProcessRootKeyForCoinsJSON processes root key material and returns structured data
func ProcessRootKeyForCoinsJSON(rootPrivateKeyBytes []byte, rootChainCodeBytes []byte, coinConfigs []EnhancedCoinConfig) (RootKeyInfo, []CoinKeyInfo, error) {
        // Build root key info
        rootKeyInfo := BuildRootKeyInfoFromBytes(rootPrivateKeyBytes, rootChainCodeBytes)
        
        // Create secp256k1 private key from bytes
        privateKey := secp256k1.PrivKeyFromBytes(rootPrivateKeyBytes)
        
        // Create extended key for derivation
        net := &chaincfg.MainNetParams
        extendedPrivateKey := hdkeychain.NewExtendedKey(
                net.HDPrivateKeyID[:],
                privateKey.Serialize(),
                rootChainCodeBytes,
                []byte{0x00, 0x00, 0x00, 0x00},
                0,
                0,
                true,
        )

        var coinKeys []CoinKeyInfo

        // Process each enhanced coin configuration using the appropriate handler
        for _, coin := range coinConfigs {
                key, err := GetDerivedPrivateKeys(coin.DerivePath, extendedPrivateKey)
                if err != nil {
                        return rootKeyInfo, nil, fmt.Errorf("error deriving private key for %s: %w", coin.Name, err)
                }

                // Use the enhanced configuration handler
                var coinKeyInfo CoinKeyInfo
                if coin.Handler != nil {
                        coinKeyInfo, err = coin.Handler(key, coin)
                } else {
                        return rootKeyInfo, nil, fmt.Errorf("no handler available for coin: %s", coin.Name)
                }

                if err != nil {
                        return rootKeyInfo, nil, fmt.Errorf("error processing %s keys: %w", coin.Name, err)
                }

                coinKeys = append(coinKeys, coinKeyInfo)
        }

        return rootKeyInfo, coinKeys, nil
}

// ProcessEdDSAKeyForCoinsJSON processes EdDSA key material and returns structured data
func ProcessEdDSAKeyForCoinsJSON(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, coinConfigs []EnhancedCoinConfig) ([]CoinKeyInfo, error) {
        var coinKeys []CoinKeyInfo

        // Process each EdDSA coin configuration using the handler-based approach
        for _, coin := range coinConfigs {
                // Check if EdDSAHandler is available
                if coin.EdDSAHandler == nil {
                        return nil, fmt.Errorf("no EdDSA handler available for coin: %s", coin.Name)
                }

                // Use the coin's EdDSAHandler instead of switch statement
                coinKeyInfo, err := coin.EdDSAHandler(eddsaPrivateKeyBytes, eddsaPublicKeyBytes, coin)
                if err != nil {
                        return nil, fmt.Errorf("error processing %s keys: %w", coin.Name, err)
                }

                coinKeys = append(coinKeys, coinKeyInfo)
        }

        return coinKeys, nil
}


// ConvertSupportedCoinsToJSON converts coin configs to JSON format
func ConvertSupportedCoinsToJSON() GetSupportedCoinsResult {
        ecdsaCoins := GetEnhancedECDSACoins()
        eddsaCoins := GetEnhancedEdDSACoins()
        
        var ecdsaSupportInfo []CoinSupportInfo
        for _, coin := range ecdsaCoins {
                ecdsaSupportInfo = append(ecdsaSupportInfo, CoinSupportInfo{
                        Name:       coin.Name,
                        DerivePath: coin.DerivePath,
                        Algorithm:  "ECDSA",
                })
        }
        
        var eddsaSupportInfo []CoinSupportInfo
        for _, coin := range eddsaCoins {
                eddsaSupportInfo = append(eddsaSupportInfo, CoinSupportInfo{
                        Name:       coin.Name,
                        DerivePath: coin.DerivePath,
                        Algorithm:  "EdDSA",
                })
        }

        return GetSupportedCoinsResult{
                Success:    true,
                ECDSACoins: ecdsaSupportInfo,
                EdDSACoins: eddsaSupportInfo,
        }
}

// DeriveAndShowKeysJSON processes root key material and returns JSON result
func DeriveAndShowKeysJSON(rootPrivateKeyHex, rootChainCodeHex string, eddsaPrivateKeyHex, eddsaPublicKeyHex string) (DeriveKeysResult, error) {
        result := DeriveKeysResult{
                Success: true,
                ECDSAKeys: make([]CoinKeyInfo, 0),
                EdDSAKeys: make([]CoinKeyInfo, 0),
        }

        // Decode hex strings
        rootPrivateKeyBytes, err := hex.DecodeString(rootPrivateKeyHex)
        if err != nil {
                result.Success = false
                result.Error = fmt.Sprintf("Error decoding private key hex: %v", err)
                return result, err
        }

        rootChainCodeBytes, err := hex.DecodeString(rootChainCodeHex)
        if err != nil {
                result.Success = false
                result.Error = fmt.Sprintf("Error decoding chain code hex: %v", err)
                return result, err
        }

        // Build root key info
        result.RootKeyInfo = BuildRootKeyInfoFromBytes(rootPrivateKeyBytes, rootChainCodeBytes)

        // Process ECDSA coins
        ecdsaCoins := GetEnhancedECDSACoins()
        _, ecdsaKeyInfos, err := ProcessRootKeyForCoinsJSON(rootPrivateKeyBytes, rootChainCodeBytes, ecdsaCoins)
        if err != nil {
                result.Success = false
                result.Error = fmt.Sprintf("Error processing ECDSA keys: %v", err)
                return result, err
        }
        result.ECDSAKeys = ecdsaKeyInfos

        // Process EdDSA coins if provided
        if eddsaPrivateKeyHex != "" && eddsaPublicKeyHex != "" {
                eddsaPrivateKeyBytes, err := hex.DecodeString(eddsaPrivateKeyHex)
                if err != nil {
                        result.Success = false
                        result.Error = fmt.Sprintf("Error decoding EdDSA private key hex: %v", err)
                        return result, err
                }

                eddsaPublicKeyBytes, err := hex.DecodeString(eddsaPublicKeyHex)
                if err != nil {
                        result.Success = false
                        result.Error = fmt.Sprintf("Error decoding EdDSA public key hex: %v", err)
                        return result, err
                }

                eddsaCoins := GetEnhancedEdDSACoins()
                eddsaKeyInfos, err := ProcessEdDSAKeyForCoinsJSON(eddsaPrivateKeyBytes, eddsaPublicKeyBytes, eddsaCoins)
                if err != nil {
                        result.Success = false
                        result.Error = fmt.Sprintf("Error processing EdDSA keys: %v", err)
                        return result, err
                }
                result.EdDSAKeys = eddsaKeyInfos
        }

        return result, nil
}

// ToJSON converts any result struct to JSON string
func ToJSON(v interface{}) (string, error) {
        jsonBytes, err := json.Marshal(v)
        if err != nil {
                return "", fmt.Errorf("error marshaling to JSON: %w", err)
        }
        return string(jsonBytes), nil
}