package processing

import (
        "encoding/hex"
        "fmt"

        "github.com/btcsuite/btcd/btcutil/hdkeychain"
        "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// CoinFamily represents different cryptocurrency families
type CoinFamily string

const (
        FamilyUTXO   CoinFamily = "utxo"
        FamilyCosmos CoinFamily = "cosmos"  
        FamilyEVM    CoinFamily = "evm"
        FamilyEdDSA  CoinFamily = "eddsa"
)

// CoinParams stores coin-specific parameters
type CoinParams map[string]interface{}

// CoinHandler defines the function signature for processing a coin's keys
type CoinHandler func(extendedKey *hdkeychain.ExtendedKey, config EnhancedCoinConfig) (CoinKeyInfo, error)

// EdDSACoinHandler defines the function signature for processing EdDSA-based coin keys
type EdDSACoinHandler func(privateKeyBytes, publicKeyBytes []byte, config EnhancedCoinConfig) (CoinKeyInfo, error)

// EnhancedCoinConfig represents configuration for a supported cryptocurrency with extended metadata
type EnhancedCoinConfig struct {
        Name       string
        DerivePath string
        Family     CoinFamily
        Params     CoinParams
        Handler    CoinHandler        // For ECDSA coins
        EdDSAHandler EdDSACoinHandler // For EdDSA coins
}





// Helper Functions for Common Operations

// ECKeyPair represents an ECDSA key pair
type ECKeyPair struct {
        PublicKey  *secp256k1.PublicKey
        PrivateKey *secp256k1.PrivateKey
}

// ExtractECKeys extracts EC public and private keys from an extended key
func ExtractECKeys(extendedKey *hdkeychain.ExtendedKey) (*ECKeyPair, error) {
        publicKey, err := extendedKey.ECPubKey()
        if err != nil {
                return nil, fmt.Errorf("failed to extract public key: %w", err)
        }

        privateKey, err := extendedKey.ECPrivKey()
        if err != nil {
                return nil, fmt.Errorf("failed to extract private key: %w", err)
        }

        return &ECKeyPair{
                PublicKey:  publicKey,
                PrivateKey: privateKey,
        }, nil
}

// InitializeCoinBuilder creates and initializes a CoinKeyBuilder with common ECDSA fields
func InitializeCoinBuilder(config EnhancedCoinConfig, extendedKey *hdkeychain.ExtendedKey, keyPair *ECKeyPair) *CoinKeyBuilder {
        builder := NewCoinKeyBuilder(config.Name, config.DerivePath)
        
        // Set extended private key
        builder.SetExtendedPrivateKey(extendedKey.String())
        
        // Set hex-encoded keys
        builder.SetHexPublicKey(hex.EncodeToString(keyPair.PublicKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(keyPair.PrivateKey.Serialize()))
        
        return builder
}

// SetCommonECDSAFields sets common fields that most ECDSA coins share
func SetCommonECDSAFields(builder *CoinKeyBuilder, extendedKey *hdkeychain.ExtendedKey, keyPair *ECKeyPair) *CoinKeyBuilder {
        builder.SetExtendedPrivateKey(extendedKey.String())
        builder.SetHexPublicKey(hex.EncodeToString(keyPair.PublicKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(keyPair.PrivateKey.Serialize()))
        builder.SetNetworkParams("mainnet") // Most coins use mainnet
        
        return builder
}

// GetCoinParam safely retrieves a parameter from coin config with type assertion
func GetCoinParam(params CoinParams, key string) (interface{}, bool) {
        if params == nil {
                return nil, false
        }
        value, exists := params[key]
        return value, exists
}

// GetStringParam safely retrieves a string parameter from coin config
func GetStringParam(params CoinParams, key string) (string, bool) {
        if value, exists := GetCoinParam(params, key); exists {
                if str, ok := value.(string); ok {
                        return str, true
                }
        }
        return "", false
}

// GetBoolParam safely retrieves a boolean parameter from coin config
func GetBoolParam(params CoinParams, key string) (bool, bool) {
        if value, exists := GetCoinParam(params, key); exists {
                if b, ok := value.(bool); ok {
                        return b, true
                }
        }
        return false, false
}

// Enhanced Configuration Functions

// GetEnhancedECDSACoins returns the list of all supported ECDSA cryptocurrencies with enhanced configuration
func GetEnhancedECDSACoins() []EnhancedCoinConfig {
        return []EnhancedCoinConfig{
                // UTXO Family
                {
                        Name:       "bitcoin",
                        DerivePath: "m/84'/0'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2wpkh", // Pay to Witness PubKey Hash
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler:    UTXOHandler,
                },
                {
                        Name:       "bitcoinCash",
                        DerivePath: "m/44'/145'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2pkh", // Pay to PubKey Hash
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler:    UTXOHandler,
                },
                {
                        Name:       "dogecoin",
                        DerivePath: "m/44'/3'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2pkh",
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler:    UTXOHandler,
                },
                {
                        Name:       "litecoin",
                        DerivePath: "m/84'/2'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2wpkh",
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler:    UTXOHandler,
                },
                {
                        Name:       "dash",
                        DerivePath: "m/44'/5'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2pkh",
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler:    UTXOHandler,
                },
                {
                        Name:       "zcash",
                        DerivePath: "m/44'/133'/0'/0/0",
                        Family:     FamilyUTXO,
                        Params: CoinParams{
                                "addressType": "p2pkh",
                                "network":     "mainnet",
                                "compressed":  true,
                        },
                        Handler:    UTXOHandler,
                },
                // Cosmos Family
                {
                        Name:       "thorchain",
                        DerivePath: "m/44'/931'/0'/0/0",
                        Family:     FamilyCosmos,
                        Params: CoinParams{
                                "bech32Prefix":    "thor",
                                "bech32PubPrefix": "thorpub",
                                "bech32ValPrefix": "thorv",
                                "bech32ValPubPrefix": "thorvpub",
                                "bech32ConsPrefix": "thorc",
                                "bech32ConsPubPrefix": "thorcpub",
                                "displayName":     "THORChain",
                        },
                        Handler:    CosmosHandler,
                },
                {
                        Name:       "mayachain",
                        DerivePath: "m/44'/931'/0'/0/0",
                        Family:     FamilyCosmos,
                        Params: CoinParams{
                                "bech32Prefix":    "maya",
                                "bech32PubPrefix": "mayapub",
                                "bech32ValPrefix": "mayav",
                                "bech32ValPubPrefix": "mayavpub",
                                "bech32ConsPrefix": "mayac",
                                "bech32ConsPubPrefix": "mayacpub",
                                "displayName":     "MAYAChain",
                        },
                        Handler:    CosmosHandler,
                },
                {
                        Name:       "atom",
                        DerivePath: "m/44'/118'/0'/0/0",
                        Family:     FamilyCosmos,
                        Params: CoinParams{
                                "bech32Prefix": "cosmos",
                                "displayName":  "Atom",
                        },
                        Handler:    CosmosHandler,
                },
                {
                        Name:       "kujira",
                        DerivePath: "m/44'/118'/0'/0/0",
                        Family:     FamilyCosmos,
                        Params: CoinParams{
                                "bech32Prefix": "kujira",
                                "displayName":  "Kujira",
                        },
                        Handler:    CosmosHandler,
                },
                {
                        Name:       "dydx",
                        DerivePath: "m/44'/118'/0'/0/0",
                        Family:     FamilyCosmos,
                        Params: CoinParams{
                                "bech32Prefix": "dydx",
                                "displayName":  "dYdX",
                        },
                        Handler:    CosmosHandler,
                },
                {
                        Name:       "terra-classic",
                        DerivePath: "m/44'/118'/0'/0/0",
                        Family:     FamilyCosmos,
                        Params: CoinParams{
                                "bech32Prefix": "terra",
                                "displayName":  "Terra Classic",
                        },
                        Handler:    CosmosHandler,
                },
                {
                        Name:       "terra",
                        DerivePath: "m/44'/118'/0'/0/0",
                        Family:     FamilyCosmos,
                        Params: CoinParams{
                                "bech32Prefix": "terra",
                                "displayName":  "Terra",
                        },
                        Handler:    CosmosHandler,
                },
                // EVM Family
                {
                        Name:       "ethereum",
                        DerivePath: "m/44'/60'/0'/0/0",
                        Family:     FamilyEVM,
                        Params: CoinParams{
                                "chainId": 1, // Mainnet
                                "network": "mainnet",
                        },
                        Handler:    EthereumHandler,
                },
                {
                        Name:       "tron",
                        DerivePath: "m/44'/195'/0'/0/0",
                        Family:     FamilyEVM,
                        Params: CoinParams{
                                "network": "mainnet",
                                "addressPrefix": "0x41", // Tron mainnet version byte
                        },
                        Handler:    TronHandler,
                },
        }
}

// GetEnhancedEdDSACoins returns the list of all supported EdDSA cryptocurrencies with enhanced configuration
func GetEnhancedEdDSACoins() []EnhancedCoinConfig {
        return []EnhancedCoinConfig{
                {
                        Name:       "solana",
                        DerivePath: "m/44'/501'/0'/0'",
                        Family:     FamilyEdDSA,
                        Params: CoinParams{
                                "algorithm": "ed25519",
                                "encoding":  "base58",
                                "network":   "mainnet",
                        },
                        EdDSAHandler: SolanaEdDSAHandler,
                },
                {
                        Name:       "sui",
                        DerivePath: "m/44'/784'/0'/0'/0'",
                        Family:     FamilyEdDSA,
                        Params: CoinParams{
                                "algorithm":    "ed25519",
                                "hashFunction": "blake2b",
                                "schemeFlag":   "0x00", // Ed25519 scheme flag for Sui
                                "addressFormat": "0x-prefixed hex",
                                "network":      "mainnet",
                        },
                        EdDSAHandler: SuiEdDSAHandler,
                },
                {
                        Name:       "ton",
                        DerivePath: "m/44'/607'/0'/0'/0'",
                        Family:     FamilyEdDSA,
                        Params: CoinParams{
                                "algorithm":       "ed25519",
                                "walletVersion":   "v4r2",
                                "workchain":       0,
                                "networkGlobalID": int32(-239), // Mainnet global ID
                                "subWalletId":     uint32(698983191), // Default subWalletId
                                "bounceable":      false,
                                "testnet":         false,
                                "network":         "mainnet",
                        },
                        EdDSAHandler: TonEdDSAHandler,
                },
        }
}

// GetCoinsByFamily returns all enhanced coins filtered by family type
func GetCoinsByFamily(family CoinFamily) []EnhancedCoinConfig {
        allCoins := append(GetEnhancedECDSACoins(), GetEnhancedEdDSACoins()...)
        
        var filtered []EnhancedCoinConfig
        for _, coin := range allCoins {
                if coin.Family == family {
                        filtered = append(filtered, coin)
                }
        }
        
        return filtered
}

// GetAllEnhancedCoins returns all supported cryptocurrencies with enhanced configuration
func GetAllEnhancedCoins() []EnhancedCoinConfig {
        return append(GetEnhancedECDSACoins(), GetEnhancedEdDSACoins()...)
}

// CoinHandlerRegistry maps coin names to their respective handlers
var CoinHandlerRegistry map[string]CoinHandler

// InitializeCoinHandlerRegistry sets up the registry mapping coin names to handlers
func InitializeCoinHandlerRegistry() {
        CoinHandlerRegistry = make(map[string]CoinHandler)
        
        // Populate registry from enhanced coin configurations
        enhancedCoins := GetEnhancedECDSACoins()
        for _, coin := range enhancedCoins {
                if coin.Handler != nil {
                        CoinHandlerRegistry[coin.Name] = coin.Handler
                }
        }
}

// GetCoinHandler retrieves a handler for the given coin name from the registry
func GetCoinHandler(coinName string) (CoinHandler, bool) {
        handler, exists := CoinHandlerRegistry[coinName]
        return handler, exists
}

