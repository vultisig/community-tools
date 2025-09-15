package processing

import (
        "encoding/hex"
        "fmt"
        "crypto/ed25519"

        "github.com/btcsuite/btcd/btcutil"
        "github.com/btcsuite/btcd/btcutil/hdkeychain"
        "github.com/btcsuite/btcd/chaincfg"
        coskey "github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
        "github.com/cosmos/cosmos-sdk/types"
        sdk "github.com/cosmos/cosmos-sdk/types"
        ethcrypto "github.com/ethereum/go-ethereum/crypto"
        "github.com/gcash/bchd/bchec"
        bchChainCfg "github.com/gcash/bchd/chaincfg"
        "github.com/gcash/bchutil"
        dogec "github.com/eager7/dogd/btcec"
        dogechaincfg "github.com/eager7/dogd/chaincfg"
        "github.com/eager7/dogutil"
        "github.com/ltcsuite/ltcd/ltcutil"
        ltcchaincfg "github.com/ltcsuite/ltcd/chaincfg"
        "main/internal/crypto"
        "github.com/btcsuite/btcutil/base58"
        "golang.org/x/crypto/blake2b"
        "golang.org/x/crypto/sha3"
        "crypto/sha256"
        "github.com/tonkeeper/tongo/wallet"
)

// Custom network parameters for Dash mainnet
var DashMainNetParams = chaincfg.Params{
        Name:             "mainnet",
        Net:              0xd9b4bef9, // Dash mainnet magic number
        DefaultPort:      "9999",
        DNSSeeds:         []chaincfg.DNSSeed{},
        
        // Address encoding magics
        PubKeyHashAddrID: 76,  // Dash addresses start with 'X'
        ScriptHashAddrID: 16,  // P2SH addresses start with '7'
        PrivateKeyID:     204, // WIF private keys start with 'X'
        
        // BIP32 hierarchical deterministic extended key magics
        HDPrivateKeyID: [4]byte{0x02, 0xfe, 0x52, 0xf8}, // starts with xprv
        HDPublicKeyID:  [4]byte{0x02, 0xfe, 0x52, 0xcc}, // starts with xpub
        
        // BIP44 coin type
        HDCoinType: 5,
}

// Custom network parameters for Zcash mainnet (transparent addresses)
var ZcashMainNetParams = chaincfg.Params{
        Name:             "mainnet", 
        Net:              0x24e92764, // Zcash mainnet magic number
        DefaultPort:      "8233",
        DNSSeeds:         []chaincfg.DNSSeed{},
        
        // Address encoding magics for transparent addresses
        PubKeyHashAddrID: 0x1C, // Transparent addresses start with 't1' (28 decimal)
        ScriptHashAddrID: 0x1C, // P2SH addresses
        PrivateKeyID:     0x80, // WIF private keys
        
        // BIP32 hierarchical deterministic extended key magics
        HDPrivateKeyID: [4]byte{0x04, 0x88, 0xad, 0xe4}, // starts with xprv
        HDPublicKeyID:  [4]byte{0x04, 0x88, 0xb2, 0x1e}, // starts with xpub
        
        // BIP44 coin type
        HDCoinType: 133,
}

func GetDerivedPrivateKeys(derivePath string, rootPrivateKey *hdkeychain.ExtendedKey) (*hdkeychain.ExtendedKey, error) {
        pathBuf, err := crypto.GetDerivePathBytes(derivePath)
        if err != nil {
                return nil, fmt.Errorf("get derive path bytes failed: %w", err)
        }
        key := rootPrivateKey
        for _, item := range pathBuf {
                key, err = key.Derive(item)
                if err != nil {
                        return nil, err
                }
        }
        return key, nil
}

// UTXOHandler unified handler for all UTXO-family cryptocurrencies (Bitcoin, Bitcoin Cash, Dogecoin, Litecoin)
func UTXOHandler(extendedKey *hdkeychain.ExtendedKey, config EnhancedCoinConfig) (CoinKeyInfo, error) {
        // Extract keys using helper function
        keyPair, err := ExtractECKeys(extendedKey)
        if err != nil {
                return CoinKeyInfo{}, fmt.Errorf("failed to extract keys for %s: %w", config.Name, err)
        }

        // Initialize builder with common fields
        builder := InitializeCoinBuilder(config, extendedKey, keyPair)
        builder.SetNetworkParams("mainnet")

        // Branch based on coin type for network-specific operations
        switch config.Name {
        case "bitcoin":
                return processBitcoin(builder, keyPair)
        case "bitcoinCash":
                return processBitcoinCash(builder, keyPair)
        case "dogecoin":
                return processDogecoin(builder, keyPair)
        case "litecoin":
                return processLitecoin(builder, keyPair)
        case "dash":
                return processDash(builder, keyPair)
        case "zcash":
                return processZcash(builder, keyPair)
        default:
                return builder.Build(), fmt.Errorf("unsupported UTXO coin: %s", config.Name)
        }
}

// processBitcoin handles Bitcoin-specific address and WIF generation
func processBitcoin(builder *CoinKeyBuilder, keyPair *ECKeyPair) (CoinKeyInfo, error) {
        net := &chaincfg.MainNetParams
        
        wif, err := btcutil.NewWIF(keyPair.PrivateKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(keyPair.PublicKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }

        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        builder.SetAdditionalInfo("p2wpkh")
        
        return builder.Build(), nil
}

// processBitcoinCash handles Bitcoin Cash-specific address and WIF generation
func processBitcoinCash(builder *CoinKeyBuilder, keyPair *ECKeyPair) (CoinKeyInfo, error) {
        net := &bchChainCfg.MainNetParams
        
        bchNonHardenedPrivKey, _ := bchec.PrivKeyFromBytes(bchec.S256(), keyPair.PrivateKey.Serialize())
        wif, err := bchutil.NewWIF(bchNonHardenedPrivKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := bchutil.NewAddressPubKeyHash(bchutil.Hash160(keyPair.PublicKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }

        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        
        return builder.Build(), nil
}

// processDogecoin handles Dogecoin-specific address and WIF generation
func processDogecoin(builder *CoinKeyBuilder, keyPair *ECKeyPair) (CoinKeyInfo, error) {
        net := &dogechaincfg.MainNetParams
        
        dogutilNonHardenedPrivKey, _ := dogec.PrivKeyFromBytes(dogec.S256(), keyPair.PrivateKey.Serialize())
        wif, err := dogutil.NewWIF(dogutilNonHardenedPrivKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := dogutil.NewAddressPubKeyHash(dogutil.Hash160(keyPair.PublicKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }

        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        
        return builder.Build(), nil
}

// processLitecoin handles Litecoin-specific address and WIF generation
func processLitecoin(builder *CoinKeyBuilder, keyPair *ECKeyPair) (CoinKeyInfo, error) {
        net := &ltcchaincfg.MainNetParams
        
        wif, err := ltcutil.NewWIF(keyPair.PrivateKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := ltcutil.NewAddressWitnessPubKeyHash(ltcutil.Hash160(keyPair.PublicKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }

        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        
        return builder.Build(), nil
}

// processDash handles Dash-specific address and WIF generation
func processDash(builder *CoinKeyBuilder, keyPair *ECKeyPair) (CoinKeyInfo, error) {
        net := &DashMainNetParams
        
        wif, err := btcutil.NewWIF(keyPair.PrivateKey, net, true)
        if err != nil {
                return builder.Build(), err
        }

        addressPubKey, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(keyPair.PublicKey.SerializeCompressed()), net)
        if err != nil {
                return builder.Build(), err
        }

        builder.SetAddress(addressPubKey.EncodeAddress())
        builder.SetWIFPrivateKey(wif.String())
        builder.SetAdditionalInfo("p2pkh")
        
        return builder.Build(), nil
}

// processZcash handles Zcash transparent address and WIF generation
// Zcash requires custom address encoding with two-byte version prefix
func processZcash(builder *CoinKeyBuilder, keyPair *ECKeyPair) (CoinKeyInfo, error) {
        // Use standard Bitcoin mainnet params for WIF generation (0x80 prefix)
        btcNet := &chaincfg.MainNetParams
        
        wif, err := btcutil.NewWIF(keyPair.PrivateKey, btcNet, true)
        if err != nil {
                return builder.Build(), fmt.Errorf("failed to create Zcash WIF: %w", err)
        }

        // Generate Zcash transparent address with two-byte prefix [0x1C, 0xB8]
        zcashAddress, err := generateZcashTransparentAddress(keyPair.PublicKey.SerializeCompressed())
        if err != nil {
                return builder.Build(), fmt.Errorf("failed to generate Zcash address: %w", err)
        }
        
        // Additional validation: ensure address is not empty (critical for UI display)
        if zcashAddress == "" {
                return builder.Build(), fmt.Errorf("Zcash address generation returned empty string")
        }

        builder.SetAddress(zcashAddress)
        builder.SetWIFPrivateKey(wif.String())
        builder.SetAdditionalInfo("p2pkh")
        
        return builder.Build(), nil
}

// generateZcashTransparentAddress creates a Zcash transparent address with proper two-byte prefix
// Uses manual encoding to ensure WASM compatibility and proper validation
func generateZcashTransparentAddress(pubKeyBytes []byte) (string, error) {
        if len(pubKeyBytes) == 0 {
                return "", fmt.Errorf("public key bytes cannot be empty")
        }
        
        // Hash160 of the public key
        pubKeyHash := btcutil.Hash160(pubKeyBytes)
        if len(pubKeyHash) != 20 {
                return "", fmt.Errorf("invalid hash160 length: %d", len(pubKeyHash))
        }
        
        // Zcash transparent P2PKH version bytes [0x1C, 0xB8] for "t1" addresses
        versionBytes := []byte{0x1C, 0xB8}
        
        // Combine version + hash160 (manual encoding for WASM reliability)
        versioned := make([]byte, 0, len(versionBytes)+len(pubKeyHash))
        versioned = append(versioned, versionBytes...)
        versioned = append(versioned, pubKeyHash...)
        
        // Double SHA256 for checksum (explicit implementation)
        firstHash := sha256.Sum256(versioned)
        secondHash := sha256.Sum256(firstHash[:])
        checksum := secondHash[:4]
        
        // Final address = versioned payload + checksum
        finalAddr := make([]byte, 0, len(versioned)+4)
        finalAddr = append(finalAddr, versioned...)
        finalAddr = append(finalAddr, checksum...)
        
        // Base58 encode with validation
        address := base58.Encode(finalAddr)
        if address == "" {
                return "", fmt.Errorf("base58 encoding failed for Zcash address")
        }
        
        // Validate that address starts with 't1' (Zcash transparent address prefix)
        if len(address) < 2 || address[:2] != "t1" {
                return "", fmt.Errorf("invalid Zcash address format: %s (should start with 't1')", address)
        }
        
        return address, nil
}

// CosmosHandler unified handler for all Cosmos-family cryptocurrencies
func CosmosHandler(extendedKey *hdkeychain.ExtendedKey, config EnhancedCoinConfig) (CoinKeyInfo, error) {
        // Extract bech32 prefix from config params
        bech32Prefix, exists := GetStringParam(config.Params, "bech32Prefix")
        if !exists {
                return CoinKeyInfo{}, fmt.Errorf("bech32Prefix not found in config params for %s", config.Name)
        }
        
        // Use displayName if present, otherwise fall back to config.Name
        coinName := config.Name
        if displayName, exists := GetStringParam(config.Params, "displayName"); exists {
                coinName = displayName
        }
        
        // Use the existing processCosmosLike function
        return processCosmos(extendedKey, bech32Prefix, coinName, config.DerivePath)
}

// EthereumHandler returns structured Ethereum key information
func EthereumHandler(extendedKey *hdkeychain.ExtendedKey, config EnhancedCoinConfig) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("ethereum", config.DerivePath)
        builder.SetExtendedPrivateKey(extendedKey.String())
        
        nonHardenedPubKey, err := extendedKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(ethcrypto.PubkeyToAddress(*nonHardenedPubKey.ToECDSA()).Hex())
        
        return builder.Build(), nil
}


// processCosmosLike returns structured Cosmos chain key information
func processCosmos(extendedPrivateKey *hdkeychain.ExtendedKey, bech32PrefixAcc string, coinName, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder(coinName, derivePath)
        builder.SetExtendedPrivateKey(extendedPrivateKey.String())

        nonHardenedPubKey, err := extendedPrivateKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedPrivateKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        compressedPubkey := coskey.PubKey{
                Key: nonHardenedPubKey.SerializeCompressed(),
        }

        // Generate the address bytes
        addrBytes := types.AccAddress(compressedPubkey.Address().Bytes())

        // Use sdk.Bech32ifyAccPub with the correct prefix
        bech32Addr := sdk.MustBech32ifyAddressBytes(bech32PrefixAcc, addrBytes)
        
        builder.SetHexPublicKey(hex.EncodeToString(nonHardenedPubKey.SerializeCompressed()))
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetAddress(bech32Addr)
        builder.SetNetworkParams("mainnet")
        
        return builder.Build(), nil
}


// processSolana returns structured Solana key information from raw Ed25519 keys
func processSolana(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("solana", derivePath)
        
        // For Solana, the Ed25519 public key IS the address
        solanaAddress := base58.Encode(eddsaPublicKeyBytes)
        
        builder.SetHexPrivateKey(hex.EncodeToString(eddsaPrivateKeyBytes))
        builder.SetHexPublicKey(hex.EncodeToString(eddsaPublicKeyBytes))
        builder.SetAddress(solanaAddress)
        builder.SetAdditionalInfo("Note: This is a private key scalar and can only be used for signing, not importing into another wallet")
        
        return builder.Build(), nil
}

// processSui returns structured Sui key information from raw Ed25519 keys
func processSui(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("sui", derivePath)
        
        // For Sui, we need to create an address from the public key using Blake2b hashing
        // Sui address = Blake2b(scheme_flag || public_key)[0:20]
        // where scheme_flag = 0x00 for Ed25519
        
        // Create the input for hashing: scheme flag (0x00 for Ed25519) + public key
        input := make([]byte, 1+len(eddsaPublicKeyBytes))
        input[0] = 0x00 // Ed25519 scheme flag
        copy(input[1:], eddsaPublicKeyBytes)
        
        // Hash using Blake2b
        hash := blake2b.Sum256(input)
        
        // Use full hash for address
        addressBytes := hash[:]
        
        // Convert to hex with 0x prefix for Sui address format
        suiAddress := "0x" + hex.EncodeToString(addressBytes)
        
        builder.SetHexPrivateKey(hex.EncodeToString(eddsaPrivateKeyBytes))
        builder.SetHexPublicKey(hex.EncodeToString(eddsaPublicKeyBytes))
        builder.SetAddress(suiAddress)
        builder.SetAdditionalInfo("Note: This is a private key scalar and can only be used for signing, not importing into another wallet")
        
        return builder.Build(), nil
}

// TronHandler returns structured Tron key information
func TronHandler(extendedKey *hdkeychain.ExtendedKey, config EnhancedCoinConfig) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("tron", config.DerivePath)
        builder.SetExtendedPrivateKey(extendedKey.String())
        
        nonHardenedPubKey, err := extendedKey.ECPubKey()
        if err != nil {
                return builder.Build(), err
        }
        nonHardenedPrivKey, err := extendedKey.ECPrivKey()
        if err != nil {
                return builder.Build(), err
        }

        // Get uncompressed public key (64 bytes + 0x04 prefix)
        pubKeyECDSA := nonHardenedPubKey.ToECDSA()
        pubKeyBytes := ethcrypto.FromECDSAPub(pubKeyECDSA)
        
        // Remove the 0x04 prefix to get the 64-byte uncompressed key
        pubKeyNoPrefix := pubKeyBytes[1:]
        
        // Hash with Keccak256
        hash := sha3.NewLegacyKeccak256()
        hash.Write(pubKeyNoPrefix)
        pubKeyHash := hash.Sum(nil)
        
        // Take the last 20 bytes
        ethAddr := pubKeyHash[12:]
        
        // Prefix with Tron version byte (0x41 for mainnet)
        tronAddr := make([]byte, 21)
        tronAddr[0] = 0x41
        copy(tronAddr[1:], ethAddr)
        
        // Calculate checksum using double SHA256
        firstSHA := sha256.Sum256(tronAddr)
        secondSHA := sha256.Sum256(firstSHA[:])
        checksum := secondSHA[:4]
        
        // Combine address + checksum and encode with Base58
        addrWithChecksum := make([]byte, 25)
        copy(addrWithChecksum[:21], tronAddr)
        copy(addrWithChecksum[21:], checksum)
        
        tronAddress := base58.Encode(addrWithChecksum)
        
        builder.SetHexPrivateKey(hex.EncodeToString(nonHardenedPrivKey.Serialize()))
        builder.SetHexPublicKey(hex.EncodeToString(pubKeyBytes))
        builder.SetAddress(tronAddress)
        
        return builder.Build(), nil
}

// processTon returns structured TON key information from raw Ed25519 keys
func processTon(eddsaPrivateKeyBytes []byte, eddsaPublicKeyBytes []byte, derivePath string) (CoinKeyInfo, error) {
        builder := NewCoinKeyBuilder("ton", derivePath)
        
        // Validate key lengths
        if len(eddsaPrivateKeyBytes) != 32 {
                return builder.Build(), fmt.Errorf("private key must be 32 bytes, got %d", len(eddsaPrivateKeyBytes))
        }
        if len(eddsaPublicKeyBytes) != 32 {
                return builder.Build(), fmt.Errorf("public key must be 32 bytes, got %d", len(eddsaPublicKeyBytes))
        }

        // Set wallet parameters for mainnet V3R2 wallet
        ver := wallet.V4R2
        workchain := 0                         // Mainnet workchain
        networkGlobalID := int32(-239)         // Mainnet global ID
        subWalletId := uint32(698983191)       // Default subWalletId for v3R2

        // Generate address using the improved offline method
        addr, err := wallet.GenerateWalletAddress(
                ed25519.PublicKey(eddsaPublicKeyBytes),
                ver,
                &networkGlobalID,
                workchain,
                &subWalletId,
        )
        if err != nil {
                return builder.Build(), fmt.Errorf("error generating wallet address: %w", err)
        }

        // Convert to user-friendly, non-bounceable, mainnet format
        tonAddress := addr.ToHuman(false, false) // bounceable=false, testnet=false
        
        builder.SetHexPrivateKey(hex.EncodeToString(eddsaPrivateKeyBytes))
        builder.SetHexPublicKey(hex.EncodeToString(eddsaPublicKeyBytes))
        builder.SetAddress(tonAddress)
        builder.SetAdditionalInfo("Note: This is a private key scalar and can only be used for signing, not importing into another wallet")
        
        return builder.Build(), nil
}

// EdDSA Handler Functions using proper EdDSACoinHandler signature

// SolanaEdDSAHandler processes Solana keys using proper EdDSA cryptography
func SolanaEdDSAHandler(privateKeyBytes, publicKeyBytes []byte, config EnhancedCoinConfig) (CoinKeyInfo, error) {
        return processSolana(privateKeyBytes, publicKeyBytes, config.DerivePath)
}

// SuiEdDSAHandler processes Sui keys using proper EdDSA cryptography
func SuiEdDSAHandler(privateKeyBytes, publicKeyBytes []byte, config EnhancedCoinConfig) (CoinKeyInfo, error) {
        return processSui(privateKeyBytes, publicKeyBytes, config.DerivePath)
}

// TonEdDSAHandler processes TON keys using proper EdDSA cryptography
func TonEdDSAHandler(privateKeyBytes, publicKeyBytes []byte, config EnhancedCoinConfig) (CoinKeyInfo, error) {
        return processTon(privateKeyBytes, publicKeyBytes, config.DerivePath)
}

