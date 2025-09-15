package processing

// DebugLevel represents the severity level of a debug event
type DebugLevel string

const (
        DEBUG DebugLevel = "DEBUG"
        INFO  DebugLevel = "INFO"
        WARN  DebugLevel = "WARN"
        ERROR DebugLevel = "ERROR"
)

// DebugEvent represents a single debug event captured during processing
type DebugEvent struct {
        Timestamp string         `json:"timestamp"`
        Level     DebugLevel     `json:"level"`
        Category  string         `json:"category"`
        Message   string         `json:"message"`
        Phase     string         `json:"phase,omitempty"`
        Share     string         `json:"share,omitempty"`
        Fields    map[string]any `json:"fields,omitempty"`
}

// DebugPayload represents the complete debug information for a processing session
type DebugPayload struct {
        Enabled    bool         `json:"enabled"`
        Level      DebugLevel   `json:"level"`
        Categories []string     `json:"categories"`
        Dropped    int          `json:"dropped"`
        Events     []DebugEvent `json:"events"`
}

// CoinKeyInfo represents key information for a specific cryptocurrency
type CoinKeyInfo struct {
        Name            string `json:"name"`
        DerivePath      string `json:"derivePath"`
        ExtendedPrivKey string `json:"extendedPrivateKey,omitempty"`
        HexPrivateKey   string `json:"hexPrivateKey"`
        HexPublicKey    string `json:"hexPublicKey"`
        Address         string `json:"address"`
        WIFPrivateKey   string `json:"wifPrivateKey,omitempty"`
        NetworkParams   string `json:"networkParams,omitempty"`
        AdditionalInfo  string `json:"additionalInfo,omitempty"`
}

// ShareDetails represents information about the vault shares
type ShareDetails struct {
        BackupName    string   `json:"backupName"`
        ThisShare     string   `json:"thisShare"`
        AllShares     []string `json:"allShares"`
        ResharePrefix string   `json:"resharePrefix,omitempty"`
}

// PublicKeyInfo represents public key information for different algorithms
type PublicKeyInfo struct {
        ECDSA string `json:"ecdsa,omitempty"`
        EdDSA string `json:"eddsa,omitempty"`
}

// RootKeyInfo represents root key information
type RootKeyInfo struct {
        HexPubKeyECDSA  string `json:"hexPubKeyECDSA"`
        HexPrivKeyECDSA string `json:"hexPrivKeyECDSA"`
        HexPubKeyEdDSA  string `json:"hexPubKeyEdDSA,omitempty"`
        HexPrivKeyEdDSA string `json:"hexPrivKeyEdDSA,omitempty"`
        ChainCode       string `json:"chainCode"`
        ExtendedPrivKey string `json:"extendedPrivateKey"`
}

// ProcessResult represents the complete result from processing vault files
type ProcessResult struct {
        Success      bool           `json:"success"`
        Error        string         `json:"error,omitempty"`
        ShareDetails []ShareDetails `json:"shareDetails"`
        PublicKeys   PublicKeyInfo  `json:"publicKeys"`
        RootKeyInfo  *RootKeyInfo   `json:"rootKeyInfo,omitempty"`
        CoinKeys     []CoinKeyInfo  `json:"coinKeys"`
        Debug        *DebugPayload  `json:"debug,omitempty"`
}

// DeriveKeysResult represents the result from deriving keys for all supported coins
type DeriveKeysResult struct {
        Success     bool          `json:"success"`
        Error       string        `json:"error,omitempty"`
        RootKeyInfo RootKeyInfo   `json:"rootKeyInfo"`
        ECDSAKeys   []CoinKeyInfo `json:"ecdsaKeys"`
        EdDSAKeys   []CoinKeyInfo `json:"eddsaKeys"`
        Debug       *DebugPayload `json:"debug,omitempty"`
}

// CoinSupportInfo represents information about a supported coin
type CoinSupportInfo struct {
        Name       string `json:"name"`
        DerivePath string `json:"derivePath"`
        Algorithm  string `json:"algorithm"` // "ECDSA" or "EdDSA"
}

// GetSupportedCoinsResult represents the result from getting supported coins
type GetSupportedCoinsResult struct {
        Success    bool              `json:"success"`
        Error      string            `json:"error,omitempty"`
        ECDSACoins []CoinSupportInfo `json:"ecdsaCoins"`
        EdDSACoins []CoinSupportInfo `json:"eddsaCoins"`
}
