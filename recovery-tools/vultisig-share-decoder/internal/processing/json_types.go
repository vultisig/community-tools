package processing

// CoinKeyInfo represents key information for a specific cryptocurrency
type CoinKeyInfo struct {
	Name              string `json:"name"`
	DerivePath        string `json:"derivePath"`
	ExtendedPrivKey   string `json:"extendedPrivateKey,omitempty"`
	HexPrivateKey     string `json:"hexPrivateKey"`
	HexPublicKey      string `json:"hexPublicKey"`
	Address           string `json:"address"`
	WIFPrivateKey     string `json:"wifPrivateKey,omitempty"`
	NetworkParams     string `json:"networkParams,omitempty"`
	AdditionalInfo    string `json:"additionalInfo,omitempty"`
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
	ChainCode       string `json:"chainCode"`
	ExtendedPrivKey string `json:"extendedPrivateKey"`
}

// ProcessResult represents the complete result from processing vault files
type ProcessResult struct {
	Success       bool            `json:"success"`
	Error         string          `json:"error,omitempty"`
	ShareDetails  []ShareDetails  `json:"shareDetails"`
	PublicKeys    PublicKeyInfo   `json:"publicKeys"`
	RootKeyInfo   *RootKeyInfo    `json:"rootKeyInfo,omitempty"`
	CoinKeys      []CoinKeyInfo   `json:"coinKeys"`
	RawOutput     string          `json:"rawOutput,omitempty"` // Keep for backward compatibility
}

// DeriveKeysResult represents the result from deriving keys for all supported coins
type DeriveKeysResult struct {
	Success     bool          `json:"success"`
	Error       string        `json:"error,omitempty"`
	RootKeyInfo RootKeyInfo   `json:"rootKeyInfo"`
	ECDSAKeys   []CoinKeyInfo `json:"ecdsaKeys"`
	EdDSAKeys   []CoinKeyInfo `json:"eddsaKeys"`
	RawOutput   string        `json:"rawOutput,omitempty"` // Keep for backward compatibility
}

// CoinSupportInfo represents information about a supported coin
type CoinSupportInfo struct {
	Name       string `json:"name"`
	DerivePath string `json:"derivePath"`
	Algorithm  string `json:"algorithm"` // "ECDSA" or "EdDSA"
}

// GetSupportedCoinsResult represents the result from getting supported coins
type GetSupportedCoinsResult struct {
	Success   bool               `json:"success"`
	Error     string             `json:"error,omitempty"`
	ECDSACoins []CoinSupportInfo `json:"ecdsaCoins"`
	EdDSACoins []CoinSupportInfo `json:"eddsaCoins"`
}