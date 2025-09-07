# Vultisig Share Decoder

Vultisig is a multi-chain, multi-factor, multi-platform Threshold-Signature vault that does not need any specialised hardware. It supports most UTXO, EVM, BFT and EdDSA Chains.

Vultisig doesn't expose private keys during vault creations and instead creates "shares". This is a simple recovery tool to see the public information on your vault share and recover private keys from vault shares (if you have a majority of them). This tool supports both **GG20** and **DKLS** cryptographic schemes.


## Supported Recovery Networks
It currently supports recovering the private keys from the following networks:
UTXO Chains:
- Bitcoin
- Bitcoin Cash
- Dogecoin
- Litecoin
Cosmos/BFT Chains:
- Thorchain
- Mayachain
- Atom
- Kujira
- Dydx
- Terra Classic
- Terra
EVM Chains:
- Ethereum
- Tron

It currently supports extracting signing keys from the following network (a custom signing tool needs to be built):
- Solana
- Ton
- Sui


*You can (and should) run this locally.*

## Supported Schemes
- **GG20**: Full support via web interface
- **DKLS**: Supported via web interface

## Demo
[Demo](https://vultisig-share-decoder.replit.app/?)

### Dependencies
[Go](https://go.dev/doc/install)

### Running the Web Server
1. `git clone`
2. `make all`
3. `./dist/webserver`


## Test Files Included

I included [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak) to test against.

I also included:
- `GG20_1of2.vult` and `GG20_2of2.vult` (GG20 shares)
- `DKLS_1of2.vult` and `DKLS_2of2.vult` (DKLS shares - use web interface)

## Importing results into other wallets

For `ETH` it will return something like this:
```
Private Keys:
ethereum:2abbfad6ea48607d9665eXXXXXbed21204cfe479fdec40d33058c0a4e3feb
```

`2abbfad6ea48607d9665eXXXXXbed21204cfe479fdec40d33058c0a4e3feb` can be imported into [MetaMask](https://metamask.io/)

For `BTC` it will return something like this:
```
WIF Private Keys:
bitcoin: p2wpkh:L5P6V9eVkvy5H8stBGj7MhJxh8cCSLicYvGBcxfLxdFUzuktbEir
```

`p2wpkh:L5P6V9eVkvy5H8stBGj7MhJxh8cCSLicYvGBcxfLxdFUzuktbEir` can be imported into [Electrum](https://electrum.org/#download)

You can also validate that the private key is correct if it generates the Address that matches what you had in Vultisig.


## Running the web server locally
`make all && ./dist/webserver`

## Project Structure
```
├── cmd/                    # Entry points (flattened structure)
│   ├── server.go          # Web server entry point
│   └── wasm.go            # WebAssembly entry point
├── internal/              # Internal packages (organized by function)
│   ├── crypto/            # Cryptographic operations
│   │   ├── tss.go         # TSS service implementation
│   │   └── local_state.go # Local state management
│   ├── processing/        # Key processing and reconstruction
│   │   ├── key_processing.go # Core key reconstruction logic
│   │   ├── key_handlers.go   # Cryptocurrency-specific handlers
│   │   └── shared.go         # Shared processing functionality
│   └── utils/             # Utilities and common types
│       ├── types.go       # Type definitions
│       ├── file_utils.go  # File handling utilities
│       └── encryption.go  # Encryption/decryption utilities
├── web/                   # Web assets (renamed from static/)
│   ├── index.html         # Main web interface
│   ├── main.js            # Frontend JavaScript
│   ├── main.wasm          # Compiled WebAssembly binary for GG20
│   ├── vs_wasm_bg.wasm    # Compiled WebAssembly binary for DKLS
│   ├── style.css          # Styling
│   └── wasm_exec.js       # WebAssembly execution environment
├── examples/              # Example vault files (renamed from example-shares/)
│   ├── GG20_1of2.vult     # GG20 test shares
│   ├── GG20_2of2.vult
│   ├── DKLS_1of2.vult     # DKLS test shares
│   └── DKLS_2of2.vult
├── dist/                  # Build output directory
├── go.mod                 # Go module definition
├── go.sum                 # Go module checksums
├── Makefile              # Build automation
└── README.md             # Project documentation
```

## Build Tags

The project uses Go build tags to manage different builds:
- `wasm`: WebAssembly build for browser
- `server`: Web server build


## Build Commands (in Makefile)

```bash
# Build WebAssembly
GOOS=js GOARCH=wasm go build -o web/main.wasm cmd/wasm.go

# Build Web Server
go build -o dist/webserver cmd/server.go


