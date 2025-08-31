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
- **GG20**: Full support via CLI and web interface
- **DKLS**: Only supported via the web interface (CLI support not available)

## Demo
[Demo](https://vultisig-share-decoder.replit.app/?)

### Dependencies
[Go](https://go.dev/doc/install)

### Running the GO Binary
1. `git clone`
2. `make all`
3. `./dist/cli ....` or `/.dist/webserver`

## CLI Commands

### Recover Keys from Vault Shares
**Note: DKLS recovery is only supported via the web interface, not the CLI**

Recover private keys from GG20 vault shares:
```bash
make cli && ./dist/cli recover --files "<vault_share1.dat|.bak|.vult>" --files "<vault_share2.dat|.bak|.vult>"
```

Example with included test files:
```bash
make cli && ./dist/cli recover --files "example-shares/JP_GG20_honeypot_1of3.bak"
make cli && ./dist/cli recover --files "example-shares/GG20_1of2.vult" --files "example-shares/GG20_2of2.vult"
```

For GG20 schemes, you can force the scheme (defaults to auto-detection):
```bash
make cli && ./dist/cli recover --files "vault1.vult" --files "vault2.vult" --scheme gg20
```

### Test Address Generation
Test HD derivation and address generation from a known private key with custom chaincode:

```bash
make cli && ./dist/cli test-address --private-key <hex_private_key> --chaincode <hex_chaincode>
```

Example:
```bash
make cli && ./dist/cli test-address --private-key 2abbfad6ea48607d9665e123456789bed21204cfe479fdec40d33058c0a4e3fe --chaincode e2f8c4826d6d23407cff45498b940f52756c3056fa1bcba0cb7f6bafc2478eac
```

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


## Running the server locally (which calls the CLI)
`make all && ./dist/webserver`

## Project Structure
```
├── cmd
│   ├── cli
│   │   ├── actions.go        # CLI-specific actions (decrypt, recover)
│   │   └── main.go          # CLI entry point and app configuration
│   ├── server
│   │   └── main.go          # Web server entry point
│   └── wasm
│       └── main.go          # WebAssembly entry point
├── pkg
│   ├── keyhandlers
│   │   └── key_handlers.go  # Cryptocurrency specific key handlers (BTC, ETH, etc.)
│   ├── keyprocessing
│   │   └── key_processing.go # Key processing and reconstruction logic
│   ├── shared
│   │   └── shared.go        # Core shared functionality
│   ├── types
│   │   └── types.go         # Shared type definitions
│   └── fileutils
│       └── fileutils.go     # File handling utilities
├── static                   # Web assets
│   ├── index.html          # Main web interface
│   ├── main.js             # Frontend JavaScript
│   ├── main.wasm           # Compiled WebAssembly binary for GG20
│   ├── v_wasm_bg.wasm      # Compiled WebAssembly binary for DKLS
│   ├── style.css           # Styling
│   └── wasm_exec.js        # WebAssembly execution environment
├── go.mod                  # Go module definition
├── go.sum                  # Go module checksums
├── Makefile               # Build automation
└── README.md              # Project documentation
```

## Build Tags

The project uses Go build tags to manage different builds:
- `cli`: Command-line interface build
- `wasm`: WebAssembly build for browser
- `server`: Web server build


## Build Commands (in Makefile)

```bash
# Build CLI
go build -tags cli -o dist/cli ./cmd/cli

# Build WebAssembly
GOOS=js GOARCH=wasm go build -tags wasm -o static/main.wasm

# Build Web Server
go build -tags server -o dist/webserver ./cmd/server


