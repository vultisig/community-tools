# Vultisig Share Decoder

[![Go Reference](https://pkg.go.dev/badge/github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder.svg)](https://pkg.go.dev/github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder)

Vultisig is a multi-chain, multi-factor, multi-platform Threshold-Signature vault that does not need any specialised hardware. It supports most UTXO, EVM, BFT and EdDSA Chains.

Vultisig doesn't expose private keys during vault creations and instead creates "shares". This is a recovery tool to see the public information on your vault share and recover private keys from vault shares (if you have a majority of them). This tool supports both **GG20** and **DKLS** cryptographic schemes.

You can (and should) run this locally.

## Supported Recovery Networks

**UTXO Chains:** Bitcoin, Bitcoin Cash, Dogecoin, Litecoin

**Cosmos/BFT Chains:** THORChain, MayaChain, Cosmos Hub, Kujira, dYdX, Terra Classic, Terra

**EVM Chains:** Ethereum, Tron

**EdDSA Chains:** Solana, Sui, TON

## Supported Schemes
- **GG20**: Full support via web interface
- **DKLS**: Supported via web interface

## Demo

[https://share-decoder.vultisig.com/](https://share-decoder.vultisig.com/)

### Dependencies
[Go](https://go.dev/doc/install)

### Running the Web Server
1. `git clone https://github.com/vultisig/community-tools.git`
2. `cd community-tools/recovery-tools/vultisig-share-decoder`
3. `make all`
4. `./dist/webserver`

## Test Files Included

Included test files in `examples/`:
- [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak)
- `GG20_1of2.vult` and `GG20_2of2.vult` (GG20 shares)
- `DKLS_1of2.vult` and `DKLS_2of2.vult` (DKLS shares)

## Importing Results

**Ethereum** — Import the hex private key into [MetaMask](https://metamask.io/)

**Bitcoin** — Import the WIF key (e.g. `p2wpkh:L5P6V9e...`) into [Electrum](https://electrum.org/#download)

Verify correctness by checking that the derived address matches what you had in Vultisig.

## Project Structure
```
├── cmd/                    # Entry points
│   ├── server.go          # Web server entry point
│   └── wasm.go            # WebAssembly entry point
├── internal/              # Internal packages
│   ├── crypto/            # TSS service and local state
│   ├── processing/        # Key reconstruction and coin handlers
│   └── utils/             # Types, file handling, encryption
├── web/                   # Web assets (HTML, CSS, JS, WASM binaries)
├── examples/              # Example vault files
├── go.mod
├── Makefile
└── README.md
```

## Build Tags

- `wasm`: WebAssembly build for browser
- `server`: Web server build

## Build Commands

```bash
# Build WebAssembly
GOOS=js GOARCH=wasm go build -o web/main.wasm cmd/wasm.go

# Build Web Server
go build -o dist/webserver cmd/server.go
```
