# Vultisig Share Decoder

[![Go Reference](https://pkg.go.dev/badge/github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder.svg)](https://pkg.go.dev/github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder)

Vultisig is a multi-chain, multi-factor, multi-platform Threshold-Signature vault that does not need any specialised hardware. It supports most UTXO, EVM, BFT and EdDSA Chains.

Vultisig doesn't expose private keys during vault creations and instead creates "shares". This is a recovery tool to see the public information on your vault share and recover private keys from vault shares (if you have a majority of them). This tool supports both **GG20** and **DKLS** cryptographic schemes.

You can (and should) run this locally.

## Supported Recovery Networks

**UTXO Chains:** Bitcoin, Bitcoin Cash, Dash, Dogecoin, Litecoin

**Cosmos/BFT Chains:** THORChain, MayaChain, Cosmos Hub, Kujira, dYdX, Terra Classic, Terra

**EVM Chains:** Ethereum, Tron

**XRP Ledger:** XRP

**EdDSA Chains:** Solana, Sui, TON

## Supported Schemes
- **GG20**: Full support via web interface
- **DKLS**: Supported via web interface

## Demo

[https://share-decoder.vultisig.com/](https://share-decoder.vultisig.com/)

## Install

### Pre-built binaries (recommended)

Download from the [latest release](https://github.com/vultisig/community-tools/releases/latest):

**macOS (Apple Silicon):**
```bash
curl -sSL https://github.com/vultisig/community-tools/releases/latest/download/vsd_darwin_arm64.tar.gz | tar xz
```

**Linux (x86_64):**
```bash
curl -sSL https://github.com/vultisig/community-tools/releases/latest/download/vsd_linux_amd64.tar.gz | tar xz
```

> **Note:** Keep the shared libraries (`.dylib`/`.so`) in the same directory as the `vsd` binary. `go install` is not supported due to `replace` directives required by `bnb-chain/tss-lib`.

### Build from source

Requires [Go 1.25+](https://go.dev/doc/install) and CGo.

```bash
git clone https://github.com/vultisig/community-tools.git
cd community-tools/recovery-tools/vultisig-share-decoder
make cli    # -> dist/cli
```

### Running the Web Server
```bash
make webserver
./dist/webserver
```

## Test Files Included

Included test files in `examples/`:
- [JPThor's unencrypted honeypot](https://github.com/jpthor/blockchain/blob/master/vultisig-JP%20Honeypot%20Vault-2024-09-2of3-e8e5-iPad-D3842FFB838E.bak)
- `GG20_1of2.vult` and `GG20_2of2.vult` (GG20 shares)
- `DKLS_1of2.vult` and `DKLS_2of2.vult` (DKLS shares)

## Importing Results

**Ethereum** — Import the hex private key into [MetaMask](https://metamask.io/)

**Bitcoin** — Import the WIF key (e.g. `p2wpkh:L5P6V9e...`) into [Electrum](https://electrum.org/#download)

**Solana, Sui, TON** — The EdDSA output is the raw Ed25519 scalar in hex, big-endian (not a seed). RFC 8032, libsodium, dalek and Solana expect the little-endian form, so reverse the bytes before importing.

**XRP** — The output is the raw 32-byte secp256k1 private key in hex plus its classic address, not an XRPL family seed (`s...`) and not a WIF. XRPL tooling often writes secp256k1 keys as 33 bytes with a `00` prefix; xrpl.js accepts either form, so prepend `00` only if a tool rejects the 64-character key.
**Dash** — Import the WIF key (compressed, starts with `X` — this is not a Bitcoin WIF) into a Dash wallet

Verify correctness by checking that the derived address matches what you had in Vultisig.

## Using as a Go Library

The public packages can be imported directly:

```go
import (
    "github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/vault"
    "github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/recovery"
    "github.com/vultisig/community-tools/recovery-tools/vultisig-share-decoder/pkg/derive"
)
```

- **`pkg/vault`** — Vault file parsing, AES-GCM decryption, scheme detection
- **`pkg/recovery`** — Key reconstruction for GG20 (VSS Shamir) and DKLS (algebraic export)
- **`pkg/derive`** — HD key derivation and coin-specific address generation

## Project Structure
```
cmd/
  cli/            CLI entry point
  server/         Web server entry point (for Vercel deployment)
  wasm/           Go WASM entry point (GG20 recovery)
pkg/
  vault/          Vault parsing, decryption, scheme detection
  recovery/       Key reconstruction (GG20 + DKLS)
  derive/         Coin address derivation (BIP32/BIP44)
internal/
  format/         Text and JSON output formatters
  tss/            LocalState struct for GG20 deserialization
src/
  derive.js       JS address derivation source (bundled for web)
web/              Web assets (HTML, CSS, JS, WASM binaries)
testdata/         Test vault files
```

## Build Commands

```bash
make cli        # Build CLI binary -> dist/cli
make webserver  # Build web server -> dist/webserver
make wasm       # Build Go WASM -> web/main.wasm
make derive     # Bundle JS address derivation -> web/derive.js
make pages      # Build WASM + derive + gzip for deployment
make test       # Run Go tests + JS derive tests
make check      # go fmt + go vet
```

## Build Tags

- **`cli`**: Native CLI binary (CGo enabled for DKLS)
- **`wasm`**: Go WASM for browser (GG20 only, no CGo)
- **`server`**: Web server for local development / Vercel
