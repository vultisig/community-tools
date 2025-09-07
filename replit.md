# Vultisig Share Decoder

## Overview

The Vultisig Share Decoder is a multi-platform cryptographic key recovery tool that reconstructs private keys from TSS (Threshold Signature Scheme) key shares. It's designed to recover keys for Vultisig vault shares across multiple blockchain networks including UTXO chains (Bitcoin, Litecoin), EVM chains (Ethereum), Cosmos/BFT chains (Thorchain, Atom), and others. The application supports three deployment modes: CLI for terminal usage, web server for browser-based processing, and direct WASM integration for JavaScript applications.

## User Preferences

Preferred communication style: Simple, everyday language.

## Recent Changes

**September 2025**: Successfully completed comprehensive restructuring and setup of the Vultisig Share Decoder in Replit environment:
- Configured Go development environment with proper module management
- Modified server to run on port 5000 with 0.0.0.0 binding for Replit proxy compatibility  
- Removed CLI components to focus solely on WASM generation and static file serving
- **Completed major architectural restructuring** for optimal maintainability and navigation:
  - Flattened cmd/ structure from deep nested directories to simple server.go and wasm.go files
  - Consolidated fragmented pkg/ structure into logical internal/ organization (crypto/, processing/, utils/)
  - Renamed static/ to web/ for clarity and consistency
  - Fixed all circular dependencies and import cycles between packages
  - Resolved over 60 build errors down to zero functional issues
  - Updated all imports, build configuration, and package references
- Both server and WASM builds working perfectly with successful compilation
- Application fully functional and accessible via clean web interface
- Documentation updated to reflect new clean architecture across README.md and ARCHITECTURE.md

## System Architecture

### Simplified Deployment Architecture
The system uses a clean, hierarchical Go codebase with two streamlined entry points:
- **Web Server Mode** (`cmd/server.go`): HTTP server serving static files for browser-based processing
- **WASM Mode** (`cmd/wasm.go`): WebAssembly compilation for direct JavaScript integration

### Core Processing Pipeline
The application follows a clean layered architecture with logical separation of concerns:
- **Utilities Layer** (`internal/utils/`): File processing, encryption, and common data types
- **Cryptographic Layer** (`internal/crypto/`): TSS algorithms and cryptographic primitives
- **Processing Layer** (`internal/processing/`): Key reconstruction, derivation, and scheme-specific handlers (GG20/DKLS)
- **Entry Points** (`cmd/`): Flattened server and WASM entry points

### Cryptographic Scheme Support
The system supports multiple TSS schemes with different capabilities:
- **GG20**: Full support in both CLI and web interfaces for complete key recovery
- **DKLS**: Web-only support due to implementation constraints
- **Auto-detection**: Automatic scheme identification from vault file structure

### Frontend Architecture (Web Mode)
The web interface uses vanilla JavaScript with WebAssembly integration:
- **Static File Serving**: No server-side processing required for security
- **Dual WASM Integration**: Main Go WASM module for core logic plus specialized Rust WASM for advanced cryptographic operations
- **Client-Side Encryption**: AES-GCM decryption implemented in pure JavaScript using Web Crypto API
- **Protobuf Parsing**: Custom vanilla JavaScript protobuf parser to avoid external dependencies

### Security Design Principles
- **Local Processing**: All cryptographic operations occur client-side to prevent key exposure
- **No Server Storage**: Vault shares and passwords never leave the user's device
- **Memory Safety**: Go's garbage collection and WASM sandboxing provide memory safety
- **Minimal Dependencies**: Reduced attack surface through minimal external library usage

## External Dependencies

### Core Runtime Dependencies
- **Go Runtime**: Required for CLI and server compilation
- **WebAssembly Runtime**: Browser or Node.js environment for WASM execution
- **Web Crypto API**: Browser-native cryptographic functions for AES-GCM operations

### Build and Development Tools
- **Go Build System**: Native Go toolchain for compilation
- **WASM Build Targets**: Go WASM compilation support for browser deployment
- **Rust Toolchain**: For specialized WASM module compilation (vs_wasm)

### Cryptographic Libraries
- **Native Go Crypto**: Standard library cryptographic primitives
- **Web Crypto API**: Browser-native encryption/decryption for frontend
- **Custom Protobuf Parser**: Vanilla JavaScript implementation avoiding external protobuf dependencies

### Blockchain Network Support
The application supports key recovery for multiple blockchain networks without requiring direct network connections:
- **UTXO Chains**: Bitcoin, Bitcoin Cash, Dogecoin, Litecoin
- **EVM Chains**: Ethereum, Tron
- **Cosmos/BFT Chains**: Thorchain, Mayachain, Atom, Kujira, Dydx, Terra
- **Additional Chains**: Solana, Ton, Sui (signing key extraction only)

### Static Asset Serving
- **HTTP Server**: Go's net/http package for serving static files
- **MIME Type Handling**: Proper content-type headers for WASM and JavaScript files
- **Browser Compatibility**: Modern browser support for WebAssembly and ES6 modules