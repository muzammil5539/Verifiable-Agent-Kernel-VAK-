---
name: crypto-hash
description: WASM skill providing cryptographic hashing operations for VAK agents.
---

# Crypto Hash Skill

A WebAssembly module providing cryptographic hashing operations that runs inside the VAK kernel sandbox.

## Overview

This skill provides secure hashing operations for:
- SHA-256 hashing
- HMAC-SHA256 authentication codes
- Hash verification

## Building

```bash
# Build for WASM target
cargo build -p crypto-hash --target wasm32-unknown-unknown --release

# Output location
# target/wasm32-unknown-unknown/release/crypto_hash.wasm
```

## Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| `sha256` | bytes | [u8; 32] | SHA-256 hash |
| `sha256_hex` | bytes | String | SHA-256 hash as hex string |
| `hmac_sha256` | (key, data) | [u8; 32] | HMAC-SHA256 |
| `verify_hash` | (data, hash) | bool | Verify hash matches |

## Safety

This skill runs in the VAK WASM sandbox with:
- **Epoch preemption**: Automatic timeout for long operations
- **Memory limits**: Pooling allocator enforces memory bounds
- **No secret storage**: Hashes are computed but not stored

## Usage Example

```rust
// From VAK kernel
let hash = kernel.execute_skill("crypto-hash", "sha256_hex", &data).await?;
```

## Security Considerations

- Keys should not be stored in WASM memory longer than necessary
- Use constant-time comparison for hash verification (implemented)
- Suitable for integrity checks, not for password storage

## Files

- `Cargo.toml` - Crate configuration
- `src/lib.rs` - Skill implementation
