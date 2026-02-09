---
name: json-validator
description: WASM skill providing JSON validation and manipulation for VAK agents.

---

# JSON Validator Skill

A WebAssembly module providing JSON validation and manipulation operations that runs inside the VAK kernel sandbox.

## Overview

This skill provides JSON operations for:
- JSON validation (syntax checking)
- Pretty printing (formatting)
- Minification (compression)
- Value extraction (JSONPath-like)
- Object merging
- Diff generation

## Building

```bash
# Build for WASM target
cargo build -p json-validator --target wasm32-unknown-unknown --release

# Output location
# target/wasm32-unknown-unknown/release/json_validator.wasm
```

## Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| `validate` | string | bool | Check if valid JSON |
| `pretty` | json | string | Format with indentation |
| `minify` | json | string | Remove whitespace |
| `extract` | (json, path) | value | Extract value at path |
| `merge` | (json1, json2) | json | Deep merge objects |
| `diff` | (json1, json2) | changes | Generate diff |

## Safety

This skill runs in the VAK WASM sandbox with:
- **Epoch preemption**: Automatic timeout for deeply nested JSON
- **Memory limits**: Protection against memory bomb attacks
- **Input validation**: Malformed JSON rejected early

## Usage Example

```rust
// From VAK kernel
let is_valid = kernel.execute_skill("json-validator", "validate", &json_string).await?;

let pretty = kernel.execute_skill("json-validator", "pretty", &json_string).await?;
```

## Use Cases

- Validating LLM output before parsing
- Formatting JSON for logging
- Extracting specific fields from API responses
- Comparing state snapshots

## Files

- `Cargo.toml` - Crate configuration
- `src/lib.rs` - Skill implementation
