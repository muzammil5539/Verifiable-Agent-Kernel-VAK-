---
name: text-analyzer  
description: WASM skill providing text analysis operations for VAK agents.

---

# Text Analyzer Skill

A WebAssembly module providing text analysis operations that runs inside the VAK kernel sandbox.

## Overview

This skill provides text analysis for:
- Word counting
- Character statistics
- Word frequency analysis
- Text similarity metrics
- Entropy calculation

## Building

```bash
# Build for WASM target
cargo build -p text-analyzer --target wasm32-unknown-unknown --release

# Output location
# target/wasm32-unknown-unknown/release/text_analyzer.wasm
```

## Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| `word_count` | text | u64 | Count words |
| `char_count` | text | u64 | Count characters |
| `char_stats` | text | Stats | Character breakdown |
| `frequency` | text | Map | Word frequency map |
| `similarity` | (text1, text2) | f64 | Jaccard similarity |
| `entropy` | text | f64 | Shannon entropy |

## Safety

This skill runs in the VAK WASM sandbox with:
- **Epoch preemption**: Automatic timeout for large texts
- **Memory limits**: Protection against memory exhaustion
- **UTF-8 handling**: Proper Unicode support

## Usage Example

```rust
// From VAK kernel
let count = kernel.execute_skill("text-analyzer", "word_count", &text).await?;

let similarity = kernel.execute_skill("text-analyzer", "similarity", &[text1, text2]).await?;
```

## Use Cases

- Analyzing LLM output quality
- Detecting repetitive content (high frequency + low entropy)
- Comparing text similarity for deduplication
- Token estimation for context management

## Files

- `Cargo.toml` - Crate configuration
- `src/lib.rs` - Skill implementation
