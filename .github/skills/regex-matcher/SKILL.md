---
name: regex-matcher
description: WASM skill providing pattern matching operations for VAK agents.

---

# Regex Matcher Skill

A WebAssembly module providing pattern matching operations that runs inside the VAK kernel sandbox.

## Overview

This skill provides pattern matching for:
- Regex pattern matching
- Glob pattern matching
- Find all matches
- Replace operations
- Text splitting
- Pattern extraction

## Building

```bash
# Build for WASM target
cargo build -p regex-matcher --target wasm32-unknown-unknown --release

# Output location
# target/wasm32-unknown-unknown/release/regex_matcher.wasm
```

## Operations

| Operation | Input | Output | Description |
|-----------|-------|--------|-------------|
| `matches` | (text, pattern) | bool | Check if pattern matches |
| `find_all` | (text, pattern) | Vec<Match> | Find all matches |
| `replace` | (text, pattern, replacement) | string | Replace matches |
| `replace_all` | (text, pattern, replacement) | string | Replace all matches |
| `split` | (text, pattern) | Vec<string> | Split by pattern |
| `extract` | (text, pattern) | Vec<string> | Extract capture groups |
| `glob_match` | (path, pattern) | bool | Glob pattern match |

## Safety

This skill runs in the VAK WASM sandbox with:
- **Epoch preemption**: Protection against ReDoS attacks
- **Memory limits**: Bounded match results
- **Pattern validation**: Invalid patterns rejected

## Usage Example

```rust
// From VAK kernel
let matches = kernel.execute_skill("regex-matcher", "matches", &[text, r"\d+"]).await?;

let extracted = kernel.execute_skill("regex-matcher", "extract", &[
    text,
    r"(\w+)@(\w+\.com)"
]).await?;
```

## Security Considerations

- Regex patterns are validated before execution
- Epoch preemption prevents catastrophic backtracking (ReDoS)
- Use simple patterns when possible for performance

## Use Cases

- Extracting structured data from text
- Validating input formats
- Parsing log files and responses
- File path matching for policy rules

## Files

- `Cargo.toml` - Crate configuration
- `src/lib.rs` - Skill implementation
