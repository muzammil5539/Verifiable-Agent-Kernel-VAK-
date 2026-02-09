---
name: calculator
description: WASM skill providing basic arithmetic operations for VAK agents.
---

# Calculator Skill

A WebAssembly module providing basic arithmetic operations that runs inside the VAK kernel sandbox.

## Overview

This skill provides safe arithmetic operations with proper error handling for:
- Addition
- Subtraction
- Multiplication
- Division (with zero-check)

## Building

```bash
# Build for WASM target
cargo build -p calculator --target wasm32-unknown-unknown --release

# Output location
# target/wasm32-unknown-unknown/release/calculator.wasm
```

## Operations

| Operation | Input | Output | Error Conditions |
|-----------|-------|--------|------------------|
| `add` | (a: i64, b: i64) | i64 | Overflow |
| `subtract` | (a: i64, b: i64) | i64 | Overflow |
| `multiply` | (a: i64, b: i64) | i64 | Overflow |
| `divide` | (a: i64, b: i64) | i64 | Division by zero |

## Safety

This skill runs in the VAK WASM sandbox with:
- **Epoch preemption**: Automatic timeout for long operations
- **Memory limits**: Pooling allocator enforces memory bounds
- **Panic safety**: All unsafe blocks documented with `// SAFETY:` comments

## Usage Example

```rust
// From VAK kernel
let result = kernel.execute_skill("calculator", "add", &[10, 20]).await?;
assert_eq!(result, 30);
```

## Files

- `Cargo.toml` - Crate configuration
- `src/lib.rs` - Skill implementation
