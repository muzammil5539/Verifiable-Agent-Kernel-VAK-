---
name: build-project
description: Instructions for building the VAK project including Rust, WASM skills, and Python bindings.
---

# Build Project

This skill provides instructions for building all components of the VAK project.

## Prerequisites

-   Rust 1.75+ (`rustup update stable`)
-   `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
-   Python 3.9+ (for Python bindings)
-   `maturin` (`pip install maturin`)

## Instructions

### Build the Main Crate

To build the main VAK library:

```bash
cargo build
```

For a release build:

```bash
cargo build --release
```

### Build the Entire Workspace

To build all workspace members (main crate + WASM skills):

```bash
cargo build --workspace
```

### Build WASM Skills

WASM skills are workspace members located in `.github/skills/`. To build them individually for the `wasm32-unknown-unknown` target:

```bash
cargo build -p calculator --target wasm32-unknown-unknown --release
cargo build -p crypto-hash --target wasm32-unknown-unknown --release
cargo build -p json-validator --target wasm32-unknown-unknown --release
cargo build -p text-analyzer --target wasm32-unknown-unknown --release
cargo build -p regex-matcher --target wasm32-unknown-unknown --release
```

Or build all skills at once:

```bash
cargo build --workspace --exclude vak --target wasm32-unknown-unknown --release
```

### Build Python Bindings

To build the Python bindings using PyO3:

```bash
cd python
maturin develop --features python
```

For a release wheel:

```bash
maturin build --release --features python
```

### Check Without Building

To check for compilation errors without producing binaries:

```bash
cargo check --workspace
```

### Format Code

To format all Rust code:

```bash
cargo fmt --all
```

To check formatting without applying changes:

```bash
cargo fmt --all -- --check
```

## Examples

### Build a Single Skill

```bash
cargo build -p calculator
```

### Build with All Features

```bash
cargo build --all-features
```

### Cross-Compile for Linux

```bash
cargo build --release --target x86_64-unknown-linux-gnu
```

## Guidelines

-   **Check before committing**: Run `cargo check --workspace` before committing.
-   **Format before committing**: Run `cargo fmt --all` before committing.
-   **Fix warnings**: Treat compiler warnings as errors. Fix them before merging.
-   **Incremental builds**: Use `cargo build` (not `--release`) during development for faster compilation.
-   **WASM size**: Keep WASM skill binaries small. Avoid pulling in unnecessary dependencies.
