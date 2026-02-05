# Build Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** requires reliable build processes for Rust code, WASM skills, Python bindings, and release artifacts. This agent manages all build-related tasks.

## Task Description

Manage VAK build processes including:
- Rust library compilation
- WASM skill building
- Python wheel generation
- Release artifact creation
- Cross-compilation

## Available Commands

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Build with all features
cargo build --all-features

# Build specific package
cargo build -p vak-kernel

# Build WASM skills
cargo build --target wasm32-unknown-unknown --release -p calculator-skill

# Build Python extension
cd python && maturin build --release

# Build documentation
cargo doc --no-deps

# Check compilation
cargo check --all-targets

# Clean build artifacts
cargo clean
```

## Files This Agent Can Modify

### Build Configuration
- `Cargo.toml` - Workspace and dependencies
- `rust-toolchain.toml` - Rust version
- `.cargo/config.toml` - Cargo settings
- `python/pyproject.toml` - Python build config
- `python/Cargo.toml` - PyO3 crate config

### Build Scripts
- `build.rs` - Cargo build script
- `scripts/build-release.sh`
- `scripts/build-skills.sh`

## Build Configuration

### Cargo.toml Structure
```toml
[workspace]
members = [
    ".",
    "skills/*",
]
resolver = "2"

[package]
name = "vak"
version = "0.1.0"
edition = "2021"
rust-version = "1.75"
license = "MIT OR Apache-2.0"
description = "Verifiable Agent Kernel"
repository = "https://github.com/user/vak"
documentation = "https://docs.rs/vak"
keywords = ["ai", "agents", "wasm", "policy"]
categories = ["development-tools", "wasm"]

[lib]
name = "vak"
crate-type = ["cdylib", "rlib"]

[features]
default = ["runtime"]
runtime = ["wasmtime"]
python = ["pyo3"]
full = ["runtime", "python"]

[dependencies]
# Core
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
tracing = "0.1"

# Optional
wasmtime = { version = "27.0", optional = true }
pyo3 = { version = "0.20", optional = true, features = ["extension-module"] }

[dev-dependencies]
tokio-test = "0.4"
proptest = "1.0"
criterion = "0.5"

[[bench]]
name = "kernel_benchmarks"
harness = false

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true

[profile.dev]
opt-level = 0
debug = true

[profile.test]
opt-level = 1
```

### Rust Toolchain
```toml
# rust-toolchain.toml
[toolchain]
channel = "1.75"
components = ["rustfmt", "clippy", "rust-src"]
targets = ["wasm32-unknown-unknown", "wasm32-wasi"]
```

### Cargo Config
```toml
# .cargo/config.toml
[build]
rustflags = ["-D", "warnings"]

[target.wasm32-unknown-unknown]
rustflags = ["-C", "link-arg=-zstack-size=65536"]

[target.x86_64-unknown-linux-gnu]
linker = "clang"
rustflags = ["-C", "link-arg=-fuse-ld=lld"]

[alias]
xtask = "run --package xtask --"
```

### Python Build Config
```toml
# python/pyproject.toml
[build-system]
requires = ["maturin>=1.0,<2.0"]
build-backend = "maturin"

[project]
name = "vak"
version = "0.1.0"
description = "Verifiable Agent Kernel Python SDK"
requires-python = ">=3.8"
classifiers = [
    "Programming Language :: Rust",
    "Programming Language :: Python :: Implementation :: CPython",
]

[tool.maturin]
features = ["python"]
python-source = "python"
module-name = "vak._vak_rs"
```

## Build Scripts

### Release Build Script
```bash
#!/bin/bash
# scripts/build-release.sh
set -euo pipefail

echo "Building VAK release..."

# Clean previous build
cargo clean

# Run checks
cargo fmt --check
cargo clippy -- -D warnings
cargo test

# Build release binary
cargo build --release --all-features

# Build WASM skills
for skill in skills/*/; do
    if [ -f "$skill/Cargo.toml" ]; then
        echo "Building skill: $skill"
        cargo build --release --target wasm32-unknown-unknown --manifest-path "$skill/Cargo.toml"
    fi
done

# Build Python wheel
cd python
maturin build --release
cd ..

# Create release archive
VERSION=$(cargo metadata --format-version 1 | jq -r '.packages[] | select(.name == "vak") | .version')
ARCHIVE="vak-$VERSION-$(uname -s)-$(uname -m)"

mkdir -p "dist/$ARCHIVE"
cp target/release/vak "dist/$ARCHIVE/"
cp -r skills/*/target/wasm32-unknown-unknown/release/*.wasm "dist/$ARCHIVE/skills/" 2>/dev/null || true
cp README.md LICENSE* "dist/$ARCHIVE/"

tar -czvf "dist/$ARCHIVE.tar.gz" -C dist "$ARCHIVE"

echo "Release built: dist/$ARCHIVE.tar.gz"
```

### Skills Build Script
```bash
#!/bin/bash
# scripts/build-skills.sh
set -euo pipefail

SKILLS_DIR="skills"
TARGET="wasm32-unknown-unknown"

for skill in "$SKILLS_DIR"/*/; do
    if [ -f "$skill/Cargo.toml" ]; then
        skill_name=$(basename "$skill")
        echo "Building skill: $skill_name"
        
        cargo build \
            --release \
            --target "$TARGET" \
            --manifest-path "$skill/Cargo.toml"
        
        # Copy to output directory
        cp "$skill/target/$TARGET/release/$skill_name.wasm" \
           "$skill/target/"
        
        echo "Built: $skill/target/$skill_name.wasm"
    fi
done
```

## Guardrails

### DO
- Use `--release` for production builds
- Enable LTO for release builds
- Pin dependency versions
- Test before building releases
- Sign release artifacts
- Document build requirements

### DON'T
- Commit build artifacts
- Use wildcard dependencies
- Skip tests in CI builds
- Ignore deprecation warnings
- Build without security checks
- Use unstable features in releases

### Build Requirements
- Rust 1.75+
- WASM target: `wasm32-unknown-unknown`
- Python 3.8+ (for SDK)
- Maturin (for Python builds)

## Troubleshooting

### Common Issues

**Linking errors on Linux:**
```bash
# Install LLVM linker
sudo apt install lld

# Or use GCC
RUSTFLAGS="-C linker=gcc" cargo build
```

**WASM build failures:**
```bash
# Add target
rustup target add wasm32-unknown-unknown

# Check target is installed
rustup target list --installed
```

**Python build failures:**
```bash
# Install maturin
pip install maturin

# Build in development mode
cd python && maturin develop
```

## Related Agents
- [CI/CD Agent](CI-CD%20Agent.agent.md)
- [Testing Agent](Testing%20Agent.agent.md)
- [WASM Sandbox Agent](WASM%20Sandbox%20Agent.agent.md)