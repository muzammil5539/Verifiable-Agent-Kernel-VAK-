# Development Agent

## Overview
The Development Agent is responsible for local development workflows, building, testing, and preparing code for review in the Verifiable Agent Kernel (VAK) project.

## Role & Responsibilities
- Build Rust and Python components
- Run local tests and linters
- Set up and maintain development environments
- Execute code examples and demos
- Performance benchmarking
- Dependency management

## Technology Stack

### Rust Environment
- **Rust Version**: 1.75+ (stable channel via rust-toolchain.toml)
- **Edition**: 2021
- **Build Tool**: Cargo (workspace with 2 members)
- **Components**: rustfmt, clippy, rust-analyzer

### Python Environment
- **Python Version**: 3.9+ (supports 3.9, 3.10, 3.11, 3.12)
- **Build Backend**: maturin (for PyO3 bindings)
- **Package Manager**: pip

### Build Profiles (Cargo.toml)
```toml
[profile.dev]
opt-level = 0
debug = true
incremental = true

[profile.release]
opt-level = 3
lto = "thin"
codegen-units = 1
strip = true

[profile.bench]
inherits = "release"
debug = true
```

## Build Commands

### Rust Builds
```bash
# Check compilation without building
cargo check

# Build development version
cargo build

# Build release version (optimized)
cargo build --release

# Build with all features
cargo build --all-features

# Build specific workspace member
cargo build -p vak
cargo build -p calculator

# Clean build artifacts
cargo clean
```

### Python Builds
```bash
# Install in development mode (editable)
pip install -e .

# Build Python wheel with maturin
maturin develop

# Build release wheel
maturin build --release

# Build and install with feature flags
maturin develop --features python
```

## Testing Commands

### Rust Tests
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test file
cargo test --test test_policy_enforcement

# Run integration tests only
cargo test --test '*'

# Run with async runtime
cargo test --features tokio

# Run benchmarks
cargo bench

# List available tests
cargo test -- --list
```

**Test Files** (`tests/integration/`):
- `test_policy_enforcement.rs`
- `test_full_workflow.rs`
- `test_kernel_workflow.rs`
- `test_cedar_policy.rs`
- `test_audit_integrity.rs`
- `preemption_tests.rs`

### Python Tests
```bash
# Install dev dependencies
pip install -e .[dev]

# Run all Python tests
pytest python/tests/

# Run with verbose output
pytest -v python/tests/

# Run specific test file
pytest python/tests/test_kernel.py

# Run with coverage
pytest --cov=vak python/tests/

# Run async tests
pytest python/tests/test_integration.py -v
```

**Test Files** (`python/tests/`):
- `test_kernel.py`
- `test_types.py`
- `test_code_auditor.py`
- `test_integration.py`

### Property-Based Tests
```bash
# Run proptest cases (configured in test files)
cargo test --test proptest_*
```

## Linting & Formatting

### Rust Linting
```bash
# Format code with rustfmt
cargo fmt

# Check formatting without modifying
cargo fmt -- --check

# Run clippy (basic)
cargo clippy

# Run clippy with all targets
cargo clippy --all-targets --all-features

# Run clippy with security lints (as in CI)
cargo clippy --all-targets --all-features -- \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic \
  -W clippy::cognitive_complexity \
  -W clippy::too_many_arguments
```

### Python Linting
```bash
# Run ruff linter
ruff check python/

# Auto-fix with ruff
ruff check --fix python/

# Format with ruff
ruff format python/

# Type check with mypy
mypy python/vak/
```

**Ruff Configuration** (pyproject.toml):
- Line length: 100
- Target: Python 3.9+
- Rules: E, F, I, W, UP, B, C4, DTZ, T10, EXE, ISC, PIE, PT, RSE, SIM, TID, TCH, ARG, PL

**Mypy Configuration**:
- Strict mode enabled
- Python 3.9 compatibility

## Running Examples

### Rust Examples
```bash
# Basic agent example
cargo run --example basic_agent

# Policy demonstration
cargo run --example policy_demo

# Code auditor demo
cargo run --example code_auditor_demo

# List all examples
cargo run --example
```

**Example Files** (`examples/`):
- `basic_agent.rs` - Kernel initialization and tool execution
- `policy_demo.rs` - ABAC policy enforcement
- `code_auditor_demo.rs` - Code audit functionality

### Python Examples
```bash
# Python quickstart
python examples/python_quickstart.py
```

## Dependency Management

### Adding Rust Dependencies
```bash
# Add to workspace dependencies (Cargo.toml)
# Edit [workspace.dependencies] section

# Add direct dependency
cargo add <crate-name>

# Add dev dependency
cargo add --dev <crate-name>

# Add build dependency
cargo add --build <crate-name>

# Update dependencies
cargo update
```

**Key Dependencies**:
- tokio 1.35 (async runtime)
- serde, serde_json, serde_yaml (serialization)
- wasmtime 27.0 (WASM runtime)
- rusqlite 0.32 (database)
- pyo3 0.23 (Python bindings, optional feature)
- reqwest 0.11 (HTTP, rustls-tls)
- thiserror, anyhow (error handling)
- tracing, tracing-subscriber (logging)
- sha2, ed25519-dalek (cryptography)

### Adding Python Dependencies
```bash
# Edit pyproject.toml [project.dependencies] or [project.optional-dependencies.dev]

# Install updated dependencies
pip install -e .[dev]
```

**Python Dev Dependencies**:
- pytest >= 7.0
- pytest-asyncio >= 0.21
- mypy >= 1.0
- ruff >= 0.1

## Development Environment Setup

### Prerequisites
```bash
# Install Rust (if not present)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Python 3.9+
# Use system package manager or pyenv

# Install maturin for Python bindings
pip install maturin

# Install development tools
cargo install cargo-watch
cargo install cargo-expand
cargo install cargo-tree
```

### Initial Setup
```bash
# Clone repository
git clone https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-.git
cd Verifiable-Agent-Kernel-VAK-

# Build Rust components
cargo build

# Install Python package in dev mode
pip install -e .[dev]

# Run tests to verify setup
cargo test
pytest python/tests/
```

### Watch Mode Development
```bash
# Watch Rust files and rebuild on change
cargo watch -x check -x test

# Watch and run specific example
cargo watch -x 'run --example basic_agent'
```

## Performance Benchmarking

### Running Benchmarks
```bash
# Run all benchmarks
cargo bench

# Run specific benchmark
cargo bench --bench kernel_benchmarks

# Save baseline for comparison
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

**Benchmark Files** (`benches/`):
- `kernel_benchmarks.rs` (harness=false)

**Benchmarking Framework**: criterion 0.5

## Debugging

### Debug Builds
```bash
# Build with debug info
cargo build

# Run with logging
RUST_LOG=debug cargo run --example basic_agent

# Run with tokio console
RUSTFLAGS="--cfg tokio_unstable" cargo run
```

### Tracing
- All async operations should use `#[tracing::instrument]`
- Log levels: trace, debug, info, warn, error
- JSON output available via tracing-subscriber

## Common Tasks

### Add New Module
1. Create `src/my_module/mod.rs`
2. Add module declaration in `src/lib.rs`: `pub mod my_module;`
3. Write implementation
4. Add tests in `tests/integration/test_my_module.rs`
5. Run `cargo test`
6. Document with rustdoc

### Add New Python Binding
1. Edit `src/python.rs`
2. Add PyO3 wrapper functions
3. Export in Python module
4. Add Python tests in `python/tests/`
5. Run `maturin develop && pytest`

### Add New WASM Skill
1. Create skill directory in `skills/`
2. Add as workspace member in `Cargo.toml`
3. Set crate-type = ["cdylib"]
4. Implement skill interface
5. Build with `cargo build --target wasm32-wasi`

## Build Artifacts

### Rust Artifacts
- Location: `target/debug/` (dev) or `target/release/` (release)
- Binary: `libvak.rlib` (library)
- WASM: `target/wasm32-wasi/`

### Python Artifacts
- Wheel: `target/wheels/vak-*.whl`
- Native module: `vak/_vak_native.so` (Linux) or `.dylib` (macOS) or `.pyd` (Windows)

## .gitignore Exclusions
- `target/` - Rust build artifacts
- `__pycache__/`, `*.pyc` - Python cache
- `*.so`, `*.dylib`, `*.pyd` - Native modules
- `.pytest_cache/` - Pytest cache
- `.mypy_cache/` - Mypy cache
- `*.egg-info/` - Python package info
- `dist/`, `build/` - Distribution artifacts
- `.env`, `.venv/` - Virtual environments

## Troubleshooting

### Common Issues

**Issue**: Compilation errors with tokio
- **Fix**: Ensure tokio features include "full" and "tracing"

**Issue**: Python binding not found
- **Fix**: Run `maturin develop` to rebuild bindings

**Issue**: Tests hanging
- **Fix**: Check for async runtime issues, ensure tokio-test is available

**Issue**: WASM compilation fails
- **Fix**: Install wasm32-wasi target: `rustup target add wasm32-wasi`

**Issue**: SQLite bundled feature issues
- **Fix**: Ensure rusqlite dependency includes "bundled" feature

## Notes
- Always run `cargo fmt` before committing Rust code
- Always run `ruff format` before committing Python code
- Use `cargo check` for fast feedback during development
- Run full test suite before opening PR
- Benchmark performance-critical changes
- Update documentation when adding new public APIs
