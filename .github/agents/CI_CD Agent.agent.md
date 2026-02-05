# CI/CD Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** requires robust CI/CD pipelines for quality assurance. This agent manages GitHub Actions workflows, security scanning, and release automation.

## Task Description

Manage the VAK CI/CD system including:
- GitHub Actions workflows
- Security scanning (cargo-audit, cargo-deny)
- Test automation
- Release builds
- Documentation generation

## Available Commands

```bash
# Run CI checks locally
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo audit
cargo deny check

# Build release
cargo build --release

# Generate docs
cargo doc --no-deps
```

## Files This Agent Can Modify

### GitHub Workflows
- `.github/workflows/ci.yml` - Main CI pipeline
- `.github/workflows/security.yml` - Security scanning
- `.github/workflows/release.yml` - Release automation
- `.github/workflows/docs.yml` - Documentation

### Configuration
- `deny.toml` - cargo-deny configuration
- `rust-toolchain.toml` - Rust version
- `.cargo/config.toml` - Cargo configuration

## Workflow Definitions

### Main CI Pipeline
```yaml
# .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  check:
    name: Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo check --all-features

  fmt:
    name: Formatting
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt
      - run: cargo fmt --all --check

  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo clippy --all-features -- -D warnings

  test:
    name: Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo test --all-features

  test-python:
    name: Python Tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      - run: pip install maturin pytest
      - run: cd python && maturin develop
      - run: pytest python/tests/ -v

  coverage:
    name: Coverage
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - uses: Swatinem/rust-cache@v2
      - run: cargo install cargo-tarpaulin
      - run: cargo tarpaulin --out Xml
      - uses: codecov/codecov-action@v3
```

### Security Scanning
```yaml
# .github/workflows/security.yml
name: Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 0 * * *'  # Daily

jobs:
  audit:
    name: Security Audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-audit
      - run: cargo audit

  deny:
    name: License Check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo install cargo-deny
      - run: cargo deny check

  advisories:
    name: Advisories
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v1
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

### Release Workflow
```yaml
# .github/workflows/release.yml
name: Release

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    name: Build Release
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
            target: x86_64-unknown-linux-gnu
          - os: macos-latest
            target: x86_64-apple-darwin
          - os: macos-latest
            target: aarch64-apple-darwin
          - os: windows-latest
            target: x86_64-pc-windows-msvc
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          targets: ${{ matrix.target }}
      - run: cargo build --release --target ${{ matrix.target }}
      - uses: actions/upload-artifact@v3
        with:
          name: vak-${{ matrix.target }}
          path: target/${{ matrix.target }}/release/vak*

  publish-crate:
    name: Publish to crates.io
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo publish
        env:
          CARGO_REGISTRY_TOKEN: ${{ secrets.CARGO_REGISTRY_TOKEN }}

  publish-pypi:
    name: Publish to PyPI
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: PyO3/maturin-action@v1
        with:
          command: publish
          args: -m python/Cargo.toml
        env:
          MATURIN_PYPI_TOKEN: ${{ secrets.PYPI_TOKEN }}
```

### Cargo Deny Configuration
```toml
# deny.toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
unlicensed = "deny"
allow = [
    "MIT",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Zlib",
    "Unlicense",
    "MPL-2.0",
]
copyleft = "deny"

[bans]
multiple-versions = "warn"
wildcards = "deny"
highlight = "all"

deny = [
    # Known problematic crates
]

skip = [
    # Crates allowed to have multiple versions
]

[sources]
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

## Guardrails

### DO
- Run all checks on every PR
- Cache dependencies for faster builds
- Use matrix builds for cross-platform
- Scan for vulnerabilities daily
- Require passing CI for merges
- Generate coverage reports

### DON'T
- Skip security scans
- Allow warnings in production builds
- Merge without passing tests
- Use outdated actions
- Expose secrets in logs
- Skip Python SDK tests

### Required Checks
- `cargo check` - Compilation
- `cargo fmt --check` - Formatting
- `cargo clippy -- -D warnings` - Lints
- `cargo test` - Unit tests
- `cargo audit` - Security vulnerabilities
- `cargo deny check` - License compliance
- `pytest` - Python tests

## Status Badges

```markdown
[![CI](https://github.com/user/vak/workflows/CI/badge.svg)](https://github.com/user/vak/actions)
[![Security](https://github.com/user/vak/workflows/Security/badge.svg)](https://github.com/user/vak/actions)
[![codecov](https://codecov.io/gh/user/vak/branch/main/graph/badge.svg)](https://codecov.io/gh/user/vak)
```

## Related Agents
- [Testing Agent](Testing%20Agent.agent.md)
- [Rust Code Generator Agent](Rust%20Code%20Generator%20Agent.agent.md)