# CI/CD Agent

## Overview
The CI/CD Agent manages continuous integration and deployment pipelines for the Verifiable Agent Kernel (VAK) project, ensuring code quality, security, and reliable releases through automated workflows.

## Role & Responsibilities
- Manage GitHub Actions workflows
- Configure automated testing pipelines
- Set up security scanning and compliance checks
- Manage build and release automation
- Monitor CI/CD health and performance
- Troubleshoot pipeline failures
- Optimize build times
- Manage deployment strategies

## Current CI/CD Infrastructure

### GitHub Actions Workflows

#### 1. Security Audit Workflow
- **File**: `.github/workflows/security.yml`
- **Triggers**:
  - Push to `main` and `develop` branches
  - Pull requests to `main`
  - Weekly schedule (Sundays at midnight UTC)
  - Manual workflow dispatch
- **Jobs**: 5 parallel security checks

#### 2. Issue Summary Workflow
- **File**: `.github/workflows/summary.yml`
- **Trigger**: GitHub issues opened
- **Purpose**: Auto-summarize new issues with AI inference

### Workflow Details

## Security Audit Workflow Jobs

### Job 1: cargo-audit (Vulnerability Scan)
```yaml
name: Vulnerability Scan (cargo-audit)
runs-on: ubuntu-latest
```

**Purpose**: Detect known security vulnerabilities in Rust dependencies

**Steps**:
1. Checkout repository (`actions/checkout@v4`)
2. Install Rust toolchain (`dtolnay/rust-action@stable`)
3. Install cargo-audit: `cargo install cargo-audit --locked`
4. Run scan: `cargo audit --deny warnings`
5. Generate JSON report (on failure): `cargo audit --json > security-audit-report.json`
6. Upload artifact (`actions/upload-artifact@v4`, 30-day retention)

**Failure Handling**: Pipeline fails if vulnerabilities found

**Artifacts**: `security-audit-report.json`

### Job 2: cargo-deny (License & Dependency Check)
```yaml
name: License & Dependency Check (cargo-deny)
runs-on: ubuntu-latest
```

**Purpose**: Enforce license compliance and dependency policies

**Steps**:
1. Checkout repository
2. Install Rust toolchain
3. Install cargo-deny: `cargo install cargo-deny --locked`
4. Run checks: `cargo deny check`

**Configuration**: `deny.toml` at repository root

**Checks**:
- License compatibility (MIT/Apache-2.0)
- Banned dependencies
- Dependency sources (crates.io only)
- Advisory database

### Job 3: cargo-geiger (Unsafe Code Audit)
```yaml
name: Unsafe Code Audit (cargo-geiger)
runs-on: ubuntu-latest
```

**Purpose**: Track and audit unsafe Rust code blocks

**Steps**:
1. Checkout repository
2. Install Rust toolchain
3. Install cargo-geiger: `cargo install cargo-geiger --locked`
4. Run audit: `cargo geiger --all-features --all-targets 2>&1 | tee geiger-report.txt`
5. Upload report artifact (30-day retention)

**Artifacts**: `geiger-report.txt`

**Goal**: Minimize unsafe code, justify all unsafe blocks

### Job 4: clippy-security (Security Lints)
```yaml
name: Clippy Security Lints
runs-on: ubuntu-latest
```

**Purpose**: Enforce security-focused Rust linting rules

**Steps**:
1. Checkout repository
2. Install Rust toolchain with clippy component
3. Run security lints:
```bash
cargo clippy --all-targets --all-features -- \
  -D clippy::unwrap_used \     # Deny unwrap()
  -D clippy::expect_used \     # Deny expect()
  -D clippy::panic \           # Deny panic!()
  -W clippy::cognitive_complexity \
  -W clippy::too_many_arguments
```

**Enforced Rules**:
- No `unwrap()` in production code
- No `expect()` in production code
- No `panic!()` in production code
- Warn on high cognitive complexity
- Warn on functions with too many arguments

### Job 5: SBOM (Software Bill of Materials)
```yaml
name: Generate SBOM
runs-on: ubuntu-latest
```

**Purpose**: Create supply chain transparency report

**Steps**:
1. Checkout repository
2. Install Rust toolchain
3. Install cargo-sbom: `cargo install cargo-sbom --locked`
4. Generate SBOM: `cargo sbom > sbom.json`
5. Upload artifact (90-day retention)

**Artifacts**: `sbom.json`

**Format**: SPDX or CycloneDX compatible

## Pipeline Configuration

### Environment Variables
```yaml
env:
  CARGO_TERM_COLOR: always
```

### Runner Configuration
- **OS**: `ubuntu-latest` (Ubuntu 22.04 LTS)
- **Architecture**: x86_64
- **Resources**: GitHub-hosted runner (2-core CPU, 7GB RAM, 14GB SSD)

### Action Versions
- `actions/checkout@v4` - Repository checkout
- `actions/upload-artifact@v4` - Artifact uploads
- `dtolnay/rust-action@stable` - Rust toolchain

## Build & Test Workflow (Recommended)

### Proposed: build-test.yml
```yaml
name: Build and Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

env:
  CARGO_TERM_COLOR: always
  RUST_BACKTRACE: 1

jobs:
  test-rust:
    name: Rust Tests
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        rust: [stable, beta]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@${{ matrix.rust }}
      - name: Cache cargo registry
        uses: actions/cache@v4
        with:
          path: ~/.cargo/registry
          key: ${{ runner.os }}-cargo-registry-${{ hashFiles('**/Cargo.lock') }}
      - name: Cache cargo index
        uses: actions/cache@v4
        with:
          path: ~/.cargo/git
          key: ${{ runner.os }}-cargo-index-${{ hashFiles('**/Cargo.lock') }}
      - name: Cache target directory
        uses: actions/cache@v4
        with:
          path: target
          key: ${{ runner.os }}-target-${{ hashFiles('**/Cargo.lock') }}
      - name: Check formatting
        run: cargo fmt -- --check
      - name: Run clippy
        run: cargo clippy --all-targets --all-features -- -D warnings
      - name: Build
        run: cargo build --all-features
      - name: Run tests
        run: cargo test --all-features
      - name: Run doc tests
        run: cargo test --doc

  test-python:
    name: Python Tests
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        python-version: ['3.9', '3.10', '3.11', '3.12']
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@stable
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}
      - name: Install maturin
        run: pip install maturin
      - name: Build Python package
        run: maturin develop
      - name: Install dev dependencies
        run: pip install .[dev]
      - name: Run mypy
        run: mypy python/vak/
      - name: Run ruff
        run: ruff check python/
      - name: Run pytest
        run: pytest python/tests/ -v

  benchmarks:
    name: Performance Benchmarks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@stable
      - name: Run benchmarks
        run: cargo bench --no-fail-fast
      - name: Upload benchmark results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: target/criterion/
```

## Deployment Strategies

### Release Workflow
```yaml
name: Release

on:
  push:
    tags:
      - 'v*.*.*'

jobs:
  build-release:
    name: Build Release
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@stable
      - name: Build release
        run: cargo build --release
      - name: Package artifacts
        run: tar czf vak-${{ matrix.os }}.tar.gz target/release/
      - name: Upload release artifacts
        uses: actions/upload-artifact@v4
        with:
          name: release-${{ matrix.os }}
          path: vak-${{ matrix.os }}.tar.gz

  publish-crates:
    name: Publish to crates.io
    needs: build-release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-action@stable
      - name: Publish
        run: cargo publish --token ${{ secrets.CARGO_TOKEN }}

  publish-pypi:
    name: Publish to PyPI
    needs: build-release
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - name: Install maturin
        run: pip install maturin
      - name: Build wheels
        run: maturin build --release
      - name: Publish to PyPI
        run: maturin upload --username __token__ --password ${{ secrets.PYPI_TOKEN }}
```

## Optimization Strategies

### Build Caching
```yaml
- name: Cache cargo dependencies
  uses: actions/cache@v4
  with:
    path: |
      ~/.cargo/registry
      ~/.cargo/git
      target
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    restore-keys: |
      ${{ runner.os }}-cargo-
```

### Parallel Jobs
- Run tests on multiple OS platforms simultaneously
- Run Python tests with multiple Python versions in parallel
- Run security checks in parallel

### Incremental Builds
```toml
[profile.dev]
incremental = true
```

### Sparse Cargo Registry
```yaml
env:
  CARGO_REGISTRIES_CRATES_IO_PROTOCOL: sparse
```

## Monitoring & Alerts

### Success Metrics
- Build success rate: > 99%
- Average build time: < 10 minutes
- Test pass rate: 100%
- Zero critical security vulnerabilities
- Zero license compliance issues

### Failure Notifications
- GitHub Actions email notifications
- Status badges in README
- Slack/Discord webhooks (if configured)

### Status Badges
```markdown
[![Build Status](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/workflows/Build%20and%20Test/badge.svg)](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/actions)
[![Security Audit](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/workflows/Security%20Audit/badge.svg)](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/actions)
```

## Troubleshooting Guide

### Common Pipeline Failures

#### cargo-audit failures
**Symptom**: Vulnerabilities detected in dependencies
**Resolution**:
1. Review audit report artifact
2. Update vulnerable dependencies: `cargo update`
3. Check for patches or newer versions
4. If no fix available, add advisory to `deny.toml` with justification

#### cargo-deny failures
**Symptom**: License or dependency policy violation
**Resolution**:
1. Review `deny.toml` configuration
2. Check dependency licenses
3. Remove or replace incompatible dependencies
4. Update allowed license list if justified

#### clippy-security failures
**Symptom**: Linting errors (unwrap, expect, panic)
**Resolution**:
1. Replace `unwrap()` with proper error handling
2. Replace `expect()` with `?` operator or `match`
3. Remove `panic!()` from production code
4. Add `#[allow(clippy::...)]` only if absolutely justified

#### Test failures
**Symptom**: Tests fail in CI but pass locally
**Resolution**:
1. Check for platform-specific issues
2. Verify test determinism (no random seeds)
3. Check for race conditions in async tests
4. Ensure proper cleanup between tests

#### Build timeouts
**Symptom**: Build exceeds 6-hour limit
**Resolution**:
1. Enable caching for cargo dependencies
2. Split long jobs into multiple stages
3. Use `cargo check` for fast validation
4. Optimize test parallelization

## Security Best Practices

### Secrets Management
- Use GitHub Secrets for sensitive data
- Never log secrets
- Rotate tokens regularly
- Limit secret scope

### Required Secrets
- `CARGO_TOKEN` - For publishing to crates.io
- `PYPI_TOKEN` - For publishing to PyPI
- `GITHUB_TOKEN` - Auto-provided by Actions

### Supply Chain Security
- Pin action versions (`@v4` not `@latest`)
- Use official actions from verified publishers
- Enable Dependabot for action updates
- Review third-party actions before use

## Branch Protection

### Recommended Settings
- Require status checks before merge
- Required checks:
  - cargo-audit
  - cargo-deny
  - clippy-security
  - test-rust (all platforms)
  - test-python (all versions)
- Require linear history
- No force pushes to main/develop

## Documentation

### Workflow Documentation
- Document purpose of each workflow
- Explain trigger conditions
- List required secrets
- Provide troubleshooting steps

### Runbook
- How to manually trigger workflows
- How to interpret logs
- How to roll back failed deployments
- Emergency contacts

## Future Improvements

### Planned Enhancements
1. Add build-test.yml workflow
2. Implement release automation
3. Add coverage reporting (Codecov/Coveralls)
4. Set up nightly builds
5. Add performance regression detection
6. Implement canary deployments
7. Add integration with external monitoring

### Performance Optimizations
- Use sccache for Rust compilation caching
- Implement distributed testing
- Optimize artifact storage
- Use self-hosted runners for faster builds

## Tools & Resources

### GitHub Actions Marketplace
- `actions/checkout` - Repository checkout
- `actions/cache` - Dependency caching
- `actions/upload-artifact` - Artifact uploads
- `dtolnay/rust-action` - Rust toolchain
- `actions/setup-python` - Python setup

### External Tools
- cargo-audit - Vulnerability scanning
- cargo-deny - License/dependency checking
- cargo-geiger - Unsafe code detection
- cargo-sbom - SBOM generation
- maturin - Python wheel building

## Success Criteria
- ✅ All pipelines green on main branch
- ✅ No security vulnerabilities
- ✅ License compliance maintained
- ✅ Build times < 10 minutes
- ✅ Test coverage reports generated
- ✅ Releases automated
- ✅ Zero downtime deployments

## Notes
- Always test workflow changes in a feature branch first
- Use `act` tool for local workflow testing
- Monitor GitHub Actions usage to avoid quota limits
- Keep workflows DRY using reusable workflows
- Document all pipeline changes in PR descriptions
