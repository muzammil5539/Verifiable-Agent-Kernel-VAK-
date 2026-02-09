---
name: release
description: Instructions for releasing and publishing the VAK project to crates.io and PyPI.
---

# Release Project

This skill provides instructions for publishing new releases of the VAK project.

**Current Status**: Alpha (v0.1.0) - Internal development, not yet published.

## Prerequisites

-   `cargo-release` (optional: `cargo install cargo-release`)
-   `maturin` (`pip install maturin`)
-   `git`
-   Access to crates.io (token) and PyPI (token)
-   All CI checks passing
-   Security scans clean (`cargo audit`, `cargo deny check`)

## Pre-Release Checklist

Before releasing, verify:

-   [ ] All CI checks pass (`cargo check`, `cargo test`, `cargo clippy`)
-   [ ] Security scan clean (`cargo audit --deny warnings`)
-   [ ] License compliance verified (`cargo deny check`)
-   [ ] Documentation updated (`README.md`, `TODO.md`)
-   [ ] Version bumped in:
    -   [ ] `Cargo.toml` (workspace version)
    -   [ ] `pyproject.toml` (if releasing Python bindings)
-   [ ] CHANGELOG.md updated with release notes
-   [ ] All deprecated items marked with `#[deprecated]`

## Version Management

The project uses workspace-level versioning in `Cargo.toml`:

```toml
[workspace.package]
version = "0.1.0"
```

All workspace members inherit this version:
- Main crate (`vak`)
- WASM skills (calculator, crypto-hash, json-validator, text-analyzer, regex-matcher)

## Instructions

### 1. Prepare Release

```bash
# Ensure clean working directory
git status

# Run full test suite
cargo test --workspace

# Run security checks
cargo audit --deny warnings
cargo deny check

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

### 2. Update Version

Update version in `Cargo.toml`:

```toml
[workspace.package]
version = "0.2.0"  # Bump from 0.1.0
```

### 3. Update CHANGELOG

Create/update `CHANGELOG.md`:

```markdown
# Changelog

## [0.2.0] - 2026-02-10

### Added
- Feature X
- Feature Y

### Changed
- Breaking change Z

### Fixed
- Bug fix A

### Security
- Security fix B
```

### 4. Commit and Tag

```bash
git add Cargo.toml CHANGELOG.md
git commit -m "chore: release v0.2.0"
git tag v0.2.0
git push origin main --tags
```

### 5. Publish to Crates.io

```bash
# Dry run first
cargo publish --dry-run

# Publish
cargo publish
```

**Note**: WASM skills are workspace members but may not be published separately.

### 6. Publish Python Bindings to PyPI

```bash
# Build wheels for multiple platforms
maturin build --release --features python

# Dry run
maturin publish --dry-run

# Publish
maturin publish
```

### 7. Create GitHub Release

1. Go to GitHub Releases page
2. Create new release from tag `v0.2.0`
3. Copy CHANGELOG entry as release notes
4. Attach artifacts:
   - WASM skill binaries (`.wasm` files)
   - Python wheels (`.whl` files)
   - Source tarball

## Automated Release (CI)

The project includes GitHub Action workflows that can automate releases:

### Trigger Release

```bash
git tag v0.2.0
git push origin v0.2.0
```

This triggers:
1. Full CI test suite
2. Security scans
3. Build artifacts
4. (Future) Automatic publishing

## Versioning Guidelines

### Semantic Versioning (SemVer)

- **MAJOR** (1.0.0): Breaking API changes
- **MINOR** (0.2.0): New features, backward compatible
- **PATCH** (0.1.1): Bug fixes, backward compatible

### Pre-release Versions

- Alpha: `0.1.0-alpha.1`
- Beta: `0.1.0-beta.1`
- Release Candidate: `0.1.0-rc.1`

## Release Artifacts

| Artifact | Location | Description |
|----------|----------|-------------|
| Rust crate | crates.io | Main VAK library |
| Python wheel | PyPI | Python bindings (`vak-python`) |
| WASM skills | GitHub Release | Pre-compiled WASM modules |
| Documentation | docs.rs | API documentation |

## Rollback Procedure

If a release has issues:

```bash
# Yank the problematic version from crates.io
cargo yank --vers 0.2.0

# Yank from PyPI (if applicable)
pip index versions vak-python
# Manual yank via PyPI web interface

# Create hotfix
git checkout v0.1.0
git checkout -b hotfix/0.1.1
# Fix issue
git tag v0.1.1
```

## Guidelines

-   **Semantic Versioning**: Follow SemVer strictly.
-   **Changelog**: Update `CHANGELOG.md` before releasing.
-   **CI Checks**: Ensure all CI checks pass before tagging.
-   **Dry Run**: Always perform a dry run before publishing.
-   **Wait for Crates.io**: If publishing multiple crates, wait for dependencies to propagate (~5 minutes).
-   **Security First**: Never release with known security vulnerabilities.
-   **Documentation**: Ensure docs.rs can build documentation.

## Infrastructure TODOs

- [ ] INF-002: Create official Docker images
- [ ] INF-003: Create Helm charts for Kubernetes deployment
- [ ] INF-004: Add comprehensive CI/CD release pipeline
