---
name: release-project
description: Instructions for releasing and publishing the VAK project to crates.io and PyPI.
---

# Release Project

This skill provides instructions for publishing new releases of the VAK project.

## Prerequisites

-   `cargo-release` (optional: `cargo install cargo-release`)
-   `maturin` (`pip install maturin`)
-   `git`
-   Access to crates.io (token) and PyPI (token)

## Instructions

### Publish to Crates.io

1.  Update version in `Cargo.toml`.
2.  Commit changes.
3.  Tag the release (e.g., `git tag v0.1.0`).
4.  Push changes and tags.

```bash
cargo publish --dry-run  # Verify first
cargo publish
```

### Publish to PyPI

1.  Ensure version in `pyproject.toml` matches.
2.  Build wheels.

```bash
cd python
maturin build --release
maturin publish
```

### GitHub Release

1.  Create a new release on GitHub.
2.  Attach build artifacts (binaries, WASM files).
3.  Include release notes (CHANGELOG).

## Guidelines

-   **Semantic Versioning**: Follow SemVer (major.minor.patch).
-   **Changelog**: Update `CHANGELOG.md` before releasing.
-   **CI Checks**: Ensure all CI checks pass before tagging.
-   **Dry Run**: Always perform a dry run before publishing.
-   **Wait for Crates.io**: If publishing multiple crates, wait for dependencies to propagate.

## Automated Release (CI)

The project includes a GitHub Action workflow `.github/workflows/release.yml` that automates this process when a tag starting with `v` is pushed.

To trigger a release:

```bash
git tag v0.1.0
git push origin v0.1.0
```
