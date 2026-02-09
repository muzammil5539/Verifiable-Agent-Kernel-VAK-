---
name: check-security
description: Run security audits, vulnerability scans, and license checks for the VAK project.
---

# Security Checks

This skill provides instructions for performing security audits on the VAK codebase.

## Prerequisites

- `cargo-audit` (`cargo install cargo-audit`)
- `cargo-deny` (`cargo install cargo-deny`)
- `cargo-geiger` (`cargo install cargo-geiger`)
- `cargo-sbom` (`cargo install cargo-sbom`)
- `clippy` (`rustup component add clippy`)

## Instructions

### Vulnerability Scan

To scan dependencies for known vulnerabilities:

```bash
cargo audit
```

### License & Ban Check

To check license compliance and banned crates:

```bash
cargo deny check
```

### Unsafe Code Audit

To count unsafe code usage:

```bash
cargo geiger
```

### Security Lints

To run security-focused Clippy lints:

```bash
cargo clippy --all-targets --all-features -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -W clippy::cognitive_complexity -W clippy::too_many_arguments
```

### Generate SBOM

To generate a Software Bill of Materials:

```bash
cargo sbom > sbom.json
```

## Examples

### Check Specific Advisory
To check for a specific RustSec advisory:

```bash
cargo audit --deny RUSTSEC-2023-0001
```

### Check Licenses Only
To run only the license check:

```bash
cargo deny check licenses
```

## Guidelines

-   **Zero Tolerance**: Critical and High vulnerabilities must be fixed immediately.
-   **Deny Unsafe**: Minimize `unsafe` code usage. All `unsafe` blocks must have a `// SAFETY:` comment explaining why it is safe.
-   **License Compliance**: Ensure all dependencies are compatible with the project license (MIT/Apache-2.0).
-   **No Panics**: Production code should not use `unwrap()`, `expect()`, or `panic!()`. Use `Result` instead.
