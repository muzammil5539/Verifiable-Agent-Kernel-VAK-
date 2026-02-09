---
name: security
description: Run security audits, vulnerability scans, and license checks for the VAK project.
---

# Security Checks

This skill provides instructions for performing security audits on the VAK codebase.

## Security Implementation Status

| ID | Feature | Status | Implementation |
|----|---------|--------|----------------|
| SEC-001 | Supply Chain Hardening | ✅ Complete | `.github/workflows/security.yml` |
| SEC-002 | License Compliance | ✅ Complete | `deny.toml`, CI workflow |
| SEC-003 | Unsafe Rust Audit | ✅ Complete | `#![deny(unsafe_code)]` + docs |
| SEC-004 | Prompt Injection Protection | ✅ Complete | `src/reasoner/prompt_injection.rs` |
| SEC-005 | Rate Limiting | ✅ Complete | `src/kernel/rate_limiter.rs` |

## Prerequisites

- `cargo-audit` (`cargo install cargo-audit --locked`)
- `cargo-deny` (`cargo install cargo-deny --locked`)
- `cargo-geiger` (`cargo install cargo-geiger --locked`)
- `cargo-sbom` (`cargo install cargo-sbom`)
- `clippy` (`rustup component add clippy`)

## CI/CD Integration

Security checks run automatically via `.github/workflows/security.yml`:
- **On push**: main, develop branches
- **On PR**: main branch
- **Scheduled**: Weekly on Sundays at midnight UTC

## Instructions

### Vulnerability Scan (SEC-001)

To scan dependencies for known vulnerabilities:

```bash
cargo audit
```

With strict mode (deny warnings):

```bash
cargo audit --deny warnings
```

Generate JSON report:

```bash
cargo audit --json > security-audit-report.json
```

### License & Ban Check (SEC-002)

To check license compliance and banned crates:

```bash
cargo deny check
```

The project uses `deny.toml` with the following allowed licenses:
- MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause
- ISC, Zlib, 0BSD, MPL-2.0, CC0-1.0, Unlicense

### Unsafe Code Audit (SEC-003)

The project uses `#![deny(unsafe_code)]` by default. To audit for unsafe usage in dependencies:

```bash
cargo geiger --all-features --all-targets
```

**Current Status**: 
- Main crate: Denies unsafe code
- WASM skills: Documented unsafe blocks with `// SAFETY:` comments

### Security Lints (Clippy)

To run security-focused Clippy lints:

```bash
cargo clippy --all-targets --all-features -- \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic \
  -W clippy::cognitive_complexity \
  -W clippy::too_many_arguments
```

### Generate SBOM

To generate a Software Bill of Materials:

```bash
cargo sbom > sbom.json
```

## Prompt Injection Protection (SEC-004)

The project includes built-in prompt injection detection:

```rust
use vak::reasoner::PromptInjectionDetector;

let detector = PromptInjectionDetector::new(DetectorConfig::default());
let result = detector.analyze(input_text);
match result.action {
    RecommendedAction::Allow => { /* proceed */ }
    RecommendedAction::Block => { /* reject input */ }
    _ => { /* log and review */ }
}
```

Detection categories:
- Instruction override attempts
- Role manipulation
- Context injection
- Unicode smuggling
- Encoding tricks

## Rate Limiting (SEC-005)

Per-resource rate limiting is implemented in `src/kernel/rate_limiter.rs`:
- Per-agent+action+resource key limits
- Token bucket algorithm with configurable refill
- Burst allowance support

## Examples

### Check Specific Advisory
```bash
cargo audit --deny RUSTSEC-2023-0001
```

### Check Licenses Only
```bash
cargo deny check licenses
```

### Check Bans Only
```bash
cargo deny check bans
```

### Full Security Audit Script
```bash
#!/bin/bash
set -e
echo "Running vulnerability scan..."
cargo audit --deny warnings
echo "Running license check..."
cargo deny check
echo "Running unsafe audit..."
cargo geiger --all-features || true
echo "Running security lints..."
cargo clippy --all-targets --all-features -- -D warnings
echo "All security checks passed!"
```

## Guidelines

-   **Zero Tolerance**: Critical and High vulnerabilities must be fixed immediately.
-   **Deny Unsafe**: All `unsafe` blocks must have a `// SAFETY:` comment explaining why it is safe.
-   **License Compliance**: Ensure all dependencies are compatible with the project license (MIT/Apache-2.0).
-   **No Panics**: Production code should not use `unwrap()`, `expect()`, or `panic!()`. Use `Result` instead.
-   **Default Deny**: Policy engine fails closed - no policy = no access (POL-007).
-   **Audit Trail**: All security-relevant operations are logged to the immutable audit log.

## Related Files

- `.github/workflows/security.yml` - CI security workflow
- `deny.toml` - cargo-deny configuration
- `src/reasoner/prompt_injection.rs` - Prompt injection detector
- `src/kernel/rate_limiter.rs` - Rate limiting implementation
- `src/policy/enforcer.rs` - Policy enforcement with fail-closed
