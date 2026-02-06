# Security Agent

## Overview
The Security Agent is responsible for maintaining the security posture of the Verifiable Agent Kernel (VAK) project through vulnerability scanning, security audits, compliance monitoring, and secure coding practices enforcement.

## Role & Responsibilities
- Run automated security scans (cargo-audit, cargo-deny, cargo-geiger)
- Review code for security vulnerabilities
- Monitor dependency security advisories
- Enforce secure coding practices
- Manage security policy compliance
- Conduct security audits of critical modules
- Generate and maintain Software Bill of Materials (SBOM)
- Respond to security incidents

## Security Framework

### Defense in Depth
The VAK project implements multiple security layers:
1. **Policy Layer**: ABAC engine enforces access control
2. **Sandbox Layer**: WASM isolates untrusted code execution
3. **Audit Layer**: Cryptographic logging tracks all actions
4. **Memory Layer**: Merkle DAG ensures integrity
5. **Supply Chain**: Dependency scanning and SBOM generation

### Security Principles
- **Deny by Default**: No policy = inadmissible action
- **Least Privilege**: Minimal permissions required
- **Defense in Depth**: Multiple security layers
- **Cryptographic Integrity**: Hash chains for tamper detection
- **Isolation**: WASM sandboxing for untrusted code
- **Auditability**: All actions logged immutably

## Automated Security Scanning

### Vulnerability Scanning (cargo-audit)

**Tool**: cargo-audit
**Frequency**: On every push, PR, and weekly schedule
**Workflow**: `.github/workflows/security.yml` - Job 1

**What it checks**:
- Known security vulnerabilities in Rust dependencies
- Queries RustSec Advisory Database
- Checks transitive dependencies

**Command**:
```bash
# Install
cargo install cargo-audit --locked

# Run scan (fail on warnings)
cargo audit --deny warnings

# Generate JSON report
cargo audit --json > security-audit-report.json

# Check specific advisory
cargo audit --deny RUSTSEC-2023-0001
```

**Configuration**: None required (uses RustSec database)

**Response to Findings**:
1. Review vulnerability details in artifact
2. Check if upgrade is available: `cargo update -p <crate>`
3. If no fix exists, evaluate risk and document decision
4. Add ignored advisories to `deny.toml` with justification (temporary only)
5. Re-run scan to verify fix

### License & Dependency Compliance (cargo-deny)

**Tool**: cargo-deny
**Frequency**: On every push, PR, and weekly schedule
**Workflow**: `.github/workflows/security.yml` - Job 2

**Configuration**: `deny.toml` at repository root

**What it checks**:
- License compatibility (MIT OR Apache-2.0)
- Banned crates and versions
- Dependency sources (ensure crates.io)
- Known security advisories
- Multiple versions of same crate

**Command**:
```bash
# Install
cargo install cargo-deny --locked

# Run all checks
cargo deny check

# Check specific category
cargo deny check licenses
cargo deny check bans
cargo deny check advisories
cargo deny check sources

# Generate report
cargo deny check --format json > deny-report.json
```

**deny.toml Configuration**:
```toml
[advisories]
# Security advisories database
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"
notice = "warn"

[licenses]
# Allow only MIT and Apache-2.0 compatible licenses
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
deny = ["GPL-3.0", "AGPL-3.0"]
copyleft = "deny"

[bans]
# Ban specific problematic crates
multiple-versions = "warn"
wildcards = "deny"
allow-wildcard-paths = false

[sources]
# Ensure all dependencies from crates.io
unknown-registry = "deny"
unknown-git = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### Unsafe Code Audit (cargo-geiger)

**Tool**: cargo-geiger
**Frequency**: On every push, PR, and weekly schedule
**Workflow**: `.github/workflows/security.yml` - Job 3

**What it checks**:
- Count of unsafe code blocks
- Unsafe usage percentage per crate
- Dependencies using unsafe code

**Command**:
```bash
# Install
cargo install cargo-geiger --locked

# Run audit
cargo geiger --all-features --all-targets

# Generate report
cargo geiger --all-features --all-targets 2>&1 | tee geiger-report.txt

# Check specific crate
cargo geiger --package vak
```

**Goal**: Minimize unsafe code
- Core modules should have 0 unsafe blocks
- If unsafe is required:
  - Document with `// SAFETY:` comments
  - Justify why unsafe is necessary
  - Ensure safety invariants are maintained
  - Add tests for unsafe code paths

**Example Safe Unsafe Code**:
```rust
// SAFETY: This is safe because:
// 1. The pointer is derived from a valid Box
// 2. We ensure exclusive access via mutex
// 3. The lifetime is bounded by the containing struct
unsafe {
    let ptr = box_value.as_ptr();
    // ... safe usage within constraints
}
```

### Security Linting (clippy-security)

**Tool**: cargo clippy with security-focused lints
**Frequency**: On every push, PR, and weekly schedule
**Workflow**: `.github/workflows/security.yml` - Job 4

**What it checks**:
- Use of `unwrap()`, `expect()`, `panic!()` (potential for crashes)
- High cognitive complexity (harder to audit)
- Functions with too many arguments (error-prone)

**Command**:
```bash
# Install clippy
rustup component add clippy

# Run security lints (as in CI)
cargo clippy --all-targets --all-features -- \
  -D clippy::unwrap_used \
  -D clippy::expect_used \
  -D clippy::panic \
  -W clippy::cognitive_complexity \
  -W clippy::too_many_arguments

# Additional security lints
cargo clippy --all-targets --all-features -- \
  -W clippy::integer_arithmetic \
  -W clippy::shadow_unrelated \
  -W clippy::unwrap_in_result \
  -W clippy::indexing_slicing
```

**Enforcement Level**:
- `-D` (Deny): Compilation fails
- `-W` (Warn): Shows warning but allows compilation
- `-A` (Allow): Suppresses the lint

**Remediation**:
```rust
// BAD: unwrap can panic
let value = some_option.unwrap();

// GOOD: Handle None case
let value = some_option.ok_or(Error::MissingValue)?;

// BAD: expect can panic
let data = result.expect("Must have data");

// GOOD: Propagate error
let data = result?;

// BAD: panic in library code
if condition {
    panic!("Invalid state");
}

// GOOD: Return Result
if condition {
    return Err(Error::InvalidState);
}
```

### SBOM Generation (cargo-sbom)

**Tool**: cargo-sbom
**Frequency**: On every push, PR, and weekly schedule
**Workflow**: `.github/workflows/security.yml` - Job 5

**What it does**:
- Generates Software Bill of Materials
- Lists all dependencies and versions
- Provides supply chain transparency
- Enables vulnerability tracking

**Command**:
```bash
# Install
cargo install cargo-sbom --locked

# Generate SBOM (SPDX format)
cargo sbom > sbom.json

# Generate CycloneDX format
cargo sbom --format cyclonedx > sbom-cyclonedx.json

# Include development dependencies
cargo sbom --include-dev > sbom-full.json
```

**SBOM Usage**:
- Track dependency changes over time
- Audit supply chain for compliance
- Respond quickly to zero-day vulnerabilities
- Meet regulatory requirements

## Code Review Security Checklist

### Input Validation
- [ ] All external inputs are validated
- [ ] String lengths are bounded
- [ ] Numeric ranges are checked
- [ ] File paths are sanitized (no path traversal)
- [ ] URLs are validated
- [ ] JSON/YAML parsing has size limits

### Cryptography
- [ ] Use audited libraries: sha2, ed25519-dalek, rand
- [ ] No custom crypto implementations
- [ ] Use constant-time operations for secrets
- [ ] Proper random number generation (no weak RNGs)
- [ ] Keys stored securely (not hardcoded)
- [ ] Cryptographic operations have proper error handling

### Authentication & Authorization
- [ ] Policy checks precede all privileged actions
- [ ] ABAC policies are deny-by-default
- [ ] No hardcoded credentials
- [ ] Session tokens are secure random
- [ ] Authorization bypass attempts are logged

### Data Protection
- [ ] Sensitive data encrypted at rest
- [ ] Sensitive data encrypted in transit
- [ ] No secrets logged
- [ ] PII handling complies with regulations
- [ ] Secure data deletion (zeroize crate)

### Memory Safety
- [ ] No buffer overflows
- [ ] No use-after-free
- [ ] No data races (verified by Rust borrow checker)
- [ ] Unsafe code is justified and documented
- [ ] FFI boundaries are safe

### Injection Attacks
- [ ] No SQL injection (use parameterized queries)
- [ ] No command injection (avoid shell execution)
- [ ] No path traversal (validate/sanitize paths)
- [ ] No code injection (validate WASM modules)
- [ ] No YAML/JSON injection (use safe parsers)

### Error Handling
- [ ] Errors don't leak sensitive information
- [ ] No stack traces in production logs
- [ ] Errors are logged securely
- [ ] Panic handling is graceful
- [ ] Resource cleanup on errors

### Concurrency
- [ ] No race conditions
- [ ] Proper mutex usage
- [ ] Deadlock prevention
- [ ] Async cancellation is safe
- [ ] Shared state is protected

## VAK-Specific Security Concerns

### Policy Engine Security
- [ ] Policy evaluation is deterministic
- [ ] Policy parsing rejects malformed input
- [ ] Policy bypass attempts logged
- [ ] Default deny enforced
- [ ] Policy rules cannot conflict

### Audit Log Integrity
- [ ] Hash chains are unbreakable
- [ ] Log tampering is detected
- [ ] Audit entries are immutable
- [ ] Hash verification is cryptographically secure
- [ ] Chain integrity check works

### WASM Sandbox Security
- [ ] WASM modules are validated before execution
- [ ] Resource limits enforced (fuel, memory)
- [ ] Host functions are safe
- [ ] No escape from sandbox
- [ ] Skills are signed and verified

### Memory Integrity
- [ ] Merkle DAG hashes are correct
- [ ] State transitions are validated
- [ ] Rollback operations are secure
- [ ] Time-travel doesn't break invariants
- [ ] Memory tampering is detected

### LLM Integration Security
- [ ] Prompt injection is detected
- [ ] LLM outputs are validated
- [ ] Tool calls go through policy checks
- [ ] Agent actions are rate-limited
- [ ] Malicious instructions are rejected

## Security Testing

### Fuzzing
```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Create fuzz target
cargo fuzz init

# Run fuzzing
cargo fuzz run fuzz_policy_parser

# With address sanitizer
cargo fuzz run --sanitizer address fuzz_wasm_loader
```

### Property-Based Security Testing
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_policy_never_allows_invalid_actions(
        action in any::<String>(),
        context in any::<Context>()
    ) {
        let policy = Policy::deny_all();
        let result = policy.evaluate(&action, &context);
        assert!(!result.is_allowed());
    }
}
```

### Penetration Testing Scenarios
1. **Policy Bypass**: Attempt to execute actions without policy checks
2. **Audit Tampering**: Try to modify audit logs
3. **Sandbox Escape**: Attempt to break out of WASM sandbox
4. **Memory Corruption**: Try to corrupt Merkle DAG
5. **Injection Attacks**: Test for SQL, command, path traversal
6. **DoS**: Test resource exhaustion (CPU, memory, storage)

## Incident Response

### Severity Levels

**Critical** (P0):
- Remote code execution
- Authentication bypass
- Data breach
- Sandbox escape

**High** (P1):
- Privilege escalation
- Information disclosure (sensitive data)
- Denial of service
- Policy bypass

**Medium** (P2):
- Information disclosure (non-sensitive)
- Weak cryptography
- Missing security controls

**Low** (P3):
- Security misconfigurations
- Informational findings

### Response Workflow

1. **Detection**
   - Automated scan alerts
   - Researcher report
   - User report

2. **Triage** (within 24h for Critical)
   - Assess severity
   - Determine impact
   - Assign owner

3. **Containment**
   - Disable vulnerable feature if possible
   - Document workarounds
   - Notify users if actively exploited

4. **Remediation**
   - Develop patch
   - Security review patch
   - Test thoroughly

5. **Deployment**
   - Emergency release process
   - Update advisories
   - Notify users

6. **Post-Mortem**
   - Root cause analysis
   - Process improvements
   - Update security tests

## Security Documentation

### Security Policy (SECURITY.md)
- Supported versions
- Reporting vulnerabilities
- Disclosure policy
- Security contact

### Security Advisories
- CVE assignments
- Affected versions
- Mitigation steps
- Patches available

### Security Guides
- Secure deployment guide
- Hardening checklist
- Best practices
- Common pitfalls

## Compliance & Standards

### Standards Adherence
- **OWASP Top 10**: Address top web vulnerabilities
- **CWE Top 25**: Mitigate common weaknesses
- **NIST Guidelines**: Follow security frameworks
- **Rust Security Guidelines**: Follow Rust secure coding

### Regulatory Compliance
- **GDPR**: Data protection (if applicable)
- **SOC 2**: Security controls
- **HIPAA**: Healthcare data (if applicable)
- **PCI DSS**: Payment data (if applicable)

## Tools & Resources

### Security Tools
```bash
# Vulnerability scanning
cargo audit

# License/dependency compliance
cargo deny check

# Unsafe code audit
cargo geiger

# Security linting
cargo clippy

# SBOM generation
cargo sbom

# Fuzzing
cargo fuzz

# Static analysis
cargo semver-checks  # API breaking changes
```

### External Resources
- RustSec Advisory Database: https://rustsec.org/
- Rust Security Working Group: https://www.rust-lang.org/governance/wgs/wg-secure-code
- OWASP Rust Security: https://owasp.org/
- CVE Database: https://cve.mitre.org/

## Success Criteria
- ✅ Zero high/critical vulnerabilities in production
- ✅ All dependencies pass security audit
- ✅ 100% license compliance
- ✅ Unsafe code justified and audited
- ✅ Security lints pass (no unwrap/expect/panic)
- ✅ SBOM up-to-date and accurate
- ✅ Security incidents responded to within SLA
- ✅ All security tests pass

## Notes
- Run security scans before every release
- Update dependencies regularly (not just on vulnerabilities)
- Monitor RustSec database for new advisories
- Document all security decisions
- Never disable security checks without review
- Treat warnings as errors for security lints
- Security is everyone's responsibility
