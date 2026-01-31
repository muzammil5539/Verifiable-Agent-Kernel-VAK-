# VAK Autonomous Code Auditor - MVP Demo

> **The first autonomous code auditor with cryptographic verifiability and formal safety guarantees.**

## Overview

The VAK Autonomous Code Auditor is the flagship MVP demonstration of the Verifiable Agent Kernel (VAK). It showcases how autonomous AI agents can review code for security vulnerabilities and logic errors while providing:

- **Cryptographic Proof**: Every decision is logged in a tamper-evident hash-chain
- **Formal Safety**: Constraints prevent access to sensitive files and enforce operational limits
- **PRM Integration**: Reasoning steps are scored for confidence and quality
- **Full Auditability**: Complete trace of agent observations, thoughts, and actions

## Quick Start

### Running the Rust Demo

```bash
# From the project root
cargo run --example code_auditor_demo
```

### Running the Python Demo

```bash
# From the project root
python examples/code_auditor_python.py
```

## Architecture

The Code Auditor implements all four core VAK modules:

```
┌─────────────────────────────────────────────────────────────┐
│                   Code Auditor Agent                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐  ┌──────────────────┐               │
│  │  Episodic Memory │  │  Audit Logger    │               │
│  │  (Merkle Chain)  │  │  (Hash-Chained)  │               │
│  └────────┬─────────┘  └────────┬─────────┘               │
│           │                     │                          │
│  ┌────────▼─────────────────────▼─────────┐               │
│  │         Constraint Verifier            │               │
│  │         (Formal Safety)                │               │
│  └────────────────────┬───────────────────┘               │
│                       │                                    │
│  ┌────────────────────▼───────────────────┐               │
│  │         Process Reward Model           │               │
│  │         (Reasoning Validation)         │               │
│  └────────────────────────────────────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Features Demonstrated

### 1. Immutable Memory Log (Merkle Chain)

Every observation, thought, and action is recorded in a cryptographically-linked chain:

```rust
// Recording an observation
self.episodic_memory.record_episode(
    "observation".to_string(),
    "Reading file: src/main.rs".to_string(),
    None,
);
```

The chain can be verified at any time:

```rust
assert!(auditor.episodic_memory.verify_chain().is_ok());
```

### 2. Access Control (Forbidden Files)

The auditor enforces strict access control policies:

```rust
// Configuration
forbidden_files: vec![
    ".env",
    "secrets.json", 
    "credentials.yaml",
    ".git-credentials",
    "private.key",
],
```

Attempting to access forbidden files is automatically blocked and logged:

```
✅ Access correctly denied: Access denied: '.env' is a forbidden file
```

### 3. Formal Constraints

Operational limits are enforced through formal constraint verification:

```rust
// Verify max steps constraint
let step_constraint = Constraint::new(
    "max_steps",
    ConstraintKind::LessThan {
        field: "step_count".to_string(),
        value: ConstraintValue::Integer(50),
    },
);
```

### 4. PRM Integration (Reasoning Validation)

Each reasoning step is scored by a Process Reward Model:

```rust
let reasoning_step = ReasoningStep::new(
    self.step_count,
    "Analyzing for SQL injection patterns"
)
.with_action("Pattern matching for string concatenation in SQL queries");

let score = self.prm.score_step(&reasoning_step, "SQL injection analysis").await?;

// Only proceed if confidence is above threshold
if score.score >= self.config.prm_threshold {
    // Continue analysis
}
```

### 5. Cryptographic Audit Trail

Every action is logged with hash-chain integrity:

```rust
self.audit_logger.log(
    "code-auditor",
    "read_file",
    file_path,
    AuditDecision::Allowed,
);
```

The complete audit trail can be exported as a cryptographic receipt:

```
═══════════════════════════════════════════════════════════════
                    AUDIT RECEIPT
═══════════════════════════════════════════════════════════════
Session ID:    f47ac10b-58cc-4372-a567-0e02b2c3d479
Timestamp:     2026-01-31T12:00:00Z
Total Steps:   25
Files:         2
Findings:      8
───────────────────────────────────────────────────────────────
Findings by Severity:
  Critical     2
  High         3
  Medium       2
  Low          1
───────────────────────────────────────────────────────────────
Audit Chain Hash:
  a3b8c9d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6
Episodic Memory Hash:
  1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7
═══════════════════════════════════════════════════════════════
```

## Security Analysis Capabilities

The Code Auditor detects the following vulnerability categories:

### Critical Vulnerabilities

| Type | Detection Method | Example |
|------|------------------|---------|
| SQL Injection | Pattern matching for string concatenation in SQL | `format!("SELECT * FROM users WHERE id = '{}'", user_id)` |
| Command Injection | Detection of shell command construction | `exec(user_input)` |
| Dangerous eval() | Use of eval with user input | `eval(data)` |

### High Severity Issues

| Type | Detection Method | Example |
|------|------------------|---------|
| Hardcoded Secrets | Pattern matching for API keys, passwords | `api_key = "sk-1234..."` |
| Unsafe Code | Detection of `unsafe {}` blocks | `unsafe { raw_ptr.read() }` |
| Unimplemented Code | Detection of `panic!()`, `todo!()` | `todo!()` |

### Medium Severity Issues

| Type | Detection Method | Example |
|------|------------------|---------|
| Unchecked Unwrap | Detection of `.unwrap()` | `data.parse().unwrap()` |
| Bare Except | Catching all exceptions | `except:` |

### Best Practice Violations

| Type | Detection Method | Example |
|------|------------------|---------|
| Silenced Errors | Detection of `let _ =` | `let _ = risky_operation()` |
| Expect Usage | Detection of `.expect()` | `file.read().expect("msg")` |

## Configuration

### Code Auditor Configuration

```rust
struct CodeAuditorConfig {
    /// Maximum reasoning steps allowed (default: 50)
    max_steps: usize,
    
    /// PRM score threshold for accepting a reasoning step (default: 0.6)
    prm_threshold: f64,
    
    /// Files that are forbidden from access
    forbidden_files: Vec<String>,
    
    /// Maximum files to analyze per session (default: 100)
    max_files: usize,
}
```

### Policy Configuration (YAML)

See `policies/code_auditor/code_auditor_policies.yaml` for the full ABAC policy configuration.

### Constraint Configuration (YAML)

See `policies/code_auditor/code_auditor_constraints.yaml` for the formal constraint definitions.

## Verifiable Workflow

The Code Auditor follows a strictly verifiable workflow:

```
1. TRIGGER     → PR #42 created
2. SNAPSHOT    → VAK creates Merkle Root hash 0xABC...
3. PLAN        → Agent proposes: "I will read main.py"
4. VERIFY      → Kernel checks FORBIDDEN_FILES
5. EXECUTE     → Agent calls read_file('main.py') 
6. RECORD      → Observation hashed and linked → New Root 0xDEF...
7. REASON      → Agent thinks: "Line 10 looks like SQL Injection"
8. PRM CHECK   → PRM Scorer evaluates reasoning. Score: 0.9
9. ACTION      → Agent drafts comment
10. RECEIPT    → VAK generates cryptographic proof
```

## Testing

### Running the Demo Tests (Rust)

```bash
# The demo includes embedded tests
cargo test --example code_auditor_demo
```

### Running the Demo Tests (Python)

```bash
python -m pytest examples/code_auditor_python.py -v
```

## Integration with CI/CD

The Code Auditor can be integrated into CI/CD pipelines:

```yaml
# .github/workflows/code-audit.yml
name: Code Audit
on: [pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run VAK Code Auditor
        run: cargo run --example code_auditor_demo -- --pr ${{ github.event.pull_request.number }}
      - name: Upload Audit Receipt
        uses: actions/upload-artifact@v3
        with:
          name: audit-receipt
          path: audit-receipt.json
```

## Next Steps

After the MVP demo, the following features are planned:

1. **Full PR Integration**: GitHub/GitLab webhook integration
2. **LLM-Powered Analysis**: Deep semantic understanding of code
3. **Custom Rule Engine**: User-defined vulnerability patterns
4. **Fleet Dashboard**: Centralized monitoring of multiple auditors
5. **Compliance Reports**: SOC2, ISO27001 formatted outputs

## Related Documentation

- [Project Feasibility Analysis](../Project%20Feasibility.md)
- [Blue Ocean Opportunity](../AI%20Agent%20Blue%20Ocean%20Opportunity.md)
- [Implementation Plan](../plan-vakImplementation.prompt.md)

## License

MIT OR Apache-2.0
