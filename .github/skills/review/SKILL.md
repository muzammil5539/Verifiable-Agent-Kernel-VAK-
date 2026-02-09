---
name: review
description: Instructions for reviewing Rust and Python code changes, ensuring quality, security, and correctness.
---

# Code Review

This skill provides a comprehensive checklist and guidelines for reviewing code changes in the VAK project.

## Review Checklist

### General

-   [ ] **Code Readability**: Is the code clear and easy to understand?
-   [ ] **Documentation**: Are public items documented (`///`)? Do examples work?
-   [ ] **Test Coverage**: Are there new tests for new features? Do they pass?
-   [ ] **Error Handling**: Is `Result` used? Are errors descriptive?
-   [ ] **Security**: No hardcoded secrets? Input validation?

### Rust Specific

-   [ ] **Ownership**: No unnecessary `clone()`. Proper use of lifetimes.
-   [ ] **Unsafe Code**: Is `unsafe` justified and documented with `// SAFETY:`? (SEC-003)
-   [ ] **Async**: No blocking calls in `async fn`. Correct use of `tokio`.
-   [ ] **Clippy**: Does `cargo clippy` pass without warnings?
-   [ ] **Format**: Is the code formatted with `cargo fmt`?
-   [ ] **No Panics**: No `unwrap()`, `expect()`, or `panic!()` in production code.

### Python Specific

-   [ ] **Type Hints**: Are type hints used (mypy strict)?
-   [ ] **Async**: Proper use of `async`/`await` and `asyncio`.
-   [ ] **PyO3**: Correct FFI boundaries and error conversion.
-   [ ] **Format**: Is the code formatted with `ruff format`?

### VAK-Specific Checks

-   [ ] **Policy Integration**: Does the feature go through the policy engine? (POL-004)
-   [ ] **Audit Logging**: Are critical actions logged to the audit trail?
-   [ ] **WASM Safety**: Does WASM code respect sandbox boundaries?
-   [ ] **Prompt Injection**: Is user input validated against injection? (SEC-004)
-   [ ] **Rate Limiting**: Are high-frequency operations rate-limited? (SEC-005)

## Architecture Guidelines

VAK follows a layered architecture with strict boundaries:

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent Layer                            │
└─────────────────────────────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                   VAK Kernel (src/)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Policy     │  │    Audit     │  │    Memory    │      │
│  │   Engine     │  │   Logger     │  │   Manager    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │    WASM      │  │   Reasoner   │  │    Swarm     │      │
│  │   Sandbox    │  │    (NSR)     │  │   Protocol   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
```

### Module Responsibilities

| Module | Path | Key Responsibilities |
|--------|------|---------------------|
| **Policy** | `src/policy/` | Cedar enforcement, hot-reload, context injection |
| **Audit** | `src/audit/` | Flight recorder, OpenTelemetry, GraphQL API |
| **Memory** | `src/memory/` | Merkle DAG, time travel, content-addressable store |
| **Sandbox** | `src/sandbox/` | WASM runtime, epoch ticker, pooling allocator |
| **Reasoner** | `src/reasoner/` | Datalog, PRM, constrained decoding, prompt injection |
| **Swarm** | `src/swarm/` | A2A protocol, consensus, voting |
| **Kernel** | `src/kernel/` | Core orchestration, rate limiter, custom handlers |

### Invariants

-   **Policy Enforcement**: All agent actions MUST go through the policy engine (POL-004).
-   **Audit Logging**: Critical actions MUST be logged to the immutable audit log.
-   **WASM Isolation**: Untrusted code MUST run in the WASM sandbox.
-   **Deny by Default**: No policy = no access (POL-007).
-   **Hot-Reload Safety**: Policy changes are atomic via ArcSwap (POL-006).
-   **Panic Boundary**: Host functions catch panics at WASM boundary (RT-005).

## Examples

### Reviewing a Rust Function

```rust
// Good: Uses Result, borrows instead of taking ownership
pub fn process_data(data: &[u8]) -> Result<ProcessedData, ProcessError> {
    if data.is_empty() {
        return Err(ProcessError::EmptyInput);
    }
    // ...
}

// Bad: Takes ownership unnecessarily, panics on error
pub fn process_data(data: Vec<u8>) -> ProcessedData {
    if data.is_empty() {
        panic!("Empty input!");  // Never do this!
    }
    // ...
}
```

### Reviewing a Policy-Aware Function

```rust
// Good: Uses policy enforcement
async fn execute_tool(&self, request: ToolRequest) -> Result<ToolResult, KernelError> {
    // Check policy BEFORE execution
    self.policy_engine.authorize(&request.principal, &request.action, &request.resource)?;
    
    // Log to audit trail
    self.audit_log.record(AuditEntry::ToolExecution {
        agent_id: request.agent_id,
        tool: request.tool_name,
        timestamp: Utc::now(),
    })?;
    
    // Execute in sandbox
    self.sandbox.execute(request).await
}
```

### Reviewing Host Functions

```rust
// Good: Uses panic boundary wrapper
pub fn register_host_function(linker: &mut Linker<HostState>) {
    linker.func_wrap("env", "my_function", |caller: Caller<'_, HostState>, arg: i32| {
        with_panic_boundary(|| {
            // Safe code here
            with_safe_policy_check(caller, || {
                // Policy-checked operation
                Ok(arg * 2)
            })
        })
    });
}
```

## Security Audit Checklist

-   [ ] **Dependencies**: Check `Cargo.toml` / `pyproject.toml` for new dependencies.
-   [ ] **Vulnerabilities**: Run `cargo audit` to check for known vulnerabilities.
-   [ ] **Licenses**: Run `cargo deny check licenses` for license compliance.
-   [ ] **Secrets**: Ensure no secrets are committed. Check for API keys, tokens.
-   [ ] **Input Validation**: User input goes through prompt injection detector.
-   [ ] **Rate Limits**: High-frequency operations are rate-limited.

## CI Verification

Before approving, verify CI passes:
- `cargo check --workspace`
- `cargo test`
- `cargo clippy --all-targets --all-features`
- `cargo fmt --all -- --check`
- `cargo audit` (if dependencies changed)
- `cargo deny check` (if dependencies changed)

## Notes

-   **Be Constructive**: Focus on code improvement, not criticism.
-   **Explain Why**: Provide reasons for requested changes.
-   **Verify Locally**: Pull the branch and run tests if unsure.
-   **Security First**: When in doubt, err on the side of security.
