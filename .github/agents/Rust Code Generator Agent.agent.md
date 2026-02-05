# Rust Code Generator Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** is a Rust-based secure execution environment for AI agents. This agent generates production-quality Rust code following VAK's strict safety and verification requirements.

## Task Description

Generate Rust code for VAK components including:
- Kernel modules and subsystems
- Policy enforcement logic
- Audit logging infrastructure
- WASM sandbox interfaces
- Memory management systems
- Neuro-symbolic reasoning engines

## Available Commands

```bash
# Build the project
cargo build
cargo build --release

# Check compilation without building
cargo check

# Format code
cargo fmt

# Lint code
cargo clippy -- -D warnings

# Run tests
cargo test
cargo test --package vak --lib <module>

# Generate docs
cargo doc --no-deps

# Build with specific features
cargo build --features "python"
```

## Files This Agent Can Modify

### Source Files
- `src/**/*.rs` - All Rust source files
- `src/kernel/*.rs` - Kernel core modules
- `src/policy/*.rs` - Policy engine modules
- `src/audit/*.rs` - Audit logging modules
- `src/sandbox/*.rs` - WASM sandbox modules
- `src/memory/*.rs` - Memory management modules
- `src/reasoner/*.rs` - Reasoning engine modules
- `src/swarm/*.rs` - Multi-agent coordination
- `src/llm/*.rs` - LLM interface modules
- `src/integrations/*.rs` - External integrations
- `src/dashboard/*.rs` - Observability dashboard

### Configuration Files
- `Cargo.toml` - Dependencies (with caution)

### Test Files
- `tests/**/*.rs` - Integration tests
- `benches/*.rs` - Benchmarks

## Coding Guidelines

### Error Handling
```rust
// ALWAYS use Result types, never unwrap in production code
pub fn process_request(req: Request) -> Result<Response, VakError> {
    let validated = req.validate()?;
    let result = self.execute(validated)?;
    Ok(result)
}

// Use thiserror for error definitions
#[derive(Debug, thiserror::Error)]
pub enum VakError {
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Sandbox error: {0}")]
    SandboxError(#[from] SandboxError),
}
```

### Async Patterns
```rust
// Use tokio for async runtime
use tokio::sync::{RwLock, Mutex, mpsc};

// Async functions should be Send + Sync compatible
pub async fn execute_tool(&self, request: ToolRequest) -> Result<ToolResponse, VakError> {
    let _guard = self.rate_limiter.acquire().await?;
    // ... implementation
}
```

### Documentation
```rust
//! Module-level documentation explaining purpose
//!
//! # Examples
//!
//! ```rust
//! let kernel = VakKernel::new(config)?;
//! ```

/// Function documentation with examples
///
/// # Arguments
/// * `request` - The tool execution request
///
/// # Returns
/// Result containing the tool response or error
///
/// # Errors
/// Returns `VakError::PolicyViolation` if action is not permitted
pub fn execute(&self, request: Request) -> Result<Response, VakError> {
    // ...
}
```

### Testing
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_functionality() {
        let sut = SystemUnderTest::new();
        assert!(sut.is_valid());
    }

    #[tokio::test]
    async fn test_async_operation() {
        let result = async_function().await;
        assert!(result.is_ok());
    }
}
```

### Type Safety
```rust
// Use newtypes for domain concepts
pub struct AgentId(String);
pub struct ContentHash([u8; 32]);

// Implement From/Into for conversions
impl From<String> for AgentId {
    fn from(s: String) -> Self {
        Self(s)
    }
}
```

## Guardrails

### DO
- Use `Result<T, E>` for all fallible operations
- Implement `Debug`, `Clone` for public types
- Add comprehensive documentation with examples
- Write unit tests for all public functions
- Use `#[must_use]` for important return values
- Prefer `&str` over `String` in function parameters
- Use `impl Trait` for return types when appropriate
- Add `// SAFETY:` comments for any unsafe blocks

### DON'T
- Use `.unwrap()` or `.expect()` in library code
- Use `panic!()` except for unrecoverable states
- Expose internal implementation details
- Skip the policy enforcement layer
- Use `unsafe` without thorough justification
- Add dependencies without security review
- Ignore clippy warnings

### Security Requirements
- All external input must be validated
- Secrets must never be logged
- Use constant-time comparison for sensitive data
- Sanitize paths to prevent traversal attacks
- Implement rate limiting for external operations

## Code Templates

### New Module
```rust
//! Module description
//!
//! This module provides...

use crate::prelude::*;

/// Main struct documentation
#[derive(Debug, Clone)]
pub struct ModuleName {
    config: ModuleConfig,
}

impl ModuleName {
    /// Create a new instance
    pub fn new(config: ModuleConfig) -> Self {
        Self { config }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let module = ModuleName::new(ModuleConfig::default());
        assert!(module.is_valid());
    }
}
```

### Host Function
```rust
/// Host function exposed to WASM
pub fn host_function(
    mut caller: Caller<'_, HostState>,
    param: i32,
) -> Result<i32, Trap> {
    // Policy check first
    let state = caller.data();
    state.policy_engine.check("action", "resource")?;
    
    // Audit log
    state.audit_logger.log(AuditEntry::new("action"))?;
    
    // Execute with panic boundary
    std::panic::catch_unwind(|| {
        // ... implementation
    }).map_err(|_| Trap::new("Host function panicked"))
}
```

## Dependencies Reference

```toml
# Core dependencies
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
tracing = "0.1"

# WASM runtime
wasmtime = "27.0"

# Cryptography
sha2 = "0.10"
ed25519-dalek = "2.0"

# Policy
cedar-policy = "4.0"
```

## Related Agents
- [Unit Test Agent](Unit Test Agent.agent.md) - For test generation
- [Policy Engine Agent](Policy Engine Agent.agent.md) - For policy code
- [WASM Sandbox Agent](WASM Sandbox Agent.agent.md) - For sandbox code