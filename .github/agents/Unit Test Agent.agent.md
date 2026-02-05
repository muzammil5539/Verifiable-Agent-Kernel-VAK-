# Testing Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** requires comprehensive testing to ensure the safety guarantees promised by its architecture. This agent creates and maintains tests across all levels: unit, integration, and end-to-end.

## Task Description

Create and maintain tests for VAK including:
- Unit tests for individual functions and modules
- Integration tests for component interactions
- End-to-end tests for complete workflows
- Property-based tests for invariants
- Benchmark tests for performance
- Adversarial tests for security

## Available Commands

```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests for specific module
cargo test --package vak --lib policy

# Run integration tests
cargo test --test '*'

# Run with coverage
cargo tarpaulin --out Html

# Run benchmarks
cargo bench

# Run ignored tests (e.g., long-running)
cargo test -- --ignored

# Run tests in release mode
cargo test --release

# Python tests
cd python && pytest -v
pytest python/tests/ -v --tb=short
```

## Files This Agent Can Modify

### Unit Tests (inline)
- `src/**/*.rs` - Test modules within source files

### Integration Tests
- `tests/integration/*.rs` - Integration test files
- `tests/integration/test_kernel_workflow.rs`
- `tests/integration/test_policy_enforcement.rs`
- `tests/integration/test_audit_integrity.rs`
- `tests/integration/preemption_tests.rs`
- `tests/integration/test_full_workflow.rs`

### Benchmark Tests
- `benches/*.rs` - Performance benchmarks
- `benches/kernel_benchmarks.rs`

### Python Tests
- `python/tests/*.py` - Python SDK tests

## Testing Guidelines

### Unit Test Structure
```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Setup helper
    fn setup() -> TestFixture {
        TestFixture::new()
    }

    #[test]
    fn test_function_success_case() {
        let fixture = setup();
        let result = function_under_test(&fixture.input);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_value);
    }

    #[test]
    fn test_function_error_case() {
        let fixture = setup();
        let result = function_under_test(&fixture.invalid_input);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ExpectedError::Variant));
    }

    #[test]
    #[should_panic(expected = "specific message")]
    fn test_panic_condition() {
        panic_function();
    }
}
```

### Async Test Structure
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;

    #[tokio::test]
    async fn test_async_operation() {
        let kernel = setup_kernel().await;
        let result = kernel.execute(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_concurrent_operations() {
        let kernel = Arc::new(setup_kernel().await);
        let handles: Vec<_> = (0..10)
            .map(|i| {
                let k = kernel.clone();
                tokio::spawn(async move {
                    k.execute(request(i)).await
                })
            })
            .collect();
        
        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }
    }
}
```

### Integration Test Structure
```rust
// tests/integration/test_workflow.rs

use vak::prelude::*;

mod common;

#[tokio::test]
async fn test_full_agent_workflow() {
    // Setup
    let kernel = common::setup_test_kernel().await;
    let agent_id = common::register_test_agent(&kernel).await;

    // Execute
    let request = ToolRequest::new(agent_id, "calculator", "add", json!({"a": 1, "b": 2}));
    let response = kernel.execute_tool(request).await;

    // Verify
    assert!(response.is_ok());
    let audit_trail = kernel.get_audit_trail(&agent_id).await.unwrap();
    assert!(!audit_trail.is_empty());
    
    // Cleanup
    kernel.unregister_agent(&agent_id).await.unwrap();
}
```

### Property-Based Testing
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn audit_chain_integrity_preserved(
        actions in prop::collection::vec(any::<String>(), 0..100)
    ) {
        let mut logger = AuditLogger::new();
        for action in &actions {
            logger.append(create_entry(action)).unwrap();
        }
        prop_assert!(logger.verify_integrity().is_ok());
    }

    #[test]
    fn policy_evaluation_deterministic(
        principal in "[a-z]{1,10}",
        action in "[a-z]{1,10}",
        resource in "[a-z/]{1,20}"
    ) {
        let engine = PolicyEngine::new();
        let result1 = engine.evaluate(&principal, &action, &resource);
        let result2 = engine.evaluate(&principal, &action, &resource);
        prop_assert_eq!(result1, result2);
    }
}
```

### Adversarial Tests
```rust
#[cfg(test)]
mod adversarial_tests {
    use super::*;

    #[test]
    fn test_infinite_loop_preemption() {
        let runtime = setup_runtime_with_epoch_limit(100);
        let malicious_wasm = compile_infinite_loop();
        
        let result = runtime.execute(malicious_wasm);
        
        assert!(matches!(result, Err(RuntimeError::EpochExceeded)));
    }

    #[test]
    fn test_memory_bomb_prevention() {
        let runtime = setup_runtime_with_memory_limit(512 * 1024 * 1024);
        let malicious_wasm = compile_memory_allocator();
        
        let result = runtime.execute(malicious_wasm);
        
        assert!(matches!(result, Err(RuntimeError::MemoryLimitExceeded)));
    }

    #[test]
    fn test_path_traversal_prevention() {
        let fs_handler = FileSystemHandler::new("/sandbox");
        
        let result = fs_handler.read("../../../etc/passwd");
        
        assert!(matches!(result, Err(FsError::PathTraversal)));
    }
}
```

## Test Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit | `src/**/*.rs` | Individual function testing |
| Integration | `tests/integration/` | Component interaction |
| E2E | `tests/e2e/` | Complete workflow testing |
| Benchmark | `benches/` | Performance measurement |
| Property | Various | Invariant verification |
| Adversarial | `tests/adversarial/` | Security testing |
| Python | `python/tests/` | SDK testing |

## Guardrails

### DO
- Test both success and failure paths
- Use descriptive test names that explain the scenario
- Include setup and teardown for resources
- Test edge cases and boundary conditions
- Use `#[ignore]` for long-running tests with explanation
- Mock external dependencies
- Test concurrent access patterns
- Verify audit logs are created correctly

### DON'T
- Test implementation details (test behavior)
- Use hardcoded paths that won't work on CI
- Leave flaky tests without `#[ignore]`
- Skip testing error conditions
- Use `thread::sleep` instead of proper synchronization
- Test private functions directly (test through public API)
- Ignore test failures by commenting them out

### Coverage Requirements
- Minimum 80% line coverage for new code
- 100% coverage for security-critical paths
- All public API functions must have tests
- All error variants must be tested

## Test Fixtures

```rust
// tests/common/mod.rs

pub struct TestKernel {
    pub kernel: Arc<VakKernel>,
    pub temp_dir: tempfile::TempDir,
}

impl TestKernel {
    pub async fn new() -> Self {
        let temp_dir = tempfile::tempdir().unwrap();
        let config = KernelConfig::test_config(temp_dir.path());
        let kernel = Arc::new(VakKernel::new(config).await.unwrap());
        Self { kernel, temp_dir }
    }

    pub async fn register_agent(&self, name: &str) -> AgentId {
        let config = AgentConfig::test_config(name);
        self.kernel.register_agent(config).await.unwrap()
    }
}

impl Drop for TestKernel {
    fn drop(&mut self) {
        // Cleanup happens automatically via temp_dir
    }
}
```

## Related Agents
- [Rust Code Generator Agent](Rust Code Generator Agent.agent.md)
- [CI/CD Agent](CI_CD Agent.agent.md)