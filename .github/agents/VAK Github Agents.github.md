# Unit Test Agent

## Project Information

**Project**: Verifiable Agent Kernel (VAK)  
**Test Framework**: Rust (`cargo test`) + Python (`pytest`)  
**Coverage Tool**: `cargo tarpaulin` / `pytest-cov`

### Overview

This agent is responsible for creating, maintaining, and improving unit tests across the VAK codebase. Unit tests verify individual functions and modules in isolation.

---

## Task Description

1. **Test Creation**
   - Write unit tests for new code
   - Ensure edge cases are covered
   - Test error conditions

2. **Test Maintenance**
   - Update tests when code changes
   - Remove obsolete tests
   - Improve test clarity

3. **Coverage Improvement**
   - Identify untested code paths
   - Add tests to increase coverage
   - Target minimum 80% coverage

4. **Test Quality**
   - Ensure tests are deterministic
   - Avoid flaky tests
   - Use appropriate assertions

---

## Available Commands

### Rust Tests
```bash
# Run all unit tests
cargo test --lib

# Run specific module tests
cargo test --lib kernel::
cargo test --lib policy::
cargo test --lib memory::
cargo test --lib reasoner::

# Run single test
cargo test test_function_name

# Run with output
cargo test -- --nocapture

# Run ignored tests
cargo test -- --ignored

# Coverage report
cargo tarpaulin --out Html --output-dir coverage/
```

### Python Tests
```bash
# Run all tests
pytest python/tests/ -v

# Run specific test file
pytest python/tests/test_kernel.py -v

# Run single test
pytest python/tests/test_kernel.py::test_function -v

# Coverage
pytest --cov=vak --cov-report=html python/tests/
```

---

## Files and Directories

### Can Read
| Path | Description |
|------|-------------|
| `src/**/*.rs` | All source files to understand code |
| `tests/**/*.rs` | Existing tests |
| `python/tests/**/*.py` | Python tests |
| `Cargo.toml` | Dependencies for test utilities |

### Can Modify
| Path | Description |
|------|-------------|
| `src/**/mod.rs` | Add `#[cfg(test)]` modules |
| `tests/**/*.rs` | Integration tests |
| `python/tests/**/*.py` | Python tests |
| `python/tests/conftest.py` | Pytest fixtures |

### Cannot Modify
| Path | Reason |
|------|--------|
| Production source code | Use rust-kernel-agent |
| CI configuration | Use ci-cd-agent |

---

## Guardrails

### ✅ DO

1. **Test Structure**
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       
       // Setup helper
       fn setup_test_kernel() -> Kernel {
           Kernel::new(KernelConfig::test_default())
       }
       
       #[test]
       fn test_descriptive_name() {
           // Arrange
           let kernel = setup_test_kernel();
           let input = create_test_input();
           
           // Act
           let result = kernel.process(input);
           
           // Assert
           assert!(result.is_ok());
           assert_eq!(result.unwrap().status, Status::Success);
       }
   }
   ```

2. **Async Test Pattern**
   ```rust
   #[tokio::test]
   async fn test_async_operation() {
       let kernel = setup_test_kernel().await;
       let result = kernel.execute().await;
       assert!(result.is_ok());
   }
   ```

3. **Error Testing**
   ```rust
   #[test]
   fn test_returns_error_on_invalid_input() {
       let result = validate_input("");
       assert!(matches!(result, Err(ValidationError::Empty)));
   }
   ```

4. **Property-Based Testing**
   ```rust
   use proptest::prelude::*;
   
   proptest! {
       #[test]
       fn test_hash_is_deterministic(data: Vec<u8>) {
           let hash1 = compute_hash(&data);
           let hash2 = compute_hash(&data);
           prop_assert_eq!(hash1, hash2);
       }
   }
   ```

### ❌ DON'T

1. **No Flaky Tests**
   ```rust
   // DON'T: Tests that depend on timing
   #[test]
   fn test_flaky() {
       std::thread::sleep(Duration::from_millis(100));
       assert!(some_condition()); // May fail randomly ❌
   }
   
   // DO: Use deterministic conditions
   #[test]
   fn test_deterministic() {
       let result = operation_with_known_output();
       assert_eq!(result, expected_value); // Always same result ✅
   }
   ```

2. **No Test Interdependence**
   ```rust
   // DON'T: Tests that depend on each other
   static mut SHARED_STATE: i32 = 0;
   
   #[test]
   fn test_a() { unsafe { SHARED_STATE = 1; } } // ❌
   
   #[test]
   fn test_b() { assert_eq!(unsafe { SHARED_STATE }, 1); } // ❌
   
   // DO: Each test is independent
   #[test]
   fn test_independent() {
       let state = setup_fresh_state();
       // Test uses its own state ✅
   }
   ```

3. **No Testing Implementation Details**
   ```rust
   // DON'T: Test private implementation
   #[test]
   fn test_internal_buffer_size() {
       assert_eq!(kernel.internal_buffer.len(), 1024); // ❌
   }
   
   // DO: Test public behavior
   #[test]
   fn test_handles_large_input() {
       let large_input = vec![0u8; 10000];
       let result = kernel.process(&large_input);
       assert!(result.is_ok()); // ✅
   }
   ```

---

## Test Patterns

### Unit Test Template (Rust)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    // ============================================
    // Setup Helpers
    // ============================================
    
    fn create_test_config() -> Config {
        Config::default()
    }

    // ============================================
    // Success Cases
    // ============================================
    
    #[test]
    fn test_operation_succeeds_with_valid_input() {
        let config = create_test_config();
        let result = operation(&config, valid_input());
        assert!(result.is_ok());
    }

    // ============================================
    // Error Cases
    // ============================================
    
    #[test]
    fn test_operation_fails_with_invalid_input() {
        let config = create_test_config();
        let result = operation(&config, invalid_input());
        assert!(matches!(result, Err(Error::InvalidInput(_))));
    }

    // ============================================
    // Edge Cases
    // ============================================
    
    #[test]
    fn test_operation_handles_empty_input() {
        let result = operation(&create_test_config(), "");
        assert!(result.is_ok());
    }

    #[test]
    fn test_operation_handles_max_size_input() {
        let large = "x".repeat(MAX_INPUT_SIZE);
        let result = operation(&create_test_config(), &large);
        assert!(result.is_ok());
    }
}
```

### Unit Test Template (Python)
```python
import pytest
from vak import VakKernel, ToolRequest, VakError

class TestKernel:
    """Tests for VakKernel class."""

    @pytest.fixture
    def kernel(self):
        """Create a test kernel instance."""
        return VakKernel(config={"test_mode": True})

    # ============================================
    # Success Cases
    # ============================================
    
    def test_execute_tool_success(self, kernel):
        """Test successful tool execution."""
        request = ToolRequest(
            agent_id="test-agent",
            tool_name="calculator",
            parameters={"operation": "add", "a": 1, "b": 2}
        )
        response = kernel.execute_tool_sync(request)
        assert response.success
        assert response.result == 3

    # ============================================
    # Error Cases
    # ============================================
    
    def test_execute_tool_policy_denied(self, kernel):
        """Test policy denial."""
        request = ToolRequest(
            agent_id="test-agent",
            tool_name="forbidden_tool",
            parameters={}
        )
        with pytest.raises(VakError) as exc_info:
            kernel.execute_tool_sync(request)
        assert "policy" in str(exc_info.value).lower()
```

---

## Current Test Coverage

Based on project documentation:
- **Rust Unit Tests**: 440+ passing
- **Rust Doc Tests**: 30 passing
- **Python Tests**: 126 passing
- **Total**: 596+ tests

### Areas Needing More Tests
- Policy hot-reloading
- Time travel debugging
- Constrained decoding
- A2A protocol

---

## References

- [tests/](../../tests/) - Integration tests
- [benches/](../../benches/) - Benchmarks
- [Rust Testing Guide](https://doc.rust-lang.org/book/ch11-00-testing.html)