# Quality Assurance (QA) Agent

## Overview
The QA Agent ensures the quality and reliability of the Verifiable Agent Kernel (VAK) project through comprehensive testing, validation, and quality metrics.

## Role & Responsibilities
- Execute comprehensive test suites (unit, integration, property-based)
- Perform regression testing
- Run performance benchmarks and track metrics
- Validate test coverage
- Conduct exploratory testing
- Verify bug fixes
- Test cross-platform compatibility
- Validate examples and documentation

## Testing Infrastructure

### Rust Testing Framework
- **Test Runner**: Built-in cargo test
- **Async Testing**: tokio-test
- **Property Testing**: proptest 1.4
- **Benchmarking**: criterion 0.5
- **Mocking**: mockall (if present)

### Python Testing Framework
- **Test Runner**: pytest >= 7.0
- **Async Testing**: pytest-asyncio >= 0.21
- **Coverage**: pytest-cov
- **Type Checking**: mypy >= 1.0 (strict mode)

## Test Organization

### Rust Tests

#### Unit Tests
- **Location**: Within source files (`#[cfg(test)] mod tests {}`)
- **Modules**: Throughout `src/` directory
- **Run**: `cargo test --lib`

#### Integration Tests
- **Location**: `tests/integration/`
- **Files**:
  1. `test_policy_enforcement.rs` - ABAC policy engine validation
  2. `test_full_workflow.rs` - End-to-end workflows
  3. `test_kernel_workflow.rs` - Kernel lifecycle and operations
  4. `test_cedar_policy.rs` - Policy language parsing and evaluation
  5. `test_audit_integrity.rs` - Audit log chain integrity
  6. `preemption_tests.rs` - Preemption and priority handling
- **Run**: `cargo test --test <test_name>`

#### Property-Based Tests
- **Framework**: proptest
- **Purpose**: Generate random test inputs to find edge cases
- **Usage**: Test invariants that should always hold
- **Run**: `cargo test prop_*` (convention)

#### Benchmark Tests
- **Location**: `benches/kernel_benchmarks.rs`
- **Framework**: criterion
- **Config**: `harness = false`
- **Run**: `cargo bench`
- **Metrics**: Throughput, latency, memory usage

### Python Tests

#### Test Files
- **Location**: `python/tests/`
- **Files**:
  1. `test_kernel.py` - Python kernel API
  2. `test_types.py` - Type system and serialization
  3. `test_code_auditor.py` - Code auditor functionality
  4. `test_integration.py` - Integration with Rust backend
- **Run**: `pytest python/tests/`

#### Test Configuration
```toml
[tool.pytest.ini_options]
testpaths = ["python/tests"]
```

## Test Execution Strategies

### Comprehensive Test Suite
```bash
# Run all Rust tests (unit + integration)
cargo test --all-features

# Run all Python tests
pytest python/tests/ -v

# Run both ecosystems
cargo test && pytest python/tests/
```

### Targeted Testing
```bash
# Run specific Rust integration test
cargo test --test test_policy_enforcement

# Run specific Python test file
pytest python/tests/test_kernel.py

# Run tests matching pattern
cargo test audit
pytest -k "test_audit"

# Run single test function
cargo test test_policy_enforcement::test_allow_action
pytest python/tests/test_kernel.py::test_kernel_init
```

### Verbose & Debug Testing
```bash
# Show output from tests
cargo test -- --nocapture

# Show verbose pytest output
pytest -vv -s python/tests/

# Run with logging
RUST_LOG=debug cargo test -- --nocapture

# Run with backtraces
RUST_BACKTRACE=1 cargo test
```

### Parallel & Sequential Testing
```bash
# Run tests in parallel (default)
cargo test

# Run tests sequentially
cargo test -- --test-threads=1

# Pytest parallel with pytest-xdist
pytest -n auto python/tests/
```

### Async Testing
```bash
# Rust async tests (tokio-test)
cargo test --features tokio

# Python async tests (pytest-asyncio)
pytest python/tests/test_integration.py -v
```

## Test Coverage

### Coverage Tools
```bash
# Install coverage tools
cargo install cargo-tarpaulin  # For Rust
pip install pytest-cov          # For Python

# Run Rust coverage
cargo tarpaulin --out Html --output-dir coverage/

# Run Python coverage
pytest --cov=vak --cov-report=html python/tests/
```

### Coverage Targets
- **Critical Modules**: 90%+ coverage
  - `src/kernel/`
  - `src/policy/`
  - `src/audit/`
  - `src/sandbox/`
- **Utility Modules**: 80%+ coverage
- **New Features**: 100% coverage for new code

## Performance Testing

### Benchmarks
```bash
# Run all benchmarks
cargo bench

# Run and save baseline
cargo bench -- --save-baseline main

# Compare against baseline
git checkout feature-branch
cargo bench -- --baseline main

# Generate benchmark report
cargo bench -- --noplot > benchmark_report.txt
```

### Performance Metrics
- **Kernel Operations**: < 1ms per operation
- **Policy Evaluation**: < 100μs per rule
- **Audit Logging**: < 500μs per entry
- **Memory Allocation**: Minimal allocations in hot path
- **WASM Execution**: < 10ms for typical skills

### Load Testing
```bash
# Concurrent agent testing
cargo test --release test_concurrent_agents

# High throughput testing
cargo bench bench_high_load
```

## Regression Testing

### Pre-Commit Testing
```bash
# Quick smoke tests
cargo test --lib
pytest python/tests/ -x  # Stop on first failure

# Format check
cargo fmt -- --check
ruff format --check python/
```

### Pre-Merge Testing
```bash
# Full test suite
cargo test --all-features
pytest python/tests/ -v

# Clippy lints
cargo clippy --all-targets --all-features -- -D warnings

# Python type checking
mypy python/vak/

# Security checks
cargo audit
cargo deny check
```

### Release Testing
```bash
# All tests with release optimizations
cargo test --release

# Benchmarks
cargo bench

# Examples verification
cargo run --example basic_agent
cargo run --example policy_demo
cargo run --example code_auditor_demo
python examples/python_quickstart.py

# Documentation tests
cargo test --doc

# Build all targets
cargo build --all-features --release
```

## Validation Checklist

### Functional Testing
- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Policy enforcement works correctly
- [ ] Audit logging captures all events
- [ ] Memory operations maintain integrity
- [ ] WASM sandbox isolates skills
- [ ] Multi-agent coordination functions
- [ ] Error handling is robust
- [ ] Edge cases are handled

### Security Testing
- [ ] Policy bypass attempts fail
- [ ] Audit tampering is detected
- [ ] Unsafe code is justified and reviewed
- [ ] Input validation prevents injection
- [ ] Cryptographic operations use secure primitives
- [ ] No hardcoded secrets
- [ ] Dependencies have no known vulnerabilities (cargo-audit)

### Performance Testing
- [ ] Benchmarks meet targets
- [ ] No performance regressions vs baseline
- [ ] Memory usage is acceptable
- [ ] No memory leaks
- [ ] Async operations are non-blocking
- [ ] Hot paths are optimized

### Compatibility Testing
- [ ] Rust 1.75+ compatibility
- [ ] Python 3.9, 3.10, 3.11, 3.12 compatibility
- [ ] Linux, macOS, Windows support
- [ ] x86_64, aarch64 architectures
- [ ] WASM32-WASI target builds

### Documentation Testing
- [ ] README examples work
- [ ] Rustdoc examples compile
- [ ] Python docstring examples run
- [ ] API documentation is accurate
- [ ] Migration guides are correct

## Test Quality Standards

### Test Characteristics
- **Isolated**: Tests don't depend on each other
- **Deterministic**: Same input → same output
- **Fast**: Unit tests < 1s, integration tests < 10s
- **Readable**: Clear test names and assertions
- **Maintainable**: Easy to update when code changes

### Test Naming Conventions

**Rust**:
```rust
#[test]
fn test_policy_enforcement_allows_permitted_action() { }

#[test]
fn test_policy_enforcement_denies_prohibited_action() { }

#[tokio::test]
async fn test_kernel_handles_concurrent_agents() { }
```

**Python**:
```python
def test_kernel_initialization():
def test_kernel_execute_tool():
async def test_async_kernel_operation():
```

### Assertion Best Practices
```rust
// Good: Specific assertion with context
assert_eq!(result.status, Status::Allowed, 
           "Expected policy to allow action for admin role");

// Bad: Generic assertion
assert!(result.is_ok());
```

## Continuous Testing

### Watch Mode
```bash
# Rust watch mode (requires cargo-watch)
cargo watch -x test

# Python watch mode (requires pytest-watch)
ptw python/tests/
```

### Pre-Push Hook
```bash
#!/bin/bash
# .git/hooks/pre-push
echo "Running tests before push..."
cargo test --all-features && pytest python/tests/
```

## Test Data Management

### Test Policies
- **Location**: `policies/tests/`
- **Files**:
  - `policy_test_cases.yaml` - Test policy definitions
  - `sample_constraints.yaml` - Constraint examples

### Test Fixtures
- **Python**: Use pytest fixtures in `conftest.py`
- **Rust**: Use setup functions or proptest strategies

### Mock Data
- Generate realistic test data
- Use property-based testing for randomized inputs
- Maintain test data versioning

## Failure Triage

### When Tests Fail

1. **Identify Scope**
   - Is it a single test or multiple?
   - Is it Rust or Python?
   - Is it unit, integration, or benchmark?

2. **Reproduce Locally**
   ```bash
   cargo test --test <test_name> -- --nocapture
   pytest python/tests/test_*.py -vv -s
   ```

3. **Analyze Logs**
   - Check error messages
   - Review stack traces
   - Enable debug logging

4. **Isolate Cause**
   - Run minimal reproduction
   - Check recent changes
   - Verify environment setup

5. **Report Issues**
   - Document reproduction steps
   - Include error logs
   - Note environment details

### Flaky Test Handling
- Run multiple times to confirm flakiness
- Add retry logic if appropriate
- Increase timeouts for async tests
- Improve test isolation
- Use deterministic seeds for randomness

## Quality Metrics

### Test Metrics
- Total test count: Track growth over time
- Test execution time: Monitor for slowdowns
- Flaky test rate: Should be < 1%
- Code coverage: Track per module
- Bug detection rate: Tests should catch bugs before release

### Code Quality Metrics
- Clippy warnings: Should be 0
- Unsafe code blocks: Minimize and justify
- Dependency vulnerabilities: Should be 0
- Documentation coverage: 100% for public APIs

## Tools & Commands

### Essential QA Tools
```bash
# Rust testing
cargo test              # Run tests
cargo bench            # Run benchmarks
cargo tarpaulin        # Coverage
cargo nextest run      # Alternative test runner (faster)

# Python testing
pytest                 # Run tests
pytest-cov             # Coverage
mypy                   # Type checking
pytest-xdist           # Parallel testing

# Quality checks
cargo clippy           # Linting
cargo fmt              # Formatting
cargo audit            # Vulnerability scanning
cargo deny             # License checking
cargo geiger           # Unsafe code detection
```

### CI/CD Integration
Tests are run automatically in GitHub Actions:
- **Workflow**: `.github/workflows/security.yml`
- **Triggers**: Push to main/develop, PRs, weekly schedule

## Success Criteria
- ✅ All tests pass
- ✅ No test regressions
- ✅ Coverage meets targets
- ✅ Benchmarks meet performance goals
- ✅ No flaky tests
- ✅ Security tests validate hardening
- ✅ Examples work as documented
- ✅ Cross-platform compatibility verified

## Notes
- Run full test suite before merging PRs
- Investigate and fix flaky tests immediately
- Keep tests fast - slow tests discourage frequent running
- Write tests first for bug fixes (TDD for regressions)
- Property-based tests are excellent for finding edge cases
- Benchmark against baselines to detect performance regressions
