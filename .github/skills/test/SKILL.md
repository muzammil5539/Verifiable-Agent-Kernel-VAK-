---
name: test
description: Run the VAK test suite including unit tests, integration tests, property-based tests, and benchmarks.
---

# Run Tests

This skill provides instructions for running tests to verify the correctness and performance of the VAK project.

## Test Implementation Status

| ID | Feature | Status | Notes |
|----|---------|--------|-------|
| TST-001 | Infinite Loop Preemption Tests | 🟡 Partial | Basic tests in `preemption_tests.rs` |
| TST-002 | Memory Containment Tests | ⏳ Pending | Pooling allocator ready |
| TST-003 | Policy Verification Tests | 🟡 Partial | Cedar tests in `test_cedar_policy.rs` |
| TST-004 | Integration Test Coverage | ✅ Complete | Full workflow tests |
| TST-005 | Benchmark Suite Expansion | ⏳ Pending | Basic benchmarks exist |
| TST-006 | Python SDK Tests | ⏳ Pending | Foundation exists |

## Test Components

1.  **Rust Unit Tests**: Inline `#[test]` in `src/` modules
2.  **Rust Integration Tests**: `tests/integration/`
    - `mod.rs` - Test module setup
    - `preemption_tests.rs` - Epoch/timeout preemption (RT-006)
    - `test_audit_integrity.rs` - Audit chain verification
    - `test_cedar_policy.rs` - Cedar policy enforcement
    - `test_full_workflow.rs` - End-to-end workflows
    - `test_kernel_workflow.rs` - Kernel operations
    - `test_policy_enforcement.rs` - ABAC enforcement
3.  **Python Tests**: `python/tests/`
    - `test_kernel.py` - Kernel bindings
    - `test_types.py` - Type conversions
    - `test_integration.py` - Python integration
    - `test_code_auditor.py` - Code auditor tests
4.  **Property Tests**: `proptest` based tests (run with `--release`)
5.  **Benchmarks**: `benches/`
    - `kernel_benchmarks.rs` - Kernel performance
    - `audit_benchmarks.rs` - Audit logging performance

## Prerequisites

-   Rust 1.75+
-   Python 3.9+
-   `cargo-nextest` (optional, for faster execution): `cargo install cargo-nextest`
-   `pytest` (`pip install pytest pytest-asyncio pytest-cov`)
-   `cargo-tarpaulin` (`cargo install cargo-tarpaulin`)

## Instructions

### Run All Rust Tests

```bash
cargo test
```

### Run Integration Tests Only

```bash
cargo test --test '*'
```

### Run Specific Integration Test File

```bash
# Policy enforcement tests
cargo test --test test_policy_enforcement

# Cedar policy tests
cargo test --test test_cedar_policy

# Preemption tests
cargo test --test preemption_tests

# Full workflow tests
cargo test --test test_full_workflow
```

### Run Property-Based Tests

Property tests are CPU-intensive; run in release mode:

```bash
cargo test --release prop_
```

### Run Python Tests

```bash
# All Python tests
pytest python/tests/

# Specific test file
pytest python/tests/test_kernel.py

# With verbose output
pytest python/tests/ -v
```

### Run Benchmarks

```bash
# All benchmarks
cargo bench

# Specific benchmark
cargo bench --bench kernel_benchmarks
cargo bench --bench audit_benchmarks
```

### Coverage Reports

```bash
# Rust coverage
cargo tarpaulin --out Html --output-dir coverage/

# Python coverage
pytest --cov=vak --cov-report=html python/tests/
```

## Test Categories

### Runtime/Sandbox Tests
- **Epoch preemption**: Verify timeout handling for infinite loops
- **Pooling allocator**: Memory limit enforcement
- **Panic safety**: Host function boundary protection
- **Async host**: Non-blocking I/O operations

### Policy Engine Tests
- **Cedar enforcement**: Default-deny behavior
- **Dynamic context**: Runtime attribute injection
- **Hot-reload**: Policy updates without restart

### Memory/Provenance Tests
- **Merkle DAG**: Content integrity verification
- **Time travel**: State snapshot and recovery
- **Receipts**: Cryptographic proof generation

### Neuro-Symbolic Tests
- **Datalog rules**: Safety constraint evaluation
- **PRM scoring**: Reasoning step validation
- **Constrained decoding**: Output format validation

## Examples

### Run Unit Tests Only (Fast)
```bash
cargo test --lib
```

### Run Specific Test Function
```bash
cargo test test_function_name
```

### Run Tests with Output
```bash
cargo test -- --nocapture
```

### Run Ignored Tests (Full WASM preemption)
```bash
cargo test -- --ignored
```

### Use cargo-nextest (Faster)
```bash
cargo nextest run
```

## Guidelines

-   **Run tests before committing**: Ensure `cargo test` and `pytest` pass.
-   **Use `--release` for property tests**: Property tests can be slow in debug mode.
-   **Check coverage**: Aim for >80% coverage on new code.
-   **Fix flaky tests**: If a test fails intermittently, investigate immediately.
-   **Integration tests**: New features should include integration tests.
-   **Security tests**: Security-critical features require dedicated test coverage.

## TODO: Missing Test Coverage

- [ ] TST-001: Comprehensive infinite loop patterns
- [ ] TST-002: Memory bomb attack simulation (50 agents x 4GB)
- [ ] TST-005: PRM scoring benchmarks, policy evaluation benchmarks
- [ ] TST-006: Full Python SDK coverage with error handling tests
