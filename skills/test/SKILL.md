---
name: run-tests
description: Run the VAK test suite including unit tests, integration tests, property-based tests, and benchmarks.
---

# Run Tests

This skill provides instructions for running tests to verify the correctness and performance of the VAK project.

## Test Components

1.  **Rust Unit Tests**: Inline `#[test]` in `src/`.
2.  **Rust Integration Tests**: `tests/integration/`.
3.  **Python Tests**: `python/tests/`.
4.  **Property Tests**: `proptest` based tests.
5.  **Benchmarks**: `benches/`.

## Prerequisites

-   Rust 1.75+
-   Python 3.9+
-   `cargo-nextest` (optional, for faster execution)
-   `pytest` (`pip install pytest pytest-asyncio pytest-cov`)
-   `cargo-tarpaulin` (`cargo install cargo-tarpaulin`)

## Instructions

### Run Rust Tests

To run all Rust tests:

```bash
cargo test
```

To run specific integration tests:

```bash
cargo test --test integration_test_name
```

To run property-based tests (usually long-running):

```bash
cargo test --release prop_
```

### Run Python Tests

To run Python tests:

```bash
pytest python/tests/
```

### Run Benchmarks

To run benchmarks:

```bash
cargo bench
```

### Coverage Reports

To generate coverage reports:

```bash
# Rust coverage
cargo tarpaulin --out Html --output-dir coverage/

# Python coverage
pytest --cov=vak --cov-report=html python/tests/
```

## Examples

### Run Fast Tests Only
To run unit tests quickly without integration tests:

```bash
cargo test --lib
```

### Run Specific Test Case
To run a specific test function:

```bash
cargo test test_function_name
```

### Run Python Integration Tests
To run only the Python integration tests:

```bash
pytest python/tests/test_integration.py
```

## Guidelines

-   **Run tests before committing**: Ensure `cargo test` and `pytest` pass.
-   **Use `--release` for property tests**: Property tests can be slow in debug mode.
-   **Check coverage**: Aim for >80% coverage on new code.
-   **Fix flaky tests**: If a test fails intermittently, investigate immediately.
