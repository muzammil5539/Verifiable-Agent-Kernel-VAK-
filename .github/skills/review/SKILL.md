---
name: review-code
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
-   [ ] **Unsafe Code**: Is `unsafe` justified and documented with `// SAFETY:`?
-   [ ] **Async**: No blocking calls in `async fn`. Correct use of `tokio`.
-   [ ] **Clippy**: Does `cargo clippy` pass without warnings?
-   [ ] **Format**: Is the code formatted with `cargo fmt`?

### Python Specific

-   [ ] **Type Hints**: Are type hints used (mypy strict)?
-   [ ] **Async**: Proper use of `async`/`await` and `asyncio`.
-   [ ] **PyO3**: Correct FFI boundaries and error conversion.
-   [ ] **Format**: Is the code formatted with `ruff format`?

## Architecture Guidelines

-   **Policy Enforcement**: All agent actions MUST go through the policy engine.
-   **Audit Logging**: Critical actions MUST be logged to the immutable audit log.
-   **WASM Isolation**: Untrusted code MUST run in the WASM sandbox.
-   **Deny by Default**: Access control policies should deny by default.

## Examples

### Reviewing a Rust Function

Check for:
```rust
// Good
pub fn process_data(data: &[u8]) -> Result<processedData, Error> {
    if data.is_empty() {
        return Err(Error::EmptyInput);
    }
    // ...
}

// Bad
pub fn process_data(data: Vec<u8>) -> processedData {
    if data.is_empty() {
        panic!("Empty input!");
    }
    // ...
}
```

### Reviewing a Python Function

Check for:
```python
# Good
async def fetch_data(url: str) -> Optional[dict]:
    """Fetch data from URL."""
    # ...

# Bad
def fetch_data(url):
    # ...
```

## Security Audit

-   **Dependencies**: Check `Cargo.toml` / `pyproject.toml` for new dependencies.
-   **Vulnerabilities**: Run `cargo audit` to check for known vulnerabilities.
-   **Secrets**: Ensure no secrets are committed.

## Notes

-   **Be Constructive**: Focus on code improvement, not criticism.
-   **Explain Why**: Provide reasons for requested changes.
-   **Verify Locally**: Pull the branch and run tests if unsure.
