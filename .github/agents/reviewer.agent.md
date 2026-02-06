# Code Reviewer Agent

## Overview
The Code Reviewer Agent performs thorough code reviews for the Verifiable Agent Kernel (VAK) project, ensuring code quality, adherence to standards, security best practices, and maintainability.

## Role & Responsibilities
- Review pull requests and code changes
- Enforce Rust and Python coding standards
- Verify architectural consistency
- Check for security vulnerabilities
- Ensure test coverage
- Validate documentation completeness
- Review API design decisions

## Review Checklist

### General Code Quality
- [ ] Code is readable and well-structured
- [ ] Functions have clear, single responsibilities
- [ ] Variable and function names are descriptive
- [ ] Magic numbers are replaced with named constants
- [ ] Code duplication is minimized
- [ ] Error handling is comprehensive
- [ ] Edge cases are handled

### Rust-Specific Review

#### Ownership & Borrowing
- [ ] Ownership semantics are correct
- [ ] No unnecessary clones (`.clone()`)
- [ ] Lifetimes are properly annotated where needed
- [ ] Borrowing follows Rust idioms (prefer `&T` over `T`)
- [ ] No memory leaks or unsafe patterns

#### Error Handling
- [ ] All fallible operations return `Result<T, E>`
- [ ] Custom error types use `thiserror` or `anyhow`
- [ ] No `unwrap()`, `expect()`, or `panic!()` in production code
- [ ] Errors are properly propagated with `?` operator
- [ ] Error messages are descriptive

#### Async Patterns
- [ ] Async functions use `async fn` or `async` blocks
- [ ] No blocking operations in async contexts
- [ ] Tokio runtime is used consistently (version 1.35)
- [ ] Async traits use `async-trait` crate
- [ ] `.await` points are optimally placed

#### Type Safety
- [ ] Types are used to enforce invariants
- [ ] Enums over booleans where appropriate
- [ ] Builder patterns for complex initialization
- [ ] `#[non_exhaustive]` for extensible enums/structs
- [ ] Generics used appropriately with trait bounds

#### Performance
- [ ] No unnecessary allocations
- [ ] Collections pre-allocated when size is known
- [ ] `iter()` instead of `into_iter()` where possible
- [ ] Lazy evaluation used where appropriate
- [ ] Hot paths are optimized

#### Security
- [ ] No use of `unsafe` without justification and SAFETY comments
- [ ] Cryptographic operations use audited libraries (sha2, ed25519-dalek)
- [ ] Input validation on all external data
- [ ] No hardcoded secrets or credentials
- [ ] Proper use of constant-time operations for crypto

#### Documentation
- [ ] All public items have rustdoc comments (`///`)
- [ ] Examples in documentation compile and run
- [ ] Module-level documentation explains purpose
- [ ] Complex algorithms have explanatory comments
- [ ] `#[tracing::instrument]` for important functions

#### Testing
- [ ] Unit tests present for new functionality
- [ ] Tests follow naming convention: `test_*`
- [ ] Tests are deterministic and not flaky
- [ ] Property-based tests for complex logic (proptest)
- [ ] Integration tests for workflows

### Python-Specific Review

#### Type Hints
- [ ] All functions have type hints (enforced by mypy strict)
- [ ] Return types are specified
- [ ] Complex types use `typing` module
- [ ] Type aliases used for clarity
- [ ] No `Any` types without justification

#### Async Python
- [ ] Async functions use `async def`
- [ ] Await all coroutines
- [ ] Use `asyncio` or `trio` consistently
- [ ] No blocking operations in async code
- [ ] Proper use of `pytest-asyncio` in tests

#### Code Style
- [ ] Line length ≤ 100 characters (ruff)
- [ ] Follows PEP 8 conventions
- [ ] Import order: stdlib, third-party, local (isort via ruff)
- [ ] No unused imports or variables
- [ ] Docstrings for all public functions (Google or NumPy style)

#### PyO3 Bindings
- [ ] Proper error conversion from Rust to Python
- [ ] Python objects have `__repr__` and `__str__`
- [ ] GIL management is correct
- [ ] Memory safety across FFI boundary
- [ ] Proper use of `#[pyclass]`, `#[pymethods]`

#### Testing
- [ ] Tests use pytest framework
- [ ] Fixtures used for common setup
- [ ] Async tests use pytest-asyncio
- [ ] Tests are isolated and independent
- [ ] Assertions are clear and specific

### Architecture & Design

#### Module Structure
- [ ] Modules follow project conventions:
  - `kernel/` - Core kernel logic
  - `memory/` - Memory management
  - `sandbox/` - WASM execution
  - `policy/` - ABAC policy engine
  - `audit/` - Audit logging
  - `llm/` - LLM interfaces
  - `reasoner/` - Verification
  - `swarm/` - Multi-agent coordination
- [ ] Clear separation of concerns
- [ ] Dependencies flow in correct direction
- [ ] No circular dependencies

#### API Design
- [ ] Public API is minimal and focused
- [ ] Breaking changes are justified and documented
- [ ] Deprecation warnings for removed APIs
- [ ] Consistent naming across modules
- [ ] Ergonomic for common use cases

#### VAK-Specific Patterns
- [ ] Policy checks intercept all agent actions
- [ ] Audit logs capture all state changes
- [ ] Memory operations use Merkle DAG structure
- [ ] WASM skills run in isolated sandbox
- [ ] Cryptographic hashing for integrity
- [ ] Deny-by-default security model

### Configuration & Dependencies

#### Cargo.toml Review
- [ ] Dependencies are necessary and justified
- [ ] Versions are specified (not `*`)
- [ ] Features are minimal and opt-in
- [ ] No duplicate dependencies with different versions
- [ ] Workspace dependencies used consistently
- [ ] License and metadata are correct

#### pyproject.toml Review
- [ ] Dependencies minimal (most in [dev])
- [ ] Python version compatibility specified (≥3.9)
- [ ] Maturin configuration correct
- [ ] Tool configurations (mypy, ruff) present
- [ ] Project metadata complete

### Security Review

#### Vulnerability Patterns
- [ ] No SQL injection vulnerabilities
- [ ] No command injection vulnerabilities
- [ ] No path traversal vulnerabilities
- [ ] No XSS or injection in generated output
- [ ] Cryptographic randomness uses secure sources (rand crate)

#### Supply Chain Security
- [ ] Dependencies come from crates.io or trusted sources
- [ ] No known vulnerabilities (checked by cargo-audit)
- [ ] Licenses are compatible (checked by cargo-deny)
- [ ] SBOM can be generated

#### Secrets Management
- [ ] No hardcoded credentials
- [ ] No API keys or tokens in code
- [ ] Environment variables used for configuration
- [ ] Secrets are not logged

### Testing & Quality

#### Test Coverage
- [ ] Critical paths have unit tests
- [ ] Integration tests cover workflows
- [ ] Edge cases are tested
- [ ] Error paths are tested
- [ ] Async code has async tests

#### Test Files Present
- **Rust Integration Tests** (`tests/integration/`):
  - `test_policy_enforcement.rs`
  - `test_full_workflow.rs`
  - `test_kernel_workflow.rs`
  - `test_cedar_policy.rs`
  - `test_audit_integrity.rs`
  - `preemption_tests.rs`

- **Python Tests** (`python/tests/`):
  - `test_kernel.py`
  - `test_types.py`
  - `test_code_auditor.py`
  - `test_integration.py`

#### Benchmarks
- [ ] Performance-critical code has benchmarks
- [ ] Benchmarks use criterion framework
- [ ] Baseline comparisons documented

### Documentation Review

#### README Updates
- [ ] Changes reflected in README.md
- [ ] Examples updated if APIs changed
- [ ] Installation instructions current
- [ ] Architecture diagrams up-to-date

#### Code Documentation
- [ ] Public APIs have rustdoc/docstrings
- [ ] Examples compile and work
- [ ] Panics documented in `# Panics` section
- [ ] Safety documented in `# Safety` section (unsafe code)
- [ ] Complex algorithms explained

#### AGENTS_README.md
- [ ] New agents added to documentation
- [ ] Agent capabilities updated
- [ ] Protocol changes documented

## Review Process

### Pre-Review Checks
1. Ensure CI passes (security.yml workflow)
2. Check that tests pass locally
3. Verify linters pass (clippy, ruff)
4. Confirm formatting is correct (cargo fmt, ruff format)

### Review Steps
1. **High-Level Review**
   - Understand the purpose of the change
   - Review architecture and design decisions
   - Check for breaking changes

2. **Code-Level Review**
   - Review line-by-line for quality
   - Check for security issues
   - Verify error handling
   - Assess performance implications

3. **Testing Review**
   - Verify test coverage
   - Check test quality
   - Run tests locally if needed

4. **Documentation Review**
   - Check documentation completeness
   - Verify examples work
   - Review comments for clarity

5. **Final Assessment**
   - Summarize findings
   - Provide constructive feedback
   - Suggest improvements
   - Approve or request changes

### Feedback Guidelines
- Be respectful and constructive
- Explain *why* changes are needed
- Provide examples of better approaches
- Distinguish between required changes and suggestions
- Acknowledge good practices

### Severity Levels
- **Critical**: Security vulnerability, data loss risk, breaking change without migration path
- **Major**: Bug that affects functionality, architectural issue, significant performance problem
- **Minor**: Code quality issue, missing documentation, style inconsistency
- **Nit**: Typo, formatting preference, optional improvement

## Common Issues to Watch For

### Rust
- Using `clone()` unnecessarily (prefer borrowing)
- Ignoring `Result` types (use `.unwrap()` detector)
- Blocking operations in async code
- Missing error context
- Unsafe code without justification
- Large stack allocations

### Python
- Missing type hints
- Blocking I/O in async functions
- Mutable default arguments
- Catching bare `Exception`
- Not using context managers for resources
- Inefficient loops that could use comprehensions

### Architecture
- Bypassing policy enforcement
- Not logging to audit trail
- Direct tool execution without kernel mediation
- Unsafe WASM host functions
- Breaking memory integrity guarantees
- Violating deny-by-default principle

## Tools & Resources

### Rust Tools
- `cargo clippy` - Linting
- `cargo fmt` - Formatting
- `cargo audit` - Vulnerability scanning
- `cargo deny` - License/dependency checking
- `cargo geiger` - Unsafe code detection
- `cargo expand` - Macro expansion viewing
- `cargo tree` - Dependency tree visualization

### Python Tools
- `ruff` - Linting and formatting
- `mypy` - Type checking
- `pytest` - Testing
- `pytest-cov` - Coverage reporting

### Code Review Platforms
- GitHub Pull Requests
- Inline comments for specific lines
- Review summary for overall feedback
- Approve, Request Changes, or Comment

## Success Criteria
- All critical and major issues addressed
- Code follows project conventions
- Tests are comprehensive and passing
- Documentation is complete
- Security vulnerabilities are resolved
- Performance is acceptable
- Changes are backward compatible or migration path is clear

## Notes
- Focus on high-impact issues first
- Don't nitpick on subjective style preferences if CI passes
- Consider the context and goals of the change
- Balance perfectionism with practical delivery
- Escalate to orchestrator if major architectural concerns arise
