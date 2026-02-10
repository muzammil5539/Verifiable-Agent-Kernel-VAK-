# Contributing to VAK

Thank you for your interest in contributing to the Verifiable Agent Kernel (VAK). This guide explains how to get started, our coding standards, and the review process.

## Getting Started

### Prerequisites

- Rust 1.75+ (`rustup update stable`)
- `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- Python 3.9+ (for Python bindings, optional)
- `maturin` (`pip install maturin`, optional)

### Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Verifiable-Agent-Kernel-VAK-.git
   cd Verifiable-Agent-Kernel-VAK-
   ```
3. Build the project:
   ```bash
   cargo build --workspace
   ```
4. Run tests:
   ```bash
   cargo test
   ```

## Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```
2. Make changes following the code style guide below.
3. Add tests for new functionality (coverage > 80%).
4. Run the full check suite:
   ```bash
   cargo fmt --all
   cargo clippy --all-targets --all-features -- -D warnings
   cargo test
   ```
5. Commit with a descriptive message (see commit conventions below).
6. Push and create a pull request against `main`.

## Code Style

### Rust

- **Format**: Run `cargo fmt --all` before committing.
- **Lints**: Fix all `cargo clippy` warnings. Treat warnings as errors.
- **Documentation**: Add `///` doc comments to all public structs, enums, functions, and modules.
- **Error handling**: Use `Result` and `thiserror` for error types. Never use `unwrap()`, `expect()`, or `panic!()` in production code.
- **Unsafe code**: The project uses `#![deny(unsafe_code)]`. If `unsafe` is absolutely necessary, it must include a `// SAFETY:` comment explaining why it is safe.
- **Naming**: Follow Rust naming conventions (snake_case for functions/variables, CamelCase for types).

### Python

- Use type hints for all function signatures.
- Format with `ruff format`.
- Test with `pytest`.

## Commit Conventions

Use conventional commit messages:

```
type(scope): description

feat(policy): add Cedar-style policy hot-reloading
fix(audit): prevent hash chain corruption on concurrent writes
docs(readme): update architecture diagram
test(memory): add property-based tests for Merkle DAG
refactor(kernel): extract async pipeline into separate module
chore(deps): update wasmtime to 41.0.3
```

**Types**: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`

## Testing Requirements

- **Unit tests**: Required for all public functions. Place in `#[cfg(test)] mod tests` within the same file.
- **Integration tests**: Required for new workflows. Place in `tests/integration/`.
- **Doc tests**: Include runnable examples in rustdoc comments where practical.
- **Benchmarks**: Required for performance-sensitive code. Place in `benches/`.
- **Minimum coverage**: 80% on new code.

### Running Tests

```bash
# All Rust tests
cargo test

# Unit tests only (fast)
cargo test --lib

# Integration tests only
cargo test --test '*'

# Doc tests only
cargo test --doc

# Python tests
pytest python/tests/

# Benchmarks
cargo bench
```

## Architecture Overview

VAK follows a layered kernel architecture:

```
Agent Layer
    |
VAK Kernel (src/)
  +-- kernel/     Core orchestration, rate limiting
  +-- policy/     ABAC policy engine, Cedar enforcement
  +-- audit/      Hash-chained audit logging, flight recorder
  +-- memory/     Merkle DAG, time travel, vector store
  +-- reasoner/   Neuro-symbolic reasoning, Z3, PRM
  +-- sandbox/    WASM runtime, epoch ticker, pooling
  +-- swarm/      Multi-agent consensus, A2A protocol
  +-- dashboard/  Metrics, health checks, HTTP server
  +-- llm/        LLM provider abstractions
```

### Key Invariants

- **Policy Enforcement**: All agent actions must go through the policy engine.
- **Audit Logging**: Critical actions must be logged to the immutable audit log.
- **WASM Isolation**: Untrusted code must run in the WASM sandbox.
- **Deny by Default**: No policy = no access.
- **Panic Boundary**: Host functions catch panics at the WASM boundary.

## Pull Request Process

1. Ensure CI passes (build, test, clippy, fmt).
2. Update documentation if your change affects public APIs.
3. Update `TODO.md` if your change resolves a tracked task.
4. PRs require at least 1 approval before merging.
5. Squash or rebase commits for a clean history.

## Security

- Run `cargo audit` if you change dependencies.
- Run `cargo deny check` to verify license compliance.
- Never commit secrets, API keys, or credentials.
- Report security vulnerabilities via the issue tracker (private disclosure preferred).

## WASM Skills

Skills are WASM modules in `.github/skills/`. To create a new skill:

1. Create a new directory under `.github/skills/your-skill/`.
2. Add a `Cargo.toml` with `crate-type = ["cdylib"]` and workspace version.
3. Implement the skill in `src/lib.rs` following the existing patterns.
4. Add the skill to the workspace members list in the root `Cargo.toml`.
5. Build with: `cargo build -p your-skill --target wasm32-unknown-unknown --release`
6. Sign the skill before deployment (see `vak-skill-sign` tool).

## Questions?

Open an issue on GitHub for questions about contributing.
