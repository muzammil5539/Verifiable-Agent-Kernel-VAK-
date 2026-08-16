# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

VAK (Verifiable Agent Kernel) is a Rust crate that acts as an OS-like "kernel" for AI agents: it sits between LLM-based agents and the external world, intercepting every tool call to enforce ABAC policy, log to a hash-chained audit trail, and (optionally) run untrusted tool code in a WASM sandbox. `#![deny(unsafe_code)]` applies crate-wide — all logic is safe Rust.

Full details: [ARCHITECTURE.md](ARCHITECTURE.md) (module reference, data flow, deployment) and [API.md](API.md) (API reference). Read these before making non-trivial changes — they are kept current and this file intentionally does not duplicate them.

## Common commands

```bash
# Build
cargo build --release              # release build
cargo build                        # debug build
make skills                        # build all WASM skill crates (workspace members)

# Test
cargo test                                          # all Rust tests
cargo test --lib                                     # unit tests only (fast)
cargo test --test '*' --verbose                      # integration tests only
cargo test <test_name>                                # run a single test by name (substring match)
cargo test --package vak --lib policy                 # tests in one module
cargo test --test integration_root test_stress -- --test-threads=1  # stress tests
PROPTEST_CASES=512 cargo test --test property_tests   # property-based tests, extended cases
python -m pytest python/tests/ -v                     # Python SDK tests
cargo bench                                           # benchmarks (Criterion)

# Lint / format
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo clippy -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic  # security-focused

# Coverage
cargo tarpaulin --config tarpaulin.toml --out Html --out Xml --output-dir coverage/
cargo tarpaulin --config tarpaulin.toml --fail-under 80   # CI gate, 80% minimum

# Security
cargo audit --deny warnings
cargo deny check

# Makefile shortcuts (mirrors the above)
make lint / make test / make test-all / make coverage-check / make security / make perf
```

Building the Python SDK locally uses `maturin` (`pip install -e ./python` or `make python`), driven by `pyproject.toml`'s `[tool.maturin]` config (feature `python`, module `vak._vak_native`).

## Architecture (essentials)

VAK is a Cargo workspace: the root crate (`vak`) plus WASM skill crates under `.github/skills/*` (`calculator`, `crypto-hasher`, `json-validator`, `text-analyzer`, `regex-matcher`) as workspace members. Build skills with `cargo build -p <skill> --target wasm32-unknown-unknown --release`.

Request lifecycle: `ToolRequest` → rate limiter → policy engine (ABAC, default-deny) → audit logger (hash-chained, logged before execution) → dispatcher (built-in handler or WASM sandbox) → `ToolResponse`. High-stakes actions additionally route through the neuro-symbolic reasoner (PRM score → Datalog safety rules → Z3 formal verification) before approval.

Core modules under `src/`:

| Module | Responsibility |
|---|---|
| `kernel/` | Orchestration: `Kernel` struct, request dispatch, `AgentId`/`SessionId`/`AuditId` (UUIDv7), `PolicyDecision`, rate limiting, constitution (immutable safety principles enforced pre-policy/pre-execution/post-execution) |
| `policy/` | ABAC engine — Cedar-style YAML rules, hot-reload via `arc-swap`, conflict analysis |
| `audit/` | Hash-chained (SHA-256) audit log, Ed25519 signing, flight recorder (shadow mode), replay, S3/multi-region backends |
| `memory/` | Three-tier memory: working (hot) / episodic (warm, Merkle chain via `rs_merkle`) / semantic (cold, knowledge graph + vector store); time-travel rollback by hash |
| `sandbox/` | WASM execution (Wasmtime 41.x), fuel metering, epoch-based preemption, pooling allocator, skill registry/marketplace, verified publishers |
| `reasoner/` | PRM scoring, Datalog safety rules, Z3 SMT verification, MCTS tree-of-thoughts, ZK proofs, prompt-injection detection, PRM fine-tuning toolkit |
| `llm/` | Provider-agnostic `LlmProvider` trait; LiteLLM client, mock provider for tests |
| `swarm/` | Multi-agent A2A protocol, quadratic voting, consensus, sycophancy detection |
| `integrations/` | LangChain / AutoGPT adapters, MCP JSON-RPC server |
| `dashboard/` | HTTP metrics/health endpoints |
| `lib_integration.rs` | High-level `VakRuntime`/`VakAgent` builder API for embedding VAK in apps |
| `secrets.rs` | Pluggable `SecretsProvider` (env/file/in-memory) with caching and rotation |
| `python.rs` | PyO3 bindings, feature-gated behind `python` |

Any tool name not matching a built-in (`echo`, `calculator`, `data_processor`, `system_info`) dispatches to the WASM skill registry.

## Key invariants (do not violate silently)

- **Default deny**: no matching policy rule = inadmissible. Never make an action fall through to allow.
- **Audit before execution**: the audit logger records the decision before the tool runs, not after.
- **WASM isolation**: untrusted/skill code must run inside the sandbox, never inline in the kernel.
- **Panic boundary**: host functions catch panics at the WASM/host boundary; the kernel must never crash from sandboxed code.
- **No `unsafe`**: crate-wide `#![deny(unsafe_code)]`. Don't introduce `unwrap()`/`expect()`/`panic!()` in production paths — this is enforced by the security-focused clippy lint set.

## Policies and configuration

Example ABAC policies live under `policies/` (`admin/`, `data/`, `finance/`, `tests/`) as YAML with `id`, `effect`, `patterns` (actions/resources with glob support), `conditions` (operators: `Equals`, `NotEquals`, `LessThan`, `GreaterThan`, `In`, `Contains`, `StartsWith`, `EndsWith`, `Matches`), and `priority`. Agent definitions (dev-time code-gen agents vs. runtime enforcement agents) live under `agents/`; system instructions under `instructions/`; prompt templates under `prompts/`; protocol schemas under `protocols/`.

## Testing conventions

Unit tests live in `#[cfg(test)] mod tests` next to the code; integration tests live in `tests/integration/`; property tests in `tests/property_tests.rs`. New code needs tests and should hold the 80% coverage floor enforced by `make coverage-check`. Rust commits should follow Conventional Commits (`feat(scope): ...`, `fix(scope): ...`, etc. — see [CONTRIBUTING.md](CONTRIBUTING.md)).
