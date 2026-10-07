# Changelog

All notable changes to the Verifiable Agent Kernel (VAK) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

See `docs/architecture-v2.md` for the audit and design behind these changes, and
`docs/adr/0002-reference-monitor-core-with-ports-and-transparency-log.md` and
`docs/adr/0003-admit-budget-record-outcome-pipeline-stages.md` for the decision records.

### Added
- The `cedar-analysis` feature (ADR 0009): `policy::cedar::analysis` (`Analyzer`,
  `PolicyProperties`, `AnalysisReport`, `check_reload`, `Widening`, `ReloadRefused`)
  proves properties of Cedar policy sets with SymCC and cvc5 1.3.1. `CedarPolicy::reload`
  and `reload_checked`. `examples/cedar_check.rs` runs the checks in CI.
  `policies/cedar/properties/` holds the default policies' properties.
- The `cedar` feature (ADR 0008; needs Rust 1.89): `policy::cedar` (`CedarPolicySet`,
  `CedarRequest`, `CedarDecision`, `CedarPolicyError`, `VAK_SCHEMA`) and
  `kernel::CedarPolicy`, a `PolicyDecisionPoint` over the `cedar-policy` crate. Selected
  with `policy.format: cedar` (`PolicyFormat`, `VAK_POLICY__FORMAT`), with
  `policy.cedar_schema` (`VAK_POLICY__CEDAR_SCHEMA`) for a schema of your own.
  `policies/cedar/` holds the kernel's schema, the default tool rules in Cedar, and a
  typed-arguments example.
- `kernel::DenyAll`: the decision point used when configured policies can't be loaded.
- `kernel::SqliteAuditLog` (ADR 0007): the kernel's audit log in SQLite, selected with
  `audit.format: sqlite` (`AuditLogFormat`, `VAK_AUDIT__FORMAT`). Each append is a
  durable transaction; opening verifies every row and refuses a database VAK didn't
  create. `AuditLogError::Format`.
- `audit::entry_hash` and `AuditReport::legacy_entries` (ADR 0007).
- Cargo features (ADR 0006): `wasm`, `llm`, `memory`, `reasoner`, `experimental-zk`,
  `swarm`, `integrations`, `dashboard`, `legacy-tools`, `python`, and `full` (everything
  but `python`). `default-features = false` builds the trusted core alone.
- `sandbox::signing` (ADR 0005): Ed25519 skill signatures over the module's SHA-256 and
  every manifest field except `wasm_path`, verified against trusted publisher keys.
  `SkillManifest::signed_by`, `SkillRegistry::module_digest`,
  `SandboxRuntime::prepare_file_pinned`, `SandboxError::ModuleChanged`,
  `AuditOutcome::module_sha256`, and `security.{skills_path, trusted_skill_keys,
  allow_unsigned_skills}`. `examples/sign_skill.rs` generates publisher keys and signs
  manifests.
- `sandbox::SandboxRuntime` (ADR 0004): one Wasmtime engine, a compiled-module cache
  keyed by SHA-256, and one epoch ticker that parks while idle. The kernel runs every
  WASM skill on it, on `tokio::task::spawn_blocking`. `KernelBuilder::{with_sandbox_runtime,
  with_skill_registry}`, `Kernel::sandbox_runtime`, `WasmSandbox::with_runtime`.
- Mediation pipeline stages (ADR 0003). `kernel::identity` (`AgentRegistry`,
  `AgentRecord`, `InMemoryAgentRegistry`) for the Admit stage, `kernel::budget`
  (`Budget`, `AgentRateBudget`, `Unlimited`) for the Budget stage, and
  `kernel::audit_log` (`AuditLog`, `MemoryAuditLog`, `FileAuditLog`) for the Record
  stages. Injected with `KernelBuilder::{with_agent_registry, with_budget,
  with_audit_log}`.
- `Kernel::register_agent`, `Kernel::end_session`, and
  `security.require_registered_agents`.
- Outcome leaves (`AuditEntry::outcome`, `AuditOutcome`) and receipts
  (`ToolResponse::receipt`, `AuditReceipt`).
- `KernelError::{AgentSuspended, SessionConflict, RateLimited, AuditUnavailable}`
  (E012 to E015). `PolicyRequest` gained `principal` and `session_id`.
- `audit::transparency`: RFC 9162 Merkle tree log with inclusion and consistency proofs,
  stand-alone verifiers, and Ed25519-signed tree heads. Tested against the Certificate
  Transparency reference vectors.
- `kernel::ports::PolicyDecisionPoint` and `Kernel::builder`, so embedders can inject a
  policy engine, host-side tool handlers (`with_tool`, `Kernel::register_tool`) and an
  audit signing key.
- `Kernel::audit_tree_head`, `prove_audit_inclusion`, `prove_audit_consistency` and
  `audit_leaf_hash`: any decision can be proven to a third party.
- `KernelError::AuditProof`, `HandlerError::AlreadyRegistered`,
  `CustomHandlerRegistry::{register_arc, register_new}`.

### Changed
- PyO3 0.29 (was 0.24), for RUSTSEC-2026-0176 and RUSTSEC-2026-0177 (finding K11). The
  native classes no longer derive `FromPyObject` (`skip_from_py_object`); nothing took
  them by value.
- **Toolchain:** the minimum supported Rust is 1.90, the highest among dependencies
  (Wasmtime 41); it was declared as 1.75, which nothing could build. CI tests stable
  and 1.90, and checks formatting and clippy on stable only. The metrics endpoint's
  `rust_version` and the Python module's `__rust_version__` come from
  `Cargo.toml` instead of a hardcoded "1.75".
- CI's clippy (`--all-targets --all-features -D warnings`, with `RUSTFLAGS=-D warnings`)
  passes: 24 lints from newer toolchains fixed, plus warnings that only show with some
  features off. The security clippy job (`unwrap_used`, `expect_used`, `panic`) checks
  production code, as CLAUDE.md describes, and passes. Its 96 hits are gone:
  - poisoned locks are recovered rather than unwrapped;
  - an empty plan and a missing "default" role in the neuro-symbolic pipeline no longer
    panic;
  - a missing CAS `base_path` is a configuration error;
  - constant regex patterns carry a scoped, commented `allow`.
- **Breaking:** `audit::streaming::WebhookSink::new` returns a `Result`; it panicked if
  the HTTP client couldn't be built.
- **Breaking:** `CedarPolicy::policies` returns the current set as an
  `Arc<CedarPolicySet>`. The policy loader refuses policies that carry `@property`
  (`CedarPolicyError::PropertyAsPolicy`).
- `policies/cedar/examples/payments.cedar` forbids restricted tools. SymCC showed that
  without it a finance agent could still call a blocked `transfer_funds`.
- `KernelError::PolicyViolation::policy_id` names the policies that denied, when the
  decision point reports them. It used to be `"default"` for every denial.
- **Breaking:** `AuditLogger::log` and `log_with_metadata` return
  `Result<&AuditEntry, AuditError>`. A write the backend refused used to be logged and
  returned as if stored; it is now an error, and the chain is left as it was.
- **Breaking:** `AuditLogger` entries use a version 2 hash: a domain tag and every field
  length-prefixed, `metadata` included (finding K7). Logs written before still verify
  if their version 1 entries come first; `AuditReport::legacy_entries` counts them.
- `serde_json` is built with `float_roundtrip`, so hashed JSON metadata reads back
  exactly.
- `audit.max_log_size_bytes` and `audit.retention_count` are documented as not applying
  to the kernel's log, which is never rotated.
- **Breaking:** default features are now `wasm` and `memory`. `reasoner`, `swarm`,
  `integrations`, `dashboard`, `api` and `tools` need their features (or `full`), and
  `reasoner::zk_proof` needs `experimental-zk`. `kernel::neurosymbolic_pipeline` and
  `sandbox::reasoning_host` need `reasoner`.
- `tools::skill_sign` is behind `legacy-tools`: its signatures don't cover permissions
  and the skill registry can't read them. Use `sandbox::signing`.
- **Breaking:** skill signatures are Ed25519 (`signed_by` + `signature`). The old unkeyed
  SHA-256 "signatures" no longer verify. `SkillSignatureVerifier::{compute_signature,
  sign_manifest}` and `SignatureVerificationResult` are removed; use
  `signing::sign_skill` and `VerifiedSkill`. `SignatureConfig::trusted_keys` now holds hex
  Ed25519 public keys and is enforced.
- **Behaviour change:** a skill loads only if its module file exists, and runs only with
  the module bytes it was verified with at load.
- **Behaviour change:** `security.enable_rate_limiting` and `max_requests_per_minute`
  are enforced (default 60 per agent per minute). They were previously ignored.
- **Behaviour change:** principals reach policy with `internal` from their agent
  record, not a constant `true`. Unregistered agents are not internal.
- **Behaviour change:** an executed call is recorded as two audit entries, a decision
  and an outcome. A session is bound to the first agent that uses it.
- `VakAgent`'s allowed and blocked tools are enforced by the kernel, and refusals are
  audited. `audit.log_path` selects a durable `FileAuditLog`; a log there that can't be
  opened or doesn't verify fails `Kernel::build`.
- **Breaking:** `Kernel::execute` on a permitted tool that doesn't exist now returns
  `Err(KernelError::ToolNotFound)`. It used to return `success: true` from a "default
  handler" that executed nothing.
- The allowlist and `CedarEnforcer` logic moved out of `Kernel` into `kernel::pdp`
  (`ConfigPolicy`, `EnforcerPolicy`). Behaviour is unchanged.
- `VakRuntime::builder()` settings (`with_audit_logging`, `with_policy_enforcement`,
  `with_sandboxing`, `with_default_timeout`) now reach `KernelConfig`.
- Memory Merkle tier hashes with SHA-256 over `(key, value)`, using the RFC 9162 tree
  shape. Proofs carry real sibling paths. `MerkleProof` gained `key` and `verify_for`.
- Z3 verifier: `Matches`, `Forbidden` and list values are rejected instead of being
  translated incorrectly.
- `lib.rs` status table states assurance levels instead of claiming an external audit.

### Fixed
- `memory::receipts`: a public key or signature of the wrong length fails
  verification. It used to be replaced with zero bytes, and an all-zero key is a
  small-order point that non-strict Ed25519 verification can be forged against.
- `test_signer_key_export_import` checks the imported key (same public key, same
  signatures); it used to assert nothing.
- A durable audit log (`FileAuditLog`) whose caller stopped waiting mid-append could
  store the entry without adding it to the tree. The next entry then linked to the
  wrong predecessor, and the log refused to open. Appends now run to completion
  (ADR 0007).
- `AuditLogger` rotation no longer breaks `verify_chain`, and no longer evicts entries
  it failed to archive.
- Skills were "signed" with an unkeyed hash anyone could recompute, over the module's path
  when the module was missing, and `trusted_keys` was never read (K4).
- WASM skills no longer block a Tokio worker for their whole runtime, and are no longer
  recompiled (with a new engine and a new watchdog thread) on every call (K3).
- A skill's output pointer and length are bounds-checked against guest memory as
  unsigned values. A negative length used to make the host panic while allocating the
  output buffer, unwinding through `Kernel::execute`.
- A WASM skill that hits its wall-clock limit fails with `KernelError::Timeout`, like a
  host handler, instead of a generic execution failure.
- `sandbox::async_host` fell back to an allow-everything enforcer when its policy
  enforcer couldn't be built. It now denies everything instead.
- WASM skills trapped on entry: epoch interruption was enabled with no deadline, and
  Wasmtime's default deadline is 0. A per-execution watchdog now enforces the wall-clock
  timeout, and traps are classified by trap code.
- SMT-LIB injection in the Z3 verifier: field names and string values were spliced into
  the solver script unescaped. Negative numbers were emitted as invalid `-n` literals.
- A panicking host tool handler no longer unwinds through `Kernel::execute`.

### Removed
- The unused `rs_merkle` dependency.
- `src/prelude.rs`, which was never compiled (`lib.rs` defines `prelude` inline) and
  referenced types that don't exist.

## [1.0.0] - 2026-02-13

### Added
- **v1.0 Milestone**: Production-ready release with full documentation
- **Production Deployment Guide** (`docs/production-deployment.md`): Comprehensive deployment reference covering Docker Compose, Kubernetes with Kustomize, and Helm chart deployments. Includes configuration reference, storage sizing guidelines, scaling strategies, monitoring setup, backup/recovery procedures, and a production readiness checklist.
- **Security Hardening Guide** (`docs/security-hardening.md`): Complete security best practices covering defense-in-depth layers, policy engine hardening, WASM sandbox security, audit log integrity, cryptographic configuration, container security, network security, secrets management, supply chain security, prompt injection protection, rate limiting, and compliance considerations.
- **Performance Tuning Guide** (`docs/performance-tuning.md`): Optimization reference with benchmarking procedures, kernel tuning parameters, policy engine optimization, WASM sandbox performance, audit logging optimization, memory system tuning, Python SDK performance tips, profiling tools, resource sizing formulas, and production monitoring guidance.
- **Troubleshooting Guide** (`docs/troubleshooting.md`): Diagnostic reference covering build issues, runtime errors, policy engine problems, WASM sandbox failures, audit log issues, memory system problems, Python SDK errors, Docker/Kubernetes issues, and performance debugging.
- **Migration Guide** (`docs/migration-guide.md`): Step-by-step upgrade instructions from v0.1, v0.2, and v0.3 to v1.0, covering configuration changes, API compatibility, Python SDK migration, Helm chart migration, and verification steps.

### Changed
- Bumped version to `1.0.0` across all artifacts (Cargo.toml workspace, Helm chart, Dockerfile labels)
- Updated README.md with v1.0 milestone completion, new documentation links, and production status badge
- Updated TODO.md with v1.0 completion status and Sprint 13 tracking
- Updated API.md version reference to v1.0.0
- Updated ARCHITECTURE.md Helm chart version reference
- Updated `.github/skills/README.md` version reference to v1.0
- Updated `examples/CODE_AUDITOR_README.md` status to v1.0

## [0.3.0] - 2026-02-13

### Added
- **v0.3 Milestone**: Full test coverage infrastructure, CI/CD pipeline, infrastructure tooling
- **TST-007**: Cross-module integration tests - comprehensive tests validating interactions between kernel subsystems (policy+audit, memory+audit, reasoner+policy, swarm+audit, end-to-end session lifecycle)
- **TST-008**: Stress & load testing suite - throughput tests (10K+ operations), concurrency stress tests (500 concurrent agents), latency percentile tracking (p50/p95/p99), resource exhaustion tests (50K audit chains, 200 concurrent sessions)
- **TST-009**: Code coverage infrastructure - `tarpaulin.toml` configuration with 80%+ threshold enforcement, branch coverage, HTML+XML output formats
- **INF-004**: CI/CD pipeline (`ci.yml`) - comprehensive GitHub Actions workflow with Rust build (stable + MSRV 1.75), WASM skill builds, code coverage with tarpaulin, Python SDK tests (3.9-3.12 matrix), performance benchmarks, property-based tests with extended cases
- **INF-005**: Makefile for development automation - 30+ targets covering build, test, lint, coverage, benchmarks, security, Docker, profiling, and documentation
- **INF-006**: Performance profiling tooling (`scripts/perf-profile.sh`) - benchmark tracking with baseline comparison, flamegraph generation, compilation timing analysis, binary size analysis, coverage reporting
- **SEC-006**: Dependency freshness monitoring - automated `cargo-outdated` checks in CI with artifact upload
- **SEC-007**: WASM skill integrity verification - CI job that builds all WASM skills and verifies magic bytes for module validity
- Security audit summary job aggregating results from all security checks (cargo-audit, cargo-deny, cargo-geiger, clippy, SBOM, dependency freshness, WASM integrity)

### Changed
- Updated README.md with v0.3 milestone completion, new module status entries, expanded testing/profiling documentation
- Updated TODO.md with Sprint 12 completion, v0.3 task tracking, updated test coverage summary (1,150+ tests)
- Enhanced `security.yml` workflow with dependency freshness, WASM integrity, and summary jobs
- Updated project structure documentation to include `scripts/`, `Makefile`, and `tarpaulin.toml`

## [0.2.0] - 2026-02-13

### Added
- **v0.2 Milestone**: Python SDK stable, ecosystem integrations complete
- **Python SDK - Memory Management**: `store_memory()`, `retrieve_memory()`, `store_episode()`, `retrieve_episodes()`, `search_semantic()` APIs with full stub backend support
- **Python SDK - Swarm Coordination**: `create_voting_session()`, `cast_vote()`, `tally_votes()`, `detect_sycophancy()` APIs with quadratic voting and groupthink detection
- **Python SDK - Audit Chain Verification**: `verify_audit_chain()`, `get_audit_root_hash()`, `export_audit_receipt()` APIs for hash-chain integrity verification
- **Python SDK - Agent Context**: Memory and swarm convenience methods in `_AgentContext` (`store_memory`, `retrieve_memory`, `create_vote`, `cast_vote`)
- **Python SDK - StubKernel**: Full in-memory implementations of all kernel subsystems (agent management, policy evaluation, tool execution, audit logging with SHA-256 hash chain, memory management with Merkle-chained episodes, swarm coordination with quadratic voting, sycophancy detection)
- **MCP Tool Handlers**: `VerifyPlanToolHandler` wired to `SafetyEngine::verify_plan()` for real Datalog rule checking; `ExecuteSkillToolHandler` wired to `SkillRegistry` for actual WASM skill dispatch with safety pre-checks
- **Test Coverage**: `test_memory.py` (15 tests), `test_swarm.py` (18 tests), `test_audit_chain.py` (15 tests) covering all new Python SDK APIs
- **FUT-001**: Zero-Knowledge Proof integration - commitment-based ZK proof system with Fiat-Shamir heuristic, supporting policy compliance proofs, audit integrity proofs, state transition proofs, identity attribute proofs, range proofs, and set membership proofs. Includes `ZkProver`, `ZkVerifier`, `ProofRegistry`, and batch verification.
- **FUT-002**: Constitution Protocol - immutable safety governance layer with fundamental principles (No Harm, Transparency, Least Privilege, Data Protection, Human Override), compound constraint evaluation (AND/OR/NOT), multi-point enforcement (pre-policy, pre-execution, post-execution), tamper-detection via SHA-256 hashing, and configurable blocking/warning modes.
- **FUT-003**: Enhanced PRM fine-tuning toolkit - comprehensive evaluation framework with accuracy, precision, recall, F1, AUROC, and Expected Calibration Error metrics. Includes dataset management (JSONL import/export), calibration analysis, model A/B comparison, optimal threshold search, and prompt template generation for LLM fine-tuning.
- **FUT-004**: Skill marketplace with verified publishers - multi-method publisher verification (GitHub org, GPG key, domain ownership, email), progressive trust levels (Unverified, Basic, Verified, Trusted, Official), community reputation system, malicious skill reporting with auto-suspension, vulnerability scanning for WASM binaries, and skill publishing workflow.
- **DOC-001**: Architecture documentation (ARCHITECTURE.md) - system design, module reference, data flow diagrams, security architecture, deployment guide
- **DOC-002**: API reference documentation (API.md) - complete API reference for all modules including Rust and Python SDK, configuration reference, error codes
- **INF-001**: Kubernetes operator manifests - Kustomize base with namespace, deployment, service, HPA, PDB, NetworkPolicy, ConfigMap, PVC, ServiceAccount
- **INF-002**: Docker images - multi-stage Dockerfile (deps, builder, dev, production), optimized .dockerignore, docker-compose dev profile
- **INF-003**: Helm charts - full chart with values.yaml, 10 templates (deployment, service, ingress, HPA, PDB, NetworkPolicy, ConfigMap, PVC, ServiceAccount, helpers)
- **OBS-002**: Cryptographic replay capability - ReplaySession, ReplayVerifier, ActiveReplay with hash-chain verification and step-by-step replay
- **INT-003**: LangChain Adapter Completion - LLM call interception, callback handler trait, audit integration, tool execution lifecycle management
- **INT-004**: AutoGPT Adapter Completion - PRM-scored command interception, execution result verification, plan progress tracking, callback handler system, sensitive data detection
- **SWM-002**: AgentCard Discovery - well-known endpoint support (`/.well-known/agent.json`), HTTP-based remote agent card fetching, agent card validation, TTL-based caching with eviction, search by capability/name, endpoint management
- Dockerfile and docker-compose.yml for containerized deployment (INF-003)
- CONTRIBUTING.md with development workflow and coding standards (DOC-003)
- CHANGELOG.md for tracking project changes
- MSRV (Minimum Supported Rust Version) set to 1.75 in Cargo.toml (Issue #35)
- Audit log rotation with configurable max entries and archival (Issue #20)
- Policy evaluation caching with LRU cache (Issue #40)
- Improved working memory token estimation with code-aware heuristics (Issue #15)
- Input sanitization guide for skill developers (Issue #14)

## [0.1.0] - 2026-02-10

### Added
- **Core Kernel**: Agent lifecycle management, tool dispatch, async pipeline
- **Policy Engine**: ABAC with Cedar-style enforcement, hot-reloading, dynamic context injection
- **Audit Logging**: Hash-chained immutable logs with ed25519 signing, SQLite/File/S3 backends
- **Memory System**: Merkle DAG, content-addressable storage, time travel debugging, vector store
- **WASM Sandbox**: Wasmtime runtime with fuel metering, epoch-based preemption, pooling allocator
- **Neuro-Symbolic Reasoner**: Datalog rules, Z3 SMT verification, PRM scoring, constrained decoding
- **Swarm Protocol**: A2A communication, quadratic voting, sycophancy detection, consensus mechanisms
- **Integrations**: LangChain adapter, AutoGPT adapter, MCP server, Model Context Protocol
- **Dashboard**: Prometheus metrics, health checks, HTTP server with web UI
- **Python SDK**: PyO3 bindings with async support, type stubs
- **Security**: Prompt injection detection, rate limiting, supply chain hardening, unsafe code audit
- **WASM Skills**: Calculator, crypto-hash, json-validator, text-analyzer, regex-matcher
- **Tools**: vak-skill-sign CLI for Ed25519 skill signing
- **Flight Recorder**: Shadow-mode request/response recording with replay capability
- **Verification Gateway**: Z3/SMT-based formal verification for high-stakes actions
- **Cost Accounting**: Token usage and fuel consumption tracking

### Security
- Ed25519 skill signature verification (default strict, dev-only opt-out)
- Default-deny policy enforcement (POL-007)
- Prompt injection detection with multi-category analysis (SEC-004)
- Per-agent rate limiting with token bucket algorithm (SEC-005)
- Unsafe Rust audit with documented SAFETY comments (SEC-003)

[Unreleased]: https://github.com/vak-project/verifiable-agent-kernel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vak-project/verifiable-agent-kernel/releases/tag/v0.1.0
