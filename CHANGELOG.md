# Changelog

All notable changes to the Verifiable Agent Kernel (VAK) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vak-project/verifiable-agent-kernel/releases/tag/v0.1.0
