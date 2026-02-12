# Changelog

All notable changes to the Verifiable Agent Kernel (VAK) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/vak-project/verifiable-agent-kernel/releases/tag/v0.1.0
