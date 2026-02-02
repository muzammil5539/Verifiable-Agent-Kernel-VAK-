# Verifiable Agent Kernel (VAK) - Comprehensive TODO List

This document contains all unimplemented items identified through a comprehensive gap analysis comparing the MVP specification documents (`AI Agent Blue Ocean Opportunity.md`, `AI Kernel Gap Analysis & Roadmap.md`) against the actual codebase implementation.

**Last Updated:** February 2, 2026 (Session 2)

---

## ✅ COMPLETED

### Epoch Ticker Thread (RT-001) ✅
- [x] **Implemented dedicated EpochTicker background thread** that increments `engine.increment_epoch()` every 10ms
  - Implementation: `src/sandbox/epoch_ticker.rs`
  - Features: `EpochTicker`, `TickerConfig`, `TickerHandle` structs
  - Background thread with configurable tick interval (default 10ms)
  - Start/stop/pause/resume controls with metrics tracking
  - Completed: Session 2026-02-02

### Epoch Deadline Configuration (RT-002) ✅
- [x] **Implemented `store.set_epoch_deadline()` with configurable time slices**
  - Implementation: `src/sandbox/epoch_config.rs`
  - Features: `EpochConfig`, `EpochDeadlineManager`, `PreemptionBudget`, `ExecutionLimits`
  - Configurable budget in epochs or milliseconds (e.g., 100ms = 10 epochs at 10ms/tick)
  - `EpochExecutionBuilder` for fluent configuration
  - Async yield support with `epoch_deadline_async_yield_and_update()`
  - Completed: Session 2026-02-02 (Session 2)

### Pooling Allocator Strategy (RT-003) ✅
- [x] **Implemented `wasmtime::PoolingAllocationStrategy` for memory hardening**
  - Implementation: `src/sandbox/pooling.rs`
  - Features: `PoolingConfig`, `PoolManager`, `PoolingStats` structs
  - Pre-allocated memory slab with fixed-size slots
  - `InstanceLimits` restricting linear memory to 512MB and table elements to 10,000
  - Slot checkout/return with usage tracking
  - Completed: Session 2026-02-02

### Panic Safety at WASM/Host Boundary (RT-005) ✅
- [x] **Implemented `std::panic::catch_unwind` wrapper for all host functions**
  - Implementation: `src/sandbox/host_funcs.rs`
  - Features: `with_panic_boundary()`, `with_safe_policy_check()`, `HostFuncLinker`
  - Converts panics to `HostFuncError::Panic` instead of crashing the host
  - Audit logging with `AuditLogEntry` for all host function calls
  - `HostFuncState` for tracking agent/session context
  - Completed: Session 2026-02-02 (Session 2)

### Deterministic Termination Test (RT-006) ✅
- [x] **Created test case `test_infinite_loop_preemption`**
  - Implementation: `tests/integration/preemption_tests.rs`
  - Tests for epoch configuration, budget tracking, execution limits
  - Comprehensive panic safety tests
  - Note: Full WASM infinite loop test marked `#[ignore]` until test module compiled
  - Completed: Session 2026-02-02 (Session 2)

### Cedar Policy Integration (POL-001) ✅
- [x] **Cedar Policy framework integration for formal verification**
  - Implementation: `src/policy/enforcer.rs`
  - Features: `CedarEnforcer`, `Principal`, `Action`, `Resource`, `PolicyContext`, `PolicySet` structs
  - Default-deny enforcement with context injection
  - Policy hot-reload support foundation
  - Completed: Session 2026-02-02

### Cedar Schema Definition (POL-002) ✅
- [x] **Created Cedar policy schema**
  - Implementation: `src/policy/schema.cedarschema`
  - Entity types: `Agent`, `Resource`, `Tool`
  - Action types: `Read`, `Write`, `Execute`, `Delete`
  - Principal-resource relationships defined
  - Completed: Session 2026-02-02

### Cedar Enforcer Implementation (POL-003) ✅
- [x] **Implemented policy enforcement engine**
  - Implementation: `src/policy/enforcer.rs`
  - Function `enforce(principal, action, resource) -> Result<(), PolicyError>`
  - EntityUid construction for principals/resources
  - Decision logging and audit trail
  - Completed: Session 2026-02-02

### Policy Middleware Injection (POL-004) ✅
- [x] **Insert `enforce()` call at WASM boundary before function execution**
  - Implementation: `src/sandbox/host_funcs.rs`
  - Features: `HostFuncLinker` wraps all host functions with policy checks
  - `with_policy_check()` and `with_safe_policy_check()` wrappers
  - Returns trap on permission denied
  - Completed: Session 2026-02-02 (Session 2)

### Crepe Datalog Integration (NSR-001) ✅
- [x] **Datalog safety rules engine**
  - Implementation: `src/reasoner/datalog.rs`
  - Manual Datalog-style rule evaluation (no external crate needed)
  - Fact assertion and rule chaining
  - Completed: Session 2026-02-02

### Safety Rules Implementation (NSR-002) ✅
- [x] **Safety rules for malicious behavior detection**
  - Implementation: `src/reasoner/datalog.rs`
  - Features: `SafetyRules`, `Fact`, `Violation`, `SafetyVerdict` structs
  - Rules: `Malicious(X) <- FileAccess(X, "/etc/shadow")`
  - Rules: `Violation(X) <- CriticalFile(Target), DeleteAction(X, Target)`
  - Risk-score-based network access rules
  - Completed: Session 2026-02-02

### Reasoning Host Function (NSR-003) ✅
- [x] **Implemented `verify_plan` host function exposed to WASM**
  - Implementation: `src/sandbox/reasoning_host.rs`
  - Features: `ReasoningHost`, `PlanVerification`, `VerificationResult`, `ViolationInfo`
  - Agent passes proposed plan, kernel validates against Datalog facts
  - Returns Ok or Err(Violation) with detailed violation info
  - Risk score calculation based on action type, target, and confidence
  - Completed: Session 2026-02-02 (Session 2)

### Default Policies (POL-007 partial) ✅
- [x] **Default policy set created**
  - Implementation: `policies/default_policies.yaml`
  - Default-deny baseline policies
  - Completed: Session 2026-02-02

---

## 🔴 CRITICAL - Runtime/Sandbox TODOs

### Async Host Functions (RT-004)
- [ ] **Refactor Linker to use `linker.func_wrap_async` for all I/O-bound host functions**
  - Current state: Synchronous host function calls may block tokio runtime
  - Required: Use async closures for fs, net, and other I/O operations
  - Ensure `AgentState` struct implements `Send + Sync` for tokio thread migration
  - Reference: Gap Analysis Section 4, Phase 1.3

---

## 🔴 CRITICAL - Policy Engine TODOs

### Dynamic Context Injection (POL-005)
- [ ] **Build dynamic context collector for Cedar evaluation**
  - Capture `SystemTime`, `RequestIP`, `AgentReputation` on syscalls
  - Serialize to Cedar Context JSON blob
  - Include transient state: system load, agent confidence score, recent access history
  - Reference: Gap Analysis Section 2.2.2

### Policy Hot-Reloading (POL-006)
- [ ] **Implement hot-reloading of `.cedar` policy files**
  - Store policies in Merkle Log for versioning
  - Use `ArcSwap` for lock-free policy updates
  - Trigger reload on log update
  - Reference: Gap Analysis Phase 2.3

### Default Deny Policy (POL-007)
- [ ] **Ensure Cedar integration fails closed (complete implementation)**
  - Current state: Basic default-deny in enforcer.rs, default_policies.yaml created
  - Required: Full error handling for missing/malformed policy files
  - Log policy load failures with clear error messages
  - Reference: Gap Analysis Section 3.2

### Policy Analysis Integration (POL-008)
- [ ] **Integrate Cedar Policy Analyzer**
  - Run analyzer before loading new policy sets
  - Prove safety invariants (e.g., "No agent can delete audit log")
  - Block deployment of policies that violate invariants
  - Reference: Gap Analysis Section 2.2.1

---

## 🔴 CRITICAL - Memory/Provenance TODOs

### rs-merkle Integration (MEM-001)
- [ ] **Add `rs-merkle` crate dependency for proper Merkle tree implementation**
  - Current state: Custom hash-chaining in `episodic.rs` and `merkle_dag.rs`
  - Required: Use `rs-merkle` for sparse Merkle trees with efficient inclusion proofs
  - Reference: Gap Analysis Section 2.3.1

### Sparse Merkle Tree Proofs (MEM-002)
- [ ] **Implement sparse Merkle tree for efficient inclusion proofs**
  - Allow proving agent *did* see specific file without revealing entire dataset
  - Support proof generation and verification
  - Reference: Gap Analysis Section 2.3.1

### Content-Addressable Storage Backend (MEM-003)
- [ ] **Integrate `sled` or `rocksdb` as content-addressable blob store**
  - Current state: In-memory storage or basic file persistence
  - Required: Store actual "Thinking" text and "Tool Output" using Merkle hash as key
  - Enables deduplication of identical thoughts/data
  - Reference: Gap Analysis Phase 3.2

### Cryptographic Receipt Generation (MEM-004)
- [ ] **Generate cryptographic receipts for verifiable runs**
  - Chain of hashes proving exactly what agent saw and why it made decisions
  - Include timestamp, state hash, reasoning trace
  - Reference: Blue Ocean MVP Section 4.4

### Time Travel Debugging Enhancement (MEM-005)
- [ ] **Implement full "checkout" capability from Merkle root hash**
  - Current state: Basic time travel exists in `time_travel.rs`
  - Required: Spin up local VAK instance, restore exact memory state from hash
  - Allow "step forward" one decision at a time
  - Reference: Gap Analysis Section 6.4

### Secret Scrubbing (MEM-006)
- [ ] **Automatic redaction of sensitive patterns in memory snapshots**
  - Detect API keys (e.g., `sk-proj-...`), passwords, tokens
  - Redact before persisting to disk
  - Reference: Gap Analysis Section 3.2

---

## 🟡 HIGH - Neuro-Symbolic/Reasoning TODOs

### Risk-Based Network Access Rules (NSR-004)
- [ ] **Write Datalog rules that forbid network access based on RiskScore**
  - If RiskScore fact is high, deny network operations
  - Integrate with PRM confidence scores
  - Note: Basic risk scoring implemented in `reasoning_host.rs`
  - Reference: Gap Analysis Sprint 4, T4.4

### Constrained Decoding Bridge (NSR-005)
- [ ] **Integrate grammar-based sampler (KBNF) for LLM output**
  - Current state: Free-text generation parsed via regex
  - Required: Constrain output to valid Datalog facts or JSON schemas
  - Eliminates "Parse Error" class of failures
  - Reference: Gap Analysis Section 2.4.2

### Neuro-Symbolic Hybrid Loop (NSR-006)
- [ ] **Implement complete Neural -> Symbolic -> Neural sandwich architecture**
  - 1. LLM proposes plan (Neural)
  - 2. Datalog validates against invariant rules (Symbolic)
  - 3. Execute only if validation passes (Neural execution)
  - Note: Validation step implemented in `reasoning_host.rs`
  - Reference: Gap Analysis Section 2.4.1

---

## 🟡 HIGH - Multi-Agent/Swarm TODOs

### Agent-to-Agent (A2A) Protocol Support (SWM-001)
- [ ] **Add `a2a-types` crate dependency**
  - Current state: Custom swarm messaging in `src/swarm/messages.rs`
  - Required: Standard A2A protocol for inter-agent communication
  - Reference: Gap Analysis Phase 5.2

### AgentCard Discovery Mechanism (SWM-002)
- [ ] **Implement `src/api/a2a.rs` with AgentCard serialization**
  - Allow VAK agents to discover and query other agents' interfaces
  - Support capability exchange negotiation
  - Reference: Gap Analysis Sprint 5, T5.3

### Sycophancy Prevention Metrics (SWM-003)
- [ ] **Add metrics for detecting consensus collapse**
  - Track vote diversity, disagreement rates
  - Alert on potential sycophancy patterns
  - Reference: Blue Ocean Section 1.3

### Protocol Router Enhancements (SWM-004)
- [ ] **Expand protocol router with task-specific topologies**
  - Support: Hierarchical, Debate, Voting, Peer Review modes
  - Auto-select based on task complexity analysis
  - Reference: Blue Ocean Module 4.2

---

## 🟡 HIGH - Interoperability TODOs

### MCP Server Implementation (INT-001)
- [ ] **Add `mcp-sdk-rs` / `mcp_rust_sdk` crate dependency**
  - Current state: No Model Context Protocol support
  - Required: Implement MCP for ecosystem adoption (Anthropic, GitHub tools)
  - Reference: Gap Analysis Phase 5.1

### MCP Server Bridge (INT-002)
- [ ] **Create `src/api/mcp_server.rs`**
  - Bridge incoming JSON-RPC requests to internal VAK actions
  - Map internal WASM host functions to MCP Tool definitions
  - Reference: Gap Analysis Sprint 5, T5.1-T5.2

### LangChain Adapter Completion (INT-003)
- [ ] **Complete LangChain integration with full policy/audit support**
  - Current state: Basic adapter exists in `src/integrations/langchain.rs`
  - Required: Full PRM scoring integration, rate limiting per agent
  - Reference: Integrations module

### AutoGPT Adapter Completion (INT-004)
- [ ] **Complete AutoGPT task planning interception**
  - Current state: Stub exists in `src/integrations/autogpt.rs`
  - Required: Full task planning verification and execution monitoring
  - Reference: Integrations module

---

## 🟡 HIGH - Observability/Audit TODOs

### OpenTelemetry Integration (OBS-001)
- [ ] **Add `opentelemetry` crate for distributed tracing**
  - Current state: Prometheus metrics exist in `src/dashboard/metrics.rs`
  - Required: Full distributed tracing with spans
  - Create spans for: "Inference", "Logic Check", "Policy Eval", "Tool Exec"
  - Reference: Gap Analysis Section 3.4

### Cryptographic Replay Capability (OBS-002)
- [ ] **Implement production incident replay from Merkle Log**
  - Take Merkle Log from production
  - Replay in local VAK instance
  - Reproduce exact state and decision path
  - Reference: Gap Analysis Section 3.4

### Cost Accounting System (OBS-003)
- [ ] **Track Token Usage + Fuel Consumed + I/O Bytes**
  - Generate precise micro-bill for agent execution
  - Integrate with billing/quota systems
  - Reference: Gap Analysis Section 3.4

### GraphQL API for Audit Queries (OBS-004)
- [ ] **Implement GraphQL endpoint for audit log queries**
  - Current state: Basic REST-style access
  - Required: Rich query capabilities for forensics
  - Reference: Original TODO

### Flight Recorder Enhancement (OBS-005)
- [ ] **Enhance shadow mode flight recorder with full replay**
  - Current state: Basic flight recorder in `src/audit/flight_recorder.rs`
  - Required: Complete state capture for deterministic replay
  - Reference: Issue #43

---

## 🟡 HIGH - Security TODOs

### Supply Chain Hardening (SEC-001)
- [ ] **Add CI job for `cargo-audit` vulnerability scanning**
  - Scan dependencies against RustSec vulnerability database
  - Block PRs with known vulnerabilities
  - Reference: Gap Analysis Section 3.2

### License Compliance (SEC-002)
- [ ] **Add CI job for `cargo-deny` license checking**
  - Ensure no AGPL or incompatible licenses in dependencies
  - Enforce enterprise license constraints
  - Reference: Gap Analysis Section 6.3

### Unsafe Rust Audit (SEC-003)
- [ ] **Run `cargo-geiger` and document all unsafe blocks**
  - Current state: `#![deny(unsafe_code)]` in `src/lib.rs`
  - Required: Audit all dependencies for unsafe usage
  - Document each instance with `// SAFETY:` comments
  - Reference: Gap Analysis Section 6.3

### Prompt Injection Protection (SEC-004)
- [ ] **Implement prompt injection detection and mitigation**
  - Detect attempts to override system prompts
  - Sandbox detection rules in Datalog
  - Reference: Blue Ocean Section 1.4

### Rate Limiting Enhancements (SEC-005)
- [ ] **Enhance rate limiting with per-resource limits**
  - Current state: Per-agent rate limiting exists
  - Required: Per-resource, per-action granular limits
  - Reference: Policy module

---

## 🟢 MEDIUM - Testing/CI TODOs

### Infinite Loop Preemption Tests (TST-001)
- [ ] **Create comprehensive preemption test suite**
  - Test various infinite loop patterns
  - Test CPU-intensive computations
  - Test memory bomb attacks
  - Reference: Gap Analysis Section 3.1

### Memory Containment Tests (TST-002)
- [ ] **Test PoolingAllocationStrategy prevents memory bombs**
  - Spawn 50 agents each trying to allocate 4GB
  - Verify host process RSS stays within quota
  - Reference: Gap Analysis Section 3.1

### Policy Verification Tests (TST-003)
- [ ] **Create Cedar policy verification test suite**
  - Test default deny behavior
  - Test policy hot-reload
  - Test context injection
  - Reference: Policy module

### Integration Test Coverage (TST-004)
- [ ] **Expand integration tests in `tests/integration/`**
  - Current state: Basic structure exists
  - Required: Full workflow tests
  - Reference: Tests directory

### Benchmark Suite Expansion (TST-005)
- [ ] **Expand `benches/kernel_benchmarks.rs`**
  - Add PRM scoring benchmarks
  - Add policy evaluation benchmarks
  - Add Merkle proof generation benchmarks
  - Reference: Benches directory

### Python SDK Tests (TST-006)
- [ ] **Expand Python test coverage in `python/tests/`**
  - Test all PyO3 bindings
  - Test error handling across boundary
  - Reference: Python tests

---

## 🟢 MEDIUM - Infrastructure TODOs

### Kubernetes Operator (INF-001)
- [ ] **Create Kubernetes operator for VAK deployment**
  - Custom Resource Definitions (CRDs)
  - Auto-scaling based on agent load
  - Reference: Original TODO

### Docker/Container Images (INF-002)
- [ ] **Create official Docker images**
  - Multi-arch support (amd64, arm64)
  - Minimal base images for security
  - Reference: Deployment needs

### Helm Charts (INF-003)
- [ ] **Create Helm charts for Kubernetes deployment**
  - Configurable resource limits
  - Policy ConfigMaps
  - Reference: Deployment needs

### CI/CD Pipeline Enhancements (INF-004)
- [ ] **Add comprehensive CI/CD pipeline**
  - Run all security scans
  - Run full test suite
  - Build and publish artifacts
  - Reference: GitHub Actions

---

## 🟢 MEDIUM - Documentation TODOs

### Architecture Documentation (DOC-001)
- [ ] **Create comprehensive architecture documentation**
  - System diagrams
  - Data flow diagrams
  - Security model documentation
  - Reference: README.md

### API Reference (DOC-002)
- [ ] **Generate and publish API documentation**
  - Rust docs with examples
  - Python SDK documentation
  - Reference: doc/

### Runbook/Operations Guide (DOC-003)
- [ ] **Create operations runbook**
  - Deployment procedures
  - Troubleshooting guides
  - Incident response procedures
  - Reference: Operations needs

### Policy Authoring Guide (DOC-004)
- [ ] **Create Cedar policy authoring guide**
  - Best practices
  - Common patterns
  - Security considerations
  - Reference: Policy module

---

## 🔵 LOW - Future Enhancements

### Zero-Knowledge Proof Integration (FUT-001)
- [ ] **Research and implement ZKP for verified execution**
  - Prove agent ran specific code without revealing code
  - Support "Verification Gas" for proof generation
  - Reference: Blue Ocean Phase 3

### Constitution Protocol (FUT-002)
- [ ] **Implement hard-coded Constitution files**
  - Agents cannot override constitutional constraints
  - Regulatory compliance (GDPR, EU AI Act)
  - Reference: Blue Ocean Phase 4

### Enhanced PRM Model Fine-Tuning (FUT-003)
- [ ] **Create PRM model fine-tuning toolkit**
  - Tools for training domain-specific PRMs
  - Reference: Original TODO

### Skill Marketplace Enhancements (FUT-004)
- [ ] **Enhance skill marketplace with verified publishers**
  - Current state: Basic marketplace in `src/sandbox/marketplace.rs`
  - Required: Publisher verification, reviews, ratings
  - Reference: Marketplace module

### Multi-Model Orchestration (FUT-005)
- [ ] **Support routing to multiple LLM backends**
  - Automatic failover
  - Cost optimization routing
  - Reference: LLM module

### Context Manager Dynamic Summarization (FUT-006)
- [ ] **Implement dynamic context summarization in Working Memory**
  - Current state: Basic working memory in `src/memory/working.rs`
  - Required: Automatic pruning and summarization to prevent "context flooding"
  - Implement signal-to-noise optimization
  - Reference: Blue Ocean Section Module 1.1

### LlamaIndex Integration (FUT-007)
- [ ] **Add LlamaIndex query engine integration**
  - Current state: LangChain/AutoGPT adapters exist
  - Required: Full LlamaIndex integration for query pipelines
  - Reference: Integrations module architecture diagram

### Sovereign AI / Local Inference Support (FUT-008)
- [ ] **Support local/sovereign AI deployment mode**
  - Current state: LiteLLM proxy for cloud APIs
  - Required: Direct Ollama/local model integration without proxy
  - Reduce "token tax" for long-running loops
  - Reference: Blue Ocean Section 1.5


---

## Summary Statistics

| Priority | Count | Status |
|----------|-------|--------|
| ✅ COMPLETED | 14 | Done |
| 🔴 CRITICAL | 11 | Not Started |
| 🟡 HIGH | 21 | Not Started |
| 🟢 MEDIUM | 17 | Not Started |
| 🔵 LOW | 8 | Not Started |
| **TOTAL** | **71** | 14 complete (~20%) |

---

## Implementation Phases

Based on the Gap Analysis roadmap:

### Phase 1: Core Kernel Stability ("Iron Kernel") ✅ MOSTLY COMPLETE
- RT-001 ✅ Epoch Ticker
- RT-002 ✅ Epoch Deadline Configuration
- RT-003 ✅ Pooling Allocator
- RT-004 ⏳ Async Host Functions
- RT-005 ✅ Panic Safety
- RT-006 ✅ Preemption Tests
- Focus: Runtime that cannot be crashed, stalled, or exploited

### Phase 2: Policy Layer ("Digital Superego") ✅ MOSTLY COMPLETE
- POL-001 ✅ Cedar Integration
- POL-002 ✅ Cedar Schema
- POL-003 ✅ Cedar Enforcer
- POL-004 ✅ Policy Middleware Injection
- POL-005 ⏳ Dynamic Context Injection
- POL-006 ⏳ Policy Hot-Reloading
- POL-007 ⏳ Default Deny (partial)
- POL-008 ⏳ Policy Analysis
- Focus: Formal verification of all agent actions

### Phase 3: Memory & Provenance ("Immutable Past")
- MEM-001 through MEM-006
- Focus: Cryptographic proof of history and state

### Phase 4: Neuro-Symbolic Cognitive Layer ("Prefrontal Cortex") ✅ CORE COMPLETE
- NSR-001 ✅ Datalog Integration
- NSR-002 ✅ Safety Rules
- NSR-003 ✅ Reasoning Host Function
- NSR-004 ⏳ Risk-Based Rules (partial)
- NSR-005 ⏳ Constrained Decoding
- NSR-006 ⏳ Full Hybrid Loop (partial)
- Focus: Logic-based safety constraints

### Phase 5: Ecosystem & Interoperability
- INT-001 through INT-004, SWM-001 through SWM-004
- Focus: Standardized communication protocols

---

*This TODO list was generated through comprehensive analysis of VAK documentation and codebase on February 2, 2026.*
*Updated: Session 2026-02-02 (Session 2) - Completed RT-002, RT-005, RT-006, POL-004, NSR-003*
*New completions: epoch_config.rs, host_funcs.rs, reasoning_host.rs, preemption_tests.rs*
