# Verifiable Agent Kernel (VAK) - Comprehensive TODO List

This document contains all unimplemented items identified through a comprehensive gap analysis comparing the MVP specification documents (`AI Agent Blue Ocean Opportunity.md`, `AI Kernel Gap Analysis & Roadmap.md`) against the actual codebase implementation.

**Last Updated:** February 2, 2026 (Session 4)

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

### Async Host Functions (RT-004) ✅
- [x] **Refactored Linker to use async host functions for I/O operations**
  - Implementation: `src/sandbox/async_host.rs`
  - Features: `AsyncHostContext`, `AsyncOperation`, `OperationResult`, `AsyncOperationExecutor`
  - Async closures for fs, net, and HTTP operations with non-blocking I/O
  - `AgentState` properly structured for tokio thread migration
  - Authorization cache with TTL for performance
  - Cooperative yielding and cancellation support
  - Completed: Session 2026-02-03 (Session 3)

### Dynamic Context Injection (POL-005) ✅
- [x] **Built dynamic context collector for Cedar evaluation**
  - Implementation: `src/policy/context_integration.rs`
  - Features: `IntegratedPolicyEngine`, `EnrichedDecision`, `RiskAssessment`, `ContextSnapshot`
  - Captures `SystemTime`, `RequestIP`, `AgentReputation` on syscalls
  - Serializes to Cedar Context JSON blob
  - Includes transient state: system load, agent confidence score, recent access history
  - Multi-level risk assessment (low/medium/high/critical)
  - Completed: Session 2026-02-03 (Session 3)

### Sparse Merkle Tree Proofs (MEM-002) ✅
- [x] **Implemented sparse Merkle tree for efficient inclusion proofs**
  - Implementation: `src/memory/sparse_merkle.rs`
  - Features: `SparseMerkleTree`, `SparseProof`, `CompactProof`, `NonMembershipProof`
  - Allows proving agent *did* see specific file without revealing entire dataset
  - Support for proof generation and verification
  - Batch proof support for multiple keys
  - Default leaf value and efficient sparse storage
  - Completed: Session 2026-02-03 (Session 3)

### Default Policies (POL-007 partial) ✅
- [x] **Default policy set created**
  - Implementation: `policies/default_policies.yaml`
  - Default-deny baseline policies
  - Completed: Session 2026-02-02

### Content-Addressable Storage Backend (MEM-003) ✅
- [x] **Implemented content-addressable blob store**
  - Implementation: `src/memory/content_addressable.rs`
  - Features: `ContentAddressableStore`, `ContentId`, `CasEntry`, `CasMetadata` structs
  - SHA-256 based content addressing with automatic deduplication
  - Storage backends: In-memory, file-based, SQLite
  - Batch operations: `put_batch()`, `get_batch()` for efficient bulk storage
  - Reference counting and garbage collection support
  - Store "Thinking" text and "Tool Output" using content hash as key
  - Completed: Session 2026-02-04 (Session 4)

### Risk-Based Network Access Rules (NSR-004) ✅
- [x] **Implemented Datalog rules that forbid network access based on RiskScore**
  - Implementation: `src/reasoner/datalog.rs` (enhanced)
  - Features: `RULE_007_NETWORK_HIGH_RISK`, `RULE_008_NETWORK_EXTERNAL_RISK` rules
  - Denies network access when agent risk score > 0.7
  - Escalates risk for external endpoint access
  - Integrates with PRM confidence scores for dynamic risk assessment
  - Completed: Session 2026-02-04 (Session 4)

### MCP Server Implementation (INT-001/INT-002) ✅
- [x] **Implemented Model Context Protocol server**
  - Implementation: `src/integrations/mcp.rs`
  - Features: `McpServer`, `McpTool`, `McpResource`, `McpContext` structs
  - JSON-RPC style request/response handling
  - Tool registration with automatic schema generation
  - Built-in tools: `verify_plan`, `check_policy`, `get_agent_state`
  - Resource access with URI-based addressing
  - Conversation context management
  - Bridges incoming MCP requests to internal VAK actions
  - Maps internal WASM host functions to MCP Tool definitions
  - Completed: Session 2026-02-04 (Session 4)

### OpenTelemetry Distributed Tracing (OBS-001) ✅
- [x] **Distributed tracing with automatic span creation**
  - Implementation: `src/audit/otel.rs`
  - Features: `VakTracer`, `Span`, `SpanContext`, `TraceContext`, `SpanKind` structs
  - Kernel-specific helpers: `trace_inference()`, `trace_logic_check()`, `trace_policy_eval()`, `trace_tool_exec()`, `trace_memory_op()`, `trace_swarm_comm()`, `trace_mcp_request()`
  - `traced_operation()` helper for automatic timing and error tracking
  - OTLP export support via `OtlpExporter`
  - W3C traceparent header support for distributed trace propagation
  - Completed: Session 2026-02-04 (Session 6)

### Default Deny Policy - Complete Implementation (POL-007) ✅
- [x] **Cedar integration fails closed with proper error handling**
  - Implementation: `src/policy/enforcer.rs`
  - Features: `default_deny_policy_set()` function providing hardcoded fail-closed policy
  - `policy_loaded` flag to track if valid policies have been loaded
  - Enhanced `load_policies()` with proper error handling and logging
  - `authorize()` returns explicit fail-closed message when no valid policies loaded
  - `has_policies_loaded()` method to check policy state
  - Completed: Session 2026-02-04 (Session 6)

---

## 🔴 CRITICAL - Runtime/Sandbox TODOs

---

## 🔴 CRITICAL - Policy Engine TODOs

### Policy Hot-Reloading (POL-006)
- [ ] **Implement hot-reloading of `.cedar` policy files**
  - Store policies in Merkle Log for versioning
  - Use `ArcSwap` for lock-free policy updates
  - Trigger reload on log update
  - Reference: Gap Analysis Phase 2.3

### Default Deny Policy (POL-007) ✅
- [x] **Ensure Cedar integration fails closed (complete implementation)**
  - Implementation: `src/policy/enforcer.rs`
  - Features: `default_deny_policy_set()` function providing hardcoded fail-closed policy
  - `policy_loaded` flag to track if valid policies have been loaded
  - Enhanced `load_policies()` with proper error handling and logging
  - `authorize()` returns explicit fail-closed message when no valid policies loaded
  - Log policy load failures with clear error messages
  - Completed: Session 2026-02-04 (Session 6)

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
  - Note: Custom sparse Merkle tree implemented in `sparse_merkle.rs` - can optionally migrate to `rs-merkle` for additional features
  - Reference: Gap Analysis Section 2.3.1

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

### Secret Scrubbing (MEM-006) ✅
- [x] **Automatic redaction of sensitive patterns in memory snapshots**
  - Implementation: `src/memory/secret_scrubber.rs`
  - Features: `SecretScrubber`, `ScrubberConfig`, `PatternType` structs
  - Detects API keys (OpenAI, Anthropic, AWS, GitHub), passwords, tokens, PII
  - Regex-based pattern matching with configurable redaction
  - Scrub reports with detection details
  - Completed: Session 2026-02-02 (marked in earlier session)

---

## 🟡 HIGH - Neuro-Symbolic/Reasoning TODOs

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

### Sycophancy Prevention Metrics (SWM-003) ✅
- [x] **Add metrics for detecting consensus collapse**
  - Implementation: `src/swarm/sycophancy.rs`
  - Features: `SycophancyDetector`, `SessionAnalysis`, `VoteRecord`, `OpinionCluster`
  - Shannon entropy calculation for vote diversity
  - Disagreement rate tracking and anomaly detection
  - Alert on potential sycophancy patterns (unanimous agreement, bandwagon effect, rapid consensus)
  - Risk indicators: LowEntropy, UnanimousAgreement, RapidConsensus, NoDisagreement, BandwagonEffect
  - Recommendation engine: Accept, RequestMoreDebate, IntroduceAdversary, HumanReview, BlockDecision
  - Completed: Session 2026-02-03 (Session 5)

### Protocol Router Enhancements (SWM-004)
- [ ] **Expand protocol router with task-specific topologies**
  - Support: Hierarchical, Debate, Voting, Peer Review modes
  - Auto-select based on task complexity analysis
  - Reference: Blue Ocean Module 4.2

---

## 🟡 HIGH - Interoperability TODOs

### AutoGPT Protocol (INT-003)
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

### OpenTelemetry Integration (OBS-001) ✅
- [x] **Distributed tracing implementation with spans**
  - Implementation: `src/audit/otel.rs`
  - Features: `VakTracer`, `Span`, `SpanContext`, `TraceContext`, `SpanKind` structs
  - Spans for: Inference, LogicCheck, PolicyEval, ToolExec, MemoryOp, SwarmComm, McpRequest
  - Kernel-specific helpers: `trace_inference()`, `trace_logic_check()`, `trace_policy_eval()`, `trace_tool_exec()`
  - `traced_operation()` helper for automatic timing and error tracking
  - OTLP export support via `OtlpExporter`
  - W3C traceparent header support for distributed trace propagation
  - Completed: Session 2026-02-04 (Session 6)

### Cryptographic Replay Capability (OBS-002)
- [ ] **Implement production incident replay from Merkle Log**
  - Take Merkle Log from production
  - Replay in local VAK instance
  - Reproduce exact state and decision path
  - Reference: Gap Analysis Section 3.4

### Cost Accounting System (OBS-003) ✅
- [x] **Track Token Usage + Fuel Consumed + I/O Bytes**
  - Implementation: `src/dashboard/cost_accounting.rs`
  - Features: `CostAccountant`, `ExecutionCost`, `CostBreakdown`, `BillingReport`
  - Token usage tracking (input/output tokens, LLM calls)
  - WASM fuel consumption tracking
  - Network I/O and storage operation metrics
  - API call tracking per service
  - Budget limits with alerts and enforcement
  - Configurable pricing rates (default, free, premium)
  - Prometheus metrics export
  - Billing report generation with invoice formatting
  - Completed: Session 2026-02-03 (Session 5)

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
| ✅ COMPLETED | 20 | Done |
| 🔴 CRITICAL | 7 | Not Started |
| 🟡 HIGH | 16 | Not Started |
| 🟢 MEDIUM | 17 | Not Started |
| 🔵 LOW | 8 | Not Started |
| **TOTAL** | **68** | 20 complete (~29%) |

---

## Implementation Phases

Based on the Gap Analysis roadmap:

### Phase 1: Core Kernel Stability ("Iron Kernel") ✅ COMPLETE
- RT-001 ✅ Epoch Ticker
- RT-002 ✅ Epoch Deadline Configuration
- RT-003 ✅ Pooling Allocator
- RT-004 ✅ Async Host Functions
- RT-005 ✅ Panic Safety
- RT-006 ✅ Preemption Tests
- Focus: Runtime that cannot be crashed, stalled, or exploited

### Phase 2: Policy Layer ("Digital Superego") ✅ MOSTLY COMPLETE
- POL-001 ✅ Cedar Integration
- POL-002 ✅ Cedar Schema
- POL-003 ✅ Cedar Enforcer
- POL-004 ✅ Policy Middleware Injection
- POL-005 ✅ Dynamic Context Injection
- POL-006 ⏳ Policy Hot-Reloading (foundation exists)
- POL-007 ✅ Default Deny (complete)
- POL-008 ⏳ Policy Analysis (foundation exists)
- Focus: Formal verification of all agent actions

### Phase 3: Memory & Provenance ("Immutable Past") ✅ MOSTLY COMPLETE
- MEM-001 ⏳ rs-merkle Integration (custom implementation exists)
- MEM-002 ✅ Sparse Merkle Tree Proofs
- MEM-003 ✅ Content-Addressable Storage
- MEM-004 ⏳ Cryptographic Receipt Generation (foundation exists)
- MEM-005 ⏳ Time Travel Enhancement (basic exists)
- MEM-006 ✅ Secret Scrubbing
- Focus: Cryptographic proof of history and state

### Phase 4: Neuro-Symbolic Cognitive Layer ("Prefrontal Cortex") ✅ CORE COMPLETE
- NSR-001 ✅ Datalog Integration
- NSR-002 ✅ Safety Rules
- NSR-003 ✅ Reasoning Host Function
- NSR-004 ⏳ Risk-Based Rules (partial)
- NSR-005 ⏳ Constrained Decoding
- NSR-006 ⏳ Full Hybrid Loop (partial)
- Focus: Logic-based safety constraints

### Phase 5: Ecosystem & Interoperability ✅ PARTIALLY COMPLETE
- INT-001 ✅ MCP Server Implementation
- INT-002 ✅ MCP Tool Mapping
- INT-003 ⏳ LangChain Adapter (foundation exists)
- INT-004 ⏳ AutoGPT Adapter (foundation exists)
- SWM-001 ⏳ A2A Protocol Support
- SWM-002 ⏳ AgentCard Discovery
- SWM-003 ✅ Sycophancy Prevention
- SWM-004 ⏳ Protocol Router
- Focus: Standardized communication protocols

### Observability Layer ✅ MOSTLY COMPLETE
- OBS-001 ✅ OpenTelemetry Distributed Tracing
- OBS-002 ⏳ Cryptographic Replay
- OBS-003 ✅ Cost Accounting
- OBS-004 ⏳ GraphQL API
- OBS-005 ⏳ Flight Recorder Enhancement

---

*This TODO list was generated through comprehensive analysis of VAK documentation and codebase on February 2, 2026.*
*Updated: Session 2026-02-02 (Session 2) - Completed RT-002, RT-005, RT-006, POL-004, NSR-003*
*Updated: Session 2026-02-03 (Session 5) - Completed OBS-003 (Cost Accounting), SWM-003 (Sycophancy Detection)*
*Updated: Session 2026-02-04 (Session 6) - Completed POL-007 (Default Deny), OBS-001 (OpenTelemetry), MEM-006 (Secret Scrubbing)*
*New completions: Enhanced default_deny_policy_set() in enforcer.rs, kernel tracing helpers in otel.rs*
