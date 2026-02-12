# VAK Architecture Documentation

> **Verifiable Agent Kernel (VAK)** -- Deterministic Control Plane for Autonomous AI Agents

---

## Table of Contents

- [System Overview](#system-overview)
- [Design Principles](#design-principles)
- [Layered Architecture](#layered-architecture)
- [Module Reference](#module-reference)
  - [Kernel Core](#kernel-core)
  - [Policy Engine (ABAC)](#policy-engine-abac)
  - [Audit Logger](#audit-logger)
  - [Memory Fabric](#memory-fabric)
  - [WASM Sandbox](#wasm-sandbox)
  - [Neuro-Symbolic Reasoner](#neuro-symbolic-reasoner)
  - [LLM Interface](#llm-interface)
  - [Swarm Coordination](#swarm-coordination)
  - [Integrations](#integrations)
  - [Dashboard & Observability](#dashboard--observability)
  - [Secrets Management](#secrets-management)
  - [High-Level Integration Library](#high-level-integration-library)
- [Data Flow](#data-flow)
- [Security Architecture](#security-architecture)
- [Deployment Architecture](#deployment-architecture)
- [Directory Structure](#directory-structure)

---

## System Overview

VAK is an OS-like kernel for AI agents written in Rust. It sits between the agent layer (LLMs such as GPT-4, Claude, Llama) and the external world (APIs, files, databases), intercepting every tool call to enforce policies, log decisions, and sandbox execution.

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent Layer                            │
│  (LLM-based agents: GPT-4, Claude, Llama, etc.)           │
└─────────────────┬───────────────────────────────────────────┘
                  │ Tool Requests
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   VAK Kernel (Core)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Policy     │  │    Audit     │  │    Memory    │     │
│  │   Engine     │  │   Logger     │  │   Manager    │     │
│  │   (ABAC)     │  │  (Merkle)    │  │  (3-Tier)    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │    WASM      │  │     LLM      │  │   Reasoner   │     │
│  │   Sandbox    │  │  Interface   │  │    (PRM)     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   Swarm      │  │  Dashboard   │  │   Secrets    │     │
│  │  Consensus   │  │  & Metrics   │  │   Manager    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
└─────────────────┬───────────────────────────────────────────┘
                  │ Approved Actions
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   External World                            │
│  (APIs, Files, Databases, Services)                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Design Principles

| Principle | Description |
|-----------|-------------|
| **Default Deny** | No policy = no access. Every action requires an explicit allow rule. |
| **Audit First** | Actions are logged to the tamper-evident audit chain before execution. |
| **Deterministic Execution** | WASM sandbox with fuel metering ensures reproducible results. |
| **Panic Boundary** | WASM panics are caught at the host boundary; the kernel never crashes. |
| **Isolation** | Each tool invocation runs in its own WASM instance with bounded resources. |
| **Verifiability** | Cryptographic proofs (SHA-256 hashes, Ed25519 signatures, Merkle proofs) allow third parties to verify every decision. |
| **Zero Unsafe** | The crate uses `#![deny(unsafe_code)]`. All modules are implemented in safe Rust. |

---

## Layered Architecture

VAK is organized into three conceptual layers:

### 1. Agent Interface Layer

Receives `ToolRequest` messages from agents and returns `ToolResponse` results. Supports multiple integration formats:

- **Direct Rust API** -- `Kernel::execute()`
- **Python SDK** -- PyO3 bindings via `VakKernel`
- **MCP Protocol** -- JSON-RPC Model Context Protocol server
- **LangChain / AutoGPT Adapters** -- Callback-based middleware

### 2. Kernel Services Layer

The core services that process every request:

| Service | Module | Responsibility |
|---------|--------|----------------|
| Policy Engine | `src/policy/` | ABAC evaluation, Cedar enforcement, hot-reloading |
| Audit Logger | `src/audit/` | Hash-chained logging, Ed25519 signing, replay |
| Memory Fabric | `src/memory/` | Merkle DAG, episodic chain, vector store, time travel |
| WASM Sandbox | `src/sandbox/` | Fuel-metered execution, epoch preemption, pooling |
| Reasoner | `src/reasoner/` | PRM scoring, Datalog safety rules, Z3 verification |
| Swarm | `src/swarm/` | A2A protocol, quadratic voting, sycophancy detection |
| LLM Interface | `src/llm/` | Provider abstraction, constrained decoding |

### 3. Execution Layer

Where tool code actually runs -- inside WASM sandboxes with bounded memory, CPU fuel, and timeout limits.

---

## Module Reference

### Kernel Core

**Location:** `src/kernel/`

The kernel orchestrates the full request lifecycle:

1. Accept `ToolRequest` from an agent
2. Evaluate policies via the policy engine
3. Log the decision to the audit chain
4. Dispatch execution (built-in handler or WASM sandbox)
5. Return `ToolResponse`

**Key types:**

| Type | Description |
|------|-------------|
| `Kernel` | Main struct. Holds config, audit log, sessions, skill registry, and sandbox config. |
| `AgentId` | UUIDv7 identifier for agents (time-ordered). |
| `SessionId` | UUIDv7 identifier for sessions. |
| `AuditId` | UUIDv7 identifier for audit entries. |
| `ToolRequest` | Encapsulates tool name, parameters (JSON), timeout, and a unique request ID. |
| `ToolResponse` | Contains success/failure, result JSON, error string, and execution time. |
| `PolicyDecision` | Enum: `Allow { reason, constraints }`, `Deny { reason, violated_policies }`, `Inadmissible { reason }`. |
| `KernelError` | Comprehensive error enum with error codes (E001-E010). |
| `KernelConfig` | Builder-based configuration with security, audit, policy, and resource sub-configs. |

**Sub-modules:**

| Sub-module | Purpose |
|------------|---------|
| `config.rs` | `KernelConfig`, `SecurityConfig`, `AuditConfig`, `PolicyConfig`, `ResourceConfig` |
| `types.rs` | Core type definitions (`AgentId`, `ToolRequest`, `PolicyDecision`, etc.) |
| `traits.rs` | Async traits: `PolicyEvaluator`, `AuditWriter`, `StateStore`, `ToolExecutor` |
| `async_pipeline.rs` | Concurrent request processing pipeline |
| `neurosymbolic_pipeline.rs` | PRM/reasoning integration pipeline |
| `rate_limiter.rs` | Token-bucket rate limiter per agent |
| `custom_handlers.rs` | Registry for user-defined tool handlers |

**Built-in tools:**

- `echo` -- Returns input parameters as-is
- `calculator` -- Basic arithmetic (add, subtract, multiply, divide)
- `data_processor` -- Array operations (summarize, count, filter)
- `system_info` -- Kernel metadata

Any tool name not matching a built-in is dispatched to the WASM skill registry.

---

### Policy Engine (ABAC)

**Location:** `src/policy/`

Attribute-Based Access Control with Cedar-style policy definitions.

```
┌────────────┐     ┌──────────────┐     ┌────────────────┐
│ ToolRequest│────►│ CedarEnforcer│────►│ PolicyDecision  │
└────────────┘     │  + Context   │     │ Allow/Deny/     │
                   │  + Rules     │     │ Inadmissible    │
                   └──────────────┘     └────────────────┘
```

**Key components:**

| Component | File | Description |
|-----------|------|-------------|
| `CedarEnforcer` | `enforcer.rs` | Core policy evaluation engine. Loads YAML rules, evaluates conditions. |
| `DynamicContextCollector` | `context.rs` | Injects runtime context (timestamp, risk score) into policy evaluation. |
| `HotReloadablePolicyEngine` | `hot_reload.rs` | Live policy updates using `arc-swap` for lock-free reads. |
| `IntegratedPolicyEngine` | `context_integration.rs` | Combines risk assessment with policy decisions. |
| `PolicyAnalyzer` | `analyzer.rs` | Detects policy conflicts and coverage gaps. |

**Policy rule structure (YAML):**

```yaml
rules:
  - id: "unique-rule-id"
    effect: "forbid" | "permit"
    principal: "Agent::*"
    action: "Action::\"Tool::execute\""
    resource: "File::\"/etc/shadow\""
    conditions:
      - field: "amount"
        operator: LessThan
        value: 1000
    priority: 100
```

**Condition operators:** `Equals`, `NotEquals`, `LessThan`, `GreaterThan`, `In`, `Contains`, `StartsWith`, `EndsWith`, `Matches`

---

### Audit Logger

**Location:** `src/audit/`

Provides a tamper-evident, hash-chained audit trail for every kernel action.

**Architecture:**

```
AuditEntry[N]
  ├── audit_id (UUIDv7)
  ├── timestamp
  ├── agent_id
  ├── session_id
  ├── action
  ├── decision
  ├── hash = SHA-256(contents)
  └── previous_hash ──────► AuditEntry[N-1].hash
```

**Components:**

| Component | File | Description |
|-----------|------|-------------|
| `AuditLogger` | `mod.rs` | Main logging system with chain integrity |
| `FlightRecorder` | `flight_recorder.rs` | Shadow-mode recording without execution |
| `ReplaySession` | `replay.rs` | Cryptographic replay verification |
| `AuditQueryEngine` | `graphql.rs` | GraphQL-style query API |
| `VakTracer` | `otel.rs` | OpenTelemetry integration |
| `AuditStreaming` | `streaming.rs` | Live event streaming |
| `S3Backend` | `s3_backend.rs` | Cloud archival storage |
| `MultiRegionReplication` | `multi_region.rs` | Cross-region replication |

**Storage backends:** File, SQLite (`rusqlite`), S3, In-memory

**Features:**
- Ed25519 signatures for non-repudiation
- Log rotation with configurable max entries
- Chain integrity verification
- Cryptographic receipt generation

---

### Memory Fabric

**Location:** `src/memory/`

Three-tier hierarchical memory with cryptographic integrity.

```
┌──────────────────────────────────────────────────┐
│                Working Memory (Hot)               │
│  Current context window with token estimation    │
├──────────────────────────────────────────────────┤
│              Episodic Memory (Warm)               │
│  Time-ordered Merkle chain of past episodes      │
├──────────────────────────────────────────────────┤
│              Semantic Memory (Cold)               │
│  Knowledge Graph + Vector Store                  │
└──────────────────────────────────────────────────┘
```

**Components:**

| Component | File | Description |
|-----------|------|-------------|
| `MerkleDag` | `merkle_dag.rs` | Content-addressable Merkle DAG using `rs_merkle` |
| `EpisodicMemory` | `episodic.rs` | Time-ordered episode chain |
| `VectorStore` | `vector_store.rs` | Embedding-based semantic search |
| `KnowledgeGraph` | `knowledge_graph.rs` | Entity-relationship graph (`petgraph`) |
| `ContentAddressableStore` | `content_addressable.rs` | Hash-based CAS |
| `SparseMerkleTree` | `sparse_merkle.rs` | Efficient inclusion/exclusion proofs |
| `TimeTravelDebugger` | `time_travel.rs` | Snapshot and rollback to any previous state |
| `SecretScrubber` | `secret_scrubber.rs` | Redacts secrets before storage |
| `MemorySnapshot` | `snapshot_backend.rs` | State checkpoint persistence |

**Key operations:**
- `merkle_dag.insert(key, value)` -- Cryptographically backed storage
- `merkle_dag.get_proof(key)` -- Generates Merkle inclusion proof
- `time_travel.checkout(hash)` -- Reverts to a historical snapshot
- `episodic.record_episode(...)` -- Appends to the episode chain

---

### WASM Sandbox

**Location:** `src/sandbox/`

Isolated execution environment using Wasmtime 41.x.

```
┌─────────────────────────────────────────────────────┐
│                   WasmSandbox                        │
│  ┌────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ EpochTicker│  │PoolAllocator │  │HostFuncLink │ │
│  │ (preempt)  │  │ (memory)     │  │  (bridge)   │ │
│  └────────────┘  └──────────────┘  └─────────────┘ │
│  ┌────────────┐  ┌──────────────┐                   │
│  │ SkillReg   │  │ Marketplace  │                   │
│  │ (manifest) │  │ (discovery)  │                   │
│  └────────────┘  └──────────────┘                   │
└─────────────────────────────────────────────────────┘
```

**Components:**

| Component | File | Description |
|-----------|------|-------------|
| `WasmSandbox` | `mod.rs` | Main executor with `SandboxConfig` |
| `EpochTicker` | `epoch_ticker.rs` | Background thread for cooperative preemption |
| `PoolManager` | `pooling.rs` | Fixed-slot memory pooling allocator |
| `SkillRegistry` | `registry.rs` | Manifest-based skill management |
| `HostFuncLinker` | `host_funcs.rs` | WASM-to-Rust host function bridge |
| `AsyncHostFunctions` | `async_host.rs` | Async host function support |
| `ReasoningHost` | `reasoning_host.rs` | Safety-check host functions |
| `SkillMarketplace` | `marketplace.rs` | Skill discovery and distribution |

**Default resource limits:**

| Resource | Default | Description |
|----------|---------|-------------|
| Memory | 16 MB | Per-instance memory cap |
| Fuel | 1,000,000 | CPU instruction quota |
| Timeout | 5 seconds | Per-call wall clock |
| Max execution | 30 seconds | Absolute cap |

**Skill manifest fields:** `name`, `version`, `description`, `module` (WASM path), `capabilities`, `limits` (memory pages, execution time), `exports` (function signatures with schemas)

**Included WASM skills:**

| Skill | Description |
|-------|-------------|
| `calculator` | Basic arithmetic with overflow checking |
| `crypto-hash` | SHA-256, HMAC-SHA256, digest verification |
| `json-validator` | JSON validation, pretty-print, merge, diff |
| `text-analyzer` | Word count, frequency analysis, entropy, similarity |
| `regex-matcher` | Pattern matching with ReDoS protection |

---

### Neuro-Symbolic Reasoner

**Location:** `src/reasoner/`

Combines neural (LLM) creativity with symbolic verification to validate agent reasoning.

```
      LLM Output
          │
          ▼
  ┌───────────────┐     ┌──────────────┐     ┌──────────────┐
  │ PRM Scoring   │────►│ Datalog      │────►│ Z3 Formal    │
  │ (step-level)  │     │ Safety Rules │     │ Verification │
  └───────────────┘     └──────────────┘     └──────────────┘
          │                     │                     │
          └─────────────────────┼─────────────────────┘
                                ▼
                     ┌──────────────────┐
                     │ ValidationOutcome│
                     │ (pass/fail/defer)│
                     └──────────────────┘
```

**Components:**

| Component | File | Description |
|-----------|------|-------------|
| `ProcessRewardModel` | `prm.rs` | Scores individual reasoning steps with confidence |
| `PrmGating` | `prm_gating.rs` | Threshold-based gating logic |
| `SafetyEngine` | `datalog.rs` | Datalog rule evaluation for safety constraints |
| `ConstraintVerifier` | `verifier.rs` | Generic constraint satisfaction |
| `Z3Verifier` | `z3_verifier.rs` | SMT solver for formal verification |
| `VerificationGateway` | `verification_gateway.rs` | Routes high-stakes actions through Z3 |
| `HybridReasoningLoop` | `hybrid_loop.rs` | Orchestrates neural + symbolic reasoning |
| `TreeSearch` | `tree_search.rs` | MCTS-based Tree of Thoughts exploration |
| `ConstrainedDecoder` | `constrained_decoding.rs` | Grammar/schema-constrained generation |
| `PromptInjectionDetector` | `prompt_injection.rs` | Multi-category injection detection |

---

### LLM Interface

**Location:** `src/llm/`

Provider-agnostic abstraction for language model interaction.

**Key trait:**

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest)
        -> Result<CompletionResponse, LlmError>;
}
```

**Implementations:**

| Implementation | File | Description |
|---------------|------|-------------|
| `LiteLlmClient` | `litellm.rs` | Proxy to LiteLLM (supports OpenAI, Anthropic, Ollama, etc.) |
| `MockLlmProvider` | `mock.rs` | Deterministic mock for testing |
| `ConstrainedLlm` | `constrained.rs` | Wraps any provider with output constraints |

**Types:** `CompletionRequest`, `CompletionResponse`, `Message`, `Role` (User/System/Assistant), `LlmConfig`

---

### Swarm Coordination

**Location:** `src/swarm/`

Multi-agent coordination and consensus mechanisms.

**Components:**

| Component | File | Description |
|-----------|------|-------------|
| `A2AProtocol` | `a2a.rs` | Agent-to-Agent messaging with `AgentCard` discovery |
| `QuadraticVoting` | `voting.rs` | Democratic voting with quadratic cost |
| `ConsensusMechanism` | `consensus.rs` | Majority, unanimous, and weighted consensus |
| `SycophancyDetector` | `sycophancy.rs` | Groupthink and echo-chamber detection |
| `ProtocolRouter` | `router.rs` | Topology selection based on task characteristics |
| `SwarmMessages` | `messages.rs` | Message types for inter-agent communication |

**Discovery:** Agents publish `AgentCard` JSON at `/.well-known/agent.json` (A2A standard). The `AgentCardDiscovery` service fetches, validates, and caches cards with TTL-based eviction.

---

### Integrations

**Location:** `src/integrations/`

Adapters for external agent frameworks.

| Adapter | File | Description |
|---------|------|-------------|
| `LangChainAdapter` | `langchain.rs` | Callback-based middleware for LangChain tool calls, audit logging |
| `AutoGPTAdapter` | `autogpt.rs` | PRM-scored command interception, plan tracking, verification |
| `McpServer` | `mcp.rs` | JSON-RPC Model Context Protocol server for tools |

---

### Dashboard & Observability

**Location:** `src/dashboard/`

HTTP-based observability endpoints.

| Component | File | Endpoint | Description |
|-----------|------|----------|-------------|
| `DashboardServer` | `server.rs` | `/dashboard` | Web UI |
| `MetricsCollector` | `metrics.rs` | `/metrics` | Prometheus-format metrics |
| `HealthChecker` | `health.rs` | `/health`, `/ready` | Health and readiness probes |
| `CostAccountant` | `cost_accounting.rs` | -- | Token usage, fuel consumption, billing |

---

### Secrets Management

**Location:** `src/secrets.rs`

Pluggable secrets storage with caching and rotation.

**Trait:**

```rust
pub trait SecretsProvider: Send + Sync {
    fn get_secret(&self, key: &str) -> Result<Option<Secret>, SecretsError>;
}
```

**Built-in providers:** `EnvSecretsProvider`, `FileSecretsProvider`, `InMemorySecretsProvider`

**Features:** Provider chaining, TTL-based caching, rotation tracking, expiration handling

---

### High-Level Integration Library

**Location:** `src/lib_integration.rs`

Builder-based API for embedding VAK into LLM-powered applications.

```rust
let runtime = VakRuntime::builder()
    .with_name("my-app")
    .with_audit_logging(true)
    .build().await?;

let agent = runtime.create_agent("agent-1").build().await?;
let result = agent.call_tool("calculator", json!({"operation": "add"})).await?;
let trail = agent.audit_trail();
```

**Types:** `VakRuntime`, `VakAgent`, `ToolDefinition`, `ToolCall`, `ToolResult`, `RiskLevel`

Supports OpenAI function-calling format and Anthropic tool-use format.

---

## Data Flow

### Tool Request Lifecycle

```
1. Agent sends ToolRequest
       │
       ▼
2. Rate Limiter check
       │ (pass)
       ▼
3. Policy Engine evaluates request
       │
       ├── Deny ──► Return error + Audit log (denied)
       │
       ▼ (Allow)
4. Audit Logger records decision
       │
       ▼
5. Dispatcher selects handler
       │
       ├── Built-in tool ──► Execute directly
       │
       └── WASM skill ──► Sandbox execution
              │
              ├── Load skill from SkillRegistry
              ├── Verify Ed25519 signature
              ├── Instantiate WASM with resource limits
              ├── Execute with fuel metering
              └── Return result or error
       │
       ▼
6. ToolResponse returned to agent
```

### Neuro-Symbolic Verification Flow (High-Stakes Actions)

```
1. Agent proposes action
       │
       ▼
2. PRM scores reasoning steps
       │ (score > threshold?)
       ├── No ──► Reject / request re-reasoning
       ▼ (Yes)
3. Datalog safety rules checked
       │ (violations?)
       ├── Yes ──► Block + report violations
       ▼ (No)
4. Z3 formal verification (if high-stakes)
       │ (satisfiable?)
       ├── No ──► Block + provide counterexample
       ▼ (Yes)
5. Action approved for execution
```

---

## Security Architecture

### Defense in Depth

```
Layer 1: Rate Limiting          Per-agent request throttling
Layer 2: Policy Engine          ABAC rules with default-deny
Layer 3: Prompt Injection       Multi-category detection
Layer 4: WASM Sandbox           Memory, CPU, timeout isolation
Layer 5: Ed25519 Signatures     Skill authenticity verification
Layer 6: Audit Chain            Tamper-evident logging
Layer 7: Formal Verification    Z3 proofs for critical actions
```

### Cryptographic Primitives

| Primitive | Usage |
|-----------|-------|
| SHA-256 | Audit entry hashing, Merkle tree nodes, request integrity |
| Ed25519 | Skill signing, audit entry signing |
| UUIDv7 | Time-ordered unique identifiers |
| Merkle DAG | Memory integrity proofs |
| HMAC-SHA256 | Skill-level authentication |

### Supply Chain

- `cargo-audit` for vulnerability scanning
- `cargo-deny` (via `deny.toml`) for license compliance
- `#![deny(unsafe_code)]` crate-wide

---

## Deployment Architecture

### Single Instance

```
┌──────────────────────────┐
│     Rust Binary (vak)    │
│  ┌────────────────────┐  │
│  │    VAK Kernel      │  │
│  │  + WASM Runtime    │  │
│  │  + SQLite Audit    │  │
│  │  + HTTP Dashboard  │  │
│  └────────────────────┘  │
└──────────────────────────┘
```

### Docker Deployment

```yaml
# docker-compose.yml provides:
# - VAK service with resource limits
# - Volume mounts for policies, audit logs, skills
# - Health check endpoint
# - Configurable via environment variables
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VAK_NAME` | Kernel instance name | `vak-kernel` |
| `VAK_MAX_CONCURRENT_AGENTS` | Max parallel agents | `10` |
| `VAK_MAX_EXECUTION_TIME_SECS` | Tool timeout (seconds) | `30` |
| `VAK_SECURITY__ENABLE_SANDBOXING` | WASM sandbox on/off | `true` |
| `VAK_SECURITY__ENABLE_RATE_LIMITING` | Rate limiting on/off | `true` |
| `VAK_SECURITY__MAX_REQUESTS_PER_MINUTE` | Rate limit | `60` |
| `VAK_AUDIT__ENABLED` | Audit logging on/off | `true` |
| `VAK_AUDIT__LOG_PATH` | Audit log file path | (in-memory) |
| `VAK_POLICY__ENABLED` | Policy enforcement on/off | `true` |
| `VAK_POLICY__DEFAULT_DECISION` | Default when no rule matches | `deny` |
| `VAK_RESOURCES__MAX_MEMORY_MB` | Memory limit per agent | `256` |

---

## Directory Structure

```
VAK/
├── src/                          # Core Rust implementation
│   ├── lib.rs                    # Crate root, module declarations, re-exports
│   ├── prelude.rs                # Convenient imports (Kernel, VakRuntime, etc.)
│   ├── kernel/                   # Core orchestration
│   │   ├── mod.rs                # Kernel struct and request dispatch
│   │   ├── types.rs              # AgentId, ToolRequest, PolicyDecision, etc.
│   │   ├── config.rs             # KernelConfig with builder pattern
│   │   ├── traits.rs             # PolicyEvaluator, AuditWriter, StateStore, ToolExecutor
│   │   ├── async_pipeline.rs     # Concurrent request processing
│   │   ├── neurosymbolic_pipeline.rs  # PRM integration pipeline
│   │   ├── rate_limiter.rs       # Token-bucket rate limiter
│   │   └── custom_handlers.rs    # User-defined tool handler registry
│   ├── policy/                   # ABAC policy engine
│   │   ├── enforcer.rs           # Cedar-style policy evaluation
│   │   ├── context.rs            # Dynamic context injection
│   │   ├── hot_reload.rs         # Live policy updates (arc-swap)
│   │   └── analyzer.rs           # Policy conflict detection
│   ├── audit/                    # Immutable audit logging
│   │   ├── flight_recorder.rs    # Shadow-mode recording
│   │   ├── replay.rs             # Cryptographic replay
│   │   ├── graphql.rs            # Query API
│   │   ├── otel.rs               # OpenTelemetry tracing
│   │   ├── streaming.rs          # Live event streaming
│   │   ├── s3_backend.rs         # Cloud archival
│   │   └── multi_region.rs       # Cross-region replication
│   ├── memory/                   # 3-tier memory system
│   │   ├── merkle_dag.rs         # Merkle DAG with rs_merkle
│   │   ├── episodic.rs           # Episode chain
│   │   ├── vector_store.rs       # Embedding search
│   │   ├── knowledge_graph.rs    # Entity-relationship graph
│   │   ├── time_travel.rs        # Snapshot/rollback
│   │   ├── sparse_merkle.rs      # Sparse Merkle proofs
│   │   └── secret_scrubber.rs    # Secret redaction
│   ├── sandbox/                  # WASM execution
│   │   ├── epoch_ticker.rs       # Cooperative preemption
│   │   ├── pooling.rs            # Memory pool allocator
│   │   ├── registry.rs           # Skill registry
│   │   ├── host_funcs.rs         # Host function bridge
│   │   └── marketplace.rs        # Skill marketplace
│   ├── reasoner/                 # Neuro-symbolic reasoning
│   │   ├── prm.rs                # Process Reward Model
│   │   ├── datalog.rs            # Datalog safety engine
│   │   ├── z3_verifier.rs        # SMT solver
│   │   ├── hybrid_loop.rs        # Neural + symbolic orchestration
│   │   ├── tree_search.rs        # MCTS Tree of Thoughts
│   │   └── prompt_injection.rs   # Injection detection
│   ├── llm/                      # LLM provider abstraction
│   │   ├── traits.rs             # LlmProvider trait
│   │   ├── litellm.rs            # LiteLLM client
│   │   └── mock.rs               # Mock for testing
│   ├── swarm/                    # Multi-agent coordination
│   │   ├── a2a.rs                # Agent-to-Agent protocol
│   │   ├── voting.rs             # Quadratic voting
│   │   ├── consensus.rs          # Consensus mechanisms
│   │   └── sycophancy.rs         # Groupthink detection
│   ├── integrations/             # Framework adapters
│   │   ├── langchain.rs          # LangChain middleware
│   │   ├── autogpt.rs            # AutoGPT adapter
│   │   └── mcp.rs                # MCP JSON-RPC server
│   ├── dashboard/                # Observability
│   │   ├── server.rs             # HTTP server
│   │   ├── metrics.rs            # Prometheus metrics
│   │   └── health.rs             # Health/readiness probes
│   ├── lib_integration.rs        # High-level VakRuntime API
│   ├── secrets.rs                # Secrets management
│   └── python.rs                 # PyO3 bindings (feature-gated)
│
├── agents/                       # Agent definitions (YAML)
│   ├── development/              # Code generation agents
│   └── runtime/                  # Runtime enforcement agents
│
├── policies/                     # ABAC policy files (YAML)
│   ├── default_policies.yaml     # Default deny rules
│   ├── admin/                    # Administrative policies
│   ├── data/                     # Data access policies
│   └── finance/                  # Financial operation policies
│
├── .github/skills/               # WASM skill modules
│   ├── calculator/               # Arithmetic skill
│   ├── crypto-hash/              # Hashing skill
│   ├── json-validator/           # JSON validation skill
│   ├── text-analyzer/            # Text analysis skill
│   └── regex-matcher/            # Pattern matching skill
│
├── python/                       # Python SDK
│   ├── vak/                      # Package (VakKernel, types, exceptions)
│   └── tests/                    # Python test suite
│
├── examples/                     # Usage examples (Rust + Python)
├── benches/                      # Criterion benchmarks
├── docs/                         # Additional documentation
├── instructions/                 # Agent instruction files (YAML)
├── prompts/                      # LLM prompt templates (YAML)
└── protocols/                    # Communication protocol definitions
```

---

## Further Reading

- [README.md](README.md) -- Project overview and quick start
- [API.md](API.md) -- API reference documentation
- [CONTRIBUTING.md](CONTRIBUTING.md) -- Development workflow
- [CHANGELOG.md](CHANGELOG.md) -- Version history
- [docs/python-sdk.md](docs/python-sdk.md) -- Python SDK guide
