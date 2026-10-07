# VAK API Reference

> **Verifiable Agent Kernel (VAK) v1.0.0** -- Complete API Reference

---

## Table of Contents

- [Crate Root Exports](#crate-root-exports)
- [Kernel API](#kernel-api)
  - [Kernel](#kernel)
  - [KernelConfig](#kernelconfig)
  - [Core Types](#core-types)
  - [Core Traits](#core-traits)
  - [Error Types](#error-types)
  - [Rate Limiter](#rate-limiter)
  - [Custom Handlers](#custom-handlers)
  - [Neuro-Symbolic Pipeline](#neuro-symbolic-pipeline)
- [Policy API](#policy-api)
  - [CedarEnforcer](#cedarenforcer)
  - [HotReloadablePolicyEngine](#hotreloadablepolicyengine)
  - [PolicyAnalyzer](#policyanalyzer)
- [Audit API](#audit-api)
  - [AuditEntry](#auditentry)
  - [AuditLogger](#auditlogger)
  - [FlightRecorder](#flightrecorder)
- [Memory API](#memory-api)
  - [MerkleDag](#merkledag)
  - [EpisodicMemory](#episodicmemory)
  - [VectorStore](#vectorstore)
  - [KnowledgeGraph](#knowledgegraph)
  - [TimeTravelDebugger](#timetraveldebugger)
- [Sandbox API](#sandbox-api)
  - [WasmSandbox](#wasmsandbox)
  - [SandboxConfig](#sandboxconfig)
  - [SkillRegistry](#skillregistry)
  - [Verified Publishers](#verified-publishers)
- [Reasoner API](#reasoner-api)
  - [ProcessRewardModel](#processrewardmodel)
  - [SafetyEngine](#safetyengine)
  - [Z3Verifier](#z3verifier)
  - [HybridReasoningLoop](#hybridreasoningloop)
  - [ZkProver & ZkVerifier](#zkprover--zkverifier)
  - [PrmToolkit](#prmtoolkit)
- [Constitution API](#constitution-api)
  - [ConstitutionalEngine](#constitutionalengine)
  - [Constitution & Rules](#constitution--rules)
- [LLM API](#llm-api)
  - [LlmProvider Trait](#llmprovider-trait)
  - [CompletionRequest](#completionrequest)
  - [ConstrainedDecoder](#constraineddecoder)
- [Swarm API](#swarm-api)
  - [A2AProtocol](#a2aprotocol)
  - [QuadraticVoting](#quadraticvoting)
  - [SycophancyDetector](#sycophancydetector)
- [Integration API](#integration-api)
  - [VakRuntime](#vakruntime)
  - [VakAgent](#vakagent)
  - [McpServer](#mcpserver)
  - [LangChainAdapter](#langchainadapter)
  - [AutoGPTAdapter](#autogptadapter)
- [Dashboard API](#dashboard-api)
- [Secrets API](#secrets-api)
- [Python SDK API](#python-sdk-api)
- [Configuration Reference](#configuration-reference)
- [Error Codes](#error-codes)

---

## Crate Root Exports

The `vak` crate re-exports commonly used types at the root level:

```rust
// Direct imports
use vak::{
    AgentId, SessionId, AuditId, AuditEntry,
    ToolRequest, ToolResponse, PolicyDecision,
    KernelConfig, KernelError,
};

// Prelude import (recommended)
use vak::prelude::*;
// Includes: Kernel, KernelConfig, AgentId, SessionId, AuditId,
//           AuditEntry, ToolRequest, ToolResponse, PolicyDecision,
//           KernelError, VakRuntime, VakAgent, ToolDefinition,
//           ToolCall, ToolResult, SecretsManager, SecretsProvider
```

**Feature flags:**

| Flag | Description |
|------|-------------|
| `default` | Core functionality only |
| `python` | Enable PyO3 Python bindings |

**Library version:**

```rust
let version_str: &str = vak::VERSION;           // "1.0.0"
let (major, minor, patch) = vak::version();      // (1, 0, 0)
```

---

## Kernel API

### Kernel

**Module:** `vak::kernel`

The central execution engine.

```rust
use vak::kernel::{Kernel, KernelConfig};

// Create
let kernel = Kernel::new(KernelConfig::default()).await?;

// Execute a tool
let response = kernel.execute(&agent_id, &session_id, request).await?;

// Evaluate policy without executing
let decision = kernel.evaluate_policy(&agent_id, &request).await;

// Get audit log
let entries: Vec<AuditEntry> = kernel.get_audit_log().await;

// List available tools
let tools: Vec<String> = kernel.list_tools().await;

// Get active session count
let count: usize = kernel.active_session_count().await;

// Access config
let config: &KernelConfig = kernel.config();
```

**Methods:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `new` | `async fn new(config: KernelConfig) -> Result<Self, KernelError>` | Creates a kernel instance. Validates config, loads skills, configures sandbox. |
| `execute` | `async fn execute(&self, agent_id: &AgentId, session_id: &SessionId, request: ToolRequest) -> Result<ToolResponse, KernelError>` | Runs the mediation pipeline: admit, budget, decide, record the decision, execute, record the outcome, respond with an `AuditReceipt`. Refusals at any stage are recorded. |
| `evaluate_policy` | `async fn evaluate_policy(&self, agent_id: &AgentId, request: &ToolRequest) -> PolicyDecision` | The Decide stage alone, with the agent's record as principal. No admission, budget or audit. |
| `register_agent` | `async fn register_agent(&self, record: AgentRecord) -> Result<(), KernelError>` | Adds or replaces an agent record: attributes, status, own tool scope. |
| `end_session` | `async fn end_session(&self, session_id: &SessionId) -> bool` | Releases a session's binding to its agent. |
| `get_audit_log` | `async fn get_audit_log(&self) -> Vec<AuditEntry>` | Returns all audit entries: decisions, and outcomes (`outcome` set). |
| `audit_tree_head` | `async fn audit_tree_head(&self) -> SignedTreeHead` | Current Merkle tree head, signed with the kernel's Ed25519 key. |
| `prove_audit_inclusion` / `prove_audit_consistency` | `async fn(&self, u64, u64) -> Result<_, KernelError>` | RFC 9162 proofs, verifiable without trusting the kernel. |
| `list_tools` | `async fn list_tools(&self) -> Vec<String>` | Lists built-in tools, registered host handlers and WASM skills. |
| `active_session_count` | `async fn active_session_count(&self) -> usize` | Returns the number of sessions bound to an agent. |
| `config` | `fn config(&self) -> &KernelConfig` | Returns kernel configuration reference. |

### KernelBuilder and ports

`Kernel::builder(config)` injects an implementation for any pipeline stage. Anything
not supplied is built from `config`, as `Kernel::new` would. See `docs/adr/0003`.

```rust
use vak::kernel::{AgentRecord, InMemoryAgentRegistry, Kernel, KernelConfig};

let registry = Arc::new(InMemoryAgentRegistry::new());
let kernel = Kernel::builder(config)
    .with_agent_registry(registry.clone())   // Admit: Arc<dyn AgentRegistry>
    .with_budget(budget)                     // Budget: Arc<dyn Budget>
    .with_policy(pdp)                        // Decide: Arc<dyn PolicyDecisionPoint>
    .with_audit_log(log)                     // Record: Arc<dyn AuditLog>
    .with_audit_signing_key(key)             // signs tree heads
    .with_tool(handler)                      // Execute: impl ToolHandler
    .build()
    .await?;

kernel.register_agent(AgentRecord::new(agent_id, "billing").internal(true)
    .with_allowed_tools(["invoice_lookup"])).await?;
registry.suspend(&agent_id, "key rotated").await?;  // refused from the next request
```

| Port | Default | Selected by |
|------|---------|-------------|
| `AgentRegistry` | `InMemoryAgentRegistry` (unknown agents get an anonymous record) | `security.require_registered_agents` refuses unknown agents |
| `Budget` | `AgentRateBudget::per_minute(n)` | `security.enable_rate_limiting`, `security.max_requests_per_minute` |
| `PolicyDecisionPoint` | `CedarPolicy` (feature `cedar`), `EnforcerPolicy` (YAML) or `ConfigPolicy`; `DenyAll` if configured policies don't load | `policy.format`, `policy.policy_paths`, `policy.cedar_schema` |
| `AuditLog` | `FileAuditLog` (JSONL) or `SqliteAuditLog`, else `MemoryAuditLog` | `audit.log_path`, `audit.format` (`jsonl` or `sqlite`) |

---

### KernelConfig

**Module:** `vak::kernel::config`

Builder-based configuration.

```rust
use vak::kernel::config::{KernelConfig, SecurityConfig, AuditConfig, PolicyConfig, ResourceConfig};
use std::time::Duration;

// Default configuration
let config = KernelConfig::default();

// Builder pattern
let config = KernelConfig::builder()
    .name("production-kernel")
    .max_concurrent_agents(100)
    .max_execution_time(Duration::from_secs(60))
    .security(SecurityConfig {
        enable_sandboxing: true,
        require_signed_requests: true,
        allowed_tools: vec!["calculator".into(), "echo".into()],
        blocked_tools: vec!["shell".into()],
        enable_rate_limiting: true,
        max_requests_per_minute: 120,
    })
    .audit(AuditConfig {
        enabled: true,
        log_level: LogLevel::Info,
        log_path: Some("/var/log/vak/audit.db".into()),
        format: AuditLogFormat::Sqlite,
        include_bodies: false,
        max_log_size_bytes: 100 * 1024 * 1024,
        retention_count: 10,
    })
    .policy(PolicyConfig {
        enabled: true,
        default_decision: DefaultPolicyDecision::Deny,
        policy_paths: vec!["policies/".into()],
        enable_caching: true,
        cache_ttl_seconds: 300,
    })
    .resources(ResourceConfig {
        max_memory_mb: 256,
        max_cpu_time_ms: 10_000,
        max_connections: 10,
        max_request_size_bytes: 1_048_576,
        max_response_size_bytes: 10_485_760,
    })
    .build();

// From file (YAML or JSON)
let config = KernelConfig::from_file("vak.yaml")?;

// From environment variables
let config = KernelConfig::from_env();

// Validation
config.validate()?;
```

**Sub-configurations:**

| Struct | Key Fields |
|--------|------------|
| `SecurityConfig` | `enable_sandboxing`, `require_signed_requests`, `allowed_tools`, `blocked_tools`, `enable_rate_limiting`, `max_requests_per_minute` |
| `AuditConfig` | `enabled`, `log_level`, `log_path`, `format`, `include_bodies`, `max_log_size_bytes`, `retention_count` (the last two don't apply to the kernel's log, which is never rotated) |
| `PolicyConfig` | `enabled`, `default_decision`, `policy_paths`, `format` (`yaml` or `cedar`), `cedar_schema`, `enable_caching`, `cache_ttl_seconds` |
| `ResourceConfig` | `max_memory_mb`, `max_cpu_time_ms`, `max_connections`, `max_request_size_bytes`, `max_response_size_bytes` |

**Defaults:**

| Setting | Default |
|---------|---------|
| `name` | `"vak-kernel"` |
| `max_concurrent_agents` | `10` |
| `max_execution_time` | `30s` |
| `enable_sandboxing` | `true` |
| `enable_rate_limiting` | `true` |
| `max_requests_per_minute` | `60` |
| `audit.enabled` | `true` |
| `policy.enabled` | `true` |
| `policy.default_decision` | `Deny` |
| `resources.max_memory_mb` | `256` |

---

### Core Types

**Module:** `vak::kernel::types`

#### AgentId

UUIDv7 unique agent identifier.

```rust
let id = AgentId::new();                          // Generate new
let id = AgentId::from_uuid(uuid);                // From existing UUID
let id = AgentId::parse("550e8400-...")?;         // Parse from string
let uuid: Uuid = id.as_uuid();                    // Get underlying UUID
println!("{}", id);                                // "agent-550e8400-..."
```

#### SessionId

UUIDv7 session identifier. Same API as `AgentId`.

```rust
let sid = SessionId::new();
let sid = SessionId::parse("...")?;
```

#### AuditId

UUIDv7 audit entry identifier. Same API as `AgentId`.

#### ToolRequest

Request from an agent to execute a tool.

```rust
let request = ToolRequest::new("calculator", json!({
    "operation": "add",
    "operands": [1, 2, 3]
}));

// With timeout
let request = ToolRequest::new("slow_tool", json!({}))
    .with_timeout(5000);  // 5 seconds

// Compute integrity hash
let hash: String = request.compute_hash();  // SHA-256 hex string
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | `Uuid` | Auto-generated unique request ID |
| `tool_name` | `String` | Name of the tool to execute |
| `parameters` | `serde_json::Value` | JSON parameters |
| `timeout_ms` | `Option<u64>` | Optional timeout in milliseconds |

#### ToolResponse

Result of tool execution.

```rust
// Success constructor
let response = ToolResponse::success(request_id, json!({"result": 42}), 15);

// Failure constructor
let response = ToolResponse::failure(request_id, "division by zero", 3);
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `request_id` | `Uuid` | Matching request ID |
| `success` | `bool` | Whether execution succeeded |
| `result` | `Option<Value>` | Result data (if success) |
| `error` | `Option<String>` | Error message (if failure) |
| `execution_time_ms` | `u64` | Wall-clock execution time |

#### PolicyDecision

Outcome of policy evaluation.

```rust
match decision {
    PolicyDecision::Allow { reason, constraints } => {
        // Action permitted, constraints may apply
    }
    PolicyDecision::Deny { reason, violated_policies } => {
        // Action blocked
    }
    PolicyDecision::Inadmissible { reason } => {
        // Cannot evaluate (missing context)
    }
}

// Helper methods
decision.is_allowed();       // bool
decision.is_denied();        // bool
decision.is_inadmissible();  // bool
decision.reason();           // &str
```

---

### Core Traits

**Module:** `vak::kernel::traits`

#### PolicyEvaluator

```rust
#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    async fn evaluate(
        &self,
        request: &ToolRequest,
        context: &PolicyContext,
    ) -> Result<TraitPolicyDecision, KernelError>;
}
```

#### AuditWriter

```rust
#[async_trait]
pub trait AuditWriter: Send + Sync {
    async fn write_entry(&self, entry: TraitAuditEntry) -> Result<(), KernelError>;
}
```

#### StateStore

```rust
#[async_trait]
pub trait StateStore: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KernelError>;
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<(), KernelError>;
    async fn delete(&self, key: &str) -> Result<bool, KernelError>;
    async fn exists(&self, key: &str) -> Result<bool, KernelError>;  // default impl
}
```

#### ToolExecutor

```rust
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    async fn execute(&self, request: ToolRequest) -> Result<ToolResponse, KernelError>;
}
```

**Supporting types:**

| Type | Description |
|------|-------------|
| `PolicyContext` | Contains `agent_id`, `timestamp`, `metadata` HashMap |
| `TraitPolicyDecision` | Enum: `Allow`, `Deny(String)`, `Escalate(String)` |
| `TraitAuditEntry` | Struct with `id`, `timestamp`, `agent_id`, `event_type`, `details`, `outcome` |

---

### Error Types

**Module:** `vak::kernel::types`

```rust
#[derive(Debug, Error)]
pub enum KernelError {
    InvalidConfiguration { message: String },    // E001
    PolicyViolation { policy_id, reason },        // E002
    ToolNotFound { tool_name },                   // E003
    ToolExecutionFailed { tool_name, reason },    // E004
    AgentNotFound { agent_id },                   // E005
    SessionNotFound { session_id },               // E006
    InternalError { message },                    // E007
    SerializationError(serde_json::Error),        // E008
    Timeout { timeout_ms },                       // E009
    ResourceLimitExceeded { resource, limit, requested }, // E010
    AuditProof { message },                       // E011
    AgentSuspended { agent_id, reason },          // E012
    SessionConflict { session_id },               // E013
    RateLimited { reason, retry_after_ms },       // E014
    AuditUnavailable { message },                 // E015
}
```

**Methods:**

| Method | Return | Description |
|--------|--------|-------------|
| `is_recoverable()` | `bool` | `true` for `Timeout`, `ResourceLimitExceeded` and `RateLimited` |
| `error_code()` | `&str` | Returns code string (E001-E015) |

---

### Rate Limiter

**Module:** `vak::kernel::rate_limiter`

Token-bucket rate limiter.

```rust
use vak::kernel::{RateLimiter, RateLimitConfig, ResourceKey, LimitResult};

let limiter = RateLimiter::new(RateLimitConfig {
    max_requests_per_minute: 60,
    ..Default::default()
});

let key = ResourceKey::Agent(agent_id);
match limiter.check(&key) {
    LimitResult::Allowed => { /* proceed */ }
    LimitResult::Limited { retry_after_ms } => { /* wait */ }
}
```

---

### Custom Handlers

**Module:** `vak::kernel::custom_handlers`

Register user-defined tool handlers at runtime.

```rust
use vak::kernel::{CustomHandlerRegistry, ToolHandler, HandlerResult};

let registry = CustomHandlerRegistry::new();

// Register a handler
registry.register("my_tool", |request| {
    HandlerResult::Ok(json!({"handled": true}))
});

// Check and execute
if let Some(handler) = registry.get("my_tool") {
    let result = handler.execute(request)?;
}
```

---

### Neuro-Symbolic Pipeline

**Module:** `vak::kernel::neurosymbolic_pipeline`

Orchestrates PRM scoring and formal verification for agent plans.

```rust
use vak::kernel::{NeuroSymbolicPipeline, PipelineConfig, AgentPlan, ProposedAction};

let pipeline = NeuroSymbolicPipeline::new(PipelineConfig::default());

let plan = AgentPlan {
    actions: vec![ProposedAction { /* ... */ }],
};

let result: ExecutionResult = pipeline.evaluate(plan).await?;
```

---

## Policy API

### Cedar policies (feature `cedar`)

**Module:** `vak::policy::cedar`; decision point `vak::kernel::CedarPolicy` (ADR 0008)

Policies in Cedar, evaluated by the `cedar-policy` crate and validated against a schema
when they load. Enable the `cedar` feature (Rust 1.89+) and set:

```yaml
policy:
  format: cedar
  policy_paths: ["policies/cedar"]        # .cedar files, or directories of them
  cedar_schema: "policies/cedar/vak.cedarschema"   # optional; this is the default
```

Every tool call reaches Cedar as:

| | |
|---|---|
| principal | `Vak::Agent::"<agent id>"`, with `internal`, `name` and the record's attributes |
| action | `Vak::Action::"<tool>"` if the schema declares it, else `Vak::Action::"call"` |
| resource | `Vak::Tool::"<tool>"`, with `restricted` (blocked) and `builtin` |
| context | `{ session, arguments }`, where `arguments` is `{}` for `call` |

```cedar
@id("forbid-dd")
forbid (principal, action in Vak::Action::"call", resource == Vak::Tool::"dd");

@id("permit-safe-tools")
permit (principal, action in Vak::Action::"call", resource) when { !resource.restricted };
```

To let policies read a tool's arguments, declare an action for it in the schema, with the
argument types (see `policies/cedar/examples/payments.cedarschema`):

```cedar
@id("finance-transfers-up-to-1000")
permit (principal, action == Vak::Action::"transfer_funds", resource)
when { principal has team && principal.team == "finance" && context.arguments.amount <= 1000 };
```

Requests that can't be decided cleanly are denied:

- a call whose arguments don't match its action's declared types, including extra
  fields and fractional numbers;
- an agent whose record carries an attribute the schema doesn't declare;
- a call on which any policy fails to evaluate.

A policy set that doesn't load (a parse or validation error, duplicate `@id`s, no
policies) makes the kernel deny everything, giving the load error as the reason.

`CedarPolicySet::load(schema, paths)` and `authorize(&CedarRequest)` use the engine
directly. `CedarPolicy::new(set, &config)` plus `KernelBuilder::with_policy` injects it.

### CedarEnforcer

**Module:** `vak::policy`

Cedar-style policy evaluation.

```rust
use vak::policy::CedarEnforcer;

let enforcer = CedarEnforcer::new();
enforcer.load_policy(yaml_str)?;

let decision = enforcer.evaluate(&request, &context).await?;
```

### HotReloadablePolicyEngine

Live policy updates using `arc-swap`.

```rust
use vak::policy::HotReloadablePolicyEngine;

let engine = HotReloadablePolicyEngine::new(initial_policies);
engine.update_policies(new_policies)?;  // Lock-free swap
let decision = engine.evaluate(&request, &context).await?;
```

### PolicyAnalyzer

Detects conflicts and coverage gaps.

```rust
use vak::policy::PolicyAnalyzer;

let analyzer = PolicyAnalyzer::new(&policies);
let report = analyzer.analyze_policies()?;
```

---

## Audit API

### AuditEntry

**Module:** `vak::kernel::types`

Immutable, hash-chained audit record.

```rust
let entry = AuditEntry::new(agent_id, session_id, "file_read", decision);

// With chain link
let entry = entry.with_previous(previous_entry.hash.clone());

// Verify integrity
assert!(entry.verify_integrity());
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `audit_id` | `AuditId` | Unique entry ID |
| `timestamp` | `DateTime<Utc>` | Creation time |
| `agent_id` | `AgentId` | Acting agent |
| `session_id` | `SessionId` | Active session |
| `action` | `String` | Action name |
| `decision` | `PolicyDecision` | Policy outcome |
| `hash` | `String` | SHA-256 of entry contents |
| `previous_hash` | `Option<String>` | Link to previous entry |

### The kernel's audit log

**Module:** `vak::kernel::audit_log`

Everything `Kernel::execute` decides or does is recorded through the `AuditLog` port,
and nothing else (ADR 0007). Each entry is a leaf of an RFC 9162 Merkle tree; see
`Kernel::audit_tree_head` and the proof methods above.

| Adapter | Selected by | Storage |
|---------|-------------|---------|
| `MemoryAuditLog` | no `audit.log_path` | In memory; lost on exit |
| `FileAuditLog` | `audit.log_path`, `audit.format: jsonl` (default) | One JSON entry per line, `fsync`ed per append |
| `SqliteAuditLog` | `audit.log_path`, `audit.format: sqlite` | One row per entry, each append a durable transaction; query with `json_extract(entry, '$.action')` |

The durable adapters verify every entry when they open and refuse a log that doesn't
verify (`AuditLogError::Corrupt`), one VAK didn't create, or one in the other format
(`AuditLogError::Format`). `Kernel::build` then fails; it never starts on a fresh log
instead. After a failed write a log refuses further appends until it is reopened, and
the kernel refuses requests (`KernelError::AuditUnavailable`) rather than run tools
unrecorded.

### AuditLogger

**Module:** `vak::audit`

A standalone hash-chained event log for events an application records itself, outside
the kernel. It is not the kernel's audit trail.

```rust
use vak::audit::{AuditDecision, AuditLogger, SqliteAuditBackend};

let backend = SqliteAuditBackend::new("/var/lib/app/events.db")?;
let mut logger = AuditLogger::with_backend(Box::new(backend))?; // verifies on open
logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed)?; // Err if not stored
logger.verify_chain()?;
let report = logger.export()?; // counts, chain_valid, legacy_entries
```

Each entry's hash (`vak::audit::entry_hash`) covers a domain tag and every field,
length-prefixed, `metadata` included. Entries written before ADR 0007 used a weaker
hash; they still verify when they come first in the log, and `report.legacy_entries`
counts them.

### FlightRecorder

Shadow-mode recording for safe testing.

```rust
let recorder = FlightRecorder::new();
recorder.record_request(&request).await;
recorder.record_response(&response).await;
let replay = recorder.replay().await;
```

---

## Memory API

### MerkleDag

**Module:** `vak::memory`

Cryptographic content-addressable storage.

```rust
use vak::memory::MerkleDag;

let mut dag = MerkleDag::new();
dag.insert("key", value)?;

let proof = dag.get_proof("key")?;     // Merkle inclusion proof
let value = dag.get("key")?;           // Retrieve by key
let root = dag.root_hash();            // Current root hash
```

### EpisodicMemory

Time-ordered episode chain.

```rust
use vak::memory::EpisodicMemory;

let mut memory = EpisodicMemory::new();
memory.record_episode(episode_data)?;
let episodes = memory.retrieve_recent(10)?;
```

### VectorStore

Embedding-based semantic search.

```rust
use vak::memory::VectorStore;

let mut store = VectorStore::new();
store.insert("doc-1", embedding, metadata)?;
let results = store.search(&query_embedding, top_k)?;
```

### KnowledgeGraph

Entity-relationship graph (`petgraph`).

```rust
use vak::memory::KnowledgeGraph;

let mut graph = KnowledgeGraph::new();
graph.add_entity("Alice", entity_data)?;
graph.add_relationship("Alice", "knows", "Bob")?;
let related = graph.query_relationships("Alice")?;
```

### TimeTravelDebugger

Snapshot and rollback.

```rust
use vak::memory::TimeTravelDebugger;

let debugger = TimeTravelDebugger::new();
let snapshot_hash = debugger.snapshot(&current_state)?;
debugger.checkout(&snapshot_hash)?;      // Rollback to snapshot
```

---

## Sandbox API

### WasmSandbox

**Module:** `vak::sandbox`

Isolated WASM execution.

```rust
use vak::sandbox::{WasmSandbox, SandboxConfig};

let config = SandboxConfig {
    memory_limit: 16 * 1024 * 1024,   // 16 MB
    fuel_limit: 1_000_000,
    timeout: Duration::from_secs(5),
};

let mut sandbox = WasmSandbox::new(config)?;
sandbox.load_skill_from_file("skill.wasm")?;
let result = sandbox.execute("execute", &json_input)?;
```

`execute` blocks until the skill returns or a limit stops it; from async code, call it on
`tokio::task::spawn_blocking`.

### SandboxRuntime

One engine, a compiled-module cache keyed by the module's SHA-256, and one epoch ticker
thread that runs only while a skill is executing. `WasmSandbox::new` builds one per
sandbox; share one instead:

```rust
use std::sync::Arc;
use vak::sandbox::{SandboxRuntime, SandboxRuntimeConfig, WasmSandbox};

let runtime = Arc::new(SandboxRuntime::new(SandboxRuntimeConfig::default())?);
let sandbox = WasmSandbox::with_runtime(runtime.clone(), config);

// The kernel builds its own on the first skill call, or takes one:
let kernel = Kernel::builder(kernel_config)
    .with_sandbox_runtime(runtime.clone())
    .with_skill_registry(registry)
    .build()
    .await?;
let stats = runtime.stats(); // compiled_modules, cache_hits, executions, ...
```

| `SandboxRuntimeConfig` field | Default | Description |
|-------|---------|-------------|
| `tick` | 10 ms | Epoch interval: the precision of the wall-clock deadline |
| `max_cached_modules` | 64 | Compiled modules kept; the oldest is evicted |
| `pooling` | `None` | `Some(PoolingConfig)` uses the pooling allocator, which reserves virtual memory up front |

### SandboxConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `memory_limit` | `usize` | 16 MB | Max memory in bytes |
| `fuel_limit` | `u64` | 1,000,000 | CPU instruction budget |
| `timeout` | `Duration` | 5s | Wall-clock timeout |

### SkillRegistry

Manifest-based skill management.

```rust
use vak::sandbox::SkillRegistry;

let mut registry = SkillRegistry::new("skills/".into());
let loaded_ids = registry.load_all_skills()?;
let manifest = registry.get_skill_by_name("calculator");
let skills = registry.list_skills();
let pinned: Option<[u8; 32]> = registry.module_digest("calculator");
```

`SkillRegistry::new` requires every skill to carry a valid signature from a trusted key;
with no trusted keys, nothing loads. Trust publishers with
`SkillRegistry::new_with_signature_config(dir, SignatureConfig::strict().with_trusted_key(hex))`,
or in the kernel with `security.trusted_skill_keys`. Loading reads the module once,
verifies the signature over those bytes, and pins the skill to their SHA-256.

### Skill signing

**Module:** `vak::sandbox::signing` (ADR 0005)

```rust
use vak::sandbox::signing::{sign_skill, module_digest, SkillSignatureVerifier};

// Publisher side (or: cargo run --example sign_skill -- sign skill.yaml key.hex)
sign_skill(&mut manifest, &module_bytes, &signing_key)?;   // sets signed_by, signature

// Kernel side
let verifier = SkillSignatureVerifier::try_new(
    SignatureConfig::strict().with_trusted_key(publisher_public_key_hex),
)?;
let verified = verifier.verify(&manifest, &module_digest(&module_bytes))?;
```

The signed statement is `vak.skill-signature.v1\n` followed by the canonical JSON (sorted
keys, no whitespace) of `author`, `description`, `input_schema`, `module_sha256`, `name`,
`output_schema`, `permissions` and `version`. `wasm_path` is not signed: the module is
bound by its digest.

| `KernelConfig` field | Default | Effect |
|---|---|---|
| `security.skills_path` | unset | Skill manifest directory; else `VAK_SKILLS_PATH`, `.github/skills`, `skills` |
| `security.trusted_skill_keys` | empty | Hex Ed25519 public keys whose signatures are trusted. A key that doesn't parse fails `Kernel::build` |
| `security.allow_unsigned_skills` | `false` | Load unsigned skills (development only). A bad signature is refused regardless |

### Verified Publishers

**Module:** `vak::sandbox::verified_publisher`

Publisher verification, reputation tracking, and skill marketplace.

```rust
use vak::sandbox::verified_publisher::{
    PublisherRegistry, PublisherProfile, PublisherConfig,
    VerificationRequest, VerificationMethod, TrustLevel,
    PublishedSkill, ReportReason,
};

// Create registry
let registry = PublisherRegistry::new(PublisherConfig::default());

// Register publisher
let profile = PublisherProfile::new("acme-corp", "ACME Corp", "dev@acme.com")
    .with_website("https://acme.com")
    .with_description("Enterprise tools publisher");
let id = registry.register(profile)?;

// Request and complete verification
let request = VerificationRequest::github_org("acme-corp", "acme-org");
registry.request_verification("acme-corp", request)?;
registry.complete_verification(
    "acme-corp",
    VerificationMethod::GithubOrg { org_name: "acme-org".into() },
    true,
    "Verified via GitHub API",
)?;

// Publish a skill
let skill = PublishedSkill { /* ... */ };
registry.publish_skill("acme-corp", skill)?;

// Report malicious skill
registry.report_skill("skill-id", "reporter", ReportReason::Malicious, "description")?;

// Scan WASM binary
let scan = registry.scan_skill(&wasm_bytes);

// Query reputation
let rep = registry.get_reputation("acme-corp")?;
```

**Key types:**

| Type | Description |
|------|-------------|
| `PublisherRegistry` | Central registry for publishers and skills |
| `PublisherProfile` | Publisher identity, trust level, verifications |
| `PublisherConfig` | Registry configuration (thresholds, requirements) |
| `VerificationRequest` | Request for identity verification |
| `VerificationMethod` | `GithubOrg`, `GpgKey`, `DomainOwnership`, `Email` |
| `TrustLevel` | `Unverified` → `Basic` → `Verified` → `Trusted` → `Official` |
| `PublishedSkill` | Published WASM skill with metadata and signatures |
| `SkillReport` | Report against a malicious skill |
| `ScanResult` | Vulnerability scan output with issues |
| `PublisherReputation` | Aggregated reputation details |

**PublisherRegistry methods:**

| Method | Description |
|--------|-------------|
| `register(profile)` | Register a new publisher |
| `get_publisher(id)` | Get publisher profile |
| `request_verification(id, request)` | Start verification flow |
| `complete_verification(id, method, success, details)` | Complete verification |
| `publish_skill(publisher_id, skill)` | Publish a skill |
| `report_skill(skill_id, reporter, reason, desc)` | Report malicious skill |
| `scan_skill(wasm_bytes)` | Scan WASM binary for vulnerabilities |
| `get_reputation(id)` | Get publisher reputation details |
| `update_reputation(id, delta)` | Adjust reputation score |
| `list_publishers(min_trust_level)` | List publishers by trust level |
| `get_reports(skill_id)` | Get reports for a skill |

---

## Reasoner API

### ProcessRewardModel

Scores reasoning steps.

```rust
use vak::reasoner::{ProcessRewardModel, ReasoningStep};

let prm = ProcessRewardModel::new(llm_provider);
let score = prm.score_step(&step, &context).await?;
// Returns ThoughtScore { score: f64, confidence: f64 }
```

### SafetyEngine

Datalog-based safety rule evaluation.

```rust
use vak::reasoner::{SafetyEngine, SafetyRule, Fact};

let engine = SafetyEngine::new();
engine.add_rule(SafetyRule { /* ... */ })?;
engine.add_fact(Fact { /* ... */ })?;

let verdict = engine.check_violations(&facts)?;
// Returns SafetyVerdict with list of Violations
```

### Z3Verifier

SMT formal verification.

```rust
use vak::reasoner::Z3Verifier;

let verifier = Z3Verifier::new();
let result = verifier.verify(&constraint, &context).await?;
```

### HybridReasoningLoop

Orchestrates neural + symbolic reasoning.

```rust
use vak::reasoner::HybridReasoningLoop;

let loop_ = HybridReasoningLoop::new(prm, safety_engine, verifier);
let plan = loop_.reason(&goal, &context).await?;
// Returns ExecutionPlan with validated actions
```

### ZkProver & ZkVerifier

**Module:** `vak::reasoner::zk_proof`

Zero-knowledge proof generation and verification. Enables agents to prove properties about their actions without revealing sensitive details.

```rust
use vak::reasoner::zk_proof::{
    ZkProver, ZkVerifier, ZkStatement, ProofConfig, ProofRegistry,
};

// Create prover and verifier
let config = ProofConfig::default();
let prover = ZkProver::new(config.clone());
let verifier = ZkVerifier::new(config);

// Policy compliance proof
let statement = ZkStatement::PolicyCompliance {
    policy_hash: "sha256-of-policy".into(),
    action_hash: "sha256-of-action".into(),
    context_hash: "sha256-of-context".into(),
};
let secret = b"the-actual-policy-evaluation-data";
let proof = prover.prove(&statement, secret)?;
assert!(verifier.verify(&statement, &proof)?);

// Range proof (prove value is in bounds without revealing it)
let statement = ZkStatement::RangeProof {
    value_commitment: commit_value(42, b"nonce"),
    min: 0,
    max: 100,
    domain: "transaction_amount".into(),
};
let proof = prover.prove(&statement, &42u64.to_le_bytes())?;
assert!(verifier.verify(&statement, &proof)?);

// Proof registry for batch verification
let mut registry = ProofRegistry::new();
registry.register(proof)?;
let valid_count = registry.verify_all(&verifier);
```

**Statement types:**

| Type | Description |
|------|-------------|
| `PolicyCompliance` | Prove an action was policy-compliant |
| `AuditIntegrity` | Prove audit log integrity |
| `StateTransition` | Prove valid state transitions |
| `IdentityAttribute` | Prove agent identity attributes |
| `RangeProof` | Prove a value is within bounds |
| `SetMembership` | Prove membership in a set |

**Key types:**

| Type | Description |
|------|-------------|
| `ZkProver` | Generates zero-knowledge proofs |
| `ZkVerifier` | Verifies proofs without seeing secrets |
| `ZkStatement` | Statement to prove (6 variants) |
| `ZkProof` | Generated proof with metadata |
| `ProofRegistry` | Registry for batch proof management |
| `ProofConfig` | Configuration (max proof size, TTL) |

### PrmToolkit

**Module:** `vak::reasoner::prm_toolkit`

Tools for evaluating, calibrating, and fine-tuning Process Reward Models.

```rust
use vak::reasoner::prm_toolkit::{
    PrmToolkit, EvaluationDataset, TrainingExample,
};

let toolkit = PrmToolkit::new();

// Load dataset
let mut dataset = EvaluationDataset::new("my-dataset");
dataset.add_example(TrainingExample {
    input: "Is 2+2=5?".into(),
    reasoning_steps: vec!["Check arithmetic".into()],
    predicted_score: 0.2,
    ground_truth: false,
    metadata: Default::default(),
});

// Evaluate model performance
let metrics = toolkit.evaluate(&dataset)?;
println!("Accuracy: {:.2}", metrics.accuracy);
println!("F1: {:.2}", metrics.f1_score);
println!("AUROC: {:.2}", metrics.auroc);
println!("ECE: {:.4}", metrics.expected_calibration_error);

// Find optimal threshold
let threshold = toolkit.find_optimal_threshold(&dataset, 100)?;

// Calibration analysis
let calibration = toolkit.calibration_analysis(&dataset, 10)?;

// Compare two models
let report = toolkit.compare_models(&dataset_a, &dataset_b)?;

// Export for fine-tuning
let examples = toolkit.export_fine_tuning_data(&dataset)?;

// Generate prompt template
let template = toolkit.generate_prompt_template(&dataset)?;
```

**EvaluationMetrics fields:**

| Field | Type | Description |
|-------|------|-------------|
| `accuracy` | `f64` | Overall accuracy |
| `precision` | `f64` | True positives / (true + false positives) |
| `recall` | `f64` | True positives / (true + false negatives) |
| `f1_score` | `f64` | Harmonic mean of precision and recall |
| `auroc` | `f64` | Area under ROC curve (trapezoidal) |
| `expected_calibration_error` | `f64` | ECE across calibration bins |
| `mean_absolute_error` | `f64` | MAE of predicted scores |
| `root_mean_squared_error` | `f64` | RMSE of predicted scores |

**PrmToolkit methods:**

| Method | Description |
|--------|-------------|
| `evaluate(dataset)` | Compute all metrics |
| `calibration_analysis(dataset, bins)` | Analyze prediction calibration |
| `compare_models(dataset_a, dataset_b)` | A/B comparison report |
| `find_optimal_threshold(dataset, steps)` | Search for best threshold |
| `export_fine_tuning_data(dataset)` | Export JSONL for LLM fine-tuning |
| `generate_prompt_template(dataset)` | Generate PRM prompt template |

---

## Constitution API

### ConstitutionalEngine

**Module:** `vak::kernel::constitution`

Immutable safety governance layer that enforces fundamental principles on all agent actions.

```rust
use vak::kernel::constitution::{
    ConstitutionalEngine, Constitution, ConstitutionalRule,
    Principle, EnforcementPoint, ConstitutionalDecision,
};

// Create with default safety constitution
let engine = ConstitutionalEngine::new_with_defaults();

// Evaluate an action
let context = serde_json::json!({
    "action": "file_delete",
    "resource": "/etc/passwd",
    "risk_level": "critical",
});
let decision = engine.evaluate(&context, EnforcementPoint::PreExecution)?;

match decision {
    ConstitutionalDecision::Allowed => { /* proceed */ }
    ConstitutionalDecision::Blocked { rule_id, reason, principle } => {
        println!("Blocked by rule {}: {}", rule_id, reason);
    }
    ConstitutionalDecision::Warning { rule_id, reason, principle } => {
        println!("Warning from rule {}: {}", rule_id, reason);
    }
}

// Lock constitution (makes it immutable)
engine.lock()?;

// Verify integrity (detects tampering)
assert!(engine.verify_integrity()?);
```

### Constitution & Rules

```rust
// Custom constitution
let mut constitution = Constitution::new("enterprise-safety");
constitution.add_principle(Principle {
    id: "data-sovereignty".into(),
    name: "Data Sovereignty".into(),
    description: "Data must not leave approved regions".into(),
    priority: 95,
});

constitution.add_rule(ConstitutionalRule {
    id: "block-external-transfer".into(),
    principle_id: "data-sovereignty".into(),
    description: "Block data transfers to external endpoints".into(),
    enforcement_point: EnforcementPoint::PreExecution,
    condition_field: "destination".into(),
    condition_op: ConstraintOp::NotContains("internal.corp".into()),
    blocking: true,
});

let engine = ConstitutionalEngine::new(constitution);
```

**Key types:**

| Type | Description |
|------|-------------|
| `ConstitutionalEngine` | Main engine for evaluating constitutional rules |
| `Constitution` | Collection of principles and rules with integrity hash |
| `Principle` | Fundamental safety principle with priority |
| `ConstitutionalRule` | Enforceable rule linked to a principle |
| `EnforcementPoint` | `PrePolicy`, `PreExecution`, `PostExecution`, `All` |
| `ConstitutionalDecision` | `Allowed`, `Blocked`, `Warning` |
| `ConstraintOp` | Comparison operators (Equals, Contains, LessThan, All, Any, Not, etc.) |

**Default principles (priority):**

| Principle | Priority |
|-----------|----------|
| No Harm | 100 |
| Human Override | 100 |
| Transparency | 90 |
| Least Privilege | 80 |
| Data Protection | 70 |

**ConstitutionalEngine methods:**

| Method | Description |
|--------|-------------|
| `new(constitution)` | Create with custom constitution |
| `new_with_defaults()` | Create with default safety principles |
| `evaluate(context, point)` | Evaluate action against rules |
| `evaluate_all(context)` | Evaluate at all enforcement points |
| `lock()` | Make constitution immutable |
| `verify_integrity()` | Check for tampering via SHA-256 hash |
| `get_constitution()` | Get constitution reference |
| `is_locked()` | Check if locked |

---

## LLM API

### LlmProvider Trait

**Module:** `vak::llm`

```rust
#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, request: CompletionRequest)
        -> Result<CompletionResponse, LlmError>;
}
```

**Implementations:**

| Type | Description |
|------|-------------|
| `LiteLlmClient` | HTTP client for LiteLLM proxy (OpenAI, Anthropic, Ollama, etc.) |
| `MockLlmProvider` | Deterministic responses for testing |

### CompletionRequest

```rust
use vak::llm::{CompletionRequest, Message, Role};

let request = CompletionRequest {
    messages: vec![
        Message { role: Role::System, content: "You are helpful.".into() },
        Message { role: Role::User, content: "Hello".into() },
    ],
    model: Some("gpt-4".into()),
    max_tokens: Some(1000),
    temperature: Some(0.7),
    ..Default::default()
};

let response = provider.complete(request).await?;
println!("{}", response.content);
println!("Tokens used: {}", response.usage.total_tokens);
```

### ConstrainedDecoder

Grammar/schema-constrained output generation.

```rust
use vak::reasoner::ConstrainedDecoder;

let decoder = ConstrainedDecoder::new();
let output = decoder.decode(&constraints).await?;
```

**Constraint types:** `DatalogConstraint`, `JsonSchemaConstraint`, `VakActionConstraint`

---

## Swarm API

### A2AProtocol

**Module:** `vak::swarm`

Agent-to-Agent discovery and messaging.

```rust
use vak::swarm::{AgentCard, AgentCardDiscovery, A2AProtocol};

// Publish agent capabilities
let card = AgentCard {
    name: "my-agent".into(),
    capabilities: vec!["analysis".into()],
    endpoint: "https://agent.example.com".into(),
    ..Default::default()
};

// Discover remote agents
let discovery = AgentCardDiscovery::new();
let remote_card = discovery.fetch("https://remote-agent.example.com").await?;
let agents = discovery.search_by_capability("analysis");
```

### QuadraticVoting

Democratic multi-agent voting.

```rust
use vak::swarm::{QuadraticVoting, Proposal, Vote, VoteDirection};

let mut voting = QuadraticVoting::new();
let session = voting.create_session(proposal)?;

voting.cast_vote(session_id, Vote {
    voter: agent_id,
    direction: VoteDirection::For,
    weight: 3,  // costs 9 credits (quadratic)
})?;

let result = voting.tally(session_id)?;
```

### SycophancyDetector

Groupthink detection in multi-agent systems.

```rust
use vak::swarm::SycophancyDetector;

let detector = SycophancyDetector::new();
let analysis = detector.analyze_session(&session)?;
// Returns SycophancyAnalysis with risk indicators
```

---

## Integration API

### VakRuntime

**Module:** `vak::lib_integration`

High-level builder-based API.

```rust
use vak::prelude::*;

let runtime = VakRuntime::builder()
    .with_name("my-app")
    .with_audit_logging(true)
    .build().await?;
```

### VakAgent

Managed agent abstraction.

```rust
let agent = runtime.create_agent("finance-bot").build().await?;

// Execute tool
let result = agent.call_tool("calculator", json!({
    "operation": "add",
    "operands": [100, 200]
})).await?;

// Access audit trail
let trail = agent.audit_trail();

// Tool definitions (OpenAI/Anthropic format)
let tools: Vec<ToolDefinition> = agent.available_tools();
```

### McpServer

**Module:** `vak::integrations`

JSON-RPC Model Context Protocol server.

```rust
use vak::integrations::McpServer;

let server = McpServer::new(kernel);
server.register_tool(McpTool { /* ... */ })?;
server.start("0.0.0.0:3000").await?;
```

### LangChainAdapter

LangChain integration middleware.

```rust
use vak::integrations::LangChainAdapter;

let adapter = LangChainAdapter::new(kernel);
let result = adapter.intercept_tool_call(tool_name, args).await?;
```

### AutoGPTAdapter

AutoGPT integration with PRM scoring.

```rust
use vak::integrations::AutoGPTAdapter;

let adapter = AutoGPTAdapter::new(kernel);
let result = adapter.intercept_command(command).await?;
```

---

## Dashboard API

**Module:** `vak::dashboard`

HTTP observability endpoints.

```rust
use vak::dashboard::DashboardServer;

let server = DashboardServer::new(config);
server.start().await?;
```

**Endpoints:**

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/metrics` | GET | Prometheus-format metrics |
| `/health` | GET | Health check (returns 200 OK) |
| `/ready` | GET | Readiness probe |
| `/dashboard` | GET | Web UI |

---

## Secrets API

**Module:** `vak::secrets`

Pluggable secrets management.

```rust
use vak::secrets::{SecretsManager, EnvSecretsProvider, FileSecretsProvider};

let mut manager = SecretsManager::new();
manager.add_provider(EnvSecretsProvider::new());
manager.add_provider(FileSecretsProvider::new("/etc/vak/secrets"));

let secret = manager.get_secret("API_KEY")?;
manager.rotate_secret("API_KEY", new_value)?;
```

**Built-in providers:**

| Provider | Description |
|----------|-------------|
| `EnvSecretsProvider` | Reads from environment variables |
| `FileSecretsProvider` | Reads from files on disk |
| `InMemorySecretsProvider` | In-memory storage (testing) |

**SecretsProvider trait:**

```rust
pub trait SecretsProvider: Send + Sync {
    fn get_secret(&self, key: &str) -> Result<Option<Secret>, SecretsError>;
}
```

---

## Python SDK API

**Module:** `python/vak/`

### VakKernel

```python
from vak import VakKernel, AgentConfig

kernel = VakKernel()
kernel.initialize()

# Register agent
agent = AgentConfig(
    agent_id="analyst-001",
    name="Data Analyst",
    capabilities=["read", "compute"],
    metadata={"department": "research"},
)
kernel.register_agent(agent)

# Evaluate policy
decision = kernel.evaluate_policy("analyst-001", "read", {"resource": "/data"})

# Execute tool
response = kernel.execute_tool("analyst-001", "calculator", "add", {"a": 1, "b": 2})

# Audit trail
logs = kernel.get_audit_logs(agent_id="analyst-001")

# Context managers
with kernel.session(agent) as k:
    result = k.execute_tool("analyst-001", "calculator", "add", {"a": 1, "b": 2})

kernel.shutdown()
```

### Exception Hierarchy

```python
from vak import VakError, PolicyViolationError, AgentNotFoundError, ToolExecutionError, AuditError

# VakError (base)
# ├── PolicyViolationError  (policy_id, reason)
# ├── AgentNotFoundError    (agent_id)
# ├── ToolExecutionError    (tool_id, error)
# └── AuditError            (message)
```

### Types

```python
from vak import (
    AgentConfig,       # agent_id, name, description, capabilities, metadata
    ToolRequest,       # agent_id, tool_id, action, parameters
    ToolResponse,      # success, result, error, execution_time_ms
    PolicyRule,        # id, effect, principal, action, resource, conditions
    PolicyCondition,   # field, operator, value
    AuditEntry,        # id, timestamp, agent_id, action, decision
    RiskLevel,         # LOW, MEDIUM, HIGH, CRITICAL
    PolicyEffect,      # ALLOW, DENY
)
```

---

## Configuration Reference

### YAML Configuration File

```yaml
# vak.yaml
name: "production-kernel"
max_concurrent_agents: 100
max_execution_time:
  secs: 60
  nanos: 0

security:
  enable_sandboxing: true
  require_signed_requests: true
  allowed_tools: ["calculator", "echo"]
  blocked_tools: ["shell"]
  enable_rate_limiting: true
  max_requests_per_minute: 120

audit:
  enabled: true
  log_level: "info"
  log_path: "/var/log/vak/audit.db"
  format: "sqlite"   # or "jsonl" (default)
  include_bodies: false
  max_log_size_bytes: 104857600
  retention_count: 10

policy:
  enabled: true
  default_decision: "deny"
  policy_paths: ["policies/"]
  format: "yaml"     # or "cedar" (feature `cedar`)
  enable_caching: true
  cache_ttl_seconds: 300

resources:
  max_memory_mb: 256
  max_cpu_time_ms: 10000
  max_connections: 10
  max_request_size_bytes: 1048576
  max_response_size_bytes: 10485760
```

### Policy File Format

```yaml
# policies/example.yaml
rules:
  - id: "allow-read-data"
    effect: "permit"
    principal: "Agent::\"analyst-*\""
    action: "Action::\"Tool::file_read\""
    resource: "File::\"/data/*\""
    conditions:
      - field: "agent_role"
        operator: Equals
        value: "analyst"
      - field: "time_of_day"
        operator: GreaterThan
        value: 8
    priority: 100
    description: "Allow analysts to read data files during work hours"

  - id: "deny-system-files"
    effect: "forbid"
    principal: "Agent::*"
    action: "Action::\"Tool::file_*\""
    resource: "File::\"/etc/*\""
    conditions: []
    priority: 200
    description: "Block all access to system files"
```

### Skill Manifest Format

```yaml
# skill.yaml
name: my_skill
version: "0.1.0"
description: "Skill description"
author: "Author Name"
license: "MIT"
module: target/wasm32-unknown-unknown/release/my_skill.wasm
capabilities:
  - compute
limits:
  max_memory_pages: 16       # 16 * 64KB = 1MB
  max_execution_time_ms: 1000
exports:
  - name: execute
    input_schema:
      type: object
      properties:
        operation:
          type: string
    output_schema:
      type: object
```

---

## Error Codes

| Code | Error | Recoverable | Description |
|------|-------|-------------|-------------|
| E001 | `InvalidConfiguration` | No | Kernel configuration validation failed |
| E002 | `PolicyViolation` | No | Action denied by ABAC policy |
| E003 | `ToolNotFound` | No | Requested tool does not exist |
| E004 | `ToolExecutionFailed` | No | Tool execution encountered an error |
| E005 | `AgentNotFound` | No | Agent ID not registered |
| E006 | `SessionNotFound` | No | Session expired or not found |
| E007 | `InternalError` | No | Unexpected internal error |
| E008 | `SerializationError` | No | JSON serialization/deserialization failed |
| E009 | `Timeout` | Yes | Operation exceeded time limit |
| E010 | `ResourceLimitExceeded` | Yes | Memory, CPU, or connection limit exceeded |
| E011 | `AuditProof` | No | An audit proof was requested for an index or size the log doesn't have |
| E012 | `AgentSuspended` | No | The agent is registered but suspended |
| E013 | `SessionConflict` | No | The session is bound to a different agent |
| E014 | `RateLimited` | Yes | The agent is over its request budget; retry after `retry_after_ms` |
| E015 | `AuditUnavailable` | No | The decision couldn't be recorded, so the tool didn't run |

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) -- System architecture and design
- [README.md](README.md) -- Project overview and quick start
- [CONTRIBUTING.md](CONTRIBUTING.md) -- Development workflow
- [docs/python-sdk.md](docs/python-sdk.md) -- Python SDK guide
