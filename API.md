# VAK API Reference

> **Verifiable Agent Kernel (VAK) v0.1.0** -- Complete API Reference

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
- [Reasoner API](#reasoner-api)
  - [ProcessRewardModel](#processrewardmodel)
  - [SafetyEngine](#safetyengine)
  - [Z3Verifier](#z3verifier)
  - [HybridReasoningLoop](#hybridreasoningloop)
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
let version_str: &str = vak::VERSION;           // "0.1.0"
let (major, minor, patch) = vak::version();      // (0, 1, 0)
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
| `execute` | `async fn execute(&self, agent_id: &AgentId, session_id: &SessionId, request: ToolRequest) -> Result<ToolResponse, KernelError>` | Evaluates policy, logs decision, dispatches tool, returns response. |
| `evaluate_policy` | `async fn evaluate_policy(&self, agent_id: &AgentId, request: &ToolRequest) -> PolicyDecision` | Evaluates policy for a request without executing it. |
| `get_audit_log` | `async fn get_audit_log(&self) -> Vec<AuditEntry>` | Returns all audit entries. |
| `list_tools` | `async fn list_tools(&self) -> Vec<String>` | Lists built-in tools and registered WASM skills. |
| `active_session_count` | `async fn active_session_count(&self) -> usize` | Returns number of active sessions. |
| `config` | `fn config(&self) -> &KernelConfig` | Returns kernel configuration reference. |

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
        log_path: Some("/var/log/vak/audit.log".into()),
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
| `AuditConfig` | `enabled`, `log_level`, `log_path`, `include_bodies`, `max_log_size_bytes`, `retention_count` |
| `PolicyConfig` | `enabled`, `default_decision`, `policy_paths`, `enable_caching`, `cache_ttl_seconds` |
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
}
```

**Methods:**

| Method | Return | Description |
|--------|--------|-------------|
| `is_recoverable()` | `bool` | `true` for `Timeout` and `ResourceLimitExceeded` |
| `error_code()` | `&str` | Returns code string (E001-E010) |

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

### AuditLogger

Main audit system with chain management.

```rust
logger.log(agent_id, action, resource, decision).await?;
logger.verify_chain().await?;           // Verify full chain integrity
logger.export_receipt().await?;         // Generate cryptographic receipt
```

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
```

---

## Reasoner API

### ProcessRewardModel

**Module:** `vak::reasoner`

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
  log_path: "/var/log/vak/audit.log"
  include_bodies: false
  max_log_size_bytes: 104857600
  retention_count: 10

policy:
  enabled: true
  default_decision: "deny"
  policy_paths: ["policies/"]
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

---

## Further Reading

- [ARCHITECTURE.md](ARCHITECTURE.md) -- System architecture and design
- [README.md](README.md) -- Project overview and quick start
- [CONTRIBUTING.md](CONTRIBUTING.md) -- Development workflow
- [docs/python-sdk.md](docs/python-sdk.md) -- Python SDK guide
