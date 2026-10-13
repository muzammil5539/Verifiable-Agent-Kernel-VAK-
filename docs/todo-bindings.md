# VAK Python Bindings — Tracking Checklist

> **Status legend**: ✅ Done | 🔧 In Progress | ⬜ Pending
>
> Last updated: 2026-02-11

---

## 1. Core PyO3 Classes (`src/python.rs`)

### Currently Exposed (`#[pyclass]`)

| Rust Struct | Python Name | Status | Notes |
|-------------|-------------|--------|-------|
| `PyKernel` | `Kernel` | ✅ Done | Full lifecycle, agents, policy, tools, audit |
| `PyPolicyDecision` | `PolicyDecision` | ✅ Done | effect, policy_id, reason, matched_rules |
| `PyToolResponse` | `ToolResponse` | ✅ Done | request_id, success, result, error, timing |
| `PyAuditEntry` | `AuditEntry` | ✅ Done | entry_id, timestamp, level, agent_id, action |
| `PyRiskLevel` | `RiskLevel` | ✅ Done | LOW, MEDIUM, HIGH, CRITICAL constants |

### Need Wrapping — High Priority

| Rust Struct/Enum | Source File | Status | Notes |
|------------------|-------------|--------|-------|
| `PolicyRule` | `src/policy/mod.rs` | ⬜ Pending | For programmatic rule creation |
| `PolicyContext` | `src/policy/mod.rs` | ⬜ Pending | Expose context builder |
| `PolicyEffect` (Rust enum) | `src/policy/mod.rs` | ⬜ Pending | Enum → Python enum |
| `PolicyCondition` | `src/policy/mod.rs` | ⬜ Pending | Rule conditions |
| `PolicyDecision` (Rust) | `src/policy/mod.rs` | ⬜ Pending | Rich decision type |
| `SandboxConfig` | `src/sandbox/mod.rs` | ⬜ Pending | Expose timeout/memory limits |
| `SandboxError` | `src/sandbox/mod.rs` | ⬜ Pending | Map to `ToolExecutionError` |
| `KernelConfig` | `src/kernel/config.rs` | ⬜ Pending | Typed kernel configuration |
| `SecurityConfig` | `src/kernel/config.rs` | ⬜ Pending | Security settings |
| `AuditConfig` | `src/kernel/config.rs` | ⬜ Pending | Audit settings |

### Need Wrapping — Medium Priority

| Rust Struct/Enum | Source File | Status | Notes |
|------------------|-------------|--------|-------|
| `ToolDefinition` | `src/lib_integration.rs` | ⬜ Pending | OpenAI-compatible tool def |
| `ToolCall` | `src/lib_integration.rs` | ⬜ Pending | Tool invocation request |
| `ToolResult` | `src/lib_integration.rs` | ⬜ Pending | Tool invocation result |
| `VakAgent` | `src/lib_integration.rs` | ⬜ Pending | Agent runtime repr |
| `AgentBuilder` | `src/lib_integration.rs` | ⬜ Pending | Fluent agent construction |
| `VakRuntime` | `src/lib_integration.rs` | ⬜ Pending | Runtime wrapper |
| `RuntimeConfig` | `src/lib_integration.rs` | ⬜ Pending | Runtime configuration |
| `AuditDecision` | `src/audit/mod.rs` | ⬜ Pending | Allowed/Denied enum |
| `AuditLogger` | `src/audit/mod.rs` | ⬜ Pending | Direct logger access |
| `AuditSigner` | `src/audit/mod.rs` | ⬜ Pending | Cryptographic signing |
| `AuditReport` | `src/audit/mod.rs` | ⬜ Pending | Aggregated report |
| `ReasoningStep` | `src/reasoner/mod.rs` | ⬜ Pending | PRM scoring integration |
| `ThoughtScore` | `src/reasoner/mod.rs` | ⬜ Pending | Score results |
| `Constraint` | `src/reasoner/verifier.rs` | ⬜ Pending | Formal verification |
| `ConstraintKind` | `src/reasoner/verifier.rs` | ⬜ Pending | LessThan, GreaterThan, etc. |
| `VerificationResult` | `src/reasoner/verifier.rs` | ⬜ Pending | is_satisfied() |
| `RateLimitConfig` | `src/kernel/rate_limiter.rs` | ⬜ Pending | Rate limiting configuration |
| `LimitResult` | `src/kernel/rate_limiter.rs` | ⬜ Pending | Rate limit check result |

### Need Wrapping — Low Priority

| Rust Struct/Enum | Source File | Status | Notes |
|------------------|-------------|--------|-------|
| `CompletionRequest` | `src/llm/traits.rs` | ⬜ Pending | LLM request builder |
| `CompletionResponse` | `src/llm/traits.rs` | ⬜ Pending | LLM response |
| `Message` / `Role` | `src/llm/traits.rs` | ⬜ Pending | Chat message types |
| `LlmConfig` | `src/llm/traits.rs` | ⬜ Pending | Provider configuration |
| `SecretsManager` | `src/secrets.rs` | ⬜ Pending | Secrets provider access |
| `Secret` | `src/secrets.rs` | ⬜ Pending | Secret value holder |
| `SecretScrubber` | `src/memory/secret_scrubber.rs` | ⬜ Pending | PII scrubbing |
| `MerkleDag` | `src/memory/merkle_dag.rs` | ⬜ Pending | Memory proofs |
| `KnowledgeGraph` | `src/memory/knowledge_graph.rs` | ⬜ Pending | Semantic memory |
| `SycophancyAnalysis` | `src/swarm/sycophancy.rs` | ⬜ Pending | Multi-agent analysis |
| `GateDecision` | `src/reasoner/prm_gating.rs` | ⬜ Pending | PRM gating results |
| `PromptInjectionDetector` | `src/reasoner/prompt_injection.rs` | ⬜ Pending | Security analysis |
| `AutoGPTAdapter` | `src/integrations/autogpt.rs` | ⬜ Pending | Framework integration |
| `GoalAnalysis` | `src/integrations/autogpt.rs` | ⬜ Pending | Task verification |
| `TraceContext` | `src/audit/otel.rs` | ⬜ Pending | OpenTelemetry tracing |
| `Span` | `src/audit/otel.rs` | ⬜ Pending | Trace spans |
| `VakTracer` | `src/audit/otel.rs` | ⬜ Pending | Tracer factory |
| `StreamEvent` | `src/audit/streaming.rs` | ⬜ Pending | Audit stream events |
| `AuditStreamManager` | `src/audit/streaming.rs` | ⬜ Pending | Stream management |
| `Principal` | `src/policy/enforcer.rs` | ⬜ Pending | Cedar-style principal |
| `Decision` | `src/policy/enforcer.rs` | ⬜ Pending | Enforcer decision |
| `CedarEnforcer` | `src/policy/enforcer.rs` | ⬜ Pending | Cedar policy engine |
| `PolicyAnalyzer` | `src/policy/analyzer.rs` | ⬜ Pending | Policy analysis |
| `AnalysisReport` | `src/policy/analyzer.rs` | ⬜ Pending | Analysis results |
| `HotReloadablePolicyEngine` | `src/policy/hot_reload.rs` | ⬜ Pending | Live policy reload |
| `NeuroSymbolicPipeline` | `src/kernel/neurosymbolic_pipeline.rs` | ⬜ Pending | NS pipeline |
| `ProposedAction` | `src/kernel/neurosymbolic_pipeline.rs` | ⬜ Pending | Action proposals |
| `PrmScore` | `src/kernel/neurosymbolic_pipeline.rs` | ⬜ Pending | PRM scoring |
| `AsyncPipeline` | `src/kernel/async_pipeline.rs` | ⬜ Pending | Async execution |
| `CustomHandlerRegistry` | `src/kernel/custom_handlers.rs` | ⬜ Pending | Custom handlers |

---

## 2. Python SDK Wrappers (`python/vak/`)

| Component | File | Status | Notes |
|-----------|------|--------|-------|
| `VakKernel` class | `__init__.py` | ✅ Done | Full wrapper with session + agent_context |
| `AgentConfig` dataclass | `types.py` | ✅ Done | with_capability(), with_tool_access() |
| `ToolRequest` dataclass | `types.py` | ✅ Done | |
| `ToolResponse` dataclass | `types.py` | ✅ Done | unwrap() method |
| `PolicyDecision` dataclass | `types.py` | ✅ Done | is_allowed(), is_denied() |
| `PolicyEffect` enum | `types.py` | ✅ Done | ALLOW, DENY, AUDIT |
| `AuditEntry` dataclass | `types.py` | ✅ Done | to_dict() |
| `AuditLevel` enum | `types.py` | ✅ Done | DEBUG, INFO, WARNING, ERROR, CRITICAL |
| `VakError` exception | `__init__.py` | ✅ Done | Base exception |
| `PolicyViolationError` | `__init__.py` | ✅ Done | With policy_id, reason attrs |
| `AgentNotFoundError` | `__init__.py` | ✅ Done | With agent_id attr |
| `ToolExecutionError` | `__init__.py` | ✅ Done | With tool_id, execution_time_ms attrs |
| `AuditError` | `__init__.py` | ✅ Done | For audit chain failures |
| `RiskLevel` constants | `__init__.py` | ✅ Done | LOW, MEDIUM, HIGH, CRITICAL |
| `_StubKernel` fallback | — | Removed | Answered for the kernel without one (ADR 0011); without the native module, kernel methods raise |
| `_AgentContext` helper | `__init__.py` | ✅ Done | Scoped agent operations |
| `session()` ctx manager | `__init__.py` | ✅ Done | Auto register/unregister |

---

## 3. Type Stubs (`.pyi`)

| File | Status | Notes |
|------|--------|-------|
| `python/vak/_vak_native.pyi` | ✅ Done | Full stubs for all 6 exposed classes |
| `python/vak/py.typed` | ✅ Done | PEP 561 marker file |

---

## 4. Documentation

| Document | Status | Notes |
|----------|--------|-------|
| `README_PYTHON.md` | ✅ Done | Getting started, async, FastAPI, testing |
| Rust `///` → Python `__doc__` | ✅ Done | PyO3 auto-converts doc comments |
| `.pyi` docstrings (PEP 257) | ✅ Done | Full docstrings on all stubs |
| `TODO_BINDINGS.md` | ✅ Done | This file |

---

## 5. Build System

| Task | Status | Notes |
|------|--------|-------|
| `pyproject.toml` (maturin) | ✅ Done | `maturin develop --features python` |
| `Cargo.toml` optional pyo3 | ✅ Done | `python` feature flag |
| CI: build + test wheels | ⬜ Pending | GitHub Actions workflow |
| CI: publish to PyPI | ⬜ Pending | On tag push |

---

## 6. Testing

| Test Suite | File | Status | Notes |
|------------|------|--------|-------|
| Kernel unit tests | `python/tests/test_kernel.py` | ✅ Done | |
| Type conversion tests | `python/tests/test_types.py` | ✅ Done | |
| Integration tests | `python/tests/test_integration.py` | ✅ Done | |
| Code auditor tests | `python/tests/test_code_auditor.py` | ✅ Done | |
| Rust-side PyO3 tests | `src/python.rs` | ✅ Done | `#[cfg(test)]` |
| Async pattern tests | `python/tests/test_async.py` | ⬜ Pending | run_in_executor |
| Mypy strict validation | CI | ⬜ Pending | `mypy --strict` |

---

## 7. Priority Roadmap

### Phase 1 — Core (Current) ✅

- [x] Kernel lifecycle (init, shutdown)
- [x] Agent CRUD (register, unregister, get, list)
- [x] Policy evaluation (evaluate, add_rule, validate)
- [x] Tool execution (execute, register_skill, list)
- [x] Audit logging (create, query, verify chain)
- [x] Type stubs with PEP 257 docstrings
- [x] Exception hierarchy (VakError → specialised)
- [x] RiskLevel exposure
- [x] Context managers (session, agent_context)

### Phase 2 — Policy & Config

- [ ] Expose `PolicyRule` / `PolicyCondition` for programmatic rule authoring
- [ ] Expose `KernelConfig` / `SecurityConfig` / `AuditConfig`
- [ ] Expose `RateLimitConfig` for rate limiting
- [ ] Expose `HotReloadablePolicyEngine` for live policy updates

### Phase 3 — Reasoning & Verification

- [ ] Expose `ReasoningStep` / `ThoughtScore` for PRM
- [ ] Expose `Constraint` / `ConstraintVerifier` for formal verification
- [ ] Expose `GateDecision` for PRM gating
- [ ] Expose `PromptInjectionDetector`
- [ ] Expose `NeuroSymbolicPipeline`

### Phase 4 — Memory & Audit Advanced

- [ ] Expose `MerkleDag` for memory proofs
- [ ] Expose `KnowledgeGraph` for semantic memory
- [ ] Expose `SecretScrubber` for PII redaction
- [ ] Expose `SecretsManager`
- [ ] Expose `TraceContext` / `VakTracer` for OpenTelemetry
- [ ] Expose `AuditStreamManager` for event streaming

### Phase 5 — Integrations

- [ ] Expose `AutoGPTAdapter`
- [ ] Expose `ToolDefinition` (OpenAI/Anthropic format)
- [ ] Add LangChain/CrewAI convenience wrappers
- [ ] Async-native support (pyo3-asyncio when stable)

---

*Tracking file for VAK Python bindings. Update status as work progresses.*
