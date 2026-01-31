# VAK Implementation TODO & Roadmap

> **Project:** Verifiable Agent Kernel (VAK) / Exo-Cortex 0.1
> **Target:** Autonomous Code Auditor MVP
> **Generated:** January 30, 2026
> **Last Refined:** January 30, 2026

---

## 🎯 Critical Path Analysis

The dependency graph reveals **LLM-001 is the critical blocker**:

```
LLM-001 (LLM Interface) ─┬─► NSR-001 (PRM) ─► NSR-003 (Tree of Thoughts)
                         │
                         └─► MEM-002 (Working Memory with summarization)

MEM-001 (Episodic Memory) ─► MEM-005 (Time Travel)

SBX-001 (Skill Registry) ─► SBX-002 (Signed Skills)

NSR-002 (Z3 Verifier) ─► [standalone, can parallel]
```

**Recommended execution order:**
1. **Week 1**: LLM-001 + MEM-001 + SBX-001 (parallel, no deps)
2. **Week 2**: NSR-001 + NSR-002 (parallel after LLM-001)
3. **Week 3**: MEM-002 + SBX-002 (depends on Week 1-2)
4. **Week 4**: PY-001 + Integration testing

---

## Quick Status Overview

| Module | Status | Completion |
|--------|--------|------------|
| Kernel Core | ✅ Implemented | ~80% |
| Policy Engine (ABAC) | ✅ Implemented | ~90% |
| Audit Logging | ✅ Implemented | ~95% |
| Memory Fabric | ⚠️ Partial | ~60% |
| WASM Sandbox | ⚠️ Partial | ~85% |
| Neuro-Symbolic Reasoner | ⚠️ Partial | ~40% |
| Swarm Consensus | ❌ Missing | ~0% |
| Python SDK | ⚠️ Partial | ~30% |
| LLM Interface | ✅ Implemented | 100% |

---

## TODO Items

### 🔴 P0 - Critical for MVP (Ordered by Dependency)

#### Phase 1: Foundation (No Dependencies - Start Immediately)

- [x] **LLM-001**: Implement LLM Interface abstraction ⭐ **START HERE**
  - Location: `src/llm/mod.rs`, `src/llm/traits.rs`, `src/llm/litellm.rs` (NEW)
  - Deps: reqwest, tokio, async-trait
  - Effort: 2-3 days
  - **Why first**: Blocks NSR-001, MEM-002, and any agent reasoning capability
  - Deliverables:
    - `LlmProvider` trait with `complete()`, `complete_streaming()`, `embed()`
    - `LiteLlmClient` implementation (OpenAI-compatible API)
    - `LlmConfig` for model selection, temperature, max_tokens
    - Mock provider for testing

- [x] **MEM-001**: Implement proper Episodic Memory (Merkle Chain)
  - Location: `src/memory/episodic.rs` (NEW)
  - Deps: None (can parallel with LLM-001)
  - Effort: 3-4 days
  - Deliverables:
    - `EpisodicMemory` struct with append-only Merkle chain
    - `Episode` struct (action, observation, thought, timestamp, hash)
    - `EpisodeChain` with cryptographic linkage
    - Retrieval by time range, hash, or semantic search

- [x] **SBX-001**: Implement Skill Registry with manifests
  - Location: `src/sandbox/registry.rs` (NEW)
  - Deps: None (can parallel with LLM-001)
  - Effort: 2-3 days
  - Deliverables:
    - `SkillManifest` struct (name, version, permissions, I/O schema)
    - `SkillRegistry` for loading/listing skills
    - YAML/JSON manifest parsing
    - Permission validation before execution

#### Phase 2: Reasoning (Depends on LLM-001)

- [x] **NSR-001**: Implement Process Reward Model (PRM) integration ✅ COMPLETED
  - Location: `src/reasoner/mod.rs`, `src/reasoner/prm.rs`
  - Deps: **LLM-001** (requires LLM for scoring) ✓
  - Effort: 3-5 days
  - Deliverables:
    - `ProcessRewardModel` trait ✅
    - `LlmPrm` implementation using LlmProvider ✅
    - `ThoughtScore` struct (score, confidence, reasoning) ✅
    - `ReasoningStep` struct with builder pattern ✅
    - `PrmConfig` for customization ✅
    - `MockPrm` for testing ✅
    - 17 comprehensive unit tests ✅

- [ ] **NSR-002**: Implement Z3 Formal Verification Gateway
  - Location: `src/reasoner/z3_verifier.rs` (NEW)
  - Deps: z3 crate (can parallel with NSR-001)
  - Effort: 5-7 days
  - Deliverables:
    - `FormalVerifier` trait
    - `Z3Verifier` implementation
    - `Constraint` DSL (simple assertions: >, <, ==, IN, NOT_IN)
    - YAML constraint file loading
    - `VerificationResult` with SAT/UNSAT and counterexamples

#### Phase 3: Integration (Depends on Phase 1-2)

- [ ] **PY-001**: Implement PyO3 bindings for Python SDK
  - Location: `src/python.rs` (NEW), `pyproject.toml` (NEW)
  - Deps: pyo3, maturin, all core modules complete
  - Effort: 3-5 days
  - Deliverables:
    - PyO3 module exposing `VakKernel`, `ToolRequest`, `PolicyDecision`
    - Async support via `pyo3-asyncio`
    - maturin build configuration
    - `pip install vak` working

### 🟠 P1 - Important for Production

- [ ] **MEM-002**: Implement Working Memory with dynamic summarization
  - Location: `src/memory/working.rs` (NEW)
  - Deps: LLM interface
  - Effort: 3-4 days

- [ ] **MEM-003**: Implement Knowledge Graph for Semantic Memory
  - Location: `src/memory/knowledge_graph.rs` (NEW)
  - Deps: petgraph crate
  - Effort: 4-5 days

- [ ] **MEM-004**: Integrate LanceDB for vector storage
  - Location: `src/memory/lancedb.rs` (NEW)
  - Deps: lancedb crate
  - Effort: 2-3 days

- [ ] **MEM-005**: Implement Time Travel & Rollbacks
  - Location: `src/memory/mod.rs` (UPDATE)
  - Deps: Proper Merkle DAG
  - Effort: 3-4 days

- [ ] **SBX-002**: Implement Signed Skill verification
  - Location: `src/sandbox/registry.rs` (UPDATE)
  - Deps: ed25519-dalek
  - Effort: 1-2 days

- [ ] **NSR-003**: Implement Tree of Thoughts search
  - Location: `src/reasoner/tree_search.rs` (NEW)
  - Deps: PRM integration
  - Effort: 4-5 days

### 🟡 P2 - Nice to Have

- [ ] **SWM-001**: Implement Swarm Consensus module
  - Location: `src/swarm/mod.rs` (NEW)
  - Deps: tokio channels
  - Effort: 5-7 days

- [ ] **SWM-002**: Implement Quadratic Voting
  - Location: `src/swarm/voting.rs` (NEW)
  - Deps: SWM-001
  - Effort: 2-3 days

- [ ] **SWM-003**: Implement Protocol Router
  - Location: `src/swarm/router.rs` (NEW)
  - Deps: SWM-001
  - Effort: 2-3 days

- [ ] **MEM-006**: Implement IPFS-Lite backend
  - Location: `src/memory/ipfs.rs` (NEW)
  - Deps: libipld crate
  - Effort: 3-4 days

- [ ] **INF-001**: Add persistent state storage backends
  - Location: `src/storage/` (NEW)
  - Deps: sled or rocksdb
  - Effort: 3-4 days

### 🟢 P3 - Future (Post-MVP)

- [ ] **ADV-001**: Zero-Knowledge Proof integration
- [ ] **ADV-002**: Constitution Protocol
- [ ] **ADV-003**: Fleet Management dashboard
- [ ] **ADV-004**: Decentralized Skill Marketplace

---

## Detailed Implementation Status

### ✅ Implemented Features

#### Kernel Core (`src/kernel/`)
- [x] Kernel struct with async initialization
- [x] KernelConfig with builder pattern
- [x] Policy evaluation integration
- [x] Tool request/response handling
- [x] Session and agent management
- [x] Basic tool execution dispatch
- [x] Error types (KernelError)

#### Policy Engine (`src/policy/mod.rs`)
- [x] PolicyEngine with rule management
- [x] YAML rule loading
- [x] PolicyRule struct (id, effect, patterns, conditions, priority)
- [x] PolicyEffect (Allow/Deny)
- [x] ConditionOperator (Equals, NotEquals, Contains, StartsWith, EndsWith, GreaterThan, LessThan, In)
- [x] PolicyCondition evaluation
- [x] Priority-based rule ordering
- [x] Pattern matching for resources/actions

#### Audit Logging (`src/audit/mod.rs`)
- [x] AuditLogger with hash-chained entries
- [x] SHA-256 hash computation
- [x] AuditEntry struct with cryptographic linkage
- [x] AuditDecision enum (Allowed, Denied, Error)
- [x] Chain integrity verification
- [x] Audit report generation
- [x] AuditVerificationError types

#### Memory System (`src/memory/mod.rs`)
- [x] EphemeralStorage trait + InMemoryEphemeral
- [x] SemanticStorage trait + InMemorySemanticStorage
- [x] MerkleStorage trait + InMemoryMerkleStore
- [x] NamespacedKey (namespace:key format)
- [x] StateValue with TTL support
- [x] StateManager with tier cascading
- [x] Basic MerkleProof structure
- [x] Cosine similarity for vector search

#### WASM Sandbox (`src/sandbox/mod.rs`)
- [x] WasmSandbox with Wasmtime backend
- [x] SandboxConfig (memory_limit, fuel_limit, timeout)
- [x] Module loading (from_bytes, from_file)
- [x] JSON input/output execution
- [x] Epoch-based timeout handling
- [x] SandboxError types

#### Types (`src/kernel/types.rs`)
- [x] AgentId with UUID v7
- [x] SessionId with UUID v7
- [x] AuditId with UUID v7
- [x] ToolRequest with hash computation
- [x] ToolResponse
- [x] PolicyDecision (Allow/Deny variants)
- [x] KernelError enum

### ⚠️ Partially Implemented Features

#### Merkle DAG Memory
- [x] Basic MerkleProof structure
- [ ] ❌ Proper sparse Merkle tree implementation
- [ ] ❌ Content-addressable storage
- [ ] ❌ Efficient proof generation for large trees

#### Memory Hierarchy
- [x] Three tiers defined (Ephemeral, Semantic, Merkle)
- [ ] ❌ Working Memory with dynamic summarization
- [ ] ❌ Episodic Memory with time-ordered chain
- [ ] ❌ Knowledge Graph integration

#### Python SDK
- [x] VakKernel wrapper class (stub)
- [x] Type definitions (types.py)
- [x] Exception classes
- [ ] ❌ Actual PyO3 bindings
- [ ] ❌ maturin build configuration

#### Async Kernel Traits
- [x] Traits defined (PolicyEvaluator, AuditWriter, StateStore, ToolExecutor)
- [ ] ❌ Full integration with main kernel
- [ ] ❌ Pluggable backends

### ❌ Not Implemented Features

#### Neuro-Symbolic Reasoner (Module 2)
- [x] Process Reward Model (PRM) integration ✅ COMPLETED
- [x] Step-by-step reasoning evaluation ✅ COMPLETED
- [x] Backtracking on low scores ✅ COMPLETED (via should_backtrack())
- [ ] Tree of Thoughts search (MCTS)
- [ ] Z3 Solver formal verification
- [ ] Natural language → Formal logic translation
- [ ] Invariant rule checking

#### Skill Registry
- [x] Skill manifest system ✅ COMPLETED
- [ ] Signed skill verification (ed25519)
- [x] Skill loading from registry ✅ COMPLETED
- [x] Permission scoping per skill ✅ COMPLETED

#### Swarm Consensus Protocol (Module 4)
- [ ] Quadratic Voting implementation
- [ ] Protocol Router
- [ ] Inter-agent message types
- [ ] Consensus mechanisms
- [ ] Multi-agent coordination

#### LLM Interface ✅ FULLY IMPLEMENTED
- [x] LLM abstraction traits ✅
- [x] LiteLLM router integration ✅
- [x] Model configuration ✅
- [x] Streaming support ✅

#### Storage Backends
- [ ] LanceDB for vectors
- [ ] IPFS-Lite for Merkle DAG
- [ ] Persistent state storage
- [ ] Database migrations

---

## New File Structure Required

```
src/
├── lib.rs                    # ✅ UPDATED: Added reasoner module export
├── kernel/                   # EXISTING
├── memory/
│   ├── mod.rs               # ✅ UPDATED: Export new submodules
│   ├── working.rs           # NEW: Working Memory with summarization
│   ├── episodic.rs          # ✅ IMPLEMENTED: Episodic Memory (Merkle Chain)
│   ├── knowledge_graph.rs   # NEW: Knowledge Graph
│   ├── lancedb.rs           # NEW: LanceDB backend
│   └── ipfs.rs              # NEW: IPFS-Lite backend
├── policy/                   # EXISTING
├── sandbox/
│   ├── mod.rs               # EXISTING
│   └── registry.rs          # ✅ IMPLEMENTED: Skill Registry
├── audit/                    # EXISTING
├── reasoner/                 # ✅ IMPLEMENTED MODULE
│   ├── mod.rs               # ✅ Module exports
│   ├── prm.rs               # ✅ Process Reward Model (NSR-001)
│   ├── tree_search.rs       # NEW: Tree of Thoughts / MCTS (NSR-003)
│   └── z3_verifier.rs       # NEW: Z3 Formal Verification (NSR-002)
├── swarm/                    # NEW MODULE
│   ├── mod.rs               # Module exports
│   ├── voting.rs            # Quadratic Voting
│   ├── router.rs            # Protocol Router
│   └── messages.rs          # Inter-agent messages
├── llm/                      # ✅ IMPLEMENTED MODULE
│   ├── mod.rs               # ✅ Module exports
│   ├── traits.rs            # ✅ LLM abstraction
│   ├── mock.rs              # ✅ Mock provider for testing
│   └── litellm.rs           # ✅ LiteLLM integration
└── python.rs                 # NEW: PyO3 bindings

python/
├── vak/
│   ├── __init__.py          # UPDATE
│   ├── types.py             # EXISTING
│   └── _vak_native.pyi      # NEW: Type stubs

pyproject.toml               # NEW: maturin configuration
```

---

## Dependencies to Add (Cargo.toml)

```toml
[dependencies]
# Python bindings
pyo3 = { version = "0.20", features = ["extension-module"], optional = true }

# Formal verification  
z3 = "0.12"

# Vector database
lancedb = "0.4"

# IPFS/Merkle DAG
libipld = "0.16"

# Cryptographic signatures for skills
ed25519-dalek = "2.0"

# Graph data structure
petgraph = "0.6"

# HTTP client for LLM APIs
reqwest = { version = "0.11", features = ["json", "stream"] }

[features]
python = ["pyo3"]

[lib]
crate-type = ["cdylib", "rlib"]
```

---

## Sprint Planning (Refined)

### 🏃 Sprint 1: Foundation (Week 1) - PARALLEL EXECUTION

| Task | Owner | Days | Blocker |
|------|-------|------|---------|
| **LLM-001**: LLM Interface | Dev A | 2-3 | None |
| **MEM-001**: Episodic Memory | Dev B | 3-4 | None |
| **SBX-001**: Skill Registry | Dev C | 2-3 | None |

**Sprint 1 Goal**: Three independent modules complete, enabling Phase 2.

### 🏃 Sprint 2: Reasoning (Week 2-3) - PARALLEL EXECUTION

| Task | Owner | Days | Blocker |
|------|-------|------|---------|
| **NSR-001**: PRM Integration | Dev A | 3-5 | LLM-001 ✓ |
| **NSR-002**: Z3 Verifier | Dev B | 5-7 | None |
| **SBX-002**: Signed Skills | Dev C | 1-2 | SBX-001 ✓ |

**Sprint 2 Goal**: Neuro-Symbolic Reasoner operational with formal verification.

### 🏃 Sprint 3: Memory & SDK (Week 3-4)

| Task | Owner | Days | Blocker |
|------|-------|------|---------|
| **MEM-002**: Working Memory | Dev A | 3-4 | LLM-001 ✓ |
| **PY-001**: PyO3 Bindings | Dev B | 3-5 | Core modules ✓ |
| **Integration Testing** | Dev C | 3-4 | All above |

**Sprint 3 Goal**: Python SDK working, agent can run end-to-end.

### 🏁 Sprint 4: MVP Demo (Week 5)

| Task | Owner | Days | Blocker |
|------|-------|------|---------|
| Code Auditor Demo | All | 3-5 | All P0 ✓ |
| Documentation | All | 2-3 | - |
| Bug Fixes | All | 2-3 | - |

**Sprint 4 Goal**: "Autonomous Code Auditor" MVP demo ready.

---

## 📋 Answers to Refinement Questions

### 1. ✅ LLM Interface first? **YES - Confirmed**
LLM-001 is now **Phase 1, Task 1** because:
- NSR-001 (PRM) requires LLM for scoring reasoning steps
- MEM-002 (Working Memory) requires LLM for summarization
- Any agent capability requires model access

### 2. ✅ Z3 complexity? **Start simple with YAML constraints**
Recommendation:
- Phase 1: Simple constraint DSL in YAML (>, <, ==, IN, NOT_IN, FORBIDDEN)
- Phase 2: Full Z3 integration for complex SAT solving
- Example simple constraint:
```yaml
constraints:
  - name: "no_secrets_access"
    type: FORBIDDEN
    resources: ["*.env", "secrets/*", "credentials/*"]
  - name: "max_refund"
    type: LESS_THAN
    field: "amount"
    value: 1000
```

### 3. ✅ Python SDK timing? **Week 3-4, after core stable**
- Rust CLI is sufficient for MVP demo
- PyO3 bindings are P0 for developer adoption but not for demo
- Can demo with Rust examples + Python stub if needed

### 4. ✅ Swarm priority? **P2 - Not needed for Code Auditor MVP**
- Single-agent Code Auditor doesn't need multi-agent consensus
- Swarm is for "Red Team" security review (future use case)
- Move to post-MVP roadmap

### 5. ✅ Storage backends? **In-memory for MVP, LanceDB for production**
- MVP: All in-memory (current implementation sufficient)
- Post-MVP: LanceDB for vectors, RocksDB/sled for persistence
- Time Travel requires proper Merkle DAG (MEM-001 first)

---

## Definition of Done

For each TODO item:
- [ ] Implementation complete
- [ ] Unit tests passing (>80% coverage)
- [ ] Integration tests added
- [ ] Documentation (rustdoc + examples)
- [ ] No new warnings
- [ ] Benchmarks added (for performance-critical code)

---

## 🚀 Next Actions

1. **Immediately**: Start LLM-001, MEM-001, SBX-001 in parallel
2. **Day 3**: Review LLM-001, begin NSR-001 if ready
3. **Week 2**: NSR-002 (Z3) parallel with NSR-001
4. **Week 3**: Python bindings, integration testing
5. **Week 5**: MVP demo preparation
