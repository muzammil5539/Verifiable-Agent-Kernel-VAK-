# VAK Project Context Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** is a Rust-based infrastructure layer that provides cryptographic verification, sandboxed execution, and audit logging for AI agent operations. It serves as a "trust anchor" enabling AI agents to operate with mathematical guarantees of correctness.

VAK represents a paradigm shift from loose framework-based orchestration (LangChain, AutoGen) to a kernel-based architecture where agents are treated as untrusted processes requiring strict isolation, resource metering, and cryptographic verification.

## Core Philosophy

The VAK operates on three non-negotiable pillars:

1. **Computational Verification (Isolation)**: WASM sandboxed, deterministic execution
2. **Semantic Verification (Reasoning)**: Neuro-symbolic logic constraints before action
3. **Authorization Verification (Policy)**: Cedar-based formal policy enforcement

## Architecture Components

| Component | Purpose | Location |
|-----------|---------|----------|
| `VakKernel` | Main orchestrator | `src/kernel/mod.rs` |
| `PolicyEngine` | Cedar ABAC enforcement | `src/policy/mod.rs` |
| `AuditLogger` | Merkle-chained audit trail | `src/audit/mod.rs` |
| `WasmSandbox` | Wasmtime isolated execution | `src/sandbox/mod.rs` |
| `MemoryFabric` | 3-tier hierarchical memory | `src/memory/mod.rs` |
| `Reasoner` | Neuro-symbolic verification | `src/reasoner/mod.rs` |
| `SwarmCoordinator` | Multi-agent consensus | `src/swarm/mod.rs` |
| `LLMInterface` | Model abstraction layer | `src/llm/mod.rs` |

## Core Data Structures

```rust
// Core types in src/types.rs
pub struct AgentId(pub String);
pub struct ContentHash(pub [u8; 32]);
pub struct Signature(pub Vec<u8>);
pub struct Timestamp(pub u64);

pub struct Operation {
    pub id: String,
    pub agent_id: AgentId,
    pub operation_type: OperationType,
    pub input_hash: ContentHash,
    pub timestamp: Timestamp,
    pub signature: Option<Signature>,
}

pub enum OperationType {
    FileRead,
    FileWrite,
    CodeExecution,
    NetworkRequest,
    DatabaseQuery,
}

pub struct VerificationResult {
    pub is_valid: bool,
    pub operation_id: String,
    pub verified_at: Timestamp,
    pub proof: VerificationProof,
}
```

## Task Description

This agent provides project context and architectural guidance to other agents. It:
- Explains the VAK architecture and design decisions
- Provides code location references
- Explains the relationship between components
- Guides implementation according to MVP specifications

## Available Commands

```bash
# Build project
cargo build --release

# Run tests
cargo test

# Run specific module tests
cargo test --package vak --lib <module_name>

# Generate documentation
cargo doc --open

# Check code
cargo check
cargo clippy -- -D warnings
cargo fmt --check
```

## Key Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Dependencies and project config |
| `src/lib.rs` | Library root with module exports |
| `src/kernel/mod.rs` | Core kernel implementation |
| `README.md` | Project documentation |
| `TODO.md` | Implementation tracking |

## Guardrails

### DO
- Reference actual file paths when explaining architecture
- Use terminology consistent with MVP documents
- Explain the "why" behind architectural decisions
- Link concepts to Gap Analysis requirements

### DON'T
- Make assumptions about unimplemented features
- Suggest implementations that violate safety principles
- Skip the policy enforcement layer
- Recommend bypassing the audit system

## Related Documents

- [AI Agent Blue Ocean Opportunity.md](../../AI Agent Blue Ocean Opportunity.md)
- [AI Kernel Gap Analysis & Roadmap.md](../../AI Kernel Gap Analysis & Roadmap.md)
- [TODO.md](../../TODO.md)
- [AGENTS_README.md](../../AGENTS_README.md)