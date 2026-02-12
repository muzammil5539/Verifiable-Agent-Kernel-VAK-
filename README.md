# Verifiable Agent Kernel (VAK) 🛡️

**An open-source Agent Kernel that intercepts agent actions, enforces policy rules (ABAC), and audit-logs behavior for trustworthy AI agent deployments.**

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-alpha-yellow.svg)](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-)

---

## 📑 Table of Contents

- [Overview](#overview)
- [Why VAK?](#why-vak)
- [Core Features](#core-features)
- [Architecture](#architecture)
  - [Module 1: Cryptographic Memory Fabric](#module-1-cryptographic-memory-fabric-cmf)
  - [Module 2: Neuro-Symbolic Reasoner](#module-2-neuro-symbolic-reasoner-nsr)
  - [Module 3: Policy Engine (ABAC)](#module-3-policy-engine-abac)
  - [Module 4: WASM Sandbox](#module-4-wasm-sandbox)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [Development Roadmap](#development-roadmap)
- [Skills Development](#skills-development)
- [Contributing](#contributing)
- [License](#license)

### Documentation

- [Architecture Documentation](ARCHITECTURE.md) — System design, module reference, data flow, security architecture
- [API Reference](API.md) — Complete API reference for all modules (Rust & Python)
- [Python SDK Guide](docs/python-sdk.md) — Getting started with the Python SDK
- [Contributing Guide](CONTRIBUTING.md) — Development workflow and coding standards
- [Changelog](CHANGELOG.md) — Version history

---

## Overview

The **Verifiable Agent Kernel (VAK)**, also known as **Exo-Cortex**, is a deterministic control plane for autonomous AI agents. It bridges the gap between probabilistic LLMs and trustworthy Proto-AGI systems by introducing:

- **Neuro-symbolic architecture** for reliable reasoning
- **Cryptographic memory integrity** via Merkle DAGs
- **Sandboxed execution** via WebAssembly (WASM)
- **Attribute-Based Access Control (ABAC)** for policy enforcement
- **Immutable audit logging** for complete transparency

VAK treats the LLM as the "CPU" and acts as the "Operating System," enabling enterprises to deploy autonomous agents with provable safety, auditability, and compliance guarantees.

### The Problem We Solve

Current AI agent frameworks suffer from:

1. **Context Engineering Paradox**: "Goldfish" agents with no episodic memory
2. **Determinism Gap**: Probabilistic outputs make testing and deployment unpredictable
3. **Multi-Agent Coordination Failure**: Sycophancy and consensus collapse
4. **Safety Void**: No formal verification or sandboxing
5. **Infrastructure Economics**: Unsustainable token costs for long-running tasks

VAK addresses these fundamental issues with a kernel-based approach inspired by operating system design.

---

## Why VAK?

### The Blue Ocean Opportunity

VAK occupies a unique market position:

- **High Novelty** ⭐⭐⭐⭐ (4/5): An OS-like "kernel" for AI agents is not yet mainstream
- **Technical Feasibility** ⭐⭐⭐ (3/5): Proven by research prototypes and existing POCs
- **Alignment Impact** ⭐⭐⭐⭐⭐ (5/5): Directly supports AI safety through enforced constraints
- **Business Value** ⭐⭐⭐⭐⭐ (5/5): Strong enterprise demand for provable agent safety

### Core Value Proposition

**"Deploy autonomous AI agents you can trust."**

VAK provides a transparent, enforceable layer between AI agents and the external world. It guarantees that agents only perform actions allowed by policy, logs every decision for audit, and prevents bypass attempts via structural checks.

---

## Core Features

### 🔐 Policy Enforcement
- **ABAC Engine**: Attribute-Based Access Control with rule evaluation
- **Deny by Default**: No policy = inadmissible (explicit allow required)
- **Priority-Based Rules**: Fine-grained control with pattern matching
- **Runtime Interception**: Every agent action goes through policy checks

### 📝 Audit Logging
- **Hash-Chained Entries**: Cryptographically linked audit trail (SHA-256)
- **Immutable Records**: Append-only logging prevents tampering
- **Chain Integrity Verification**: Detect any modifications to audit history
- **Flight Recorder Mode**: Shadow mode for safe testing without execution

### 🧠 Memory Architecture
- **Hierarchical Memory**: Working (hot), Episodic (warm), Semantic (cold)
- **Merkle DAG Storage**: Content-addressable with cryptographic integrity
- **Time Travel & Rollbacks**: Revert to any previous state by hash
- **Vector + Graph Storage**: Semantic retrieval with relationship preservation

### 🔒 WASM Sandbox
- **Isolated Execution**: Skills run in WebAssembly sandboxes
- **Resource Limits**: Memory, CPU (fuel), and timeout constraints
- **Deterministic**: Same input always produces same output
- **Signed Skills**: Ed25519 verification for skill authenticity

### 🤖 Neuro-Symbolic Reasoning
- **Process Reward Model (PRM)**: Step-by-step reasoning validation
- **Tree of Thoughts**: MCTS-based exploration with backtracking
- **Z3 Formal Verification**: Mathematical proof of constraint satisfaction
- **LLM Integration**: Pluggable LLM interface (LiteLLM compatible)
- **Zero-Knowledge Proofs**: Prove properties without revealing sensitive data
- **PRM Fine-Tuning Toolkit**: Dataset management, calibration analysis, and A/B testing

### 🌐 Multi-Agent Support
- **Async Kernel**: Non-blocking, concurrent agent execution
- **Quadratic Voting**: Prevent sycophancy in multi-agent systems
- **Swarm Consensus**: Debate protocols and ensemble aggregation
- **Protocol Router**: Standardized inter-agent communication

### 📜 Constitution Protocol
- **Safety Principles**: Immutable rules that cannot be overridden by policies
- **Multi-Point Enforcement**: Pre-policy, pre-execution, and post-execution checks
- **Compound Constraints**: Logical AND/OR/NOT combinations for complex rules
- **Tamper Detection**: Cryptographic hashing of the constitution itself

### 🏪 Skill Marketplace
- **Verified Publishers**: Multi-method identity verification (GitHub, GPG, domain, email)
- **Trust Levels**: Progressive trust from unverified to official
- **Reputation System**: Community-driven publisher reputation scores
- **Vulnerability Scanning**: Automated security checks on skill publish
- **Malicious Skill Reporting**: Community reporting with auto-suspension

---

## Architecture

VAK follows a modular, layered architecture inspired by operating system design:

```
┌─────────────────────────────────────────────────────────────┐
│                      Agent Layer                            │
│  (LLM-based agents: GPT-4, Claude, Llama, etc.)           │
└─────────────────┬───────────────────────────────────────────┘
                  │ Tool Requests
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   VAK Kernel (Core)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │   Policy     │  │    Audit     │  │    Memory    │    │
│  │   Engine     │  │   Logger     │  │   Manager    │    │
│  │   (ABAC)     │  │  (Merkle)    │  │  (3-Tier)    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │    WASM      │  │     LLM      │  │   Reasoner   │    │
│  │   Sandbox    │  │  Interface   │  │    (PRM)     │    │
│  └──────────────┘  └──────────────┘  └──────────────┘    │
└─────────────────┬───────────────────────────────────────────┘
                  │ Approved Actions
                  ▼
┌─────────────────────────────────────────────────────────────┐
│                   External World                            │
│  (APIs, Files, Databases, Services)                        │
└─────────────────────────────────────────────────────────────┘
```

### Communication Flow

```
┌──────────────┐   tool_request    ┌─────────────────────┐
│   Any Agent  │ ─────────────────►│ Policy Enforcement  │
└──────────────┘                   └──────────┬──────────┘
                                              │
                         ┌────────────────────┼────────────────────┐
                         │                    │                    │
                         ▼                    ▼                    ▼
                 ┌───────────────┐    ┌───────────────┐   ┌───────────────┐
                 │ Formal Verif  │    │ Tool Executor │   │ Audit Logger  │
                 │ (high-stakes) │    │    (WASM)     │   │  (all actions)│
                 └───────────────┘    └───────────────┘   └───────────────┘
```

### Module 1: Cryptographic Memory Fabric (CMF)

**Solving the "Goldfish" and "Hallucination" problems.**

VAK implements a hierarchical Merkle DAG for memory management:

#### Memory Tiers

- **Working Memory (Hot)**: Current context window with dynamic summarization
- **Episodic Memory (Warm)**: Time-ordered Merkle Chain of past trajectories
- **Semantic Memory (Cold)**: Knowledge Graph + Vector Store for structured retrieval

#### Content-Addressable Integrity

- **State Hash**: Entire agent state at step T represented by a single root hash
- **Audit Trails**: Cryptographic proof of decision provenance
- **Time Travel**: Instant rollback to any previous state by hash

### Module 2: Neuro-Symbolic Reasoner (NSR)

**Solving the "Reliability" and "Safety" problems.**

Combines neural creativity with symbolic verification:

- **Process Reward Model (PRM)**: Score reasoning steps before execution
- **Tree of Thoughts (ToT)**: MCTS-based exploration with backtracking
- **Z3 Formal Verification**: Mathematical constraint satisfaction
- **Loop Detection**: Prevent infinite reasoning loops

### Module 3: Policy Engine (ABAC)

**Solving the "Permission" and "Compliance" problems.**

Attribute-Based Access Control with:

- **Rule Evaluation**: JSON/YAML policy definitions
- **Condition Operators**: `eq`, `lt`, `gt`, `in`, `contains`, `startsWith`, etc.
- **Priority System**: Explicit rule ordering for conflict resolution
- **Pattern Matching**: Glob patterns for resources/actions

Example policy:

```yaml
id: "refund_approval"
effect: Allow
patterns:
  actions: ["refund_user"]
  resources: ["payments/*"]
conditions:
  - field: "amount"
    operator: LessThan
    value: 1000
  - field: "user_status"
    operator: Equals
    value: "verified"
priority: 100
```

### Module 4: WASM Sandbox

**Solving the "Security" and "Isolation" problems.**

Skills (tools) run in WebAssembly sandboxes with:

- **Memory Limits**: Bounded memory pages (e.g., 16 pages = 1MB)
- **Fuel Limits**: CPU execution quotas to prevent infinite loops
- **Timeout Handling**: Epoch-based interruption
- **Signed Execution**: Ed25519 signatures for skill verification

---

## Project Structure

```
VAK/
├── src/                          # Core Rust implementation
│   ├── kernel/                   # Kernel core (sessions, agents, orchestration)
│   ├── policy/                   # ABAC policy engine
│   ├── audit/                    # Hash-chained audit logging
│   ├── memory/                   # 3-tier memory system
│   ├── sandbox/                  # WASM execution environment
│   ├── llm/                      # LLM abstraction layer
│   └── reasoner/                 # Neuro-symbolic reasoning (PRM, Z3)
│
├── agents/                       # Agent definitions
│   ├── development/              # Dev-time code generation agents
│   │   ├── kernel_core_agent.yaml
│   │   ├── crypto_memory_agent.yaml
│   │   ├── neurosymbolic_agent.yaml
│   │   ├── wasm_sandbox_agent.yaml
│   │   ├── policy_engine_agent.yaml
│   │   ├── python_sdk_agent.yaml
│   │   └── testing_agent.yaml
│   │
│   └── runtime/                  # Runtime enforcement agents
│       ├── policy_enforcement_agent.yaml
│       ├── audit_logging_agent.yaml
│       ├── prm_scoring_agent.yaml
│       ├── formal_verification_agent.yaml
│       ├── swarm_consensus_agent.yaml
│       └── state_manager_agent.yaml
│
├── instructions/                 # System instructions for agents
│   ├── global.instructions.yaml          # Core principles
│   ├── safety.instructions.yaml          # Safety rules
│   ├── code_generation.instructions.yaml # Dev standards
│   └── policy_authoring.instructions.yaml
│
├── prompts/                      # Prompt templates
│   ├── code_generation.prompts.yaml
│   ├── reasoning_verification.prompts.yaml
│   ├── policy_audit.prompts.yaml
│   └── multi_agent.prompts.yaml
│
├── protocols/                    # Communication protocols
│   ├── inter_agent_protocol.yaml
│   └── kernel_api.yaml
│
├── policies/                     # Example ABAC policies
│   ├── admin/, data/, finance/, tests/
│
├── skills/                       # WASM skill modules
│   ├── calculator/               # Example arithmetic skill
│   └── README.md                 # Skills development guide
│
├── examples/                     # Usage examples
│   ├── basic_agent.rs
│   ├── policy_demo.rs
│   └── python_quickstart.py
│
├── python/                       # Python SDK
│   └── vak/
│       ├── __init__.py
│       └── types.py
│
├── config/                       # Configuration
│   └── agent_registry.yaml
│
├── k8s/                          # Kubernetes manifests
│   └── base/                    # Kustomize base (deployment, service, hpa, etc.)
│
├── helm/                         # Helm charts
│   └── vak/                     # VAK chart (Chart.yaml, values.yaml, templates/)
│
└── benches/                      # Performance benchmarks
```

---

## Installation

### Prerequisites

- **Rust**: 1.75 or later
- **Python**: 3.8+ (for Python SDK)
- **WASM Target**: For building skills

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add WASM target
rustup target add wasm32-unknown-unknown
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-.git
cd Verifiable-Agent-Kernel-VAK-

# Build the project
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

### Python SDK Installation

```bash
# Install from source (PyO3 bindings - coming soon)
pip install -e ./python
```

---

## Quick Start

### Basic Agent Example

```rust
use vak::{Kernel, KernelConfig, ToolRequest, AgentId};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the kernel
    let config = KernelConfig::default()
        .with_policy_path("policies/")
        .with_audit_enabled(true);
    
    let kernel = Arc::new(Kernel::new(config).await?);
    
    // Create an agent session
    let agent_id = AgentId::new();
    let session = kernel.create_session(agent_id).await?;
    
    // Execute a tool request
    let request = ToolRequest::new(
        agent_id,
        "file_read",
        serde_json::json!({"path": "/data/example.txt"})
    );
    
    let response = kernel.execute_tool(request).await?;
    println!("Response: {:?}", response);
    
    // View audit trail
    let audit_report = kernel.audit_logger().generate_report().await?;
    println!("Audit Report: {}", audit_report);
    
    Ok(())
}
```

### Policy Definition Example

```yaml
# policies/admin/file_access.yaml
---
id: "allow_read_data"
effect: Allow
patterns:
  actions: ["file_read", "file_list"]
  resources: ["/data/*"]
conditions:
  - field: "agent_role"
    operator: Equals
    value: "admin"
priority: 100

---
id: "deny_system_files"
effect: Deny
patterns:
  actions: ["file_*"]
  resources: ["/etc/*", "/sys/*", "/proc/*"]
conditions: []
priority: 200
```

### Python Usage Example

```python
from vak import VakKernel, ToolRequest

# Initialize kernel
kernel = VakKernel(
    policy_path="policies/",
    audit_enabled=True
)

# Create agent
agent_id = kernel.create_agent(role="finance-agent")

# Execute tool with policy enforcement
request = ToolRequest(
    agent_id=agent_id,
    tool="refund_user",
    params={"amount": 500, "user_id": "123"}
)

response = kernel.execute(request)
print(f"Status: {response.status}")
print(f"Result: {response.result}")

# Check audit log
audit_trail = kernel.get_audit_trail(agent_id)
for entry in audit_trail:
    print(f"{entry.timestamp}: {entry.action} - {entry.decision}")
```

---

## Usage Examples

The `examples/` directory contains comprehensive examples:

### 1. Basic Agent (`basic_agent.rs`)
Demonstrates core kernel functionality, session management, and tool execution.

### 2. Policy Demo (`policy_demo.rs`)
Shows ABAC policy enforcement with various rule types and conditions.

### 3. Python Quickstart (`python_quickstart.py`)
Python SDK usage for integrating VAK with LangChain and other frameworks.

Run examples:

```bash
# Rust examples
cargo run --example basic_agent
cargo run --example policy_demo

# Python examples
python examples/python_quickstart.py
```

---

## Development Roadmap

### Current Status (v0.1 - Alpha) — 100% Complete

**Completed Phases:**
- ✅ Phase 1: Core Kernel Stability ("Iron Kernel")
- ✅ Phase 2: Policy Layer ("Digital Superego")
- ✅ Phase 3: Memory & Provenance ("Immutable Past")
- ✅ Phase 4: Neuro-Symbolic Cognitive Layer ("Prefrontal Cortex")
- ✅ Phase 5: Ecosystem & Interoperability
- ✅ Security Layer
- ✅ Testing Layer
- ✅ P3 Future Features (ZK Proofs, Constitution, PRM Toolkit, Marketplace)

**Documentation:**
- ✅ Architecture Documentation (DOC-001)
- ✅ API Reference Documentation (DOC-002)

**Infrastructure:**
- ✅ Kubernetes Operator (INF-001)
- ✅ Docker Images (INF-002)
- ✅ Helm Charts (INF-003)
- ✅ Cryptographic Replay (OBS-002)

| Module | Status | Completion |
|--------|--------|------------|
| Kernel Core | ✅ Complete | 100% |
| Policy Engine (ABAC) | ✅ Complete | 100% |
| Audit Logging | ✅ Complete | 100% |
| Memory Fabric | ✅ Complete | 100% |
| WASM Sandbox | ✅ Complete | 100% |
| Neuro-Symbolic Reasoner | ✅ Complete | 100% |
| Security Layer | ✅ Complete | 100% |
| Swarm/A2A Protocol | ✅ Complete | 100% |
| MCP/Integrations | ✅ Complete | 100% |
| Python SDK | ⚠️ Partial | ~40% |
| Testing Suite | ✅ Complete | 100% |
| LLM Interface | ✅ Implemented | 100% |
| Documentation | ✅ Complete | 100% |
| Zero-Knowledge Proofs | ✅ Complete | 100% |
| Constitution Protocol | ✅ Complete | 100% |
| PRM Fine-Tuning Toolkit | ✅ Complete | 100% |
| Skill Marketplace | ✅ Complete | 100% |

### Roadmap by Priority

#### 🔴 P0 - Critical for MVP

**Phase 1: Core Kernel Stability** ✅ COMPLETE
- [x] RT-001: Epoch Ticker Thread
- [x] RT-002: Epoch Deadline Configuration
- [x] RT-003: Pooling Allocator Strategy
- [x] RT-004: Async Host Functions
- [x] RT-005: Panic Safety at WASM/Host Boundary
- [x] RT-006: Deterministic Termination Tests

**Phase 2: Policy Layer** ✅ COMPLETE
- [x] POL-001: Cedar Policy Integration
- [x] POL-002: Cedar Schema Definition
- [x] POL-003: Cedar Enforcer Implementation
- [x] POL-004: Policy Middleware Injection
- [x] POL-005: Dynamic Context Injection
- [x] POL-006: Policy Hot-Reloading
- [x] POL-007: Default Deny Policy
- [x] POL-008: Policy Analysis Integration

**Phase 3: Memory & Provenance** ✅ COMPLETE
- [x] MEM-001: rs_merkle Integration
- [x] MEM-002: Sparse Merkle Tree Proofs
- [x] MEM-003: Content-Addressable Storage
- [x] MEM-004: Cryptographic Receipt Generation
- [x] MEM-005: Time Travel Debugging
- [x] MEM-006: Secret Scrubbing

**Phase 4: Neuro-Symbolic Cognitive Layer** ✅ COMPLETE
- [x] NSR-001: Datalog Integration
- [x] NSR-002: Safety Rules Implementation
- [x] NSR-003: Reasoning Host Function
- [x] NSR-004: Risk-Based Network Access Rules
- [x] NSR-005: Constrained Decoding Bridge
- [x] NSR-006: Neuro-Symbolic Hybrid Loop

**Security Layer** ✅ COMPLETE
- [x] SEC-001: Supply Chain Hardening (cargo-audit)
- [x] SEC-002: License Compliance (cargo-deny)
- [x] SEC-003: Unsafe Rust Audit
- [x] SEC-004: Prompt Injection Protection
- [x] SEC-005: Rate Limiting

**Phase 5: Ecosystem & Interoperability** ✅ COMPLETE
- [x] INT-001: MCP Server Implementation
- [x] INT-002: MCP Tool Mapping
- [x] INT-003: LangChain Adapter Completion
- [x] INT-004: AutoGPT Adapter Completion
- [x] SWM-001: A2A Protocol Support
- [x] SWM-002: AgentCard Discovery

**Testing Layer** ✅ COMPLETE
- [x] TST-001: Infinite Loop Preemption Tests
- [x] TST-002: Memory Containment Tests
- [x] TST-003: Policy Verification Tests
- [x] TST-004: Integration Test Coverage
- [x] TST-005: Benchmark Suite Expansion
- [x] TST-006: Python SDK Tests

#### 🟠 P1 - Important for Production
- [x] DOC-001: Architecture documentation
- [x] DOC-002: API reference documentation

#### 🟡 P2 - Nice to Have
- [x] INF-001: Kubernetes operator
- [x] INF-002: Docker images
- [x] INF-003: Helm charts
- [x] OBS-002: Cryptographic replay capability

#### 🟢 P3 - Future (Post-MVP)
- [x] FUT-001: Zero-Knowledge Proof integration
- [x] FUT-002: Constitution Protocol
- [x] FUT-003: Enhanced PRM fine-tuning toolkit
- [x] FUT-004: Skill marketplace with verified publishers

### Target Milestones

- **v0.1 (Current - Alpha)**: Core kernel, policy engine, audit logging, neuro-symbolic layer ✅
- **v0.2 (Q1 2026)**: Complete ecosystem integrations, Python SDK stable
- **v0.3 (Q2 2026)**: Full test coverage, infrastructure tooling
- **v1.0 (Q3 2026)**: Production-ready with full documentation

---

## Skills Development

Skills are sandboxed WebAssembly modules that extend VAK with domain-specific capabilities. Each skill runs in isolation with controlled resource access.

### Creating a Skill

```rust
// src/lib.rs
#[no_mangle]
pub extern "C" fn execute(input_ptr: *const u8, input_len: usize) -> *const u8 {
    // Parse JSON input
    // Perform computation
    // Return JSON output
}
```

### Skill Manifest

```yaml
# skill.yaml
name: my_skill
version: "0.1.0"
description: "Brief description"
author: "Your Name"
license: "MIT"

module: target/wasm32-unknown-unknown/release/my_skill.wasm

capabilities:
  - compute

limits:
  max_memory_pages: 16
  max_execution_time_ms: 1000

exports:
  - name: execute
    input_schema:
      type: object
    output_schema:
      type: object
```

### Building Skills

```bash
cargo build --target wasm32-unknown-unknown --release
```

For detailed skill development guide, see [skills/README.md](skills/README.md).

---

## Contributing

We welcome contributions! Please see our [contribution guidelines](CONTRIBUTING.md) for details.

### Development Agents

VAK uses specialized agents for development tasks. See [AGENTS_README.md](AGENTS_README.md) for the complete agent structure and capabilities.

**Development Agents:**
- Kernel Core Agent
- Crypto Memory Agent
- Neuro-Symbolic Agent
- WASM Sandbox Agent
- Policy Engine Agent
- Python SDK Agent
- Testing Agent

**Runtime Agents:**
- Policy Enforcement Agent
- Audit Logging Agent
- PRM Scoring Agent
- Formal Verification Agent
- Swarm Consensus Agent
- State Manager Agent

### Testing

```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --package vak --lib policy

# Run with coverage
cargo tarpaulin --out Html

# Run benchmarks
cargo bench
```

### Code Quality

```bash
# Format code
cargo fmt

# Lint
cargo clippy -- -D warnings

# Check for issues
cargo check
```

---

## License

This project is dual-licensed under:

- MIT License ([LICENSE-MIT](LICENSE-MIT))
- Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE))

You may choose either license for your use.

---

## Acknowledgments

VAK is inspired by:

- **CoALA Framework**: Cognitive Architectures for Language Agents
- **Agent Control Plane**: Imran Siddique's ABAC interceptor research
- **Sovereign Kernel**: David Mc's verifiable kernel proof-of-concept
- **Process Reward Models**: OpenAI's PRM research
- **Tree of Thoughts**: Yao et al.'s ToT framework

---

## Contact & Support

- **Issues**: [GitHub Issues](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/issues)
- **Discussions**: [GitHub Discussions](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/discussions)
- **Email**: [Contact Us](mailto:support@vak-project.org)

---

**Built with ❤️ for the Agentic AI Era**
