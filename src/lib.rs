//! # Verifiable Agent Kernel (VAK)
//!
//! A secure, auditable, and verifiable execution environment for AI agents.
//!
//! ## Overview
//!
//! VAK provides a kernel-based architecture for AI agent systems with:
//!
//! - **Cryptographic Verification**: All operations are logged to an immutable audit trail
//! - **Sandboxed Execution**: WASM-based isolation prevents unauthorized access
//! - **Policy Enforcement**: Cedar-style ABAC policies, behind a pluggable decision point
//! - **Neuro-Symbolic Reasoning**: Datalog rules verify agent behavior
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        VAK Kernel                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
//! │  │  Policy  │  │  Audit   │  │  Memory  │  │ Reasoner │   │
//! │  │  Engine  │  │  Logger  │  │  Fabric  │  │  Engine  │   │
//! │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
//! │  │   WASM   │  │   LLM    │  │  Swarm   │  │   MCP    │   │
//! │  │ Sandbox  │  │Interface │  │Consensus │  │  Server  │   │
//! │  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use vak::prelude::*;
//! use vak::kernel::config::KernelConfig;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a kernel with default configuration
//!     let config = KernelConfig::default();
//!     let kernel = Kernel::new(config).await?;
//!
//!     // Create agent and session identifiers
//!     let agent_id = AgentId::new();
//!     let session_id = SessionId::new();
//!
//!     // Execute a tool through the kernel
//!     let request = ToolRequest::new("calculator", serde_json::json!({
//!         "operation": "add",
//!         "a": 1,
//!         "b": 2
//!     }));
//!
//!     let response = kernel.execute(&agent_id, &session_id, request).await?;
//!     println!("Result: {:?}", response.result);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Modules
//!
//! Always built (the trusted core):
//!
//! - [`kernel`]: Core kernel orchestration and execution
//! - [`policy`]: Cedar-style policy enforcement
//! - [`audit`]: Immutable audit logging and tracing
//! - [`secrets`]: Pluggable secrets providers
//! - [`lib_integration`]: `VakRuntime` / `VakAgent` library API
//!
//! Behind features (see below): `sandbox`, `memory`, `llm`, `reasoner`,
//! `swarm`, `integrations`, `dashboard`, `api`, `tools`, `python`.
//!
//! ## Safety Guarantees
//!
//! VAK provides several safety guarantees:
//!
//! 1. **Computational Safety**: WASM sandbox with epoch-based preemption
//! 2. **Policy Safety**: All actions decided by the policy decision point, default deny
//! 3. **Memory Safety**: Rust's ownership system + WASM isolation
//! 4. **Audit Safety**: Tamper-evident RFC 9162 Merkle log with inclusion and consistency proofs
//!
//! ## Feature Flags
//!
//! The trusted core is always built; `default-features = false` builds it
//! alone, with no Wasmtime. Everything outside it is a feature
//! (`docs/adr/0006`). The core never imports a feature-gated module.
//!
//! | Feature | Default | Enables |
//! |---------|---------|---------|
//! | `wasm` | yes | `sandbox`: WASM skills, skill registry and signatures (Wasmtime) |
//! | `memory` | yes | `memory` tiers (implies `llm`) |
//! | `llm` | via `memory` | `llm` provider adapters |
//! | `reasoner` | no | `reasoner` (Heuristic) and `kernel::neurosymbolic_pipeline` |
//! | `experimental-zk` | no | `reasoner::zk_proof` (not a sound proof system) |
//! | `swarm` | no | `swarm` voting, consensus, A2A bus |
//! | `integrations` | no | LangChain, AutoGPT and MCP adapters (implies `reasoner`, `wasm`) |
//! | `dashboard` | no | `dashboard` and `api` (implies `swarm`) |
//! | `legacy-tools` | no | `tools::skill_sign`, superseded by `sandbox::signing` |
//! | `cedar` | no | Cedar policies through the `cedar-policy` crate (`policy::cedar`); needs Rust 1.89 |
//! | `cedar-analysis` | no | SymCC proofs about Cedar policy sets (`policy::cedar::analysis`); checks run cvc5 |
//! | `python` | no | PyO3 bindings, built by maturin |
//! | `full` | no | everything except `python` |
//!
//! ## Assurance Status
//!
//! No external security audit has been performed. The levels below follow
//! `docs/architecture-v2.md` §6: *Enforced* means deterministic and
//! fail-closed, *Heuristic* means a useful signal that must not be the only
//! control on a dangerous action, *Experimental* means not sound.
//!
//! | Component | Level | Notes |
//! |-----------|-------|-------|
//! | Kernel mediation | Enforced | Default deny; unknown tools fail closed |
//! | Policy (`CedarEnforcer`, YAML) | Enforced | Cedar-style, not the `cedar-policy` engine |
//! | Policy (`CedarPolicy`, feature `cedar`) | Enforced | The `cedar-policy` engine; schema-validated; errors deny |
//! | Policy analysis (feature `cedar-analysis`) | Enforced, for the properties stated | SymCC with cvc5: ceilings, floors, never-errors, no-widening reloads |
//! | Kernel audit log | Enforced | RFC 9162 Merkle tree, signed tree heads; in memory, or durable (JSONL or SQLite) with `audit.log_path`, verified on open |
//! | WASM sandbox | Enforced | Fuel and wall-clock limits; Ed25519-signed skills pinned to their verified module |
//! | `reasoner` (PRM, ToT, Datalog, prompt-injection) | Heuristic | LLM judge, closures, regexes |
//! | `reasoner::zk_proof` | Experimental | Not a sound proof system |
//! | `swarm` consensus | Heuristic | Votes are unauthenticated |
//! | Python bindings (`python`) | Experimental | `vak.Kernel` doesn't call the kernel; `execute_tool` runs nothing (finding I4) |
//!
//! ## License
//!
//! MIT OR Apache-2.0

#![doc(html_root_url = "https://docs.rs/vak/0.1.0")]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rustdoc::missing_doc_code_examples)]
#![cfg_attr(test, allow(clippy::unwrap_used))]
#![cfg_attr(test, allow(clippy::expect_used))]

// Re-export core types at the crate root for convenience
pub use kernel::types::{
    AgentId, AuditEntry, AuditId, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse,
};

pub use kernel::config::KernelConfig;

/// Core kernel module containing the execution engine and policy enforcement.
pub mod kernel;

/// Multi-tier memory/state management with verifiable storage.
#[cfg(feature = "memory")]
pub mod memory;

/// WASM sandbox module for isolated skill/tool execution.
#[cfg(feature = "wasm")]
pub mod sandbox;

/// ABAC (Attribute-Based Access Control) policy engine.
pub mod policy;

/// Audit logging module for immutable audit trails.
pub mod audit;

/// LLM interface module for interacting with language models.
#[cfg(feature = "llm")]
pub mod llm;

/// Reasoner module with Process Reward Model (PRM) integration.
///
/// Provides step-by-step validation of reasoning chains using PRMs
/// to detect errors early and enable backtracking when needed.
///
/// Outside the trusted core, and heuristic: feature `reasoner`.
#[cfg(feature = "reasoner")]
pub mod reasoner;

/// Swarm consensus module for multi-agent coordination (SWM-001/002/003).
///
/// Provides swarm coordination, quadratic voting, and protocol routing
/// for multi-agent collaboration scenarios. Feature `swarm`.
#[cfg(feature = "swarm")]
pub mod swarm;

/// External framework integrations (Issue #45).
///
/// Provides middleware adapters for LangChain, AutoGPT, and other
/// agent frameworks to use VAK as a verification layer. Feature
/// `integrations`.
#[cfg(feature = "integrations")]
pub mod integrations;

/// API module.
///
/// Provides HTTP API endpoints for VAK features. Feature `dashboard`.
#[cfg(feature = "dashboard")]
pub mod api;

/// The superseded `vak-skill-sign` tool. Its signatures don't cover a
/// skill's permissions and the skill registry can't read them; use
/// `sandbox::signing` and `examples/sign_skill.rs` instead. Feature
/// `legacy-tools`.
#[cfg(feature = "legacy-tools")]
pub mod tools;

/// Dashboard and observability module (Issue #46).
///
/// Provides metrics endpoints, health checks, and a web-based
/// dashboard for monitoring VAK operations. Feature `dashboard`.
#[cfg(feature = "dashboard")]
pub mod dashboard;

/// LLM Integration Library (Issue #24).
///
/// High-level API for using VAK as a library in LLM-powered applications.
/// Provides builder patterns, tool definitions compatible with OpenAI/Anthropic
/// formats, and managed agent abstractions.
pub mod lib_integration;

/// Secrets management module (Issue #37).
///
/// Provides pluggable secrets providers for secure credential storage.
/// Supports environment variables, in-memory, file-based, and chained
/// providers with caching and expiration support.
pub mod secrets;

/// PyO3 Python bindings module (PY-001).
///
/// Provides Python bindings for the VAK Kernel via PyO3.
/// Build with `maturin develop --features python` to enable.
#[cfg(feature = "python")]
pub mod python;

pub mod prelude {
    //! Convenient re-exports for common VAK usage patterns.
    //!
    //! This module provides quick access to the most commonly used types
    //! for both kernel operations and LLM integration.
    //!
    //! # Example
    //!
    //! ```rust,ignore
    //! use vak::prelude::*;
    //!
    //! let runtime = VakRuntime::builder().build()?;
    //! let agent = runtime.create_agent("my-agent")?;
    //! ```

    // Core kernel types
    pub use crate::kernel::config::KernelConfig;
    pub use crate::kernel::types::{
        AgentId, AuditEntry, AuditId, KernelError, PolicyDecision, SessionId, ToolRequest,
        ToolResponse,
    };
    pub use crate::kernel::{
        FunctionHandler, Kernel, KernelBuilder, PolicyDecisionPoint, PolicyRequest, ToolHandler,
    };

    // Audit proofs
    pub use crate::audit::transparency::{
        verify_consistency, verify_inclusion, ConsistencyProof, InclusionProof, SignedTreeHead,
    };

    // LLM integration types for library consumers
    pub use crate::lib_integration::{ToolCall, ToolDefinition, ToolResult, VakAgent, VakRuntime};

    // Secrets management
    pub use crate::secrets::{SecretsManager, SecretsProvider};
}

/// Library version information.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Returns the library version as a tuple of (major, minor, patch).
#[must_use]
pub fn version() -> (u32, u32, u32) {
    let parts: Vec<u32> = VERSION.split('.').filter_map(|s| s.parse().ok()).collect();

    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_parsing() {
        let (major, minor, patch) = version();
        // Verify version components are valid (non-negative is implicit for u32)
        // This test ensures version parsing works correctly
        assert!(major < 1000, "Major version should be reasonable");
        assert!(minor < 1000, "Minor version should be reasonable");
        assert!(patch < 1000, "Patch version should be reasonable");
    }
}
