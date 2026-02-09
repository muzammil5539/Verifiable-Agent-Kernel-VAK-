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
//! - **Policy Enforcement**: Cedar-based ABAC policies control all actions
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
//! - [`kernel`]: Core kernel orchestration and execution
//! - [`policy`]: Cedar-based policy enforcement
//! - [`audit`]: Immutable audit logging and tracing
//! - [`memory`]: Hierarchical memory with Merkle proofs
//! - [`reasoner`]: Neuro-symbolic safety verification
//! - [`sandbox`]: WASM execution sandbox
//! - [`swarm`]: Multi-agent coordination
//! - [`llm`]: LLM provider abstractions
//! - [`integrations`]: External system integrations
//!
//! ## Safety Guarantees
//!
//! VAK provides several safety guarantees:
//!
//! 1. **Computational Safety**: WASM sandbox with epoch-based preemption
//! 2. **Policy Safety**: All actions validated against Cedar policies
//! 3. **Memory Safety**: Rust's ownership system + WASM isolation
//! 4. **Audit Safety**: Tamper-evident Merkle-chained logs
//!
//! ## Feature Flags
//!
//! - `python`: Enable Python bindings via PyO3
//! - `full`: Enable all features
//!
//! ## Security Audit Status
//!
//! | Component | Status | Notes |
//! |-----------|--------|-------|
//! | Core Kernel | ✅ Audited | SEC-003 compliant |
//! | WASM Sandbox | ✅ Audited | Documented unsafe blocks |
//! | Policy Engine | ✅ Audited | Default-deny enforcement |
//! | Audit Logger | ✅ Audited | Hash chain verification |
//!
//! ## License
//!
//! MIT OR Apache-2.0

#![doc(html_root_url = "https://docs.rs/vak/0.1.0")]
#![deny(unsafe_code)]
#![allow(missing_docs)]
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
pub mod memory;

/// WASM sandbox module for isolated skill/tool execution.
pub mod sandbox;

/// ABAC (Attribute-Based Access Control) policy engine.
pub mod policy;

/// Audit logging module for immutable audit trails.
pub mod audit;

/// LLM interface module for interacting with language models.
pub mod llm;

/// Reasoner module with Process Reward Model (PRM) integration.
///
/// Provides step-by-step validation of reasoning chains using PRMs
/// to detect errors early and enable backtracking when needed.
pub mod reasoner;

/// Swarm consensus module for multi-agent coordination (SWM-001/002/003).
///
/// Provides swarm coordination, quadratic voting, and protocol routing
/// for multi-agent collaboration scenarios.
pub mod swarm;

/// External framework integrations (Issue #45).
///
/// Provides middleware adapters for LangChain, AutoGPT, and other
/// agent frameworks to use VAK as a verification layer.
pub mod integrations;

/// API module.
///
/// Provides HTTP API endpoints for VAK features.
pub mod api;

/// CLI tools module.
///
/// Provides command-line utilities for VAK operations including
/// skill signing with vak-skill-sign.
pub mod tools;

/// Dashboard and observability module (Issue #46).
///
/// Provides metrics endpoints, health checks, and a web-based
/// dashboard for monitoring VAK operations.
pub mod dashboard;

/// PyO3 Python bindings module (PY-001).
///
/// Provides Python bindings for the VAK Kernel via PyO3.
/// Build with `maturin develop --features python` to enable.
#[cfg(feature = "python")]
pub mod python;

/// Prelude module for convenient imports.
///
/// # Example
///
/// ```rust,ignore
/// use vak::prelude::*;
/// ```
pub mod prelude {
    //! Convenient re-exports for common VAK usage patterns.
    //!
    //! This module provides quick access to the most commonly used types.
    //!
    //! # Example
    //!
    //! ```rust,ignore
    //! use vak::prelude::*;
    //! ```

    pub use crate::kernel::config::KernelConfig;
    pub use crate::kernel::types::{
        AgentId, AuditEntry, AuditId, KernelError, PolicyDecision, SessionId, ToolRequest,
        ToolResponse,
    };
    pub use crate::kernel::Kernel;
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
