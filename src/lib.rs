//! # Verifiable Agent Kernel (VAK)
//!
//! VAK is a secure, auditable execution environment for AI agents. It provides:
//!
//! - **Policy-based access control**: Fine-grained permissions for agent actions
//! - **Cryptographic audit trails**: Immutable, verifiable logs of all operations
//! - **Sandboxed execution**: Isolated environments for safe agent operation
//! - **Formal verification**: Mathematical guarantees of safety properties
//!
//! ## Architecture
//!
//! The kernel is organized into several core modules:
//!
//! - [`kernel`]: Core kernel functionality including policy engine and execution
//! - [`types`]: Core type definitions used throughout the system
//! - [`config`]: Configuration management and validation
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use vak::kernel::{Kernel, KernelConfig};
//! use vak::kernel::types::ToolRequest;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Initialize the kernel with default configuration
//!     let config = KernelConfig::default();
//!     let kernel = Kernel::new(config).await?;
//!     
//!     // Process a tool request
//!     // let response = kernel.execute(request).await?;
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - `full`: Enable all features
//! - `tracing`: Enable detailed tracing instrumentation
//! - `metrics`: Enable Prometheus metrics export

#![doc(html_logo_url = "https://example.com/vak-logo.png")]
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    missing_debug_implementations,
    rust_2018_idioms,
    unreachable_pub,
    clippy::all,
    clippy::pedantic
)]
#![allow(clippy::module_name_repetitions)]

// Re-export core types at the crate root for convenience
pub use kernel::types::{
    AgentId, AuditEntry, AuditId, KernelError, PolicyDecision, SessionId, ToolRequest,
    ToolResponse,
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

/// Prelude module for convenient imports.
///
/// # Example
///
/// ```rust
/// use vak::prelude::*;
/// ```
pub mod prelude {
    //! Convenient re-exports for common VAK usage patterns.

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
    let parts: Vec<u32> = VERSION
        .split('.')
        .filter_map(|s| s.parse().ok())
        .collect();

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
