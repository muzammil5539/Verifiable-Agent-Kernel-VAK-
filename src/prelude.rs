//! Convenient re-exports for common VAK types.
//!
//! This module provides a "prelude" that can be imported to get quick access
//! to the most commonly used types in VAK.
//!
//! # Example
//!
//! ```rust,ignore
//! use vak::prelude::*;
//!
//! let agent_id = AgentId::new();
//! let session_id = SessionId::new();
//! let request = ToolRequest::new("calculator", serde_json::json!({}));
//! ```

// Core kernel types
pub use crate::kernel::{Kernel, KernelError, KernelResult};
pub use crate::kernel::types::{AgentId, SessionId, ToolRequest, ToolResponse};

// Policy types
pub use crate::policy::{PolicyDecision, PolicyEffect, PolicyEngine, PolicyError};

// Audit types
pub use crate::audit::{AuditEntry, AuditDecision, AuditLogger};

// Memory types
pub use crate::memory::{MemoryStore, ContentId};

// Reasoner types  
pub use crate::reasoner::{SafetyEngine, SafetyVerdict, Fact, Violation};

// Swarm types
pub use crate::swarm::{SwarmAgentId, SwarmAgent, AgentRole, SwarmConfig};

// Re-export common external types
pub use serde_json::json;
