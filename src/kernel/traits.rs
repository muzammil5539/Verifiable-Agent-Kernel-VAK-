//! Core async traits for the Verifiable Agent Kernel (VAK).
//!
//! This module defines the fundamental abstractions for policy evaluation,
//! audit logging, state management, and tool execution within the kernel.

use async_trait::async_trait;
use crate::kernel::error::KernelError;
use crate::kernel::types::{AgentId, ToolRequest, ToolResponse};

/// Context information for policy evaluation decisions.
#[derive(Debug, Clone)]
pub struct PolicyContext {
    /// The agent making the request.
    pub agent_id: AgentId,
    /// Current timestamp for the evaluation.
    pub timestamp: u64,
    /// Additional metadata for policy evaluation.
    pub metadata: std::collections::HashMap<String, String>,
}

/// Result of a policy evaluation specific to the traits module.
/// This is a simplified version for trait implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraitPolicyDecision {
    /// The request is allowed to proceed.
    Allow,
    /// The request is denied with a reason.
    Deny(String),
    /// The request requires additional review or escalation.
    Escalate(String),
}

/// An entry in the audit log for trait implementations.
/// This is a simplified version for trait implementations.
#[derive(Debug, Clone)]
pub struct TraitAuditEntry {
    /// Unique identifier for this audit entry.
    pub id: String,
    /// Timestamp when the event occurred.
    pub timestamp: u64,
    /// The agent involved in the event.
    pub agent_id: AgentId,
    /// Type of event being audited.
    pub event_type: String,
    /// Detailed description of the event.
    pub details: String,
    /// The outcome or result of the event.
    pub outcome: Option<String>,
}

/// Evaluates tool requests against defined policies.
///
/// The `PolicyEvaluator` trait provides the core abstraction for determining
/// whether a given tool request should be allowed, denied, or escalated
/// based on the current policy context.
///
/// # Example
///
/// ```ignore
/// use async_trait::async_trait;
/// use vak::kernel::traits::{PolicyEvaluator, PolicyContext, TraitPolicyDecision};
///
/// struct MyPolicyEvaluator;
///
/// #[async_trait]
/// impl PolicyEvaluator for MyPolicyEvaluator {
///     async fn evaluate(
///         &self,
///         request: &ToolRequest,
///         context: &PolicyContext,
///     ) -> Result<TraitPolicyDecision, KernelError> {
///         // Custom policy logic here
///         Ok(TraitPolicyDecision::Allow)
///     }
/// }
/// ```
#[async_trait]
pub trait PolicyEvaluator: Send + Sync {
    /// Evaluates a tool request against the current policies.
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to evaluate.
    /// * `context` - The policy context containing agent info and metadata.
    ///
    /// # Returns
    ///
    /// A `TraitPolicyDecision` indicating whether the request is allowed, denied, or escalated.
    async fn evaluate(
        &self,
        request: &ToolRequest,
        context: &PolicyContext,
    ) -> Result<TraitPolicyDecision, KernelError>;
}

/// Writes audit entries to a persistent audit log.
///
/// The `AuditWriter` trait provides the abstraction for recording
/// security-relevant events and actions within the kernel for
/// compliance and forensic analysis.
///
/// # Example
///
/// ```ignore
/// use async_trait::async_trait;
/// use vak::kernel::traits::{AuditWriter, TraitAuditEntry};
///
/// struct FileAuditWriter;
///
/// #[async_trait]
/// impl AuditWriter for FileAuditWriter {
///     async fn write_entry(&self, entry: TraitAuditEntry) -> Result<(), KernelError> {
///         // Write to file or external system
///         Ok(())
///     }
/// }
/// ```
#[async_trait]
pub trait AuditWriter: Send + Sync {
    /// Writes an audit entry to the audit log.
    ///
    /// # Arguments
    ///
    /// * `entry` - The audit entry to record.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the entry was successfully written, or an error otherwise.
    async fn write_entry(&self, entry: TraitAuditEntry) -> Result<(), KernelError>;
}

/// Manages persistent state for agents.
///
/// The `StateStore` trait provides a key-value abstraction for storing
/// and retrieving agent state data. Implementations may use various
/// backends such as in-memory stores, databases, or distributed systems.
///
/// # Example
///
/// ```ignore
/// use async_trait::async_trait;
/// use vak::kernel::traits::StateStore;
///
/// struct InMemoryStateStore {
///     data: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
/// }
///
/// #[async_trait]
/// impl StateStore for InMemoryStateStore {
///     async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KernelError> {
///         Ok(self.data.read().unwrap().get(key).cloned())
///     }
///
///     async fn set(&self, key: &str, value: Vec<u8>) -> Result<(), KernelError> {
///         self.data.write().unwrap().insert(key.to_string(), value);
///         Ok(())
///     }
///
///     async fn delete(&self, key: &str) -> Result<bool, KernelError> {
///         Ok(self.data.write().unwrap().remove(key).is_some())
///     }
/// }
/// ```
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Retrieves the value associated with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up.
    ///
    /// # Returns
    ///
    /// `Some(value)` if the key exists, `None` otherwise.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KernelError>;

    /// Stores a value with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key under which to store the value.
    /// * `value` - The value to store.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the value was successfully stored, or an error otherwise.
    async fn set(&self, key: &str, value: Vec<u8>) -> Result<(), KernelError>;

    /// Deletes the value associated with the given key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete.
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the key existed and was deleted, `Ok(false)` if the key did not exist.
    async fn delete(&self, key: &str) -> Result<bool, KernelError>;

    /// Checks if a key exists in the store.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to check.
    ///
    /// # Returns
    ///
    /// `true` if the key exists, `false` otherwise.
    async fn exists(&self, key: &str) -> Result<bool, KernelError> {
        Ok(self.get(key).await?.is_some())
    }
}

/// Executes tool requests and returns responses.
///
/// The `ToolExecutor` trait provides the abstraction for executing
/// tool calls requested by agents. Implementations handle the actual
/// invocation of tools, whether they are local functions, external APIs,
/// or sandboxed WASM modules.
///
/// # Example
///
/// ```ignore
/// use async_trait::async_trait;
/// use vak::kernel::traits::ToolExecutor;
/// use vak::kernel::types::{ToolRequest, ToolResponse};
///
/// struct LocalToolExecutor;
///
/// #[async_trait]
/// impl ToolExecutor for LocalToolExecutor {
///     async fn execute(&self, request: ToolRequest) -> Result<ToolResponse, KernelError> {
///         // Execute the tool and return the response
///         Ok(ToolResponse {
///             request_id: request.id,
///             success: true,
///             result: Some("Tool executed successfully".to_string()),
///             error: None,
///         })
///     }
/// }
/// ```
#[async_trait]
pub trait ToolExecutor: Send + Sync {
    /// Executes a tool request and returns the response.
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to execute.
    ///
    /// # Returns
    ///
    /// A `ToolResponse` containing the result of the execution.
    async fn execute(&self, request: ToolRequest) -> Result<ToolResponse, KernelError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_decision_equality() {
        assert_eq!(TraitPolicyDecision::Allow, TraitPolicyDecision::Allow);
        assert_eq!(
            TraitPolicyDecision::Deny("reason".to_string()),
            TraitPolicyDecision::Deny("reason".to_string())
        );
        assert_ne!(TraitPolicyDecision::Allow, TraitPolicyDecision::Deny("denied".to_string()));
    }

    #[test]
    fn test_audit_entry_creation() {
        let entry = TraitAuditEntry {
            id: "test-001".to_string(),
            timestamp: 1234567890,
            agent_id: AgentId::new(),
            event_type: "tool_execution".to_string(),
            details: "Executed read_file tool".to_string(),
            outcome: Some("success".to_string()),
        };
        assert_eq!(entry.id, "test-001");
        assert_eq!(entry.event_type, "tool_execution");
    }
}
