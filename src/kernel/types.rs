//! # Core Type Definitions
//!
//! This module contains the fundamental types used throughout the VAK kernel.
//! All types are designed with safety, serialization, and auditability in mind.
//!
//! ## Type Categories
//!
//! - **Identifiers**: `AgentId`, `SessionId`, `AuditId` - Unique identifiers for entities
//! - **Policy Types**: `PolicyDecision` - Represents the outcome of policy evaluation
//! - **Request/Response**: `ToolRequest`, `ToolResponse` - Communication primitives
//! - **Audit Types**: `AuditEntry` - Immutable audit log entries
//! - **Errors**: `KernelError` - Comprehensive error handling

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

// ============================================================================
// Identifier Types
// ============================================================================

/// A unique identifier for an agent in the system.
///
/// `AgentId` uses UUIDv7 for time-ordered unique identifiers, which provides:
/// - Global uniqueness
/// - Temporal ordering (newer IDs sort after older ones)
/// - High performance generation
///
/// # Example
///
/// ```rust
/// use vak::kernel::types::AgentId;
///
/// let agent_id = AgentId::new();
/// println!("Agent ID: {}", agent_id);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(Uuid);

impl AgentId {
    /// Creates a new unique agent identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Creates an `AgentId` from an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Parses an `AgentId` from a string representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid UUID.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for AgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "agent-{}", self.0)
    }
}

/// A unique identifier for a session.
///
/// Sessions track a continuous interaction between an agent and the kernel.
/// Each session maintains its own state and audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(Uuid);

impl SessionId {
    /// Creates a new unique session identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Creates a `SessionId` from an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }

    /// Parses a `SessionId` from a string representation.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not a valid UUID.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

/// A unique identifier for an audit log entry.
///
/// `AuditId` provides a cryptographically secure, time-ordered identifier
/// for each audit entry, ensuring traceability and integrity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditId(Uuid);

impl AuditId {
    /// Creates a new unique audit identifier.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Creates an `AuditId` from an existing UUID.
    #[must_use]
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Returns the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for AuditId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for AuditId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "audit-{}", self.0)
    }
}

// ============================================================================
// Policy Types
// ============================================================================

/// The result of a policy evaluation.
///
/// This enum represents the three possible outcomes when the policy engine
/// evaluates a request:
///
/// - `Allow`: The action is permitted, possibly with constraints
/// - `Deny`: The action is explicitly forbidden
/// - `Inadmissible`: The action cannot be evaluated (e.g., missing context)
///
/// # Example
///
/// ```rust
/// use vak::kernel::types::PolicyDecision;
///
/// let decision = PolicyDecision::Allow {
///     reason: "Agent has required permissions".to_string(),
///     constraints: Some(vec!["max_tokens:1000".to_string()]),
/// };
///
/// match decision {
///     PolicyDecision::Allow { reason, .. } => println!("Allowed: {}", reason),
///     PolicyDecision::Deny { reason, .. } => println!("Denied: {}", reason),
///     PolicyDecision::Inadmissible { reason } => println!("Inadmissible: {}", reason),
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// The action is allowed.
    Allow {
        /// Human-readable explanation for why the action was allowed.
        reason: String,
        /// Optional constraints that must be applied during execution.
        #[serde(skip_serializing_if = "Option::is_none")]
        constraints: Option<Vec<String>>,
    },

    /// The action is explicitly denied.
    Deny {
        /// Human-readable explanation for why the action was denied.
        reason: String,
        /// The specific policy rule(s) that caused the denial.
        #[serde(skip_serializing_if = "Option::is_none")]
        violated_policies: Option<Vec<String>>,
    },

    /// The action cannot be evaluated due to missing information or invalid state.
    Inadmissible {
        /// Human-readable explanation for why the action is inadmissible.
        reason: String,
    },
}

impl PolicyDecision {
    /// Returns `true` if the decision allows the action.
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow { .. })
    }

    /// Returns `true` if the decision denies the action.
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, PolicyDecision::Deny { .. })
    }

    /// Returns `true` if the decision is inadmissible.
    #[must_use]
    pub fn is_inadmissible(&self) -> bool {
        matches!(self, PolicyDecision::Inadmissible { .. })
    }

    /// Returns the reason for this decision.
    #[must_use]
    pub fn reason(&self) -> &str {
        match self {
            PolicyDecision::Allow { reason, .. }
            | PolicyDecision::Deny { reason, .. }
            | PolicyDecision::Inadmissible { reason } => reason,
        }
    }
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// A request from an agent to execute a tool.
///
/// `ToolRequest` encapsulates all the information needed to execute a tool
/// on behalf of an agent. Each request has a unique identifier for tracking
/// and auditing purposes.
///
/// # Example
///
/// ```rust
/// use vak::kernel::types::ToolRequest;
/// use serde_json::json;
///
/// let request = ToolRequest {
///     request_id: uuid::Uuid::new_v4(),
///     tool_name: "file_read".to_string(),
///     parameters: json!({
///         "path": "/data/config.json",
///         "encoding": "utf-8"
///     }),
///     timeout_ms: Some(5000),
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolRequest {
    /// Unique identifier for this request.
    pub request_id: Uuid,

    /// The name of the tool to execute.
    pub tool_name: String,

    /// Parameters to pass to the tool.
    pub parameters: serde_json::Value,

    /// Optional timeout in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl ToolRequest {
    /// Creates a new tool request with the given parameters.
    #[must_use]
    pub fn new(tool_name: impl Into<String>, parameters: serde_json::Value) -> Self {
        Self {
            request_id: Uuid::new_v4(),
            tool_name: tool_name.into(),
            parameters,
            timeout_ms: None,
        }
    }

    /// Sets the timeout for this request.
    #[must_use]
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = Some(timeout_ms);
        self
    }

    /// Computes a SHA-256 hash of the request for integrity verification.
    #[must_use]
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.request_id.as_bytes());
        hasher.update(self.tool_name.as_bytes());
        hasher.update(self.parameters.to_string().as_bytes());
        format!("{:x}", hasher.finalize())
    }
}

/// The response from a tool execution.
///
/// `ToolResponse` contains the result of executing a tool request,
/// including success/failure status, any returned data, and timing information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResponse {
    /// The ID of the original request.
    pub request_id: Uuid,

    /// Whether the tool execution was successful.
    pub success: bool,

    /// The result data if successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,

    /// Error information if the execution failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Time taken to execute the tool in milliseconds.
    pub execution_time_ms: u64,
}

impl ToolResponse {
    /// Creates a successful response with the given result.
    #[must_use]
    pub fn success(request_id: Uuid, result: serde_json::Value, execution_time_ms: u64) -> Self {
        Self {
            request_id,
            success: true,
            result: Some(result),
            error: None,
            execution_time_ms,
        }
    }

    /// Creates a failure response with the given error message.
    #[must_use]
    pub fn failure(request_id: Uuid, error: impl Into<String>, execution_time_ms: u64) -> Self {
        Self {
            request_id,
            success: false,
            result: None,
            error: Some(error.into()),
            execution_time_ms,
        }
    }
}

// ============================================================================
// Audit Types
// ============================================================================

/// An immutable audit log entry.
///
/// `AuditEntry` records all significant actions in the kernel, providing
/// a complete, tamper-evident trail of agent activity.
///
/// Each entry includes:
/// - A unique audit ID
/// - The agent and session involved
/// - The action taken and its result
/// - A cryptographic hash for integrity verification
/// - A reference to the previous entry (for chain integrity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this audit entry.
    pub audit_id: AuditId,

    /// Timestamp when the entry was created.
    pub timestamp: DateTime<Utc>,

    /// The agent that performed the action.
    pub agent_id: AgentId,

    /// The session in which the action was performed.
    pub session_id: SessionId,

    /// The action that was performed.
    pub action: String,

    /// The policy decision for this action.
    pub decision: PolicyDecision,

    /// SHA-256 hash of this entry's contents.
    pub hash: String,

    /// Hash of the previous audit entry (for chain integrity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
}

impl AuditEntry {
    /// Creates a new audit entry.
    #[must_use]
    pub fn new(
        agent_id: AgentId,
        session_id: SessionId,
        action: impl Into<String>,
        decision: PolicyDecision,
    ) -> Self {
        let audit_id = AuditId::new();
        let timestamp = Utc::now();
        let action = action.into();

        let hash = Self::compute_hash(&audit_id, &timestamp, &agent_id, &session_id, &action);

        Self {
            audit_id,
            timestamp,
            agent_id,
            session_id,
            action,
            decision,
            hash,
            previous_hash: None,
        }
    }

    /// Creates a new audit entry with a reference to the previous entry.
    #[must_use]
    pub fn with_previous(mut self, previous_hash: String) -> Self {
        self.previous_hash = Some(previous_hash);
        // Recompute hash to include previous_hash
        self.hash = Self::compute_hash(
            &self.audit_id,
            &self.timestamp,
            &self.agent_id,
            &self.session_id,
            &self.action,
        );
        self
    }

    /// Computes the SHA-256 hash for an audit entry.
    fn compute_hash(
        audit_id: &AuditId,
        timestamp: &DateTime<Utc>,
        agent_id: &AgentId,
        session_id: &SessionId,
        action: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(audit_id.0.as_bytes());
        hasher.update(timestamp.to_rfc3339().as_bytes());
        hasher.update(agent_id.0.as_bytes());
        hasher.update(session_id.0.as_bytes());
        hasher.update(action.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Verifies the integrity of this audit entry by recomputing its hash.
    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        let computed = Self::compute_hash(
            &self.audit_id,
            &self.timestamp,
            &self.agent_id,
            &self.session_id,
            &self.action,
        );
        computed == self.hash
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in the VAK kernel.
///
/// This enum provides comprehensive error handling for all kernel operations,
/// with detailed context for debugging and auditing.
#[derive(Debug, Error)]
pub enum KernelError {
    /// The kernel configuration is invalid.
    #[error("Invalid configuration: {message}")]
    InvalidConfiguration {
        /// Description of the configuration error.
        message: String,
    },

    /// A policy violation occurred.
    #[error("Policy violation [{policy_id}]: {reason}")]
    PolicyViolation {
        /// The ID of the violated policy.
        policy_id: String,
        /// The reason for the violation.
        reason: String,
    },

    /// The requested tool was not found.
    #[error("Tool not found: {tool_name}")]
    ToolNotFound {
        /// The name of the tool that was not found.
        tool_name: String,
    },

    /// Tool execution failed.
    #[error("Tool execution failed [{tool_name}]: {reason}")]
    ToolExecutionFailed {
        /// The name of the tool that failed.
        tool_name: String,
        /// The reason for the failure.
        reason: String,
    },

    /// The agent was not found.
    #[error("Agent not found: {agent_id}")]
    AgentNotFound {
        /// The ID of the agent that was not found.
        agent_id: String,
    },

    /// The session was not found or has expired.
    #[error("Session not found or expired: {session_id}")]
    SessionNotFound {
        /// The ID of the session that was not found.
        session_id: String,
    },

    /// An internal kernel error occurred.
    #[error("Internal kernel error: {message}")]
    InternalError {
        /// Description of the internal error.
        message: String,
    },

    /// Serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// A timeout occurred during execution.
    #[error("Operation timed out after {timeout_ms}ms")]
    Timeout {
        /// The timeout duration in milliseconds.
        timeout_ms: u64,
    },

    /// Resource limit exceeded.
    #[error("Resource limit exceeded: {resource} (limit: {limit}, requested: {requested})")]
    ResourceLimitExceeded {
        /// The name of the resource.
        resource: String,
        /// The limit value.
        limit: u64,
        /// The requested value.
        requested: u64,
    },
}

impl KernelError {
    /// Returns `true` if this error is recoverable.
    #[must_use]
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            KernelError::Timeout { .. } | KernelError::ResourceLimitExceeded { .. }
        )
    }

    /// Returns an error code for this error type.
    #[must_use]
    pub fn error_code(&self) -> &'static str {
        match self {
            KernelError::InvalidConfiguration { .. } => "E001",
            KernelError::PolicyViolation { .. } => "E002",
            KernelError::ToolNotFound { .. } => "E003",
            KernelError::ToolExecutionFailed { .. } => "E004",
            KernelError::AgentNotFound { .. } => "E005",
            KernelError::SessionNotFound { .. } => "E006",
            KernelError::InternalError { .. } => "E007",
            KernelError::SerializationError(_) => "E008",
            KernelError::Timeout { .. } => "E009",
            KernelError::ResourceLimitExceeded { .. } => "E010",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_creation() {
        let id1 = AgentId::new();
        let id2 = AgentId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_agent_id_parsing() {
        let original = AgentId::new();
        let uuid_str = original.as_uuid().to_string();
        let parsed = AgentId::parse(&uuid_str).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_policy_decision_helpers() {
        let allow = PolicyDecision::Allow {
            reason: "test".to_string(),
            constraints: None,
        };
        assert!(allow.is_allowed());
        assert!(!allow.is_denied());

        let deny = PolicyDecision::Deny {
            reason: "test".to_string(),
            violated_policies: None,
        };
        assert!(deny.is_denied());
        assert!(!deny.is_allowed());
    }

    #[test]
    fn test_tool_request_hash() {
        let request = ToolRequest::new("test_tool", serde_json::json!({"key": "value"}));
        let hash1 = request.compute_hash();
        let hash2 = request.compute_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_audit_entry_integrity() {
        let entry = AuditEntry::new(
            AgentId::new(),
            SessionId::new(),
            "test_action",
            PolicyDecision::Allow {
                reason: "test".to_string(),
                constraints: None,
            },
        );
        assert!(entry.verify_integrity());
    }

    #[test]
    fn test_kernel_error_codes() {
        let error = KernelError::PolicyViolation {
            policy_id: "test".to_string(),
            reason: "test".to_string(),
        };
        assert_eq!(error.error_code(), "E002");
    }
}
