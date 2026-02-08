use serde::{Deserialize, Serialize};

// ============================================================================
// Audit Entry Types
// ============================================================================

/// Represents a single audit log entry with cryptographic chaining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this entry
    pub id: u64,
    /// Unix timestamp when the entry was created
    pub timestamp: u64,
    /// ID of the agent that performed the action
    pub agent_id: String,
    /// The action that was performed
    pub action: String,
    /// The resource that was accessed
    pub resource: String,
    /// The decision outcome
    pub decision: AuditDecision,
    /// SHA-256 hash of this entry
    pub hash: String,
    /// Hash of the previous entry (chain linkage)
    pub prev_hash: String,
    /// Optional ed25519 signature for non-repudiation (Issue #51)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Optional metadata for extensibility
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Decision outcome for an audited action
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuditDecision {
    /// Action was allowed
    Allowed,
    /// Action was denied
    Denied,
    /// An error occurred during evaluation
    Error(String),
}

impl std::fmt::Display for AuditDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditDecision::Allowed => write!(f, "ALLOWED"),
            AuditDecision::Denied => write!(f, "DENIED"),
            AuditDecision::Error(msg) => write!(f, "ERROR: {}", msg),
        }
    }
}

/// Compliance report generated from audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// Total number of audit entries
    pub total_entries: usize,
    /// Number of allowed actions
    pub allowed_count: usize,
    /// Number of denied actions
    pub denied_count: usize,
    /// Number of actions that resulted in errors
    pub error_count: usize,
    /// Whether the hash chain is valid
    pub chain_valid: bool,
    /// Timestamp of first entry (if any)
    pub first_timestamp: Option<u64>,
    /// Timestamp of last entry (if any)
    pub last_timestamp: Option<u64>,
    /// All audit entries
    pub entries: Vec<AuditEntry>,
}
