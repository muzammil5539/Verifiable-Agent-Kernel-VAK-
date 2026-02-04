//! Common types and traits for framework adapters

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Adapter-specific errors
#[derive(Debug, Error)]
pub enum AdapterError {
    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// PRM score too low
    #[error("PRM score {score} below threshold {threshold}")]
    LowPrmScore { score: f64, threshold: f64 },

    /// Action blocked
    #[error("Action '{action}' blocked: {reason}")]
    ActionBlocked { action: String, reason: String },

    /// Rate limited
    #[error("Rate limited: {0}")]
    RateLimited(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Communication error with VAK kernel
    #[error("Kernel communication error: {0}")]
    KernelError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for adapter operations
pub type AdapterResult<T> = Result<T, AdapterError>;

// ============================================================================
// Hook Types
// ============================================================================

/// Decision made by an interception hook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HookDecision {
    /// Allow the action to proceed
    Allow,
    /// Block the action with a reason
    Block { reason: String },
    /// Modify the action parameters
    Modify { new_params: HashMap<String, serde_json::Value> },
    /// Require human approval before proceeding
    RequireApproval { prompt: String },
    /// Log and monitor but allow
    Monitor { alert_level: AlertLevel },
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AlertLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Trait for interception hooks
pub trait InterceptionHook: Send + Sync {
    /// Name of the hook
    fn name(&self) -> &str;
    
    /// Check if the hook should apply to this action
    fn applies_to(&self, action: &ActionContext) -> bool;
    
    /// Evaluate the action and return a decision
    fn evaluate(&self, action: &ActionContext) -> HookDecision;
}

// ============================================================================
// Action Context
// ============================================================================

/// Context about an action being performed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionContext {
    /// Type of action (tool call, chain execution, etc.)
    pub action_type: ActionType,
    /// Name of the action or tool
    pub name: String,
    /// Input parameters
    pub params: HashMap<String, serde_json::Value>,
    /// Agent identifier
    pub agent_id: String,
    /// Session identifier
    pub session_id: String,
    /// Timestamp
    pub timestamp: u64,
    /// Previous actions in this session
    pub previous_actions: Vec<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Types of actions that can be intercepted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// LangChain tool invocation
    ToolCall,
    /// LangChain chain execution
    ChainExecution,
    /// AutoGPT task planning
    TaskPlanning,
    /// AutoGPT command execution
    CommandExecution,
    /// LLM prompt/completion
    LlmCall,
    /// Memory access
    MemoryAccess,
    /// File operation
    FileOperation,
    /// Network request
    NetworkRequest,
    /// Code execution
    CodeExecution,
    /// Database query
    DatabaseQuery,
    /// Generic action
    Other,
}

impl ActionContext {
    /// Create a new action context
    pub fn new(action_type: ActionType, name: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            action_type,
            name: name.into(),
            params: HashMap::new(),
            agent_id: agent_id.into(),
            session_id: uuid::Uuid::new_v4().to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            previous_actions: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a parameter
    pub fn with_param(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        self.params.insert(
            key.into(),
            serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
        );
        self
    }

    /// Set session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = session_id.into();
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

// ============================================================================
// Interception Result
// ============================================================================

/// Result of action interception
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterceptionResult {
    /// Original action context
    pub context: ActionContext,
    /// Decision made
    pub decision: HookDecision,
    /// Name of hook that made the decision
    pub hook_name: String,
    /// PRM score if evaluated
    pub prm_score: Option<f64>,
    /// Execution time in microseconds
    pub evaluation_time_us: u64,
    /// Audit log entry ID
    pub audit_entry_id: Option<String>,
}

// ============================================================================
// Adapter Configuration Base
// ============================================================================

/// Base configuration for all adapters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseAdapterConfig {
    /// Enable/disable the adapter
    pub enabled: bool,
    /// PRM score threshold
    pub prm_threshold: f64,
    /// Enable audit logging
    pub audit_enabled: bool,
    /// Actions to always block
    pub blocked_actions: Vec<String>,
    /// Actions to always allow (bypass checks)
    pub allowed_actions: Vec<String>,
    /// Maximum actions per minute
    pub rate_limit_per_minute: Option<u32>,
    /// Human approval required actions
    pub require_approval: Vec<String>,
}

impl Default for BaseAdapterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            prm_threshold: 0.7,
            audit_enabled: true,
            blocked_actions: vec![],
            allowed_actions: vec![],
            rate_limit_per_minute: Some(60),
            require_approval: vec![],
        }
    }
}

// ============================================================================
// VAK Connection
// ============================================================================

/// Connection to the VAK kernel
pub struct VakConnection {
    /// Kernel address (for remote connections)
    pub address: Option<String>,
    /// Connection timeout
    pub timeout_ms: u64,
    /// Whether using local in-process kernel
    pub local: bool,
}

impl Default for VakConnection {
    fn default() -> Self {
        Self {
            address: None,
            timeout_ms: 5000,
            local: true,
        }
    }
}

impl VakConnection {
    /// Create a local in-process connection
    pub fn local() -> Self {
        Self::default()
    }

    /// Create a remote connection
    pub fn remote(address: impl Into<String>) -> Self {
        Self {
            address: Some(address.into()),
            timeout_ms: 5000,
            local: false,
        }
    }
}
