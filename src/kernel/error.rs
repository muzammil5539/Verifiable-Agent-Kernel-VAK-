//! Kernel error types for the Verifiable Agent Kernel.

use thiserror::Error;

/// Represents all possible errors that can occur within the kernel.
#[derive(Debug, Error)]
pub enum KernelError {
    /// A policy rule was violated during execution.
    #[error("Policy violation: rule '{rule}' - {reason}")]
    PolicyViolation {
        /// The policy rule that was violated.
        rule: String,
        /// The reason for the violation.
        reason: String,
    },

    /// An action was deemed inadmissible by the kernel.
    #[error("Inadmissible action '{action}': {explanation}")]
    Inadmissible {
        /// The action that was rejected.
        action: String,
        /// Explanation of why the action is inadmissible.
        explanation: String,
    },

    /// The requested agent was not found in the registry.
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// The session has expired or is invalid.
    #[error("Session expired: {0}")]
    SessionExpired(String),

    /// A tool execution failed during agent processing.
    #[error("Tool execution failed: tool '{tool}' - {cause}")]
    ToolExecutionFailed {
        /// The tool that failed.
        tool: String,
        /// The cause of the failure.
        cause: String,
    },

    /// A configuration error occurred.
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// An error occurred during audit logging.
    #[error("Audit error: {0}")]
    AuditError(String),

    /// An error occurred in the sandbox environment.
    #[error("Sandbox error: {0}")]
    SandboxError(String),

    /// An internal kernel error occurred.
    #[error("Internal error: {0}")]
    InternalError(String),
}

impl KernelError {
    /// Creates a new PolicyViolation error.
    pub fn policy_violation(rule: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::PolicyViolation {
            rule: rule.into(),
            reason: reason.into(),
        }
    }

    /// Creates a new Inadmissible error.
    pub fn inadmissible(action: impl Into<String>, explanation: impl Into<String>) -> Self {
        Self::Inadmissible {
            action: action.into(),
            explanation: explanation.into(),
        }
    }

    /// Creates a new ToolExecutionFailed error.
    pub fn tool_execution_failed(tool: impl Into<String>, cause: impl Into<String>) -> Self {
        Self::ToolExecutionFailed {
            tool: tool.into(),
            cause: cause.into(),
        }
    }
}

/// A specialized Result type for kernel operations.
pub type KernelResult<T> = Result<T, KernelError>;
