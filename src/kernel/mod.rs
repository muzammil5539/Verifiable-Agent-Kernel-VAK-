//! # VAK Kernel Module
//!
//! This module contains the core kernel implementation for the Verifiable Agent Kernel.
//! It provides the central execution engine, policy enforcement, and audit capabilities.
//!
//! ## Submodules
//!
//! - [`types`]: Core type definitions (AgentId, SessionId, PolicyDecision, etc.)
//! - [`config`]: Kernel configuration structures and validation
//! - [`traits`]: Async traits for policy evaluation, audit, state, and tool execution
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        VAK Kernel                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │   Policy    │  │    Audit     │  │     Session      │   │
//! │  │   Engine    │  │   Logger     │  │    Manager       │   │
//! │  └─────────────┘  └──────────────┘  └──────────────────┘   │
//! │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │    Tool     │  │    State     │  │    Sandbox       │   │
//! │  │  Registry   │  │   Manager    │  │    Runtime       │   │
//! │  └─────────────┘  └──────────────┘  └──────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod config;
pub mod traits;
pub mod types;

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{info, instrument};

use self::config::KernelConfig;
use self::types::{
    AgentId, AuditEntry, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse,
};

/// The main kernel instance that manages agent execution and policy enforcement.
///
/// The `Kernel` is the central component of VAK, responsible for:
/// - Processing tool requests from agents
/// - Enforcing security policies
/// - Maintaining audit logs
/// - Managing agent sessions
///
/// # Thread Safety
///
/// `Kernel` is designed to be shared across threads. Clone the `Arc<Kernel>`
/// to share ownership between tasks.
///
/// # Example
///
/// ```rust,no_run
/// use vak::kernel::{Kernel, KernelConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = KernelConfig::default();
/// let kernel = Kernel::new(config).await?;
///
/// // Kernel is now ready to process requests
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Kernel {
    /// Kernel configuration
    config: KernelConfig,

    /// Audit log entries (in production, this would be persisted)
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,

    /// Active sessions
    sessions: Arc<RwLock<std::collections::HashMap<SessionId, AgentId>>>,
}

impl Kernel {
    /// Creates a new kernel instance with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `config` - The kernel configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel fails to initialize (e.g., invalid configuration).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vak::kernel::{Kernel, KernelConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let kernel = Kernel::new(KernelConfig::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(config), fields(kernel_name = %config.name))]
    pub async fn new(config: KernelConfig) -> Result<Self, KernelError> {
        config.validate()?;

        info!(
            kernel_name = %config.name,
            max_agents = config.max_concurrent_agents,
            "Initializing VAK kernel"
        );

        Ok(Self {
            config,
            audit_log: Arc::new(RwLock::new(Vec::new())),
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        })
    }

    /// Returns a reference to the kernel configuration.
    #[must_use]
    pub fn config(&self) -> &KernelConfig {
        &self.config
    }

    /// Evaluates a policy decision for a given tool request.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The ID of the agent making the request
    /// * `request` - The tool request to evaluate
    ///
    /// # Returns
    ///
    /// A `PolicyDecision` indicating whether the request is allowed, denied, or inadmissible.
    #[instrument(skip(self, request), fields(agent_id = %agent_id, tool = %request.tool_name))]
    pub async fn evaluate_policy(
        &self,
        agent_id: &AgentId,
        request: &ToolRequest,
    ) -> PolicyDecision {
        // TODO: Implement actual policy evaluation logic
        // For now, return Allow for demonstration
        info!(
            agent_id = %agent_id,
            tool = %request.tool_name,
            "Evaluating policy for tool request"
        );

        PolicyDecision::Allow {
            reason: "Default allow policy".to_string(),
            constraints: None,
        }
    }

    /// Executes a tool request after policy evaluation.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The ID of the agent making the request
    /// * `session_id` - The session ID for the request
    /// * `request` - The tool request to execute
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The policy evaluation denies the request
    /// - The tool execution fails
    /// - The audit logging fails
    #[instrument(skip(self, request), fields(
        agent_id = %agent_id,
        session_id = %session_id,
        tool = %request.tool_name
    ))]
    pub async fn execute(
        &self,
        agent_id: &AgentId,
        session_id: &SessionId,
        request: ToolRequest,
    ) -> Result<ToolResponse, KernelError> {
        // Step 1: Evaluate policy
        let decision = self.evaluate_policy(agent_id, &request).await;

        match &decision {
            PolicyDecision::Deny { reason, .. } => {
                return Err(KernelError::PolicyViolation {
                    policy_id: "default".to_string(),
                    reason: reason.clone(),
                });
            }
            PolicyDecision::Inadmissible { reason } => {
                return Err(KernelError::PolicyViolation {
                    policy_id: "default".to_string(),
                    reason: reason.clone(),
                });
            }
            PolicyDecision::Allow { .. } => {
                // Continue with execution
            }
        }

        // Step 2: Log the request
        let audit_entry = AuditEntry::new(
            agent_id.clone(),
            session_id.clone(),
            request.tool_name.clone(),
            decision,
        );

        {
            let mut log = self.audit_log.write().await;
            log.push(audit_entry);
        }

        // Step 3: Execute the tool (placeholder)
        // TODO: Implement actual tool execution
        let response = ToolResponse {
            request_id: request.request_id,
            success: true,
            result: Some(serde_json::json!({
                "status": "executed",
                "tool": request.tool_name
            })),
            error: None,
            execution_time_ms: 0,
        };

        Ok(response)
    }

    /// Retrieves the audit log entries.
    ///
    /// In production, this would support pagination and filtering.
    pub async fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().await.clone()
    }

    /// Returns the number of active sessions.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kernel_creation() {
        let config = KernelConfig::default();
        let kernel = Kernel::new(config).await;
        assert!(kernel.is_ok());
    }

    #[tokio::test]
    async fn test_policy_evaluation() {
        let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
        let agent_id = AgentId::new();
        let request = ToolRequest {
            request_id: uuid::Uuid::new_v4(),
            tool_name: "test_tool".to_string(),
            parameters: serde_json::json!({}),
            timeout_ms: Some(5000),
        };

        let decision = kernel.evaluate_policy(&agent_id, &request).await;
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }
}
