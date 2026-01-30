use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, instrument};

use crate::kernel::types::{AgentId, ToolCall, ToolResult, Policy, AuditEntry};

/// Policy engine for validating tool executions
#[derive(Debug, Default)]
pub struct PolicyEngine {
    policies: HashMap<String, Policy>,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    pub fn add_policy(&mut self, name: String, policy: Policy) {
        self.policies.insert(name, policy);
    }

    pub fn check(&self, agent_id: &AgentId, tool_call: &ToolCall) -> bool {
        // Default: allow if no policies defined, otherwise check all applicable policies
        self.policies.values().all(|policy| policy.allows(agent_id, tool_call))
    }
}

/// Audit logger for recording kernel operations
#[derive(Debug, Default)]
pub struct AuditLogger {
    entries: Vec<AuditEntry>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn log(&mut self, entry: AuditEntry) {
        info!(agent_id = %entry.agent_id, action = %entry.action, "Audit log entry");
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}

/// Kernel state tracking registered agents and execution context
#[derive(Debug, Default)]
pub struct KernelState {
    agents: HashMap<AgentId, AgentInfo>,
    running: bool,
}

#[derive(Debug, Clone)]
pub struct AgentInfo {
    pub id: AgentId,
    pub name: String,
    pub capabilities: Vec<String>,
}

/// Main Verifiable Agent Kernel
pub struct Kernel {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    audit_logger: Arc<RwLock<AuditLogger>>,
    state: Arc<RwLock<KernelState>>,
}

impl Kernel {
    /// Create a new Kernel instance with initialized components
    #[instrument(name = "kernel_init")]
    pub async fn new() -> Self {
        info!("Initializing Verifiable Agent Kernel");

        let policy_engine = Arc::new(RwLock::new(PolicyEngine::new()));
        let audit_logger = Arc::new(RwLock::new(AuditLogger::new()));
        let state = Arc::new(RwLock::new(KernelState {
            agents: HashMap::new(),
            running: true,
        }));

        info!("Kernel initialized successfully");

        Self {
            policy_engine,
            audit_logger,
            state,
        }
    }

    /// Register an agent with the kernel
    #[instrument(skip(self), fields(agent_id = %agent_id, agent_name = %name))]
    pub async fn register_agent(
        &self,
        agent_id: AgentId,
        name: String,
        capabilities: Vec<String>,
    ) -> Result<(), KernelError> {
        info!("Registering agent");

        let mut state = self.state.write().await;
        
        if state.agents.contains_key(&agent_id) {
            warn!("Agent already registered");
            return Err(KernelError::AgentAlreadyRegistered(agent_id));
        }

        let agent_info = AgentInfo {
            id: agent_id.clone(),
            name: name.clone(),
            capabilities,
        };

        state.agents.insert(agent_id.clone(), agent_info);

        // Log the registration
        let mut logger = self.audit_logger.write().await;
        logger.log(AuditEntry {
            timestamp: chrono::Utc::now(),
            agent_id,
            action: "register".to_string(),
            details: format!("Agent '{}' registered", name),
            success: true,
        });

        info!("Agent registered successfully");
        Ok(())
    }

    /// Execute a tool call after policy validation
    #[instrument(skip(self, tool_call), fields(agent_id = %agent_id, tool = %tool_call.tool_name))]
    pub async fn execute_tool(
        &self,
        agent_id: AgentId,
        tool_call: ToolCall,
    ) -> Result<ToolResult, KernelError> {
        info!("Processing tool execution request");

        // Check if kernel is running
        let state = self.state.read().await;
        if !state.running {
            error!("Kernel is shutting down");
            return Err(KernelError::KernelShuttingDown);
        }

        // Verify agent is registered
        if !state.agents.contains_key(&agent_id) {
            warn!("Unregistered agent attempted tool execution");
            return Err(KernelError::AgentNotRegistered(agent_id));
        }
        drop(state);

        // Policy check
        let policy_engine = self.policy_engine.read().await;
        if !policy_engine.check(&agent_id, &tool_call) {
            warn!("Policy check failed for tool execution");
            
            let mut logger = self.audit_logger.write().await;
            logger.log(AuditEntry {
                timestamp: chrono::Utc::now(),
                agent_id: agent_id.clone(),
                action: format!("execute:{}", tool_call.tool_name),
                details: "Policy check failed".to_string(),
                success: false,
            });

            return Err(KernelError::PolicyViolation(tool_call.tool_name));
        }
        drop(policy_engine);

        // Execute the tool (placeholder - actual implementation would dispatch to tool handlers)
        info!("Executing tool");
        let result = ToolResult {
            tool_name: tool_call.tool_name.clone(),
            output: serde_json::json!({"status": "executed"}),
            success: true,
        };

        // Log successful execution
        let mut logger = self.audit_logger.write().await;
        logger.log(AuditEntry {
            timestamp: chrono::Utc::now(),
            agent_id,
            action: format!("execute:{}", tool_call.tool_name),
            details: "Tool executed successfully".to_string(),
            success: true,
        });

        info!("Tool execution completed");
        Ok(result)
    }

    /// Shutdown the kernel gracefully
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<(), KernelError> {
        info!("Initiating kernel shutdown");

        let mut state = self.state.write().await;
        state.running = false;

        // Log shutdown
        let mut logger = self.audit_logger.write().await;
        logger.log(AuditEntry {
            timestamp: chrono::Utc::now(),
            agent_id: "kernel".to_string(),
            action: "shutdown".to_string(),
            details: format!("Kernel shutdown with {} agents", state.agents.len()),
            success: true,
        });

        info!("Kernel shutdown complete");
        Ok(())
    }

    /// Get the policy engine for configuration
    pub fn policy_engine(&self) -> Arc<RwLock<PolicyEngine>> {
        Arc::clone(&self.policy_engine)
    }

    /// Get the audit logger for inspection
    pub fn audit_logger(&self) -> Arc<RwLock<AuditLogger>> {
        Arc::clone(&self.audit_logger)
    }
}

/// Kernel operation errors
#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("Agent '{0}' is already registered")]
    AgentAlreadyRegistered(AgentId),

    #[error("Agent '{0}' is not registered")]
    AgentNotRegistered(AgentId),

    #[error("Policy violation for tool '{0}'")]
    PolicyViolation(String),

    #[error("Kernel is shutting down")]
    KernelShuttingDown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_kernel_lifecycle() {
        let kernel = Kernel::new().await;
        
        // Register an agent
        kernel
            .register_agent("agent-1".to_string(), "TestAgent".to_string(), vec!["read".to_string()])
            .await
            .unwrap();

        // Execute a tool
        let tool_call = ToolCall {
            tool_name: "test_tool".to_string(),
            parameters: serde_json::json!({}),
        };
        
        let result = kernel.execute_tool("agent-1".to_string(), tool_call).await;
        assert!(result.is_ok());

        // Shutdown
        kernel.shutdown().await.unwrap();
    }
}
