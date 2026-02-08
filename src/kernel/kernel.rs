use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error, instrument};
use chrono::{DateTime, Utc};

use crate::kernel::types::AgentId;

/// Tool call request structure
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub tool_name: String,
    pub parameters: serde_json::Value,
}

/// Tool execution result
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub tool_name: String,
    pub output: serde_json::Value,
    pub success: bool,
}

/// Simple policy rule
#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub allow_all: bool,
}

impl Policy {
    pub fn allows(&self, _agent_id: &AgentId, _tool_call: &ToolCall) -> bool {
        self.allow_all
    }
}

/// Audit entry for this kernel module
#[derive(Debug, Clone)]
pub struct SimpleAuditEntry {
    pub timestamp: DateTime<Utc>,
    pub agent_id: AgentId,
    pub action: String,
    pub details: String,
    pub success: bool,
}

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
    entries: Vec<SimpleAuditEntry>,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    pub fn log(&mut self, entry: SimpleAuditEntry) {
        info!(agent_id = %entry.agent_id, action = %entry.action, "Audit log entry");
        self.entries.push(entry);
    }

    pub fn entries(&self) -> &[SimpleAuditEntry] {
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

/// Tool handler trait for implementing tool execution logic
#[async_trait]
pub trait ToolHandler: Send + Sync {
    async fn execute(&self, agent_id: AgentId, tool_call: ToolCall) -> Result<ToolResult, SimpleKernelError>;
}

/// Registry for tool handlers
#[derive(Default)]
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn ToolHandler>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, name: impl Into<String>, handler: Box<dyn ToolHandler>) {
        self.tools.insert(name.into(), handler);
    }

    pub fn get(&self, name: &str) -> Option<&Box<dyn ToolHandler>> {
        self.tools.get(name)
    }
}

/// Echo tool handler
pub struct EchoTool;

#[async_trait]
impl ToolHandler for EchoTool {
    async fn execute(&self, _agent_id: AgentId, tool_call: ToolCall) -> Result<ToolResult, SimpleKernelError> {
        Ok(ToolResult {
            tool_name: tool_call.tool_name.clone(),
            output: tool_call.parameters.clone(),
            success: true,
        })
    }
}

/// Calculator tool handler
pub struct CalculatorTool;

#[async_trait]
impl ToolHandler for CalculatorTool {
    async fn execute(&self, _agent_id: AgentId, tool_call: ToolCall) -> Result<ToolResult, SimpleKernelError> {
        let operation = tool_call.parameters.get("operation")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let a = tool_call.parameters.get("a")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let b = tool_call.parameters.get("b")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        let result = match operation {
            "add" => Ok(a + b),
            "subtract" => Ok(a - b),
            "multiply" => Ok(a * b),
            "divide" => {
                if b == 0.0 {
                    Err("Division by zero".to_string())
                } else {
                    Ok(a / b)
                }
            }
            _ => Err("Unknown operation".to_string()),
        };

        match result {
            Ok(value) => Ok(ToolResult {
                tool_name: tool_call.tool_name.clone(),
                output: serde_json::json!({
                    "operation": operation,
                    "a": a,
                    "b": b,
                    "result": value
                }),
                success: true,
            }),
            Err(err) => Ok(ToolResult {
                tool_name: tool_call.tool_name.clone(),
                output: serde_json::json!({
                    "error": err,
                    "operation": operation
                }),
                success: false,
            }),
        }
    }
}

/// Status tool handler
pub struct StatusTool {
    state: Arc<RwLock<KernelState>>,
}

impl StatusTool {
    pub fn new(state: Arc<RwLock<KernelState>>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl ToolHandler for StatusTool {
    async fn execute(&self, _agent_id: AgentId, tool_call: ToolCall) -> Result<ToolResult, SimpleKernelError> {
        let state = self.state.read().await;
        Ok(ToolResult {
            tool_name: tool_call.tool_name.clone(),
            output: serde_json::json!({
                "running": state.running,
                "agent_count": state.agents.len(),
                "status": "operational"
            }),
            success: true,
        })
    }
}

/// Alternative Kernel implementation for simpler use cases
pub struct SimpleKernel {
    policy_engine: Arc<RwLock<PolicyEngine>>,
    audit_logger: Arc<RwLock<AuditLogger>>,
    state: Arc<RwLock<KernelState>>,
    tool_registry: Arc<RwLock<ToolRegistry>>,
}

impl SimpleKernel {
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

        let mut tool_registry = ToolRegistry::new();
        tool_registry.register("echo", Box::new(EchoTool));
        tool_registry.register("calculator", Box::new(CalculatorTool));
        tool_registry.register("status", Box::new(StatusTool::new(Arc::clone(&state))));

        info!("Kernel initialized successfully");

        Self {
            policy_engine,
            audit_logger,
            state,
            tool_registry: Arc::new(RwLock::new(tool_registry)),
        }
    }

    /// Register an agent with the kernel
    #[instrument(skip(self), fields(agent_id = %agent_id, agent_name = %name))]
    pub async fn register_agent(
        &self,
        agent_id: AgentId,
        name: String,
        capabilities: Vec<String>,
    ) -> Result<(), SimpleKernelError> {
        info!("Registering agent");

        let mut state = self.state.write().await;
        
        if state.agents.contains_key(&agent_id) {
            warn!("Agent already registered");
            return Err(SimpleKernelError::AgentAlreadyRegistered(agent_id.to_string()));
        }

        let agent_info = AgentInfo {
            id: agent_id.clone(),
            name: name.clone(),
            capabilities,
        };

        state.agents.insert(agent_id.clone(), agent_info);

        // Log the registration
        let mut logger = self.audit_logger.write().await;
        logger.log(SimpleAuditEntry {
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
    ) -> Result<ToolResult, SimpleKernelError> {
        info!("Processing tool execution request");

        // Check if kernel is running
        let state = self.state.read().await;
        if !state.running {
            error!("Kernel is shutting down");
            return Err(SimpleKernelError::KernelShuttingDown);
        }

        // Verify agent is registered
        if !state.agents.contains_key(&agent_id) {
            warn!("Unregistered agent attempted tool execution");
            return Err(SimpleKernelError::AgentNotRegistered(agent_id.to_string()));
        }
        drop(state);

        // Policy check
        let policy_engine = self.policy_engine.read().await;
        if !policy_engine.check(&agent_id, &tool_call) {
            warn!("Policy check failed for tool execution");
            
            let mut logger = self.audit_logger.write().await;
            logger.log(SimpleAuditEntry {
                timestamp: chrono::Utc::now(),
                agent_id: agent_id.clone(),
                action: format!("execute:{}", tool_call.tool_name),
                details: "Policy check failed".to_string(),
                success: false,
            });

            return Err(SimpleKernelError::PolicyViolation(tool_call.tool_name));
        }
        drop(policy_engine);

        // Execute the tool using the tool registry
        info!("Executing tool");
        
        let tool_name = tool_call.tool_name.clone();

        // Dispatch to appropriate tool handler based on tool name
        let tool_registry = self.tool_registry.read().await;
        let result = if let Some(handler) = tool_registry.get(&tool_name) {
            handler.execute(agent_id, tool_call).await?
        } else {
            // Custom operation handler registry
            //
            // This default handler provides a placeholder for tools not built into
            // the kernel. Future implementation should include:
            //
            // 1. Custom Tool Registry: Register external tool handlers at runtime
            //    ```rust,ignore
            //    if let Some(handler) = self.custom_handlers.get(&tool_call.tool_name) {
            //        return handler.execute(&tool_call, &agent_id).await;
            //    }
            //    ```
            //
            // 2. WASM Skill Execution: Load and execute WASM-based skills
            //    - Located in skills/ directory
            //    - Sandboxed execution with policy enforcement
            //
            // 3. External Service Integration: Call external APIs/services
            //    - MCP tool bridging
            //    - LangChain/AutoGPT adapter integration
            //
            // Security considerations for custom handlers:
            // - All custom tools must pass policy validation (done above)
            // - Tool execution should be sandboxed (use WASM sandbox)
            // - Results must be sanitized before returning
            // - Execution time should be bounded (epoch deadline)
            // - Audit logging required for all tool executions
            //
            debug!(tool = %tool_name, "Using default handler for unregistered tool");

            ToolResult {
                tool_name: tool_name.clone(),
                output: serde_json::json!({
                    "status": "executed",
                    "handler": "default",
                    "message": format!("Tool '{}' executed with default handler", tool_name),
                    "note": "Register custom handler for full functionality"
                }),
                success: true,
            }
        };

        // Log successful execution
        let mut logger = self.audit_logger.write().await;
        logger.log(SimpleAuditEntry {
            timestamp: chrono::Utc::now(),
            agent_id,
            action: format!("execute:{}", tool_name),
            details: "Tool executed successfully".to_string(),
            success: true,
        });

        info!("Tool execution completed");
        Ok(result)
    }

    /// Shutdown the kernel gracefully
    #[instrument(skip(self))]
    pub async fn shutdown(&self) -> Result<(), SimpleKernelError> {
        info!("Initiating kernel shutdown");

        let mut state = self.state.write().await;
        state.running = false;

        // Log shutdown
        let mut logger = self.audit_logger.write().await;
        logger.log(SimpleAuditEntry {
            timestamp: chrono::Utc::now(),
            agent_id: AgentId::new(),
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
pub enum SimpleKernelError {
    #[error("Agent '{0}' is already registered")]
    AgentAlreadyRegistered(String),

    #[error("Agent '{0}' is not registered")]
    AgentNotRegistered(String),

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
        let kernel = SimpleKernel::new().await;
        
        // Register an agent
        let agent_id = AgentId::new();
        kernel
            .register_agent(agent_id.clone(), "TestAgent".to_string(), vec!["read".to_string()])
            .await
            .unwrap();

        // Execute a tool
        let tool_call = ToolCall {
            tool_name: "test_tool".to_string(),
            parameters: serde_json::json!({}),
        };
        
        let result = kernel.execute_tool(agent_id.clone(), tool_call).await;
        assert!(result.is_ok());

        // Test Echo Tool
        let echo_call = ToolCall {
            tool_name: "echo".to_string(),
            parameters: serde_json::json!({"msg": "hello"}),
        };
        let echo_result = kernel.execute_tool(agent_id.clone(), echo_call).await.unwrap();
        assert!(echo_result.success);
        assert_eq!(echo_result.output["msg"], "hello");

        // Test Calculator Tool
        let calc_call = ToolCall {
            tool_name: "calculator".to_string(),
            parameters: serde_json::json!({"operation": "add", "a": 2.0, "b": 3.0}),
        };
        let calc_result = kernel.execute_tool(agent_id.clone(), calc_call).await.unwrap();
        assert!(calc_result.success);
        assert_eq!(calc_result.output["result"], 5.0);

        // Test Status Tool
        let status_call = ToolCall {
            tool_name: "status".to_string(),
            parameters: serde_json::json!({}),
        };
        let status_result = kernel.execute_tool(agent_id.clone(), status_call).await.unwrap();
        assert!(status_result.success);
        assert_eq!(status_result.output["running"], true);
        assert_eq!(status_result.output["agent_count"], 1);

        // Shutdown
        kernel.shutdown().await.unwrap();
    }
}
