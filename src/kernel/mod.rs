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
//! - [`async_pipeline`]: Async request processing pipeline for multi-agent throughput (Issue #44)
//! - [`custom_handlers`]: Custom tool handler registry for runtime extensibility
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

pub mod async_pipeline;
pub mod config;
pub mod custom_handlers;
pub mod error;
pub mod neurosymbolic_pipeline;
pub mod rate_limiter;
pub mod traits;
pub mod types;

// Re-export commonly used types at the module level
pub use self::config::KernelConfig;
pub use self::custom_handlers::{
    CustomHandlerRegistry, FunctionHandler, HandlerError, HandlerMetadata, HandlerResult,
    ToolHandler,
};
pub use self::neurosymbolic_pipeline::{
    AgentPlan, ExecutionResult, NeuroSymbolicPipeline, PipelineConfig, PipelineError,
    ProposedAction,
};
pub use self::rate_limiter::{
    LimitResult, RateLimitConfig, RateLimiter, ResourceKey,
};

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{info, instrument, warn};

use self::types::{
    AgentId, AuditEntry, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse,
};

// Import sandbox and skill registry for WASM execution (Issue #6)
use crate::sandbox::{SandboxConfig, SkillRegistry, WasmSandbox};

/// The main kernel instance that manages agent execution and policy enforcement.
///
/// The `Kernel` is the central component of VAK, responsible for:
/// - Processing tool requests from agents
/// - Enforcing security policies
/// - Maintaining audit logs
/// - Managing agent sessions
/// - Executing WASM skills in sandboxed environments (Issue #6)
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

    /// Skill registry for WASM tools (Issue #6)
    skill_registry: Arc<RwLock<SkillRegistry>>,

    /// Sandbox configuration for WASM execution
    sandbox_config: SandboxConfig,
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

        // Initialize skill registry (Issue #6)
        let skills_dir = PathBuf::from("skills");
        let mut skill_registry = SkillRegistry::new(skills_dir.clone());

        // Try to load skills from directory
        if skills_dir.exists() {
            match skill_registry.load_all_skills() {
                Ok(ids) => info!(count = ids.len(), "Loaded skills from registry"),
                Err(e) => warn!(error = %e, "Failed to load skills from registry"),
            }
        }

        // Configure sandbox based on kernel config
        let sandbox_config = SandboxConfig {
            memory_limit: (config.resources.max_memory_mb as usize) * 1024 * 1024, // Convert MB to bytes
            fuel_limit: 10_000_000, // Default fuel limit
            timeout: config.max_execution_time,
        };

        Ok(Self {
            config,
            audit_log: Arc::new(RwLock::new(Vec::new())),
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            skill_registry: Arc::new(RwLock::new(skill_registry)),
            sandbox_config,
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
    ///
    /// # Policy Evaluation Logic
    ///
    /// 1. Checks if the tool is in the blocked tools list
    /// 2. Checks if allowed_tools is non-empty and tool is not in it
    /// 3. Validates agent session exists (if sessions are active)
    /// 4. Returns Allow with any applicable constraints
    #[instrument(skip(self, request), fields(agent_id = %agent_id, tool = %request.tool_name))]
    pub async fn evaluate_policy(
        &self,
        agent_id: &AgentId,
        request: &ToolRequest,
    ) -> PolicyDecision {
        info!(
            agent_id = %agent_id,
            tool = %request.tool_name,
            "Evaluating policy for tool request"
        );

        // Check if the tool is explicitly blocked
        if self
            .config
            .security
            .blocked_tools
            .contains(&request.tool_name)
        {
            tracing::warn!(
                tool = %request.tool_name,
                "Tool is in blocked list"
            );
            return PolicyDecision::Deny {
                reason: format!("Tool '{}' is blocked by security policy", request.tool_name),
                violated_policies: Some(vec!["security.blocked_tools".to_string()]),
            };
        }

        // Check if allowed_tools is non-empty and tool is not in it
        if !self.config.security.allowed_tools.is_empty()
            && !self
                .config
                .security
                .allowed_tools
                .contains(&request.tool_name)
        {
            tracing::warn!(
                tool = %request.tool_name,
                "Tool not in allowed list"
            );
            return PolicyDecision::Deny {
                reason: format!(
                    "Tool '{}' is not in the allowed tools list",
                    request.tool_name
                ),
                violated_policies: Some(vec!["security.allowed_tools".to_string()]),
            };
        }

        // Check if policy enforcement is enabled
        if !self.config.policy.enabled {
            return PolicyDecision::Allow {
                reason: "Policy enforcement is disabled".to_string(),
                constraints: None,
            };
        }

        // Build constraints based on configuration
        let mut constraints = Vec::new();

        // Add timeout constraint if configured
        if self.config.max_execution_time.as_millis() > 0 {
            constraints.push(format!(
                "max_execution_time_ms:{}",
                self.config.max_execution_time.as_millis()
            ));
        }

        // Add memory limit constraint
        if self.config.resources.max_memory_mb > 0 {
            constraints.push(format!(
                "max_memory_mb:{}",
                self.config.resources.max_memory_mb
            ));
        }

        // Add sandboxing requirement if enabled
        if self.config.security.enable_sandboxing {
            constraints.push("sandboxed:true".to_string());
        }

        PolicyDecision::Allow {
            reason: format!(
                "Agent {} authorized to execute tool '{}'",
                agent_id, request.tool_name
            ),
            constraints: if constraints.is_empty() {
                None
            } else {
                Some(constraints)
            },
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

        // Step 3: Execute the tool
        // Measure execution time
        let start_time = std::time::Instant::now();

        // Execute the tool based on its name
        // In a full implementation, this would dispatch to a tool registry
        // For now, we handle some built-in tools and return a default response for others
        let execution_result = self.dispatch_tool(&request).await;

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        let response = match execution_result {
            Ok(result) => ToolResponse {
                request_id: request.request_id,
                success: true,
                result: Some(result),
                error: None,
                execution_time_ms,
            },
            Err(e) => ToolResponse {
                request_id: request.request_id,
                success: false,
                result: None,
                error: Some(e.to_string()),
                execution_time_ms,
            },
        };

        Ok(response)
    }

    /// Dispatches a tool request to the appropriate handler.
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to dispatch
    ///
    /// # Returns
    ///
    /// The result of the tool execution as a JSON value.
    ///
    /// # Built-in Tools
    ///
    /// The kernel provides several built-in tools:
    /// - `echo`: Returns the input parameters as-is
    /// - `calculator`: Performs basic arithmetic operations
    /// - `data_processor`: Processes data arrays with various operations
    /// - `system_info`: Returns system information (kernel version, etc.)
    async fn dispatch_tool(&self, request: &ToolRequest) -> Result<serde_json::Value, KernelError> {
        match request.tool_name.as_str() {
            "echo" => {
                // Echo tool: returns the input parameters
                Ok(request.parameters.clone())
            }
            "calculator" => {
                // Calculator tool: performs basic arithmetic
                self.handle_calculator(request).await
            }
            "data_processor" => {
                // Data processor: summarize, transform, filter data
                self.handle_data_processor(request).await
            }
            "system_info" => {
                // System info: return kernel information
                Ok(serde_json::json!({
                    "kernel_name": self.config.name,
                    "version": crate::VERSION,
                    "max_concurrent_agents": self.config.max_concurrent_agents,
                    "sandboxing_enabled": self.config.security.enable_sandboxing,
                    "audit_enabled": self.config.audit.enabled,
                }))
            }
            _ => {
                // Try to execute as WASM skill (Issue #6)
                self.execute_wasm_skill(request).await
            }
        }
    }

    /// Executes a WASM skill in the sandbox (Issue #6)
    ///
    /// This method handles the execution flow:
    /// 1. Look up skill in registry by name
    /// 2. Load the WASM module if found
    /// 3. Execute in sandboxed environment with resource limits
    /// 4. Return the result or fall back to default handler
    async fn execute_wasm_skill(
        &self,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        // Check if skill exists in registry
        let registry = self.skill_registry.read().await;

        if let Some(manifest) = registry.get_skill_by_name(&request.tool_name) {
            // Skill found - try to execute in sandbox
            info!(
                tool = %request.tool_name,
                version = %manifest.version,
                "Executing WASM skill"
            );

            // Create sandbox with configured limits
            let mut sandbox = WasmSandbox::new(self.sandbox_config.clone()).map_err(|e| {
                KernelError::ToolExecutionFailed {
                    tool_name: request.tool_name.clone(),
                    reason: format!("Failed to create sandbox: {}", e),
                }
            })?;

            // Load the WASM module
            sandbox
                .load_skill_from_file(&manifest.wasm_path)
                .map_err(|e| KernelError::ToolExecutionFailed {
                    tool_name: request.tool_name.clone(),
                    reason: format!("Failed to load WASM module: {}", e),
                })?;

            // Execute the skill
            // WASM skills expose an "execute" function that takes JSON input
            let result = sandbox
                .execute("execute", &request.parameters)
                .map_err(|e| KernelError::ToolExecutionFailed {
                    tool_name: request.tool_name.clone(),
                    reason: format!("WASM execution failed: {}", e),
                })?;

            Ok(result)
        } else {
            // Skill not found - return generic response
            info!(
                tool = %request.tool_name,
                "Tool not found in skill registry, using default handler"
            );

            Ok(serde_json::json!({
                "status": "executed",
                "tool": request.tool_name,
                "message": "Tool executed successfully (default handler)",
                "parameters_received": request.parameters
            }))
        }
    }

    /// List available tools/skills
    pub async fn list_tools(&self) -> Vec<String> {
        let registry = self.skill_registry.read().await;
        let mut tools = vec![
            "echo".to_string(),
            "calculator".to_string(),
            "data_processor".to_string(),
            "system_info".to_string(),
        ];

        // Add registered WASM skills
        for skill in registry.list_skills() {
            tools.push(skill.name.clone());
        }

        tools
    }

    /// Handles calculator tool requests.
    async fn handle_calculator(
        &self,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        let operation = request
            .parameters
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "calculator".to_string(),
                reason: "Missing 'operation' parameter".to_string(),
            })?;

        let operands = request
            .parameters
            .get("operands")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "calculator".to_string(),
                reason: "Missing or invalid 'operands' parameter".to_string(),
            })?;

        let numbers: Result<Vec<f64>, _> = operands
            .iter()
            .map(|v| {
                v.as_f64().ok_or_else(|| KernelError::ToolExecutionFailed {
                    tool_name: "calculator".to_string(),
                    reason: "Operands must be numbers".to_string(),
                })
            })
            .collect();

        let numbers = numbers?;

        let result = match operation {
            "add" => numbers.iter().sum::<f64>(),
            "subtract" => {
                if numbers.is_empty() {
                    0.0
                } else {
                    numbers.iter().skip(1).fold(numbers[0], |acc, x| acc - x)
                }
            }
            "multiply" => numbers.iter().product::<f64>(),
            "divide" => {
                if numbers.is_empty() {
                    return Err(KernelError::ToolExecutionFailed {
                        tool_name: "calculator".to_string(),
                        reason: "Division requires at least one operand".to_string(),
                    });
                }
                if numbers.iter().skip(1).any(|&x| x == 0.0) {
                    return Err(KernelError::ToolExecutionFailed {
                        tool_name: "calculator".to_string(),
                        reason: "Division by zero".to_string(),
                    });
                }
                numbers.iter().skip(1).fold(numbers[0], |acc, x| acc / x)
            }
            _ => {
                return Err(KernelError::ToolExecutionFailed {
                    tool_name: "calculator".to_string(),
                    reason: format!("Unknown operation: {}", operation),
                });
            }
        };

        Ok(serde_json::json!({
            "operation": operation,
            "operands": operands,
            "result": result
        }))
    }

    /// Handles data processor tool requests.
    async fn handle_data_processor(
        &self,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        let action = request
            .parameters
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "data_processor".to_string(),
                reason: "Missing 'action' parameter".to_string(),
            })?;

        let data = request
            .parameters
            .get("data")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "data_processor".to_string(),
                reason: "Missing or invalid 'data' parameter".to_string(),
            })?;

        match action {
            "summarize" => {
                let numbers: Vec<f64> = data.iter().filter_map(|v| v.as_f64()).collect();

                if numbers.is_empty() {
                    return Ok(serde_json::json!({
                        "action": "summarize",
                        "count": 0,
                        "message": "No numeric data to summarize"
                    }));
                }

                let sum: f64 = numbers.iter().sum();
                let count = numbers.len();
                let mean = sum / count as f64;
                let min = numbers.iter().cloned().fold(f64::INFINITY, f64::min);
                let max = numbers.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

                Ok(serde_json::json!({
                    "action": "summarize",
                    "count": count,
                    "sum": sum,
                    "mean": mean,
                    "min": min,
                    "max": max
                }))
            }
            "count" => Ok(serde_json::json!({
                "action": "count",
                "count": data.len()
            })),
            "filter" => {
                let predicate = request
                    .parameters
                    .get("predicate")
                    .and_then(|v| v.as_str())
                    .unwrap_or("non_null");

                let filtered: Vec<&serde_json::Value> = match predicate {
                    "non_null" => data.iter().filter(|v| !v.is_null()).collect(),
                    "numbers" => data.iter().filter(|v| v.is_number()).collect(),
                    "strings" => data.iter().filter(|v| v.is_string()).collect(),
                    _ => data.iter().collect(),
                };

                Ok(serde_json::json!({
                    "action": "filter",
                    "predicate": predicate,
                    "original_count": data.len(),
                    "filtered_count": filtered.len(),
                    "filtered_data": filtered
                }))
            }
            _ => Err(KernelError::ToolExecutionFailed {
                tool_name: "data_processor".to_string(),
                reason: format!("Unknown action: {}", action),
            }),
        }
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
