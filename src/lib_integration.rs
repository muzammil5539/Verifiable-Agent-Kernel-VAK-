//! # VAK LLM Integration Library
//!
//! High-level API for integrating the Verifiable Agent Kernel with LLM applications.
//!
//! This module provides a clean, ergonomic interface for using VAK as a library
//! in LLM-powered applications. It wraps the kernel's internal complexity behind
//! builder patterns and convenient abstractions.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use vak::lib_integration::{VakRuntime, VakAgent, ToolDefinition};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create and configure the runtime
//!     let runtime = VakRuntime::builder()
//!         .with_name("my-llm-app")
//!         .with_audit_logging(true)
//!         .with_policy_enforcement(true)
//!         .build()
//!         .await?;
//!
//!     // Create an agent
//!     let agent = runtime.create_agent("code-reviewer")
//!         .with_allowed_tools(vec!["calculator", "json_validator"])
//!         .build()
//!         .await?;
//!
//!     // Execute a tool call (as an LLM would)
//!     let result = agent.call_tool("calculator", serde_json::json!({
//!         "operation": "add",
//!         "operands": [1, 2, 3]
//!     })).await?;
//!
//!     // Get the audit trail for this agent
//!     let trail = agent.audit_trail().await;
//!
//!     // Export a verifiable receipt
//!     let receipt = agent.export_receipt().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## LLM Tool Integration
//!
//! VAK provides tool definitions compatible with OpenAI function calling,
//! Anthropic tool use, and other LLM tool-use protocols:
//!
//! ```rust,ignore
//! use vak::lib_integration::VakRuntime;
//!
//! let runtime = VakRuntime::builder().build().await?;
//! let tools = runtime.tool_definitions_openai();
//! // Pass `tools` to your LLM API call
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, instrument};

use crate::kernel::config::KernelConfig;
use crate::kernel::types::{AgentId, KernelError, SessionId, ToolRequest};
use crate::kernel::Kernel;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from the LLM integration layer
#[derive(Debug, thiserror::Error)]
pub enum IntegrationError {
    /// Kernel initialization failed
    #[error("Kernel error: {0}")]
    KernelError(#[from] KernelError),

    /// Tool not found
    #[error("Tool '{0}' not found in registry")]
    ToolNotFound(String),

    /// Tool execution failed
    #[error("Tool execution failed: {0}")]
    ToolExecutionFailed(String),

    /// Agent not found
    #[error("Agent '{0}' not found")]
    AgentNotFound(String),

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Audit error
    #[error("Audit error: {0}")]
    AuditError(String),
}

/// Result type for integration operations
pub type IntegrationResult<T> = Result<T, IntegrationError>;

// ============================================================================
// Tool Definitions (LLM-compatible)
// ============================================================================

/// A tool definition compatible with LLM function calling protocols.
///
/// This struct can be serialized to match OpenAI's function calling format,
/// Anthropic's tool use format, or any JSON-schema based tool protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Unique name of the tool
    pub name: String,
    /// Human-readable description for the LLM
    pub description: String,
    /// JSON Schema for the tool's parameters
    pub parameters: serde_json::Value,
    /// Whether the tool requires confirmation before execution
    #[serde(default)]
    pub requires_confirmation: bool,
    /// Risk level of the tool (informational for the LLM)
    #[serde(default)]
    pub risk_level: RiskLevel,
    /// Categories/tags for the tool
    #[serde(default)]
    pub categories: Vec<String>,
}

/// Risk level classification for tools
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Tool is read-only and safe
    #[default]
    Low,
    /// Tool may modify state
    Medium,
    /// Tool performs sensitive operations
    High,
    /// Tool performs irreversible or security-critical operations
    Critical,
}

/// OpenAI-compatible function definition wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIFunction {
    /// The type, always "function"
    #[serde(rename = "type")]
    pub function_type: String,
    /// The function definition
    pub function: OpenAIFunctionDef,
}

/// OpenAI function definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenAIFunctionDef {
    /// Function name
    pub name: String,
    /// Function description
    pub description: String,
    /// Parameter schema
    pub parameters: serde_json::Value,
}

/// Anthropic-compatible tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicTool {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Input schema
    pub input_schema: serde_json::Value,
}

impl ToolDefinition {
    /// Create a new tool definition
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        parameters: serde_json::Value,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            parameters,
            requires_confirmation: false,
            risk_level: RiskLevel::Low,
            categories: Vec::new(),
        }
    }

    /// Set the risk level
    pub fn with_risk_level(mut self, level: RiskLevel) -> Self {
        self.risk_level = level;
        self
    }

    /// Set confirmation requirement
    pub fn with_confirmation(mut self, required: bool) -> Self {
        self.requires_confirmation = required;
        self
    }

    /// Add categories
    pub fn with_categories(mut self, categories: Vec<String>) -> Self {
        self.categories = categories;
        self
    }

    /// Convert to OpenAI function calling format
    pub fn to_openai(&self) -> OpenAIFunction {
        OpenAIFunction {
            function_type: "function".to_string(),
            function: OpenAIFunctionDef {
                name: self.name.clone(),
                description: self.description.clone(),
                parameters: self.parameters.clone(),
            },
        }
    }

    /// Convert to Anthropic tool use format
    pub fn to_anthropic(&self) -> AnthropicTool {
        AnthropicTool {
            name: self.name.clone(),
            description: self.description.clone(),
            input_schema: self.parameters.clone(),
        }
    }
}

// ============================================================================
// Built-in Tool Definitions
// ============================================================================

/// Get the built-in tool definitions provided by VAK
pub fn builtin_tool_definitions() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition::new(
            "calculator",
            "Perform arithmetic operations (add, subtract, multiply, divide) on numbers.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "operation": {
                        "type": "string",
                        "enum": ["add", "subtract", "multiply", "divide"],
                        "description": "The arithmetic operation to perform"
                    },
                    "operands": {
                        "type": "array",
                        "items": { "type": "number" },
                        "minItems": 1,
                        "description": "Numbers to operate on"
                    }
                },
                "required": ["operation", "operands"]
            }),
        ),
        ToolDefinition::new(
            "data_processor",
            "Process and analyze data arrays with operations like summarize, count, and filter.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["summarize", "count", "filter"],
                        "description": "The processing action to perform"
                    },
                    "data": {
                        "type": "array",
                        "items": {},
                        "description": "The data array to process"
                    },
                    "predicate": {
                        "type": "string",
                        "enum": ["non_null", "numbers", "strings"],
                        "description": "Filter predicate (only for 'filter' action)"
                    }
                },
                "required": ["action", "data"]
            }),
        ),
        ToolDefinition::new(
            "system_info",
            "Get information about the VAK kernel instance (version, configuration, capabilities).",
            serde_json::json!({
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }),
        ),
        ToolDefinition::new(
            "echo",
            "Echo back the input parameters. Useful for testing tool integration.",
            serde_json::json!({
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Message to echo back"
                    }
                }
            }),
        ),
    ]
}

// ============================================================================
// Tool Call / Result Types
// ============================================================================

/// A tool call from an LLM, ready to be executed by VAK
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool call ID (from the LLM)
    pub id: String,
    /// Name of the tool to call
    pub name: String,
    /// Arguments as a JSON value
    pub arguments: serde_json::Value,
}

/// Result of a tool execution, ready to be sent back to the LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    /// Tool call ID this result corresponds to
    pub tool_call_id: String,
    /// Whether the execution succeeded
    pub success: bool,
    /// The result content (for the LLM to read)
    pub content: String,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
    /// Audit hash for this execution
    pub audit_hash: Option<String>,
}

// ============================================================================
// VakAgent
// ============================================================================

/// A managed agent within the VAK runtime.
///
/// Represents an LLM agent with policy enforcement, audit logging,
/// and tool execution capabilities.
pub struct VakAgent {
    /// Agent identifier
    agent_id: AgentId,
    /// Session identifier
    session_id: SessionId,
    /// Agent name
    name: String,
    /// Reference to the kernel
    kernel: Arc<Kernel>,
    /// Allowed tools for this agent
    allowed_tools: Option<Vec<String>>,
    /// Blocked tools for this agent
    blocked_tools: Vec<String>,
    /// Execution history
    history: Arc<RwLock<Vec<ToolResult>>>,
    /// Custom metadata
    metadata: HashMap<String, String>,
}

impl VakAgent {
    /// Get the agent's unique ID
    pub fn id(&self) -> &AgentId {
        &self.agent_id
    }

    /// Get the agent's name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the session ID
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Execute a single tool call.
    ///
    /// This is the primary method for LLM tool integration.
    /// It handles policy checking, execution, and audit logging.
    #[instrument(skip(self, arguments), fields(agent = %self.name, tool = %tool_name))]
    pub async fn call_tool(
        &self,
        tool_name: &str,
        arguments: serde_json::Value,
    ) -> IntegrationResult<ToolResult> {
        let tool_call = ToolCall {
            id: uuid::Uuid::new_v4().to_string(),
            name: tool_name.to_string(),
            arguments,
        };
        self.execute_tool_call(&tool_call).await
    }

    /// Execute a tool call from an LLM response.
    ///
    /// Handles the full lifecycle: policy check -> execute -> audit -> return result.
    pub async fn execute_tool_call(&self, tool_call: &ToolCall) -> IntegrationResult<ToolResult> {
        // Check agent-level tool restrictions
        if let Some(ref allowed) = self.allowed_tools {
            if !allowed.contains(&tool_call.name) {
                return Ok(ToolResult {
                    tool_call_id: tool_call.id.clone(),
                    success: false,
                    content: format!(
                        "Tool '{}' is not in the allowed tools list for agent '{}'",
                        tool_call.name, self.name
                    ),
                    execution_time_ms: 0,
                    audit_hash: None,
                });
            }
        }

        if self.blocked_tools.contains(&tool_call.name) {
            return Ok(ToolResult {
                tool_call_id: tool_call.id.clone(),
                success: false,
                content: format!(
                    "Tool '{}' is blocked for agent '{}'",
                    tool_call.name, self.name
                ),
                execution_time_ms: 0,
                audit_hash: None,
            });
        }

        // Create kernel tool request
        let request = ToolRequest {
            request_id: uuid::Uuid::new_v4(),
            tool_name: tool_call.name.clone(),
            parameters: tool_call.arguments.clone(),
            timeout_ms: Some(30_000),
        };

        // Execute through kernel (includes policy check and audit)
        let response = self
            .kernel
            .execute(&self.agent_id, &self.session_id, request)
            .await
            .map_err(|e| IntegrationError::ToolExecutionFailed(e.to_string()))?;

        let tool_result = ToolResult {
            tool_call_id: tool_call.id.clone(),
            success: response.success,
            content: if response.success {
                response
                    .result
                    .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
                    .unwrap_or_default()
            } else {
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            },
            execution_time_ms: response.execution_time_ms,
            audit_hash: None,
        };

        // Store in history
        self.history.write().await.push(tool_result.clone());

        Ok(tool_result)
    }

    /// Execute multiple tool calls in sequence
    pub async fn execute_tool_calls(
        &self,
        tool_calls: &[ToolCall],
    ) -> IntegrationResult<Vec<ToolResult>> {
        let mut results = Vec::with_capacity(tool_calls.len());
        for call in tool_calls {
            results.push(self.execute_tool_call(call).await?);
        }
        Ok(results)
    }

    /// Get the execution history for this agent
    pub async fn history(&self) -> Vec<ToolResult> {
        self.history.read().await.clone()
    }

    /// Get the audit trail for this agent from the kernel
    pub async fn audit_trail(&self) -> Vec<crate::kernel::types::AuditEntry> {
        self.kernel.get_audit_log().await
    }

    /// Get available tools for this agent
    pub async fn available_tools(&self) -> Vec<String> {
        let all_tools = self.kernel.list_tools().await;
        if let Some(ref allowed) = self.allowed_tools {
            all_tools
                .into_iter()
                .filter(|t| allowed.contains(t) && !self.blocked_tools.contains(t))
                .collect()
        } else {
            all_tools
                .into_iter()
                .filter(|t| !self.blocked_tools.contains(t))
                .collect()
        }
    }

    /// Set custom metadata for this agent
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }

    /// Get custom metadata
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

impl std::fmt::Debug for VakAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VakAgent")
            .field("agent_id", &self.agent_id)
            .field("name", &self.name)
            .field("session_id", &self.session_id)
            .field("allowed_tools", &self.allowed_tools)
            .field("blocked_tools", &self.blocked_tools)
            .finish()
    }
}

// ============================================================================
// VakAgent Builder
// ============================================================================

/// Builder for creating a `VakAgent` with configuration
pub struct AgentBuilder {
    name: String,
    kernel: Arc<Kernel>,
    allowed_tools: Option<Vec<String>>,
    blocked_tools: Vec<String>,
    metadata: HashMap<String, String>,
}

impl AgentBuilder {
    /// Create a new agent builder
    fn new(name: impl Into<String>, kernel: Arc<Kernel>) -> Self {
        Self {
            name: name.into(),
            kernel,
            allowed_tools: None,
            blocked_tools: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Restrict the agent to only use specific tools
    pub fn with_allowed_tools(mut self, tools: Vec<impl Into<String>>) -> Self {
        self.allowed_tools = Some(tools.into_iter().map(Into::into).collect());
        self
    }

    /// Block specific tools from being used
    pub fn with_blocked_tools(mut self, tools: Vec<impl Into<String>>) -> Self {
        self.blocked_tools = tools.into_iter().map(Into::into).collect();
        self
    }

    /// Add metadata to the agent
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the agent
    pub async fn build(self) -> IntegrationResult<VakAgent> {
        info!(agent_name = %self.name, "Creating VAK agent");

        Ok(VakAgent {
            agent_id: AgentId::new(),
            session_id: SessionId::new(),
            name: self.name,
            kernel: self.kernel,
            allowed_tools: self.allowed_tools,
            blocked_tools: self.blocked_tools,
            history: Arc::new(RwLock::new(Vec::new())),
            metadata: self.metadata,
        })
    }
}

// ============================================================================
// VakRuntime
// ============================================================================

/// The main runtime for VAK LLM integration.
///
/// `VakRuntime` manages the kernel, agents, and tool registry.
/// It's the entry point for applications using VAK as a library.
pub struct VakRuntime {
    /// The underlying kernel
    kernel: Arc<Kernel>,
    /// Registered tool definitions
    tool_definitions: Arc<RwLock<Vec<ToolDefinition>>>,
    /// Active agents (reserved for future agent lifecycle management)
    _agents: Arc<RwLock<HashMap<String, Arc<VakAgent>>>>,
    /// Runtime configuration
    config: RuntimeConfig,
}

/// Configuration for the VakRuntime
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    /// Name of the runtime instance
    pub name: String,
    /// Whether audit logging is enabled
    pub audit_enabled: bool,
    /// Whether policy enforcement is enabled
    pub policy_enabled: bool,
    /// Whether WASM sandboxing is enabled
    pub sandboxing_enabled: bool,
    /// Maximum concurrent agents
    pub max_agents: u32,
    /// Default tool execution timeout
    pub default_timeout: Duration,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            name: "vak-runtime".to_string(),
            audit_enabled: true,
            policy_enabled: true,
            sandboxing_enabled: true,
            max_agents: 100,
            default_timeout: Duration::from_secs(30),
        }
    }
}

impl VakRuntime {
    /// Create a new runtime builder
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::new()
    }

    /// Create a runtime with default configuration
    pub async fn new() -> IntegrationResult<Self> {
        Self::builder().build().await
    }

    /// Create a new agent within this runtime
    pub fn create_agent(&self, name: impl Into<String>) -> AgentBuilder {
        AgentBuilder::new(name, self.kernel.clone())
    }

    /// Register a custom tool definition
    pub async fn register_tool(&self, definition: ToolDefinition) {
        self.tool_definitions.write().await.push(definition);
    }

    /// Get all tool definitions (built-in + custom)
    pub async fn tool_definitions(&self) -> Vec<ToolDefinition> {
        let custom = self.tool_definitions.read().await;
        let mut all = builtin_tool_definitions();
        all.extend(custom.iter().cloned());
        all
    }

    /// Get tool definitions in OpenAI function calling format
    pub async fn tool_definitions_openai(&self) -> Vec<OpenAIFunction> {
        self.tool_definitions()
            .await
            .into_iter()
            .map(|t| t.to_openai())
            .collect()
    }

    /// Get tool definitions in Anthropic tool use format
    pub async fn tool_definitions_anthropic(&self) -> Vec<AnthropicTool> {
        self.tool_definitions()
            .await
            .into_iter()
            .map(|t| t.to_anthropic())
            .collect()
    }

    /// Execute a tool call directly (without agent context)
    pub async fn execute_tool_call(&self, tool_call: &ToolCall) -> IntegrationResult<ToolResult> {
        let agent_id = AgentId::new();
        let session_id = SessionId::new();

        let request = ToolRequest {
            request_id: uuid::Uuid::new_v4(),
            tool_name: tool_call.name.clone(),
            parameters: tool_call.arguments.clone(),
            timeout_ms: Some(self.config.default_timeout.as_millis() as u64),
        };

        let response = self
            .kernel
            .execute(&agent_id, &session_id, request)
            .await
            .map_err(|e| IntegrationError::ToolExecutionFailed(e.to_string()))?;

        Ok(ToolResult {
            tool_call_id: tool_call.id.clone(),
            success: response.success,
            content: if response.success {
                response
                    .result
                    .map(|v| serde_json::to_string_pretty(&v).unwrap_or_default())
                    .unwrap_or_default()
            } else {
                response.error.unwrap_or_else(|| "Unknown error".to_string())
            },
            execution_time_ms: response.execution_time_ms,
            audit_hash: None,
        })
    }

    /// Process a batch of tool calls from an LLM response
    pub async fn process_tool_calls(
        &self,
        agent: &VakAgent,
        tool_calls: Vec<ToolCall>,
    ) -> IntegrationResult<Vec<ToolResult>> {
        agent.execute_tool_calls(&tool_calls).await
    }

    /// Get the underlying kernel reference (for advanced usage)
    pub fn kernel(&self) -> &Arc<Kernel> {
        &self.kernel
    }

    /// Get the runtime configuration
    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    /// Get the VAK version
    pub fn version(&self) -> &str {
        crate::VERSION
    }
}

impl std::fmt::Debug for VakRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VakRuntime")
            .field("config", &self.config)
            .finish()
    }
}

// ============================================================================
// RuntimeBuilder
// ============================================================================

/// Builder for creating a `VakRuntime`
pub struct RuntimeBuilder {
    name: String,
    audit_enabled: bool,
    policy_enabled: bool,
    sandboxing_enabled: bool,
    max_agents: u32,
    default_timeout: Duration,
    custom_tools: Vec<ToolDefinition>,
    kernel_config: Option<KernelConfig>,
}

impl RuntimeBuilder {
    /// Create a new runtime builder with defaults
    fn new() -> Self {
        Self {
            name: "vak-runtime".to_string(),
            audit_enabled: true,
            policy_enabled: true,
            sandboxing_enabled: true,
            max_agents: 100,
            default_timeout: Duration::from_secs(30),
            custom_tools: Vec::new(),
            kernel_config: None,
        }
    }

    /// Set the runtime name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Enable or disable audit logging
    pub fn with_audit_logging(mut self, enabled: bool) -> Self {
        self.audit_enabled = enabled;
        self
    }

    /// Enable or disable policy enforcement
    pub fn with_policy_enforcement(mut self, enabled: bool) -> Self {
        self.policy_enabled = enabled;
        self
    }

    /// Enable or disable WASM sandboxing
    pub fn with_sandboxing(mut self, enabled: bool) -> Self {
        self.sandboxing_enabled = enabled;
        self
    }

    /// Set maximum concurrent agents
    pub fn with_max_agents(mut self, max: u32) -> Self {
        self.max_agents = max;
        self
    }

    /// Set default tool execution timeout
    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    /// Add a custom tool definition
    pub fn with_tool(mut self, tool: ToolDefinition) -> Self {
        self.custom_tools.push(tool);
        self
    }

    /// Use a custom kernel configuration
    pub fn with_kernel_config(mut self, config: KernelConfig) -> Self {
        self.kernel_config = Some(config);
        self
    }

    /// Build the runtime
    pub async fn build(self) -> IntegrationResult<VakRuntime> {
        info!(name = %self.name, "Building VAK runtime");

        let kernel_config = self.kernel_config.unwrap_or_else(|| {
            KernelConfig::builder()
                .name(&self.name)
                .max_concurrent_agents(self.max_agents as usize)
                .build()
        });

        let kernel = Arc::new(Kernel::new(kernel_config).await?);

        let tool_definitions = Arc::new(RwLock::new(self.custom_tools));

        Ok(VakRuntime {
            kernel,
            tool_definitions,
            _agents: Arc::new(RwLock::new(HashMap::new())),
            config: RuntimeConfig {
                name: self.name,
                audit_enabled: self.audit_enabled,
                policy_enabled: self.policy_enabled,
                sandboxing_enabled: self.sandboxing_enabled,
                max_agents: self.max_agents,
                default_timeout: self.default_timeout,
            },
        })
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Quick helper to create a tool call from name and arguments
pub fn tool_call(name: impl Into<String>, args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: uuid::Uuid::new_v4().to_string(),
        name: name.into(),
        arguments: args,
    }
}

/// Parse tool calls from an OpenAI-format response
pub fn parse_openai_tool_calls(response: &serde_json::Value) -> Vec<ToolCall> {
    let mut calls = Vec::new();

    if let Some(choices) = response.get("choices").and_then(|v| v.as_array()) {
        for choice in choices {
            if let Some(tool_calls) = choice
                .get("message")
                .and_then(|m| m.get("tool_calls"))
                .and_then(|tc| tc.as_array())
            {
                for tc in tool_calls {
                    if let (Some(id), Some(function)) =
                        (tc.get("id").and_then(|v| v.as_str()), tc.get("function"))
                    {
                        if let (Some(name), Some(arguments)) = (
                            function.get("name").and_then(|v| v.as_str()),
                            function.get("arguments").and_then(|v| v.as_str()),
                        ) {
                            if let Ok(args) = serde_json::from_str(arguments) {
                                calls.push(ToolCall {
                                    id: id.to_string(),
                                    name: name.to_string(),
                                    arguments: args,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    calls
}

/// Format tool results for sending back to an OpenAI-format API
pub fn format_openai_tool_results(results: &[ToolResult]) -> Vec<serde_json::Value> {
    results
        .iter()
        .map(|r| {
            serde_json::json!({
                "role": "tool",
                "tool_call_id": r.tool_call_id,
                "content": r.content,
            })
        })
        .collect()
}

/// Format tool results for sending back to an Anthropic-format API
pub fn format_anthropic_tool_results(results: &[ToolResult]) -> Vec<serde_json::Value> {
    results
        .iter()
        .map(|r| {
            serde_json::json!({
                "type": "tool_result",
                "tool_use_id": r.tool_call_id,
                "content": r.content,
                "is_error": !r.success,
            })
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_definition_creation() {
        let tool = ToolDefinition::new(
            "test_tool",
            "A test tool",
            serde_json::json!({"type": "object", "properties": {}}),
        );
        assert_eq!(tool.name, "test_tool");
        assert_eq!(tool.risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_tool_definition_to_openai() {
        let tool = ToolDefinition::new(
            "calculator",
            "Do math",
            serde_json::json!({"type": "object"}),
        );
        let openai = tool.to_openai();
        assert_eq!(openai.function_type, "function");
        assert_eq!(openai.function.name, "calculator");
    }

    #[test]
    fn test_tool_definition_to_anthropic() {
        let tool = ToolDefinition::new(
            "calculator",
            "Do math",
            serde_json::json!({"type": "object"}),
        );
        let anthropic = tool.to_anthropic();
        assert_eq!(anthropic.name, "calculator");
    }

    #[test]
    fn test_builtin_tool_definitions() {
        let tools = builtin_tool_definitions();
        assert!(tools.len() >= 4);
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"calculator"));
        assert!(names.contains(&"data_processor"));
        assert!(names.contains(&"system_info"));
        assert!(names.contains(&"echo"));
    }

    #[test]
    fn test_tool_call_creation() {
        let call = tool_call("calculator", serde_json::json!({"op": "add"}));
        assert_eq!(call.name, "calculator");
        assert!(!call.id.is_empty());
    }

    #[test]
    fn test_parse_openai_tool_calls() {
        let response = serde_json::json!({
            "choices": [{
                "message": {
                    "tool_calls": [{
                        "id": "call_123",
                        "type": "function",
                        "function": {
                            "name": "calculator",
                            "arguments": "{\"operation\": \"add\", \"operands\": [1, 2]}"
                        }
                    }]
                }
            }]
        });

        let calls = parse_openai_tool_calls(&response);
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "calculator");
        assert_eq!(calls[0].id, "call_123");
    }

    #[test]
    fn test_format_openai_tool_results() {
        let results = vec![ToolResult {
            tool_call_id: "call_123".to_string(),
            success: true,
            content: "42".to_string(),
            execution_time_ms: 5,
            audit_hash: None,
        }];

        let formatted = format_openai_tool_results(&results);
        assert_eq!(formatted.len(), 1);
        assert_eq!(formatted[0]["role"], "tool");
        assert_eq!(formatted[0]["tool_call_id"], "call_123");
    }

    #[test]
    fn test_format_anthropic_tool_results() {
        let results = vec![ToolResult {
            tool_call_id: "tu_123".to_string(),
            success: false,
            content: "error occurred".to_string(),
            execution_time_ms: 10,
            audit_hash: None,
        }];

        let formatted = format_anthropic_tool_results(&results);
        assert_eq!(formatted.len(), 1);
        assert_eq!(formatted[0]["type"], "tool_result");
        assert_eq!(formatted[0]["is_error"], true);
    }

    #[tokio::test]
    async fn test_runtime_builder() {
        let runtime = VakRuntime::builder()
            .with_name("test-runtime")
            .with_audit_logging(true)
            .with_policy_enforcement(false)
            .build()
            .await;

        assert!(runtime.is_ok());
        let runtime = runtime.unwrap();
        assert_eq!(runtime.config().name, "test-runtime");
    }

    #[tokio::test]
    async fn test_runtime_tool_definitions() {
        let runtime = VakRuntime::builder().build().await.unwrap();

        runtime
            .register_tool(ToolDefinition::new(
                "custom_tool",
                "My custom tool",
                serde_json::json!({"type": "object"}),
            ))
            .await;

        let tools = runtime.tool_definitions().await;
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"custom_tool"));
        assert!(names.contains(&"calculator"));
    }

    #[tokio::test]
    async fn test_agent_creation() {
        let runtime = VakRuntime::builder().build().await.unwrap();

        let agent = runtime
            .create_agent("test-agent")
            .with_allowed_tools(vec!["calculator", "echo"])
            .build()
            .await;

        assert!(agent.is_ok());
        let agent = agent.unwrap();
        assert_eq!(agent.name(), "test-agent");
    }

    #[tokio::test]
    async fn test_agent_tool_execution() {
        let runtime = VakRuntime::builder()
            .with_policy_enforcement(false)
            .build()
            .await
            .unwrap();

        let agent = runtime.create_agent("test-agent").build().await.unwrap();

        let result = agent
            .call_tool(
                "calculator",
                serde_json::json!({
                    "operation": "add",
                    "operands": [1, 2, 3]
                }),
            )
            .await;

        assert!(result.is_ok());
        let result = result.unwrap();
        assert!(result.success);
        assert!(result.content.contains("6"));
    }

    #[tokio::test]
    async fn test_agent_blocked_tool() {
        let runtime = VakRuntime::builder().build().await.unwrap();

        let agent = runtime
            .create_agent("restricted-agent")
            .with_blocked_tools(vec!["calculator"])
            .build()
            .await
            .unwrap();

        let result = agent
            .call_tool("calculator", serde_json::json!({}))
            .await
            .unwrap();
        assert!(!result.success);
        assert!(result.content.contains("blocked"));
    }

    #[tokio::test]
    async fn test_runtime_config_defaults() {
        let config = RuntimeConfig::default();
        assert!(config.audit_enabled);
        assert!(config.policy_enabled);
        assert!(config.sandboxing_enabled);
        assert_eq!(config.max_agents, 100);
    }

    #[test]
    fn test_risk_level_default() {
        let level = RiskLevel::default();
        assert_eq!(level, RiskLevel::Low);
    }

    #[test]
    fn test_tool_definition_serialization() {
        let tool = ToolDefinition::new(
            "test",
            "desc",
            serde_json::json!({"type": "object"}),
        )
        .with_risk_level(RiskLevel::High)
        .with_categories(vec!["math".to_string()]);

        let json = serde_json::to_string(&tool).unwrap();
        assert!(json.contains("\"risk_level\":\"high\""));
        assert!(json.contains("\"math\""));
    }
}
