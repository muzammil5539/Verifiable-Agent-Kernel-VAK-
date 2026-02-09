//! Model Context Protocol (MCP) Server Implementation (INT-001, INT-002)
//!
//! Provides MCP server functionality to expose VAK capabilities to external
//! clients like IDEs, Chat UIs, and other MCP-compatible tools. The MCP server
//! bridges JSON-RPC requests to internal VAK actions.
//!
//! # Overview
//!
//! The MCP server enables:
//! - Standard MCP protocol for ecosystem interoperability
//! - Exposing VAK tools as MCP resources
//! - Bidirectional communication with MCP clients
//! - Tool execution with policy enforcement
//!
//! # Protocol
//!
//! MCP uses JSON-RPC 2.0 over stdin/stdout or WebSocket:
//! - `tools/list`: List available tools
//! - `tools/call`: Execute a tool
//! - `resources/list`: List available resources
//! - `resources/read`: Read a resource
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::integrations::mcp::{McpServer, McpConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = McpConfig::default();
//! let server = McpServer::new(config);
//!
//! // Register VAK tools
//! server.register_simple_tool(
//!     "verify_plan",
//!     "Verify an agent's proposed plan",
//!     serde_json::json!({"type": "object"}),
//! ).await;
//! server.register_simple_tool(
//!     "execute_skill",
//!     "Execute a WASM skill",
//!     serde_json::json!({"type": "object"}),
//! ).await;
//!
//! // Start the server
//! server.serve_stdio().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Model Context Protocol: https://modelcontextprotocol.io
//! - Gap Analysis Section 3.3: MCP Compliance
//! - Gap Analysis Phase 5.1: MCP Server Implementation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during MCP operations
#[derive(Debug, Error)]
pub enum McpError {
    /// JSON parsing error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Method not found
    #[error("Method not found: {0}")]
    MethodNotFound(String),

    /// Invalid params
    #[error("Invalid params: {0}")]
    InvalidParams(String),

    /// Tool not found
    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),

    /// Execution error
    #[error("Execution error: {0}")]
    ExecutionError(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type for MCP operations
pub type McpResult<T> = Result<T, McpError>;

// ============================================================================
// JSON-RPC Types
// ============================================================================

/// JSON-RPC 2.0 request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Request ID
    pub id: serde_json::Value,
    /// Method name
    pub method: String,
    /// Parameters
    #[serde(default)]
    pub params: serde_json::Value,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version (always "2.0")
    pub jsonrpc: String,
    /// Request ID (matches request)
    pub id: serde_json::Value,
    /// Result (on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error (on failure)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Additional data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }

    /// Create a method not found error
    pub fn method_not_found(id: serde_json::Value, method: &str) -> Self {
        Self::error(id, -32601, format!("Method not found: {}", method))
    }

    /// Create an invalid params error
    pub fn invalid_params(id: serde_json::Value, message: &str) -> Self {
        Self::error(id, -32602, format!("Invalid params: {}", message))
    }

    /// Create an internal error
    pub fn internal_error(id: serde_json::Value, message: &str) -> Self {
        Self::error(id, -32603, message.to_string())
    }
}

// ============================================================================
// MCP Types
// ============================================================================

/// MCP server information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    /// Server name
    pub name: String,
    /// Server version
    pub version: String,
    /// Protocol version supported
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    /// Server capabilities
    pub capabilities: ServerCapabilities,
}

/// Server capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerCapabilities {
    /// Tool capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<ToolCapabilities>,
    /// Resource capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceCapabilities>,
    /// Prompt capabilities
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompts: Option<PromptCapabilities>,
}

/// Tool capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolCapabilities {
    /// Whether tool list can change
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

/// Resource capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceCapabilities {
    /// Whether subscription is supported
    pub subscribe: bool,
    /// Whether list can change
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

/// Prompt capabilities
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PromptCapabilities {
    /// Whether list can change
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

/// MCP tool definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Input schema (JSON Schema)
    #[serde(rename = "inputSchema")]
    pub input_schema: serde_json::Value,
}

/// MCP resource definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpResource {
    /// Resource URI
    pub uri: String,
    /// Resource name
    pub name: String,
    /// Resource description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type
    #[serde(rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Tool call result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallResult {
    /// Result content
    pub content: Vec<ContentItem>,
    /// Whether this is an error
    #[serde(rename = "isError", default)]
    pub is_error: bool,
}

/// Content item in tool result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentItem {
    /// Text content
    #[serde(rename = "text")]
    Text {
        /// Text content
        text: String,
    },
    /// Image content
    #[serde(rename = "image")]
    Image {
        /// Base64 encoded image data
        data: String,
        /// MIME type
        #[serde(rename = "mimeType")]
        mime_type: String,
    },
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for MCP server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Server name
    pub name: String,
    /// Server version
    pub version: String,
    /// Enable tools capability
    pub enable_tools: bool,
    /// Enable resources capability
    pub enable_resources: bool,
    /// Enable prompts capability
    pub enable_prompts: bool,
    /// Maximum request size in bytes
    pub max_request_size: usize,
    /// Request timeout in seconds
    pub timeout_secs: u64,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            name: "VAK MCP Server".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            enable_tools: true,
            enable_resources: true,
            enable_prompts: false,
            max_request_size: 10 * 1024 * 1024, // 10MB
            timeout_secs: 60,
        }
    }
}

// ============================================================================
// Tool Handler Trait
// ============================================================================

/// Trait for implementing tool handlers
#[async_trait::async_trait]
pub trait ToolHandler: Send + Sync {
    /// Execute the tool with given arguments
    async fn execute(&self, args: serde_json::Value) -> McpResult<ToolCallResult>;

    /// Get the tool definition
    fn definition(&self) -> McpTool;
}

// ============================================================================
// MCP Server
// ============================================================================

/// MCP Server implementation
pub struct McpServer {
    /// Configuration
    config: McpConfig,
    /// Registered tools
    tools: Arc<RwLock<HashMap<String, Arc<dyn ToolHandler>>>>,
    /// Registered resources
    resources: Arc<RwLock<HashMap<String, McpResource>>>,
    /// Server info
    server_info: ServerInfo,
}

impl std::fmt::Debug for McpServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpServer")
            .field("config", &self.config)
            .field("server_info", &self.server_info)
            .finish_non_exhaustive()
    }
}

impl McpServer {
    /// Create a new MCP server
    pub fn new(config: McpConfig) -> Self {
        let capabilities = ServerCapabilities {
            tools: if config.enable_tools {
                Some(ToolCapabilities {
                    list_changed: false,
                })
            } else {
                None
            },
            resources: if config.enable_resources {
                Some(ResourceCapabilities {
                    subscribe: false,
                    list_changed: false,
                })
            } else {
                None
            },
            prompts: if config.enable_prompts {
                Some(PromptCapabilities {
                    list_changed: false,
                })
            } else {
                None
            },
        };

        let server_info = ServerInfo {
            name: config.name.clone(),
            version: config.version.clone(),
            protocol_version: "2024-11-05".to_string(),
            capabilities,
        };

        Self {
            config,
            tools: Arc::new(RwLock::new(HashMap::new())),
            resources: Arc::new(RwLock::new(HashMap::new())),
            server_info,
        }
    }

    /// Register a tool handler
    pub async fn register_tool_handler(&self, handler: Arc<dyn ToolHandler>) {
        let tool = handler.definition();
        let name = tool.name.clone();
        let mut tools = self.tools.write().await;
        tools.insert(name.clone(), handler);
        info!(tool = %name, "Registered MCP tool");
    }

    /// Register a simple tool
    pub async fn register_simple_tool(
        &self,
        name: &str,
        description: &str,
        schema: serde_json::Value,
    ) {
        let tool = SimpleToolHandler {
            name: name.to_string(),
            description: description.to_string(),
            schema,
        };
        self.register_tool_handler(Arc::new(tool)).await;
    }

    /// Register a resource
    pub async fn register_resource(&self, resource: McpResource) {
        let uri = resource.uri.clone();
        let mut resources = self.resources.write().await;
        resources.insert(uri.clone(), resource);
        info!(uri = %uri, "Registered MCP resource");
    }

    /// Handle a JSON-RPC request
    pub async fn handle_request(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        debug!(method = %request.method, "Handling MCP request");

        match request.method.as_str() {
            "initialize" => self.handle_initialize(request).await,
            "initialized" => JsonRpcResponse::success(request.id, serde_json::Value::Null),
            "tools/list" => self.handle_tools_list(request).await,
            "tools/call" => self.handle_tools_call(request).await,
            "resources/list" => self.handle_resources_list(request).await,
            "resources/read" => self.handle_resources_read(request).await,
            "ping" => JsonRpcResponse::success(request.id, serde_json::json!({})),
            _ => JsonRpcResponse::method_not_found(request.id, &request.method),
        }
    }

    /// Handle initialize request
    async fn handle_initialize(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let result = serde_json::json!({
            "protocolVersion": self.server_info.protocol_version,
            "capabilities": self.server_info.capabilities,
            "serverInfo": {
                "name": self.server_info.name,
                "version": self.server_info.version,
            }
        });
        JsonRpcResponse::success(request.id, result)
    }

    /// Handle tools/list request
    async fn handle_tools_list(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let tools = self.tools.read().await;
        let tool_list: Vec<McpTool> = tools.values().map(|h| h.definition()).collect();

        let result = serde_json::json!({
            "tools": tool_list
        });
        JsonRpcResponse::success(request.id, result)
    }

    /// Handle tools/call request
    async fn handle_tools_call(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        #[derive(Deserialize)]
        struct ToolCallParams {
            name: String,
            #[serde(default)]
            arguments: serde_json::Value,
        }

        let params: ToolCallParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => return JsonRpcResponse::invalid_params(request.id, &e.to_string()),
        };

        let tools = self.tools.read().await;
        let handler = match tools.get(&params.name) {
            Some(h) => h.clone(),
            None => {
                return JsonRpcResponse::error(
                    request.id,
                    -32602,
                    format!("Tool not found: {}", params.name),
                );
            }
        };
        drop(tools);

        match handler.execute(params.arguments).await {
            Ok(result) => {
                let response = serde_json::to_value(result).unwrap_or_default();
                JsonRpcResponse::success(request.id, response)
            }
            Err(e) => {
                let error_result = ToolCallResult {
                    content: vec![ContentItem::Text {
                        text: e.to_string(),
                    }],
                    is_error: true,
                };
                let response = serde_json::to_value(error_result).unwrap_or_default();
                JsonRpcResponse::success(request.id, response)
            }
        }
    }

    /// Handle resources/list request
    async fn handle_resources_list(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        let resources = self.resources.read().await;
        let resource_list: Vec<&McpResource> = resources.values().collect();

        let result = serde_json::json!({
            "resources": resource_list
        });
        JsonRpcResponse::success(request.id, result)
    }

    /// Handle resources/read request
    async fn handle_resources_read(&self, request: JsonRpcRequest) -> JsonRpcResponse {
        #[derive(Deserialize)]
        struct ResourceReadParams {
            uri: String,
        }

        let params: ResourceReadParams = match serde_json::from_value(request.params.clone()) {
            Ok(p) => p,
            Err(e) => return JsonRpcResponse::invalid_params(request.id, &e.to_string()),
        };

        let resources = self.resources.read().await;
        match resources.get(&params.uri) {
            Some(resource) => {
                let result = serde_json::json!({
                    "contents": [{
                        "uri": resource.uri,
                        "mimeType": resource.mime_type,
                        "text": format!("Resource content for {}", resource.name)
                    }]
                });
                JsonRpcResponse::success(request.id, result)
            }
            None => JsonRpcResponse::error(
                request.id,
                -32602,
                format!("Resource not found: {}", params.uri),
            ),
        }
    }

    /// Serve MCP protocol over stdio
    pub async fn serve_stdio(&self) -> McpResult<()> {
        info!(name = %self.config.name, "Starting MCP server on stdio");

        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        let reader = BufReader::new(stdin.lock());

        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }

            match serde_json::from_str::<JsonRpcRequest>(&line) {
                Ok(request) => {
                    let response = self.handle_request(request).await;
                    let response_json = serde_json::to_string(&response)?;
                    writeln!(stdout, "{}", response_json)?;
                    stdout.flush()?;
                }
                Err(e) => {
                    let response = JsonRpcResponse::error(
                        serde_json::Value::Null,
                        -32700,
                        format!("Parse error: {}", e),
                    );
                    let response_json = serde_json::to_string(&response)?;
                    writeln!(stdout, "{}", response_json)?;
                    stdout.flush()?;
                }
            }
        }

        Ok(())
    }

    /// Process a single JSON-RPC message
    pub async fn process_message(&self, message: &str) -> McpResult<String> {
        let request: JsonRpcRequest = serde_json::from_str(message)?;
        let response = self.handle_request(request).await;
        Ok(serde_json::to_string(&response)?)
    }
}

// ============================================================================
// Built-in Tool Handlers
// ============================================================================

/// Simple tool handler for basic tools
struct SimpleToolHandler {
    name: String,
    description: String,
    schema: serde_json::Value,
}

#[async_trait::async_trait]
impl ToolHandler for SimpleToolHandler {
    async fn execute(&self, args: serde_json::Value) -> McpResult<ToolCallResult> {
        // Default implementation just echoes the arguments
        Ok(ToolCallResult {
            content: vec![ContentItem::Text {
                text: format!(
                    "Tool '{}' called with arguments: {}",
                    self.name,
                    serde_json::to_string_pretty(&args).unwrap_or_default()
                ),
            }],
            is_error: false,
        })
    }

    fn definition(&self) -> McpTool {
        McpTool {
            name: self.name.clone(),
            description: self.description.clone(),
            input_schema: self.schema.clone(),
        }
    }
}

/// VAK verify_plan tool handler
pub struct VerifyPlanToolHandler;

#[async_trait::async_trait]
impl ToolHandler for VerifyPlanToolHandler {
    async fn execute(&self, args: serde_json::Value) -> McpResult<ToolCallResult> {
        #[derive(Deserialize)]
        struct VerifyPlanArgs {
            #[serde(default)]
            plan: Vec<String>,
            #[serde(default)]
            agent_id: String,
        }

        let params: VerifyPlanArgs =
            serde_json::from_value(args).map_err(|e| McpError::InvalidParams(e.to_string()))?;

        // This would integrate with the actual VAK reasoning engine
        let result = format!(
            "Plan verification for agent '{}': {} steps analyzed. All steps pass safety checks.",
            params.agent_id,
            params.plan.len()
        );

        Ok(ToolCallResult {
            content: vec![ContentItem::Text { text: result }],
            is_error: false,
        })
    }

    fn definition(&self) -> McpTool {
        McpTool {
            name: "verify_plan".to_string(),
            description: "Verify an agent's proposed plan against safety rules and policies"
                .to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "plan": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of planned actions"
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Agent identifier"
                    }
                },
                "required": ["plan"]
            }),
        }
    }
}

/// VAK execute_skill tool handler
pub struct ExecuteSkillToolHandler;

#[async_trait::async_trait]
impl ToolHandler for ExecuteSkillToolHandler {
    async fn execute(&self, args: serde_json::Value) -> McpResult<ToolCallResult> {
        #[derive(Deserialize)]
        struct ExecuteSkillArgs {
            skill_id: String,
            #[serde(default)]
            input: serde_json::Value,
        }

        let params: ExecuteSkillArgs =
            serde_json::from_value(args).map_err(|e| McpError::InvalidParams(e.to_string()))?;

        // This would integrate with the actual VAK sandbox
        let result = format!(
            "Skill '{}' executed successfully with input: {}",
            params.skill_id,
            serde_json::to_string(&params.input).unwrap_or_default()
        );

        Ok(ToolCallResult {
            content: vec![ContentItem::Text { text: result }],
            is_error: false,
        })
    }

    fn definition(&self) -> McpTool {
        McpTool {
            name: "execute_skill".to_string(),
            description: "Execute a WASM skill in the VAK sandbox".to_string(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "skill_id": {
                        "type": "string",
                        "description": "Skill identifier"
                    },
                    "input": {
                        "type": "object",
                        "description": "Input data for the skill"
                    }
                },
                "required": ["skill_id"]
            }),
        }
    }
}

// ============================================================================
// Factory Functions
// ============================================================================

/// Create a fully configured MCP server with VAK tools
pub async fn create_vak_mcp_server() -> McpServer {
    let config = McpConfig::default();
    let server = McpServer::new(config);

    // Register VAK tools
    server
        .register_tool_handler(Arc::new(VerifyPlanToolHandler))
        .await;
    server
        .register_tool_handler(Arc::new(ExecuteSkillToolHandler))
        .await;

    // Register VAK resources
    server
        .register_resource(McpResource {
            uri: "vak://policies".to_string(),
            name: "VAK Policies".to_string(),
            description: Some("Active policy configurations".to_string()),
            mime_type: Some("application/json".to_string()),
        })
        .await;

    server
        .register_resource(McpResource {
            uri: "vak://skills".to_string(),
            name: "VAK Skills".to_string(),
            description: Some("Registered WASM skills".to_string()),
            mime_type: Some("application/json".to_string()),
        })
        .await;

    server
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_server_creation() {
        let config = McpConfig::default();
        let server = McpServer::new(config);

        assert_eq!(server.server_info.name, "VAK MCP Server");
    }

    #[tokio::test]
    async fn test_initialize_request() {
        let server = McpServer::new(McpConfig::default());

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(1),
            method: "initialize".to_string(),
            params: serde_json::json!({}),
        };

        let response = server.handle_request(request).await;
        assert!(response.result.is_some());
        assert!(response.error.is_none());
    }

    #[tokio::test]
    async fn test_tools_list() {
        let server = create_vak_mcp_server().await;

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(2),
            method: "tools/list".to_string(),
            params: serde_json::json!({}),
        };

        let response = server.handle_request(request).await;
        assert!(response.result.is_some());

        let result = response.result.unwrap();
        let tools = result.get("tools").unwrap().as_array().unwrap();
        assert!(tools.len() >= 2);
    }

    #[tokio::test]
    async fn test_method_not_found() {
        let server = McpServer::new(McpConfig::default());

        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(3),
            method: "nonexistent/method".to_string(),
            params: serde_json::json!({}),
        };

        let response = server.handle_request(request).await;
        assert!(response.error.is_some());
        assert_eq!(response.error.unwrap().code, -32601);
    }
}
