//! Custom Operation Handler Registry
//!
//! Provides a registry for custom tool handlers that can be registered at runtime.
//! This enables extending the kernel with new tools without modifying core code.
//!
//! # Overview
//!
//! Custom handlers allow:
//! - Runtime registration of new tools
//! - WASM skill integration
//! - External service bridging
//! - Plugin-based extensibility
//!
//! # Security Considerations
//!
//! All custom handlers:
//! - Must pass policy validation before execution
//! - Are subject to rate limiting
//! - Have bounded execution time (epoch deadline)
//! - Generate audit log entries
//!
//! # Example
//!
//! ```rust,ignore
//! use vak::kernel::custom_handlers::{CustomHandlerRegistry, ToolHandler};
//!
//! let mut registry = CustomHandlerRegistry::new();
//!
//! // Register a custom handler
//! registry.register("my_tool", Box::new(|call, agent_id| {
//!     Box::pin(async move {
//!         Ok(ToolResponse {
//!             tool_name: call.tool_name.clone(),
//!             output: serde_json::json!({"result": "success"}),
//!             success: true,
//!         })
//!     })
//! }));
//!
//! // Execute a tool
//! let result = registry.execute("my_tool", &tool_call, &agent_id).await?;
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::kernel::types::{AgentId, ToolRequest, ToolResponse};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during custom handler operations
#[derive(Debug, Error)]
pub enum HandlerError {
    /// Handler not found
    #[error("Handler not found: {0}")]
    NotFound(String),

    /// Handler execution failed
    #[error("Handler execution failed: {0}")]
    ExecutionFailed(String),

    /// Handler timeout
    #[error("Handler execution timed out after {0}ms")]
    Timeout(u64),

    /// Invalid parameters
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    /// Policy violation
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
}

/// Result type for handler operations
pub type HandlerResult<T> = Result<T, HandlerError>;

// ============================================================================
// Handler Types
// ============================================================================

/// Boxed future type for async handler execution
pub type HandlerFuture = Pin<Box<dyn Future<Output = HandlerResult<ToolResponse>> + Send>>;

/// Trait for custom tool handlers
pub trait ToolHandler: Send + Sync {
    /// Execute the tool with the given call and agent context
    fn execute(&self, call: &ToolRequest, agent_id: &AgentId) -> HandlerFuture;

    /// Get the tool name
    fn name(&self) -> &str;

    /// Get tool description for documentation
    fn description(&self) -> &str {
        "No description available"
    }

    /// Get the JSON schema for tool parameters
    fn parameter_schema(&self) -> Option<serde_json::Value> {
        None
    }

    /// Check if this handler requires special permissions
    fn required_capabilities(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Metadata about a registered handler
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandlerMetadata {
    /// Tool name
    pub name: String,
    /// Tool description
    pub description: String,
    /// Required capabilities
    pub required_capabilities: Vec<String>,
    /// Parameter schema (JSON Schema)
    pub parameter_schema: Option<serde_json::Value>,
    /// Registration timestamp
    pub registered_at: chrono::DateTime<chrono::Utc>,
    /// Whether the handler is enabled
    pub enabled: bool,
}

// ============================================================================
// Handler Registry
// ============================================================================

/// Registry for custom tool handlers
pub struct CustomHandlerRegistry {
    /// Registered handlers
    handlers: RwLock<HashMap<String, Arc<dyn ToolHandler>>>,
    /// Handler metadata
    metadata: RwLock<HashMap<String, HandlerMetadata>>,
    /// Default timeout for handler execution (milliseconds)
    default_timeout_ms: u64,
}

impl CustomHandlerRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            metadata: RwLock::new(HashMap::new()),
            default_timeout_ms: 30_000, // 30 seconds default
        }
    }

    /// Create a registry with custom timeout
    pub fn with_timeout(timeout_ms: u64) -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            metadata: RwLock::new(HashMap::new()),
            default_timeout_ms: timeout_ms,
        }
    }

    /// Register a custom handler
    pub async fn register<H: ToolHandler + 'static>(&self, handler: H) -> HandlerResult<()> {
        let name = handler.name().to_string();

        let metadata = HandlerMetadata {
            name: name.clone(),
            description: handler.description().to_string(),
            required_capabilities: handler.required_capabilities(),
            parameter_schema: handler.parameter_schema(),
            registered_at: chrono::Utc::now(),
            enabled: true,
        };

        let mut handlers = self.handlers.write().await;
        let mut meta_map = self.metadata.write().await;

        if handlers.contains_key(&name) {
            warn!(tool = %name, "Overwriting existing handler");
        }

        handlers.insert(name.clone(), Arc::new(handler));
        meta_map.insert(name.clone(), metadata);

        info!(tool = %name, "Registered custom handler");
        Ok(())
    }

    /// Unregister a handler
    pub async fn unregister(&self, name: &str) -> HandlerResult<()> {
        let mut handlers = self.handlers.write().await;
        let mut metadata = self.metadata.write().await;

        if handlers.remove(name).is_none() {
            return Err(HandlerError::NotFound(name.to_string()));
        }
        metadata.remove(name);

        info!(tool = %name, "Unregistered custom handler");
        Ok(())
    }

    /// Check if a handler is registered
    pub async fn has_handler(&self, name: &str) -> bool {
        let handlers = self.handlers.read().await;
        handlers.contains_key(name)
    }

    /// Get handler metadata
    pub async fn get_metadata(&self, name: &str) -> Option<HandlerMetadata> {
        let metadata = self.metadata.read().await;
        metadata.get(name).cloned()
    }

    /// List all registered handlers
    pub async fn list_handlers(&self) -> Vec<HandlerMetadata> {
        let metadata = self.metadata.read().await;
        metadata.values().cloned().collect()
    }

    /// Execute a handler
    pub async fn execute(
        &self,
        tool_call: &ToolRequest,
        agent_id: &AgentId,
    ) -> HandlerResult<ToolResponse> {
        let handlers = self.handlers.read().await;

        let handler = handlers
            .get(&tool_call.tool_name)
            .ok_or_else(|| HandlerError::NotFound(tool_call.tool_name.clone()))?;

        // Check if handler is enabled
        let metadata = self.metadata.read().await;
        if let Some(meta) = metadata.get(&tool_call.tool_name) {
            if !meta.enabled {
                return Err(HandlerError::ExecutionFailed(format!(
                    "Handler '{}' is disabled",
                    tool_call.tool_name
                )));
            }
        }
        drop(metadata);

        debug!(
            tool = %tool_call.tool_name,
            agent = %agent_id,
            "Executing custom handler"
        );

        // Execute with timeout
        let handler = Arc::clone(handler);
        let call_clone = tool_call.clone();
        let agent_clone = agent_id.clone();

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(self.default_timeout_ms),
            async move { handler.execute(&call_clone, &agent_clone).await },
        )
        .await
        .map_err(|_| HandlerError::Timeout(self.default_timeout_ms))?;

        result
    }

    /// Enable a handler
    pub async fn enable(&self, name: &str) -> HandlerResult<()> {
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(name) {
            meta.enabled = true;
            Ok(())
        } else {
            Err(HandlerError::NotFound(name.to_string()))
        }
    }

    /// Disable a handler
    pub async fn disable(&self, name: &str) -> HandlerResult<()> {
        let mut metadata = self.metadata.write().await;
        if let Some(meta) = metadata.get_mut(name) {
            meta.enabled = false;
            Ok(())
        } else {
            Err(HandlerError::NotFound(name.to_string()))
        }
    }
}

impl Default for CustomHandlerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for CustomHandlerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomHandlerRegistry")
            .field("default_timeout_ms", &self.default_timeout_ms)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Simple Function Handler
// ============================================================================

/// A simple handler that wraps a function
pub struct FunctionHandler<F>
where
    F: Fn(&ToolRequest, &AgentId) -> HandlerFuture + Send + Sync,
{
    name: String,
    description: String,
    func: F,
}

impl<F> FunctionHandler<F>
where
    F: Fn(&ToolRequest, &AgentId) -> HandlerFuture + Send + Sync,
{
    /// Create a new function handler
    pub fn new(name: impl Into<String>, func: F) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            func,
        }
    }

    /// Set the description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

impl<F> ToolHandler for FunctionHandler<F>
where
    F: Fn(&ToolRequest, &AgentId) -> HandlerFuture + Send + Sync,
{
    fn execute(&self, call: &ToolRequest, agent_id: &AgentId) -> HandlerFuture {
        (self.func)(call, agent_id)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> &str {
        &self.description
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHandler {
        name: String,
    }

    impl ToolHandler for TestHandler {
        fn execute(&self, call: &ToolRequest, _agent_id: &AgentId) -> HandlerFuture {
            let request_id = call.request_id;
            Box::pin(async move {
                Ok(ToolResponse::success(
                    request_id,
                    serde_json::json!({"test": "result"}),
                    0,
                ))
            })
        }

        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "Test handler for unit tests"
        }
    }

    #[tokio::test]
    async fn test_register_handler() {
        let registry = CustomHandlerRegistry::new();
        let handler = TestHandler {
            name: "test_tool".to_string(),
        };

        registry.register(handler).await.unwrap();
        assert!(registry.has_handler("test_tool").await);
    }

    #[tokio::test]
    async fn test_execute_handler() {
        let registry = CustomHandlerRegistry::new();
        let handler = TestHandler {
            name: "test_tool".to_string(),
        };

        registry.register(handler).await.unwrap();

        let call = ToolRequest::new("test_tool", serde_json::json!({}));
        let agent_id = AgentId::new();

        let result = registry.execute(&call, &agent_id).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_unregister_handler() {
        let registry = CustomHandlerRegistry::new();
        let handler = TestHandler {
            name: "test_tool".to_string(),
        };

        registry.register(handler).await.unwrap();
        assert!(registry.has_handler("test_tool").await);

        registry.unregister("test_tool").await.unwrap();
        assert!(!registry.has_handler("test_tool").await);
    }

    #[tokio::test]
    async fn test_handler_not_found() {
        let registry = CustomHandlerRegistry::new();

        let call = ToolRequest::new("nonexistent", serde_json::json!({}));
        let agent_id = AgentId::new();

        let result = registry.execute(&call, &agent_id).await;
        assert!(matches!(result, Err(HandlerError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_disable_handler() {
        let registry = CustomHandlerRegistry::new();
        let handler = TestHandler {
            name: "test_tool".to_string(),
        };

        registry.register(handler).await.unwrap();
        registry.disable("test_tool").await.unwrap();

        let call = ToolRequest::new("test_tool", serde_json::json!({}));
        let agent_id = AgentId::new();

        let result = registry.execute(&call, &agent_id).await;
        assert!(matches!(result, Err(HandlerError::ExecutionFailed(_))));
    }
}
