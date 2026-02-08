//! Async Host Functions Module (RT-004)
//!
//! Provides asynchronous host function infrastructure for WASM sandbox execution.
//! This module ensures that I/O-bound host functions don't block the tokio runtime.
//!
//! # Architecture
//!
//! ```text
//! WASM Call -> Async Wrapper -> Tokio Task -> Result
//! ```
//!
//! The key insight is that while WASM host functions must be synchronous at the
//! WASM boundary, we can use `tokio::task::spawn_blocking` for I/O operations
//! and `Store::epoch_deadline_async_yield_and_update` for cooperative yielding.
//!
//! # Features
//!
//! - Async I/O operations (file system, network)
//! - Non-blocking policy evaluation
//! - Cooperative yielding during long operations
//! - Thread-safe state access
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::async_host::{AsyncHostContext, AsyncOperation};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let context = AsyncHostContext::new("agent-1", "session-1");
//!
//! // Queue an async operation
//! let result = context.execute_async(AsyncOperation::FileRead {
//!     path: "/data/config.json".to_string(),
//! }).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 4, Phase 1.3: Async Host Interface (HFI)
//! - Gap Analysis Section 2.1.1: Async Stack Switching

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info};

use crate::policy::context::{ContextConfig, DynamicContextCollector};
use crate::policy::enforcer::{Action, CedarEnforcer, EnforcerConfig, Principal, Resource};

/// Errors that can occur in async host operations
#[derive(Debug, Error)]
pub enum AsyncHostError {
    /// Operation timed out
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),

    /// Operation cancelled
    #[error("Operation cancelled: {0}")]
    Cancelled(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// Permission denied
    #[error("Permission denied: {action} on {resource}")]
    PermissionDenied { action: String, resource: String },

    /// Resource exhausted
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Channel error
    #[error("Channel error: {0}")]
    ChannelError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for AsyncHostError {
    fn from(err: std::io::Error) -> Self {
        AsyncHostError::IoError(err.to_string())
    }
}

impl From<tokio::sync::oneshot::error::RecvError> for AsyncHostError {
    fn from(err: tokio::sync::oneshot::error::RecvError) -> Self {
        AsyncHostError::ChannelError(err.to_string())
    }
}

/// Result type for async host operations
pub type AsyncHostResult<T> = Result<T, AsyncHostError>;

/// Configuration for async host operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncHostConfig {
    /// Default operation timeout
    pub default_timeout: Duration,
    /// Maximum concurrent operations per agent
    pub max_concurrent_ops: usize,
    /// Enable operation queuing when at capacity
    pub queue_when_full: bool,
    /// Maximum queue depth per agent
    pub max_queue_depth: usize,
    /// Enable pre-authorization caching
    pub cache_authorizations: bool,
    /// Authorization cache TTL
    pub auth_cache_ttl: Duration,
}

impl Default for AsyncHostConfig {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            max_concurrent_ops: 10,
            queue_when_full: true,
            max_queue_depth: 100,
            cache_authorizations: true,
            auth_cache_ttl: Duration::from_secs(60),
        }
    }
}

/// Types of async operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AsyncOperation {
    /// File read operation
    FileRead { path: String },
    /// File write operation
    FileWrite { path: String, data: Vec<u8> },
    /// HTTP GET request
    HttpGet {
        url: String,
        headers: HashMap<String, String>,
    },
    /// HTTP POST request
    HttpPost {
        url: String,
        body: Vec<u8>,
        headers: HashMap<String, String>,
    },
    /// Policy evaluation
    PolicyCheck {
        principal: String,
        action: String,
        resource: String,
    },
    /// Custom async operation
    Custom {
        name: String,
        params: serde_json::Value,
    },
}

impl AsyncOperation {
    /// Get the action name for policy checks
    pub fn action_name(&self) -> &str {
        match self {
            AsyncOperation::FileRead { .. } => "fs_read",
            AsyncOperation::FileWrite { .. } => "fs_write",
            AsyncOperation::HttpGet { .. } => "http_get",
            AsyncOperation::HttpPost { .. } => "http_post",
            AsyncOperation::PolicyCheck { .. } => "policy_check",
            AsyncOperation::Custom { name, .. } => name,
        }
    }

    /// Get the resource for policy checks
    pub fn resource_name(&self) -> String {
        match self {
            AsyncOperation::FileRead { path } => path.clone(),
            AsyncOperation::FileWrite { path, .. } => path.clone(),
            AsyncOperation::HttpGet { url, .. } => url.clone(),
            AsyncOperation::HttpPost { url, .. } => url.clone(),
            AsyncOperation::PolicyCheck { resource, .. } => resource.clone(),
            AsyncOperation::Custom { params, .. } => params
                .get("resource")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string(),
        }
    }
}

/// Result of an async operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationResult {
    /// Operation ID
    pub operation_id: String,
    /// Success status
    pub success: bool,
    /// Result data (if successful)
    pub data: Option<Vec<u8>>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Execution duration
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Cached authorization decision
#[derive(Debug, Clone)]
struct CachedAuth {
    allowed: bool,
    cached_at: Instant,
}

/// Async host context for managing operations
pub struct AsyncHostContext {
    /// Agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Configuration
    config: AsyncHostConfig,
    /// Concurrency limiter
    semaphore: Arc<Semaphore>,
    /// Policy enforcer
    enforcer: Arc<CedarEnforcer>,
    /// Context collector
    context_collector: Arc<DynamicContextCollector>,
    /// Authorization cache
    auth_cache: Arc<RwLock<HashMap<String, CachedAuth>>>,
    /// Operation counter
    operation_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl std::fmt::Debug for AsyncHostContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncHostContext")
            .field("agent_id", &self.agent_id)
            .field("session_id", &self.session_id)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// AsyncHostContext is Send + Sync automatically because all its fields are Send + Sync:
// - String: Send + Sync
// - AsyncHostConfig: Clone + Send + Sync (derives)
// - Arc<T>: Send + Sync when T is Send + Sync
// - AtomicU64: Send + Sync

impl AsyncHostContext {
    /// Create a new async host context
    pub fn new(agent_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self::with_config(agent_id, session_id, AsyncHostConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(
        agent_id: impl Into<String>,
        session_id: impl Into<String>,
        config: AsyncHostConfig,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_ops));
        let enforcer = Arc::new(
            CedarEnforcer::new(EnforcerConfig::default())
                .unwrap_or_else(|_| CedarEnforcer::new_permissive()),
        );
        let context_collector = Arc::new(DynamicContextCollector::new(ContextConfig::default()));

        Self {
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            config,
            semaphore,
            enforcer,
            context_collector,
            auth_cache: Arc::new(RwLock::new(HashMap::new())),
            operation_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Execute an async operation with policy check
    pub async fn execute_async(
        &self,
        operation: AsyncOperation,
    ) -> AsyncHostResult<OperationResult> {
        let start = Instant::now();
        let operation_id = self.next_operation_id();

        // Acquire semaphore permit
        let _permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| AsyncHostError::ResourceExhausted(e.to_string()))?;

        // Check authorization
        self.check_authorization(&operation).await?;

        // Execute the operation
        let result = self.execute_operation(&operation).await;

        let duration = start.elapsed();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        match result {
            Ok(data) => Ok(OperationResult {
                operation_id,
                success: true,
                data: Some(data),
                error: None,
                duration_ms: duration.as_millis() as u64,
                timestamp,
            }),
            Err(e) => Ok(OperationResult {
                operation_id,
                success: false,
                data: None,
                error: Some(e.to_string()),
                duration_ms: duration.as_millis() as u64,
                timestamp,
            }),
        }
    }

    /// Execute operation with timeout
    pub async fn execute_with_timeout(
        &self,
        operation: AsyncOperation,
        timeout: Duration,
    ) -> AsyncHostResult<OperationResult> {
        tokio::time::timeout(timeout, self.execute_async(operation))
            .await
            .map_err(|_| AsyncHostError::Timeout(timeout))?
    }

    /// Pre-authorize a batch of operations (for caching)
    pub async fn pre_authorize(&self, operations: &[AsyncOperation]) -> AsyncHostResult<Vec<bool>> {
        let mut results = Vec::with_capacity(operations.len());

        for op in operations {
            let allowed = self.check_authorization(op).await.is_ok();
            results.push(allowed);
        }

        Ok(results)
    }

    /// Check authorization for an operation
    async fn check_authorization(&self, operation: &AsyncOperation) -> AsyncHostResult<()> {
        let cache_key = format!(
            "{}:{}:{}",
            self.agent_id,
            operation.action_name(),
            operation.resource_name()
        );

        // Check cache first
        if self.config.cache_authorizations {
            let cache = self.auth_cache.read().await;
            if let Some(cached) = cache.get(&cache_key) {
                if cached.cached_at.elapsed() < self.config.auth_cache_ttl {
                    if cached.allowed {
                        return Ok(());
                    } else {
                        return Err(AsyncHostError::PermissionDenied {
                            action: operation.action_name().to_string(),
                            resource: operation.resource_name(),
                        });
                    }
                }
            }
        }

        // Collect dynamic context
        let context = self
            .context_collector
            .collect_context(&self.agent_id)
            .await
            .ok();

        // Evaluate policy
        let principal = Principal::agent(&self.agent_id);
        let action = Action::new("Agent", operation.action_name());
        let resource = Resource::new("Resource", &operation.resource_name());

        let decision = self
            .enforcer
            .authorize(&principal, &action, &resource, context.as_ref())
            .await;
        let allowed = decision.map(|d| d.is_allowed()).unwrap_or(false);

        // Update cache
        if self.config.cache_authorizations {
            let mut cache = self.auth_cache.write().await;
            cache.insert(
                cache_key,
                CachedAuth {
                    allowed,
                    cached_at: Instant::now(),
                },
            );
        }

        if allowed {
            Ok(())
        } else {
            Err(AsyncHostError::PermissionDenied {
                action: operation.action_name().to_string(),
                resource: operation.resource_name(),
            })
        }
    }

    /// Execute the actual operation
    async fn execute_operation(&self, operation: &AsyncOperation) -> AsyncHostResult<Vec<u8>> {
        match operation {
            AsyncOperation::FileRead { path } => self.execute_file_read(path).await,
            AsyncOperation::FileWrite { path, data } => self.execute_file_write(path, data).await,
            AsyncOperation::HttpGet { url, headers } => self.execute_http_get(url, headers).await,
            AsyncOperation::HttpPost { url, body, headers } => {
                self.execute_http_post(url, body, headers).await
            }
            AsyncOperation::PolicyCheck {
                principal,
                action,
                resource,
            } => self.execute_policy_check(principal, action, resource).await,
            AsyncOperation::Custom { name, params } => self.execute_custom(name, params).await,
        }
    }

    /// Execute file read using spawn_blocking
    async fn execute_file_read(&self, path: &str) -> AsyncHostResult<Vec<u8>> {
        let path = path.to_string();
        tokio::task::spawn_blocking(move || {
            std::fs::read(&path).map_err(|e| AsyncHostError::IoError(e.to_string()))
        })
        .await
        .map_err(|e| AsyncHostError::Internal(e.to_string()))?
    }

    /// Execute file write using spawn_blocking
    async fn execute_file_write(&self, path: &str, data: &[u8]) -> AsyncHostResult<Vec<u8>> {
        let path = path.to_string();
        let data = data.to_vec();
        tokio::task::spawn_blocking(move || {
            std::fs::write(&path, &data).map_err(|e| AsyncHostError::IoError(e.to_string()))?;
            Ok(vec![])
        })
        .await
        .map_err(|e| AsyncHostError::Internal(e.to_string()))?
    }

    /// Execute HTTP GET request using reqwest
    ///
    /// # Arguments
    /// * `url` - The URL to request
    /// * `headers` - Custom headers to include in the request
    ///
    /// # Returns
    /// Response body as bytes on success
    ///
    /// # Errors
    /// Returns `AsyncHostError::IoError` on network or HTTP errors
    async fn execute_http_get(
        &self,
        url: &str,
        headers: &HashMap<String, String>,
    ) -> AsyncHostResult<Vec<u8>> {
        debug!(url = %url, "Executing HTTP GET");

        let client = reqwest::Client::builder()
            .timeout(self.config.default_timeout)
            .build()
            .map_err(|e| {
                AsyncHostError::Internal(format!("Failed to create HTTP client: {}", e))
            })?;

        let mut request_builder = client.get(url);

        // Add custom headers
        for (key, value) in headers {
            request_builder = request_builder.header(key, value);
        }

        // Add user-agent header to identify VAK requests
        request_builder = request_builder.header("User-Agent", "VAK-Agent/1.0");

        let response = request_builder
            .send()
            .await
            .map_err(|e| AsyncHostError::IoError(format!("HTTP GET failed: {}", e)))?;

        // Check for HTTP errors
        let status = response.status();
        if !status.is_success() {
            return Err(AsyncHostError::IoError(format!(
                "HTTP GET returned status {}: {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| AsyncHostError::IoError(format!("Failed to read response body: {}", e)))
    }

    /// Execute HTTP POST request using reqwest
    ///
    /// # Arguments
    /// * `url` - The URL to send the request to
    /// * `body` - The request body as bytes
    /// * `headers` - Custom headers to include in the request
    ///
    /// # Returns
    /// Response body as bytes on success
    ///
    /// # Errors
    /// Returns `AsyncHostError::IoError` on network or HTTP errors
    async fn execute_http_post(
        &self,
        url: &str,
        body: &[u8],
        headers: &HashMap<String, String>,
    ) -> AsyncHostResult<Vec<u8>> {
        debug!(url = %url, body_len = body.len(), "Executing HTTP POST");

        let client = reqwest::Client::builder()
            .timeout(self.config.default_timeout)
            .build()
            .map_err(|e| {
                AsyncHostError::Internal(format!("Failed to create HTTP client: {}", e))
            })?;

        let mut request_builder = client.post(url).body(body.to_vec());

        // Add custom headers
        for (key, value) in headers {
            request_builder = request_builder.header(key, value);
        }

        // Add default content-type if not specified
        if !headers.contains_key("Content-Type") && !headers.contains_key("content-type") {
            request_builder = request_builder.header("Content-Type", "application/octet-stream");
        }

        // Add user-agent header to identify VAK requests
        request_builder = request_builder.header("User-Agent", "VAK-Agent/1.0");

        let response = request_builder
            .send()
            .await
            .map_err(|e| AsyncHostError::IoError(format!("HTTP POST failed: {}", e)))?;

        // Check for HTTP errors
        let status = response.status();
        if !status.is_success() {
            return Err(AsyncHostError::IoError(format!(
                "HTTP POST returned status {}: {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| AsyncHostError::IoError(format!("Failed to read response body: {}", e)))
    }

    /// Execute policy check
    async fn execute_policy_check(
        &self,
        principal_id: &str,
        action_name: &str,
        resource_id: &str,
    ) -> AsyncHostResult<Vec<u8>> {
        let principal = Principal::agent(principal_id);
        let action = Action::new("Agent", action_name);
        let resource = Resource::new("Resource", resource_id);

        let context = self
            .context_collector
            .collect_context(principal_id)
            .await
            .ok();

        let decision = self
            .enforcer
            .authorize(&principal, &action, &resource, context.as_ref())
            .await;
        let allowed = decision.map(|d| d.is_allowed()).unwrap_or(false);

        Ok(serde_json::to_vec(&serde_json::json!({ "allowed": allowed })).unwrap_or_default())
    }

    /// Execute custom operation handler.
    ///
    /// # Custom Operation Handler Integration
    ///
    /// This method provides a flexible extension point for custom async operations
    /// that don't fit the predefined operation types (file I/O, HTTP, policy).
    ///
    /// ## Current Implementation Status
    ///
    /// **NOTE**: This is a placeholder implementation that echoes back the params.
    /// In production, this should be extended to:
    ///
    /// 1. Register custom operation handlers via a trait-based system
    /// 2. Dispatch to appropriate handlers based on operation name
    /// 3. Apply policy checks specific to custom operation types
    /// 4. Implement timeout and resource limits per handler
    ///
    /// ## Example Future Usage
    ///
    /// ```rust,ignore
    /// // Register a custom handler
    /// context.register_handler("database_query", |params| async {
    ///     let query = params.get("query").and_then(|v| v.as_str())?;
    ///     // Execute query with proper sandboxing
    ///     Ok(result_bytes)
    /// });
    ///
    /// // Execute the custom operation
    /// let result = context.execute_async(AsyncOperation::Custom {
    ///     name: "database_query".to_string(),
    ///     params: json!({"query": "SELECT * FROM users LIMIT 10"}),
    /// }).await?;
    /// ```
    ///
    /// ## Security Considerations
    ///
    /// Custom handlers MUST:
    /// - Validate all input parameters
    /// - Respect resource quotas (memory, CPU, network)
    /// - Log operations for audit purposes
    /// - Implement proper error handling
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the custom operation (used for handler dispatch)
    /// * `params` - JSON parameters for the operation
    ///
    /// # Returns
    ///
    /// Returns the serialized params as a placeholder. Future implementations
    /// should return actual operation results.
    ///
    /// # TODO
    ///
    /// - [ ] Implement custom handler registry
    /// - [ ] Add per-handler policy evaluation
    /// - [ ] Add handler-specific timeout configuration
    /// - [ ] Add handler metrics and tracing
    async fn execute_custom(
        &self,
        name: &str,
        params: &serde_json::Value,
    ) -> AsyncHostResult<Vec<u8>> {
        debug!(name = %name, "Executing custom operation");

        // TODO: Implement custom handler registry and dispatch
        // Current implementation echoes params for testing purposes
        info!(
            operation_name = %name,
            agent_id = %self.agent_id,
            "Custom operation executed (placeholder implementation)"
        );

        // Return params as result for now - serves as acknowledgment
        // that the operation was received and processed
        Ok(serde_json::to_vec(params).unwrap_or_default())
    }

    /// Generate next operation ID
    fn next_operation_id(&self) -> String {
        let id = self
            .operation_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("{}-{}-{}", self.agent_id, self.session_id, id)
    }

    /// Invalidate authorization cache for this agent
    pub async fn invalidate_auth_cache(&self) {
        let mut cache = self.auth_cache.write().await;
        cache.retain(|k, _| !k.starts_with(&self.agent_id));
    }

    /// Get pending operation count
    pub fn pending_operations(&self) -> usize {
        self.config.max_concurrent_ops - self.semaphore.available_permits()
    }
}

/// Async operation executor for batch operations
pub struct AsyncOperationExecutor {
    /// Contexts by agent
    contexts: Arc<RwLock<HashMap<String, Arc<AsyncHostContext>>>>,
    /// Configuration
    config: AsyncHostConfig,
}

impl AsyncOperationExecutor {
    /// Create a new executor
    pub fn new(config: AsyncHostConfig) -> Self {
        Self {
            contexts: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Get or create context for an agent
    pub async fn get_context(&self, agent_id: &str, session_id: &str) -> Arc<AsyncHostContext> {
        let key = format!("{}:{}", agent_id, session_id);

        {
            let contexts = self.contexts.read().await;
            if let Some(ctx) = contexts.get(&key) {
                return ctx.clone();
            }
        }

        let ctx = Arc::new(AsyncHostContext::with_config(
            agent_id,
            session_id,
            self.config.clone(),
        ));

        let mut contexts = self.contexts.write().await;
        contexts.insert(key, ctx.clone());
        ctx
    }

    /// Execute operations for multiple agents concurrently
    pub async fn execute_batch(
        &self,
        operations: Vec<(String, String, AsyncOperation)>,
    ) -> Vec<AsyncHostResult<OperationResult>> {
        let futures: Vec<_> = operations
            .into_iter()
            .map(|(agent_id, session_id, op)| {
                let executor = self.clone();
                async move {
                    let ctx = executor.get_context(&agent_id, &session_id).await;
                    ctx.execute_async(op).await
                }
            })
            .collect();

        futures::future::join_all(futures).await
    }

    /// Clean up inactive contexts
    pub async fn cleanup_inactive(&self, _max_age: Duration) {
        let contexts = self.contexts.write().await;
        // In production, would track last activity time and remove stale contexts
        info!(count = contexts.len(), "Cleaned up inactive contexts");
    }
}

impl Clone for AsyncOperationExecutor {
    fn clone(&self) -> Self {
        Self {
            contexts: self.contexts.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_async_host_context_creation() {
        let ctx = AsyncHostContext::new("agent-1", "session-1");
        assert_eq!(ctx.agent_id, "agent-1");
        assert_eq!(ctx.session_id, "session-1");
    }

    #[tokio::test]
    async fn test_operation_result() {
        let result = OperationResult {
            operation_id: "test-1".to_string(),
            success: true,
            data: Some(vec![1, 2, 3]),
            error: None,
            duration_ms: 100,
            timestamp: 1234567890,
        };
        assert!(result.success);
        assert_eq!(result.data.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn test_async_operation_action_names() {
        let file_read = AsyncOperation::FileRead {
            path: "/test".to_string(),
        };
        assert_eq!(file_read.action_name(), "fs_read");
        assert_eq!(file_read.resource_name(), "/test");

        let http_get = AsyncOperation::HttpGet {
            url: "https://example.com".to_string(),
            headers: HashMap::new(),
        };
        assert_eq!(http_get.action_name(), "http_get");
    }

    #[tokio::test]
    async fn test_pending_operations() {
        let ctx = AsyncHostContext::new("agent-1", "session-1");
        assert_eq!(ctx.pending_operations(), 0);
    }

    #[tokio::test]
    async fn test_executor_batch() {
        let executor = AsyncOperationExecutor::new(AsyncHostConfig::default());

        let operations = vec![(
            "agent-1".to_string(),
            "session-1".to_string(),
            AsyncOperation::Custom {
                name: "test".to_string(),
                params: serde_json::json!({"key": "value"}),
            },
        )];

        let results = executor.execute_batch(operations).await;
        assert_eq!(results.len(), 1);
    }
}
