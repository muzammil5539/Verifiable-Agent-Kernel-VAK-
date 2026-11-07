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
//! # What the policy sees is what runs
//!
//! The enforcer matches resources by prefix and suffix (`/data/*`), so an
//! operation is canonicalised before it is checked, and the canonical form
//! is what executes. A path must be absolute with no `..`; `.` and repeated
//! separators are removed. A URL must be http or https with a host and no
//! user info, and is normalised by parsing. HTTP redirects aren't followed,
//! and a request can't set `Host`. Responses are capped at
//! `max_response_bytes`. Symlinks are not resolved: a policy over a path
//! with a symlink in it governs where the link points.
//!
//! A context denies everything until it has an enforcer with policies
//! ([`AsyncHostContext::with_enforcer`]).
//!
//! # References
//!
//! - Gap Analysis Section 4, Phase 1.3: Async Host Interface (HFI)
//! - Gap Analysis Section 2.1.1: Async Stack Switching

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info};

use crate::policy::context::{ContextConfig, DynamicContextCollector};
use crate::policy::enforcer::{
    Action, CedarEnforcer, EnforcerConfig, EnforcerResult, Principal, Resource,
};

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
    PermissionDenied {
        /// The action that was denied
        action: String,
        /// The resource the action was attempted on
        resource: String,
    },

    /// Resource exhausted
    #[error("Resource exhausted: {0}")]
    ResourceExhausted(String),

    /// Channel error
    #[error("Channel error: {0}")]
    ChannelError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// An operation refused before its policy check: a path or URL a
    /// prefix rule could be fooled by, or a header it may not set
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
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
    /// Default operation timeout, for every operation: a custom handler's
    /// own timeout replaces it. It used to apply only to HTTP.
    pub default_timeout: Duration,
    /// Maximum concurrent operations per agent
    pub max_concurrent_ops: usize,
    /// Wait for a slot when at capacity; without it, an operation at
    /// capacity fails at once. It used to be ignored.
    pub queue_when_full: bool,
    /// Maximum operations waiting for a slot per agent; one more fails. It
    /// used to be ignored.
    pub max_queue_depth: usize,
    /// Enable pre-authorization caching
    pub cache_authorizations: bool,
    /// Authorization cache TTL
    pub auth_cache_ttl: Duration,
    /// The largest HTTP response body read, in bytes.
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
}

fn default_max_response_bytes() -> usize {
    10 * 1024 * 1024
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
            max_response_bytes: default_max_response_bytes(),
        }
    }
}

/// Custom operation handler trait
#[async_trait]
pub trait CustomHandler: Send + Sync {
    /// Handle the custom operation
    async fn handle(&self, params: serde_json::Value) -> AsyncHostResult<Vec<u8>>;
}

/// Registration for a custom handler
#[derive(Clone)]
pub struct HandlerRegistration {
    /// The handler implementation
    pub handler: Arc<dyn CustomHandler>,
    /// Optional execution timeout override
    pub timeout: Option<Duration>,
}

/// Types of async operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AsyncOperation {
    /// File read operation
    FileRead {
        /// Path to the file to read
        path: String,
    },
    /// File write operation
    FileWrite {
        /// Path to the file to write
        path: String,
        /// Data to write to the file
        data: Vec<u8>,
    },
    /// HTTP GET request
    HttpGet {
        /// Target URL for the GET request
        url: String,
        /// HTTP headers to include in the request
        headers: HashMap<String, String>,
    },
    /// HTTP POST request
    HttpPost {
        /// Target URL for the POST request
        url: String,
        /// Request body bytes
        body: Vec<u8>,
        /// HTTP headers to include in the request
        headers: HashMap<String, String>,
    },
    /// Policy evaluation
    PolicyCheck {
        /// Principal requesting the action
        principal: String,
        /// Action to be evaluated
        action: String,
        /// Resource the action targets
        resource: String,
    },
    /// Custom async operation
    Custom {
        /// Name identifying the custom operation
        name: String,
        /// Parameters for the custom operation
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

/// `path` as an absolute path with no `.` component or repeated separator.
/// A `..` component is refused rather than resolved: resolving it
/// lexically can disagree with the filesystem when a symlink precedes it.
fn canonical_path(path: &str) -> AsyncHostResult<String> {
    let refuse = |why: &str| AsyncHostError::InvalidRequest(format!("path {path:?} {why}"));
    let mut canonical = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::ParentDir => return Err(refuse("has a '..' component")),
            Component::CurDir => {}
            other => canonical.push(other.as_os_str()),
        }
    }
    if !canonical.is_absolute() {
        return Err(refuse("isn't absolute"));
    }
    canonical
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| refuse("isn't UTF-8"))
}

/// `url` parsed and re-serialised, which normalises its case, encoding,
/// default port and dot segments: http or https, with a host and no user
/// info. `https://allowed.example@evil.example/` used to pass a rule for
/// `https://allowed.example*`. The fragment, which is never sent, is
/// dropped.
fn canonical_url(url: &str) -> AsyncHostResult<String> {
    let refuse = |why: String| AsyncHostError::InvalidRequest(format!("URL {url:?} {why}"));
    let mut parsed = reqwest::Url::parse(url).map_err(|e| refuse(format!("doesn't parse: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(refuse(format!(
            "has scheme {:?}; only http and https",
            parsed.scheme()
        )));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(refuse("has no host".into()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(refuse("has user info".into()));
    }
    parsed.set_fragment(None);
    Ok(parsed.into())
}

/// Refuses a `Host` header: it would send the request to another virtual
/// host than the URL the policy approved.
fn check_headers(headers: &HashMap<String, String>) -> AsyncHostResult<()> {
    if headers
        .keys()
        .any(|name| name.trim().eq_ignore_ascii_case("host"))
    {
        return Err(AsyncHostError::InvalidRequest(
            "an operation can't set the Host header".into(),
        ));
    }
    Ok(())
}

impl AsyncOperation {
    /// The operation with its path or URL canonical, as it is checked and
    /// executed. See the module documentation.
    ///
    /// # Errors
    ///
    /// [`AsyncHostError::InvalidRequest`] for a path, URL or header that
    /// would let a policy check approve something other than what runs.
    pub fn canonical(self) -> AsyncHostResult<Self> {
        Ok(match self {
            AsyncOperation::FileRead { path } => AsyncOperation::FileRead {
                path: canonical_path(&path)?,
            },
            AsyncOperation::FileWrite { path, data } => AsyncOperation::FileWrite {
                path: canonical_path(&path)?,
                data,
            },
            AsyncOperation::HttpGet { url, headers } => {
                check_headers(&headers)?;
                AsyncOperation::HttpGet {
                    url: canonical_url(&url)?,
                    headers,
                }
            }
            AsyncOperation::HttpPost { url, body, headers } => {
                check_headers(&headers)?;
                AsyncOperation::HttpPost {
                    url: canonical_url(&url)?,
                    body,
                    headers,
                }
            }
            other => other,
        })
    }
}

/// Reads a response body, refusing one longer than `limit`.
async fn read_capped(mut response: reqwest::Response, limit: usize) -> AsyncHostResult<Vec<u8>> {
    let too_large = || {
        AsyncHostError::ResourceExhausted(format!(
            "the response is larger than the {limit}-byte limit"
        ))
    };
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| AsyncHostError::IoError(format!("Failed to read response body: {}", e)))?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Counts an operation as waiting for a slot until dropped.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
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
    /// Authorization cache, by (action, resource). The key used to be the
    /// two joined by `:`, so `("fs_read", "a:b")` and `("fs_read:a", "b")`
    /// shared one.
    auth_cache: Arc<RwLock<HashMap<(String, String), CachedAuth>>>,
    /// Operation counter
    operation_counter: Arc<std::sync::atomic::AtomicU64>,
    /// Custom operation handlers
    custom_handlers: Arc<RwLock<HashMap<String, HandlerRegistration>>>,
    /// Operations waiting for a slot
    waiting: AtomicUsize,
    /// When an operation last started
    last_active: std::sync::Mutex<Instant>,
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

/// The enforcer a host context starts with.
///
/// If it can't be built, the context gets one that denies everything. This
/// used to fall back to `CedarEnforcer::new_permissive()`, so a construction
/// failure granted every host operation for the skill's whole lifetime.
fn enforcer_or_deny(built: EnforcerResult<CedarEnforcer>) -> CedarEnforcer {
    built.unwrap_or_else(|e| {
        tracing::error!(
            error = %e,
            "Failed to construct async host policy enforcer - denying all operations"
        );
        CedarEnforcer::new_denying()
    })
}

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
        let enforcer = Arc::new(enforcer_or_deny(CedarEnforcer::new(
            EnforcerConfig::default(),
        )));
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
            custom_handlers: Arc::new(RwLock::new(HashMap::new())),
            waiting: AtomicUsize::new(0),
            last_active: std::sync::Mutex::new(Instant::now()),
        }
    }

    /// Uses `enforcer` for every authorization. A context starts with one
    /// that denies everything, and there was no way to give it another.
    pub fn with_enforcer(mut self, enforcer: Arc<CedarEnforcer>) -> Self {
        self.enforcer = enforcer;
        self.auth_cache = Arc::new(RwLock::new(HashMap::new()));
        self
    }

    /// How long since an operation last started (or the context was made).
    pub fn idle_for(&self) -> Duration {
        self.last_active
            .lock()
            .map(|at| at.elapsed())
            .unwrap_or_default()
    }

    /// A slot to run in: at once if one is free; otherwise, with
    /// `queue_when_full`, after waiting behind at most `max_queue_depth`
    /// others.
    async fn slot(&self) -> AsyncHostResult<tokio::sync::OwnedSemaphorePermit> {
        if let Ok(permit) = self.semaphore.clone().try_acquire_owned() {
            return Ok(permit);
        }
        if !self.config.queue_when_full {
            return Err(AsyncHostError::ResourceExhausted(format!(
                "{} operations are running, the most allowed, and queue_when_full is off",
                self.config.max_concurrent_ops
            )));
        }
        let ahead = self.waiting.fetch_add(1, Ordering::SeqCst);
        let _waiting = Waiting(&self.waiting);
        if ahead >= self.config.max_queue_depth {
            return Err(AsyncHostError::ResourceExhausted(format!(
                "{ahead} operations are already waiting, the most allowed"
            )));
        }
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| AsyncHostError::ResourceExhausted(e.to_string()))
    }

    /// Register a custom operation handler
    pub async fn register_handler(&self, name: impl Into<String>, handler: Arc<dyn CustomHandler>) {
        self.register_handler_with_timeout(name, handler, None)
            .await;
    }

    /// Register a custom operation handler with configuration
    pub async fn register_handler_with_timeout(
        &self,
        name: impl Into<String>,
        handler: Arc<dyn CustomHandler>,
        timeout: Option<Duration>,
    ) {
        let mut handlers = self.custom_handlers.write().await;
        handlers.insert(name.into(), HandlerRegistration { handler, timeout });
    }

    /// Execute an async operation with policy check
    pub async fn execute_async(
        &self,
        operation: AsyncOperation,
    ) -> AsyncHostResult<OperationResult> {
        let start = Instant::now();
        let operation_id = self.next_operation_id();
        if let Ok(mut at) = self.last_active.lock() {
            *at = start;
        }
        let operation = operation.canonical()?;

        // Acquire a slot
        let _permit = self.slot().await?;

        // Check authorization
        self.check_authorization(&operation).await?;

        // Execute the operation, within the default timeout; a custom
        // handler applies its own.
        let result = match &operation {
            AsyncOperation::Custom { .. } => self.execute_operation(&operation).await,
            _ => tokio::time::timeout(
                self.config.default_timeout,
                self.execute_operation(&operation),
            )
            .await
            .unwrap_or(Err(AsyncHostError::Timeout(self.config.default_timeout))),
        };

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
            let allowed = match op.clone().canonical() {
                Ok(op) => self.check_authorization(&op).await.is_ok(),
                Err(_) => false,
            };
            results.push(allowed);
        }

        Ok(results)
    }

    /// Check authorization for an operation
    async fn check_authorization(&self, operation: &AsyncOperation) -> AsyncHostResult<()> {
        let cache_key = (
            operation.action_name().to_string(),
            operation.resource_name(),
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
        let resource = Resource::new("Resource", operation.resource_name());

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

        // No redirects: the policy approved this URL, not wherever a
        // redirect leads. They used to be followed.
        let client = reqwest::Client::builder()
            .timeout(self.config.default_timeout)
            .redirect(reqwest::redirect::Policy::none())
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

        read_capped(response, self.config.max_response_bytes).await
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

        // No redirects: the policy approved this URL, not wherever a
        // redirect leads. They used to be followed.
        let client = reqwest::Client::builder()
            .timeout(self.config.default_timeout)
            .redirect(reqwest::redirect::Policy::none())
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

        read_capped(response, self.config.max_response_bytes).await
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
    /// This implementation dispatches to registered handlers.
    ///
    /// 1. Register custom operation handlers via `register_handler`
    /// 2. Dispatch to appropriate handlers based on operation name
    /// 3. Apply policy checks specific to custom operation types (via `execute_async`)
    /// 4. Enforces handler-specific timeout if configured
    ///
    /// ## Example Usage
    ///
    /// ```rust,ignore
    /// // Define a handler
    /// struct MyHandler;
    /// #[async_trait]
    /// impl CustomHandler for MyHandler {
    ///     async fn handle(&self, params: serde_json::Value) -> AsyncHostResult<Vec<u8>> {
    ///         Ok(vec![])
    ///     }
    /// }
    ///
    /// // Register
    /// context.register_handler("my_op", Arc::new(MyHandler)).await;
    /// ```
    ///
    /// ## Security Considerations
    ///
    /// Custom handlers MUST:
    /// - Validate all input parameters
    /// - Respect resource quotas (memory, CPU, network)
    /// - Log operations for audit purposes
    /// - Implement proper error handling
    async fn execute_custom(
        &self,
        name: &str,
        params: &serde_json::Value,
    ) -> AsyncHostResult<Vec<u8>> {
        debug!(name = %name, "Executing custom operation");

        let registration = {
            let handlers = self.custom_handlers.read().await;
            handlers.get(name).cloned()
        };

        if let Some(reg) = registration {
            let fut = reg.handler.handle(params.clone());
            let timeout = reg.timeout.unwrap_or(self.config.default_timeout);
            tokio::time::timeout(timeout, fut)
                .await
                .map_err(|_| AsyncHostError::Timeout(timeout))?
        } else {
            tracing::warn!(name = %name, "Custom handler not found");
            Err(AsyncHostError::Internal(format!(
                "Custom handler '{}' not found",
                name
            )))
        }
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
        self.auth_cache.write().await.clear();
    }

    /// Get pending operation count
    pub fn pending_operations(&self) -> usize {
        self.config
            .max_concurrent_ops
            .saturating_sub(self.semaphore.available_permits())
    }
}

/// Contexts by (agent, session).
type ContextMap = HashMap<(String, String), Arc<AsyncHostContext>>;

/// Async operation executor for batch operations
pub struct AsyncOperationExecutor {
    /// Contexts by (agent, session). The key used to be the two joined by
    /// `:`, so agent `a:b` in session `c` and agent `a` in session `b:c`
    /// shared a context, and one ran as the other.
    contexts: Arc<RwLock<ContextMap>>,
    /// Configuration
    config: AsyncHostConfig,
    /// The enforcer every context uses, if one was given
    enforcer: Option<Arc<CedarEnforcer>>,
}

impl AsyncOperationExecutor {
    /// Create a new executor
    pub fn new(config: AsyncHostConfig) -> Self {
        Self {
            contexts: Arc::new(RwLock::new(HashMap::new())),
            config,
            enforcer: None,
        }
    }

    /// Gives every context this executor creates `enforcer`
    /// ([`AsyncHostContext::with_enforcer`]).
    pub fn with_enforcer(mut self, enforcer: Arc<CedarEnforcer>) -> Self {
        self.enforcer = Some(enforcer);
        self
    }

    /// Get or create context for an agent
    pub async fn get_context(&self, agent_id: &str, session_id: &str) -> Arc<AsyncHostContext> {
        let key = (agent_id.to_string(), session_id.to_string());

        {
            let contexts = self.contexts.read().await;
            if let Some(ctx) = contexts.get(&key) {
                return ctx.clone();
            }
        }

        let mut ctx = AsyncHostContext::with_config(agent_id, session_id, self.config.clone());
        if let Some(enforcer) = &self.enforcer {
            ctx = ctx.with_enforcer(enforcer.clone());
        }
        let ctx = Arc::new(ctx);

        let mut contexts = self.contexts.write().await;
        contexts.entry(key).or_insert(ctx).clone()
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

    /// Removes contexts idle for longer than `max_age` that no one else
    /// holds and that have nothing running, and returns how many. It used
    /// to remove nothing, only log that it had.
    pub async fn cleanup_inactive(&self, max_age: Duration) -> usize {
        let mut contexts = self.contexts.write().await;
        let before = contexts.len();
        contexts.retain(|_, ctx| {
            Arc::strong_count(ctx) > 1 || ctx.pending_operations() > 0 || ctx.idle_for() <= max_age
        });
        let removed = before - contexts.len();
        info!(
            removed,
            kept = contexts.len(),
            "Cleaned up inactive contexts"
        );
        removed
    }

    /// How many contexts the executor holds.
    pub async fn context_count(&self) -> usize {
        self.contexts.read().await.len()
    }
}

impl Clone for AsyncOperationExecutor {
    fn clone(&self) -> Self {
        Self {
            contexts: self.contexts.clone(),
            config: self.config.clone(),
            enforcer: self.enforcer.clone(),
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
    async fn test_enforcer_construction_failure_denies() {
        // Regression: a failed construction used to fall back to an enforcer
        // that allowed every host operation.
        let failed = Err(crate::policy::enforcer::EnforcerError::InvalidPolicy(
            "broken".to_string(),
        ));
        let enforcer = enforcer_or_deny(failed);
        let decision = enforcer
            .authorize(
                &Principal::agent("agent-1"),
                &Action::file_read(),
                &Resource::file("/etc/passwd"),
                None,
            )
            .await;
        assert!(
            !matches!(decision, Ok(ref d) if d.is_allowed()),
            "a host context without a working enforcer must deny, got {decision:?}"
        );

        // The same enforcer behind a context denies a real operation.
        let mut ctx = AsyncHostContext::new("agent-1", "session-1");
        ctx.enforcer = Arc::new(enforcer);
        ctx.register_handler("test_op", Arc::new(TestHandler)).await;
        let result = ctx
            .execute_async(AsyncOperation::Custom {
                name: "test_op".to_string(),
                params: serde_json::json!({"key": "success"}),
            })
            .await;
        assert!(
            !matches!(result, Ok(ref r) if r.success),
            "operation must not run, got {result:?}"
        );
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

    struct TestHandler;

    #[async_trait]
    impl CustomHandler for TestHandler {
        async fn handle(&self, params: serde_json::Value) -> AsyncHostResult<Vec<u8>> {
            let key = params.get("key").and_then(|v| v.as_str()).unwrap_or("");
            if key == "error" {
                return Err(AsyncHostError::Internal("Custom error".to_string()));
            }
            Ok(key.as_bytes().to_vec())
        }
    }

    #[tokio::test]
    async fn test_custom_handler_registration_and_execution() {
        let mut ctx = AsyncHostContext::new("agent-1", "session-1");
        // Override enforcer to be permissive for this test
        ctx.enforcer = Arc::new(CedarEnforcer::new_permissive());

        ctx.register_handler("test_op", Arc::new(TestHandler)).await;

        // Success case
        let op = AsyncOperation::Custom {
            name: "test_op".to_string(),
            params: serde_json::json!({"key": "success"}),
        };

        let result = ctx.execute_async(op).await.unwrap();
        assert!(result.success);
        assert_eq!(result.data.unwrap(), b"success");

        // Error case from handler
        let op_error = AsyncOperation::Custom {
            name: "test_op".to_string(),
            params: serde_json::json!({"key": "error"}),
        };

        let result_error = ctx.execute_async(op_error).await.unwrap();
        assert!(!result_error.success);
        assert_eq!(result_error.error.unwrap(), "Internal error: Custom error");

        // Handler not found case
        let op_missing = AsyncOperation::Custom {
            name: "missing_op".to_string(),
            params: serde_json::json!({}),
        };

        let result_missing = ctx.execute_async(op_missing).await.unwrap();
        assert!(!result_missing.success);
        assert!(result_missing.error.unwrap().contains("not found"));
    }

    struct TimeoutHandler;
    #[async_trait]
    impl CustomHandler for TimeoutHandler {
        async fn handle(&self, _params: serde_json::Value) -> AsyncHostResult<Vec<u8>> {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_custom_handler_timeout() {
        let mut ctx = AsyncHostContext::new("agent-1", "session-1");
        // Override enforcer to be permissive for this test
        ctx.enforcer = Arc::new(CedarEnforcer::new_permissive());

        // Register with very short timeout
        ctx.register_handler_with_timeout(
            "timeout_op",
            Arc::new(TimeoutHandler),
            Some(Duration::from_millis(10)),
        )
        .await;

        let op = AsyncOperation::Custom {
            name: "timeout_op".to_string(),
            params: serde_json::json!({}),
        };

        let result = ctx.execute_async(op).await.unwrap();
        assert!(!result.success);
        // AsyncHostError::Timeout formats as "Operation timed out after ..."
        assert!(result.error.unwrap().contains("timed out"));
    }

    use crate::policy::enforcer::{forbid_rule, permit_rule, CedarRule, PolicySet};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// An enforcer with `rules` loaded, for agent-1's `action` on resources.
    async fn enforcer(rules: Vec<CedarRule>) -> Arc<CedarEnforcer> {
        let enforcer = CedarEnforcer::new(EnforcerConfig::default()).unwrap();
        let mut set = PolicySet::new();
        for rule in rules {
            set.add_rule(rule);
        }
        enforcer
            .load_policies_from_str(&serde_yaml::to_string(&set).unwrap())
            .await
            .unwrap();
        Arc::new(enforcer)
    }

    fn permit(action: &str, resource: &str) -> CedarRule {
        permit_rule(
            format!("permit-{action}-{resource}"),
            "Agent::\"agent-1\"",
            format!("Action::\"Agent::{action}\""),
            format!("Resource::\"{resource}"),
        )
    }

    fn forbid(action: &str, resource: &str) -> CedarRule {
        forbid_rule(
            format!("forbid-{action}-{resource}"),
            "*",
            format!("Action::\"Agent::{action}\""),
            format!("Resource::\"{resource}"),
        )
    }

    async fn context(rules: Vec<CedarRule>) -> AsyncHostContext {
        AsyncHostContext::new("agent-1", "session-1").with_enforcer(enforcer(rules).await)
    }

    fn read(path: impl Into<String>) -> AsyncOperation {
        AsyncOperation::FileRead { path: path.into() }
    }

    fn get(url: impl Into<String>) -> AsyncOperation {
        AsyncOperation::HttpGet {
            url: url.into(),
            headers: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_a_path_is_checked_as_it_is_read() {
        // The enforcer matches by prefix, and the path was checked as
        // given: `/data/../secret` passed a rule for `/data/*`.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap().to_string();
        std::fs::create_dir(dir.path().join("data")).unwrap();
        std::fs::write(dir.path().join("data/ok.txt"), "ok").unwrap();
        std::fs::write(dir.path().join("data/private.txt"), "private").unwrap();
        std::fs::write(dir.path().join("secret.txt"), "secret").unwrap();
        let ctx = context(vec![
            permit("fs_read", &format!("{root}/data/*")),
            permit("fs_write", &format!("{root}/data/*")),
            forbid("fs_read", &format!("{root}/data/private*")),
        ])
        .await;

        let ok = ctx
            .execute_async(read(format!("{root}/data/ok.txt")))
            .await
            .unwrap();
        assert_eq!(ok.data.as_deref(), Some(&b"ok"[..]));
        let dotted = ctx
            .execute_async(read(format!("{root}/data/./ok.txt")))
            .await
            .unwrap();
        assert_eq!(dotted.data.as_deref(), Some(&b"ok"[..]));

        for path in [
            format!("{root}/data/../secret.txt"),
            "data/ok.txt".to_string(),
            "relative".to_string(),
        ] {
            let err = ctx.execute_async(read(path.clone())).await.unwrap_err();
            assert!(
                matches!(err, AsyncHostError::InvalidRequest(_)),
                "{path}: {err}"
            );
        }
        // A forbid rule can't be stepped around with `.` or `//` either.
        for path in [
            format!("{root}/data/./private.txt"),
            format!("{root}//data//private.txt"),
        ] {
            let err = ctx.execute_async(read(path.clone())).await.unwrap_err();
            assert!(
                matches!(err, AsyncHostError::PermissionDenied { .. }),
                "{path}: {err}"
            );
        }

        let write = |path: String| AsyncOperation::FileWrite {
            path,
            data: b"new".to_vec(),
        };
        assert!(
            ctx.execute_async(write(format!("{root}/data/new.txt")))
                .await
                .unwrap()
                .success
        );
        assert_eq!(
            std::fs::read(dir.path().join("data/new.txt")).unwrap(),
            b"new"
        );
        assert!(ctx
            .execute_async(write(format!("{root}/data/../escape.txt")))
            .await
            .is_err());
        assert!(!dir.path().join("escape.txt").exists());

        // Permitted but missing: it ran, and failed.
        let missing = ctx
            .execute_async(read(format!("{root}/data/none")))
            .await
            .unwrap();
        assert!(!missing.success && missing.error.unwrap().contains("I/O error"));
        let batch = ctx
            .pre_authorize(&[
                read(format!("{root}/data/ok.txt")),
                read(format!("{root}/data/../secret.txt")),
                read(format!("{root}/secret.txt")),
            ])
            .await
            .unwrap();
        assert_eq!(batch, [true, false, false]);
    }

    /// One canned response.
    #[derive(Clone)]
    struct Reply {
        status: u16,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
        no_length: bool,
    }

    fn reply(status: u16, body: &str) -> Reply {
        Reply {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            no_length: false,
        }
    }

    /// An HTTP server on localhost answering each path from `routes` (404
    /// otherwise), recording each request's head and body.
    async fn serve(
        routes: impl Fn(String) -> HashMap<&'static str, Reply> + Send + 'static,
    ) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let routes = Arc::new(routes(base.clone()));
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let (routes, log) = (routes.clone(), log.clone());
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 4096];
                    loop {
                        let n = socket.read(&mut chunk).await.unwrap_or(0);
                        request.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&request).to_string();
                        if let Some(end) = text.find("\r\n\r\n") {
                            let length = text
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                                })
                                .unwrap_or(0);
                            if request.len() >= end + 4 + length {
                                break;
                            }
                        }
                        if n == 0 {
                            break;
                        }
                    }
                    let text = String::from_utf8_lossy(&request).to_string();
                    let path = text.split_whitespace().nth(1).unwrap_or("").to_string();
                    log.lock().unwrap().push(text);
                    let reply = routes
                        .get(path.as_str())
                        .cloned()
                        .unwrap_or_else(|| reply(404, ""));
                    let mut head =
                        format!("HTTP/1.1 {} Stub\r\nConnection: close\r\n", reply.status);
                    if !reply.no_length {
                        head += &format!("Content-Length: {}\r\n", reply.body.len());
                    }
                    for (name, value) in &reply.headers {
                        head += &format!("{name}: {value}\r\n");
                    }
                    head += "\r\n";
                    let _ = socket.write_all(head.as_bytes()).await;
                    let _ = socket.write_all(&reply.body).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (base, seen)
    }

    #[tokio::test]
    async fn test_a_url_is_checked_as_it_is_fetched() {
        let (base, seen) = serve(|base| {
            HashMap::from([
                ("/ok", reply(200, "hello")),
                ("/secret", reply(200, "secret")),
                (
                    "/redirect",
                    Reply {
                        headers: vec![("Location", format!("{base}/secret"))],
                        ..reply(302, "")
                    },
                ),
                ("/big", reply(200, &"x".repeat(64))),
                (
                    "/big-stream",
                    Reply {
                        no_length: true,
                        ..reply(200, &"x".repeat(64))
                    },
                ),
                ("/fails", reply(500, "")),
            ])
        })
        .await;
        let config = AsyncHostConfig {
            max_response_bytes: 16,
            ..AsyncHostConfig::default()
        };
        let ctx = AsyncHostContext::with_config("agent-1", "session-1", config).with_enforcer(
            enforcer(vec![
                permit("http_get", &format!("{base}/ok*")),
                permit("http_get", &format!("{base}/redirect*")),
                permit("http_get", &format!("{base}/big*")),
                permit("http_get", &format!("{base}/fails*")),
                permit("http_get", "http://localhost*"),
                permit("http_post", &format!("{base}/ok*")),
            ])
            .await,
        );

        let ok = ctx.execute_async(get(format!("{base}/ok"))).await.unwrap();
        assert_eq!(ok.data.as_deref(), Some(&b"hello"[..]));

        // Checked as given, these reached /secret.
        let err = ctx
            .execute_async(get(format!("{base}/ok/../secret")))
            .await
            .unwrap_err();
        assert!(
            matches!(err, AsyncHostError::PermissionDenied { .. }),
            "{err}"
        );
        let authority = base.trim_start_matches("http://");
        let err = ctx
            .execute_async(get(format!("http://localhost@{authority}/secret")))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("user info"), "{err}");
        let redirected = ctx
            .execute_async(get(format!("{base}/redirect")))
            .await
            .unwrap();
        assert!(!redirected.success, "redirects aren't followed");
        assert!(redirected.error.unwrap().contains("302"));
        let requests = seen.lock().unwrap().clone();
        assert!(
            !requests.iter().any(|r| r.starts_with("GET /secret")),
            "nothing fetched /secret: {requests:?}"
        );

        // A request can't pick another virtual host, or another scheme.
        let err = ctx
            .execute_async(AsyncOperation::HttpGet {
                url: format!("{base}/ok"),
                headers: HashMap::from([("HOST".to_string(), "internal".to_string())]),
            })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Host header"), "{err}");
        for url in [
            "file:///etc/passwd",
            "ftp://example.com/x",
            "not a url",
            "http://",
            "mailto:a@example.com",
        ] {
            let err = ctx.execute_async(get(url)).await.unwrap_err();
            assert!(
                matches!(err, AsyncHostError::InvalidRequest(_)),
                "{url}: {err}"
            );
        }

        // Responses are capped, by Content-Length or while streaming.
        for path in ["/big", "/big-stream"] {
            let big = ctx
                .execute_async(get(format!("{base}{path}")))
                .await
                .unwrap();
            assert!(big.error.unwrap().contains("16-byte limit"), "{path}");
        }
        let failed = ctx
            .execute_async(get(format!("{base}/fails")))
            .await
            .unwrap();
        assert!(failed.error.unwrap().contains("500"));

        let posted = ctx
            .execute_async(AsyncOperation::HttpPost {
                url: format!("{base}/ok"),
                body: b"payload".to_vec(),
                headers: HashMap::from([("X-Trace".to_string(), "1".to_string())]),
            })
            .await
            .unwrap();
        assert_eq!(posted.data.as_deref(), Some(&b"hello"[..]));
        let post = seen.lock().unwrap().last().unwrap().clone();
        assert!(
            post.starts_with("POST /ok") && post.ends_with("payload"),
            "{post}"
        );
        assert!(post
            .to_ascii_lowercase()
            .contains("content-type: application/octet-stream"));
        assert!(post.to_ascii_lowercase().contains("x-trace: 1"));
        let err = ctx
            .execute_async(AsyncOperation::HttpPost {
                url: format!("{base}/ok"),
                body: vec![],
                headers: HashMap::from([("host".to_string(), "x".to_string())]),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AsyncHostError::InvalidRequest(_)));
        let unreachable = ctx
            .execute_async(get("http://localhost:9/x"))
            .await
            .unwrap();
        assert!(unreachable.error.unwrap().contains("HTTP GET failed"));
    }

    /// Holds its slot until released.
    struct Gate(Arc<tokio::sync::Semaphore>);

    #[async_trait]
    impl CustomHandler for Gate {
        async fn handle(&self, _params: serde_json::Value) -> AsyncHostResult<Vec<u8>> {
            let _released = self.0.acquire().await;
            Ok(b"done".to_vec())
        }
    }

    fn custom(name: &str) -> AsyncOperation {
        AsyncOperation::Custom {
            name: name.to_string(),
            params: serde_json::json!({ "resource": "r" }),
        }
    }

    async fn gated(
        config: AsyncHostConfig,
    ) -> (Arc<AsyncHostContext>, Arc<tokio::sync::Semaphore>) {
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let ctx = AsyncHostContext::with_config("agent-1", "session-1", config)
            .with_enforcer(Arc::new(CedarEnforcer::new_permissive()));
        ctx.register_handler("gate", Arc::new(Gate(gate.clone())))
            .await;
        (Arc::new(ctx), gate)
    }

    async fn until(condition: impl Fn() -> bool) {
        for _ in 0..500 {
            if condition() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        panic!("condition never held");
    }

    #[tokio::test]
    async fn test_the_queue_settings_apply() {
        // queue_when_full and max_queue_depth were never read: every
        // operation waited, however many were waiting.
        let config = AsyncHostConfig {
            max_concurrent_ops: 1,
            max_queue_depth: 1,
            ..AsyncHostConfig::default()
        };
        let (ctx, gate) = gated(config.clone()).await;
        let first = tokio::spawn({
            let ctx = ctx.clone();
            async move { ctx.execute_async(custom("gate")).await }
        });
        until(|| ctx.pending_operations() == 1).await;
        let second = tokio::spawn({
            let ctx = ctx.clone();
            async move { ctx.execute_async(custom("gate")).await }
        });
        until(|| ctx.waiting.load(Ordering::SeqCst) == 1).await;
        let err = ctx.execute_async(custom("gate")).await.unwrap_err();
        assert!(err.to_string().contains("already waiting"), "{err}");
        assert_eq!(
            ctx.waiting.load(Ordering::SeqCst),
            1,
            "the refused one isn't counted"
        );
        gate.add_permits(2);
        assert!(first.await.unwrap().unwrap().success);
        assert!(second.await.unwrap().unwrap().success);
        assert_eq!(ctx.waiting.load(Ordering::SeqCst), 0);

        let (ctx, gate) = gated(AsyncHostConfig {
            queue_when_full: false,
            ..config
        })
        .await;
        let first = tokio::spawn({
            let ctx = ctx.clone();
            async move { ctx.execute_async(custom("gate")).await }
        });
        until(|| ctx.pending_operations() == 1).await;
        let err = ctx.execute_async(custom("gate")).await.unwrap_err();
        assert!(err.to_string().contains("queue_when_full is off"), "{err}");
        gate.add_permits(1);
        assert!(first.await.unwrap().unwrap().success);
    }

    #[tokio::test]
    async fn test_the_default_timeout_applies_to_every_operation() {
        // It applied only to HTTP: a handler without its own timeout could
        // run for ever.
        let (ctx, _gate) = gated(AsyncHostConfig {
            default_timeout: Duration::from_millis(20),
            ..AsyncHostConfig::default()
        })
        .await;
        let result = ctx.execute_async(custom("gate")).await.unwrap();
        assert!(result.error.unwrap().contains("timed out after 20ms"));
        let result = ctx
            .execute_with_timeout(custom("gate"), Duration::from_millis(5))
            .await;
        assert!(matches!(result, Err(AsyncHostError::Timeout(_))));
    }

    struct Echo;

    #[async_trait]
    impl CustomHandler for Echo {
        async fn handle(&self, _params: serde_json::Value) -> AsyncHostResult<Vec<u8>> {
            Ok(b"ran".to_vec())
        }
    }

    #[tokio::test]
    async fn test_cached_authorizations_do_not_collide() {
        // The cache key joined action and resource with `:`, so allowing
        // fs_read on "/a:b" allowed a custom "fs_read:/a" on "b".
        let ctx = context(vec![permit("fs_read", "/a:b*")]).await;
        ctx.register_handler("fs_read:/a", Arc::new(Echo)).await;
        let read = ctx.execute_async(read("/a:b")).await.unwrap();
        assert!(!read.success, "allowed, and the file doesn't exist");
        let err = ctx
            .execute_async(AsyncOperation::Custom {
                name: "fs_read:/a".into(),
                params: serde_json::json!({ "resource": "b" }),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, AsyncHostError::PermissionDenied { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_a_cached_decision_lasts_until_invalidated() {
        let rules = enforcer(vec![permit("fs_read", "/cached*")]).await;
        let ctx = AsyncHostContext::new("agent-1", "s").with_enforcer(rules.clone());
        assert_eq!(ctx.pre_authorize(&[read("/cached")]).await.unwrap(), [true]);
        rules.load_policies_from_str("rules: []").await.unwrap();
        assert_eq!(
            ctx.pre_authorize(&[read("/cached")]).await.unwrap(),
            [true],
            "cached"
        );
        ctx.invalidate_auth_cache().await;
        assert_eq!(
            ctx.pre_authorize(&[read("/cached")]).await.unwrap(),
            [false]
        );

        let uncached = AsyncHostContext::with_config(
            "agent-1",
            "s",
            AsyncHostConfig {
                cache_authorizations: false,
                ..AsyncHostConfig::default()
            },
        )
        .with_enforcer(enforcer(vec![permit("fs_read", "/x*")]).await);
        assert_eq!(
            uncached
                .pre_authorize(&[read("/x"), read("/y")])
                .await
                .unwrap(),
            [true, false]
        );
        assert!(format!("{uncached:?}").contains("agent-1"));
    }

    #[tokio::test]
    async fn test_executor_contexts_are_per_agent_and_session() {
        // "a:b" in "c" and "a" in "b:c" shared a context, so one ran as the
        // other.
        let executor = AsyncOperationExecutor::new(AsyncHostConfig::default());
        let first = executor.get_context("a:b", "c").await;
        let second = executor.get_context("a", "b:c").await;
        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(
            (first.agent_id.as_str(), second.agent_id.as_str()),
            ("a:b", "a")
        );
        assert!(Arc::ptr_eq(&first, &executor.get_context("a:b", "c").await));
        assert_eq!(executor.context_count().await, 2);

        // Cleanup removed nothing, only logged.
        assert_eq!(
            executor.cleanup_inactive(Duration::from_secs(3600)).await,
            0,
            "recent"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert_eq!(
            executor.cleanup_inactive(Duration::ZERO).await,
            0,
            "both held"
        );
        drop(second);
        assert_eq!(executor.cleanup_inactive(Duration::ZERO).await, 1);
        assert_eq!(executor.context_count().await, 1);
        drop(first);
        assert_eq!(executor.cleanup_inactive(Duration::ZERO).await, 1);
    }

    #[tokio::test]
    async fn test_executor_contexts_use_its_enforcer() {
        // An executor's contexts had no way to get an enforcer, so every
        // operation was denied.
        let check = AsyncOperation::PolicyCheck {
            principal: "agent-1".into(),
            action: "fs_read".into(),
            resource: "/data/x".into(),
        };
        let rules = enforcer(vec![
            permit("policy_check", "/data*"),
            permit("fs_read", "/data/*"),
        ])
        .await;
        let executor = AsyncOperationExecutor::new(AsyncHostConfig::default()).with_enforcer(rules);
        let results = executor
            .clone()
            .execute_batch(vec![
                ("agent-1".into(), "s".into(), check.clone()),
                ("agent-2".into(), "s".into(), check),
            ])
            .await;
        let answer = results[0].as_ref().unwrap().data.clone().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&answer).unwrap()["allowed"],
            true
        );
        assert!(results[1].is_err(), "agent-2 may not check policy");
        let plain = AsyncOperationExecutor::new(AsyncHostConfig::default());
        let denied = plain
            .execute_batch(vec![("agent-1".into(), "s".into(), custom("x"))])
            .await;
        assert!(denied[0].is_err());
    }

    #[test]
    fn test_canonical_forms() {
        assert_eq!(canonical_path("/a/./b//c/").unwrap(), "/a/b/c");
        assert!(canonical_path("/a/../b").is_err());
        assert!(canonical_path("a/b").is_err());
        assert!(canonical_path("").is_err());
        assert_eq!(
            canonical_url("HTTP://Example.COM:80/a/./b/../c?q=1#frag").unwrap(),
            "http://example.com/a/c?q=1"
        );
        assert_eq!(
            canonical_url("https://example.com").unwrap(),
            "https://example.com/"
        );
        assert!(canonical_url("https://user:pass@example.com/").is_err());
        assert!(canonical_url("https://:pass@example.com/").is_err());
        let unchanged = AsyncOperation::PolicyCheck {
            principal: "p".into(),
            action: "a".into(),
            resource: "r".into(),
        };
        assert_eq!(unchanged.clone().canonical().unwrap().resource_name(), "r");
        assert_eq!(unchanged.action_name(), "policy_check");
        assert_eq!(custom("c").resource_name(), "r");
        let none = AsyncOperation::Custom {
            name: "c".into(),
            params: serde_json::json!({}),
        };
        assert_eq!(none.resource_name(), "unknown");
    }

    #[test]
    fn test_errors() {
        let io: AsyncHostError = std::io::Error::other("disk").into();
        assert_eq!(io.to_string(), "I/O error: disk");
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        drop(tx);
        let closed: AsyncHostError = tokio_test::block_on(rx).unwrap_err().into();
        assert!(matches!(closed, AsyncHostError::ChannelError(_)));
        assert!(AsyncHostError::Cancelled("x".into())
            .to_string()
            .contains("cancelled"));
        let config: AsyncHostConfig = serde_json::from_value({
            let mut v = serde_json::to_value(AsyncHostConfig::default()).unwrap();
            v.as_object_mut().unwrap().remove("max_response_bytes");
            v
        })
        .unwrap();
        assert_eq!(
            config.max_response_bytes,
            10 * 1024 * 1024,
            "older configs get the default"
        );
    }
}
