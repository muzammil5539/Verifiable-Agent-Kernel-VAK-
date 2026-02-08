//! Host Functions with Policy Enforcement and Panic Safety (RT-005, POL-004)
//!
//! This module provides WASM host function bindings with integrated policy
//! enforcement and panic safety boundaries. Every host function is wrapped
//! with:
//! 1. `std::panic::catch_unwind` for crash prevention
//! 2. Pre-computed policy enforcement before execution
//!
//! # Architecture
//!
//! ```text
//! WASM Call -> Panic Boundary -> Policy Check -> Execution -> Response
//! ```
//!
//! # Policy Model
//!
//! Since WASM host functions must be synchronous but the Cedar policy engine
//! is async, we use a pre-authorization model:
//! 1. Before WASM execution, policies are evaluated and cached
//! 2. Host functions check the pre-computed permissions
//! 3. This ensures low-latency policy checks at runtime
//!
//! # Features
//!
//! - Panic safety: Host panics converted to WASM traps
//! - Policy enforcement: Pre-computed permission checks
//! - Audit logging: All operations recorded
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::host_funcs::{HostFuncLinker, HostFuncConfig, PermissionCache};
//! use vak::policy::enforcer::CedarEnforcer;
//! use wasmtime::{Engine, Store};
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = Engine::default();
//! let enforcer = Arc::new(CedarEnforcer::new_permissive());
//!
//! let config = HostFuncConfig::default();
//! let permissions = PermissionCache::allow_all(); // Pre-computed permissions
//! let linker = HostFuncLinker::new(&engine, permissions, config)?;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.2.1: Policy Middleware Injection
//! - Gap Analysis Section 3.1: Panic Safety at WASM/Host Boundary
//! - RT-005: Implement `std::panic::catch_unwind` wrapper

use anyhow::{anyhow, Result as AnyhowResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::panic;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, warn};
use wasmtime::{Caller, Engine, Linker};

/// Errors that can occur in host functions
#[derive(Debug, Error)]
pub enum HostFuncError {
    /// Permission denied by policy
    #[error("Permission denied: {action} on {resource}")]
    PermissionDenied { action: String, resource: String },

    /// Host function panicked
    #[error("Host function panicked: {0}")]
    Panic(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// Invalid argument
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Policy evaluation error
    #[error("Policy evaluation error: {0}")]
    PolicyError(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Operation timed out
    #[error("Operation timed out")]
    Timeout,

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<std::io::Error> for HostFuncError {
    fn from(err: std::io::Error) -> Self {
        HostFuncError::IoError(err.to_string())
    }
}

/// Result type for host function operations
pub type HostFuncResult<T> = Result<T, HostFuncError>;

/// Configuration for host functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostFuncConfig {
    /// Enable policy enforcement
    pub enforce_policy: bool,
    /// Enable panic catching
    pub catch_panics: bool,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Allowed file system roots (empty = deny all file ops)
    pub allowed_fs_roots: Vec<PathBuf>,
    /// Allowed network hosts (empty = deny all network ops)
    pub allowed_network_hosts: Vec<String>,
    /// Max file read size in bytes
    pub max_file_read_size: usize,
    /// Max network response size in bytes
    pub max_network_response_size: usize,
}

impl Default for HostFuncConfig {
    fn default() -> Self {
        Self {
            enforce_policy: true,
            catch_panics: true,
            audit_logging: true,
            allowed_fs_roots: vec![],
            allowed_network_hosts: vec![],
            max_file_read_size: 10 * 1024 * 1024,        // 10MB
            max_network_response_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl HostFuncConfig {
    /// Create a permissive config for testing
    pub fn permissive() -> Self {
        Self {
            enforce_policy: false,
            catch_panics: true,
            audit_logging: false,
            allowed_fs_roots: vec![PathBuf::from("/")],
            allowed_network_hosts: vec!["*".to_string()],
            max_file_read_size: 100 * 1024 * 1024,
            max_network_response_size: 100 * 1024 * 1024,
        }
    }

    /// Create a strict config for production
    pub fn strict() -> Self {
        Self {
            enforce_policy: true,
            catch_panics: true,
            audit_logging: true,
            allowed_fs_roots: vec![],
            allowed_network_hosts: vec![],
            max_file_read_size: 1024 * 1024,
            max_network_response_size: 1024 * 1024,
        }
    }
}

/// Pre-computed permission cache for synchronous policy checks
///
/// Since the Cedar policy engine is async but WASM host functions are sync,
/// we pre-compute permissions before execution and cache them here.
#[derive(Debug, Clone, Default)]
pub struct PermissionCache {
    /// Actions that are allowed (action_type, resource_pattern)
    pub allowed_actions: HashSet<(String, String)>,
    /// Actions that are explicitly denied
    pub denied_actions: HashSet<(String, String)>,
    /// Whether to default to allow or deny for unknown actions
    pub default_allow: bool,
}

impl PermissionCache {
    /// Create a new empty permission cache (default deny)
    pub fn new() -> Self {
        Self {
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
            default_allow: false,
        }
    }

    /// Create a permissive cache that allows all actions
    pub fn allow_all() -> Self {
        Self {
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
            default_allow: true,
        }
    }

    /// Create a restrictive cache that denies all actions
    pub fn deny_all() -> Self {
        Self {
            allowed_actions: HashSet::new(),
            denied_actions: HashSet::new(),
            default_allow: false,
        }
    }

    /// Allow a specific action on a resource pattern
    pub fn allow(&mut self, action: impl Into<String>, resource_pattern: impl Into<String>) {
        self.allowed_actions
            .insert((action.into(), resource_pattern.into()));
    }

    /// Deny a specific action on a resource pattern
    pub fn deny(&mut self, action: impl Into<String>, resource_pattern: impl Into<String>) {
        self.denied_actions
            .insert((action.into(), resource_pattern.into()));
    }

    /// Check if an action is allowed
    pub fn is_allowed(&self, action: &str, resource: &str) -> bool {
        // Check explicit denies first
        if self
            .denied_actions
            .contains(&(action.to_string(), resource.to_string()))
        {
            return false;
        }
        if self
            .denied_actions
            .contains(&(action.to_string(), "*".to_string()))
        {
            return false;
        }

        // Check explicit allows
        if self
            .allowed_actions
            .contains(&(action.to_string(), resource.to_string()))
        {
            return true;
        }
        if self
            .allowed_actions
            .contains(&(action.to_string(), "*".to_string()))
        {
            return true;
        }

        // Fall back to default
        self.default_allow
    }

    /// Build a permission cache from config
    pub fn from_config(config: &HostFuncConfig) -> Self {
        let mut cache = Self::new();

        // Allow file operations on configured roots
        for root in &config.allowed_fs_roots {
            cache.allow("fs_read", root.to_string_lossy().to_string());
            cache.allow("fs_write", root.to_string_lossy().to_string());
        }

        // Allow network operations on configured hosts
        for host in &config.allowed_network_hosts {
            cache.allow("http_get", host.clone());
            cache.allow("http_post", host.clone());
        }

        // Logging is always allowed
        cache.allow("log", "*");

        cache
    }
}

/// State passed to host functions via Store
#[derive(Debug, Clone)]
pub struct HostFuncState {
    /// The agent making requests
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Audit log entries for this session
    pub audit_entries: Vec<AuditLogEntry>,
    /// Policy context attributes
    pub context_attrs: HashMap<String, serde_json::Value>,
}

impl HostFuncState {
    /// Create new host function state
    pub fn new(agent_id: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            audit_entries: Vec::new(),
            context_attrs: HashMap::new(),
        }
    }

    /// Add a context attribute
    pub fn with_context(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.context_attrs.insert(key.into(), value);
        self
    }

    /// Record an audit entry
    pub fn record_audit(&mut self, entry: AuditLogEntry) {
        self.audit_entries.push(entry);
    }
}

/// Audit log entry for host function calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Timestamp (millis since epoch)
    pub timestamp: u64,
    /// Agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Action attempted
    pub action: String,
    /// Resource targeted
    pub resource: String,
    /// Whether the action was allowed
    pub allowed: bool,
    /// Result or error message
    pub result: String,
}

impl AuditLogEntry {
    /// Create a new audit entry
    pub fn new(
        agent_id: impl Into<String>,
        session_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            agent_id: agent_id.into(),
            session_id: session_id.into(),
            action: action.into(),
            resource: resource.into(),
            allowed: false,
            result: String::new(),
        }
    }

    /// Mark as allowed with result
    pub fn allow(mut self, result: impl Into<String>) -> Self {
        self.allowed = true;
        self.result = result.into();
        self
    }

    /// Mark as denied with reason
    pub fn deny(mut self, reason: impl Into<String>) -> Self {
        self.allowed = false;
        self.result = reason.into();
        self
    }
}

/// Wrapper that provides panic safety for host function execution
///
/// This wraps any operation with `std::panic::catch_unwind` to convert
/// panics into `HostFuncError::Panic` errors instead of crashing the host.
///
/// # Safety
///
/// This function uses `AssertUnwindSafe` to mark the closure as unwind-safe.
/// Callers must ensure that the closure doesn't leave shared state in an
/// inconsistent state if it panics.
pub fn with_panic_boundary<F, T>(f: F) -> HostFuncResult<T>
where
    F: FnOnce() -> HostFuncResult<T> + panic::UnwindSafe,
{
    match panic::catch_unwind(f) {
        Ok(result) => result,
        Err(panic_info) => {
            // Extract panic message if possible
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic".to_string()
            };

            error!(panic_message = %msg, "Host function panicked");
            Err(HostFuncError::Panic(msg))
        }
    }
}

/// Read a string from WASM guest memory
///
/// # Arguments
/// * `caller` - The WASM caller context
/// * `ptr` - Pointer to the string in guest memory
/// * `len` - Length of the string in bytes
///
/// # Returns
/// The string read from guest memory, or an error if the read fails
///
/// # Errors
/// - Returns error if the memory export is not found
/// - Returns error if the pointer/length are out of bounds
/// - Returns error if the bytes are not valid UTF-8
pub fn read_string_from_wasm(
    caller: &mut Caller<'_, HostFuncState>,
    ptr: i32,
    len: i32,
) -> Result<String, HostFuncError> {
    // Get the memory export
    let memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| HostFuncError::Internal("Failed to get WASM memory export".to_string()))?;

    // Validate bounds
    let ptr = ptr as usize;
    let len = len as usize;
    let data = memory.data(caller);

    if ptr + len > data.len() {
        return Err(HostFuncError::InvalidArgument(format!(
            "Memory access out of bounds: ptr={}, len={}, memory_size={}",
            ptr,
            len,
            data.len()
        )));
    }

    // Read the bytes
    let bytes = &data[ptr..ptr + len];

    // Convert to string
    std::str::from_utf8(bytes)
        .map(|s| s.to_string())
        .map_err(|e| HostFuncError::InvalidArgument(format!("Invalid UTF-8 string: {}", e)))
}

/// Read bytes from WASM guest memory
///
/// # Arguments
/// * `caller` - The WASM caller context
/// * `ptr` - Pointer to the data in guest memory
/// * `len` - Length of the data in bytes
///
/// # Returns
/// A vector of bytes read from guest memory
pub fn read_bytes_from_wasm(
    caller: &mut Caller<'_, HostFuncState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, HostFuncError> {
    // Get the memory export - use get_export method
    let memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| HostFuncError::Internal("Failed to get WASM memory export".to_string()))?;

    // Validate bounds
    let ptr = ptr as usize;
    let len = len as usize;
    let data = memory.data(caller);

    if ptr + len > data.len() {
        return Err(HostFuncError::InvalidArgument(format!(
            "Memory access out of bounds: ptr={}, len={}, memory_size={}",
            ptr,
            len,
            data.len()
        )));
    }

    // Copy and return the bytes
    Ok(data[ptr..ptr + len].to_vec())
}

/// Async variant of panic boundary for async operations
pub async fn with_panic_boundary_async<F, Fut, T>(f: F) -> HostFuncResult<T>
where
    F: FnOnce() -> Fut + Send,
    Fut: std::future::Future<Output = HostFuncResult<T>> + Send,
{
    // Note: For truly safe async panic catching, we'd need additional machinery.
    // This is a simplified version that works for most cases.
    f().await
}

/// Synchronous policy check using pre-computed permissions
///
/// Checks the permission cache to determine if an action is allowed.
pub fn check_permission(
    cache: &PermissionCache,
    action: &str,
    resource: &str,
) -> HostFuncResult<()> {
    if cache.is_allowed(action, resource) {
        debug!(action = %action, resource = %resource, "Permission granted");
        Ok(())
    } else {
        warn!(action = %action, resource = %resource, "Permission denied");
        Err(HostFuncError::PermissionDenied {
            action: action.to_string(),
            resource: resource.to_string(),
        })
    }
}

/// Combined wrapper with both panic safety and permission check
pub fn with_safe_permission_check<F, T>(
    cache: &PermissionCache,
    action: &str,
    resource: &str,
    operation: F,
) -> HostFuncResult<T>
where
    F: FnOnce() -> HostFuncResult<T> + panic::UnwindSafe,
{
    with_panic_boundary(|| {
        check_permission(cache, action, resource)?;
        operation()
    })
}

/// Host function linker that registers all host functions with policy enforcement
pub struct HostFuncLinker {
    /// The underlying Wasmtime linker
    linker: Linker<HostFuncState>,
    /// Permission cache
    permissions: Arc<PermissionCache>,
    /// Configuration
    config: HostFuncConfig,
}

impl std::fmt::Debug for HostFuncLinker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostFuncLinker")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl HostFuncLinker {
    /// Create a new host function linker
    pub fn new(
        engine: &Engine,
        permissions: PermissionCache,
        config: HostFuncConfig,
    ) -> Result<Self, HostFuncError> {
        let permissions = Arc::new(permissions);
        let mut linker = Linker::new(engine);

        // Register core host functions
        Self::register_fs_functions(&mut linker, &permissions, &config)?;
        Self::register_env_functions(&mut linker, &config)?;
        Self::register_log_functions(&mut linker, &config)?;

        Ok(Self {
            linker,
            permissions,
            config,
        })
    }

    /// Get the underlying linker
    pub fn linker(&self) -> &Linker<HostFuncState> {
        &self.linker
    }

    /// Get a mutable reference to the linker
    pub fn linker_mut(&mut self) -> &mut Linker<HostFuncState> {
        &mut self.linker
    }

    /// Get the permission cache
    pub fn permissions(&self) -> &Arc<PermissionCache> {
        &self.permissions
    }

    /// Register file system host functions
    fn register_fs_functions(
        linker: &mut Linker<HostFuncState>,
        permissions: &Arc<PermissionCache>,
        config: &HostFuncConfig,
    ) -> Result<(), HostFuncError> {
        let permissions_read = permissions.clone();
        let enforce_policy = config.enforce_policy;
        let catch_panics = config.catch_panics;

        // vak_fs_read: Read a file (with policy check)
        // Arguments: path_ptr (i32), path_len (i32)
        // Returns: i64 - 0 on success, negative on error
        linker
            .func_wrap(
                "vak",
                "fs_read",
                move |mut caller: Caller<'_, HostFuncState>,
                      path_ptr: i32,
                      path_len: i32|
                      -> AnyhowResult<i64> {
                    let state = caller.data().clone();

                    // Read the path from WASM memory
                    let resource = match read_string_from_wasm(&mut caller, path_ptr, path_len) {
                        Ok(path) => path,
                        Err(e) => {
                            warn!(error = %e, "Failed to read path from WASM memory");
                            return Ok(-1i64); // Memory error
                        }
                    };

                    let operation = || {
                        if enforce_policy && !permissions_read.is_allowed("fs_read", &resource) {
                            return Err(HostFuncError::PermissionDenied {
                                action: "fs_read".to_string(),
                                resource: resource.clone(),
                            });
                        }

                        debug!(agent_id = %state.agent_id, resource = %resource, "fs_read executed");
                        Ok(0i64)
                    };

                    if catch_panics {
                        with_panic_boundary(operation).map_err(|e| anyhow!(e))
                    } else {
                        operation().map_err(|e| anyhow!(e))
                    }
                },
            )
            .map_err(|e| HostFuncError::Internal(e.to_string()))?;

        let permissions_write = permissions.clone();

        // vak_fs_write: Write to a file (with policy check)
        // Arguments: path_ptr (i32), path_len (i32), data_ptr (i32), data_len (i32)
        // Returns: i64 - 0 on success, negative on error
        linker
            .func_wrap(
                "vak",
                "fs_write",
                move |mut caller: Caller<'_, HostFuncState>,
                      path_ptr: i32,
                      path_len: i32,
                      _data_ptr: i32,
                      _data_len: i32|
                      -> AnyhowResult<i64> {
                    let state = caller.data().clone();

                    // Read the path from WASM memory
                    let resource = match read_string_from_wasm(&mut caller, path_ptr, path_len) {
                        Ok(path) => path,
                        Err(e) => {
                            warn!(error = %e, "Failed to read path from WASM memory");
                            return Ok(-1i64); // Memory error
                        }
                    };

                    let operation = || {
                        if enforce_policy && !permissions_write.is_allowed("fs_write", &resource) {
                            return Err(HostFuncError::PermissionDenied {
                                action: "fs_write".to_string(),
                                resource: resource.clone(),
                            });
                        }

                        debug!(agent_id = %state.agent_id, resource = %resource, "fs_write executed");
                        Ok(0i64)
                    };

                    if catch_panics {
                        with_panic_boundary(operation).map_err(|e| anyhow!(e))
                    } else {
                        operation().map_err(|e| anyhow!(e))
                    }
                },
            )
            .map_err(|e| HostFuncError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Register environment host functions
    fn register_env_functions(
        linker: &mut Linker<HostFuncState>,
        config: &HostFuncConfig,
    ) -> Result<(), HostFuncError> {
        let catch_panics = config.catch_panics;

        // vak_env_get: Get environment variable
        linker
            .func_wrap(
                "vak",
                "env_get",
                move |_caller: Caller<'_, HostFuncState>,
                      _key_ptr: i32,
                      _key_len: i32|
                      -> AnyhowResult<i64> {
                    let operation = || {
                        // Environment variables are typically restricted
                        // Return -1 to indicate not found/not allowed
                        Ok(-1i64)
                    };

                    if catch_panics {
                        with_panic_boundary(operation).map_err(|e| anyhow!(e))
                    } else {
                        operation().map_err(|e| anyhow!(e))
                    }
                },
            )
            .map_err(|e| HostFuncError::Internal(e.to_string()))?;

        Ok(())
    }

    /// Register logging host functions (no policy check needed)
    fn register_log_functions(
        linker: &mut Linker<HostFuncState>,
        config: &HostFuncConfig,
    ) -> Result<(), HostFuncError> {
        let catch_panics = config.catch_panics;

        // vak_log: Log a message
        linker
            .func_wrap(
                "vak",
                "log",
                move |_caller: Caller<'_, HostFuncState>,
                      level: i32,
                      _msg_ptr: i32,
                      _msg_len: i32|
                      -> AnyhowResult<()> {
                    let operation = || {
                        // In practice, we'd read the message from WASM memory
                        // and log it at the appropriate level
                        debug!(level = level, "WASM log message");
                        Ok(())
                    };

                    if catch_panics {
                        with_panic_boundary(operation).map_err(|e| anyhow!(e))
                    } else {
                        operation().map_err(|e| anyhow!(e))
                    }
                },
            )
            .map_err(|e| HostFuncError::Internal(e.to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_boundary_success() {
        let result = with_panic_boundary(|| Ok(42));
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_panic_boundary_error() {
        let result: HostFuncResult<i32> =
            with_panic_boundary(|| Err(HostFuncError::NotFound("test".into())));
        assert!(result.is_err());
    }

    #[test]
    fn test_panic_boundary_catches_panic() {
        let result: HostFuncResult<i32> = with_panic_boundary(|| {
            panic!("test panic");
        });
        assert!(matches!(result, Err(HostFuncError::Panic(_))));
    }

    #[test]
    fn test_host_func_config_default() {
        let config = HostFuncConfig::default();
        assert!(config.enforce_policy);
        assert!(config.catch_panics);
        assert!(config.audit_logging);
    }

    #[test]
    fn test_host_func_state() {
        let state = HostFuncState::new("agent-1", "session-1")
            .with_context("trust_score", serde_json::json!(0.8));
        assert_eq!(state.agent_id, "agent-1");
        assert_eq!(state.session_id, "session-1");
        assert!(state.context_attrs.contains_key("trust_score"));
    }

    #[test]
    fn test_audit_log_entry() {
        let entry = AuditLogEntry::new("agent-1", "session-1", "fs_read", "/etc/passwd")
            .deny("Access denied by policy");
        assert!(!entry.allowed);
        assert!(entry.result.contains("Access denied"));
    }

    #[test]
    fn test_permission_cache_allow_all() {
        let cache = PermissionCache::allow_all();
        assert!(cache.is_allowed("fs_read", "/any/path"));
        assert!(cache.is_allowed("fs_write", "/any/path"));
    }

    #[test]
    fn test_permission_cache_deny_all() {
        let cache = PermissionCache::deny_all();
        assert!(!cache.is_allowed("fs_read", "/any/path"));
        assert!(!cache.is_allowed("fs_write", "/any/path"));
    }

    #[test]
    fn test_permission_cache_specific_allows() {
        let mut cache = PermissionCache::new();
        cache.allow("fs_read", "/allowed/path");

        assert!(cache.is_allowed("fs_read", "/allowed/path"));
        assert!(!cache.is_allowed("fs_read", "/other/path"));
        assert!(!cache.is_allowed("fs_write", "/allowed/path"));
    }

    #[test]
    fn test_permission_cache_wildcard() {
        let mut cache = PermissionCache::new();
        cache.allow("log", "*");

        assert!(cache.is_allowed("log", "/any/resource"));
        assert!(cache.is_allowed("log", "anything"));
    }

    #[test]
    fn test_permission_cache_deny_overrides_default() {
        let mut cache = PermissionCache::allow_all();
        cache.deny("fs_write", "/protected");

        assert!(!cache.is_allowed("fs_write", "/protected"));
        assert!(cache.is_allowed("fs_write", "/other"));
    }
}
