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
//! - Audit logging: with `audit_logging`, every `fs_read` and `fs_write`
//!   call is recorded in [`HostFuncState::audit_entries`], allowed or not
//! - Guest memory: pointers and lengths are unsigned wasm32 values, bounds
//!   checked without overflow, so no guest input can panic the host
//!
//! # Not implemented
//!
//! `vak.fs_read` and `vak.fs_write` check the policy and record the call,
//! but read and write nothing: an allowed call returns [`NOT_IMPLEMENTED`].
//! They used to return 0, which their ABI defines as success. `vak.env_get`
//! exposes no variables and always returns -1.
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

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::panic;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, warn};
use wasmtime::{format_err, Result as HostResult};
use wasmtime::{Caller, Engine, Linker};

use super::runtime::{guest_offset, guest_range};

/// Returned by `vak.fs_read` and `vak.fs_write` when the path can't be read
/// from guest memory: out of bounds, not UTF-8, or no exported memory.
pub const GUEST_MEMORY_ERROR: i64 = -1;

/// Returned by `vak.fs_read` and `vak.fs_write` when the policy allows the
/// call: neither is implemented, so nothing was read or written.
pub const NOT_IMPLEMENTED: i64 = -2;

/// The longest message `vak.log` accepts, in bytes. A longer one is dropped
/// with a warning, unread.
pub const MAX_LOG_MESSAGE: usize = 4096;

/// Errors that can occur in host functions
#[derive(Debug, Error)]
pub enum HostFuncError {
    /// Permission denied by policy
    #[error("Permission denied: {action} on {resource}")]
    PermissionDenied {
        /// The action that was denied
        action: String,
        /// The resource the action was attempted on
        resource: String,
    },

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
    /// Allowed file system paths (empty = deny all file ops).
    /// [`PermissionCache::from_config`] matches each exactly: a directory
    /// allows itself, not the files under it.
    pub allowed_fs_roots: Vec<PathBuf>,
    /// Allowed network hosts (empty = deny all network ops)
    pub allowed_network_hosts: Vec<String>,
    /// Max file read size in bytes. Not applied: no host function reads
    /// files yet.
    pub max_file_read_size: usize,
    /// Max network response size in bytes. Not applied: no host function
    /// makes network requests yet.
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
    panic::catch_unwind(f).unwrap_or_else(|payload| Err(panicked(payload.as_ref())))
}

/// The error for a caught panic, carrying its message when it has one.
fn panicked(payload: &(dyn std::any::Any + Send)) -> HostFuncError {
    let msg = if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "Unknown panic".to_string()
    };
    error!(panic_message = %msg, "Host function panicked");
    HostFuncError::Panic(msg)
}

/// The bytes `ptr..ptr + len` of the caller's exported memory.
fn guest_bytes(
    caller: &mut Caller<'_, HostFuncState>,
    ptr: i32,
    len: i32,
) -> HostFuncResult<Vec<u8>> {
    let memory = caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| HostFuncError::Internal("Failed to get WASM memory export".to_string()))?;
    let data = memory.data(caller);
    // `ptr` and `len` used to be sign-extended and added unchecked, so a
    // negative pointer overflowed or sliced out of bounds: a panic on the
    // host, outside any panic boundary, that any guest could cause.
    let range = guest_range(ptr, len, data.len()).ok_or_else(|| {
        HostFuncError::InvalidArgument(format!(
            "Memory access out of bounds: ptr={}, len={}, memory_size={}",
            guest_offset(ptr),
            guest_offset(len),
            data.len()
        ))
    })?;
    Ok(data[range].to_vec())
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
    String::from_utf8(guest_bytes(caller, ptr, len)?)
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
///
/// # Errors
/// The same as [`read_string_from_wasm`], but any bytes are accepted.
pub fn read_bytes_from_wasm(
    caller: &mut Caller<'_, HostFuncState>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, HostFuncError> {
    guest_bytes(caller, ptr, len)
}

/// Async variant of [`with_panic_boundary`]: a panic while making the
/// future, or while polling it, becomes [`HostFuncError::Panic`].
///
/// It used to await the future unguarded, so a panic propagated despite
/// the name. The same caveat about shared state applies.
pub async fn with_panic_boundary_async<F, Fut, T>(f: F) -> HostFuncResult<T>
where
    F: FnOnce() -> Fut + Send,
    Fut: std::future::Future<Output = HostFuncResult<T>> + Send,
{
    use futures::FutureExt;
    let future = panic::catch_unwind(panic::AssertUnwindSafe(f))
        .map_err(|payload| panicked(payload.as_ref()))?;
    panic::AssertUnwindSafe(future)
        .catch_unwind()
        .await
        .unwrap_or_else(|payload| Err(panicked(payload.as_ref())))
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
        let switches = Switches::from(config);

        // vak_fs_read: Read a file (with policy check)
        // Arguments: path_ptr (i32), path_len (i32)
        // Returns: i64 - NOT_IMPLEMENTED if allowed, GUEST_MEMORY_ERROR if
        // the path can't be read; a denied call traps.
        let read = permissions.clone();
        linker
            .func_wrap(
                "vak",
                "fs_read",
                move |mut caller: Caller<'_, HostFuncState>,
                      path_ptr: i32,
                      path_len: i32|
                      -> HostResult<i64> {
                    fs_call(&mut caller, "fs_read", path_ptr, path_len, &read, switches)
                },
            )
            .map_err(|e| HostFuncError::Internal(e.to_string()))?;

        // vak_fs_write: Write to a file (with policy check)
        // Arguments: path_ptr (i32), path_len (i32), data_ptr (i32), data_len (i32)
        // Returns: as fs_read; the data is not read.
        let write = permissions.clone();
        linker
            .func_wrap(
                "vak",
                "fs_write",
                move |mut caller: Caller<'_, HostFuncState>,
                      path_ptr: i32,
                      path_len: i32,
                      _data_ptr: i32,
                      _data_len: i32|
                      -> HostResult<i64> {
                    fs_call(
                        &mut caller,
                        "fs_write",
                        path_ptr,
                        path_len,
                        &write,
                        switches,
                    )
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
                      -> HostResult<i64> {
                    let operation = || {
                        // Environment variables are typically restricted
                        // Return -1 to indicate not found/not allowed
                        Ok(-1i64)
                    };

                    if catch_panics {
                        with_panic_boundary(operation).map_err(|e| format_err!(e))
                    } else {
                        operation().map_err(|e| format_err!(e))
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
        // Arguments: level (0 error, 1 warn, 2 info, 3 debug, else trace),
        // msg_ptr (i32), msg_len (i32). A message that can't be read, or is
        // longer than MAX_LOG_MESSAGE, is dropped with a warning.
        linker
            .func_wrap(
                "vak",
                "log",
                move |mut caller: Caller<'_, HostFuncState>,
                      level: i32,
                      msg_ptr: i32,
                      msg_len: i32|
                      -> HostResult<()> {
                    let message = if guest_offset(msg_len) > MAX_LOG_MESSAGE {
                        Err(HostFuncError::InvalidArgument(format!(
                            "a log message of {} bytes is over the {MAX_LOG_MESSAGE}-byte limit",
                            guest_offset(msg_len)
                        )))
                    } else {
                        read_string_from_wasm(&mut caller, msg_ptr, msg_len)
                    };
                    let agent_id = caller.data().agent_id.clone();
                    let operation = || {
                        // Debug formatting escapes control characters, so a
                        // guest can't forge log lines.
                        match message {
                            Ok(message) => match level {
                                0 => error!(agent_id = %agent_id, message = ?message, "WASM log"),
                                1 => warn!(agent_id = %agent_id, message = ?message, "WASM log"),
                                2 => tracing::info!(agent_id = %agent_id, message = ?message, "WASM log"),
                                3 => debug!(agent_id = %agent_id, message = ?message, "WASM log"),
                                _ => tracing::trace!(agent_id = %agent_id, message = ?message, "WASM log"),
                            },
                            Err(e) => warn!(agent_id = %agent_id, error = %e, "WASM log message dropped"),
                        }
                        Ok(())
                    };

                    if catch_panics {
                        with_panic_boundary(operation).map_err(|e| format_err!(e))
                    } else {
                        operation().map_err(|e| format_err!(e))
                    }
                },
            )
            .map_err(|e| HostFuncError::Internal(e.to_string()))?;

        Ok(())
    }
}

/// The parts of [`HostFuncConfig`] a host function reads on each call.
#[derive(Debug, Clone, Copy)]
struct Switches {
    enforce_policy: bool,
    catch_panics: bool,
    audit_logging: bool,
}

impl From<&HostFuncConfig> for Switches {
    fn from(config: &HostFuncConfig) -> Self {
        Self {
            enforce_policy: config.enforce_policy,
            catch_panics: config.catch_panics,
            audit_logging: config.audit_logging,
        }
    }
}

/// The body of `vak.fs_read` and `vak.fs_write`.
///
/// Reads the path from guest memory, checks it against `permissions`, and
/// with `audit_logging` records the call in the caller's state, whether
/// allowed, denied or unreadable. Nothing records entries otherwise: the
/// setting was on by default and never read.
///
/// An allowed call returns [`NOT_IMPLEMENTED`]; it used to return 0, the
/// ABI's success, having done nothing. A denied call traps.
fn fs_call(
    caller: &mut Caller<'_, HostFuncState>,
    action: &'static str,
    path_ptr: i32,
    path_len: i32,
    permissions: &PermissionCache,
    switches: Switches,
) -> HostResult<i64> {
    let record = |caller: &mut Caller<'_, HostFuncState>,
                  resource: &str,
                  outcome: Result<&str, String>| {
        if switches.audit_logging {
            let state = caller.data();
            let entry = AuditLogEntry::new(&state.agent_id, &state.session_id, action, resource);
            let entry = match outcome {
                Ok(result) => entry.allow(result),
                Err(reason) => entry.deny(reason),
            };
            caller.data_mut().record_audit(entry);
        }
    };

    let resource = match read_string_from_wasm(caller, path_ptr, path_len) {
        Ok(path) => path,
        Err(e) => {
            warn!(error = %e, action, "Failed to read path from WASM memory");
            record(caller, "", Err(e.to_string()));
            return Ok(GUEST_MEMORY_ERROR);
        }
    };

    let agent_id = caller.data().agent_id.clone();
    let operation = || {
        if switches.enforce_policy && !permissions.is_allowed(action, &resource) {
            return Err(HostFuncError::PermissionDenied {
                action: action.to_string(),
                resource: resource.clone(),
            });
        }
        warn!(
            agent_id = %agent_id,
            resource = %resource,
            action,
            "allowed, but not implemented: nothing was read or written"
        );
        Ok(NOT_IMPLEMENTED)
    };
    let outcome = if switches.catch_panics {
        with_panic_boundary(operation)
    } else {
        operation()
    };

    match &outcome {
        Ok(_) => record(
            caller,
            &resource,
            Ok("allowed; not implemented, so nothing was done"),
        ),
        Err(e) => record(caller, &resource, Err(e.to_string())),
    }
    outcome.map_err(|e| format_err!(e))
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

    use wasmtime::{Instance, Module, Store};

    /// A guest that imports every host function, with two paths and some
    /// invalid UTF-8 in its memory.
    const GUEST_WAT: &str = r#"
        (module
          (import "vak" "fs_read" (func $fs_read (param i32 i32) (result i64)))
          (import "vak" "fs_write" (func $fs_write (param i32 i32 i32 i32) (result i64)))
          (import "vak" "env_get" (func $env_get (param i32 i32) (result i64)))
          (import "vak" "log" (func $log (param i32 i32 i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "/data/a.txt")
          (data (i32.const 16) "/etc/shadow")
          (data (i32.const 32) "\ff\fe")
          (data (i32.const 48) "line one\0aFORGED line")
          (func (export "read") (param i32 i32) (result i64)
            (call $fs_read (local.get 0) (local.get 1)))
          (func (export "write") (param i32 i32) (result i64)
            (call $fs_write (local.get 0) (local.get 1) (i32.const 0) (i32.const 4)))
          (func (export "env") (result i64)
            (call $env_get (i32.const 0) (i32.const 4)))
          (func (export "log") (param i32 i32 i32)
            (call $log (local.get 0) (local.get 1) (local.get 2))))
    "#;
    const DATA: (i32, i32) = (0, 11);
    const SHADOW: (i32, i32) = (16, 11);
    const NOT_UTF8: (i32, i32) = (32, 2);

    fn guest(
        permissions: PermissionCache,
        config: HostFuncConfig,
        wat: &str,
    ) -> (Store<HostFuncState>, Instance) {
        let engine = Engine::default();
        let linker = HostFuncLinker::new(&engine, permissions, config).unwrap();
        let module = Module::new(&engine, wat).unwrap();
        let mut store = Store::new(&engine, HostFuncState::new("agent-1", "session-1"));
        let instance = linker.linker().instantiate(&mut store, &module).unwrap();
        (store, instance)
    }

    fn call(
        store: &mut Store<HostFuncState>,
        instance: &Instance,
        name: &str,
        (ptr, len): (i32, i32),
    ) -> wasmtime::Result<i64> {
        instance
            .get_typed_func::<(i32, i32), i64>(&mut *store, name)
            .unwrap()
            .call(&mut *store, (ptr, len))
    }

    fn data_reader() -> PermissionCache {
        let mut permissions = PermissionCache::new();
        permissions.allow("fs_read", "/data/a.txt");
        permissions
    }

    #[test]
    fn test_a_guest_pointer_cannot_panic_the_host() {
        // Pointers were sign-extended and `ptr + len` added unchecked,
        // outside the panic boundary: `fs_read(-1, 2)` panicked the host.
        let (mut store, instance) = guest(data_reader(), HostFuncConfig::default(), GUEST_WAT);
        for range in [
            (-1, 2),
            (i32::MIN, 1),
            (i32::MAX, i32::MAX),
            (0, -1),
            (-1, -1),
            (65_530, 10),
            (65_536, 1),
            NOT_UTF8,
        ] {
            for name in ["read", "write"] {
                assert_eq!(
                    call(&mut store, &instance, name, range).unwrap(),
                    GUEST_MEMORY_ERROR,
                    "{name}{range:?}"
                );
            }
        }
        let entries = &store.data().audit_entries;
        assert_eq!(entries.len(), 16, "each unreadable call is recorded");
        assert!(entries.iter().all(|e| !e.allowed && e.resource.is_empty()));
        assert!(
            entries[0].result.contains("out of bounds"),
            "{:?}",
            entries[0]
        );
        assert!(entries[15].result.contains("UTF-8"), "{:?}", entries[15]);

        // The last byte of memory, and an empty path at its end, are in
        // bounds, so the policy decides them.
        for range in [(65_535, 1), (65_536, 0)] {
            let err = call(&mut store, &instance, "read", range).unwrap_err();
            assert!(
                format!("{err:#}").contains("Permission denied"),
                "{range:?}: {err:#}"
            );
        }
    }

    #[test]
    fn test_an_allowed_fs_call_does_nothing_and_says_so() {
        // Both returned 0, success by their ABI, having done nothing.
        let (mut store, instance) = guest(data_reader(), HostFuncConfig::default(), GUEST_WAT);
        assert_eq!(
            call(&mut store, &instance, "read", DATA).unwrap(),
            NOT_IMPLEMENTED
        );

        let err = call(&mut store, &instance, "write", DATA).unwrap_err();
        assert!(
            format!("{err:#}").contains("Permission denied: fs_write on /data/a.txt"),
            "{err:#}"
        );
        let err = call(&mut store, &instance, "read", SHADOW).unwrap_err();
        assert!(
            format!("{err:#}").contains("fs_read on /etc/shadow"),
            "{err:#}"
        );

        // Every call is recorded with its outcome; nothing recorded them.
        let entries = &store.data().audit_entries;
        let seen: Vec<_> = entries
            .iter()
            .map(|e| (e.action.as_str(), e.resource.as_str(), e.allowed))
            .collect();
        assert_eq!(
            seen,
            [
                ("fs_read", "/data/a.txt", true),
                ("fs_write", "/data/a.txt", false),
                ("fs_read", "/etc/shadow", false),
            ]
        );
        assert!(entries[0].result.contains("not implemented"));
        assert!(entries[1].result.contains("Permission denied"));
        assert!(entries
            .iter()
            .all(|e| e.agent_id == "agent-1" && e.session_id == "session-1"));
    }

    #[test]
    fn test_the_switches_apply() {
        let quiet = HostFuncConfig {
            audit_logging: false,
            ..HostFuncConfig::default()
        };
        let (mut store, instance) = guest(data_reader(), quiet, GUEST_WAT);
        assert_eq!(
            call(&mut store, &instance, "read", DATA).unwrap(),
            NOT_IMPLEMENTED
        );
        assert!(call(&mut store, &instance, "read", SHADOW).is_err());
        assert_eq!(
            call(&mut store, &instance, "read", (-1, 2)).unwrap(),
            GUEST_MEMORY_ERROR
        );
        assert!(
            store.data().audit_entries.is_empty(),
            "audit logging is off"
        );

        // Without enforcement nothing is denied, and still nothing is done.
        let open = HostFuncConfig {
            enforce_policy: false,
            ..HostFuncConfig::default()
        };
        let (mut store, instance) = guest(PermissionCache::deny_all(), open, GUEST_WAT);
        assert_eq!(
            call(&mut store, &instance, "write", SHADOW).unwrap(),
            NOT_IMPLEMENTED
        );
        assert!(store.data().audit_entries[0].allowed);

        // Without the panic boundary the outcomes are the same.
        let unguarded = HostFuncConfig {
            catch_panics: false,
            ..HostFuncConfig::default()
        };
        let (mut store, instance) = guest(data_reader(), unguarded, GUEST_WAT);
        assert_eq!(
            call(&mut store, &instance, "read", DATA).unwrap(),
            NOT_IMPLEMENTED
        );
        assert!(call(&mut store, &instance, "write", DATA).is_err());
        assert_eq!(
            call(&mut store, &instance, "read", (-1, 2)).unwrap(),
            GUEST_MEMORY_ERROR
        );
        let env = instance
            .get_typed_func::<(), i64>(&mut store, "env")
            .unwrap();
        assert_eq!(env.call(&mut store, ()).unwrap(), -1);
        let log = instance
            .get_typed_func::<(i32, i32, i32), ()>(&mut store, "log")
            .unwrap();
        log.call(&mut store, (2, DATA.0, DATA.1)).unwrap();
    }

    #[test]
    fn test_env_get_exposes_nothing() {
        let (mut store, instance) = guest(
            PermissionCache::allow_all(),
            HostFuncConfig::permissive(),
            GUEST_WAT,
        );
        let env = instance
            .get_typed_func::<(), i64>(&mut store, "env")
            .unwrap();
        assert_eq!(env.call(&mut store, ()).unwrap(), -1);
    }

    /// Collects what the `fmt` subscriber writes.
    #[derive(Clone, Default)]
    struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_log_reads_the_message_and_escapes_it() {
        // `log` used to read only the level; the message never reached the
        // log.
        let captured = Captured::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let (mut store, instance) =
                guest(PermissionCache::new(), HostFuncConfig::default(), GUEST_WAT);
            let log = instance
                .get_typed_func::<(i32, i32, i32), ()>(&mut store, "log")
                .unwrap();
            for level in 0..5 {
                log.call(&mut store, (level, DATA.0, DATA.1)).unwrap();
            }
            log.call(&mut store, (2, 48, 20)).unwrap();
            // Unreadable and oversized messages are dropped, not trapped.
            log.call(&mut store, (2, -1, 2)).unwrap();
            log.call(&mut store, (2, 0, (MAX_LOG_MESSAGE + 1) as i32))
                .unwrap();
            log.call(&mut store, (2, NOT_UTF8.0, NOT_UTF8.1)).unwrap();
        });

        let text = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        for level in ["ERROR", "WARN", "INFO", "DEBUG", "TRACE"] {
            assert!(
                text.lines().any(|l| l.contains(level)
                    && l.contains("\"/data/a.txt\"")
                    && l.contains("agent-1")),
                "{level} in {text}"
            );
        }
        assert!(
            text.contains(r#""line one\nFORGED line""#),
            "escaped: {text}"
        );
        assert!(!text.lines().any(|l| l.starts_with("FORGED")), "{text}");
        assert_eq!(
            text.matches("WASM log message dropped").count(),
            3,
            "{text}"
        );
        assert!(
            text.contains("4097 bytes is over the 4096-byte limit"),
            "{text}"
        );
    }

    #[test]
    fn test_a_guest_without_memory_gets_a_memory_error() {
        let wat = r#"
            (module
              (import "vak" "fs_read" (func $fs_read (param i32 i32) (result i64)))
              (func (export "read") (param i32 i32) (result i64)
                (call $fs_read (local.get 0) (local.get 1))))
        "#;
        let (mut store, instance) =
            guest(PermissionCache::allow_all(), HostFuncConfig::default(), wat);
        assert_eq!(
            call(&mut store, &instance, "read", (0, 1)).unwrap(),
            GUEST_MEMORY_ERROR
        );
        assert!(store.data().audit_entries[0]
            .result
            .contains("memory export"));
    }

    #[test]
    fn test_read_bytes_from_wasm_checks_bounds() {
        let engine = Engine::default();
        let mut linker =
            HostFuncLinker::new(&engine, PermissionCache::new(), HostFuncConfig::default())
                .unwrap();
        assert!(format!("{linker:?}").contains("HostFuncLinker"));
        assert!(!linker.permissions().default_allow);
        linker
            .linker_mut()
            .func_wrap(
                "test",
                "bytes",
                |mut caller: Caller<'_, HostFuncState>, ptr: i32, len: i32| -> HostResult<i64> {
                    Ok(match read_bytes_from_wasm(&mut caller, ptr, len) {
                        Ok(bytes) => bytes.iter().map(|b| i64::from(*b)).sum(),
                        Err(_) => -1,
                    })
                },
            )
            .unwrap();
        let wat = r#"
            (module
              (import "test" "bytes" (func $bytes (param i32 i32) (result i64)))
              (memory (export "memory") 1)
              (data (i32.const 0) "\01\02\ff")
              (func (export "read") (param i32 i32) (result i64)
                (call $bytes (local.get 0) (local.get 1))))
        "#;
        let module = Module::new(&engine, wat).unwrap();
        let mut store = Store::new(&engine, HostFuncState::new("a", "s"));
        let instance = linker.linker().instantiate(&mut store, &module).unwrap();
        assert_eq!(
            call(&mut store, &instance, "read", (0, 3)).unwrap(),
            258,
            "any bytes"
        );
        assert_eq!(call(&mut store, &instance, "read", (-1, 2)).unwrap(), -1);
        assert_eq!(
            call(&mut store, &instance, "read", (65_535, 2)).unwrap(),
            -1
        );
    }

    #[tokio::test]
    async fn test_the_async_panic_boundary_catches_panics() {
        // It awaited the future unguarded, so a panic propagated.
        assert_eq!(
            with_panic_boundary_async(|| async { Ok(7) }).await.unwrap(),
            7
        );
        let polled: HostFuncResult<i32> = with_panic_boundary_async(|| async {
            tokio::task::yield_now().await;
            panic!("while polling")
        })
        .await;
        assert!(matches!(polled, Err(HostFuncError::Panic(m)) if m == "while polling"));
        let made: HostFuncResult<i32> =
            with_panic_boundary_async(|| -> std::future::Ready<HostFuncResult<i32>> {
                panic!("{}", String::from("while making"))
            })
            .await;
        assert!(matches!(made, Err(HostFuncError::Panic(m)) if m == "while making"));
        let failed: HostFuncResult<i32> =
            with_panic_boundary_async(|| async { Err(HostFuncError::Timeout) }).await;
        assert!(matches!(failed, Err(HostFuncError::Timeout)));
    }

    #[test]
    fn test_a_panic_without_a_message() {
        let result: HostFuncResult<()> = with_panic_boundary(|| std::panic::panic_any(7u8));
        assert!(matches!(result, Err(HostFuncError::Panic(m)) if m == "Unknown panic"));
    }

    #[test]
    fn test_permission_checks() {
        let cache = data_reader();
        assert!(check_permission(&cache, "fs_read", "/data/a.txt").is_ok());
        let err = check_permission(&cache, "fs_read", "/data").unwrap_err();
        assert_eq!(err.to_string(), "Permission denied: fs_read on /data");
        assert_eq!(
            with_safe_permission_check(&cache, "fs_read", "/data/a.txt", || Ok(1)).unwrap(),
            1
        );
        assert!(with_safe_permission_check(&cache, "fs_write", "/data/a.txt", || Ok(1)).is_err());
        let panicked: HostFuncResult<()> =
            with_safe_permission_check(&cache, "fs_read", "/data/a.txt", || panic!("boom"));
        assert!(matches!(panicked, Err(HostFuncError::Panic(_))));

        // A wildcard deny beats a specific allow, and a wildcard allow
        // covers every resource.
        let mut cache = data_reader();
        cache.deny("fs_read", "*");
        assert!(!cache.is_allowed("fs_read", "/data/a.txt"));
        let mut cache = PermissionCache::new();
        cache.allow("http_get", "*");
        assert!(cache.is_allowed("http_get", "example.com"));
    }

    #[test]
    fn test_configs_and_the_cache_built_from_them() {
        let strict = HostFuncConfig::strict();
        assert!(strict.enforce_policy && strict.allowed_fs_roots.is_empty());
        assert_eq!(strict.max_file_read_size, 1024 * 1024);
        let permissive = HostFuncConfig::permissive();
        assert!(!permissive.enforce_policy);

        let cache = PermissionCache::from_config(&HostFuncConfig {
            allowed_fs_roots: vec![PathBuf::from("/data")],
            allowed_network_hosts: vec!["api.example.com".into()],
            ..HostFuncConfig::default()
        });
        assert!(cache.is_allowed("fs_read", "/data") && cache.is_allowed("fs_write", "/data"));
        assert!(
            !cache.is_allowed("fs_read", "/data/a.txt"),
            "matched exactly"
        );
        assert!(cache.is_allowed("http_get", "api.example.com"));
        assert!(cache.is_allowed("http_post", "api.example.com"));
        assert!(!cache.is_allowed("http_get", "evil.example.com"));
        assert!(cache.is_allowed("log", "anything"));
        assert!(!PermissionCache::from_config(&strict).is_allowed("fs_read", "/"));
    }

    #[test]
    fn test_entries_and_errors() {
        let entry = AuditLogEntry::new("a", "s", "fs_read", "/x").allow("done");
        assert!(entry.allowed && entry.result == "done" && entry.timestamp > 0);
        let io: HostFuncError = std::io::Error::other("disk").into();
        assert_eq!(io.to_string(), "I/O error: disk");
        for (err, text) in [
            (
                HostFuncError::Panic("p".into()),
                "Host function panicked: p",
            ),
            (
                HostFuncError::InvalidArgument("x".into()),
                "Invalid argument: x",
            ),
            (
                HostFuncError::PolicyError("x".into()),
                "Policy evaluation error: x",
            ),
            (HostFuncError::NotFound("x".into()), "Resource not found: x"),
            (HostFuncError::Timeout, "Operation timed out"),
            (HostFuncError::Internal("x".into()), "Internal error: x"),
        ] {
            assert_eq!(err.to_string(), text);
        }
    }
}
