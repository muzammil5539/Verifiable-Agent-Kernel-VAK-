//! WASM Sandbox for secure tool/skill execution
//!
//! Provides isolated execution environment with resource limits
//! using wasmtime for WebAssembly runtime.
//!
//! # Features
//! - Resource-limited WASM execution (memory, CPU, time)
//! - Skill registry with manifest-based permissions
//! - Cryptographic signature verification (SBX-002)
//! - Marketplace integration for skill discovery and installation
//! - Epoch-based preemptive termination (RT-001)
//! - Pooling allocator for memory hardening (RT-003)
//! - Epoch deadline configuration (RT-002)
//! - Host functions with panic safety (RT-005)
//! - Policy enforcement at WASM boundary (POL-004)
//! - Neuro-symbolic reasoning host functions (NSR-003)
//! - Async host functions for non-blocking I/O (RT-004)

pub mod async_host;
pub mod epoch_config;
pub mod epoch_ticker;
pub mod host_funcs;
pub mod marketplace;
pub mod pooling;
#[cfg(feature = "reasoner")]
pub mod reasoning_host;
pub mod registry;
pub mod runtime;
pub mod signing;
pub mod verified_publisher;

// Re-export the shared runtime (Phase 1 slice 1b, docs/adr/0004)
pub use runtime::{PreparedSkill, SandboxRuntime, SandboxRuntimeConfig, SandboxRuntimeStats};

// Re-export registry types for convenient access
pub use registry::{
    PermissionError, RegistryError, SignatureConfig, SignatureError, SkillId, SkillManifest,
    SkillPermissions, SkillRegistry, SkillSignatureVerifier, VerifiedSkill,
};

// Re-export marketplace types
pub use marketplace::{
    InstallResult, MarketplaceClient, MarketplaceConfig, MarketplaceError, MarketplaceSkill,
    Publisher, SearchResults, SkillCategory, SkillLicense, SkillQuery, SkillReview, SortOrder,
    UninstallResult,
};

// Re-export epoch ticker types (RT-001)
pub use epoch_ticker::{
    EpochTicker, EpochTickerBuilder, EpochTickerConfig, EpochTickerError, EpochTickerStats,
};

// Re-export pooling types (RT-003)
pub use pooling::{
    create_pooling_engine, create_standard_engine, PoolManager, PoolingConfig, PoolingError,
    PoolingStats,
};

// Re-export epoch config types (RT-002)
pub use epoch_config::{
    BudgetStats, EpochConfig, EpochConfigError, EpochDeadlineManager, EpochExecutionBuilder,
    ExecutionLimits, PreemptionBudget,
};

// Re-export host function types (RT-005, POL-004)
pub use host_funcs::{
    check_permission, with_panic_boundary, with_safe_permission_check, AuditLogEntry,
    HostFuncConfig, HostFuncError, HostFuncLinker, HostFuncState, PermissionCache,
};

// Re-export reasoning host types (NSR-003)
#[cfg(feature = "reasoner")]
pub use reasoning_host::{
    register_reasoning_functions, PlanVerification, ReasoningConfig, ReasoningHost,
    ReasoningHostError, ReasoningHostState, VerificationResult, ViolationInfo,
};

// Re-export async host types (RT-004)
pub use async_host::{
    AsyncHostConfig, AsyncHostContext, AsyncHostError, AsyncHostResult, AsyncOperation,
    AsyncOperationExecutor, OperationResult,
};

// Re-export verified publisher types (FUT-004)
pub use verified_publisher::{
    IssueSeverity, PublishedSkill, PublisherConfig, PublisherError, PublisherProfile,
    PublisherRegistry, PublisherReputation, PublisherResult, ReportReason, ReportStatus, ScanIssue,
    ScanResult, SkillReport, TrustLevel, VerificationMethod, VerificationRecord,
    VerificationRequest, VerificationStatus,
};

use std::sync::Arc;
use std::time::Duration;
use wasmtime::{Store, StoreLimits, StoreLimitsBuilder};

/// Configuration for sandbox resource limits
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum memory in bytes (default: 16MB)
    pub memory_limit: usize,
    /// Maximum fuel (CPU cycles) allowed (default: 1_000_000)
    pub fuel_limit: u64,
    /// Execution timeout (default: 5 seconds)
    pub timeout: Duration,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            memory_limit: 16 * 1024 * 1024, // 16 MB
            fuel_limit: 1_000_000,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Errors that can occur during sandbox operations
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// Failed to create the WASM engine
    #[error("Failed to create WASM engine: {0}")]
    EngineCreation(String),

    /// Failed to load a WASM module
    #[error("Failed to load WASM module: {0}")]
    ModuleLoad(String),

    /// Failed to instantiate the module
    #[error("Failed to instantiate module: {0}")]
    Instantiation(String),

    /// Function not found in the module
    #[error("Function '{0}' not found in module")]
    FunctionNotFound(String),

    /// Execution failed with an error
    #[error("Execution failed: {0}")]
    Execution(String),

    /// CPU fuel limit exceeded
    #[error("Fuel exhausted: CPU limit exceeded")]
    FuelExhausted,

    /// Memory limit exceeded
    #[error("Memory limit exceeded")]
    MemoryLimitExceeded,

    /// Execution timed out
    #[error("Execution timeout after {0:?}")]
    Timeout(Duration),

    /// Invalid JSON input provided
    #[error("Invalid JSON input: {0}")]
    InvalidInput(String),

    /// Invalid JSON output from execution
    #[error("Invalid JSON output: {0}")]
    InvalidOutput(String),

    /// Memory allocation failed in guest
    #[error("Memory allocation failed in guest")]
    GuestAllocation,

    /// The module on disk is not the one the skill was verified with.
    #[error("Module changed since it was verified: expected sha256 {expected}, found {actual}")]
    ModuleChanged {
        /// Hex SHA-256 the skill is pinned to.
        expected: String,
        /// Hex SHA-256 of the bytes found.
        actual: String,
    },
}

/// The most elements a skill's table may hold, at instantiation or after
/// `table.grow`.
///
/// Tables live in host memory, outside the linear memory that
/// [`SandboxConfig::memory_limit`] bounds. Without this cap a skill could
/// declare or grow a table of 2^32 elements and have the host allocate tens
/// of gigabytes (docs/adr/0010). It matches the pooling allocator's default,
/// so the limit is the same whichever allocator runs the skill. The shipped
/// skills use under 40.
pub const MAX_TABLE_ELEMENTS: usize = 10_000;

/// Store data holding resource limits. Time limits are enforced by the
/// store's epoch deadline (see [`runtime`]), not tracked here.
#[derive(Debug)]
pub struct SandboxState {
    limits: StoreLimits,
}

impl SandboxState {
    fn new(config: &SandboxConfig) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(config.memory_limit)
            .table_elements(MAX_TABLE_ELEMENTS)
            .build();

        Self { limits }
    }
}

/// A sandbox for one skill: a [`SandboxRuntime`] plus the limits to run it
/// with.
///
/// [`WasmSandbox::new`] builds a runtime of its own, which is what the kernel
/// used to do on every call. To share one engine, module cache and epoch
/// ticker across sandboxes, build them with [`WasmSandbox::with_runtime`].
pub struct WasmSandbox {
    runtime: Arc<SandboxRuntime>,
    config: SandboxConfig,
    skill: Option<PreparedSkill>,
}

impl std::fmt::Debug for WasmSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmSandbox")
            .field("config", &self.config)
            .field("module_loaded", &self.skill.is_some())
            .finish_non_exhaustive()
    }
}

impl WasmSandbox {
    /// Create a new WASM sandbox with the given configuration, on a runtime
    /// of its own.
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let runtime = Arc::new(SandboxRuntime::new(SandboxRuntimeConfig::default())?);
        Ok(Self::with_runtime(runtime, config))
    }

    /// Create a sandbox on a shared runtime.
    #[must_use]
    pub fn with_runtime(runtime: Arc<SandboxRuntime>, config: SandboxConfig) -> Self {
        Self {
            runtime,
            config,
            skill: None,
        }
    }

    /// Create a sandbox with default configuration
    pub fn with_defaults() -> Result<Self, SandboxError> {
        Self::new(SandboxConfig::default())
    }

    /// Load a WASM skill module from bytes (binary or text format). Compiled
    /// once per distinct content on the runtime.
    pub fn load_skill(&mut self, wasm_bytes: &[u8]) -> Result<(), SandboxError> {
        self.skill = Some(self.runtime.prepare(wasm_bytes)?);
        Ok(())
    }

    /// Load a WASM skill module from a file path
    pub fn load_skill_from_file(&mut self, path: &std::path::Path) -> Result<(), SandboxError> {
        self.skill = Some(self.runtime.prepare_file(path)?);
        Ok(())
    }

    fn loaded(&self) -> Result<&PreparedSkill, SandboxError> {
        self.skill.as_ref().ok_or_else(|| {
            SandboxError::ModuleLoad("No module loaded. Call load_skill() first.".into())
        })
    }

    /// Execute a function in the loaded WASM module with JSON input/output
    ///
    /// Blocks until the call returns or a limit stops it; from async code,
    /// call it on `tokio::task::spawn_blocking`.
    ///
    /// # Arguments
    /// * `func_name` - Name of the exported function to call
    /// * `input` - JSON value to pass as input
    ///
    /// # Returns
    /// * JSON value returned by the function
    pub fn execute(
        &self,
        func_name: &str,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        self.runtime
            .execute_json(self.loaded()?, &self.config, func_name, input)
    }

    /// Execute a simple function that takes no input and returns an i32
    /// Useful for testing or simple operations
    pub fn execute_simple(&self, func_name: &str) -> Result<i32, SandboxError> {
        self.runtime
            .execute_i32(self.loaded()?, &self.config, func_name)
    }

    /// Get remaining fuel after execution
    pub fn remaining_fuel(&self, store: &Store<SandboxState>) -> u64 {
        store.get_fuel().unwrap_or(0)
    }

    /// Get the current sandbox configuration
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Check if a module is loaded
    pub fn has_module(&self) -> bool {
        self.skill.is_some()
    }

    /// The runtime this sandbox runs on.
    #[must_use]
    pub fn runtime(&self) -> &Arc<SandboxRuntime> {
        &self.runtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.memory_limit, 16 * 1024 * 1024);
        assert_eq!(config.fuel_limit, 1_000_000);
        assert_eq!(config.timeout, Duration::from_secs(5));
    }

    #[test]
    fn test_sandbox_creation() {
        let sandbox = WasmSandbox::with_defaults();
        assert!(sandbox.is_ok());

        let sandbox = sandbox.unwrap();
        assert!(!sandbox.has_module());
    }

    #[test]
    fn test_custom_config() {
        let config = SandboxConfig {
            memory_limit: 8 * 1024 * 1024,
            fuel_limit: 500_000,
            timeout: Duration::from_secs(10),
        };

        let sandbox = WasmSandbox::new(config.clone());
        assert!(sandbox.is_ok());

        let sandbox = sandbox.unwrap();
        assert_eq!(sandbox.config().memory_limit, 8 * 1024 * 1024);
        assert_eq!(sandbox.config().fuel_limit, 500_000);
    }

    #[test]
    fn test_load_invalid_wasm() {
        let mut sandbox = WasmSandbox::with_defaults().unwrap();
        let result = sandbox.load_skill(b"not valid wasm");
        assert!(result.is_err());

        if let Err(SandboxError::ModuleLoad(_)) = result {
            // Expected error type
        } else {
            panic!("Expected ModuleLoad error");
        }
    }

    #[test]
    fn test_execute_without_module() {
        let sandbox = WasmSandbox::with_defaults().unwrap();
        let result = sandbox.execute("test", &serde_json::json!({}));
        assert!(result.is_err());
    }

    /// A module implementing the skill ABI (`alloc`, then
    /// `execute(ptr, len) -> out_ptr` with a little-endian length prefix at
    /// `out_ptr`). `execute` echoes its input; `spin` never returns.
    const ECHO_SKILL_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $p))
          (func (export "execute") (param $ptr i32) (param $len i32) (result i32)
            (i32.store (i32.const 0) (local.get $len))
            (memory.copy (i32.const 4) (local.get $ptr) (local.get $len))
            (i32.const 0))
          (func (export "answer") (result i32)
            (i32.const 42))
          (func (export "spin") (result i32)
            (loop $l (br $l))
            (i32.const 0)))
    "#;

    fn echo_sandbox(config: SandboxConfig) -> WasmSandbox {
        let mut sandbox = WasmSandbox::new(config).unwrap();
        sandbox.load_skill(ECHO_SKILL_WAT.as_bytes()).unwrap();
        sandbox
    }

    #[test]
    fn test_execute_runs_a_real_module() {
        // Regression: epoch interruption was enabled with no deadline set, and
        // Wasmtime's default deadline is 0, so every skill trapped on entry.
        let sandbox = echo_sandbox(SandboxConfig::default());
        let input = serde_json::json!({"operation": "add", "operands": [1, 2]});
        assert_eq!(sandbox.execute("execute", &input).unwrap(), input);
    }

    #[test]
    fn test_execute_simple_runs_a_real_module() {
        let sandbox = echo_sandbox(SandboxConfig::default());
        assert_eq!(sandbox.execute_simple("answer").unwrap(), 42);
    }

    #[test]
    fn test_wall_clock_timeout_interrupts_infinite_loop() {
        // Enough fuel that only the wall-clock deadline can stop the loop.
        let sandbox = echo_sandbox(SandboxConfig {
            fuel_limit: u64::MAX / 2,
            timeout: Duration::from_millis(100),
            ..SandboxConfig::default()
        });
        let started = Instant::now();
        let result = sandbox.execute_simple("spin");
        assert!(
            matches!(result, Err(SandboxError::Timeout(_))),
            "expected timeout, got {result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_fuel_limit_interrupts_infinite_loop() {
        let sandbox = echo_sandbox(SandboxConfig {
            fuel_limit: 10_000,
            timeout: Duration::from_secs(30),
            ..SandboxConfig::default()
        });
        assert!(matches!(
            sandbox.execute_simple("spin"),
            Err(SandboxError::FuelExhausted)
        ));
    }

    #[test]
    fn test_concurrent_executions_do_not_cut_each_other_short() {
        // All executions share one engine epoch. A deadline expressed in
        // ticks would let one execution's ticks expire another; the deadline
        // must be wall-clock per store.
        let sandbox = std::sync::Arc::new(echo_sandbox(SandboxConfig {
            fuel_limit: u64::MAX / 2,
            timeout: Duration::from_millis(400),
            ..SandboxConfig::default()
        }));
        let spinners: Vec<_> = (0..4)
            .map(|_| {
                let sandbox = std::sync::Arc::clone(&sandbox);
                std::thread::spawn(move || {
                    let started = Instant::now();
                    let result = sandbox.execute_simple("spin");
                    (result, started.elapsed())
                })
            })
            .collect();
        for spinner in spinners {
            let (result, elapsed) = spinner.join().unwrap();
            assert!(matches!(result, Err(SandboxError::Timeout(_))));
            assert!(
                elapsed >= Duration::from_millis(400),
                "interrupted early after {elapsed:?}"
            );
        }
    }
}
