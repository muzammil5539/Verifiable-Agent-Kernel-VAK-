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

pub mod epoch_ticker;
pub mod marketplace;
pub mod pooling;
pub mod registry;

// Re-export registry types for convenient access
pub use registry::{
    PermissionError, RegistryError, SignatureConfig, SignatureError, SignatureVerificationResult,
    SkillId, SkillManifest, SkillPermissions, SkillRegistry, SkillSignatureVerifier,
};

// Re-export marketplace types
pub use marketplace::{
    MarketplaceClient, MarketplaceConfig, MarketplaceError, MarketplaceSkill,
    SkillCategory, SkillLicense, SkillQuery, SkillReview, SearchResults,
    InstallResult, UninstallResult, Publisher, SortOrder,
};

// Re-export epoch ticker types (RT-001)
pub use epoch_ticker::{
    EpochTicker, EpochTickerBuilder, EpochTickerConfig, EpochTickerError, EpochTickerStats,
};

// Re-export pooling types (RT-003)
pub use pooling::{
    PoolingConfig, PoolingError, PoolingStats, PoolManager,
    create_pooling_engine, create_standard_engine,
};

use std::time::{Duration, Instant};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};

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
}

/// Store data holding resource limits and state
#[derive(Debug)]
pub struct SandboxState {
    limits: StoreLimits,
    start_time: Option<Instant>,
    timeout: Duration,
}

impl SandboxState {
    fn new(config: &SandboxConfig) -> Self {
        let limits = StoreLimitsBuilder::new()
            .memory_size(config.memory_limit)
            .build();

        Self {
            limits,
            start_time: None,
            timeout: config.timeout,
        }
    }

    fn start_execution(&mut self) {
        self.start_time = Some(Instant::now());
    }

    fn check_timeout(&self) -> bool {
        self.start_time
            .map(|start| start.elapsed() > self.timeout)
            .unwrap_or(false)
    }
}

/// WASM Sandbox for isolated skill execution
pub struct WasmSandbox {
    engine: Engine,
    config: SandboxConfig,
    module: Option<Module>,
}

impl std::fmt::Debug for WasmSandbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmSandbox")
            .field("config", &self.config)
            .field("module_loaded", &self.module.is_some())
            .finish_non_exhaustive()
    }
}

impl WasmSandbox {
    /// Create a new WASM sandbox with the given configuration
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let mut wasm_config = Config::new();

        // Enable fuel consumption for CPU limiting
        wasm_config.consume_fuel(true);

        // Enable epoch interruption for timeout handling
        wasm_config.epoch_interruption(true);

        let engine =
            Engine::new(&wasm_config).map_err(|e| SandboxError::EngineCreation(e.to_string()))?;

        Ok(Self {
            engine,
            config,
            module: None,
        })
    }

    /// Create a sandbox with default configuration
    pub fn with_defaults() -> Result<Self, SandboxError> {
        Self::new(SandboxConfig::default())
    }

    /// Load a WASM skill module from bytes
    pub fn load_skill(&mut self, wasm_bytes: &[u8]) -> Result<(), SandboxError> {
        let module = Module::new(&self.engine, wasm_bytes)
            .map_err(|e| SandboxError::ModuleLoad(e.to_string()))?;

        self.module = Some(module);
        Ok(())
    }

    /// Load a WASM skill module from a file path
    pub fn load_skill_from_file(&mut self, path: &std::path::Path) -> Result<(), SandboxError> {
        let module = Module::from_file(&self.engine, path)
            .map_err(|e| SandboxError::ModuleLoad(e.to_string()))?;

        self.module = Some(module);
        Ok(())
    }

    /// Execute a function in the loaded WASM module with JSON input/output
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
        let module = self.module.as_ref().ok_or_else(|| {
            SandboxError::ModuleLoad("No module loaded. Call load_skill() first.".into())
        })?;

        // Create store with resource limits
        let state = SandboxState::new(&self.config);
        let mut store = Store::new(&self.engine, state);

        // Configure resource limits
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.config.fuel_limit)
            .map_err(|e| SandboxError::EngineCreation(format!("Failed to set fuel: {}", e)))?;

        // Set up epoch deadline for timeout
        store.epoch_deadline_trap();

        // Create linker and instantiate module
        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| SandboxError::Instantiation(e.to_string()))?;

        // Serialize input to JSON string
        let input_json =
            serde_json::to_string(input).map_err(|e| SandboxError::InvalidInput(e.to_string()))?;

        // Get memory and required functions
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| SandboxError::Instantiation("Module has no exported memory".into()))?;

        // Try to get allocation function (standard WASM interface)
        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| SandboxError::FunctionNotFound("alloc".into()))?;

        // Allocate memory for input in guest
        let input_bytes = input_json.as_bytes();
        let input_len = input_bytes.len() as i32;

        store.data_mut().start_execution();

        let input_ptr = alloc_fn.call(&mut store, input_len).map_err(|_e| {
            if store.get_fuel().unwrap_or(0) == 0 {
                SandboxError::FuelExhausted
            } else if store.data().check_timeout() {
                SandboxError::Timeout(self.config.timeout)
            } else {
                SandboxError::GuestAllocation
            }
        })?;

        // Write input to guest memory
        memory
            .write(&mut store, input_ptr as usize, input_bytes)
            .map_err(|_| SandboxError::MemoryLimitExceeded)?;

        // Get and call the target function
        // Expected signature: func(input_ptr: i32, input_len: i32) -> i32 (output_ptr)
        let target_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, func_name)
            .map_err(|_| SandboxError::FunctionNotFound(func_name.into()))?;

        let output_ptr = target_fn
            .call(&mut store, (input_ptr, input_len))
            .map_err(|e| {
                if store.get_fuel().unwrap_or(0) == 0 {
                    SandboxError::FuelExhausted
                } else if store.data().check_timeout() {
                    SandboxError::Timeout(self.config.timeout)
                } else {
                    SandboxError::Execution(e.to_string())
                }
            })?;

        // Read output length (first 4 bytes at output_ptr)
        let mut len_bytes = [0u8; 4];
        memory
            .read(&store, output_ptr as usize, &mut len_bytes)
            .map_err(|_| SandboxError::InvalidOutput("Failed to read output length".into()))?;
        let output_len = i32::from_le_bytes(len_bytes) as usize;

        // Read output JSON string
        let mut output_bytes = vec![0u8; output_len];
        memory
            .read(&store, (output_ptr + 4) as usize, &mut output_bytes)
            .map_err(|_| SandboxError::InvalidOutput("Failed to read output data".into()))?;

        // Parse output JSON
        let output_json = String::from_utf8(output_bytes)
            .map_err(|e| SandboxError::InvalidOutput(e.to_string()))?;

        serde_json::from_str(&output_json).map_err(|e| SandboxError::InvalidOutput(e.to_string()))
    }

    /// Execute a simple function that takes no input and returns an i32
    /// Useful for testing or simple operations
    pub fn execute_simple(&self, func_name: &str) -> Result<i32, SandboxError> {
        let module = self.module.as_ref().ok_or_else(|| {
            SandboxError::ModuleLoad("No module loaded. Call load_skill() first.".into())
        })?;

        let state = SandboxState::new(&self.config);
        let mut store = Store::new(&self.engine, state);

        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.config.fuel_limit)
            .map_err(|e| SandboxError::EngineCreation(format!("Failed to set fuel: {}", e)))?;

        let linker = Linker::new(&self.engine);
        let instance = linker
            .instantiate(&mut store, module)
            .map_err(|e| SandboxError::Instantiation(e.to_string()))?;

        let func = instance
            .get_typed_func::<(), i32>(&mut store, func_name)
            .map_err(|_| SandboxError::FunctionNotFound(func_name.into()))?;

        store.data_mut().start_execution();

        func.call(&mut store, ()).map_err(|e| {
            if store.get_fuel().unwrap_or(0) == 0 {
                SandboxError::FuelExhausted
            } else if store.data().check_timeout() {
                SandboxError::Timeout(self.config.timeout)
            } else {
                SandboxError::Execution(e.to_string())
            }
        })
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
        self.module.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
