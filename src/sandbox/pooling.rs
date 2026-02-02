//! Pooling Allocator for Memory Hardening (RT-003)
//!
//! This module implements a pooling allocation strategy for WASM instances
//! to prevent memory exhaustion attacks and reduce allocation overhead.
//!
//! # Architecture
//!
//! The pooling allocator pre-allocates a large slab of memory at startup
//! and divides it into fixed-size slots. Each agent instance gets a slot,
//! enforcing strict memory limits per agent.
//!
//! # Benefits
//!
//! - Prevents OOM attacks where agents recursively grow memory
//! - Reduces instantiation time to microseconds by reusing slots
//! - Eliminates virtual memory fragmentation
//! - Provides predictable memory usage
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::pooling::{PoolingConfig, create_pooling_engine};
//!
//! let config = PoolingConfig::default();
//! let engine = create_pooling_engine(&config).unwrap();
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.1.2: Memory Isolation and the Pooling Allocator
//! - Wasmtime Store Limits documentation

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};
use wasmtime::{Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig};

/// Errors that can occur with pooling allocation
#[derive(Debug, Error)]
pub enum PoolingError {
    /// Failed to create engine with pooling config
    #[error("Failed to create pooling engine: {0}")]
    EngineCreation(String),

    /// Pool exhausted - no available slots
    #[error("Instance pool exhausted: {0} instances in use")]
    PoolExhausted(u32),

    /// Configuration error
    #[error("Invalid pooling configuration: {0}")]
    ConfigError(String),

    /// Memory limit exceeded
    #[error("Memory limit exceeded: requested {requested} bytes, limit {limit} bytes")]
    MemoryLimitExceeded { requested: usize, limit: usize },
}

/// Configuration for the pooling allocator
///
/// These limits follow the recommendations from Gap Analysis Section 2.1.2:
/// - Linear memory restricted to 512MB per instance
/// - Table elements limited to 10,000
#[derive(Debug, Clone)]
pub struct PoolingConfig {
    /// Maximum number of concurrent instances (default: 100)
    pub max_instances: u32,
    /// Maximum memory per instance in bytes (default: 512MB)
    pub max_memory_per_instance: usize,
    /// Maximum table elements per instance (default: 10,000)
    pub max_table_elements: u32,
    /// Maximum tables per instance (default: 1)
    pub max_tables: u32,
    /// Maximum memories per instance (default: 1)
    pub max_memories: u32,
    /// Memory pages to pre-reserve (default: 1000 = ~64MB)
    pub memory_pages: u64,
    /// Enable epoch interruption (default: true)
    pub epoch_interruption: bool,
    /// Enable fuel consumption (default: true)
    pub consume_fuel: bool,
}

impl Default for PoolingConfig {
    fn default() -> Self {
        Self {
            max_instances: 100,
            // 512MB as specified in Gap Analysis
            max_memory_per_instance: 512 * 1024 * 1024,
            // 10,000 as specified in Gap Analysis
            max_table_elements: 10_000,
            max_tables: 1,
            max_memories: 1,
            memory_pages: 1000,
            epoch_interruption: true,
            consume_fuel: true,
        }
    }
}

impl PoolingConfig {
    /// Create a minimal config for testing
    pub fn minimal() -> Self {
        Self {
            max_instances: 10,
            max_memory_per_instance: 64 * 1024 * 1024, // 64MB
            max_table_elements: 1000,
            max_tables: 1,
            max_memories: 1,
            memory_pages: 100,
            epoch_interruption: true,
            consume_fuel: true,
        }
    }

    /// Create a high-density config for many small agents
    pub fn high_density() -> Self {
        Self {
            max_instances: 1000,
            max_memory_per_instance: 32 * 1024 * 1024, // 32MB
            max_table_elements: 1000,
            max_tables: 1,
            max_memories: 1,
            memory_pages: 500,
            epoch_interruption: true,
            consume_fuel: true,
        }
    }

    /// Create a config for resource-intensive agents
    pub fn resource_intensive() -> Self {
        Self {
            max_instances: 20,
            max_memory_per_instance: 1024 * 1024 * 1024, // 1GB
            max_table_elements: 100_000,
            max_tables: 4,
            max_memories: 4,
            memory_pages: 10000,
            epoch_interruption: true,
            consume_fuel: true,
        }
    }

    /// Set max instances
    pub fn with_max_instances(mut self, count: u32) -> Self {
        self.max_instances = count;
        self
    }

    /// Set max memory per instance
    pub fn with_max_memory(mut self, bytes: usize) -> Self {
        self.max_memory_per_instance = bytes;
        self
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), PoolingError> {
        if self.max_instances == 0 {
            return Err(PoolingError::ConfigError(
                "max_instances must be greater than 0".to_string(),
            ));
        }
        if self.max_memory_per_instance == 0 {
            return Err(PoolingError::ConfigError(
                "max_memory_per_instance must be greater than 0".to_string(),
            ));
        }
        if self.max_table_elements == 0 {
            return Err(PoolingError::ConfigError(
                "max_table_elements must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Statistics for pooling allocator usage
#[derive(Debug, Default)]
pub struct PoolingStats {
    /// Number of instances currently allocated
    pub instances_allocated: AtomicU64,
    /// Peak number of instances ever allocated
    pub peak_instances: AtomicU64,
    /// Total number of instance allocations
    pub total_allocations: AtomicU64,
    /// Total number of instance deallocations
    pub total_deallocations: AtomicU64,
}

impl PoolingStats {
    /// Record an allocation
    pub fn record_allocation(&self) {
        let current = self.instances_allocated.fetch_add(1, Ordering::Relaxed) + 1;
        self.total_allocations.fetch_add(1, Ordering::Relaxed);

        // Update peak if necessary
        let mut peak = self.peak_instances.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_instances.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }

    /// Record a deallocation
    pub fn record_deallocation(&self) {
        self.instances_allocated.fetch_sub(1, Ordering::Relaxed);
        self.total_deallocations.fetch_add(1, Ordering::Relaxed);
    }

    /// Get current instance count
    pub fn current_instances(&self) -> u64 {
        self.instances_allocated.load(Ordering::Relaxed)
    }

    /// Get peak instance count
    pub fn peak(&self) -> u64 {
        self.peak_instances.load(Ordering::Relaxed)
    }
}

/// Create a Wasmtime engine with pooling allocation strategy
///
/// This function creates an engine configured for high-density agent hosting
/// with memory limits enforced at the allocator level.
pub fn create_pooling_engine(config: &PoolingConfig) -> Result<Engine, PoolingError> {
    config.validate()?;

    let mut engine_config = Config::new();

    // Enable required features
    if config.epoch_interruption {
        engine_config.epoch_interruption(true);
    }
    if config.consume_fuel {
        engine_config.consume_fuel(true);
    }

    // Configure pooling allocation
    let mut pooling_config = PoolingAllocationConfig::default();

    // Set instance limits
    pooling_config.total_component_instances(config.max_instances);
    pooling_config.total_memories(config.max_instances * config.max_memories);
    pooling_config.total_tables(config.max_instances * config.max_tables);

    // Set per-instance limits
    pooling_config.max_memories_per_component(config.max_memories);
    pooling_config.max_tables_per_component(config.max_tables);
    pooling_config.table_elements(config.max_table_elements as usize);

    // Set memory limits
    pooling_config.max_memory_size(config.max_memory_per_instance);

    info!(
        max_instances = config.max_instances,
        max_memory_mb = config.max_memory_per_instance / (1024 * 1024),
        max_table_elements = config.max_table_elements,
        "Creating pooling engine"
    );

    // Apply pooling strategy
    engine_config.allocation_strategy(InstanceAllocationStrategy::Pooling(pooling_config));

    Engine::new(&engine_config).map_err(|e| PoolingError::EngineCreation(e.to_string()))
}

/// Create a standard (non-pooling) engine for comparison or fallback
pub fn create_standard_engine(
    epoch_interruption: bool,
    consume_fuel: bool,
) -> Result<Engine, PoolingError> {
    let mut config = Config::new();

    if epoch_interruption {
        config.epoch_interruption(true);
    }
    if consume_fuel {
        config.consume_fuel(true);
    }

    Engine::new(&config).map_err(|e| PoolingError::EngineCreation(e.to_string()))
}

/// Manager for pooled WASM instances
///
/// Tracks instance allocation and provides statistics about pool usage.
pub struct PoolManager {
    engine: Engine,
    config: PoolingConfig,
    stats: Arc<PoolingStats>,
}

impl std::fmt::Debug for PoolManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoolManager")
            .field("config", &self.config)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl PoolManager {
    /// Create a new pool manager with the given configuration
    pub fn new(config: PoolingConfig) -> Result<Self, PoolingError> {
        let engine = create_pooling_engine(&config)?;
        Ok(Self {
            engine,
            config,
            stats: Arc::new(PoolingStats::default()),
        })
    }

    /// Get the underlying engine
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Get the configuration
    pub fn config(&self) -> &PoolingConfig {
        &self.config
    }

    /// Get pool statistics
    pub fn stats(&self) -> &PoolingStats {
        &self.stats
    }

    /// Check if the pool has available capacity
    pub fn has_capacity(&self) -> bool {
        self.stats.current_instances() < self.config.max_instances as u64
    }

    /// Get remaining capacity
    pub fn remaining_capacity(&self) -> u64 {
        let current = self.stats.current_instances();
        let max = self.config.max_instances as u64;
        max.saturating_sub(current)
    }

    /// Record that an instance was allocated from the pool
    pub fn record_allocation(&self) -> Result<(), PoolingError> {
        if !self.has_capacity() {
            return Err(PoolingError::PoolExhausted(self.config.max_instances));
        }
        self.stats.record_allocation();
        debug!(
            current = self.stats.current_instances(),
            max = self.config.max_instances,
            "Instance allocated from pool"
        );
        Ok(())
    }

    /// Record that an instance was returned to the pool
    pub fn record_deallocation(&self) {
        self.stats.record_deallocation();
        debug!(
            current = self.stats.current_instances(),
            "Instance returned to pool"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = PoolingConfig::default();
        assert_eq!(config.max_instances, 100);
        assert_eq!(config.max_memory_per_instance, 512 * 1024 * 1024);
        assert_eq!(config.max_table_elements, 10_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_minimal_config() {
        let config = PoolingConfig::minimal();
        assert_eq!(config.max_instances, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_invalid_config() {
        let config = PoolingConfig {
            max_instances: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_stats() {
        let stats = PoolingStats::default();

        stats.record_allocation();
        stats.record_allocation();
        assert_eq!(stats.current_instances(), 2);
        assert_eq!(stats.peak(), 2);

        stats.record_deallocation();
        assert_eq!(stats.current_instances(), 1);
        assert_eq!(stats.peak(), 2); // Peak should remain

        stats.record_allocation();
        stats.record_allocation();
        assert_eq!(stats.current_instances(), 3);
        assert_eq!(stats.peak(), 3);
    }

    #[test]
    fn test_create_standard_engine() {
        let engine = create_standard_engine(true, true);
        assert!(engine.is_ok());
    }

    // Note: Pooling engine creation test may fail on some systems due to
    // memory requirements. Only run with sufficient resources.
    #[test]
    #[ignore]
    fn test_create_pooling_engine() {
        let config = PoolingConfig::minimal();
        let engine = create_pooling_engine(&config);
        assert!(engine.is_ok());
    }

    #[test]
    #[ignore]
    fn test_pool_manager() {
        let config = PoolingConfig::minimal();
        let manager = PoolManager::new(config).unwrap();

        assert!(manager.has_capacity());
        assert_eq!(manager.remaining_capacity(), 10);

        manager.record_allocation().unwrap();
        assert_eq!(manager.stats().current_instances(), 1);
        assert_eq!(manager.remaining_capacity(), 9);

        manager.record_deallocation();
        assert_eq!(manager.stats().current_instances(), 0);
        assert_eq!(manager.remaining_capacity(), 10);
    }
}
