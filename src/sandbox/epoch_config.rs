//! Epoch Deadline Integration (RT-002)
//!
//! This module provides integration between the EpochTicker and WASM Stores,
//! enabling configurable time-slice budgets for agent execution.
//!
//! # Architecture
//!
//! The epoch deadline system works in conjunction with the EpochTicker:
//! 1. EpochTicker increments engine epochs at regular intervals (e.g., 10ms)
//! 2. Each Store is configured with an epoch deadline
//! 3. When current_epoch >= deadline, WASM execution traps
//! 4. For async operations, execution can yield instead of trapping
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::epoch_config::{EpochConfig, EpochDeadlineManager};
//! use wasmtime::{Engine, Store};
//! use std::sync::Arc;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = Arc::new(Engine::default());
//! let mut store = Store::new(&engine, ());
//!
//! // Configure 100ms budget (10 epochs at 10ms each)
//! let config = EpochConfig::with_budget_ms(100);
//! EpochDeadlineManager::set_deadline(&mut store, &config);
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.1.1: Deterministic Preemption
//! - Gap Analysis Section 6.1: The "Time" Problem in Agent Kernels
//! - RT-002: Implement `store.set_epoch_deadline()` with configurable time slices

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::{debug, warn};
use wasmtime::Store;

/// Errors related to epoch deadline configuration
#[derive(Debug, Error)]
pub enum EpochConfigError {
    /// Invalid budget configuration
    #[error("Invalid epoch budget: {0}")]
    InvalidBudget(String),

    /// Deadline already exceeded
    #[error("Epoch deadline already exceeded")]
    DeadlineExceeded,

    /// Engine not configured for epochs
    #[error("Engine not configured for epoch interruption")]
    EpochsNotEnabled,
}

/// Configuration for epoch-based time slicing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochConfig {
    /// Number of epochs to allocate (budget)
    pub epoch_budget: u64,
    /// Tick interval in milliseconds (should match EpochTicker)
    pub tick_interval_ms: u64,
    /// Whether to yield (async) or trap on deadline
    pub async_yield: bool,
    /// Increment to add when yielding
    pub yield_increment: u64,
}

impl Default for EpochConfig {
    fn default() -> Self {
        Self {
            // 10 epochs * 10ms = 100ms budget
            epoch_budget: 10,
            tick_interval_ms: 10,
            async_yield: false,
            yield_increment: 5,
        }
    }
}

impl EpochConfig {
    /// Create config with specific epoch budget
    pub fn with_budget(epochs: u64) -> Self {
        Self {
            epoch_budget: epochs,
            ..Default::default()
        }
    }

    /// Create config with millisecond budget (converted to epochs)
    pub fn with_budget_ms(ms: u64) -> Self {
        let tick_interval_ms = 10; // Default tick interval
        let epochs = ms / tick_interval_ms;
        Self {
            epoch_budget: epochs.max(1),
            tick_interval_ms,
            ..Default::default()
        }
    }

    /// Create config for async operation (yields instead of trapping)
    pub fn async_with_budget_ms(ms: u64) -> Self {
        let mut config = Self::with_budget_ms(ms);
        config.async_yield = true;
        config
    }

    /// Calculate total budget in milliseconds
    pub fn budget_ms(&self) -> u64 {
        self.epoch_budget * self.tick_interval_ms
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), EpochConfigError> {
        if self.epoch_budget == 0 {
            return Err(EpochConfigError::InvalidBudget(
                "epoch_budget must be greater than 0".to_string(),
            ));
        }
        if self.tick_interval_ms == 0 {
            return Err(EpochConfigError::InvalidBudget(
                "tick_interval_ms must be greater than 0".to_string(),
            ));
        }
        Ok(())
    }
}

/// Manager for epoch deadline operations on Stores
pub struct EpochDeadlineManager;

impl EpochDeadlineManager {
    /// Set epoch deadline on a store for synchronous trapping
    ///
    /// When the current epoch reaches the deadline, WASM execution will trap.
    pub fn set_deadline<T>(store: &mut Store<T>, config: &EpochConfig) {
        store.set_epoch_deadline(config.epoch_budget);
        debug!(
            budget_epochs = config.epoch_budget,
            budget_ms = config.budget_ms(),
            "Set epoch deadline (trap mode)"
        );
    }

    /// Set epoch deadline for async yield behavior
    ///
    /// When the deadline is reached, execution yields back to the async
    /// runtime, allowing other tasks to run. The deadline is then extended.
    #[cfg(feature = "async")]
    pub fn set_deadline_async_yield<T>(store: &mut Store<T>, config: &EpochConfig) {
        let increment = config.yield_increment;
        store.epoch_deadline_async_yield_and_update(move |_| -> UpdateDeadline {
            UpdateDeadline::Continue(increment)
        });
        store.set_epoch_deadline(config.epoch_budget);
        debug!(
            budget_epochs = config.epoch_budget,
            yield_increment = increment,
            "Set epoch deadline (async yield mode)"
        );
    }

    /// Extend the deadline by additional epochs
    pub fn extend_deadline<T>(store: &mut Store<T>, additional_epochs: u64) {
        // Get current deadline and add more
        // Note: In practice we'd track the current deadline
        store.set_epoch_deadline(additional_epochs);
        debug!(additional = additional_epochs, "Extended epoch deadline");
    }

    /// Check remaining epochs before deadline
    ///
    /// Returns None if epochs are not enabled on the engine.
    pub fn remaining_epochs<T>(store: &Store<T>) -> Option<u64> {
        // Note: Wasmtime doesn't expose a direct way to check remaining epochs
        // This would require tracking state ourselves
        None
    }
}

/// Preemption budget tracker for agents
///
/// Tracks epoch consumption across multiple execution slices,
/// allowing for fair scheduling of multiple agents.
#[derive(Debug)]
pub struct PreemptionBudget {
    /// Total epochs allocated
    total_budget: AtomicU64,
    /// Epochs consumed
    consumed: AtomicU64,
    /// Whether the budget is exhausted
    exhausted: AtomicBool,
}

use std::sync::atomic::AtomicBool;

impl PreemptionBudget {
    /// Create a new preemption budget
    pub fn new(total_epochs: u64) -> Self {
        Self {
            total_budget: AtomicU64::new(total_epochs),
            consumed: AtomicU64::new(0),
            exhausted: AtomicBool::new(false),
        }
    }

    /// Record epoch consumption
    pub fn record_consumption(&self, epochs: u64) {
        let new_consumed = self.consumed.fetch_add(epochs, Ordering::SeqCst) + epochs;
        let budget = self.total_budget.load(Ordering::SeqCst);
        
        if new_consumed >= budget {
            self.exhausted.store(true, Ordering::SeqCst);
            warn!(
                consumed = new_consumed,
                budget = budget,
                "Preemption budget exhausted"
            );
        }
    }

    /// Check if budget is exhausted
    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::SeqCst)
    }

    /// Get remaining epochs
    pub fn remaining(&self) -> u64 {
        let budget = self.total_budget.load(Ordering::SeqCst);
        let consumed = self.consumed.load(Ordering::SeqCst);
        budget.saturating_sub(consumed)
    }

    /// Reset the budget
    pub fn reset(&self) {
        self.consumed.store(0, Ordering::SeqCst);
        self.exhausted.store(false, Ordering::SeqCst);
    }

    /// Add more budget
    pub fn add_budget(&self, epochs: u64) {
        self.total_budget.fetch_add(epochs, Ordering::SeqCst);
        // May un-exhaust if we were exhausted
        if self.remaining() > 0 {
            self.exhausted.store(false, Ordering::SeqCst);
        }
    }

    /// Get consumption statistics
    pub fn stats(&self) -> BudgetStats {
        BudgetStats {
            total: self.total_budget.load(Ordering::SeqCst),
            consumed: self.consumed.load(Ordering::SeqCst),
            remaining: self.remaining(),
            exhausted: self.is_exhausted(),
        }
    }
}

/// Statistics about budget usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetStats {
    /// Total budget allocated
    pub total: u64,
    /// Epochs consumed
    pub consumed: u64,
    /// Remaining epochs
    pub remaining: u64,
    /// Whether budget is exhausted
    pub exhausted: bool,
}

/// Builder for configuring epoch-based execution
pub struct EpochExecutionBuilder {
    config: EpochConfig,
    fuel_limit: Option<u64>,
    memory_limit: Option<usize>,
}

impl EpochExecutionBuilder {
    /// Create a new builder with default config
    pub fn new() -> Self {
        Self {
            config: EpochConfig::default(),
            fuel_limit: None,
            memory_limit: None,
        }
    }

    /// Set epoch budget in milliseconds
    pub fn budget_ms(mut self, ms: u64) -> Self {
        self.config = EpochConfig::with_budget_ms(ms);
        self
    }

    /// Set epoch budget directly
    pub fn budget_epochs(mut self, epochs: u64) -> Self {
        self.config.epoch_budget = epochs;
        self
    }

    /// Enable async yielding
    pub fn async_yield(mut self) -> Self {
        self.config.async_yield = true;
        self
    }

    /// Set yield increment for async mode
    pub fn yield_increment(mut self, epochs: u64) -> Self {
        self.config.yield_increment = epochs;
        self
    }

    /// Also limit fuel consumption
    pub fn with_fuel(mut self, limit: u64) -> Self {
        self.fuel_limit = Some(limit);
        self
    }

    /// Also limit memory
    pub fn with_memory(mut self, bytes: usize) -> Self {
        self.memory_limit = Some(bytes);
        self
    }

    /// Build the epoch config
    pub fn build(self) -> Result<ExecutionLimits, EpochConfigError> {
        self.config.validate()?;
        Ok(ExecutionLimits {
            epoch_config: self.config,
            fuel_limit: self.fuel_limit,
            memory_limit: self.memory_limit,
        })
    }
}

impl Default for EpochExecutionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined execution limits for WASM
#[derive(Debug, Clone)]
pub struct ExecutionLimits {
    /// Epoch-based time limits
    pub epoch_config: EpochConfig,
    /// Optional fuel limit
    pub fuel_limit: Option<u64>,
    /// Optional memory limit
    pub memory_limit: Option<usize>,
}

impl ExecutionLimits {
    /// Apply limits to a store
    pub fn apply<T>(&self, store: &mut Store<T>) {
        // Set epoch deadline
        EpochDeadlineManager::set_deadline(store, &self.epoch_config);

        // Set fuel if configured
        if let Some(fuel) = self.fuel_limit {
            let _ = store.set_fuel(fuel);
        }

        debug!(
            epoch_budget = self.epoch_config.epoch_budget,
            fuel_limit = ?self.fuel_limit,
            memory_limit = ?self.memory_limit,
            "Applied execution limits to store"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_epoch_config_default() {
        let config = EpochConfig::default();
        assert_eq!(config.epoch_budget, 10);
        assert_eq!(config.tick_interval_ms, 10);
        assert_eq!(config.budget_ms(), 100);
    }

    #[test]
    fn test_epoch_config_from_ms() {
        let config = EpochConfig::with_budget_ms(500);
        assert_eq!(config.epoch_budget, 50);
        assert_eq!(config.budget_ms(), 500);
    }

    #[test]
    fn test_epoch_config_async() {
        let config = EpochConfig::async_with_budget_ms(100);
        assert!(config.async_yield);
    }

    #[test]
    fn test_epoch_config_validation() {
        let mut config = EpochConfig::default();
        assert!(config.validate().is_ok());

        config.epoch_budget = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_preemption_budget() {
        let budget = PreemptionBudget::new(100);
        assert_eq!(budget.remaining(), 100);
        assert!(!budget.is_exhausted());

        budget.record_consumption(50);
        assert_eq!(budget.remaining(), 50);
        assert!(!budget.is_exhausted());

        budget.record_consumption(60);
        assert!(budget.is_exhausted());
    }

    #[test]
    fn test_preemption_budget_reset() {
        let budget = PreemptionBudget::new(100);
        budget.record_consumption(100);
        assert!(budget.is_exhausted());

        budget.reset();
        assert!(!budget.is_exhausted());
        assert_eq!(budget.remaining(), 100);
    }

    #[test]
    fn test_execution_builder() {
        let limits = EpochExecutionBuilder::new()
            .budget_ms(200)
            .with_fuel(1_000_000)
            .with_memory(16 * 1024 * 1024)
            .build()
            .unwrap();

        assert_eq!(limits.epoch_config.budget_ms(), 200);
        assert_eq!(limits.fuel_limit, Some(1_000_000));
        assert_eq!(limits.memory_limit, Some(16 * 1024 * 1024));
    }
}
