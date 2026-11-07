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

    /// A limit that couldn't be applied to the store
    #[error("Execution limit not applied: {0}")]
    NotApplied(String),
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

    /// Calculate total budget in milliseconds, saturating at `u64::MAX`.
    /// The product used to be unchecked, a panic in debug builds.
    pub fn budget_ms(&self) -> u64 {
        self.epoch_budget.saturating_mul(self.tick_interval_ms)
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
    pub fn set_deadline_async_yield<T>(store: &mut Store<T>, config: &EpochConfig) {
        let increment = config.yield_increment;
        // Set initial deadline
        store.set_epoch_deadline(config.epoch_budget);
        // Configure async yield with increment
        // In newer wasmtime, this just takes the increment value directly
        store.epoch_deadline_async_yield_and_update(increment);
        debug!(
            budget_epochs = config.epoch_budget,
            yield_increment = increment,
            "Set epoch deadline (async yield mode)"
        );
    }

    /// Sets the deadline to `epochs` from the engine's current epoch.
    ///
    /// This replaces the deadline rather than adding to it: Wasmtime can't
    /// report a store's deadline, so there is nothing to add to. A deadline
    /// further off than `epochs` comes nearer. (It used to say it extended
    /// the deadline.)
    pub fn extend_deadline<T>(store: &mut Store<T>, epochs: u64) {
        store.set_epoch_deadline(epochs);
        debug!(epochs, "Reset epoch deadline");
    }

    /// Always `None`: Wasmtime doesn't expose a store's deadline, and this
    /// doesn't track it. (It used to say it returned `None` only without
    /// epochs enabled.) Use [`PreemptionBudget`] to track a budget.
    pub fn remaining_epochs<T>(_store: &Store<T>) -> Option<u64> {
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

    /// Record epoch consumption, saturating at `u64::MAX`. The sum used to
    /// be unchecked: a panic in debug builds, and in release a wrap back to
    /// a small count that un-exhausted the budget.
    pub fn record_consumption(&self, epochs: u64) {
        let previous = self
            .consumed
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_add(epochs))
            })
            .unwrap_or_default();
        let new_consumed = previous.saturating_add(epochs);
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

    /// Add more budget, saturating at `u64::MAX`. The sum used to wrap,
    /// shrinking the budget.
    pub fn add_budget(&self, epochs: u64) {
        let _ = self
            .total_budget
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                Some(n.saturating_add(epochs))
            });
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
    /// Applies the limits to a store: the epoch deadline, trapping or, with
    /// `async_yield`, yielding; and the fuel limit.
    ///
    /// # Errors
    ///
    /// [`EpochConfigError::NotApplied`], having applied nothing, if a limit
    /// can't be applied: a memory limit, which needs a `ResourceLimiter`
    /// in the store's data, or fuel on an engine without fuel metering.
    /// Each used to be skipped silently, leaving the store unlimited, and
    /// `async_yield` was ignored.
    pub fn apply<T>(&self, store: &mut Store<T>) -> Result<(), EpochConfigError> {
        if let Some(bytes) = self.memory_limit {
            return Err(EpochConfigError::NotApplied(format!(
                "a {bytes}-byte memory limit needs a ResourceLimiter in the store's data \
                 (wasmtime::StoreLimits); apply can't install one"
            )));
        }
        // get_fuel fails exactly when the engine doesn't meter fuel.
        if self.fuel_limit.is_some() && store.get_fuel().is_err() {
            return Err(EpochConfigError::NotApplied(
                "the engine doesn't meter fuel, so a fuel limit can't apply".into(),
            ));
        }

        // Set epoch deadline
        if self.epoch_config.async_yield {
            EpochDeadlineManager::set_deadline_async_yield(store, &self.epoch_config);
        } else {
            EpochDeadlineManager::set_deadline(store, &self.epoch_config);
        }

        // Set fuel if configured
        if let Some(fuel) = self.fuel_limit {
            store
                .set_fuel(fuel)
                .map_err(|e| EpochConfigError::NotApplied(e.to_string()))?;
        }

        debug!(
            epoch_budget = self.epoch_config.epoch_budget,
            fuel_limit = ?self.fuel_limit,
            memory_limit = ?self.memory_limit,
            "Applied execution limits to store"
        );
        Ok(())
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

    #[test]
    fn test_budget_arithmetic_saturates() {
        // Each sum or product was unchecked: a panic in debug builds, and
        // in release a wrap that un-exhausted or shrank the budget.
        let huge = EpochConfig {
            epoch_budget: u64::MAX,
            ..EpochConfig::default()
        };
        assert_eq!(huge.budget_ms(), u64::MAX);

        let budget = PreemptionBudget::new(10);
        budget.record_consumption(u64::MAX);
        budget.record_consumption(5);
        assert!(budget.is_exhausted());
        assert_eq!(budget.stats().consumed, u64::MAX);
        assert_eq!(budget.remaining(), 0);

        let budget = PreemptionBudget::new(u64::MAX - 1);
        budget.add_budget(5);
        assert_eq!(budget.stats().total, u64::MAX);
        budget.record_consumption(u64::MAX);
        assert!(budget.is_exhausted());
        budget.add_budget(1);
        assert!(budget.is_exhausted(), "nothing remains");
    }

    const SPIN_WAT: &str = r#"
        (module
          (func (export "answer") (result i32) (i32.const 42)))
    "#;

    fn epoch_store(fuel: bool) -> (wasmtime::Engine, Store<()>, wasmtime::Instance) {
        let mut config = wasmtime::Config::new();
        config.epoch_interruption(true).consume_fuel(fuel);
        let engine = wasmtime::Engine::new(&config).unwrap();
        let module = wasmtime::Module::new(&engine, SPIN_WAT).unwrap();
        let mut store = Store::new(&engine, ());
        if fuel {
            store.set_fuel(1_000).unwrap();
        }
        store.set_epoch_deadline(1_000);
        let instance = wasmtime::Instance::new(&mut store, &module, &[]).unwrap();
        (engine, store, instance)
    }

    fn answer(store: &mut Store<()>, instance: &wasmtime::Instance) -> wasmtime::Result<i32> {
        instance
            .get_typed_func::<(), i32>(&mut *store, "answer")
            .unwrap()
            .call(&mut *store, ())
    }

    #[test]
    fn test_limits_apply_or_say_why_not() {
        // A memory limit, and fuel on an engine without fuel metering, were
        // skipped silently; async_yield was ignored.
        let (engine, mut store, instance) = epoch_store(false);
        let limits = EpochExecutionBuilder::new()
            .budget_epochs(1)
            .with_memory(1 << 20)
            .build()
            .unwrap();
        let err = limits.apply(&mut store).unwrap_err();
        assert!(err.to_string().contains("ResourceLimiter"), "{err}");
        let fueled = EpochExecutionBuilder::new()
            .budget_epochs(1)
            .with_fuel(100)
            .build()
            .unwrap();
        let err = fueled.apply(&mut store).unwrap_err();
        assert!(err.to_string().contains("doesn't meter fuel"), "{err}");
        assert_eq!(
            answer(&mut store, &instance).unwrap(),
            42,
            "nothing applied"
        );

        // The epoch deadline applies: one tick past it, the call traps.
        let plain = EpochExecutionBuilder::new()
            .budget_epochs(1)
            .build()
            .unwrap();
        plain.apply(&mut store).unwrap();
        engine.increment_epoch();
        assert!(answer(&mut store, &instance).is_err(), "past the deadline");
        EpochDeadlineManager::extend_deadline(&mut store, 5);
        assert_eq!(answer(&mut store, &instance).unwrap(), 42, "a new deadline");
        assert_eq!(EpochDeadlineManager::remaining_epochs(&store), None);

        let (_engine, mut store, instance) = epoch_store(true);
        fueled.apply(&mut store).unwrap();
        assert_eq!(store.get_fuel().unwrap(), 100);
        assert_eq!(answer(&mut store, &instance).unwrap(), 42);

        // async_yield chooses the yielding deadline.
        let yielding = EpochExecutionBuilder::default()
            .budget_ms(50)
            .async_yield()
            .yield_increment(3)
            .build()
            .unwrap();
        assert!(yielding.epoch_config.async_yield);
        assert_eq!(yielding.epoch_config.yield_increment, 3);
        let (_engine, mut store, instance) = epoch_store(false);
        yielding.apply(&mut store).unwrap();
        // A yielding store needs the async call APIs; a trapping one doesn't.
        let err = answer(&mut store, &instance).unwrap_err();
        assert!(format!("{err:#}").contains("_async"), "{err:#}");
        EpochDeadlineManager::set_deadline_async_yield(
            &mut store,
            &EpochConfig::async_with_budget_ms(20),
        );

        assert!(EpochExecutionBuilder::new()
            .budget_epochs(0)
            .build()
            .is_err());
        assert!(EpochConfigError::NotApplied("x".into())
            .to_string()
            .contains("not applied"));
    }
}
