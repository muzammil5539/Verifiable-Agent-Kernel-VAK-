//! Epoch Ticker for Preemptive Agent Termination (RT-001)
//!
//! This module implements a background thread that increments the Wasmtime epoch
//! counter at regular intervals, enabling preemptive termination of runaway agents.
//!
//! # Architecture
//!
//! The EpochTicker spawns a dedicated tokio task that periodically calls
//! `engine.increment_epoch()`. When combined with `store.set_epoch_deadline()`,
//! this provides deterministic preemption of WASM execution.
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::epoch_ticker::{EpochTicker, EpochTickerConfig};
//! use wasmtime::Engine;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = Arc::new(Engine::default());
//! let config = EpochTickerConfig::default();
//! let ticker = EpochTicker::start(engine, config).await?;
//!
//! // Later, stop the ticker
//! ticker.stop().await;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.1.1: Deterministic Preemption
//! - Gap Analysis Section 6.1: The "Time" Problem in Agent Kernels
//! - Wasmtime Config: epoch_interruption(true)

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::time::interval;
use tracing::{debug, info, warn};
use wasmtime::Engine;

/// Errors that can occur with the epoch ticker
#[derive(Debug, Error)]
pub enum EpochTickerError {
    /// Ticker is already running
    #[error("Epoch ticker is already running")]
    AlreadyRunning,

    /// Ticker failed to start
    #[error("Failed to start epoch ticker: {0}")]
    StartFailed(String),

    /// Ticker is not running
    #[error("Epoch ticker is not running")]
    NotRunning,
}

/// Configuration for the epoch ticker
#[derive(Debug, Clone)]
pub struct EpochTickerConfig {
    /// Interval between epoch increments (default: 10ms)
    pub tick_interval: Duration,
    /// Whether to log tick events at debug level
    pub debug_logging: bool,
}

impl Default for EpochTickerConfig {
    fn default() -> Self {
        Self {
            // 10ms interval as specified in Gap Analysis Section 4, Phase 1
            tick_interval: Duration::from_millis(10),
            debug_logging: false,
        }
    }
}

impl EpochTickerConfig {
    /// Create config with custom tick interval
    pub fn with_interval(interval: Duration) -> Self {
        Self {
            tick_interval: interval,
            ..Default::default()
        }
    }

    /// Enable debug logging
    pub fn with_debug_logging(mut self) -> Self {
        self.debug_logging = true;
        self
    }
}

/// Epoch ticker statistics
#[derive(Debug, Default)]
pub struct EpochTickerStats {
    /// Total number of epoch increments
    pub total_ticks: AtomicU64,
    /// Number of ticks since last reset
    pub ticks_since_reset: AtomicU64,
}

impl EpochTickerStats {
    /// Get the total tick count
    pub fn total_ticks(&self) -> u64 {
        self.total_ticks.load(Ordering::Relaxed)
    }

    /// Get ticks since reset
    pub fn ticks_since_reset(&self) -> u64 {
        self.ticks_since_reset.load(Ordering::Relaxed)
    }

    /// Reset the ticks_since_reset counter
    pub fn reset(&self) {
        self.ticks_since_reset.store(0, Ordering::Relaxed);
    }

    /// Increment tick counters
    fn tick(&self) {
        self.total_ticks.fetch_add(1, Ordering::Relaxed);
        self.ticks_since_reset.fetch_add(1, Ordering::Relaxed);
    }
}

/// Background epoch ticker for preemptive WASM termination
///
/// The EpochTicker runs a background task that increments the Wasmtime
/// engine's epoch counter at regular intervals. This enables preemptive
/// termination of agents that exceed their allocated time budget.
pub struct EpochTicker {
    /// Flag indicating if the ticker is running
    running: Arc<AtomicBool>,
    /// Notification channel to stop the ticker
    stop_notify: Arc<Notify>,
    /// Statistics about ticker operation
    stats: Arc<EpochTickerStats>,
    /// Handle to the background task
    task_handle: Option<tokio::task::JoinHandle<()>>,
    /// Configuration
    config: EpochTickerConfig,
}

impl std::fmt::Debug for EpochTicker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpochTicker")
            .field("running", &self.running.load(Ordering::Relaxed))
            .field("total_ticks", &self.stats.total_ticks())
            .field("config", &self.config)
            .finish()
    }
}

impl EpochTicker {
    /// Start a new epoch ticker for the given engine
    ///
    /// This spawns a background task that increments the engine's epoch
    /// counter at regular intervals defined by the configuration.
    ///
    /// # Arguments
    ///
    /// * `engine` - The Wasmtime engine to tick epochs for
    /// * `config` - Configuration for the ticker
    ///
    /// # Returns
    ///
    /// A running EpochTicker instance that can be stopped later
    pub async fn start(
        engine: Arc<Engine>,
        config: EpochTickerConfig,
    ) -> Result<Self, EpochTickerError> {
        let running = Arc::new(AtomicBool::new(true));
        let stop_notify = Arc::new(Notify::new());
        let stats = Arc::new(EpochTickerStats::default());

        let running_clone = running.clone();
        let stop_notify_clone = stop_notify.clone();
        let stats_clone = stats.clone();
        let tick_interval = config.tick_interval;
        let debug_logging = config.debug_logging;

        info!(
            interval_ms = tick_interval.as_millis(),
            "Starting epoch ticker"
        );

        let task_handle = tokio::spawn(async move {
            let mut ticker = interval(tick_interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        if !running_clone.load(Ordering::Relaxed) {
                            break;
                        }

                        // Increment the engine's epoch counter
                        engine.increment_epoch();
                        stats_clone.tick();

                        if debug_logging {
                            debug!(
                                total_ticks = stats_clone.total_ticks(),
                                "Epoch tick"
                            );
                        }
                    }
                    _ = stop_notify_clone.notified() => {
                        info!("Epoch ticker received stop signal");
                        break;
                    }
                }
            }

            info!(
                total_ticks = stats_clone.total_ticks(),
                "Epoch ticker stopped"
            );
        });

        Ok(Self {
            running,
            stop_notify,
            stats,
            task_handle: Some(task_handle),
            config,
        })
    }

    /// Start with default configuration
    pub async fn start_default(engine: Arc<Engine>) -> Result<Self, EpochTickerError> {
        Self::start(engine, EpochTickerConfig::default()).await
    }

    /// Stop the epoch ticker
    ///
    /// This signals the background task to stop and waits for it to complete.
    pub async fn stop(mut self) {
        if !self.running.load(Ordering::Relaxed) {
            warn!("Epoch ticker already stopped");
            return;
        }

        self.running.store(false, Ordering::Relaxed);
        self.stop_notify.notify_one();

        if let Some(handle) = self.task_handle.take() {
            if let Err(e) = handle.await {
                warn!(error = %e, "Error waiting for epoch ticker to stop");
            }
        }
    }

    /// Check if the ticker is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    /// Get ticker statistics
    pub fn stats(&self) -> &EpochTickerStats {
        &self.stats
    }

    /// Get the configuration
    pub fn config(&self) -> &EpochTickerConfig {
        &self.config
    }

    /// Reset tick counters (useful for per-agent tracking)
    pub fn reset_stats(&self) {
        self.stats.reset();
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        if self.running.load(Ordering::Relaxed) {
            self.running.store(false, Ordering::Relaxed);
            self.stop_notify.notify_one();
        }
    }
}

/// Builder for creating epoch tickers with custom configuration
#[derive(Debug, Default)]
pub struct EpochTickerBuilder {
    config: EpochTickerConfig,
}

impl EpochTickerBuilder {
    /// Create a new builder with default configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the tick interval
    pub fn tick_interval(mut self, interval: Duration) -> Self {
        self.config.tick_interval = interval;
        self
    }

    /// Enable debug logging
    pub fn debug_logging(mut self, enabled: bool) -> Self {
        self.config.debug_logging = enabled;
        self
    }

    /// Build and start the ticker
    pub async fn start(self, engine: Arc<Engine>) -> Result<EpochTicker, EpochTickerError> {
        EpochTicker::start(engine, self.config).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmtime::Config;

    fn create_test_engine() -> Arc<Engine> {
        let mut config = Config::new();
        config.epoch_interruption(true);
        Arc::new(Engine::new(&config).expect("Failed to create engine"))
    }

    #[tokio::test]
    async fn test_epoch_ticker_starts_and_stops() {
        let engine = create_test_engine();
        let ticker = EpochTicker::start_default(engine).await.unwrap();

        assert!(ticker.is_running());

        // Let it tick a few times
        tokio::time::sleep(Duration::from_millis(50)).await;

        assert!(ticker.stats().total_ticks() > 0);

        ticker.stop().await;
    }

    #[tokio::test]
    async fn test_epoch_ticker_custom_interval() {
        let engine = create_test_engine();
        let config = EpochTickerConfig::with_interval(Duration::from_millis(5));
        let ticker = EpochTicker::start(engine, config).await.unwrap();

        // Let it tick
        tokio::time::sleep(Duration::from_millis(100)).await;

        // With 5ms interval, we should have ~20 ticks in 100ms
        let ticks = ticker.stats().total_ticks();
        assert!(ticks >= 10, "Expected at least 10 ticks, got {}", ticks);

        ticker.stop().await;
    }

    #[tokio::test]
    async fn test_epoch_ticker_builder() {
        let engine = create_test_engine();
        let ticker = EpochTickerBuilder::new()
            .tick_interval(Duration::from_millis(20))
            .debug_logging(false)
            .start(engine)
            .await
            .unwrap();

        assert!(ticker.is_running());
        assert_eq!(ticker.config().tick_interval, Duration::from_millis(20));

        ticker.stop().await;
    }

    #[tokio::test]
    async fn test_stats_reset() {
        let engine = create_test_engine();
        let ticker = EpochTicker::start_default(engine).await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        let initial_ticks = ticker.stats().ticks_since_reset();
        assert!(initial_ticks > 0);

        ticker.reset_stats();
        assert_eq!(ticker.stats().ticks_since_reset(), 0);

        // Total ticks should still reflect all ticks
        assert!(ticker.stats().total_ticks() >= initial_ticks);

        ticker.stop().await;
    }
}
