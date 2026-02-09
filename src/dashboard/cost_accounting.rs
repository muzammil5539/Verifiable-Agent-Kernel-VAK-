//! Cost Accounting System (OBS-003)
//!
//! Provides precise cost tracking for agent execution, including:
//! - Token usage (input/output)
//! - WASM fuel consumption
//! - I/O bytes transferred
//! - API call costs
//!
//! Enables micro-billing for agent execution in multi-tenant environments.
//!
//! # Overview
//!
//! The cost accounting system tracks:
//! - LLM token consumption (input and output tokens)
//! - WASM execution fuel (deterministic compute units)
//! - Network I/O bytes (ingress and egress)
//! - Storage operations (reads and writes)
//! - API calls to external services
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::dashboard::cost_accounting::{CostAccountant, CostConfig, ExecutionCost};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let accountant = CostAccountant::new(CostConfig::default());
//!
//! // Track token usage
//! accountant.record_tokens("agent-1", "session-1", 500, 150).await?;
//!
//! // Track fuel consumption
//! accountant.record_fuel("agent-1", "session-1", 10000).await?;
//!
//! // Get cost summary
//! let cost = accountant.get_session_cost("agent-1", "session-1").await?;
//! println!("Total cost: ${:.6}", cost.total_cost_usd);
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 3.4: Cost Accounting

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during cost accounting
#[derive(Debug, Error)]
pub enum CostError {
    /// Session not found
    #[error("Session not found: agent={agent_id}, session={session_id}")]
    SessionNotFound {
        /// Agent ID
        agent_id: String,
        /// Session ID
        session_id: String,
    },

    /// Budget exceeded
    #[error("Budget exceeded: limit=${limit:.6}, current=${current:.6}")]
    BudgetExceeded {
        /// Budget limit
        limit: f64,
        /// Current cost
        current: f64,
    },

    /// Invalid cost configuration
    #[error("Invalid cost configuration: {0}")]
    InvalidConfig(String),

    /// Rate calculation error
    #[error("Rate calculation error: {0}")]
    RateError(String),
}

/// Result type for cost accounting operations
pub type CostResult<T> = Result<T, CostError>;

// ============================================================================
// Cost Configuration
// ============================================================================

/// Pricing rates for different resource types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingRates {
    /// Cost per 1000 input tokens (USD)
    pub input_tokens_per_1k: f64,
    /// Cost per 1000 output tokens (USD)
    pub output_tokens_per_1k: f64,
    /// Cost per 1M WASM fuel units (USD)
    pub fuel_per_1m: f64,
    /// Cost per GB of network I/O (USD)
    pub io_per_gb: f64,
    /// Cost per 1000 storage operations (USD)
    pub storage_ops_per_1k: f64,
    /// Cost per external API call (USD)
    pub api_call_base: f64,
}

impl Default for PricingRates {
    fn default() -> Self {
        Self {
            // Based on typical LLM API pricing
            input_tokens_per_1k: 0.001,  // $1 per 1M input tokens
            output_tokens_per_1k: 0.002, // $2 per 1M output tokens
            fuel_per_1m: 0.0001,         // $0.10 per 1B fuel units
            io_per_gb: 0.01,             // $0.01 per GB
            storage_ops_per_1k: 0.0005,  // $0.50 per 1M ops
            api_call_base: 0.0001,       // $0.10 per 1000 calls
        }
    }
}

impl PricingRates {
    /// Create zero-cost rates (for testing)
    pub fn free() -> Self {
        Self {
            input_tokens_per_1k: 0.0,
            output_tokens_per_1k: 0.0,
            fuel_per_1m: 0.0,
            io_per_gb: 0.0,
            storage_ops_per_1k: 0.0,
            api_call_base: 0.0,
        }
    }

    /// Create premium rates
    pub fn premium() -> Self {
        Self {
            input_tokens_per_1k: 0.003,
            output_tokens_per_1k: 0.006,
            fuel_per_1m: 0.0002,
            io_per_gb: 0.02,
            storage_ops_per_1k: 0.001,
            api_call_base: 0.0002,
        }
    }
}

/// Configuration for cost accounting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostConfig {
    /// Enable cost tracking
    pub enabled: bool,
    /// Pricing rates
    pub rates: PricingRates,
    /// Default budget limit per session (USD, 0 = unlimited)
    pub default_budget_usd: f64,
    /// Alert threshold (percentage of budget)
    pub alert_threshold_percent: f64,
    /// Retention period for cost records (hours)
    pub retention_hours: u64,
    /// Enable detailed per-operation tracking
    pub detailed_tracking: bool,
}

impl Default for CostConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rates: PricingRates::default(),
            default_budget_usd: 0.0, // Unlimited by default
            alert_threshold_percent: 80.0,
            retention_hours: 720, // 30 days
            detailed_tracking: true,
        }
    }
}

// ============================================================================
// Usage Metrics
// ============================================================================

/// Token usage metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Total input tokens consumed
    pub input_tokens: u64,
    /// Total output tokens generated
    pub output_tokens: u64,
    /// Number of LLM calls
    pub llm_calls: u64,
}

impl TokenUsage {
    /// Add token usage
    pub fn add(&mut self, input: u64, output: u64) {
        self.input_tokens += input;
        self.output_tokens += output;
        self.llm_calls += 1;
    }

    /// Total tokens
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }
}

/// WASM fuel metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FuelUsage {
    /// Total fuel consumed
    pub fuel_consumed: u64,
    /// Number of WASM executions
    pub executions: u64,
    /// Peak fuel consumption in a single execution
    pub peak_fuel: u64,
}

impl FuelUsage {
    /// Add fuel usage
    pub fn add(&mut self, fuel: u64) {
        self.fuel_consumed += fuel;
        self.executions += 1;
        self.peak_fuel = self.peak_fuel.max(fuel);
    }
}

/// I/O metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IoUsage {
    /// Bytes read from network
    pub network_ingress_bytes: u64,
    /// Bytes sent over network
    pub network_egress_bytes: u64,
    /// Storage read operations
    pub storage_reads: u64,
    /// Storage write operations
    pub storage_writes: u64,
    /// Storage bytes read
    pub storage_bytes_read: u64,
    /// Storage bytes written
    pub storage_bytes_written: u64,
}

impl IoUsage {
    /// Record network I/O
    pub fn add_network(&mut self, ingress: u64, egress: u64) {
        self.network_ingress_bytes += ingress;
        self.network_egress_bytes += egress;
    }

    /// Record storage I/O
    pub fn add_storage(&mut self, reads: u64, writes: u64, bytes_read: u64, bytes_written: u64) {
        self.storage_reads += reads;
        self.storage_writes += writes;
        self.storage_bytes_read += bytes_read;
        self.storage_bytes_written += bytes_written;
    }

    /// Total network bytes
    pub fn total_network_bytes(&self) -> u64 {
        self.network_ingress_bytes + self.network_egress_bytes
    }

    /// Total storage operations
    pub fn total_storage_ops(&self) -> u64 {
        self.storage_reads + self.storage_writes
    }
}

/// API call metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApiUsage {
    /// Total API calls
    pub total_calls: u64,
    /// Calls by service name
    pub calls_by_service: HashMap<String, u64>,
}

impl ApiUsage {
    /// Record an API call
    pub fn add_call(&mut self, service: &str) {
        self.total_calls += 1;
        *self
            .calls_by_service
            .entry(service.to_string())
            .or_default() += 1;
    }
}

// ============================================================================
// Execution Cost
// ============================================================================

/// Complete cost breakdown for an execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionCost {
    /// Agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Start timestamp (Unix millis)
    pub started_at: u64,
    /// Last updated timestamp (Unix millis)
    pub updated_at: u64,
    /// Token usage
    pub tokens: TokenUsage,
    /// Fuel usage
    pub fuel: FuelUsage,
    /// I/O usage
    pub io: IoUsage,
    /// API usage
    pub api: ApiUsage,
    /// Cost breakdown
    pub cost_breakdown: CostBreakdown,
    /// Total cost in USD
    pub total_cost_usd: f64,
    /// Budget limit (0 = unlimited)
    pub budget_limit_usd: f64,
    /// Whether budget has been exceeded
    pub budget_exceeded: bool,
}

impl ExecutionCost {
    /// Create a new execution cost tracker
    pub fn new(agent_id: String, session_id: String, budget_limit_usd: f64) -> Self {
        let now = current_timestamp_millis();
        Self {
            agent_id,
            session_id,
            started_at: now,
            updated_at: now,
            tokens: TokenUsage::default(),
            fuel: FuelUsage::default(),
            io: IoUsage::default(),
            api: ApiUsage::default(),
            cost_breakdown: CostBreakdown::default(),
            total_cost_usd: 0.0,
            budget_limit_usd,
            budget_exceeded: false,
        }
    }

    /// Calculate costs based on rates
    pub fn calculate_costs(&mut self, rates: &PricingRates) {
        self.cost_breakdown.token_cost =
            (self.tokens.input_tokens as f64 * rates.input_tokens_per_1k / 1000.0)
                + (self.tokens.output_tokens as f64 * rates.output_tokens_per_1k / 1000.0);

        self.cost_breakdown.fuel_cost =
            self.fuel.fuel_consumed as f64 * rates.fuel_per_1m / 1_000_000.0;

        self.cost_breakdown.io_cost =
            self.io.total_network_bytes() as f64 * rates.io_per_gb / 1_073_741_824.0;

        self.cost_breakdown.storage_cost =
            self.io.total_storage_ops() as f64 * rates.storage_ops_per_1k / 1000.0;

        self.cost_breakdown.api_cost = self.api.total_calls as f64 * rates.api_call_base;

        self.total_cost_usd = self.cost_breakdown.total();
        self.updated_at = current_timestamp_millis();

        if self.budget_limit_usd > 0.0 && self.total_cost_usd > self.budget_limit_usd {
            self.budget_exceeded = true;
        }
    }

    /// Get remaining budget
    pub fn remaining_budget(&self) -> Option<f64> {
        if self.budget_limit_usd > 0.0 {
            Some((self.budget_limit_usd - self.total_cost_usd).max(0.0))
        } else {
            None
        }
    }

    /// Get budget usage percentage
    pub fn budget_usage_percent(&self) -> Option<f64> {
        if self.budget_limit_usd > 0.0 {
            Some((self.total_cost_usd / self.budget_limit_usd) * 100.0)
        } else {
            None
        }
    }
}

/// Breakdown of costs by category
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CostBreakdown {
    /// Cost from token usage
    pub token_cost: f64,
    /// Cost from WASM fuel
    pub fuel_cost: f64,
    /// Cost from network I/O
    pub io_cost: f64,
    /// Cost from storage operations
    pub storage_cost: f64,
    /// Cost from API calls
    pub api_cost: f64,
}

impl CostBreakdown {
    /// Total of all costs
    pub fn total(&self) -> f64 {
        self.token_cost + self.fuel_cost + self.io_cost + self.storage_cost + self.api_cost
    }

    /// As percentages of total
    pub fn as_percentages(&self) -> HashMap<String, f64> {
        let total = self.total();
        if total == 0.0 {
            return HashMap::new();
        }

        let mut percentages = HashMap::new();
        percentages.insert("tokens".to_string(), self.token_cost / total * 100.0);
        percentages.insert("fuel".to_string(), self.fuel_cost / total * 100.0);
        percentages.insert("io".to_string(), self.io_cost / total * 100.0);
        percentages.insert("storage".to_string(), self.storage_cost / total * 100.0);
        percentages.insert("api".to_string(), self.api_cost / total * 100.0);
        percentages
    }
}

// ============================================================================
// Cost Accountant
// ============================================================================

/// Main cost accounting system
pub struct CostAccountant {
    config: CostConfig,
    /// Active sessions: (agent_id, session_id) -> ExecutionCost
    sessions: Arc<RwLock<HashMap<(String, String), ExecutionCost>>>,
    /// Completed sessions (for history/billing)
    completed: Arc<RwLock<Vec<ExecutionCost>>>,
    /// Global counters (atomic for fast updates)
    total_tokens_input: AtomicU64,
    total_tokens_output: AtomicU64,
    total_fuel: AtomicU64,
    total_io_bytes: AtomicU64,
    total_api_calls: AtomicU64,
}

impl std::fmt::Debug for CostAccountant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CostAccountant")
            .field("config", &self.config)
            .field(
                "total_tokens_input",
                &self.total_tokens_input.load(Ordering::Relaxed),
            )
            .field(
                "total_tokens_output",
                &self.total_tokens_output.load(Ordering::Relaxed),
            )
            .field("total_fuel", &self.total_fuel.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl CostAccountant {
    /// Create a new cost accountant
    pub fn new(config: CostConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
            total_tokens_input: AtomicU64::new(0),
            total_tokens_output: AtomicU64::new(0),
            total_fuel: AtomicU64::new(0),
            total_io_bytes: AtomicU64::new(0),
            total_api_calls: AtomicU64::new(0),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(CostConfig::default())
    }

    /// Start tracking a new session
    pub async fn start_session(
        &self,
        agent_id: &str,
        session_id: &str,
        budget_limit: Option<f64>,
    ) -> CostResult<()> {
        let budget = budget_limit.unwrap_or(self.config.default_budget_usd);
        let cost = ExecutionCost::new(agent_id.to_string(), session_id.to_string(), budget);

        let mut sessions = self.sessions.write().await;
        sessions.insert((agent_id.to_string(), session_id.to_string()), cost);

        info!(
            agent_id,
            session_id,
            budget_usd = budget,
            "Cost tracking session started"
        );
        Ok(())
    }

    /// Record token usage
    pub async fn record_tokens(
        &self,
        agent_id: &str,
        session_id: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> CostResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        // Update global counters
        self.total_tokens_input
            .fetch_add(input_tokens, Ordering::Relaxed);
        self.total_tokens_output
            .fetch_add(output_tokens, Ordering::Relaxed);

        // Update session
        let mut sessions = self.sessions.write().await;
        let key = (agent_id.to_string(), session_id.to_string());

        if let Some(cost) = sessions.get_mut(&key) {
            cost.tokens.add(input_tokens, output_tokens);
            cost.calculate_costs(&self.config.rates);

            // Check budget
            if cost.budget_exceeded {
                warn!(
                    agent_id,
                    session_id,
                    cost = cost.total_cost_usd,
                    limit = cost.budget_limit_usd,
                    "Budget exceeded"
                );
                return Err(CostError::BudgetExceeded {
                    limit: cost.budget_limit_usd,
                    current: cost.total_cost_usd,
                });
            }

            // Check alert threshold
            if let Some(usage) = cost.budget_usage_percent() {
                if usage >= self.config.alert_threshold_percent {
                    warn!(
                        agent_id,
                        session_id,
                        usage_percent = usage,
                        "Budget usage alert"
                    );
                }
            }
        } else {
            // Auto-create session if not exists
            let mut cost = ExecutionCost::new(
                agent_id.to_string(),
                session_id.to_string(),
                self.config.default_budget_usd,
            );
            cost.tokens.add(input_tokens, output_tokens);
            cost.calculate_costs(&self.config.rates);
            sessions.insert(key, cost);
        }

        debug!(
            agent_id,
            session_id, input_tokens, output_tokens, "Tokens recorded"
        );
        Ok(())
    }

    /// Record WASM fuel consumption
    pub async fn record_fuel(&self, agent_id: &str, session_id: &str, fuel: u64) -> CostResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        self.total_fuel.fetch_add(fuel, Ordering::Relaxed);

        let mut sessions = self.sessions.write().await;
        let key = (agent_id.to_string(), session_id.to_string());

        if let Some(cost) = sessions.get_mut(&key) {
            cost.fuel.add(fuel);
            cost.calculate_costs(&self.config.rates);
        }

        debug!(agent_id, session_id, fuel, "Fuel consumption recorded");
        Ok(())
    }

    /// Record network I/O
    pub async fn record_network_io(
        &self,
        agent_id: &str,
        session_id: &str,
        ingress_bytes: u64,
        egress_bytes: u64,
    ) -> CostResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        self.total_io_bytes
            .fetch_add(ingress_bytes + egress_bytes, Ordering::Relaxed);

        let mut sessions = self.sessions.write().await;
        let key = (agent_id.to_string(), session_id.to_string());

        if let Some(cost) = sessions.get_mut(&key) {
            cost.io.add_network(ingress_bytes, egress_bytes);
            cost.calculate_costs(&self.config.rates);
        }

        debug!(
            agent_id,
            session_id, ingress_bytes, egress_bytes, "Network I/O recorded"
        );
        Ok(())
    }

    /// Record storage I/O
    pub async fn record_storage_io(
        &self,
        agent_id: &str,
        session_id: &str,
        reads: u64,
        writes: u64,
        bytes_read: u64,
        bytes_written: u64,
    ) -> CostResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let mut sessions = self.sessions.write().await;
        let key = (agent_id.to_string(), session_id.to_string());

        if let Some(cost) = sessions.get_mut(&key) {
            cost.io
                .add_storage(reads, writes, bytes_read, bytes_written);
            cost.calculate_costs(&self.config.rates);
        }

        debug!(agent_id, session_id, reads, writes, "Storage I/O recorded");
        Ok(())
    }

    /// Record API call
    pub async fn record_api_call(
        &self,
        agent_id: &str,
        session_id: &str,
        service: &str,
    ) -> CostResult<()> {
        if !self.config.enabled {
            return Ok(());
        }

        self.total_api_calls.fetch_add(1, Ordering::Relaxed);

        let mut sessions = self.sessions.write().await;
        let key = (agent_id.to_string(), session_id.to_string());

        if let Some(cost) = sessions.get_mut(&key) {
            cost.api.add_call(service);
            cost.calculate_costs(&self.config.rates);
        }

        debug!(agent_id, session_id, service, "API call recorded");
        Ok(())
    }

    /// Get cost for a specific session
    pub async fn get_session_cost(
        &self,
        agent_id: &str,
        session_id: &str,
    ) -> CostResult<ExecutionCost> {
        let sessions = self.sessions.read().await;
        let key = (agent_id.to_string(), session_id.to_string());

        sessions
            .get(&key)
            .cloned()
            .ok_or(CostError::SessionNotFound {
                agent_id: agent_id.to_string(),
                session_id: session_id.to_string(),
            })
    }

    /// End a session and move to completed
    pub async fn end_session(&self, agent_id: &str, session_id: &str) -> CostResult<ExecutionCost> {
        let mut sessions = self.sessions.write().await;
        let key = (agent_id.to_string(), session_id.to_string());

        if let Some(cost) = sessions.remove(&key) {
            let mut completed = self.completed.write().await;
            completed.push(cost.clone());

            info!(
                agent_id,
                session_id,
                total_cost_usd = cost.total_cost_usd,
                tokens = cost.tokens.total_tokens(),
                fuel = cost.fuel.fuel_consumed,
                "Session ended"
            );

            Ok(cost)
        } else {
            Err(CostError::SessionNotFound {
                agent_id: agent_id.to_string(),
                session_id: session_id.to_string(),
            })
        }
    }

    /// Get all active session costs
    pub async fn get_active_sessions(&self) -> Vec<ExecutionCost> {
        let sessions = self.sessions.read().await;
        sessions.values().cloned().collect()
    }

    /// Get total cost across all active sessions
    pub async fn get_total_active_cost(&self) -> f64 {
        let sessions = self.sessions.read().await;
        sessions.values().map(|c| c.total_cost_usd).sum()
    }

    /// Get global usage statistics
    pub fn get_global_stats(&self) -> GlobalCostStats {
        GlobalCostStats {
            total_input_tokens: self.total_tokens_input.load(Ordering::Relaxed),
            total_output_tokens: self.total_tokens_output.load(Ordering::Relaxed),
            total_fuel: self.total_fuel.load(Ordering::Relaxed),
            total_io_bytes: self.total_io_bytes.load(Ordering::Relaxed),
            total_api_calls: self.total_api_calls.load(Ordering::Relaxed),
        }
    }

    /// Generate billing report
    pub async fn generate_billing_report(&self, agent_id: &str) -> BillingReport {
        let completed = self.completed.read().await;
        let sessions = self.sessions.read().await;

        let agent_sessions: Vec<_> = completed
            .iter()
            .chain(sessions.values())
            .filter(|c| c.agent_id == agent_id)
            .cloned()
            .collect();

        let total_cost: f64 = agent_sessions.iter().map(|c| c.total_cost_usd).sum();
        let total_fuel: u64 = agent_sessions.iter().map(|c| c.fuel.fuel_consumed).sum();

        BillingReport {
            agent_id: agent_id.to_string(),
            generated_at: current_timestamp_millis(),
            session_count: agent_sessions.len(),
            total_cost_usd: total_cost,
            total_input_tokens: agent_sessions.iter().map(|c| c.tokens.input_tokens).sum(),
            total_output_tokens: agent_sessions.iter().map(|c| c.tokens.output_tokens).sum(),
            total_fuel,
            total_io_bytes: agent_sessions
                .iter()
                .map(|c| c.io.total_network_bytes())
                .sum(),
            total_api_calls: agent_sessions.iter().map(|c| c.api.total_calls).sum(),
            sessions: agent_sessions,
        }
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let stats = self.get_global_stats();

        let mut output = String::new();

        output.push_str(&format!(
            "# HELP vak_cost_tokens_input_total Total input tokens consumed\n\
             # TYPE vak_cost_tokens_input_total counter\n\
             vak_cost_tokens_input_total {}\n\n",
            stats.total_input_tokens
        ));

        output.push_str(&format!(
            "# HELP vak_cost_tokens_output_total Total output tokens generated\n\
             # TYPE vak_cost_tokens_output_total counter\n\
             vak_cost_tokens_output_total {}\n\n",
            stats.total_output_tokens
        ));

        output.push_str(&format!(
            "# HELP vak_cost_fuel_total Total WASM fuel consumed\n\
             # TYPE vak_cost_fuel_total counter\n\
             vak_cost_fuel_total {}\n\n",
            stats.total_fuel
        ));

        output.push_str(&format!(
            "# HELP vak_cost_io_bytes_total Total I/O bytes transferred\n\
             # TYPE vak_cost_io_bytes_total counter\n\
             vak_cost_io_bytes_total {}\n\n",
            stats.total_io_bytes
        ));

        output.push_str(&format!(
            "# HELP vak_cost_api_calls_total Total API calls made\n\
             # TYPE vak_cost_api_calls_total counter\n\
             vak_cost_api_calls_total {}\n\n",
            stats.total_api_calls
        ));

        output
    }
}

impl Default for CostAccountant {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Global cost statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCostStats {
    /// Total input tokens across all sessions
    pub total_input_tokens: u64,
    /// Total output tokens across all sessions
    pub total_output_tokens: u64,
    /// Total fuel consumed across all sessions
    pub total_fuel: u64,
    /// Total I/O bytes across all sessions
    pub total_io_bytes: u64,
    /// Total API calls across all sessions
    pub total_api_calls: u64,
}

/// Billing report for an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BillingReport {
    /// Agent ID
    pub agent_id: String,
    /// When this report was generated
    pub generated_at: u64,
    /// Number of sessions
    pub session_count: usize,
    /// Total cost in USD
    pub total_cost_usd: f64,
    /// Total input tokens
    pub total_input_tokens: u64,
    /// Total output tokens
    pub total_output_tokens: u64,
    /// Total fuel consumed
    pub total_fuel: u64,
    /// Total I/O bytes
    pub total_io_bytes: u64,
    /// Total API calls
    pub total_api_calls: u64,
    /// Individual session costs
    pub sessions: Vec<ExecutionCost>,
}

impl BillingReport {
    /// Export as JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or_default()
    }

    /// Export as formatted text invoice
    pub fn to_invoice(&self) -> String {
        let mut invoice = String::new();

        invoice.push_str("═══════════════════════════════════════════════════════\n");
        invoice.push_str("                   VAK BILLING REPORT                   \n");
        invoice.push_str("═══════════════════════════════════════════════════════\n\n");

        invoice.push_str(&format!("Agent ID:        {}\n", self.agent_id));
        invoice.push_str(&format!(
            "Generated:       {}\n",
            format_timestamp(self.generated_at)
        ));
        invoice.push_str(&format!("Sessions:        {}\n", self.session_count));
        invoice.push_str("\n───────────────────────────────────────────────────────\n");
        invoice.push_str("                      USAGE SUMMARY                      \n");
        invoice.push_str("───────────────────────────────────────────────────────\n\n");

        invoice.push_str(&format!(
            "Input Tokens:    {:>15}\n",
            format_number(self.total_input_tokens)
        ));
        invoice.push_str(&format!(
            "Output Tokens:   {:>15}\n",
            format_number(self.total_output_tokens)
        ));
        invoice.push_str(&format!(
            "WASM Fuel:       {:>15}\n",
            format_number(self.total_fuel)
        ));
        invoice.push_str(&format!(
            "I/O Bytes:       {:>15}\n",
            format_bytes(self.total_io_bytes)
        ));
        invoice.push_str(&format!(
            "API Calls:       {:>15}\n",
            format_number(self.total_api_calls)
        ));

        invoice.push_str("\n───────────────────────────────────────────────────────\n");
        invoice.push_str(&format!(
            "TOTAL COST:                        ${:.6} USD\n",
            self.total_cost_usd
        ));
        invoice.push_str("═══════════════════════════════════════════════════════\n");

        invoice
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current timestamp in milliseconds
fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Format timestamp for display
fn format_timestamp(millis: u64) -> String {
    chrono::DateTime::from_timestamp_millis(millis as i64)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

/// Format large numbers with commas
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format bytes as human-readable
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_cost_tracking() {
        let accountant = CostAccountant::with_defaults();

        accountant
            .start_session("agent-1", "session-1", None)
            .await
            .unwrap();
        accountant
            .record_tokens("agent-1", "session-1", 1000, 500)
            .await
            .unwrap();
        accountant
            .record_fuel("agent-1", "session-1", 1_000_000)
            .await
            .unwrap();

        let cost = accountant
            .get_session_cost("agent-1", "session-1")
            .await
            .unwrap();
        assert!(cost.total_cost_usd > 0.0);
        assert_eq!(cost.tokens.input_tokens, 1000);
        assert_eq!(cost.tokens.output_tokens, 500);
        assert_eq!(cost.fuel.fuel_consumed, 1_000_000);
    }

    #[tokio::test]
    async fn test_budget_limit() {
        let mut config = CostConfig::default();
        config.rates = PricingRates {
            input_tokens_per_1k: 1.0, // $1 per 1K tokens for easy testing
            ..PricingRates::default()
        };
        let accountant = CostAccountant::new(config);

        accountant
            .start_session("agent-1", "session-1", Some(0.5))
            .await
            .unwrap();

        // First batch should succeed
        accountant
            .record_tokens("agent-1", "session-1", 400, 0)
            .await
            .unwrap();

        // Second batch should exceed budget
        let result = accountant
            .record_tokens("agent-1", "session-1", 200, 0)
            .await;
        assert!(matches!(result, Err(CostError::BudgetExceeded { .. })));
    }

    #[tokio::test]
    async fn test_billing_report() {
        let accountant = CostAccountant::with_defaults();

        accountant
            .start_session("agent-1", "session-1", None)
            .await
            .unwrap();
        accountant
            .record_tokens("agent-1", "session-1", 1000, 500)
            .await
            .unwrap();
        accountant
            .end_session("agent-1", "session-1")
            .await
            .unwrap();

        let report = accountant.generate_billing_report("agent-1").await;
        assert_eq!(report.session_count, 1);
        assert_eq!(report.total_input_tokens, 1000);
        assert_eq!(report.total_output_tokens, 500);
    }

    #[test]
    fn test_cost_breakdown_percentages() {
        let breakdown = CostBreakdown {
            token_cost: 0.50,
            fuel_cost: 0.20,
            io_cost: 0.10,
            storage_cost: 0.15,
            api_cost: 0.05,
        };

        let percentages = breakdown.as_percentages();
        assert!((percentages["tokens"] - 50.0).abs() < 0.01);
        assert!((percentages["fuel"] - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_global_stats() {
        let accountant = CostAccountant::with_defaults();

        accountant
            .total_tokens_input
            .fetch_add(1000, Ordering::Relaxed);
        accountant
            .total_tokens_output
            .fetch_add(500, Ordering::Relaxed);
        accountant
            .total_fuel
            .fetch_add(1_000_000, Ordering::Relaxed);

        let stats = accountant.get_global_stats();
        assert_eq!(stats.total_input_tokens, 1000);
        assert_eq!(stats.total_output_tokens, 500);
        assert_eq!(stats.total_fuel, 1_000_000);
    }
}
