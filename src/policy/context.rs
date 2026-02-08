//! Dynamic Context Injection for Cedar Policy Evaluation (POL-005)
//!
//! This module provides real-time context collection for ABAC policy decisions.
//! Context includes system state, agent reputation, and environmental factors.
//!
//! # Overview
//!
//! Dynamic context injection enables policies to make decisions based on:
//! - Current system load and resource availability
//! - Agent trust/reputation scores
//! - Time-based access windows
//! - Geographic/IP-based restrictions
//! - Recent agent behavior patterns
//!
//! # Example
//!
//! ```rust
//! use vak::policy::context::{DynamicContextCollector, ContextConfig, SystemMetrics};
//!
//! let collector = DynamicContextCollector::new(ContextConfig::default());
//!
//! // Collect context for a policy decision
//! let context = collector.collect_context("agent-123").await;
//!
//! // Context now contains real-time system state
//! assert!(context.timestamp.is_some());
//! assert!(context.system_load.is_some());
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.2.2: Context-Aware Authorization

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::enforcer::PolicyContext;

/// Errors that can occur during context collection
#[derive(Debug, Error)]
pub enum ContextError {
    /// System metrics collection failed
    #[error("Failed to collect system metrics: {0}")]
    MetricsError(String),

    /// Agent reputation lookup failed
    #[error("Failed to lookup agent reputation: {0}")]
    ReputationError(String),

    /// Rate limit exceeded for context collection
    #[error("Context collection rate limit exceeded")]
    RateLimitExceeded,

    /// Context provider not available
    #[error("Context provider unavailable: {0}")]
    ProviderUnavailable(String),
}

/// Result type for context operations
pub type ContextResult<T> = Result<T, ContextError>;

/// Configuration for dynamic context collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConfig {
    /// Enable system metrics collection
    pub collect_system_metrics: bool,
    /// Enable agent reputation lookup
    pub collect_reputation: bool,
    /// Enable IP geolocation
    pub collect_geolocation: bool,
    /// Cache TTL for context data (seconds)
    pub cache_ttl_secs: u64,
    /// Rate limit for context collection (per second)
    pub rate_limit_per_sec: u32,
    /// System load threshold for high-load mode
    pub high_load_threshold: f64,
    /// Default trust score for unknown agents
    pub default_trust_score: f64,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            collect_system_metrics: true,
            collect_reputation: true,
            collect_geolocation: false,
            cache_ttl_secs: 5,
            rate_limit_per_sec: 1000,
            high_load_threshold: 0.8,
            default_trust_score: 0.5,
        }
    }
}

impl ContextConfig {
    /// Create a minimal configuration for testing
    pub fn minimal() -> Self {
        Self {
            collect_system_metrics: false,
            collect_reputation: false,
            collect_geolocation: false,
            cache_ttl_secs: 0,
            rate_limit_per_sec: 10000,
            high_load_threshold: 0.9,
            default_trust_score: 0.5,
        }
    }

    /// Create a full configuration for production
    pub fn production() -> Self {
        Self {
            collect_system_metrics: true,
            collect_reputation: true,
            collect_geolocation: true,
            cache_ttl_secs: 10,
            rate_limit_per_sec: 500,
            high_load_threshold: 0.7,
            default_trust_score: 0.3,
        }
    }
}

/// System metrics for context injection
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SystemMetrics {
    /// CPU load (0.0 - 1.0)
    pub cpu_load: f64,
    /// Memory usage (0.0 - 1.0)
    pub memory_usage: f64,
    /// Active agent count
    pub active_agents: u64,
    /// Pending request count
    pub pending_requests: u64,
    /// System alert level (0 = normal, 1+ = elevated)
    pub alert_level: u32,
    /// Collection timestamp
    pub collected_at: u64,
}

impl SystemMetrics {
    /// Calculate overall system load
    pub fn overall_load(&self) -> f64 {
        (self.cpu_load + self.memory_usage) / 2.0
    }

    /// Check if system is under high load
    pub fn is_high_load(&self, threshold: f64) -> bool {
        self.overall_load() > threshold
    }
}

/// Agent reputation data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentReputation {
    /// Agent ID
    pub agent_id: String,
    /// Trust score (0.0 - 1.0)
    pub trust_score: f64,
    /// Number of successful actions
    pub successful_actions: u64,
    /// Number of failed/denied actions
    pub failed_actions: u64,
    /// Number of policy violations
    pub violations: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Recent action types (for behavioral analysis)
    pub recent_actions: Vec<String>,
}

impl AgentReputation {
    /// Create default reputation for new agent
    pub fn new_agent(agent_id: impl Into<String>, default_score: f64) -> Self {
        Self {
            agent_id: agent_id.into(),
            trust_score: default_score,
            successful_actions: 0,
            failed_actions: 0,
            violations: 0,
            last_activity: current_timestamp(),
            recent_actions: Vec::new(),
        }
    }

    /// Calculate a derived risk score (inverse of trust)
    pub fn risk_score(&self) -> f64 {
        1.0 - self.trust_score
    }

    /// Check if agent has suspicious behavior pattern
    pub fn is_suspicious(&self) -> bool {
        // Flag as suspicious if:
        // - More than 30% of actions fail
        // - Any policy violations
        // - Very rapid activity (> 100 recent actions)
        let failure_rate = if self.successful_actions + self.failed_actions > 0 {
            self.failed_actions as f64 / (self.successful_actions + self.failed_actions) as f64
        } else {
            0.0
        };

        failure_rate > 0.3 || self.violations > 0 || self.recent_actions.len() > 100
    }
}

/// Cached context entry
#[derive(Debug, Clone)]
struct CachedContext {
    context: PolicyContext,
    cached_at: u64,
}

/// Dynamic context collector for policy evaluation
///
/// Collects real-time context data including system metrics, agent reputation,
/// and environmental factors for ABAC policy decisions.
pub struct DynamicContextCollector {
    config: ContextConfig,
    /// System metrics (shared, updated periodically)
    system_metrics: Arc<RwLock<SystemMetrics>>,
    /// Agent reputation store
    reputation_store: Arc<RwLock<HashMap<String, AgentReputation>>>,
    /// Context cache
    cache: Arc<RwLock<HashMap<String, CachedContext>>>,
    /// Rate limiter counter
    rate_counter: AtomicU64,
    /// Rate limit window start
    rate_window_start: AtomicU64,
}

impl std::fmt::Debug for DynamicContextCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicContextCollector")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DynamicContextCollector {
    /// Create a new context collector
    pub fn new(config: ContextConfig) -> Self {
        Self {
            config,
            system_metrics: Arc::new(RwLock::new(SystemMetrics::default())),
            reputation_store: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            rate_counter: AtomicU64::new(0),
            rate_window_start: AtomicU64::new(current_timestamp()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ContextConfig::default())
    }

    /// Collect full context for a policy decision
    pub async fn collect_context(&self, agent_id: &str) -> ContextResult<PolicyContext> {
        // Check rate limit
        self.check_rate_limit()?;

        // Check cache first
        if let Some(cached) = self.get_cached_context(agent_id).await {
            debug!(agent_id = %agent_id, "Using cached context");
            return Ok(cached);
        }

        let mut context = PolicyContext::new().with_current_time();

        // Collect system metrics
        if self.config.collect_system_metrics {
            let metrics = self.system_metrics.read().await;
            context.system_load = Some(metrics.overall_load());
            context.alert_mode = Some(metrics.alert_level > 0);
            context.custom.insert(
                "active_agents".to_string(),
                serde_json::json!(metrics.active_agents),
            );
            context.custom.insert(
                "pending_requests".to_string(),
                serde_json::json!(metrics.pending_requests),
            );
        }

        // Collect agent reputation
        if self.config.collect_reputation {
            let reputation = self.get_or_create_reputation(agent_id).await;
            context.trust_score = Some(reputation.trust_score);
            context.custom.insert(
                "risk_score".to_string(),
                serde_json::json!(reputation.risk_score()),
            );
            context.custom.insert(
                "is_suspicious".to_string(),
                serde_json::json!(reputation.is_suspicious()),
            );
            context.custom.insert(
                "violation_count".to_string(),
                serde_json::json!(reputation.violations),
            );
        }

        // Cache the context
        self.cache_context(agent_id, &context).await;

        Ok(context)
    }

    /// Collect minimal context (for high-performance scenarios)
    pub async fn collect_minimal_context(&self, agent_id: &str) -> PolicyContext {
        PolicyContext::new()
            .with_current_time()
            .with_trust_score(self.config.default_trust_score)
            .with_custom("agent_id", serde_json::json!(agent_id))
    }

    /// Update system metrics
    pub async fn update_system_metrics(&self, metrics: SystemMetrics) {
        let mut current = self.system_metrics.write().await;
        *current = metrics;
        info!(
            cpu_load = %current.cpu_load,
            memory_usage = %current.memory_usage,
            "System metrics updated"
        );
    }

    /// Update agent reputation after an action
    pub async fn update_reputation(
        &self,
        agent_id: &str,
        action: &str,
        success: bool,
        violation: bool,
    ) {
        let mut store = self.reputation_store.write().await;
        let reputation = store.entry(agent_id.to_string()).or_insert_with(|| {
            AgentReputation::new_agent(agent_id, self.config.default_trust_score)
        });

        // Update counters
        if success {
            reputation.successful_actions += 1;
        } else {
            reputation.failed_actions += 1;
        }

        if violation {
            reputation.violations += 1;
        }

        // Update recent actions (keep last 50)
        reputation.recent_actions.push(action.to_string());
        if reputation.recent_actions.len() > 50 {
            reputation.recent_actions.remove(0);
        }

        reputation.last_activity = current_timestamp();

        // Recalculate trust score
        reputation.trust_score = self.calculate_trust_score(reputation);

        debug!(
            agent_id = %agent_id,
            trust_score = %reputation.trust_score,
            "Agent reputation updated"
        );
    }

    /// Get or create agent reputation
    async fn get_or_create_reputation(&self, agent_id: &str) -> AgentReputation {
        let mut store = self.reputation_store.write().await;
        store
            .entry(agent_id.to_string())
            .or_insert_with(|| {
                AgentReputation::new_agent(agent_id, self.config.default_trust_score)
            })
            .clone()
    }

    /// Calculate trust score based on reputation data
    fn calculate_trust_score(&self, reputation: &AgentReputation) -> f64 {
        let total_actions = reputation.successful_actions + reputation.failed_actions;
        if total_actions == 0 {
            return self.config.default_trust_score;
        }

        let success_rate = reputation.successful_actions as f64 / total_actions as f64;

        // Penalize violations heavily
        let violation_penalty = (reputation.violations as f64 * 0.1).min(0.5);

        // Base score from success rate, minus violation penalty
        (success_rate - violation_penalty).clamp(0.0, 1.0)
    }

    /// Check rate limit
    fn check_rate_limit(&self) -> ContextResult<()> {
        let now = current_timestamp();
        let window_start = self.rate_window_start.load(Ordering::Relaxed);

        // Reset counter if window expired (1 second window)
        if now > window_start + 1 {
            self.rate_window_start.store(now, Ordering::Relaxed);
            self.rate_counter.store(0, Ordering::Relaxed);
        }

        let count = self.rate_counter.fetch_add(1, Ordering::Relaxed);
        if count >= self.config.rate_limit_per_sec as u64 {
            warn!("Context collection rate limit exceeded");
            return Err(ContextError::RateLimitExceeded);
        }

        Ok(())
    }

    /// Get cached context if still valid
    async fn get_cached_context(&self, agent_id: &str) -> Option<PolicyContext> {
        let cache = self.cache.read().await;
        if let Some(cached) = cache.get(agent_id) {
            let now = current_timestamp();
            if now < cached.cached_at + self.config.cache_ttl_secs {
                return Some(cached.context.clone());
            }
        }
        None
    }

    /// Cache a context
    async fn cache_context(&self, agent_id: &str, context: &PolicyContext) {
        if self.config.cache_ttl_secs > 0 {
            let mut cache = self.cache.write().await;
            cache.insert(
                agent_id.to_string(),
                CachedContext {
                    context: context.clone(),
                    cached_at: current_timestamp(),
                },
            );
        }
    }

    /// Clear cache for an agent
    pub async fn invalidate_cache(&self, agent_id: &str) {
        let mut cache = self.cache.write().await;
        cache.remove(agent_id);
    }

    /// Clear all caches
    pub async fn clear_all_caches(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get current system metrics
    pub async fn get_system_metrics(&self) -> SystemMetrics {
        self.system_metrics.read().await.clone()
    }

    /// Get agent reputation
    pub async fn get_reputation(&self, agent_id: &str) -> Option<AgentReputation> {
        let store = self.reputation_store.read().await;
        store.get(agent_id).cloned()
    }
}

/// Get current Unix timestamp in seconds
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Context provider trait for extensibility
#[async_trait::async_trait]
pub trait ContextProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &str;

    /// Collect context attributes
    async fn collect(&self, agent_id: &str) -> ContextResult<HashMap<String, serde_json::Value>>;
}

/// Geolocation context provider for location-based policy decisions
///
/// This provider can determine geographic context for policy enforcement,
/// such as restricting operations based on region or jurisdiction.
///
/// In production deployments, this would integrate with:
/// - IP geolocation databases (MaxMind GeoIP2, IP2Location)
/// - Cloud provider metadata services
/// - Network topology information
pub struct GeolocationProvider {
    /// Whether geolocation is enabled
    enabled: bool,
    /// Default country code when geolocation is unavailable
    default_country: String,
    /// Default region code when geolocation is unavailable  
    default_region: String,
    /// Configured location overrides by agent ID
    agent_locations: std::sync::RwLock<HashMap<String, GeoLocation>>,
}

/// Geographic location data
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GeoLocation {
    /// ISO 3166-1 alpha-2 country code (e.g., "US", "DE", "JP")
    pub country_code: String,
    /// Region/state code (e.g., "CA" for California)
    pub region_code: String,
    /// City name (optional)
    pub city: Option<String>,
    /// Timezone (e.g., "America/Los_Angeles")
    pub timezone: Option<String>,
    /// Whether this is a cloud/datacenter IP
    pub is_datacenter: bool,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,
}

impl Default for GeoLocation {
    fn default() -> Self {
        Self {
            country_code: "XX".to_string(), // Unknown country
            region_code: "XX".to_string(),
            city: None,
            timezone: None,
            is_datacenter: false,
            confidence: 0.0,
        }
    }
}

impl GeolocationProvider {
    /// Create a new geolocation provider
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            default_country: "XX".to_string(),
            default_region: "XX".to_string(),
            agent_locations: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Create with default location fallback
    pub fn with_defaults(
        default_country: impl Into<String>,
        default_region: impl Into<String>,
    ) -> Self {
        Self {
            enabled: true,
            default_country: default_country.into(),
            default_region: default_region.into(),
            agent_locations: std::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Set a specific location for an agent (useful for testing or known deployments)
    pub fn set_agent_location(&self, agent_id: &str, location: GeoLocation) {
        if let Ok(mut locations) = self.agent_locations.write() {
            locations.insert(agent_id.to_string(), location);
        }
    }

    /// Clear agent location override
    pub fn clear_agent_location(&self, agent_id: &str) {
        if let Ok(mut locations) = self.agent_locations.write() {
            locations.remove(agent_id);
        }
    }

    /// Get location for an agent
    fn get_location(&self, agent_id: &str) -> GeoLocation {
        // Check for agent-specific override
        if let Ok(locations) = self.agent_locations.read() {
            if let Some(loc) = locations.get(agent_id) {
                return loc.clone();
            }
        }

        // Return default location
        GeoLocation {
            country_code: self.default_country.clone(),
            region_code: self.default_region.clone(),
            city: None,
            timezone: None,
            is_datacenter: false,
            confidence: 0.5, // Medium confidence for default
        }
    }
}

#[async_trait::async_trait]
impl ContextProvider for GeolocationProvider {
    fn name(&self) -> &str {
        "geolocation"
    }

    async fn collect(&self, agent_id: &str) -> ContextResult<HashMap<String, serde_json::Value>> {
        if !self.enabled {
            return Ok(HashMap::new());
        }

        let location = self.get_location(agent_id);

        let mut attrs = HashMap::new();
        attrs.insert(
            "country".to_string(),
            serde_json::json!(location.country_code),
        );
        attrs.insert(
            "region".to_string(),
            serde_json::json!(location.region_code),
        );
        attrs.insert(
            "is_datacenter".to_string(),
            serde_json::json!(location.is_datacenter),
        );
        attrs.insert(
            "geo_confidence".to_string(),
            serde_json::json!(location.confidence),
        );

        if let Some(city) = &location.city {
            attrs.insert("city".to_string(), serde_json::json!(city));
        }

        if let Some(tz) = &location.timezone {
            attrs.insert("timezone".to_string(), serde_json::json!(tz));
        }

        Ok(attrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_context_collection() {
        let collector = DynamicContextCollector::new(ContextConfig::minimal());
        let context = collector.collect_context("agent-1").await.unwrap();

        assert!(context.timestamp.is_some());
    }

    #[tokio::test]
    async fn test_reputation_update() {
        let collector = DynamicContextCollector::with_defaults();

        // Simulate some actions
        collector
            .update_reputation("agent-1", "read", true, false)
            .await;
        collector
            .update_reputation("agent-1", "write", true, false)
            .await;
        collector
            .update_reputation("agent-1", "delete", false, true)
            .await;

        let rep = collector.get_reputation("agent-1").await.unwrap();
        assert_eq!(rep.successful_actions, 2);
        assert_eq!(rep.failed_actions, 1);
        assert_eq!(rep.violations, 1);
        assert!(rep.trust_score < 1.0); // Should be penalized
    }

    #[tokio::test]
    async fn test_system_metrics_update() {
        let collector = DynamicContextCollector::with_defaults();

        let metrics = SystemMetrics {
            cpu_load: 0.7,
            memory_usage: 0.5,
            active_agents: 10,
            pending_requests: 5,
            alert_level: 0,
            collected_at: current_timestamp(),
        };

        collector.update_system_metrics(metrics).await;

        let retrieved = collector.get_system_metrics().await;
        assert_eq!(retrieved.cpu_load, 0.7);
        assert_eq!(retrieved.active_agents, 10);
    }

    #[tokio::test]
    async fn test_context_caching() {
        let config = ContextConfig {
            cache_ttl_secs: 60, // Long TTL for test
            ..ContextConfig::minimal()
        };
        let collector = DynamicContextCollector::new(config);

        // First call should miss cache
        let _ctx1 = collector.collect_context("agent-1").await.unwrap();

        // Second call should hit cache
        let ctx2 = collector.collect_context("agent-1").await.unwrap();
        assert!(ctx2.timestamp.is_some());

        // Invalidate cache
        collector.invalidate_cache("agent-1").await;

        // Should get fresh context
        let _ctx3 = collector.collect_context("agent-1").await.unwrap();
    }

    #[test]
    fn test_agent_reputation_suspicious() {
        let mut rep = AgentReputation::new_agent("test", 0.5);

        // Not suspicious initially
        assert!(!rep.is_suspicious());

        // Add a violation
        rep.violations = 1;
        assert!(rep.is_suspicious());
    }

    #[test]
    fn test_system_metrics_high_load() {
        let metrics = SystemMetrics {
            cpu_load: 0.9,
            memory_usage: 0.8,
            ..Default::default()
        };

        assert!(metrics.is_high_load(0.7));
        assert!(!metrics.is_high_load(0.95));
    }

    #[tokio::test]
    async fn test_geolocation_provider_disabled() {
        let provider = GeolocationProvider::new(false);
        let attrs = provider.collect("agent-1").await.unwrap();

        // When disabled, should return empty map
        assert!(attrs.is_empty());
    }

    #[tokio::test]
    async fn test_geolocation_provider_enabled() {
        let provider = GeolocationProvider::new(true);
        let attrs = provider.collect("agent-1").await.unwrap();

        // Should have basic attributes
        assert!(attrs.contains_key("country"));
        assert!(attrs.contains_key("region"));
        assert!(attrs.contains_key("is_datacenter"));
        assert!(attrs.contains_key("geo_confidence"));
    }

    #[tokio::test]
    async fn test_geolocation_provider_with_defaults() {
        let provider = GeolocationProvider::with_defaults("US", "CA");
        let attrs = provider.collect("agent-1").await.unwrap();

        assert_eq!(attrs.get("country"), Some(&serde_json::json!("US")));
        assert_eq!(attrs.get("region"), Some(&serde_json::json!("CA")));
    }

    #[tokio::test]
    async fn test_geolocation_provider_agent_override() {
        let provider = GeolocationProvider::with_defaults("US", "CA");

        // Set specific location for agent
        provider.set_agent_location(
            "agent-special",
            GeoLocation {
                country_code: "DE".to_string(),
                region_code: "BE".to_string(),
                city: Some("Berlin".to_string()),
                timezone: Some("Europe/Berlin".to_string()),
                is_datacenter: false,
                confidence: 0.95,
            },
        );

        // Regular agent gets default
        let attrs1 = provider.collect("agent-1").await.unwrap();
        assert_eq!(attrs1.get("country"), Some(&serde_json::json!("US")));

        // Special agent gets override
        let attrs2 = provider.collect("agent-special").await.unwrap();
        assert_eq!(attrs2.get("country"), Some(&serde_json::json!("DE")));
        assert_eq!(attrs2.get("city"), Some(&serde_json::json!("Berlin")));
        assert_eq!(
            attrs2.get("timezone"),
            Some(&serde_json::json!("Europe/Berlin"))
        );

        // Clear override
        provider.clear_agent_location("agent-special");
        let attrs3 = provider.collect("agent-special").await.unwrap();
        assert_eq!(attrs3.get("country"), Some(&serde_json::json!("US")));
    }

    #[test]
    fn test_geo_location_default() {
        let loc = GeoLocation::default();
        assert_eq!(loc.country_code, "XX");
        assert_eq!(loc.region_code, "XX");
        assert!(loc.city.is_none());
        assert_eq!(loc.confidence, 0.0);
    }
}
