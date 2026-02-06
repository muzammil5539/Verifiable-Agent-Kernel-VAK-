//! Rate Limiting Enhancements (SEC-005)
//!
//! Provides per-resource, per-action granular rate limiting for agent actions.
//! Extends basic per-agent rate limiting with fine-grained control.
//!
//! # Overview
//!
//! Enhanced rate limiting enables:
//! - Per-agent rate limits
//! - Per-resource rate limits
//! - Per-action type rate limits
//! - Combined limits (agent + resource + action)
//! - Burst allowance with token bucket algorithm
//! - Sliding window rate limiting
//!
//! # Example
//!
//! ```rust
//! use vak::kernel::rate_limiter::{RateLimiter, RateLimitConfig, ResourceLimit};
//!
//! let mut limiter = RateLimiter::new(RateLimitConfig::default());
//!
//! // Add per-resource limits
//! limiter.add_resource_limit("/api/secrets", ResourceLimit::new(10, 60)); // 10 req/min
//! limiter.add_resource_limit("/api/data/*", ResourceLimit::new(100, 60)); // 100 req/min
//!
//! // Check if request is allowed
//! let result = limiter.check("agent-1", "read", "/api/secrets");
//! if !result.allowed {
//!     println!("Rate limited: {}", result.reason.unwrap());
//! }
//! ```
//!
//! # References
//!
//! - SEC-005: Rate Limiting Enhancements
//! - Gap Analysis Section 3.2: Security Gates

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during rate limiting
#[derive(Debug, Error)]
pub enum RateLimitError {
    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    LimitExceeded(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Pattern error
    #[error("Invalid pattern: {0}")]
    PatternError(String),
}

/// Result type for rate limit operations
pub type RateLimitResult<T> = Result<T, RateLimitError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the rate limiter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Enable rate limiting
    pub enabled: bool,
    /// Default requests per minute per agent
    pub default_agent_rpm: u32,
    /// Default requests per minute per resource
    pub default_resource_rpm: u32,
    /// Burst allowance multiplier (e.g., 1.5 = 50% burst)
    pub burst_multiplier: f64,
    /// Window size for sliding window in seconds
    pub window_seconds: u64,
    /// Enable per-action limits
    pub per_action_limits: bool,
    /// Cleanup interval for expired entries (seconds)
    pub cleanup_interval_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_agent_rpm: 60,
            default_resource_rpm: 100,
            burst_multiplier: 1.5,
            window_seconds: 60,
            per_action_limits: true,
            cleanup_interval_secs: 300,
        }
    }
}

// ============================================================================
// Rate Limit Types
// ============================================================================

/// A rate limit specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimit {
    /// Maximum requests in the window
    pub max_requests: u32,
    /// Window size in seconds
    pub window_secs: u64,
    /// Burst allowance (additional requests allowed in bursts)
    pub burst_allowance: u32,
    /// Priority (higher = more important, gets more lenient limits)
    pub priority: i32,
}

impl ResourceLimit {
    /// Create a new resource limit
    pub fn new(max_requests: u32, window_secs: u64) -> Self {
        Self {
            max_requests,
            window_secs,
            burst_allowance: (max_requests as f64 * 0.2) as u32,
            priority: 0,
        }
    }

    /// Create with burst allowance
    pub fn with_burst(mut self, burst: u32) -> Self {
        self.burst_allowance = burst;
        self
    }

    /// Create with priority
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
}

/// Action-specific rate limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionLimit {
    /// Action name
    pub action: String,
    /// Maximum requests per window
    pub max_requests: u32,
    /// Window size in seconds
    pub window_secs: u64,
}

impl ActionLimit {
    /// Create a new action limit
    pub fn new(action: impl Into<String>, max_requests: u32, window_secs: u64) -> Self {
        Self {
            action: action.into(),
            max_requests,
            window_secs,
        }
    }
}

// ============================================================================
// Token Bucket
// ============================================================================

/// Token bucket for rate limiting
#[derive(Debug)]
struct TokenBucket {
    /// Current token count
    tokens: f64,
    /// Maximum tokens (bucket capacity)
    max_tokens: f64,
    /// Refill rate (tokens per second)
    refill_rate: f64,
    /// Last update time
    last_update: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_update: Instant::now(),
        }
    }

    fn try_acquire(&mut self, tokens: f64) -> bool {
        self.refill();
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_update = now;
    }

    fn available(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

// ============================================================================
// Sliding Window Counter
// ============================================================================

/// Sliding window counter for accurate rate limiting
#[derive(Debug)]
struct SlidingWindow {
    /// Request counts per sub-window
    windows: Vec<(Instant, u32)>,
    /// Window duration
    window_duration: Duration,
    /// Number of sub-windows
    sub_windows: usize,
}

impl SlidingWindow {
    fn new(window_secs: u64, sub_windows: usize) -> Self {
        Self {
            windows: Vec::with_capacity(sub_windows),
            window_duration: Duration::from_secs(window_secs),
            sub_windows,
        }
    }

    fn record(&mut self) {
        let now = Instant::now();
        self.cleanup(now);

        if let Some(last) = self.windows.last_mut() {
            let sub_window = self.window_duration / self.sub_windows as u32;
            if now.duration_since(last.0) < sub_window {
                last.1 += 1;
                return;
            }
        }

        self.windows.push((now, 1));
    }

    fn count(&mut self) -> u32 {
        let now = Instant::now();
        self.cleanup(now);
        self.windows.iter().map(|(_, c)| c).sum()
    }

    fn cleanup(&mut self, now: Instant) {
        let cutoff = now - self.window_duration;
        self.windows.retain(|(t, _)| *t > cutoff);
    }
}

// ============================================================================
// Rate Limit Result
// ============================================================================

/// Result of a rate limit check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Reason if denied
    pub reason: Option<String>,
    /// Current usage count
    pub current_count: u32,
    /// Maximum allowed
    pub max_allowed: u32,
    /// Time until reset (seconds)
    pub retry_after_secs: Option<u64>,
    /// Which limit was hit
    pub limit_type: Option<LimitType>,
}

/// Type of limit that was hit
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LimitType {
    /// Agent-level limit
    Agent,
    /// Resource-level limit
    Resource,
    /// Action-level limit
    Action,
    /// Combined limit
    Combined,
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Main rate limiter implementation
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-agent token buckets
    agent_buckets: RwLock<HashMap<String, TokenBucket>>,
    /// Per-resource sliding windows
    resource_windows: RwLock<HashMap<String, SlidingWindow>>,
    /// Per-action sliding windows
    action_windows: RwLock<HashMap<String, SlidingWindow>>,
    /// Custom resource limits
    resource_limits: RwLock<HashMap<String, ResourceLimit>>,
    /// Custom action limits
    action_limits: RwLock<HashMap<String, ActionLimit>>,
    /// Statistics
    stats: RateLimiterStats,
}

/// Rate limiter statistics
#[derive(Debug, Default)]
pub struct RateLimiterStats {
    /// Total requests checked
    pub total_checked: AtomicU64,
    /// Total requests allowed
    pub total_allowed: AtomicU64,
    /// Total requests denied
    pub total_denied: AtomicU64,
    /// Denials by agent
    pub agent_denials: AtomicU64,
    /// Denials by resource
    pub resource_denials: AtomicU64,
    /// Denials by action
    pub action_denials: AtomicU64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            agent_buckets: RwLock::new(HashMap::new()),
            resource_windows: RwLock::new(HashMap::new()),
            action_windows: RwLock::new(HashMap::new()),
            resource_limits: RwLock::new(HashMap::new()),
            action_limits: RwLock::new(HashMap::new()),
            stats: RateLimiterStats::default(),
        }
    }

    /// Create with default configuration
    pub fn default_config() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Get the configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Add a custom resource limit
    pub fn add_resource_limit(&self, resource_pattern: impl Into<String>, limit: ResourceLimit) {
        let mut limits = self.resource_limits.write().unwrap();
        limits.insert(resource_pattern.into(), limit);
    }

    /// Add a custom action limit
    pub fn add_action_limit(&self, limit: ActionLimit) {
        let mut limits = self.action_limits.write().unwrap();
        limits.insert(limit.action.clone(), limit);
    }

    /// Check if a request is allowed
    pub fn check(&self, agent_id: &str, action: &str, resource: &str) -> CheckResult {
        self.stats.total_checked.fetch_add(1, Ordering::Relaxed);

        if !self.config.enabled {
            self.stats.total_allowed.fetch_add(1, Ordering::Relaxed);
            return CheckResult {
                allowed: true,
                reason: None,
                current_count: 0,
                max_allowed: u32::MAX,
                retry_after_secs: None,
                limit_type: None,
            };
        }

        // Check agent limit
        if let Some(result) = self.check_agent_limit(agent_id) {
            if !result.allowed {
                self.stats.total_denied.fetch_add(1, Ordering::Relaxed);
                self.stats.agent_denials.fetch_add(1, Ordering::Relaxed);
                return result;
            }
        }

        // Check resource limit
        if let Some(result) = self.check_resource_limit(resource) {
            if !result.allowed {
                self.stats.total_denied.fetch_add(1, Ordering::Relaxed);
                self.stats.resource_denials.fetch_add(1, Ordering::Relaxed);
                return result;
            }
        }

        // Check action limit
        if self.config.per_action_limits {
            if let Some(result) = self.check_action_limit(action) {
                if !result.allowed {
                    self.stats.total_denied.fetch_add(1, Ordering::Relaxed);
                    self.stats.action_denials.fetch_add(1, Ordering::Relaxed);
                    return result;
                }
            }
        }

        // Record the request
        self.record_request(agent_id, action, resource);

        self.stats.total_allowed.fetch_add(1, Ordering::Relaxed);
        CheckResult {
            allowed: true,
            reason: None,
            current_count: 0,
            max_allowed: self.config.default_agent_rpm,
            retry_after_secs: None,
            limit_type: None,
        }
    }

    fn check_agent_limit(&self, agent_id: &str) -> Option<CheckResult> {
        let mut buckets = self.agent_buckets.write().unwrap();
        let bucket = buckets.entry(agent_id.to_string()).or_insert_with(|| {
            let max_tokens = self.config.default_agent_rpm as f64 * self.config.burst_multiplier;
            let refill_rate = self.config.default_agent_rpm as f64 / 60.0;
            TokenBucket::new(max_tokens, refill_rate)
        });

        if !bucket.try_acquire(1.0) {
            Some(CheckResult {
                allowed: false,
                reason: Some(format!("Agent rate limit exceeded for {}", agent_id)),
                current_count: (bucket.max_tokens - bucket.available()) as u32,
                max_allowed: self.config.default_agent_rpm,
                retry_after_secs: Some(1),
                limit_type: Some(LimitType::Agent),
            })
        } else {
            None
        }
    }

    fn check_resource_limit(&self, resource: &str) -> Option<CheckResult> {
        let limits = self.resource_limits.read().unwrap();

        // Find matching resource limit (supports glob patterns)
        let matching_limit = limits.iter().find(|(pattern, _)| {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                resource.starts_with(prefix)
            } else {
                pattern.as_str() == resource
            }
        });

        let limit = matching_limit.map(|(_, l)| l).cloned().unwrap_or_else(|| {
            ResourceLimit::new(self.config.default_resource_rpm, self.config.window_seconds)
        });

        let mut windows = self.resource_windows.write().unwrap();
        let window = windows
            .entry(resource.to_string())
            .or_insert_with(|| SlidingWindow::new(limit.window_secs, 10));

        let count = window.count();
        let max_with_burst = limit.max_requests + limit.burst_allowance;

        if count >= max_with_burst {
            Some(CheckResult {
                allowed: false,
                reason: Some(format!("Resource rate limit exceeded for {}", resource)),
                current_count: count,
                max_allowed: limit.max_requests,
                retry_after_secs: Some(limit.window_secs),
                limit_type: Some(LimitType::Resource),
            })
        } else {
            None
        }
    }

    fn check_action_limit(&self, action: &str) -> Option<CheckResult> {
        let limits = self.action_limits.read().unwrap();
        let limit = limits.get(action)?;

        let mut windows = self.action_windows.write().unwrap();
        let window = windows
            .entry(action.to_string())
            .or_insert_with(|| SlidingWindow::new(limit.window_secs, 10));

        let count = window.count();
        if count >= limit.max_requests {
            Some(CheckResult {
                allowed: false,
                reason: Some(format!("Action rate limit exceeded for {}", action)),
                current_count: count,
                max_allowed: limit.max_requests,
                retry_after_secs: Some(limit.window_secs),
                limit_type: Some(LimitType::Action),
            })
        } else {
            None
        }
    }

    fn record_request(&self, _agent_id: &str, action: &str, resource: &str) {
        // Record in resource window
        {
            let mut windows = self.resource_windows.write().unwrap();
            if let Some(window) = windows.get_mut(resource) {
                window.record();
            }
        }

        // Record in action window
        if self.config.per_action_limits {
            let mut windows = self.action_windows.write().unwrap();
            if let Some(window) = windows.get_mut(action) {
                window.record();
            }
        }
    }

    /// Get statistics
    pub fn get_stats(&self) -> RateLimiterStatsSnapshot {
        RateLimiterStatsSnapshot {
            total_checked: self.stats.total_checked.load(Ordering::Relaxed),
            total_allowed: self.stats.total_allowed.load(Ordering::Relaxed),
            total_denied: self.stats.total_denied.load(Ordering::Relaxed),
            agent_denials: self.stats.agent_denials.load(Ordering::Relaxed),
            resource_denials: self.stats.resource_denials.load(Ordering::Relaxed),
            action_denials: self.stats.action_denials.load(Ordering::Relaxed),
        }
    }

    /// Reset statistics
    pub fn reset_stats(&self) {
        self.stats.total_checked.store(0, Ordering::Relaxed);
        self.stats.total_allowed.store(0, Ordering::Relaxed);
        self.stats.total_denied.store(0, Ordering::Relaxed);
        self.stats.agent_denials.store(0, Ordering::Relaxed);
        self.stats.resource_denials.store(0, Ordering::Relaxed);
        self.stats.action_denials.store(0, Ordering::Relaxed);
    }

    /// Clear all rate limit state (for testing)
    pub fn clear(&self) {
        self.agent_buckets.write().unwrap().clear();
        self.resource_windows.write().unwrap().clear();
        self.action_windows.write().unwrap().clear();
    }
}

/// Snapshot of rate limiter statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiterStatsSnapshot {
    /// Total requests checked
    pub total_checked: u64,
    /// Total requests allowed
    pub total_allowed: u64,
    /// Total requests denied
    pub total_denied: u64,
    /// Denials by agent limit
    pub agent_denials: u64,
    /// Denials by resource limit
    pub resource_denials: u64,
    /// Denials by action limit
    pub action_denials: u64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_rate_limiting() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_agent_rpm: 10,
            burst_multiplier: 1.0,
            ..Default::default()
        });

        // First 10 requests should pass
        for i in 0..10 {
            let result = limiter.check("agent-1", "read", "/resource");
            assert!(result.allowed, "Request {} should be allowed", i);
        }

        // 11th request should be rate limited
        let result = limiter.check("agent-1", "read", "/resource");
        assert!(!result.allowed, "11th request should be denied");
        assert_eq!(result.limit_type, Some(LimitType::Agent));
    }

    #[test]
    fn test_resource_limits() {
        let limiter = RateLimiter::default_config();
        limiter.add_resource_limit("/sensitive/*", ResourceLimit::new(5, 60));

        // First 5 requests to sensitive resource should pass
        for i in 0..5 {
            let result = limiter.check("agent-1", "read", "/sensitive/data");
            // Record the request manually since we're testing resource limits
            if result.allowed {
                let mut windows = limiter.resource_windows.write().unwrap();
                windows
                    .entry("/sensitive/data".to_string())
                    .or_insert_with(|| SlidingWindow::new(60, 10))
                    .record();
            }
        }
    }

    #[test]
    fn test_action_limits() {
        let limiter = RateLimiter::default_config();
        limiter.add_action_limit(ActionLimit::new("delete", 3, 60));

        // First 3 delete requests should pass (with burst)
        for i in 0..3 {
            let result = limiter.check("agent-1", "delete", "/resource");
            // Record manually
            if result.allowed {
                let mut windows = limiter.action_windows.write().unwrap();
                windows
                    .entry("delete".to_string())
                    .or_insert_with(|| SlidingWindow::new(60, 10))
                    .record();
            }
        }
    }

    #[test]
    fn test_burst_allowance() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_agent_rpm: 10,
            burst_multiplier: 1.5, // 50% burst
            ..Default::default()
        });

        // Should allow 15 requests (10 + 50% burst)
        for i in 0..15 {
            let result = limiter.check("agent-1", "read", "/resource");
            assert!(result.allowed, "Request {} should be allowed with burst", i);
        }

        // 16th should be denied
        let result = limiter.check("agent-1", "read", "/resource");
        assert!(!result.allowed, "16th request should be denied");
    }

    #[test]
    fn test_disabled_rate_limiting() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: false,
            default_agent_rpm: 1,
            ..Default::default()
        });

        // All requests should pass when disabled
        for _ in 0..100 {
            let result = limiter.check("agent-1", "read", "/resource");
            assert!(result.allowed, "Request should be allowed when disabled");
        }
    }

    #[test]
    fn test_stats_tracking() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_agent_rpm: 5,
            burst_multiplier: 1.0,
            ..Default::default()
        });

        // Make 10 requests (5 allowed, 5 denied)
        for _ in 0..10 {
            limiter.check("agent-1", "read", "/resource");
        }

        let stats = limiter.get_stats();
        assert_eq!(stats.total_checked, 10);
        assert_eq!(stats.total_allowed, 5);
        assert_eq!(stats.total_denied, 5);
    }

    #[test]
    fn test_clear() {
        let limiter = RateLimiter::new(RateLimitConfig {
            default_agent_rpm: 1,
            burst_multiplier: 1.0,
            ..Default::default()
        });

        // Use up the limit
        limiter.check("agent-1", "read", "/resource");
        let result = limiter.check("agent-1", "read", "/resource");
        assert!(!result.allowed);

        // Clear and try again
        limiter.clear();
        let result = limiter.check("agent-1", "read", "/resource");
        assert!(result.allowed);
    }
}
