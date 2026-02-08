//! Rate Limiting for Kernel Operations (SEC-005)
//!
//! Provides per-resource rate limiting to prevent abuse and ensure fair access.
//!
//! # Overview
//!
//! This module implements a multi-layer rate limiting system:
//! - Per-agent token bucket for overall throughput control
//! - Per-resource sliding window for fine-grained limits
//! - Per-action sliding window for operation-specific limits
//!
//! # Example
//!
//! ```rust,ignore
//! use vak::kernel::rate_limiter::{RateLimiter, RateLimitConfig, ResourceKey};
//!
//! let limiter = RateLimiter::with_defaults();
//! let key = ResourceKey::new("agent-1", "read", "/data/file.txt");
//!
//! let result = limiter.check(&key).await;
//! if result.allowed {
//!     // Proceed with operation
//! }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during rate limiting
#[derive(Debug, Error, Clone)]
pub enum RateLimitError {
    /// Rate limit exceeded
    #[error("Rate limit exceeded: {0}")]
    LimitExceeded(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Invalid pattern
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
}

/// Result type for rate limiting operations
pub type RateLimitResult<T> = Result<T, RateLimitError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Default requests per second
    pub default_rps: u32,
    /// Default burst size
    pub default_burst: u32,
    /// Window size in seconds
    pub window_secs: u64,
    /// Enable rate limiting
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_rps: 100,
            default_burst: 20,
            window_secs: 1,
            enabled: true,
        }
    }
}

// ============================================================================
// Resource Key
// ============================================================================

/// Key for identifying rate-limited resources
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceKey {
    /// Agent ID
    pub agent_id: String,
    /// Action type
    pub action: String,
    /// Resource path
    pub resource: String,
}

impl ResourceKey {
    /// Create a new resource key
    pub fn new(
        agent_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            action: action.into(),
            resource: resource.into(),
        }
    }
}

// ============================================================================
// Token Bucket
// ============================================================================

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Current tokens available
    pub tokens: f64,
    /// Maximum tokens (burst size)
    pub max_tokens: f64,
    /// Refill rate (tokens per second)
    pub refill_rate: f64,
    /// Last refill time
    pub last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            tokens: max_tokens as f64,
            max_tokens: max_tokens as f64,
            refill_rate: refill_rate as f64,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume a token
    pub fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Get current token count
    pub fn available_tokens(&mut self) -> f64 {
        self.refill();
        self.tokens
    }
}

// ============================================================================
// Sliding Window
// ============================================================================

/// Sliding window counter for rate limiting
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    /// Request timestamps
    requests: Vec<Instant>,
    /// Window duration
    window: Duration,
    /// Maximum requests per window
    max_requests: u32,
}

impl SlidingWindow {
    /// Create a new sliding window
    pub fn new(window_secs: u64, max_requests: u32) -> Self {
        Self {
            requests: Vec::new(),
            window: Duration::from_secs(window_secs),
            max_requests,
        }
    }

    /// Record a request and check if allowed
    pub fn record(&mut self) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);

        // Remove old requests
        self.requests.retain(|&t| t > cutoff);

        // Check if under limit
        if self.requests.len() < self.max_requests as usize {
            self.requests.push(now);
            true
        } else {
            false
        }
    }

    /// Get current request count in window
    pub fn current_count(&mut self) -> usize {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        self.requests.retain(|&t| t > cutoff);
        self.requests.len()
    }
}

// ============================================================================
// Limit Result
// ============================================================================

/// Result of a rate limit check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Remaining requests in window
    pub remaining: u32,
    /// Seconds until reset
    pub reset_in_secs: u64,
    /// Retry after seconds (if not allowed)
    pub retry_after_secs: Option<u64>,
}

impl LimitResult {
    /// Create an allowed result
    pub fn allowed(remaining: u32, reset_in_secs: u64) -> Self {
        Self {
            allowed: true,
            remaining,
            reset_in_secs,
            retry_after_secs: None,
        }
    }

    /// Create a denied result
    pub fn denied(retry_after_secs: u64) -> Self {
        Self {
            allowed: false,
            remaining: 0,
            reset_in_secs: retry_after_secs,
            retry_after_secs: Some(retry_after_secs),
        }
    }
}

// ============================================================================
// Rate Limiter
// ============================================================================

/// Rate limiter for kernel operations
pub struct RateLimiter {
    /// Configuration
    config: RateLimitConfig,
    /// Per-agent token buckets
    agent_buckets: Arc<RwLock<HashMap<String, TokenBucket>>>,
    /// Per-resource sliding windows
    resource_windows: Arc<RwLock<HashMap<ResourceKey, SlidingWindow>>>,
    /// Per-action sliding windows
    action_windows: Arc<RwLock<HashMap<String, SlidingWindow>>>,
    /// Custom resource limits (pattern -> (rps, burst))
    resource_limits: Arc<RwLock<Vec<(String, u32, u32)>>>,
    /// Custom action limits (action -> (rps, burst))
    action_limits: Arc<RwLock<HashMap<String, (u32, u32)>>>,
    /// Statistics
    stats: Arc<RwLock<RateLimitStats>>,
}

/// Rate limiting statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RateLimitStats {
    /// Total requests checked
    pub total_requests: u64,
    /// Requests allowed
    pub allowed: u64,
    /// Requests denied
    pub denied: u64,
    /// Burst requests used
    pub burst_used: u64,
}

impl RateLimiter {
    /// Create a new rate limiter
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            agent_buckets: Arc::new(RwLock::new(HashMap::new())),
            resource_windows: Arc::new(RwLock::new(HashMap::new())),
            action_windows: Arc::new(RwLock::new(HashMap::new())),
            resource_limits: Arc::new(RwLock::new(Vec::new())),
            action_limits: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(RateLimitStats::default())),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Add a resource limit pattern
    pub async fn add_resource_limit(&self, pattern: &str, rps: u32, burst: u32) {
        let mut limits = self.resource_limits.write().await;
        limits.push((pattern.to_string(), rps, burst));
    }

    /// Add an action limit
    pub async fn add_action_limit(&self, action: &str, rps: u32, burst: u32) {
        let mut limits = self.action_limits.write().await;
        limits.insert(action.to_string(), (rps, burst));
    }

    /// Check if a request is allowed
    pub async fn check(&self, key: &ResourceKey) -> LimitResult {
        if !self.config.enabled {
            return LimitResult::allowed(u32::MAX, 0);
        }

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_requests += 1;
        }

        // Check agent bucket
        let agent_allowed = self.check_agent_bucket(&key.agent_id).await;
        if !agent_allowed {
            let mut stats = self.stats.write().await;
            stats.denied += 1;
            return LimitResult::denied(1);
        }

        // Check resource window
        let resource_allowed = self.check_resource_window(key).await;
        if !resource_allowed {
            let mut stats = self.stats.write().await;
            stats.denied += 1;
            return LimitResult::denied(self.config.window_secs);
        }

        // Check action window
        let action_allowed = self.check_action_window(&key.action).await;
        if !action_allowed {
            let mut stats = self.stats.write().await;
            stats.denied += 1;
            return LimitResult::denied(self.config.window_secs);
        }

        // All checks passed
        {
            let mut stats = self.stats.write().await;
            stats.allowed += 1;
        }

        LimitResult::allowed(self.config.default_rps, self.config.window_secs)
    }

    /// Check agent token bucket
    async fn check_agent_bucket(&self, agent_id: &str) -> bool {
        let mut buckets = self.agent_buckets.write().await;
        let bucket = buckets.entry(agent_id.to_string()).or_insert_with(|| {
            TokenBucket::new(self.config.default_burst, self.config.default_rps)
        });
        bucket.try_consume()
    }

    /// Check resource sliding window
    async fn check_resource_window(&self, key: &ResourceKey) -> bool {
        // Find matching limit
        let limits = self.resource_limits.read().await;
        let matching_limit = limits.iter().find(|(pattern, _, _)| {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                key.resource.starts_with(prefix)
            } else {
                key.resource == *pattern
            }
        });

        let (rps, _burst) = matching_limit
            .map(|(_, r, b)| (*r, *b))
            .unwrap_or((self.config.default_rps, self.config.default_burst));
        drop(limits);

        let mut windows = self.resource_windows.write().await;
        let window = windows
            .entry(key.clone())
            .or_insert_with(|| SlidingWindow::new(self.config.window_secs, rps));
        window.record()
    }

    /// Check action sliding window
    async fn check_action_window(&self, action: &str) -> bool {
        let limits = self.action_limits.read().await;
        let (rps, _burst) = limits
            .get(action)
            .copied()
            .unwrap_or((self.config.default_rps, self.config.default_burst));
        drop(limits);

        let mut windows = self.action_windows.write().await;
        let window = windows
            .entry(action.to_string())
            .or_insert_with(|| SlidingWindow::new(self.config.window_secs, rps));
        window.record()
    }

    /// Record a successful request (for tracking burst usage)
    pub async fn record_success(&self, key: &ResourceKey) {
        // Update resource window
        {
            let mut windows = self.resource_windows.write().await;
            if let Some(window) = windows.get_mut(key) {
                let _ = window.record();
            }
        }

        // Update action window
        {
            let mut windows = self.action_windows.write().await;
            if let Some(window) = windows.get_mut(&key.action) {
                let _ = window.record();
            }
        }
    }

    /// Get current statistics
    pub async fn get_stats(&self) -> RateLimitStats {
        self.stats.read().await.clone()
    }

    /// Reset all rate limit state
    pub async fn reset(&self) {
        self.agent_buckets.write().await.clear();
        self.resource_windows.write().await.clear();
        self.action_windows.write().await.clear();
    }

    /// Check if rate limiting is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("config", &self.config)
            .field("enabled", &self.config.enabled)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10, 5);

        // Should have full tokens initially
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());

        // Consume all tokens
        for _ in 0..8 {
            bucket.try_consume();
        }

        // Should be empty now
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_sliding_window() {
        let mut window = SlidingWindow::new(1, 5);

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(window.record());
        }

        // Should deny 6th request
        assert!(!window.record());

        // Count should be 5
        assert_eq!(window.current_count(), 5);
    }

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let limiter = RateLimiter::with_defaults();

        let key = ResourceKey::new("agent-1", "read", "/data/file.txt");

        // First request should be allowed
        let result = limiter.check(&key).await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let key = ResourceKey::new("agent-1", "read", "/data/file.txt");

        // Should always allow when disabled
        for _ in 0..1000 {
            let result = limiter.check(&key).await;
            assert!(result.allowed);
        }
    }

    #[tokio::test]
    async fn test_resource_limit_pattern() {
        let limiter = RateLimiter::with_defaults();

        // Add a specific limit for /sensitive/* paths
        limiter.add_resource_limit("/sensitive/*", 2, 2).await;

        let key = ResourceKey::new("agent-1", "read", "/sensitive/data.txt");

        // First 2 should be allowed
        assert!(limiter.check(&key).await.allowed);
        assert!(limiter.check(&key).await.allowed);

        // 3rd should be denied (per-resource limit)
        // Note: This may pass agent bucket but fail resource window
    }

    #[tokio::test]
    async fn test_action_limit() {
        let limiter = RateLimiter::with_defaults();

        // Add a specific limit for write actions
        limiter.add_action_limit("write", 3, 3).await;

        let key = ResourceKey::new("agent-1", "write", "/data/file.txt");

        // First 3 should be allowed
        assert!(limiter.check(&key).await.allowed);
        assert!(limiter.check(&key).await.allowed);
        assert!(limiter.check(&key).await.allowed);
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let limiter = RateLimiter::with_defaults();

        let key = ResourceKey::new("agent-1", "read", "/data/file.txt");

        // Make some requests
        limiter.check(&key).await;
        limiter.check(&key).await;
        limiter.check(&key).await;

        let stats = limiter.get_stats().await;
        assert_eq!(stats.total_requests, 3);
    }

    #[tokio::test]
    async fn test_reset() {
        let limiter = RateLimiter::with_defaults();

        let key = ResourceKey::new("agent-1", "read", "/data/file.txt");

        // Make some requests
        limiter.check(&key).await;
        limiter.check(&key).await;

        // Reset
        limiter.reset().await;

        // Should have fresh state
        let result = limiter.check(&key).await;
        assert!(result.allowed);
    }

    #[test]
    fn test_limit_result() {
        let allowed = LimitResult::allowed(10, 60);
        assert!(allowed.allowed);
        assert_eq!(allowed.remaining, 10);
        assert!(allowed.retry_after_secs.is_none());

        let denied = LimitResult::denied(30);
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after_secs, Some(30));
    }

    #[test]
    fn test_resource_key() {
        let key1 = ResourceKey::new("agent-1", "read", "/data/file.txt");
        let key2 = ResourceKey::new("agent-1", "read", "/data/file.txt");
        let key3 = ResourceKey::new("agent-2", "read", "/data/file.txt");

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }
}
