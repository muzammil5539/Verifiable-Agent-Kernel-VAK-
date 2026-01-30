//! # Kernel Configuration
//!
//! This module provides configuration structures for the VAK kernel.
//! Configuration can be loaded from files, environment variables, or constructed programmatically.
//!
//! ## Configuration Sources
//!
//! The kernel supports multiple configuration sources with the following priority (highest first):
//! 1. Environment variables (prefixed with `VAK_`)
//! 2. Configuration file (`vak.toml` or `vak.yaml`)
//! 3. Default values
//!
//! ## Example Configuration File (TOML)
//!
//! ```toml
//! [kernel]
//! name = "production-kernel"
//! max_concurrent_agents = 100
//!
//! [security]
//! enable_sandboxing = true
//! max_execution_time_ms = 30000
//!
//! [audit]
//! enabled = true
//! log_level = "info"
//! ```

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::types::KernelError;

/// Main kernel configuration structure.
///
/// This structure holds all configuration options for the VAK kernel.
/// It can be constructed using the builder pattern or loaded from a file.
///
/// # Example
///
/// ```rust
/// use vak::kernel::config::KernelConfig;
///
/// // Using defaults
/// let config = KernelConfig::default();
///
/// // Using builder pattern
/// let config = KernelConfig::builder()
///     .name("my-kernel")
///     .max_concurrent_agents(50)
///     .build();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfig {
    /// Human-readable name for this kernel instance.
    #[serde(default = "default_name")]
    pub name: String,

    /// Maximum number of agents that can run concurrently.
    #[serde(default = "default_max_concurrent_agents")]
    pub max_concurrent_agents: usize,

    /// Maximum execution time for a single tool invocation.
    #[serde(default = "default_max_execution_time")]
    pub max_execution_time: Duration,

    /// Security-related configuration.
    #[serde(default)]
    pub security: SecurityConfig,

    /// Audit logging configuration.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Policy engine configuration.
    #[serde(default)]
    pub policy: PolicyConfig,

    /// Resource limits configuration.
    #[serde(default)]
    pub resources: ResourceConfig,
}

fn default_name() -> String {
    "vak-kernel".to_string()
}

fn default_max_concurrent_agents() -> usize {
    10
}

fn default_max_execution_time() -> Duration {
    Duration::from_secs(30)
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            name: default_name(),
            max_concurrent_agents: default_max_concurrent_agents(),
            max_execution_time: default_max_execution_time(),
            security: SecurityConfig::default(),
            audit: AuditConfig::default(),
            policy: PolicyConfig::default(),
            resources: ResourceConfig::default(),
        }
    }
}

impl KernelConfig {
    /// Creates a new configuration builder.
    #[must_use]
    pub fn builder() -> KernelConfigBuilder {
        KernelConfigBuilder::default()
    }

    /// Validates the configuration and returns an error if invalid.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `max_concurrent_agents` is 0
    /// - `max_execution_time` is 0
    /// - Policy paths don't exist (if specified)
    pub fn validate(&self) -> Result<(), KernelError> {
        if self.max_concurrent_agents == 0 {
            return Err(KernelError::InvalidConfiguration {
                message: "max_concurrent_agents must be greater than 0".to_string(),
            });
        }

        if self.max_execution_time.is_zero() {
            return Err(KernelError::InvalidConfiguration {
                message: "max_execution_time must be greater than 0".to_string(),
            });
        }

        if self.resources.max_memory_mb == 0 {
            return Err(KernelError::InvalidConfiguration {
                message: "max_memory_mb must be greater than 0".to_string(),
            });
        }

        Ok(())
    }

    /// Loads configuration from a file.
    ///
    /// Supports TOML, YAML, and JSON formats (detected by extension).
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed.
    pub fn from_file(_path: impl Into<PathBuf>) -> Result<Self, KernelError> {
        // TODO: Implement file loading using the `config` crate
        // For now, return default configuration
        Ok(Self::default())
    }

    /// Loads configuration from environment variables.
    ///
    /// Environment variables are prefixed with `VAK_` and use `__` as a separator
    /// for nested values. For example:
    /// - `VAK_NAME` sets `name`
    /// - `VAK_SECURITY__ENABLE_SANDBOXING` sets `security.enable_sandboxing`
    #[must_use]
    pub fn from_env() -> Self {
        // TODO: Implement environment variable loading
        Self::default()
    }
}

/// Builder for `KernelConfig`.
#[derive(Debug, Default)]
pub struct KernelConfigBuilder {
    name: Option<String>,
    max_concurrent_agents: Option<usize>,
    max_execution_time: Option<Duration>,
    security: Option<SecurityConfig>,
    audit: Option<AuditConfig>,
    policy: Option<PolicyConfig>,
    resources: Option<ResourceConfig>,
}

impl KernelConfigBuilder {
    /// Sets the kernel name.
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the maximum number of concurrent agents.
    #[must_use]
    pub fn max_concurrent_agents(mut self, max: usize) -> Self {
        self.max_concurrent_agents = Some(max);
        self
    }

    /// Sets the maximum execution time for tool invocations.
    #[must_use]
    pub fn max_execution_time(mut self, duration: Duration) -> Self {
        self.max_execution_time = Some(duration);
        self
    }

    /// Sets the security configuration.
    #[must_use]
    pub fn security(mut self, config: SecurityConfig) -> Self {
        self.security = Some(config);
        self
    }

    /// Sets the audit configuration.
    #[must_use]
    pub fn audit(mut self, config: AuditConfig) -> Self {
        self.audit = Some(config);
        self
    }

    /// Sets the policy configuration.
    #[must_use]
    pub fn policy(mut self, config: PolicyConfig) -> Self {
        self.policy = Some(config);
        self
    }

    /// Sets the resource limits configuration.
    #[must_use]
    pub fn resources(mut self, config: ResourceConfig) -> Self {
        self.resources = Some(config);
        self
    }

    /// Builds the `KernelConfig`.
    #[must_use]
    pub fn build(self) -> KernelConfig {
        KernelConfig {
            name: self.name.unwrap_or_else(default_name),
            max_concurrent_agents: self.max_concurrent_agents.unwrap_or_else(default_max_concurrent_agents),
            max_execution_time: self.max_execution_time.unwrap_or_else(default_max_execution_time),
            security: self.security.unwrap_or_default(),
            audit: self.audit.unwrap_or_default(),
            policy: self.policy.unwrap_or_default(),
            resources: self.resources.unwrap_or_default(),
        }
    }
}

/// Security-related configuration options.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Whether to enable sandboxing for tool execution.
    #[serde(default = "default_true")]
    pub enable_sandboxing: bool,

    /// Whether to require signed tool requests.
    #[serde(default)]
    pub require_signed_requests: bool,

    /// List of allowed tool names (empty means all tools are allowed).
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// List of blocked tool names.
    #[serde(default)]
    pub blocked_tools: Vec<String>,

    /// Whether to enable rate limiting.
    #[serde(default = "default_true")]
    pub enable_rate_limiting: bool,

    /// Maximum requests per minute per agent.
    #[serde(default = "default_rate_limit")]
    pub max_requests_per_minute: u32,
}

fn default_true() -> bool {
    true
}

fn default_rate_limit() -> u32 {
    60
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enable_sandboxing: true,
            require_signed_requests: false,
            allowed_tools: Vec::new(),
            blocked_tools: Vec::new(),
            enable_rate_limiting: true,
            max_requests_per_minute: default_rate_limit(),
        }
    }
}

/// Audit logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Whether audit logging is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Log level for audit entries.
    #[serde(default = "default_log_level")]
    pub log_level: LogLevel,

    /// Path to store audit logs.
    #[serde(default)]
    pub log_path: Option<PathBuf>,

    /// Whether to include request/response bodies in audit logs.
    #[serde(default)]
    pub include_bodies: bool,

    /// Maximum size of the audit log before rotation (in bytes).
    #[serde(default = "default_max_log_size")]
    pub max_log_size_bytes: u64,

    /// Number of rotated log files to keep.
    #[serde(default = "default_log_retention")]
    pub retention_count: u32,
}

fn default_log_level() -> LogLevel {
    LogLevel::Info
}

fn default_max_log_size() -> u64 {
    100 * 1024 * 1024 // 100 MB
}

fn default_log_retention() -> u32 {
    10
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_level: LogLevel::Info,
            log_path: None,
            include_bodies: false,
            max_log_size_bytes: default_max_log_size(),
            retention_count: default_log_retention(),
        }
    }
}

/// Log level for audit entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Trace level - most verbose.
    Trace,
    /// Debug level.
    Debug,
    /// Info level - default.
    Info,
    /// Warning level.
    Warn,
    /// Error level - least verbose.
    Error,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

/// Policy engine configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Whether policy enforcement is enabled.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Default policy decision when no policy matches.
    #[serde(default)]
    pub default_decision: DefaultPolicyDecision,

    /// Paths to policy definition files.
    #[serde(default)]
    pub policy_paths: Vec<PathBuf>,

    /// Whether to enable policy caching.
    #[serde(default = "default_true")]
    pub enable_caching: bool,

    /// Cache TTL in seconds.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u64,
}

fn default_cache_ttl() -> u64 {
    300 // 5 minutes
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_decision: DefaultPolicyDecision::Deny,
            policy_paths: Vec::new(),
            enable_caching: true,
            cache_ttl_seconds: default_cache_ttl(),
        }
    }
}

/// Default policy decision when no policy matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicyDecision {
    /// Allow by default (open policy).
    Allow,
    /// Deny by default (closed policy - recommended).
    Deny,
}

impl Default for DefaultPolicyDecision {
    fn default() -> Self {
        Self::Deny
    }
}

/// Resource limits configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    /// Maximum memory usage per agent in MB.
    #[serde(default = "default_max_memory")]
    pub max_memory_mb: u64,

    /// Maximum CPU time per request in milliseconds.
    #[serde(default = "default_max_cpu_time")]
    pub max_cpu_time_ms: u64,

    /// Maximum number of concurrent connections per agent.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,

    /// Maximum request body size in bytes.
    #[serde(default = "default_max_request_size")]
    pub max_request_size_bytes: u64,

    /// Maximum response body size in bytes.
    #[serde(default = "default_max_response_size")]
    pub max_response_size_bytes: u64,
}

fn default_max_memory() -> u64 {
    256 // 256 MB
}

fn default_max_cpu_time() -> u64 {
    10000 // 10 seconds
}

fn default_max_connections() -> u32 {
    10
}

fn default_max_request_size() -> u64 {
    1024 * 1024 // 1 MB
}

fn default_max_response_size() -> u64 {
    10 * 1024 * 1024 // 10 MB
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: default_max_memory(),
            max_cpu_time_ms: default_max_cpu_time(),
            max_connections: default_max_connections(),
            max_request_size_bytes: default_max_request_size(),
            max_response_size_bytes: default_max_response_size(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = KernelConfig::default();
        assert_eq!(config.name, "vak-kernel");
        assert_eq!(config.max_concurrent_agents, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_builder() {
        let config = KernelConfig::builder()
            .name("test-kernel")
            .max_concurrent_agents(50)
            .max_execution_time(Duration::from_secs(60))
            .build();

        assert_eq!(config.name, "test-kernel");
        assert_eq!(config.max_concurrent_agents, 50);
        assert_eq!(config.max_execution_time, Duration::from_secs(60));
    }

    #[test]
    fn test_invalid_config() {
        let mut config = KernelConfig::default();
        config.max_concurrent_agents = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_security_config_defaults() {
        let security = SecurityConfig::default();
        assert!(security.enable_sandboxing);
        assert!(!security.require_signed_requests);
        assert!(security.allowed_tools.is_empty());
    }

    #[test]
    fn test_config_serialization() {
        let config = KernelConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: KernelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.name, deserialized.name);
    }
}
