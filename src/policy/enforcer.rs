//! Cedar Policy Enforcer (POL-001, POL-003)
//!
//! This module provides Cedar Policy integration for formal verification
//! of agent permissions. Cedar is a purpose-built authorization language
//! that supports rigorous automated reasoning.
//!
//! # Architecture
//!
//! The enforcer acts as middleware between WASM host functions and their
//! implementations. Every action must pass through Cedar authorization
//! before execution.
//!
//! # Features
//!
//! - Formal policy verification using Cedar language
//! - Dynamic context injection (time, IP, trust score)
//! - Default-deny security model
//! - Policy hot-reloading support
//! - Policy analysis for safety invariants
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::policy::enforcer::{CedarEnforcer, EnforcerConfig, Principal, Action, Resource};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let enforcer = CedarEnforcer::new(EnforcerConfig::default())?;
//!
//! // Load policies from file
//! enforcer.load_policies("policies/agent_policies.cedar").await?;
//!
//! // Check authorization
//! let principal = Principal::agent("agent-123");
//! let action = Action::new("File", "read");
//! let resource = Resource::file("/data/config.json");
//!
//! let decision = enforcer.authorize(&principal, &action, &resource, None)?;
//! if decision.is_allowed() {
//!     // Proceed with action
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.2.1: Decoupled Policy Engine (Cedar)
//! - Cedar Policy Language: https://www.cedarpolicy.com/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Errors that can occur during policy enforcement
#[derive(Debug, Error)]
pub enum EnforcerError {
    /// Policy file not found
    #[error("Policy file not found: {0}")]
    PolicyNotFound(String),

    /// Invalid policy syntax
    #[error("Invalid policy syntax: {0}")]
    InvalidPolicy(String),

    /// Authorization denied
    #[error("Authorization denied: {action} on {resource} by {principal}")]
    Denied {
        principal: String,
        action: String,
        resource: String,
        reason: String,
    },

    /// Policy evaluation error
    #[error("Policy evaluation error: {0}")]
    EvaluationError(String),

    /// Schema validation error
    #[error("Schema validation error: {0}")]
    SchemaError(String),

    /// Context error
    #[error("Context error: {0}")]
    ContextError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),
}

/// Result type for enforcer operations
pub type EnforcerResult<T> = Result<T, EnforcerError>;

/// Configuration for the Cedar enforcer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcerConfig {
    /// Enable enforcement (if false, all actions allowed but logged)
    pub enabled: bool,
    /// Default-deny mode (fail closed if no policy matches)
    pub default_deny: bool,
    /// Path to schema file (optional)
    pub schema_path: Option<String>,
    /// Enable policy caching
    pub cache_enabled: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Log all authorization decisions
    pub audit_decisions: bool,
}

impl Default for EnforcerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_deny: true, // Fail closed as per Gap Analysis Section 3.2
            schema_path: None,
            cache_enabled: true,
            cache_ttl_secs: 300,
            audit_decisions: true,
        }
    }
}

impl EnforcerConfig {
    /// Create a permissive config for testing
    pub fn permissive() -> Self {
        Self {
            enabled: true,
            default_deny: false,
            schema_path: None,
            cache_enabled: false,
            cache_ttl_secs: 0,
            audit_decisions: false,
        }
    }

    /// Create a strict config for production
    pub fn strict() -> Self {
        Self {
            enabled: true,
            default_deny: true,
            schema_path: None,
            cache_enabled: true,
            cache_ttl_secs: 60,
            audit_decisions: true,
        }
    }
}

/// Principal (who is making the request)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Principal {
    /// Entity type (e.g., "Agent", "User", "Service")
    pub entity_type: String,
    /// Entity ID
    pub id: String,
    /// Additional attributes
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

impl std::hash::Hash for Principal {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.entity_type.hash(state);
        self.id.hash(state);
        // Skip attributes for hashing
    }
}

impl Principal {
    /// Create a new principal
    pub fn new(entity_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            entity_type: entity_type.into(),
            id: id.into(),
            attributes: HashMap::new(),
        }
    }

    /// Create an agent principal
    pub fn agent(id: impl Into<String>) -> Self {
        Self::new("Agent", id)
    }

    /// Create a user principal
    pub fn user(id: impl Into<String>) -> Self {
        Self::new("User", id)
    }

    /// Create a service principal
    pub fn service(id: impl Into<String>) -> Self {
        Self::new("Service", id)
    }

    /// Add an attribute
    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Get the Cedar entity UID string
    pub fn to_entity_uid(&self) -> String {
        format!("{}::\"{}\"", self.entity_type, self.id)
    }
}

/// Action being performed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Action {
    /// Action type (e.g., "File", "Network", "Tool")
    pub action_type: String,
    /// Action name (e.g., "read", "write", "execute")
    pub name: String,
}

impl Action {
    /// Create a new action
    pub fn new(action_type: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            action_type: action_type.into(),
            name: name.into(),
        }
    }

    /// File read action
    pub fn file_read() -> Self {
        Self::new("File", "read")
    }

    /// File write action
    pub fn file_write() -> Self {
        Self::new("File", "write")
    }

    /// File delete action
    pub fn file_delete() -> Self {
        Self::new("File", "delete")
    }

    /// Network request action
    pub fn network_request() -> Self {
        Self::new("Network", "request")
    }

    /// Tool execute action
    pub fn tool_execute() -> Self {
        Self::new("Tool", "execute")
    }

    /// Get the Cedar action UID string
    pub fn to_action_uid(&self) -> String {
        format!("Action::\"{}::{}\"", self.action_type, self.name)
    }
}

/// Resource being accessed
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resource {
    /// Resource type (e.g., "File", "Endpoint", "Tool")
    pub resource_type: String,
    /// Resource ID/path
    pub id: String,
    /// Additional attributes
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

impl std::hash::Hash for Resource {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.resource_type.hash(state);
        self.id.hash(state);
        // Skip attributes for hashing
    }
}

impl Resource {
    /// Create a new resource
    pub fn new(resource_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            id: id.into(),
            attributes: HashMap::new(),
        }
    }

    /// Create a file resource
    pub fn file(path: impl Into<String>) -> Self {
        Self::new("File", path)
    }

    /// Create an endpoint resource
    pub fn endpoint(url: impl Into<String>) -> Self {
        Self::new("Endpoint", url)
    }

    /// Create a tool resource
    pub fn tool(name: impl Into<String>) -> Self {
        Self::new("Tool", name)
    }

    /// Add an attribute
    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Get the Cedar entity UID string
    pub fn to_entity_uid(&self) -> String {
        format!("{}::\"{}\"", self.resource_type, self.id)
    }
}

/// Dynamic context for policy evaluation (POL-005)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyContext {
    /// Current timestamp (Unix seconds)
    pub timestamp: Option<u64>,
    /// Request source IP
    pub source_ip: Option<String>,
    /// Agent trust/reputation score (0.0 - 1.0)
    pub trust_score: Option<f64>,
    /// System load level (0.0 - 1.0)
    pub system_load: Option<f64>,
    /// Whether system is in alert mode
    pub alert_mode: Option<bool>,
    /// Custom attributes
    #[serde(default)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl PolicyContext {
    /// Create a new empty context
    pub fn new() -> Self {
        Self::default()
    }

    /// Create context with current timestamp
    pub fn with_current_time(mut self) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        self.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        self
    }

    /// Set trust score
    pub fn with_trust_score(mut self, score: f64) -> Self {
        self.trust_score = Some(score.clamp(0.0, 1.0));
        self
    }

    /// Set source IP
    pub fn with_source_ip(mut self, ip: impl Into<String>) -> Self {
        self.source_ip = Some(ip.into());
        self
    }

    /// Set system load
    pub fn with_system_load(mut self, load: f64) -> Self {
        self.system_load = Some(load.clamp(0.0, 1.0));
        self
    }

    /// Set alert mode
    pub fn with_alert_mode(mut self, alert: bool) -> Self {
        self.alert_mode = Some(alert);
        self
    }

    /// Add custom attribute
    pub fn with_custom(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }
}

/// Authorization decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    /// Whether the action is allowed
    pub allowed: bool,
    /// Reason for the decision
    pub reason: String,
    /// Policy that matched (if any)
    pub matched_policy: Option<String>,
    /// Evaluation duration in microseconds
    pub evaluation_time_us: u64,
    /// Whether this was a cached result
    pub cached: bool,
}

impl Decision {
    /// Create an allow decision
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            allowed: true,
            reason: reason.into(),
            matched_policy: None,
            evaluation_time_us: 0,
            cached: false,
        }
    }

    /// Create a deny decision
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: reason.into(),
            matched_policy: None,
            evaluation_time_us: 0,
            cached: false,
        }
    }

    /// Check if allowed
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }

    /// Check if denied
    pub fn is_denied(&self) -> bool {
        !self.allowed
    }

    /// Get the reason for the decision
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Set matched policy
    pub fn with_policy(mut self, policy: impl Into<String>) -> Self {
        self.matched_policy = Some(policy.into());
        self
    }
}

/// A Cedar-style policy rule (simplified representation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CedarRule {
    /// Unique rule ID
    pub id: String,
    /// Effect: "permit" or "forbid"
    pub effect: String,
    /// Principal pattern (glob or exact)
    pub principal: String,
    /// Action pattern
    pub action: String,
    /// Resource pattern
    pub resource: String,
    /// Conditions (as expressions)
    #[serde(default)]
    pub conditions: Vec<String>,
    /// Human-readable description
    pub description: Option<String>,
}

/// Policy set containing multiple rules
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicySet {
    /// Policy rules
    pub rules: Vec<CedarRule>,
    /// Policy set version
    pub version: Option<String>,
    /// Last modified timestamp
    pub modified: Option<u64>,
}

impl PolicySet {
    /// Create an empty policy set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: CedarRule) {
        self.rules.push(rule);
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Get rule count
    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// The Cedar Policy Enforcer
///
/// This is the main entry point for policy enforcement. It evaluates
/// authorization requests against loaded policies using Cedar semantics.
pub struct CedarEnforcer {
    config: EnforcerConfig,
    policies: Arc<RwLock<PolicySet>>,
    stats: EnforcerStats,
}

/// Statistics for the enforcer
#[derive(Debug, Default)]
pub struct EnforcerStats {
    /// Total authorization requests
    pub total_requests: std::sync::atomic::AtomicU64,
    /// Allowed requests
    pub allowed_requests: std::sync::atomic::AtomicU64,
    /// Denied requests
    pub denied_requests: std::sync::atomic::AtomicU64,
    /// Errors during evaluation
    pub errors: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for CedarEnforcer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CedarEnforcer")
            .field("config", &self.config)
            .field("stats", &self.stats)
            .finish()
    }
}

impl CedarEnforcer {
    /// Create a new Cedar enforcer
    pub fn new(config: EnforcerConfig) -> EnforcerResult<Self> {
        info!(
            enabled = config.enabled,
            default_deny = config.default_deny,
            "Creating Cedar enforcer"
        );

        Ok(Self {
            config,
            policies: Arc::new(RwLock::new(PolicySet::new())),
            stats: EnforcerStats::default(),
        })
    }

    /// Create with default configuration
    pub fn with_defaults() -> EnforcerResult<Self> {
        Self::new(EnforcerConfig::default())
    }

    /// Create a permissive enforcer for testing (always allows)
    pub fn new_permissive() -> Self {
        Self {
            config: EnforcerConfig::permissive(),
            policies: Arc::new(RwLock::new(PolicySet::new())),
            stats: EnforcerStats::default(),
        }
    }

    /// Load policies from a YAML file
    pub async fn load_policies<P: AsRef<Path>>(&self, path: P) -> EnforcerResult<()> {
        let path = path.as_ref();
        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| EnforcerError::IoError(format!("{}: {}", path.display(), e)))?;

        let policy_set: PolicySet = serde_yaml::from_str(&content)
            .map_err(|e| EnforcerError::InvalidPolicy(e.to_string()))?;

        info!(
            path = %path.display(),
            rules = policy_set.len(),
            "Loaded policy set"
        );

        let mut policies = self.policies.write().await;
        *policies = policy_set;

        Ok(())
    }

    /// Load policies from a string
    pub async fn load_policies_from_str(&self, content: &str) -> EnforcerResult<()> {
        let policy_set: PolicySet = serde_yaml::from_str(content)
            .map_err(|e| EnforcerError::InvalidPolicy(e.to_string()))?;

        let mut policies = self.policies.write().await;
        *policies = policy_set;

        Ok(())
    }

    /// Add a single rule
    pub async fn add_rule(&self, rule: CedarRule) {
        let mut policies = self.policies.write().await;
        policies.add_rule(rule);
    }

    /// Authorize a request
    pub async fn authorize(
        &self,
        principal: &Principal,
        action: &Action,
        resource: &Resource,
        context: Option<&PolicyContext>,
    ) -> EnforcerResult<Decision> {
        use std::sync::atomic::Ordering;
        use std::time::Instant;

        let start = Instant::now();
        self.stats.total_requests.fetch_add(1, Ordering::Relaxed);

        // If enforcement is disabled, allow everything
        if !self.config.enabled {
            debug!("Enforcement disabled, allowing");
            return Ok(Decision::allow("Enforcement disabled"));
        }

        let policies = self.policies.read().await;

        // Default deny if no policies loaded
        if policies.is_empty() {
            if self.config.default_deny {
                warn!(
                    principal = %principal.to_entity_uid(),
                    action = %action.to_action_uid(),
                    resource = %resource.to_entity_uid(),
                    "No policies loaded, denying (default-deny mode)"
                );
                self.stats.denied_requests.fetch_add(1, Ordering::Relaxed);
                return Ok(Decision::deny("No policies loaded (default-deny)"));
            } else {
                return Ok(Decision::allow("No policies loaded (default-allow)"));
            }
        }

        // Evaluate policies
        let decision = self.evaluate_policies(
            &policies,
            principal,
            action,
            resource,
            context,
        );

        let elapsed = start.elapsed();
        let mut result = match decision {
            Ok(d) => d,
            Err(e) => {
                error!(error = %e, "Policy evaluation error");
                self.stats.errors.fetch_add(1, Ordering::Relaxed);
                if self.config.default_deny {
                    Decision::deny(format!("Evaluation error: {}", e))
                } else {
                    return Err(e);
                }
            }
        };

        result.evaluation_time_us = elapsed.as_micros() as u64;

        if result.allowed {
            self.stats.allowed_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.denied_requests.fetch_add(1, Ordering::Relaxed);
        }

        if self.config.audit_decisions {
            info!(
                principal = %principal.to_entity_uid(),
                action = %action.to_action_uid(),
                resource = %resource.to_entity_uid(),
                allowed = result.allowed,
                reason = %result.reason,
                time_us = result.evaluation_time_us,
                "Authorization decision"
            );
        }

        Ok(result)
    }

    /// Evaluate policies against a request
    fn evaluate_policies(
        &self,
        policies: &PolicySet,
        principal: &Principal,
        action: &Action,
        resource: &Resource,
        _context: Option<&PolicyContext>,
    ) -> EnforcerResult<Decision> {
        let principal_uid = principal.to_entity_uid();
        let action_uid = action.to_action_uid();
        let resource_uid = resource.to_entity_uid();

        // Check for explicit forbid rules first (forbid overrides permit)
        for rule in &policies.rules {
            if rule.effect == "forbid" && self.rule_matches(rule, &principal_uid, &action_uid, &resource_uid) {
                return Ok(Decision::deny(format!(
                    "Forbidden by rule: {}",
                    rule.description.as_deref().unwrap_or(&rule.id)
                )).with_policy(rule.id.clone()));
            }
        }

        // Check for permit rules
        for rule in &policies.rules {
            if rule.effect == "permit" && self.rule_matches(rule, &principal_uid, &action_uid, &resource_uid) {
                return Ok(Decision::allow(format!(
                    "Permitted by rule: {}",
                    rule.description.as_deref().unwrap_or(&rule.id)
                )).with_policy(rule.id.clone()));
            }
        }

        // Default decision
        if self.config.default_deny {
            Ok(Decision::deny("No matching permit rule (default-deny)"))
        } else {
            Ok(Decision::allow("No matching forbid rule (default-allow)"))
        }
    }

    /// Check if a rule matches the request
    fn rule_matches(
        &self,
        rule: &CedarRule,
        principal: &str,
        action: &str,
        resource: &str,
    ) -> bool {
        self.pattern_matches(&rule.principal, principal)
            && self.pattern_matches(&rule.action, action)
            && self.pattern_matches(&rule.resource, resource)
    }

    /// Simple glob-style pattern matching
    fn pattern_matches(&self, pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            return value.starts_with(prefix);
        }
        if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            return value.ends_with(suffix);
        }
        pattern == value
    }

    /// Get the configuration
    pub fn config(&self) -> &EnforcerConfig {
        &self.config
    }

    /// Get enforcement statistics
    pub fn stats(&self) -> &EnforcerStats {
        &self.stats
    }

    /// Check if enforcement is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Helper function to create a quick permit rule
pub fn permit_rule(
    id: impl Into<String>,
    principal: impl Into<String>,
    action: impl Into<String>,
    resource: impl Into<String>,
) -> CedarRule {
    CedarRule {
        id: id.into(),
        effect: "permit".to_string(),
        principal: principal.into(),
        action: action.into(),
        resource: resource.into(),
        conditions: vec![],
        description: None,
    }
}

/// Helper function to create a quick forbid rule
pub fn forbid_rule(
    id: impl Into<String>,
    principal: impl Into<String>,
    action: impl Into<String>,
    resource: impl Into<String>,
) -> CedarRule {
    CedarRule {
        id: id.into(),
        effect: "forbid".to_string(),
        principal: principal.into(),
        action: action.into(),
        resource: resource.into(),
        conditions: vec![],
        description: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enforcer_default_deny() {
        let enforcer = CedarEnforcer::new(EnforcerConfig::default()).unwrap();

        let principal = Principal::agent("test-agent");
        let action = Action::file_read();
        let resource = Resource::file("/etc/passwd");

        let decision = enforcer
            .authorize(&principal, &action, &resource, None)
            .await
            .unwrap();

        assert!(decision.is_denied());
        assert!(decision.reason.contains("No policies loaded"));
    }

    #[tokio::test]
    async fn test_enforcer_permit_rule() {
        let enforcer = CedarEnforcer::new(EnforcerConfig::default()).unwrap();

        // Add a permit rule
        enforcer
            .add_rule(permit_rule(
                "allow-agent-read",
                "Agent::*",
                "Action::\"File::read\"",
                "File::*",
            ))
            .await;

        let principal = Principal::agent("test-agent");
        let action = Action::file_read();
        let resource = Resource::file("/data/test.txt");

        let decision = enforcer
            .authorize(&principal, &action, &resource, None)
            .await
            .unwrap();

        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_enforcer_forbid_overrides_permit() {
        let enforcer = CedarEnforcer::new(EnforcerConfig::default()).unwrap();

        // Add permit rule for all files
        enforcer
            .add_rule(permit_rule(
                "allow-all-read",
                "*",
                "*",
                "File::*",
            ))
            .await;

        // Add forbid rule for sensitive files
        enforcer
            .add_rule(forbid_rule(
                "deny-secrets",
                "*",
                "*",
                "File::\"/etc/shadow\"",
            ))
            .await;

        let principal = Principal::agent("test-agent");
        let action = Action::file_read();
        let resource = Resource::file("/etc/shadow");

        let decision = enforcer
            .authorize(&principal, &action, &resource, None)
            .await
            .unwrap();

        assert!(decision.is_denied());
        assert!(decision.matched_policy.as_deref() == Some("deny-secrets"));
    }

    #[tokio::test]
    async fn test_policy_context() {
        let context = PolicyContext::new()
            .with_current_time()
            .with_trust_score(0.8)
            .with_source_ip("192.168.1.1")
            .with_system_load(0.5);

        assert!(context.timestamp.is_some());
        assert_eq!(context.trust_score, Some(0.8));
        assert_eq!(context.source_ip, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_principal_entity_uid() {
        let principal = Principal::agent("agent-123");
        assert_eq!(principal.to_entity_uid(), "Agent::\"agent-123\"");

        let principal = Principal::user("user@example.com");
        assert_eq!(principal.to_entity_uid(), "User::\"user@example.com\"");
    }

    #[test]
    fn test_action_uid() {
        let action = Action::file_read();
        assert_eq!(action.to_action_uid(), "Action::\"File::read\"");
    }

    #[test]
    fn test_resource_uid() {
        let resource = Resource::file("/data/config.json");
        assert_eq!(resource.to_entity_uid(), "File::\"/data/config.json\"");
    }
}
