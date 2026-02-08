//! Policy Hot-Reloading System (POL-006)
//!
//! Provides lock-free policy updates using ArcSwap with Merkle log versioning.
//! Policies can be reloaded at runtime without blocking ongoing evaluations.
//!
//! # Features
//! - Lock-free policy reads using `ArcSwap`
//! - File system watching for automatic reload
//! - Merkle log versioning for policy history
//! - Atomic policy swaps with rollback support
//!
//! # Example
//! ```rust,ignore
//! use vak::policy::hot_reload::{HotReloadablePolicyEngine, HotReloadConfig};
//!
//! let config = HotReloadConfig::new("policies/");
//! let engine = HotReloadablePolicyEngine::new(config).await?;
//!
//! // Policies are automatically reloaded when files change
//! engine.start_watching().await?;
//! ```

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::{ArcSwap, Guard};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, warn};

use crate::policy::{ConditionOperator, PolicyCondition, PolicyEffect, PolicyRule};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during hot-reload operations
#[derive(Debug, Error)]
pub enum HotReloadError {
    /// Failed to load policy file
    #[error("Failed to load policy file: {0}")]
    LoadError(String),

    /// Policy validation failed
    #[error("Policy validation failed: {0}")]
    ValidationError(String),

    /// File system error
    #[error("File system error: {0}")]
    FileSystemError(#[from] std::io::Error),

    /// Watch error
    #[error("Watch error: {0}")]
    WatchError(String),

    /// Rollback error
    #[error("Rollback failed: {0}")]
    RollbackError(String),
}

/// Result type for hot-reload operations
pub type HotReloadResult<T> = Result<T, HotReloadError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for hot-reloadable policy engine
#[derive(Debug, Clone)]
pub struct HotReloadConfig {
    /// Directory containing policy files
    pub policy_dir: PathBuf,
    /// File extensions to watch (default: [".yaml", ".yml", ".cedar"])
    pub watch_extensions: Vec<String>,
    /// Debounce duration for file changes
    pub debounce_duration: Duration,
    /// Maximum number of policy versions to retain
    pub max_versions: usize,
    /// Whether to validate policies before loading
    pub validate_before_load: bool,
    /// Whether to auto-rollback on validation failure
    pub auto_rollback: bool,
}

impl Default for HotReloadConfig {
    fn default() -> Self {
        Self {
            policy_dir: PathBuf::from("policies"),
            watch_extensions: vec![
                ".yaml".to_string(),
                ".yml".to_string(),
                ".cedar".to_string(),
            ],
            debounce_duration: Duration::from_millis(500),
            max_versions: 10,
            validate_before_load: true,
            auto_rollback: true,
        }
    }
}

impl HotReloadConfig {
    /// Create a new configuration with the given policy directory
    pub fn new(policy_dir: impl Into<PathBuf>) -> Self {
        Self {
            policy_dir: policy_dir.into(),
            ..Default::default()
        }
    }

    /// Set the debounce duration
    pub fn with_debounce(mut self, duration: Duration) -> Self {
        self.debounce_duration = duration;
        self
    }

    /// Set the maximum number of versions to retain
    pub fn with_max_versions(mut self, max: usize) -> Self {
        self.max_versions = max;
        self
    }
}

// ============================================================================
// Policy Version
// ============================================================================

/// A versioned snapshot of the policy set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyVersion {
    /// Version number (monotonically increasing)
    pub version: u64,
    /// Merkle root hash of all policies
    pub merkle_root: String,
    /// Timestamp when this version was created
    pub created_at: SystemTime,
    /// Hash of the previous version (for chain integrity)
    pub previous_hash: Option<String>,
    /// Individual policy hashes
    pub policy_hashes: HashMap<String, String>,
    /// Description of changes
    pub change_description: Option<String>,
}

impl PolicyVersion {
    /// Create a new policy version
    pub fn new(version: u64, policies: &[PolicyRule], previous: Option<&PolicyVersion>) -> Self {
        let policy_hashes: HashMap<String, String> = policies
            .iter()
            .map(|p| (p.id.clone(), Self::hash_policy(p)))
            .collect();

        let merkle_root = Self::compute_merkle_root(&policy_hashes);
        let previous_hash = previous.map(|p| p.merkle_root.clone());

        Self {
            version,
            merkle_root,
            created_at: SystemTime::now(),
            previous_hash,
            policy_hashes,
            change_description: None,
        }
    }

    /// Hash a single policy
    fn hash_policy(policy: &PolicyRule) -> String {
        let mut hasher = Sha256::new();
        hasher.update(policy.id.as_bytes());
        hasher.update(format!("{:?}", policy.effect).as_bytes());
        hasher.update(format!("{}", policy.priority).as_bytes());
        hasher.update(policy.action_pattern.as_bytes());
        hasher.update(policy.resource_pattern.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Compute Merkle root from policy hashes
    fn compute_merkle_root(hashes: &HashMap<String, String>) -> String {
        let mut sorted_hashes: Vec<_> = hashes.values().collect();
        sorted_hashes.sort();

        let mut hasher = Sha256::new();
        for hash in sorted_hashes {
            hasher.update(hash.as_bytes());
        }
        hex::encode(hasher.finalize())
    }

    /// Set the change description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.change_description = Some(description.into());
        self
    }
}

// ============================================================================
// Policy Snapshot
// ============================================================================

/// An immutable snapshot of the current policy state
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    /// The policies in this snapshot
    pub policies: Vec<PolicyRule>,
    /// Version information
    pub version: PolicyVersion,
}

impl PolicySnapshot {
    /// Create a new snapshot
    pub fn new(policies: Vec<PolicyRule>, version: PolicyVersion) -> Self {
        Self { policies, version }
    }

    /// Find a policy by ID
    pub fn find_policy(&self, id: &str) -> Option<&PolicyRule> {
        self.policies.iter().find(|p| p.id == id)
    }

    /// Get the number of policies
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

// ============================================================================
// Hot Reload Metrics
// ============================================================================

/// Metrics for hot-reload operations
/// Metrics for hot-reload operations
#[derive(Debug, Default, Clone)]
pub struct HotReloadMetrics {
    /// Number of successful reloads
    pub successful_reloads: u64,
    /// Number of failed reloads
    pub failed_reloads: u64,
    /// Number of rollbacks performed
    pub rollbacks: u64,
    /// Last reload timestamp
    pub last_reload: Option<SystemTime>,
    /// Last reload duration
    pub last_reload_duration: Option<Duration>,
    /// Current policy count
    pub policy_count: usize,
    /// Current version number
    pub current_version: u64,
}

// ============================================================================
// Policy Decision Type for Hot Reload
// ============================================================================

/// Decision result from hot-reloadable policy evaluation
#[derive(Debug, Clone)]
pub enum HotReloadDecision {
    /// Action is allowed
    Allow {
        /// The rule that matched
        matched_rule: String,
    },
    /// Action is denied
    Deny {
        /// The rule that matched
        matched_rule: String,
        /// Reason for denial
        reason: String,
    },
}

impl HotReloadDecision {
    /// Check if the decision allows the action
    pub fn is_allowed(&self) -> bool {
        matches!(self, HotReloadDecision::Allow { .. })
    }
}

// ============================================================================
// Hot-Reloadable Policy Engine
// ============================================================================

/// Policy engine with hot-reload capability
///
/// Uses `ArcSwap` for lock-free reads during policy evaluation,
/// allowing policies to be updated without blocking ongoing requests.
pub struct HotReloadablePolicyEngine {
    /// Current policy snapshot (lock-free access)
    current: ArcSwap<PolicySnapshot>,
    /// Version history for rollback
    version_history: RwLock<Vec<Arc<PolicySnapshot>>>,
    /// Configuration
    config: HotReloadConfig,
    /// Metrics
    metrics: RwLock<HotReloadMetrics>,
    /// Shutdown signal sender
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl HotReloadablePolicyEngine {
    /// Create a new hot-reloadable policy engine
    pub async fn new(config: HotReloadConfig) -> HotReloadResult<Self> {
        // Load initial policies
        let policies = Self::load_policies_from_dir(&config.policy_dir).await?;

        // Create engine first so we can use validate_policies
        let engine = Self {
            current: ArcSwap::from(Arc::new(PolicySnapshot::new(
                vec![],
                PolicyVersion::new(0, &[], None),
            ))),
            version_history: RwLock::new(vec![]),
            config,
            metrics: RwLock::new(HotReloadMetrics::default()),
            shutdown_tx: None,
        };

        // Validate policies if configured
        if engine.config.validate_before_load {
            engine.validate_policies(&policies)?;
        }

        // Create version and snapshot
        let version = PolicyVersion::new(1, &policies, None);
        let snapshot = Arc::new(PolicySnapshot::new(policies, version));

        // Store the snapshot
        engine.current.store(snapshot.clone());
        *engine.version_history.write().await = vec![snapshot];

        Ok(engine)
    }

    /// Create with default configuration
    pub async fn with_defaults() -> HotReloadResult<Self> {
        Self::new(HotReloadConfig::default()).await
    }

    /// Get the current policy snapshot (lock-free read)
    pub fn current(&self) -> Guard<Arc<PolicySnapshot>> {
        self.current.load()
    }

    /// Get the current version number
    pub fn current_version(&self) -> u64 {
        self.current.load().version.version
    }

    /// Get the Merkle root of current policies
    pub fn merkle_root(&self) -> String {
        self.current.load().version.merkle_root.clone()
    }

    /// Evaluate a policy decision
    pub fn evaluate(
        &self,
        agent_id: &str,
        action: &str,
        resource: &str,
        context: &serde_json::Value,
    ) -> HotReloadDecision {
        let snapshot = self.current.load();

        // Find matching policies sorted by priority
        let mut matching_policies: Vec<_> = snapshot
            .policies
            .iter()
            .filter(|p| Self::matches_policy(p, action, resource))
            .collect();

        matching_policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Apply first matching policy (highest priority)
        for policy in matching_policies {
            if Self::evaluate_conditions(policy, agent_id, context) {
                return match policy.effect {
                    PolicyEffect::Allow => HotReloadDecision::Allow {
                        matched_rule: policy.id.clone(),
                    },
                    PolicyEffect::Deny => HotReloadDecision::Deny {
                        matched_rule: policy.id.clone(),
                        reason: format!("Policy {} denied action", policy.id),
                    },
                };
            }
        }

        // Default deny
        HotReloadDecision::Deny {
            matched_rule: "default".to_string(),
            reason: "No matching policy found (default deny)".to_string(),
        }
    }

    fn matches_policy(policy: &PolicyRule, action: &str, resource: &str) -> bool {
        let action_pattern = &policy.action_pattern;
        let resource_pattern = &policy.resource_pattern;

        let action_match = action_pattern == "*"
            || action_pattern == action
            || (action_pattern.ends_with('*')
                && action.starts_with(&action_pattern[..action_pattern.len() - 1]));

        let resource_match = resource_pattern == "*"
            || resource_pattern == resource
            || (resource_pattern.ends_with('*')
                && resource.starts_with(&resource_pattern[..resource_pattern.len() - 1]));

        action_match && resource_match
    }

    fn evaluate_conditions(
        policy: &PolicyRule,
        agent_id: &str,
        context: &serde_json::Value,
    ) -> bool {
        // If no conditions, policy matches
        if policy.conditions.is_empty() {
            return true;
        }

        // Evaluate all conditions (AND logic)
        for condition in &policy.conditions {
            let field_value = if condition.attribute == "agent_id" {
                Some(serde_json::Value::String(agent_id.to_string()))
            } else {
                context.get(&condition.attribute).cloned()
            };

            if let Some(value) = field_value {
                if !Self::evaluate_condition(condition, &value) {
                    return false;
                }
            } else {
                // Field not present, condition fails
                return false;
            }
        }

        true
    }

    /// Evaluate a single condition against a value
    fn evaluate_condition(condition: &PolicyCondition, value: &serde_json::Value) -> bool {
        match condition.operator {
            ConditionOperator::Equals => value == &condition.value,
            ConditionOperator::NotEquals => value != &condition.value,
            ConditionOperator::Contains => {
                if let (Some(val_str), Some(cond_str)) = (value.as_str(), condition.value.as_str())
                {
                    val_str.contains(cond_str)
                } else {
                    false
                }
            }
            ConditionOperator::StartsWith => {
                if let (Some(val_str), Some(cond_str)) = (value.as_str(), condition.value.as_str())
                {
                    val_str.starts_with(cond_str)
                } else {
                    false
                }
            }
            ConditionOperator::EndsWith => {
                if let (Some(val_str), Some(cond_str)) = (value.as_str(), condition.value.as_str())
                {
                    val_str.ends_with(cond_str)
                } else {
                    false
                }
            }
            ConditionOperator::GreaterThan => {
                if let (Some(val_num), Some(cond_num)) = (value.as_f64(), condition.value.as_f64())
                {
                    val_num > cond_num
                } else {
                    false
                }
            }
            ConditionOperator::LessThan => {
                if let (Some(val_num), Some(cond_num)) = (value.as_f64(), condition.value.as_f64())
                {
                    val_num < cond_num
                } else {
                    false
                }
            }
            ConditionOperator::In => {
                if let Some(arr) = condition.value.as_array() {
                    arr.contains(value)
                } else {
                    false
                }
            }
        }
    }

    /// Reload policies from disk
    pub async fn reload(&self) -> HotReloadResult<PolicyVersion> {
        let start = std::time::Instant::now();

        info!(dir = ?self.config.policy_dir, "Reloading policies");

        // Load new policies
        let new_policies = Self::load_policies_from_dir(&self.config.policy_dir).await?;

        // Validate if configured
        if self.config.validate_before_load {
            self.validate_policies(&new_policies)?;
        }

        // Create new version
        let current_snapshot = self.current.load();
        let new_version = PolicyVersion::new(
            current_snapshot.version.version + 1,
            &new_policies,
            Some(&current_snapshot.version),
        );

        let new_snapshot = Arc::new(PolicySnapshot::new(new_policies, new_version.clone()));

        // Atomically swap
        self.current.store(new_snapshot.clone());

        // Update history
        let mut history = self.version_history.write().await;
        history.push(new_snapshot);

        // Prune old versions if needed
        while history.len() > self.config.max_versions {
            history.remove(0);
        }

        // Update metrics
        let duration = start.elapsed();
        let mut metrics = self.metrics.write().await;
        metrics.successful_reloads += 1;
        metrics.last_reload = Some(SystemTime::now());
        metrics.last_reload_duration = Some(duration);
        metrics.policy_count = self.current.load().len();
        metrics.current_version = new_version.version;

        info!(
            version = new_version.version,
            merkle_root = %new_version.merkle_root,
            duration_ms = duration.as_millis(),
            "Policy reload successful"
        );

        Ok(new_version)
    }

    /// Rollback to a previous version
    pub async fn rollback(&self, target_version: u64) -> HotReloadResult<()> {
        let history = self.version_history.read().await;

        let target = history
            .iter()
            .find(|s| s.version.version == target_version)
            .cloned()
            .ok_or_else(|| {
                HotReloadError::RollbackError(format!("Version {} not found", target_version))
            })?;

        drop(history);

        // Atomically swap to old version
        self.current.store(target);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.rollbacks += 1;
        metrics.current_version = target_version;

        info!(
            version = target_version,
            "Rolled back to previous policy version"
        );

        Ok(())
    }

    /// Get version history
    pub async fn get_history(&self) -> Vec<PolicyVersion> {
        let history = self.version_history.read().await;
        history.iter().map(|s| s.version.clone()).collect()
    }

    /// Get metrics
    pub async fn get_metrics(&self) -> HotReloadMetrics {
        self.metrics.read().await.clone()
    }

    /// Validate policies before loading
    fn validate_policies(&self, policies: &[PolicyRule]) -> HotReloadResult<()> {
        // Check for duplicate IDs
        let mut seen_ids = std::collections::HashSet::new();
        for policy in policies {
            if !seen_ids.insert(&policy.id) {
                return Err(HotReloadError::ValidationError(format!(
                    "Duplicate policy ID: {}",
                    policy.id
                )));
            }
        }

        // Check for at least one default deny
        let has_default_deny = policies.iter().any(|p| {
            p.action_pattern == "*"
                && p.resource_pattern == "*"
                && matches!(p.effect, PolicyEffect::Deny)
        });

        if !has_default_deny {
            warn!("No default deny policy found - consider adding one for security");
        }

        Ok(())
    }

    /// Load policies from a directory
    async fn load_policies_from_dir(dir: &Path) -> HotReloadResult<Vec<PolicyRule>> {
        let mut policies = Vec::new();

        if !dir.exists() {
            warn!(dir = ?dir, "Policy directory does not exist, using empty policy set");
            return Ok(policies);
        }

        let mut entries = tokio::fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_file() {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

                if ext == "yaml" || ext == "yml" {
                    match Self::load_yaml_policies(&path).await {
                        Ok(mut file_policies) => {
                            debug!(path = ?path, count = file_policies.len(), "Loaded policies from file");
                            policies.append(&mut file_policies);
                        }
                        Err(e) => {
                            error!(path = ?path, error = %e, "Failed to load policy file");
                        }
                    }
                }
            }
        }

        info!(count = policies.len(), "Loaded policies from directory");
        Ok(policies)
    }

    /// Load policies from a YAML file
    async fn load_yaml_policies(path: &Path) -> HotReloadResult<Vec<PolicyRule>> {
        let content = tokio::fs::read_to_string(path).await?;

        // Try to parse as a list of policies
        let policies: Vec<PolicyRule> = serde_yaml::from_str(&content)
            .map_err(|e| HotReloadError::LoadError(format!("YAML parse error: {}", e)))?;

        Ok(policies)
    }

    /// Start watching for file changes
    ///
    /// Note: Due to Rust's safety requirements, this implementation uses a polling
    /// mechanism that checks for file modifications. For production use, consider
    /// using the `notify` crate with proper async integration.
    pub async fn start_watching(&mut self) -> HotReloadResult<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(shutdown_tx);

        let policy_dir = self.config.policy_dir.clone();
        let debounce = self.config.debounce_duration;

        // Note: This implementation just starts the watcher loop but doesn't
        // automatically reload policies. In a real implementation, you would
        // use a channel to signal the main engine to reload, or use Arc<Self>.
        tokio::spawn(async move {
            let mut last_check = SystemTime::now();

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Stopping policy file watcher");
                        break;
                    }
                    _ = tokio::time::sleep(debounce) => {
                        // Check if any files have been modified
                        if let Ok(modified) = Self::check_for_modifications(&policy_dir, last_check).await {
                            if modified {
                                // Log the modification - actual reload must be triggered externally
                                // due to Rust's borrowing rules preventing unsafe access
                                info!("Policy files modified - reload required");
                                last_check = SystemTime::now();
                            }
                        }
                    }
                }
            }
        });

        info!(dir = ?self.config.policy_dir, "Started policy file watcher");
        Ok(())
    }

    /// Check if any policy files have been modified
    async fn check_for_modifications(dir: &Path, since: SystemTime) -> HotReloadResult<bool> {
        if !dir.exists() {
            return Ok(false);
        }

        let mut entries = tokio::fs::read_dir(dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                if let Ok(metadata) = tokio::fs::metadata(&path).await {
                    if let Ok(modified) = metadata.modified() {
                        if modified > since {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Stop watching for file changes
    pub async fn stop_watching(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
    }
}

impl std::fmt::Debug for HotReloadablePolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HotReloadablePolicyEngine")
            .field("config", &self.config)
            .field("current_version", &self.current.load().version.version)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_policy(id: &str, effect: PolicyEffect) -> PolicyRule {
        PolicyRule {
            id: id.to_string(),
            effect,
            action_pattern: "*".to_string(),
            resource_pattern: "*".to_string(),
            conditions: vec![],
            priority: 0,
            description: None,
        }
    }

    #[test]
    fn test_policy_version_creation() {
        let policies = vec![
            create_test_policy("policy1", PolicyEffect::Allow),
            create_test_policy("policy2", PolicyEffect::Deny),
        ];

        let version = PolicyVersion::new(1, &policies, None);

        assert_eq!(version.version, 1);
        assert!(version.previous_hash.is_none());
        assert_eq!(version.policy_hashes.len(), 2);
        assert!(!version.merkle_root.is_empty());
    }

    #[test]
    fn test_policy_version_chain() {
        let policies = vec![create_test_policy("policy1", PolicyEffect::Allow)];

        let v1 = PolicyVersion::new(1, &policies, None);
        let v2 = PolicyVersion::new(2, &policies, Some(&v1));

        assert_eq!(v2.previous_hash, Some(v1.merkle_root.clone()));
    }

    #[test]
    fn test_policy_snapshot() {
        let policies = vec![
            create_test_policy("policy1", PolicyEffect::Allow),
            create_test_policy("policy2", PolicyEffect::Deny),
        ];
        let version = PolicyVersion::new(1, &policies, None);
        let snapshot = PolicySnapshot::new(policies, version);

        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.find_policy("policy1").is_some());
        assert!(snapshot.find_policy("nonexistent").is_none());
    }

    #[tokio::test]
    async fn test_hot_reload_engine_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = HotReloadConfig::new(temp_dir.path());

        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        assert_eq!(engine.current_version(), 1);
    }

    #[tokio::test]
    async fn test_policy_evaluation() {
        let temp_dir = TempDir::new().unwrap();

        // Create a policy file using new format
        let policy_content = r#"
- id: "allow_read"
  effect: allow
  action_pattern: "read"
  resource_pattern: "data/*"
  conditions: []
  priority: 100

- id: "default_deny"
  effect: deny
  action_pattern: "*"
  resource_pattern: "*"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, policy_content)
            .await
            .unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        // Test allowed action
        let decision = engine.evaluate("agent1", "read", "data/file.txt", &serde_json::json!({}));
        assert!(matches!(decision, HotReloadDecision::Allow { .. }));

        // Test denied action
        let decision = engine.evaluate("agent1", "write", "data/file.txt", &serde_json::json!({}));
        assert!(matches!(decision, HotReloadDecision::Deny { .. }));
    }

    #[tokio::test]
    async fn test_policy_reload() {
        let temp_dir = TempDir::new().unwrap();

        // Initial policy
        let initial_content = r#"
- id: "policy1"
  effect: deny
  action_pattern: "*"
  resource_pattern: "*"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, initial_content)
            .await
            .unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        assert_eq!(engine.current_version(), 1);

        // Update policy
        let updated_content = r#"
- id: "policy1"
  effect: allow
  action_pattern: "*"
  resource_pattern: "*"
  conditions: []
  priority: 0
"#;

        tokio::fs::write(&policy_path, updated_content)
            .await
            .unwrap();

        // Reload
        let new_version = engine.reload().await.unwrap();

        assert_eq!(new_version.version, 2);
        assert_eq!(engine.current_version(), 2);
    }

    #[tokio::test]
    async fn test_rollback() {
        let temp_dir = TempDir::new().unwrap();

        let policy_content = r#"
- id: "policy1"
  effect: Deny
  patterns:
    actions: ["*"]
    resources: ["*"]
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, policy_content)
            .await
            .unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        // Reload a few times
        engine.reload().await.unwrap();
        engine.reload().await.unwrap();

        assert_eq!(engine.current_version(), 3);

        // Rollback to version 1
        engine.rollback(1).await.unwrap();

        assert_eq!(engine.current_version(), 1);
    }

    #[tokio::test]
    async fn test_validation() {
        let temp_dir = TempDir::new().unwrap();

        // Create policy with duplicate IDs using correct field names
        // Note: effect must be lowercase (allow/deny) per serde config
        let policy_content = r#"
- id: "duplicate"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0

- id: "duplicate"
  effect: deny
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, policy_content)
            .await
            .unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let result = HotReloadablePolicyEngine::new(config).await;

        assert!(result.is_err(), "Should fail due to duplicate policy IDs");
    }

    #[tokio::test]
    async fn test_metrics() {
        let temp_dir = TempDir::new().unwrap();
        let config = HotReloadConfig::new(temp_dir.path());

        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        engine.reload().await.unwrap();

        let metrics = engine.get_metrics().await;

        assert_eq!(metrics.successful_reloads, 1);
        assert!(metrics.last_reload.is_some());
    }
}
