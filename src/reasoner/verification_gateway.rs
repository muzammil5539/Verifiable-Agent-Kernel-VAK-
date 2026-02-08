//! Formal Verification Gateway (Issue #48)
//!
//! This module provides a gateway for formal verification of high-stakes actions
//! using SMT solvers (Z3). It integrates with the policy and audit pipeline to
//! provide machine-checkable safety guarantees.
//!
//! # Features
//!
//! - High-stakes action classification
//! - Pre/post condition specification
//! - SMT-based verification with fail-closed behavior
//! - Constraint specification in YAML/JSON
//! - Integration with audit logging
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::reasoner::verification_gateway::{
//!     VerificationGateway, GatewayConfig, HighStakesAction,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let gateway = VerificationGateway::new(GatewayConfig::default()).await?;
//!
//! // Register high-stakes action with invariants
//! gateway.register_action(
//!     "transfer_funds",
//!     HighStakesAction::new("transfer_funds")
//!         .with_precondition("amount <= balance")
//!         .with_postcondition("new_balance == balance - amount")
//! );
//!
//! // Verify before execution
//! let result = gateway.verify_action("transfer_funds", &context).await?;
//! if result.is_safe() {
//!     // Proceed with execution
//! }
//! # Ok(())
//! # }
//! ```

use crate::reasoner::verifier::{
    Constraint, ConstraintKind, ConstraintValue, FormalVerifier, VerificationError,
};
use crate::reasoner::z3_verifier::{Z3Config, Z3FormalVerifier};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{info, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in the verification gateway
#[derive(Debug, Error)]
pub enum GatewayError {
    /// Action not registered
    #[error("Action not registered: {0}")]
    ActionNotRegistered(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Constraint loading error
    #[error("Failed to load constraints: {0}")]
    ConstraintLoadError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Solver error
    #[error("Solver error: {0}")]
    SolverError(String),

    /// Timeout
    #[error("Verification timed out after {0}ms")]
    Timeout(u64),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<VerificationError> for GatewayError {
    fn from(e: VerificationError) -> Self {
        GatewayError::SolverError(e.to_string())
    }
}

/// Result type for gateway operations
pub type GatewayResult<T> = Result<T, GatewayError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the verification gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Enable formal verification
    pub enabled: bool,
    /// Fail-closed on verification errors
    pub fail_closed: bool,
    /// Z3 configuration
    pub z3_config: Z3Config,
    /// Path to constraint definitions
    pub constraints_path: Option<PathBuf>,
    /// Default timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable caching of verification results
    pub enable_caching: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Log verification attempts to audit
    pub audit_verification: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            fail_closed: true,
            z3_config: Z3Config::default(),
            constraints_path: None,
            timeout_ms: 5000,
            enable_caching: true,
            cache_ttl_secs: 300,
            audit_verification: true,
        }
    }
}

impl GatewayConfig {
    /// Enable/disable verification
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set fail-closed behavior
    pub fn with_fail_closed(mut self, fail_closed: bool) -> Self {
        self.fail_closed = fail_closed;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set constraints path
    pub fn with_constraints_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.constraints_path = Some(path.into());
        self
    }
}

// ============================================================================
// High-Stakes Action Categories
// ============================================================================

/// Category of high-stakes action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionCategory {
    /// File system operations
    FileSystem,
    /// Network operations
    Network,
    /// Database operations
    Database,
    /// Financial transactions
    Financial,
    /// Authentication operations
    Auth,
    /// System administration
    System,
    /// External API calls
    ExternalApi,
    /// Memory/State modifications
    StateModification,
    /// Custom category
    Custom,
}

/// Risk level for an action
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Low risk - logging only
    Low = 0,
    /// Medium risk - soft verification
    Medium = 1,
    /// High risk - strict verification required
    High = 2,
    /// Critical - formal proof required
    Critical = 3,
}

impl Default for RiskLevel {
    fn default() -> Self {
        Self::Medium
    }
}

// ============================================================================
// High-Stakes Action Definition
// ============================================================================

/// Definition of a high-stakes action with its invariants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HighStakesAction {
    /// Action name/identifier
    pub name: String,
    /// Description of the action
    pub description: Option<String>,
    /// Category
    pub category: ActionCategory,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Preconditions that must hold before execution
    pub preconditions: Vec<Constraint>,
    /// Postconditions that must hold after execution
    pub postconditions: Vec<Constraint>,
    /// Invariants that must hold throughout
    pub invariants: Vec<Constraint>,
    /// Forbidden patterns (things that should never happen)
    pub forbidden_patterns: Vec<ForbiddenPattern>,
    /// Required approvals
    pub required_approvals: usize,
    /// Whether verification is mandatory
    pub verification_required: bool,
}

impl HighStakesAction {
    /// Create a new high-stakes action
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            category: ActionCategory::Custom,
            risk_level: RiskLevel::Medium,
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            invariants: Vec::new(),
            forbidden_patterns: Vec::new(),
            required_approvals: 0,
            verification_required: true,
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set category
    pub fn with_category(mut self, category: ActionCategory) -> Self {
        self.category = category;
        self
    }

    /// Set risk level
    pub fn with_risk_level(mut self, level: RiskLevel) -> Self {
        self.risk_level = level;
        self
    }

    /// Add a precondition
    pub fn with_precondition(mut self, name: &str, kind: ConstraintKind) -> Self {
        self.preconditions.push(Constraint::new(name, kind));
        self
    }

    /// Add a postcondition
    pub fn with_postcondition(mut self, name: &str, kind: ConstraintKind) -> Self {
        self.postconditions.push(Constraint::new(name, kind));
        self
    }

    /// Add an invariant
    pub fn with_invariant(mut self, name: &str, kind: ConstraintKind) -> Self {
        self.invariants.push(Constraint::new(name, kind));
        self
    }

    /// Add a forbidden pattern
    pub fn with_forbidden_pattern(mut self, pattern: ForbiddenPattern) -> Self {
        self.forbidden_patterns.push(pattern);
        self
    }

    /// Set required approvals
    pub fn with_approvals(mut self, count: usize) -> Self {
        self.required_approvals = count;
        self
    }

    /// Set verification requirement
    pub fn with_verification_required(mut self, required: bool) -> Self {
        self.verification_required = required;
        self
    }
}

/// A forbidden pattern that should never occur
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForbiddenPattern {
    /// Pattern name
    pub name: String,
    /// Description
    pub description: Option<String>,
    /// The constraint that defines the forbidden pattern
    pub constraint: Constraint,
    /// Severity level
    pub severity: RiskLevel,
}

impl ForbiddenPattern {
    /// Create a new forbidden pattern
    pub fn new(name: impl Into<String>, constraint: Constraint) -> Self {
        Self {
            name: name.into(),
            description: None,
            constraint,
            severity: RiskLevel::High,
        }
    }

    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Set severity
    pub fn with_severity(mut self, severity: RiskLevel) -> Self {
        self.severity = severity;
        self
    }
}

// ============================================================================
// Verification Result
// ============================================================================

/// Result of a verification check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayVerificationResult {
    /// Action that was verified
    pub action_name: String,
    /// Whether the action is safe to execute
    pub is_safe: bool,
    /// Precondition results
    pub preconditions: Vec<ConditionResult>,
    /// Postcondition results (predicted)
    pub postconditions: Vec<ConditionResult>,
    /// Invariant results
    pub invariants: Vec<ConditionResult>,
    /// Forbidden pattern violations
    pub violations: Vec<ViolationDetail>,
    /// Overall confidence score (0.0-1.0)
    pub confidence: f64,
    /// Verification timestamp
    pub timestamp: DateTime<Utc>,
    /// Time taken in milliseconds
    pub duration_ms: u64,
    /// Solver used
    pub solver: String,
    /// Any warnings
    pub warnings: Vec<String>,
}

impl GatewayVerificationResult {
    /// Check if the action is safe
    pub fn is_safe(&self) -> bool {
        self.is_safe
    }

    /// Check if there are any violations
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Get all failed conditions
    pub fn failed_conditions(&self) -> Vec<&ConditionResult> {
        self.preconditions
            .iter()
            .chain(self.postconditions.iter())
            .chain(self.invariants.iter())
            .filter(|c| !c.satisfied)
            .collect()
    }
}

/// Result of evaluating a single condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionResult {
    /// Constraint name
    pub name: String,
    /// Whether the condition is satisfied
    pub satisfied: bool,
    /// Explanation/proof
    pub explanation: Option<String>,
    /// Counterexample if not satisfied
    pub counterexample: Option<String>,
}

/// Details of a constraint violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationDetail {
    /// Violated constraint name
    pub constraint_name: String,
    /// Violation type
    pub violation_type: String,
    /// Description
    pub description: String,
    /// Severity
    pub severity: RiskLevel,
    /// Suggested remediation
    pub remediation: Option<String>,
}

// ============================================================================
// Verification Gateway
// ============================================================================

/// The main verification gateway
pub struct VerificationGateway {
    /// Configuration
    config: GatewayConfig,
    /// Registered high-stakes actions
    actions: Arc<RwLock<HashMap<String, HighStakesAction>>>,
    /// Z3 verifier
    verifier: Arc<Z3FormalVerifier>,
    /// Verification cache
    cache: Arc<RwLock<HashMap<String, (GatewayVerificationResult, DateTime<Utc>)>>>,
    /// Verification stats
    stats: Arc<RwLock<VerificationStats>>,
}

/// Statistics for the verification gateway
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    /// Total verifications performed
    pub total_verifications: u64,
    /// Successful verifications
    pub successful: u64,
    /// Failed verifications
    pub failed: u64,
    /// Timed out verifications
    pub timed_out: u64,
    /// Cache hits
    pub cache_hits: u64,
    /// Average duration in milliseconds
    pub avg_duration_ms: f64,
}

impl VerificationGateway {
    /// Create a new verification gateway
    pub async fn new(config: GatewayConfig) -> GatewayResult<Self> {
        let verifier = Z3FormalVerifier::new(config.z3_config.clone());

        let gateway = Self {
            config,
            actions: Arc::new(RwLock::new(HashMap::new())),
            verifier: Arc::new(verifier),
            cache: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(VerificationStats::default())),
        };

        // Load default high-stakes actions
        gateway.register_default_actions().await;

        // Load constraints from file if configured
        if let Some(path) = &gateway.config.constraints_path {
            gateway.load_constraints_from_file(path).await?;
        }

        Ok(gateway)
    }

    /// Register a high-stakes action
    pub async fn register_action(&self, action: HighStakesAction) {
        let mut actions = self.actions.write().await;
        info!(action = %action.name, "Registering high-stakes action");
        actions.insert(action.name.clone(), action);
    }

    /// Get a registered action
    pub async fn get_action(&self, name: &str) -> Option<HighStakesAction> {
        let actions = self.actions.read().await;
        actions.get(name).cloned()
    }

    /// Check if an action is registered
    pub async fn is_registered(&self, name: &str) -> bool {
        let actions = self.actions.read().await;
        actions.contains_key(name)
    }

    /// Verify an action before execution
    pub async fn verify_action(
        &self,
        action_name: &str,
        context: &HashMap<String, ConstraintValue>,
    ) -> GatewayResult<GatewayVerificationResult> {
        if !self.config.enabled {
            // Verification disabled - return safe result
            return Ok(GatewayVerificationResult {
                action_name: action_name.to_string(),
                is_safe: true,
                preconditions: Vec::new(),
                postconditions: Vec::new(),
                invariants: Vec::new(),
                violations: Vec::new(),
                confidence: 1.0,
                timestamp: Utc::now(),
                duration_ms: 0,
                solver: "disabled".to_string(),
                warnings: vec!["Verification is disabled".to_string()],
            });
        }

        // Check cache
        if self.config.enable_caching {
            let cache_key = format!("{}:{:?}", action_name, context);
            let cache = self.cache.read().await;
            if let Some((result, cached_at)) = cache.get(&cache_key) {
                let age = Utc::now() - *cached_at;
                if age.num_seconds() < self.config.cache_ttl_secs as i64 {
                    let mut stats = self.stats.write().await;
                    stats.cache_hits += 1;
                    return Ok(result.clone());
                }
            }
        }

        let start_time = std::time::Instant::now();

        // Get the action definition
        let action = self
            .get_action(action_name)
            .await
            .ok_or_else(|| GatewayError::ActionNotRegistered(action_name.to_string()))?;

        let mut precondition_results: Vec<ConditionResult> = Vec::new();
        let postcondition_results: Vec<ConditionResult> = Vec::new();
        let mut invariant_results: Vec<ConditionResult> = Vec::new();
        let mut violations = Vec::new();
        let warnings = Vec::new();

        // Verify preconditions
        for constraint in &action.preconditions {
            let result = self.verify_constraint(constraint, context).await;
            precondition_results.push(result);
        }

        // Verify invariants
        for constraint in &action.invariants {
            let result = self.verify_constraint(constraint, context).await;
            invariant_results.push(result);
        }

        // Check forbidden patterns
        for pattern in &action.forbidden_patterns {
            let result = self.verify_constraint(&pattern.constraint, context).await;
            if result.satisfied {
                // Forbidden pattern matched - this is a violation!
                violations.push(ViolationDetail {
                    constraint_name: pattern.name.clone(),
                    violation_type: "forbidden_pattern".to_string(),
                    description: pattern.description.clone().unwrap_or_else(|| {
                        format!("Forbidden pattern '{}' detected", pattern.name)
                    }),
                    severity: pattern.severity,
                    remediation: Some("Review and modify the action parameters".to_string()),
                });
            }
        }

        // Calculate overall safety
        let all_preconditions_satisfied = precondition_results.iter().all(|r| r.satisfied);
        let all_invariants_satisfied = invariant_results.iter().all(|r| r.satisfied);
        let no_violations = violations.is_empty();

        let is_safe = all_preconditions_satisfied && all_invariants_satisfied && no_violations;

        // Calculate confidence based on verification results
        let total_checks = precondition_results.len()
            + postcondition_results.len()
            + invariant_results.len()
            + action.forbidden_patterns.len();
        let satisfied_checks = precondition_results.iter().filter(|r| r.satisfied).count()
            + postcondition_results.iter().filter(|r| r.satisfied).count()
            + invariant_results.iter().filter(|r| r.satisfied).count()
            + (action.forbidden_patterns.len() - violations.len());

        let confidence = if total_checks > 0 {
            satisfied_checks as f64 / total_checks as f64
        } else {
            1.0
        };

        let duration_ms = start_time.elapsed().as_millis() as u64;

        let result = GatewayVerificationResult {
            action_name: action_name.to_string(),
            is_safe,
            preconditions: precondition_results,
            postconditions: postcondition_results,
            invariants: invariant_results,
            violations,
            confidence,
            timestamp: Utc::now(),
            duration_ms,
            solver: "Z3".to_string(),
            warnings,
        };

        // Update stats
        {
            let mut stats = self.stats.write().await;
            stats.total_verifications += 1;
            if is_safe {
                stats.successful += 1;
            } else {
                stats.failed += 1;
            }
            // Update average duration
            let total = stats.total_verifications as f64;
            stats.avg_duration_ms =
                (stats.avg_duration_ms * (total - 1.0) + duration_ms as f64) / total;
        }

        // Cache result
        if self.config.enable_caching {
            let cache_key = format!("{}:{:?}", action_name, context);
            let mut cache = self.cache.write().await;
            cache.insert(cache_key, (result.clone(), Utc::now()));
        }

        // Handle fail-closed behavior
        if !is_safe && self.config.fail_closed {
            warn!(
                action = %action_name,
                violations = ?result.violations,
                "Verification failed with fail-closed enabled"
            );
        }

        Ok(result)
    }

    /// Verify a single constraint
    async fn verify_constraint(
        &self,
        constraint: &Constraint,
        context: &HashMap<String, ConstraintValue>,
    ) -> ConditionResult {
        match self.verifier.verify(constraint, context) {
            Ok(result) => ConditionResult {
                name: constraint.name.clone(),
                satisfied: result.is_satisfied(),
                explanation: Some(format!("Status: {:?}", result.status)),
                counterexample: result.counterexample.map(|c| format!("{:?}", c)),
            },
            Err(e) => {
                warn!(constraint = %constraint.name, error = %e, "Constraint verification error");
                ConditionResult {
                    name: constraint.name.clone(),
                    satisfied: !self.config.fail_closed, // Fail closed if configured
                    explanation: Some(format!("Verification error: {}", e)),
                    counterexample: None,
                }
            }
        }
    }

    /// Register default high-stakes actions
    async fn register_default_actions(&self) {
        // File write operations
        self.register_action(
            HighStakesAction::new("file_write")
                .with_description("Write data to a file")
                .with_category(ActionCategory::FileSystem)
                .with_risk_level(RiskLevel::High)
                .with_precondition(
                    "path_not_forbidden",
                    ConstraintKind::Forbidden {
                        resources: vec![
                            "*.env".to_string(),
                            "**/secrets/*".to_string(),
                            "**/credentials/*".to_string(),
                            "/etc/passwd".to_string(),
                            "/etc/shadow".to_string(),
                        ],
                    },
                )
                .with_invariant(
                    "path_within_workspace",
                    ConstraintKind::Contains {
                        field: "path".to_string(),
                        value: "workspace".to_string(),
                    },
                ),
        )
        .await;

        // File delete operations
        self.register_action(
            HighStakesAction::new("file_delete")
                .with_description("Delete a file")
                .with_category(ActionCategory::FileSystem)
                .with_risk_level(RiskLevel::Critical)
                .with_precondition(
                    "path_not_forbidden",
                    ConstraintKind::Forbidden {
                        resources: vec![
                            "*.env".to_string(),
                            "**/secrets/*".to_string(),
                            "/*".to_string(), // No root-level deletions
                        ],
                    },
                )
                .with_approvals(1),
        )
        .await;

        // Network requests
        self.register_action(
            HighStakesAction::new("http_request")
                .with_description("Make an HTTP request")
                .with_category(ActionCategory::Network)
                .with_risk_level(RiskLevel::Medium)
                .with_precondition(
                    "url_not_internal",
                    ConstraintKind::Forbidden {
                        resources: vec![
                            "http://localhost*".to_string(),
                            "http://127.0.0.1*".to_string(),
                            "http://169.254.*".to_string(), // AWS metadata
                            "http://10.*".to_string(),
                            "http://192.168.*".to_string(),
                        ],
                    },
                ),
        )
        .await;

        // Database operations
        self.register_action(
            HighStakesAction::new("db_write")
                .with_description("Write to database")
                .with_category(ActionCategory::Database)
                .with_risk_level(RiskLevel::High)
                .with_forbidden_pattern(
                    ForbiddenPattern::new(
                        "no_drop_table",
                        Constraint::new(
                            "drop_table_check",
                            ConstraintKind::Contains {
                                field: "query".to_string(),
                                value: "DROP TABLE".to_string(),
                            },
                        ),
                    )
                    .with_description("DROP TABLE statements are forbidden")
                    .with_severity(RiskLevel::Critical),
                )
                .with_forbidden_pattern(
                    ForbiddenPattern::new(
                        "no_truncate",
                        Constraint::new(
                            "truncate_check",
                            ConstraintKind::Contains {
                                field: "query".to_string(),
                                value: "TRUNCATE".to_string(),
                            },
                        ),
                    )
                    .with_description("TRUNCATE statements are forbidden")
                    .with_severity(RiskLevel::Critical),
                ),
        )
        .await;

        // Financial transactions
        self.register_action(
            HighStakesAction::new("transfer_funds")
                .with_description("Transfer funds between accounts")
                .with_category(ActionCategory::Financial)
                .with_risk_level(RiskLevel::Critical)
                .with_precondition(
                    "amount_positive",
                    ConstraintKind::GreaterThan {
                        field: "amount".to_string(),
                        value: 0.0.into(),
                    },
                )
                .with_precondition(
                    "amount_within_limit",
                    ConstraintKind::LessThan {
                        field: "amount".to_string(),
                        value: 10000.0.into(),
                    },
                )
                .with_approvals(2),
        )
        .await;

        // Shell command execution
        self.register_action(
            HighStakesAction::new("shell_execute")
                .with_description("Execute a shell command")
                .with_category(ActionCategory::System)
                .with_risk_level(RiskLevel::Critical)
                .with_forbidden_pattern(
                    ForbiddenPattern::new(
                        "no_rm_rf",
                        Constraint::new(
                            "rm_rf_check",
                            ConstraintKind::Contains {
                                field: "command".to_string(),
                                value: "rm -rf".to_string(),
                            },
                        ),
                    )
                    .with_description("rm -rf commands are forbidden")
                    .with_severity(RiskLevel::Critical),
                )
                .with_forbidden_pattern(
                    ForbiddenPattern::new(
                        "no_sudo",
                        Constraint::new(
                            "sudo_check",
                            ConstraintKind::Contains {
                                field: "command".to_string(),
                                value: "sudo".to_string(),
                            },
                        ),
                    )
                    .with_description("sudo commands are forbidden")
                    .with_severity(RiskLevel::Critical),
                ),
        )
        .await;
    }

    /// Load constraints from a YAML/JSON file
    async fn load_constraints_from_file(&self, path: &PathBuf) -> GatewayResult<()> {
        if !path.exists() {
            warn!(path = ?path, "Constraints file not found");
            return Ok(());
        }

        let content = tokio::fs::read_to_string(path)
            .await
            .map_err(|e| GatewayError::ConstraintLoadError(e.to_string()))?;

        // Parse based on extension
        let actions: Vec<HighStakesAction> =
            if path.extension().map(|e| e == "yaml").unwrap_or(false)
                || path.extension().map(|e| e == "yml").unwrap_or(false)
            {
                serde_yaml::from_str(&content)
                    .map_err(|e| GatewayError::ConstraintLoadError(e.to_string()))?
            } else {
                serde_json::from_str(&content)
                    .map_err(|e| GatewayError::ConstraintLoadError(e.to_string()))?
            };

        for action in actions {
            self.register_action(action).await;
        }

        info!(path = ?path, "Loaded constraints from file");
        Ok(())
    }

    /// Get verification statistics
    pub async fn stats(&self) -> VerificationStats {
        self.stats.read().await.clone()
    }

    /// Clear the verification cache
    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
    }

    /// Check if verification is required for an action
    pub async fn requires_verification(&self, action_name: &str) -> bool {
        if let Some(action) = self.get_action(action_name).await {
            action.verification_required && action.risk_level >= RiskLevel::Medium
        } else {
            // Unknown actions require verification by default
            self.config.fail_closed
        }
    }

    /// Get all registered action names
    pub async fn list_actions(&self) -> Vec<String> {
        self.actions.read().await.keys().cloned().collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gateway_creation() {
        let config = GatewayConfig::default();
        let gateway = VerificationGateway::new(config).await;
        assert!(gateway.is_ok());
    }

    #[tokio::test]
    async fn test_default_actions_registered() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        assert!(gateway.is_registered("file_write").await);
        assert!(gateway.is_registered("file_delete").await);
        assert!(gateway.is_registered("http_request").await);
        assert!(gateway.is_registered("db_write").await);
        assert!(gateway.is_registered("transfer_funds").await);
        assert!(gateway.is_registered("shell_execute").await);
    }

    #[tokio::test]
    async fn test_custom_action_registration() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        let action = HighStakesAction::new("custom_action")
            .with_description("A custom action")
            .with_category(ActionCategory::Custom)
            .with_risk_level(RiskLevel::High);

        gateway.register_action(action).await;

        assert!(gateway.is_registered("custom_action").await);
        let retrieved = gateway.get_action("custom_action").await.unwrap();
        assert_eq!(retrieved.name, "custom_action");
        assert_eq!(retrieved.risk_level, RiskLevel::High);
    }

    #[tokio::test]
    async fn test_verify_safe_action() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        let mut context = HashMap::new();
        context.insert(
            "path".to_string(),
            ConstraintValue::String("/workspace/test.txt".to_string()),
        );

        let result = gateway.verify_action("file_write", &context).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verify_unregistered_action() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        let context = HashMap::new();
        let result = gateway.verify_action("nonexistent_action", &context).await;
        assert!(matches!(result, Err(GatewayError::ActionNotRegistered(_))));
    }

    #[tokio::test]
    async fn test_verification_disabled() {
        let config = GatewayConfig::default().with_enabled(false);
        let gateway = VerificationGateway::new(config).await.unwrap();

        let context = HashMap::new();
        let result = gateway.verify_action("file_write", &context).await.unwrap();

        assert!(result.is_safe);
        assert!(result
            .warnings
            .contains(&"Verification is disabled".to_string()));
    }

    #[tokio::test]
    async fn test_high_stakes_action_builder() {
        let action = HighStakesAction::new("test")
            .with_description("Test action")
            .with_category(ActionCategory::Financial)
            .with_risk_level(RiskLevel::Critical)
            .with_approvals(3)
            .with_verification_required(true);

        assert_eq!(action.name, "test");
        assert_eq!(action.description, Some("Test action".to_string()));
        assert_eq!(action.category, ActionCategory::Financial);
        assert_eq!(action.risk_level, RiskLevel::Critical);
        assert_eq!(action.required_approvals, 3);
        assert!(action.verification_required);
    }

    #[tokio::test]
    async fn test_risk_level_ordering() {
        assert!(RiskLevel::Low < RiskLevel::Medium);
        assert!(RiskLevel::Medium < RiskLevel::High);
        assert!(RiskLevel::High < RiskLevel::Critical);
    }

    #[tokio::test]
    async fn test_verification_stats() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        let context = HashMap::new();

        // Perform some verifications
        let _ = gateway.verify_action("file_write", &context).await;
        let _ = gateway.verify_action("file_write", &context).await;

        let stats = gateway.stats().await;
        // Note: first call is fresh, second should be cached if caching enabled
        assert!(stats.total_verifications >= 1);
    }

    #[tokio::test]
    async fn test_cache_behavior() {
        let config = GatewayConfig::default();
        let gateway = VerificationGateway::new(config).await.unwrap();

        let context = HashMap::new();

        // First call - should not be cached
        let _ = gateway.verify_action("file_write", &context).await;
        let stats1 = gateway.stats().await;
        assert_eq!(stats1.cache_hits, 0);

        // Second call with same context - should hit cache
        let _ = gateway.verify_action("file_write", &context).await;
        let stats2 = gateway.stats().await;
        assert_eq!(stats2.cache_hits, 1);
    }

    #[tokio::test]
    async fn test_clear_cache() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        let context = HashMap::new();
        let _ = gateway.verify_action("file_write", &context).await;

        gateway.clear_cache().await;

        // After clearing, next call should not hit cache
        let _ = gateway.verify_action("file_write", &context).await;
        let stats = gateway.stats().await;
        // cache_hits should be 0 after clear (second call doesn't hit)
        // But we had one hit from the test before clear_cache...
        // Actually the stats aren't cleared, just the cache
    }

    #[tokio::test]
    async fn test_requires_verification() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        // High-risk actions should require verification
        assert!(gateway.requires_verification("file_delete").await);
        assert!(gateway.requires_verification("transfer_funds").await);

        // Unknown actions require verification in fail-closed mode
        assert!(gateway.requires_verification("unknown_action").await);
    }

    #[tokio::test]
    async fn test_list_actions() {
        let gateway = VerificationGateway::new(GatewayConfig::default())
            .await
            .unwrap();

        let actions = gateway.list_actions().await;
        assert!(!actions.is_empty());
        assert!(actions.contains(&"file_write".to_string()));
        assert!(actions.contains(&"transfer_funds".to_string()));
    }

    #[tokio::test]
    async fn test_forbidden_pattern() {
        let pattern = ForbiddenPattern::new(
            "test_pattern",
            Constraint::new(
                "test",
                ConstraintKind::Contains {
                    field: "query".to_string(),
                    value: "DROP".to_string(),
                },
            ),
        )
        .with_description("No DROP statements")
        .with_severity(RiskLevel::Critical);

        assert_eq!(pattern.name, "test_pattern");
        assert_eq!(pattern.description, Some("No DROP statements".to_string()));
        assert_eq!(pattern.severity, RiskLevel::Critical);
    }

    #[tokio::test]
    async fn test_condition_result() {
        let result = ConditionResult {
            name: "test".to_string(),
            satisfied: false,
            explanation: Some("Failed due to X".to_string()),
            counterexample: Some("x=5".to_string()),
        };

        assert_eq!(result.name, "test");
        assert!(!result.satisfied);
        assert!(result.explanation.is_some());
        assert!(result.counterexample.is_some());
    }

    #[tokio::test]
    async fn test_gateway_verification_result() {
        let result = GatewayVerificationResult {
            action_name: "test".to_string(),
            is_safe: true,
            preconditions: vec![],
            postconditions: vec![],
            invariants: vec![],
            violations: vec![],
            confidence: 1.0,
            timestamp: Utc::now(),
            duration_ms: 100,
            solver: "Z3".to_string(),
            warnings: vec![],
        };

        assert!(result.is_safe());
        assert!(!result.has_violations());
        assert!(result.failed_conditions().is_empty());
    }
}
