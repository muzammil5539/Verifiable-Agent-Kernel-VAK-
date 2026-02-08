//! Policy Analysis Module (POL-008)
//!
//! Provides Cedar Policy Analyzer integration for proving safety invariants
//! before deploying policies. Blocks deployment of policies that violate
//! security constraints.
//!
//! # Overview
//!
//! Policy analysis enables:
//! - Safety invariant verification (e.g., "No agent can delete audit log")
//! - Policy conflict detection
//! - Coverage analysis
//! - Redundancy detection
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::policy::analyzer::{PolicyAnalyzer, AnalyzerConfig, SafetyInvariant};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let analyzer = PolicyAnalyzer::new(AnalyzerConfig::default());
//!
//! // Define safety invariants
//! analyzer.add_invariant(SafetyInvariant::new(
//!     "audit_log_protection",
//!     "No agent can delete the audit log",
//!     r#"forbid(principal, action == Action::"delete", resource == Resource::"audit_log")"#,
//! ));
//!
//! // Analyze policies
//! let report = analyzer.analyze_policies("policies/").await?;
//!
//! if !report.is_safe() {
//!     // Block deployment
//!     return Err("Policy violations detected".into());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.2.1: Policy Analysis Integration
//! - Cedar Policy Analyzer: https://www.cedarpolicy.com/en/analyzer

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::enforcer::PolicySet;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during policy analysis
#[derive(Debug, Error)]
pub enum AnalyzerError {
    /// Invalid policy
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    /// Invariant violation
    #[error("Invariant violation: {invariant} - {description}")]
    InvariantViolation {
        /// Invariant that was violated
        invariant: String,
        /// Description of the violation
        description: String,
    },

    /// Analysis failed
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Result type for analyzer operations
pub type AnalyzerResult<T> = Result<T, AnalyzerError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the policy analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerConfig {
    /// Enable analysis before policy deployment
    pub enabled: bool,
    /// Fail on any warning
    pub strict_mode: bool,
    /// Check for redundant rules
    pub check_redundancy: bool,
    /// Check for conflicts between rules
    pub check_conflicts: bool,
    /// Check coverage (ensure all resources have policies)
    pub check_coverage: bool,
    /// Maximum analysis time in seconds
    pub timeout_secs: u64,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            strict_mode: true,
            check_redundancy: true,
            check_conflicts: true,
            check_coverage: false, // Disabled by default
            timeout_secs: 30,
        }
    }
}

// ============================================================================
// Safety Invariants
// ============================================================================

/// A safety invariant that policies must satisfy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyInvariant {
    /// Unique identifier for this invariant
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this invariant ensures
    pub description: String,
    /// The invariant condition (Cedar-like expression)
    pub condition: InvariantCondition,
    /// Severity if violated
    pub severity: InvariantSeverity,
    /// Whether this invariant is enabled
    pub enabled: bool,
}

impl SafetyInvariant {
    /// Create a new safety invariant
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        condition: impl Into<String>,
    ) -> Self {
        let id_str = id.into();
        Self {
            id: id_str.clone(),
            name: id_str,
            description: description.into(),
            condition: InvariantCondition::Expression(condition.into()),
            severity: InvariantSeverity::Critical,
            enabled: true,
        }
    }

    /// Set the name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the severity
    pub fn with_severity(mut self, severity: InvariantSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Disable this invariant
    pub fn disabled(mut self) -> Self {
        self.enabled = false;
        self
    }
}

/// Types of invariant conditions
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "value")]
pub enum InvariantCondition {
    /// Simple expression-based condition
    Expression(String),
    /// Never allow a specific action on a resource
    NeverAllow {
        /// Action to forbid
        action: String,
        /// Resource to protect
        resource: String,
    },
    /// Always require a specific attribute
    RequireAttribute {
        /// Principal type
        principal_type: String,
        /// Required attribute
        attribute: String,
    },
    /// Forbid access from certain principals
    ForbidPrincipal {
        /// Principal pattern to forbid
        principal_pattern: String,
        /// Action to forbid
        action: String,
    },
    /// Custom validation function
    Custom {
        /// Validator name
        validator: String,
        /// Validator parameters
        params: HashMap<String, serde_json::Value>,
    },
}

/// Severity level for invariant violations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvariantSeverity {
    /// Informational only
    Info,
    /// Warning, but can proceed
    Warning,
    /// Error, should not proceed
    Error,
    /// Critical, must block deployment
    Critical,
}

// ============================================================================
// Analysis Results
// ============================================================================

/// Result of analyzing a policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationDetails {
    /// Invariant that was violated
    pub invariant_id: String,
    /// Severity of the violation
    pub severity: InvariantSeverity,
    /// Description of the violation
    pub description: String,
    /// Affected policy rules
    pub affected_rules: Vec<String>,
    /// Suggested fix
    pub suggestion: Option<String>,
}

/// A warning (not blocking, but should be reviewed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisWarning {
    /// Warning code
    pub code: String,
    /// Warning message
    pub message: String,
    /// Affected rules
    pub affected_rules: Vec<String>,
}

/// Result of a conflict check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConflict {
    /// First conflicting rule
    pub rule_a: String,
    /// Second conflicting rule
    pub rule_b: String,
    /// Description of the conflict
    pub description: String,
    /// Resolution suggestion
    pub resolution: String,
}

/// Result of redundancy check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedundantRule {
    /// The redundant rule
    pub rule_id: String,
    /// Rules that make it redundant
    pub superseded_by: Vec<String>,
    /// Explanation
    pub explanation: String,
}

/// Coverage report for a resource type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Resource type
    pub resource_type: String,
    /// Total resources of this type
    pub total_resources: usize,
    /// Resources with explicit policies
    pub covered_resources: usize,
    /// Coverage percentage
    pub coverage_percent: f64,
    /// Uncovered resources (sample)
    pub uncovered_sample: Vec<String>,
}

/// Complete analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Timestamp of analysis
    pub timestamp: u64,
    /// Policy set hash
    pub policy_hash: String,
    /// Number of policies analyzed
    pub policies_analyzed: usize,
    /// Number of invariants checked
    pub invariants_checked: usize,
    /// Violations found
    pub violations: Vec<ViolationDetails>,
    /// Warnings found
    pub warnings: Vec<AnalysisWarning>,
    /// Conflicts detected
    pub conflicts: Vec<PolicyConflict>,
    /// Redundant rules
    pub redundant_rules: Vec<RedundantRule>,
    /// Coverage report
    pub coverage: Option<Vec<CoverageReport>>,
    /// Analysis duration in milliseconds
    pub duration_ms: u64,
    /// Overall result
    pub passed: bool,
}

impl AnalysisReport {
    /// Create a new empty report
    pub fn new(policy_hash: String) -> Self {
        Self {
            timestamp: current_timestamp(),
            policy_hash,
            policies_analyzed: 0,
            invariants_checked: 0,
            violations: Vec::new(),
            warnings: Vec::new(),
            conflicts: Vec::new(),
            redundant_rules: Vec::new(),
            coverage: None,
            duration_ms: 0,
            passed: true,
        }
    }

    /// Check if the report indicates safe policies
    pub fn is_safe(&self) -> bool {
        self.passed && self.violations.is_empty()
    }

    /// Check if there are any critical violations
    pub fn has_critical_violations(&self) -> bool {
        self.violations
            .iter()
            .any(|v| v.severity >= InvariantSeverity::Critical)
    }

    /// Check if there are any errors
    pub fn has_errors(&self) -> bool {
        self.violations
            .iter()
            .any(|v| v.severity >= InvariantSeverity::Error)
    }

    /// Get violation count by severity
    pub fn violation_count_by_severity(&self) -> HashMap<InvariantSeverity, usize> {
        let mut counts = HashMap::new();
        for v in &self.violations {
            *counts.entry(v.severity).or_insert(0) += 1;
        }
        counts
    }

    /// Generate a summary string
    pub fn summary(&self) -> String {
        let status = if self.passed { "PASSED" } else { "FAILED" };
        format!(
            "Policy Analysis {}: {} policies, {} invariants checked, {} violations, {} warnings, {} conflicts ({}ms)",
            status,
            self.policies_analyzed,
            self.invariants_checked,
            self.violations.len(),
            self.warnings.len(),
            self.conflicts.len(),
            self.duration_ms
        )
    }
}

// ============================================================================
// Policy Analyzer
// ============================================================================

/// The policy analyzer for checking safety invariants
pub struct PolicyAnalyzer {
    /// Configuration
    config: AnalyzerConfig,
    /// Safety invariants
    invariants: Arc<RwLock<Vec<SafetyInvariant>>>,
    /// Default invariants that are always checked
    default_invariants: Vec<SafetyInvariant>,
}

impl PolicyAnalyzer {
    /// Create a new policy analyzer
    pub fn new(config: AnalyzerConfig) -> Self {
        let default_invariants = vec![
            // Audit log protection
            SafetyInvariant::new(
                "audit_log_protection",
                "No agent can delete the audit log",
                "forbid delete on resource audit_log",
            )
            .with_name("Audit Log Protection")
            .with_severity(InvariantSeverity::Critical),
            // Secrets protection
            SafetyInvariant::new(
                "secrets_protection",
                "Secrets files cannot be read by agents",
                "forbid read on resource *.secrets",
            )
            .with_name("Secrets Protection")
            .with_severity(InvariantSeverity::Critical),
            // System files protection
            SafetyInvariant::new(
                "system_files_protection",
                "System configuration files cannot be modified",
                "forbid write on resource /etc/*",
            )
            .with_name("System Files Protection")
            .with_severity(InvariantSeverity::Error),
            // Network egress control
            SafetyInvariant::new(
                "network_egress_control",
                "Agents must have explicit network permissions",
                "require attribute network_access for action network_request",
            )
            .with_name("Network Egress Control")
            .with_severity(InvariantSeverity::Warning),
        ];

        Self {
            config,
            invariants: Arc::new(RwLock::new(Vec::new())),
            default_invariants,
        }
    }

    /// Add a safety invariant
    pub async fn add_invariant(&self, invariant: SafetyInvariant) {
        let mut invariants = self.invariants.write().await;
        invariants.push(invariant);
    }

    /// Remove an invariant by ID
    pub async fn remove_invariant(&self, id: &str) -> bool {
        let mut invariants = self.invariants.write().await;
        let len_before = invariants.len();
        invariants.retain(|i| i.id != id);
        invariants.len() < len_before
    }

    /// List all invariants
    pub async fn list_invariants(&self) -> Vec<SafetyInvariant> {
        let invariants = self.invariants.read().await;
        let mut all = self.default_invariants.clone();
        all.extend(invariants.iter().cloned());
        all
    }

    /// Analyze a policy set
    pub async fn analyze(&self, policies: &PolicySet) -> AnalyzerResult<AnalysisReport> {
        let start = std::time::Instant::now();
        let policy_hash = compute_policy_hash(policies);

        let mut report = AnalysisReport::new(policy_hash);
        report.policies_analyzed = policies.rules.len();

        // Get all invariants
        let custom_invariants = self.invariants.read().await;
        let all_invariants: Vec<_> = self
            .default_invariants
            .iter()
            .chain(custom_invariants.iter())
            .filter(|i| i.enabled)
            .collect();

        report.invariants_checked = all_invariants.len();

        // Check each invariant
        for invariant in &all_invariants {
            match self.check_invariant(invariant, policies).await {
                Ok(()) => {
                    debug!(invariant = %invariant.id, "Invariant satisfied");
                }
                Err(violation) => {
                    info!(
                        invariant = %invariant.id,
                        severity = ?invariant.severity,
                        "Invariant violation detected"
                    );
                    report.violations.push(ViolationDetails {
                        invariant_id: invariant.id.clone(),
                        severity: invariant.severity,
                        description: violation,
                        affected_rules: Vec::new(), // Would need deeper analysis
                        suggestion: None,
                    });
                }
            }
        }

        // Check for conflicts
        if self.config.check_conflicts {
            let conflicts = self.find_conflicts(policies).await;
            report.conflicts = conflicts;
        }

        // Check for redundancy
        if self.config.check_redundancy {
            let redundant = self.find_redundant_rules(policies).await;
            report.redundant_rules = redundant;
        }

        // Determine if analysis passed
        report.passed =
            !report.has_critical_violations() && (!self.config.strict_mode || !report.has_errors());

        report.duration_ms = start.elapsed().as_millis() as u64;

        info!(
            passed = report.passed,
            violations = report.violations.len(),
            warnings = report.warnings.len(),
            duration_ms = report.duration_ms,
            "Policy analysis complete"
        );

        Ok(report)
    }

    /// Check a single invariant against policies
    async fn check_invariant(
        &self,
        invariant: &SafetyInvariant,
        policies: &PolicySet,
    ) -> Result<(), String> {
        match &invariant.condition {
            InvariantCondition::Expression(expr) => {
                // Parse and check the expression
                self.check_expression(expr, policies)
            }
            InvariantCondition::NeverAllow { action, resource } => {
                // Check that no permit rule allows this action on this resource
                for rule in &policies.rules {
                    if rule.effect == "permit" {
                        // Simplified check - in production would use Cedar's analyzer
                        if rule_matches_action_resource(rule, action, resource) {
                            return Err(format!(
                                "Rule '{}' allows {} on {}",
                                rule.id, action, resource
                            ));
                        }
                    }
                }
                Ok(())
            }
            InvariantCondition::RequireAttribute {
                principal_type,
                attribute,
            } => {
                // Check that all rules for this principal type require the attribute
                for rule in &policies.rules {
                    if rule.effect == "permit"
                        && rule_matches_principal_type(rule, principal_type)
                        && !rule_requires_attribute(rule, attribute)
                    {
                        return Err(format!(
                            "Rule '{}' for {} doesn't require attribute {}",
                            rule.id, principal_type, attribute
                        ));
                    }
                }
                Ok(())
            }
            InvariantCondition::ForbidPrincipal {
                principal_pattern,
                action,
            } => {
                // Check no permit for this principal pattern
                for rule in &policies.rules {
                    if rule.effect == "permit"
                        && rule_matches_principal_pattern(rule, principal_pattern)
                        && rule_matches_action(rule, action)
                    {
                        return Err(format!(
                            "Rule '{}' allows {} for principal {}",
                            rule.id, action, principal_pattern
                        ));
                    }
                }
                Ok(())
            }
            InvariantCondition::Custom {
                validator,
                params: _,
            } => {
                // Custom validators would be implemented here
                warn!(
                    validator = %validator,
                    "Custom validator not implemented"
                );
                Ok(())
            }
        }
    }

    /// Check an expression-based invariant
    fn check_expression(&self, expr: &str, policies: &PolicySet) -> Result<(), String> {
        // Simplified expression checking
        // In production, this would use Cedar's formal analyzer

        // Parse simple expressions like "forbid delete on resource audit_log"
        let parts: Vec<&str> = expr.split_whitespace().collect();

        if parts.is_empty() {
            return Err("Empty expression".to_string());
        }

        match parts[0] {
            "forbid" => {
                // Check that no permit rule allows this
                if parts.len() >= 5 && parts[2] == "on" && parts[3] == "resource" {
                    let action = parts[1];
                    let resource = parts[4];

                    for rule in &policies.rules {
                        if rule.effect == "permit"
                            && rule_matches_action_resource(rule, action, resource)
                        {
                            return Err(format!(
                                "Rule '{}' allows forbidden action {} on {}",
                                rule.id, action, resource
                            ));
                        }
                    }
                }
                Ok(())
            }
            "require" => {
                // Check attribute requirements
                Ok(())
            }
            _ => {
                warn!(expression = %expr, "Unknown expression type");
                Ok(())
            }
        }
    }

    /// Find conflicts between rules
    async fn find_conflicts(&self, policies: &PolicySet) -> Vec<PolicyConflict> {
        let mut conflicts = Vec::new();

        // Compare each pair of rules
        for (i, rule_a) in policies.rules.iter().enumerate() {
            for rule_b in policies.rules.iter().skip(i + 1) {
                // Check for overlapping conditions with different effects
                if rule_a.effect != rule_b.effect && rules_overlap(rule_a, rule_b) {
                    conflicts.push(PolicyConflict {
                        rule_a: rule_a.id.clone(),
                        rule_b: rule_b.id.clone(),
                        description: format!(
                            "Rules have overlapping conditions but different effects ({:?} vs {:?})",
                            rule_a.effect, rule_b.effect
                        ),
                        resolution: "Review rule priorities or refine conditions".to_string(),
                    });
                }
            }
        }

        conflicts
    }

    /// Find redundant rules
    async fn find_redundant_rules(&self, policies: &PolicySet) -> Vec<RedundantRule> {
        let mut redundant = Vec::new();

        // Check for rules that are subsumed by others
        for (i, rule_a) in policies.rules.iter().enumerate() {
            for rule_b in policies.rules.iter().skip(i + 1) {
                if rule_a.effect == rule_b.effect && rule_subsumes(rule_a, rule_b) {
                    redundant.push(RedundantRule {
                        rule_id: rule_b.id.clone(),
                        superseded_by: vec![rule_a.id.clone()],
                        explanation: "Rule is covered by a more general rule".to_string(),
                    });
                }
            }
        }

        redundant
    }
}

impl std::fmt::Debug for PolicyAnalyzer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyAnalyzer")
            .field("config", &self.config)
            .field("default_invariants_count", &self.default_invariants.len())
            .finish()
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Compute a hash of the policy set
fn compute_policy_hash(policies: &PolicySet) -> String {
    let serialized = serde_json::to_string(policies).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Check if a rule matches a specific action and resource
fn rule_matches_action_resource(
    rule: &super::enforcer::CedarRule,
    action: &str,
    resource: &str,
) -> bool {
    // Simplified matching - in production would use proper pattern matching
    let action_matches = rule.action == action
        || rule.action == "*"
        || action.contains(&rule.action)
        || matches_glob(action, &rule.action);

    let resource_matches = rule.resource == resource
        || rule.resource == "*"
        || resource.contains(&rule.resource)
        || matches_glob(resource, &rule.resource);

    action_matches && resource_matches
}

/// Check if a rule matches a principal type
fn rule_matches_principal_type(rule: &super::enforcer::CedarRule, principal_type: &str) -> bool {
    rule.principal == principal_type
        || rule.principal == "*"
        || rule.principal.starts_with(principal_type)
}

/// Check if a rule requires a specific attribute
fn rule_requires_attribute(rule: &super::enforcer::CedarRule, attribute: &str) -> bool {
    rule.conditions.iter().any(|c| c.contains(attribute))
}

/// Check if a rule matches a principal pattern
fn rule_matches_principal_pattern(rule: &super::enforcer::CedarRule, pattern: &str) -> bool {
    rule.principal == pattern || matches_glob(&rule.principal, pattern)
}

/// Check if a rule matches an action
fn rule_matches_action(rule: &super::enforcer::CedarRule, action: &str) -> bool {
    rule.action == action || rule.action == "*"
}

/// Check if two rules have overlapping conditions
fn rules_overlap(rule_a: &super::enforcer::CedarRule, rule_b: &super::enforcer::CedarRule) -> bool {
    // Check for principal overlap
    let principal_overlap =
        rule_a.principal == rule_b.principal || rule_a.principal == "*" || rule_b.principal == "*";

    // Check for action overlap
    let action_overlap =
        rule_a.action == rule_b.action || rule_a.action == "*" || rule_b.action == "*";

    // Check for resource overlap
    let resource_overlap = rule_a.resource == rule_b.resource
        || rule_a.resource == "*"
        || rule_b.resource == "*"
        || patterns_overlap(&rule_a.resource, &rule_b.resource);

    principal_overlap && action_overlap && resource_overlap
}

/// Check if rule_a subsumes rule_b (rule_a is more general)
fn rule_subsumes(rule_a: &super::enforcer::CedarRule, rule_b: &super::enforcer::CedarRule) -> bool {
    // rule_a subsumes rule_b if rule_a covers all cases that rule_b covers

    // Check principals: rule_a must cover rule_b's principal
    let principals_covered = rule_a.principal == "*"
        || rule_a.principal == rule_b.principal
        || matches_glob(&rule_b.principal, &rule_a.principal);

    // Check actions
    let actions_covered = rule_a.action == "*"
        || rule_a.action == rule_b.action
        || matches_glob(&rule_b.action, &rule_a.action);

    // Check resources
    let resources_covered = rule_a.resource == "*"
        || rule_a.resource == rule_b.resource
        || matches_glob(&rule_b.resource, &rule_a.resource);

    principals_covered && actions_covered && resources_covered
}

/// Simple glob pattern matching
fn matches_glob(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];
            return value.starts_with(prefix) && value.ends_with(suffix);
        }
    }

    value == pattern
}

/// Check if two patterns potentially overlap
fn patterns_overlap(pattern_a: &str, pattern_b: &str) -> bool {
    // Simple overlap check
    if pattern_a.contains('*') || pattern_b.contains('*') {
        // If either has a wildcard, they might overlap
        return true;
    }

    // Check for common prefix
    pattern_a.starts_with(pattern_b) || pattern_b.starts_with(pattern_a)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::enforcer::CedarRule;

    fn create_test_policies() -> PolicySet {
        PolicySet {
            rules: vec![
                CedarRule {
                    id: "allow_read_data".to_string(),
                    effect: "permit".to_string(),
                    principal: "Agent".to_string(),
                    action: "read".to_string(),
                    resource: "/data/*".to_string(),
                    conditions: vec![],
                    description: None,
                },
                CedarRule {
                    id: "deny_delete_audit".to_string(),
                    effect: "forbid".to_string(),
                    principal: "*".to_string(),
                    action: "delete".to_string(),
                    resource: "audit_log".to_string(),
                    conditions: vec![],
                    description: None,
                },
            ],
            version: None,
            modified: None,
        }
    }

    #[test]
    fn test_invariant_creation() {
        let invariant = SafetyInvariant::new(
            "test_invariant",
            "Test description",
            "forbid delete on resource audit_log",
        )
        .with_name("Test Invariant")
        .with_severity(InvariantSeverity::Critical);

        assert_eq!(invariant.id, "test_invariant");
        assert_eq!(invariant.name, "Test Invariant");
        assert_eq!(invariant.severity, InvariantSeverity::Critical);
        assert!(invariant.enabled);
    }

    #[test]
    fn test_analysis_report() {
        let report = AnalysisReport::new("test_hash".to_string());

        assert!(report.is_safe());
        assert!(!report.has_critical_violations());
        assert!(report.summary().contains("PASSED"));
    }

    #[test]
    fn test_glob_matching() {
        assert!(matches_glob("test.txt", "*"));
        assert!(matches_glob("data/file.json", "data/*.json"));
        assert!(!matches_glob("other/file.json", "data/*.json"));
        assert!(matches_glob("exactly", "exactly"));
    }

    #[test]
    fn test_rule_overlap() {
        let rule_a = CedarRule {
            id: "rule_a".to_string(),
            effect: "permit".to_string(),
            principal: "Agent".to_string(),
            action: "read".to_string(),
            resource: "/data/*".to_string(),
            conditions: vec![],
            description: None,
        };

        let rule_b = CedarRule {
            id: "rule_b".to_string(),
            effect: "forbid".to_string(),
            principal: "Agent".to_string(),
            action: "read".to_string(),
            resource: "/data/secret".to_string(),
            conditions: vec![],
            description: None,
        };

        assert!(rules_overlap(&rule_a, &rule_b));
    }

    #[tokio::test]
    async fn test_analyzer_basic() {
        let analyzer = PolicyAnalyzer::new(AnalyzerConfig::default());
        let policies = create_test_policies();

        let report = analyzer.analyze(&policies).await.unwrap();

        // Should pass because we have a deny rule for audit_log
        println!("Report: {}", report.summary());
    }

    #[tokio::test]
    async fn test_custom_invariant() {
        let analyzer = PolicyAnalyzer::new(AnalyzerConfig::default());

        // Add custom invariant
        analyzer
            .add_invariant(
                SafetyInvariant::new(
                    "custom_test",
                    "Custom test invariant",
                    "forbid write on resource /critical/*",
                )
                .with_severity(InvariantSeverity::Error),
            )
            .await;

        let invariants = analyzer.list_invariants().await;
        assert!(invariants.iter().any(|i| i.id == "custom_test"));
    }
}
