//! Constitution Protocol (FUT-002)
//!
//! Provides a constitutional governance layer for the VAK kernel that enforces
//! fundamental safety principles on all agent actions. The Constitution Protocol
//! operates as an additional enforcement layer alongside the policy engine,
//! implementing immutable rules that cannot be overridden by regular policies.
//!
//! # Architecture
//!
//! The Constitution Protocol works at three enforcement points:
//! 1. **Pre-Policy**: Before ABAC evaluation, constitutional rules filter obviously harmful actions
//! 2. **Pre-Execution**: After policy approval, constitutional checks validate the specific action
//! 3. **Post-Execution**: After execution, outcomes are verified against constitutional principles
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::kernel::constitution::{
//!     ConstitutionalEngine, ConstitutionalRule, Constitution,
//!     ConstitutionConfig, EnforcementPoint, Principle,
//! };
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a constitution with fundamental principles
//! let constitution = Constitution::default_safety_constitution();
//!
//! // Create the engine
//! let config = ConstitutionConfig::default();
//! let engine = ConstitutionalEngine::new(config, constitution);
//!
//! // Evaluate an action
//! let context = serde_json::json!({
//!     "agent_id": "agent-001",
//!     "action": "read_file",
//!     "resource": "/data/public.csv",
//! });
//!
//! let decision = engine.evaluate(&context)?;
//! assert!(decision.is_allowed());
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during constitutional evaluation
#[derive(Debug, Error)]
pub enum ConstitutionError {
    /// Rule evaluation failed
    #[error("Rule evaluation failed for '{rule_id}': {reason}")]
    RuleEvaluationFailed {
        /// Rule identifier
        rule_id: String,
        /// Failure reason
        reason: String,
    },

    /// Invalid constitution definition
    #[error("Invalid constitution: {0}")]
    InvalidConstitution(String),

    /// Missing required context field
    #[error("Missing required context field: {0}")]
    MissingContextField(String),

    /// Constitution is locked and cannot be modified
    #[error("Constitution is locked and immutable")]
    ConstitutionLocked,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for constitutional operations
pub type ConstitutionResult<T> = Result<T, ConstitutionError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the Constitutional Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionConfig {
    /// Enable constitutional enforcement
    pub enabled: bool,
    /// Log all evaluations (even allowed ones)
    pub log_all_evaluations: bool,
    /// Enable post-execution verification
    pub enable_post_execution: bool,
    /// Maximum evaluation time in milliseconds
    pub max_evaluation_time_ms: u64,
    /// Enable human review escalation
    pub enable_human_review: bool,
}

impl Default for ConstitutionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_all_evaluations: true,
            enable_post_execution: true,
            max_evaluation_time_ms: 100,
            enable_human_review: false,
        }
    }
}

impl ConstitutionConfig {
    /// Create a strict configuration
    pub fn strict() -> Self {
        Self {
            enabled: true,
            log_all_evaluations: true,
            enable_post_execution: true,
            max_evaluation_time_ms: 50,
            enable_human_review: true,
        }
    }

    /// Create a permissive configuration (for testing)
    pub fn permissive() -> Self {
        Self {
            enabled: true,
            log_all_evaluations: false,
            enable_post_execution: false,
            max_evaluation_time_ms: 1000,
            enable_human_review: false,
        }
    }
}

// ============================================================================
// Constitutional Principles
// ============================================================================

/// A fundamental principle in the constitution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principle {
    /// Unique principle identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Detailed description
    pub description: String,
    /// Priority (higher = more important, evaluated first)
    pub priority: u32,
    /// Whether this principle can be overridden
    pub immutable: bool,
}

impl Principle {
    /// Create a new principle
    pub fn new(id: impl Into<String>, name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: description.into(),
            priority: 0,
            immutable: true,
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Set mutability
    pub fn with_immutable(mut self, immutable: bool) -> Self {
        self.immutable = immutable;
        self
    }
}

// ============================================================================
// Enforcement Points
// ============================================================================

/// When in the execution pipeline the rule is enforced
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPoint {
    /// Before policy evaluation
    PrePolicy,
    /// After policy approval, before execution
    PreExecution,
    /// After execution, verifying outcomes
    PostExecution,
    /// At all enforcement points
    All,
}

impl fmt::Display for EnforcementPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrePolicy => write!(f, "pre_policy"),
            Self::PreExecution => write!(f, "pre_execution"),
            Self::PostExecution => write!(f, "post_execution"),
            Self::All => write!(f, "all"),
        }
    }
}

// ============================================================================
// Constraint Operators
// ============================================================================

/// Operators for constraint evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintOp {
    /// Field must equal value
    Equals {
        /// Field to check
        field: String,
        /// Expected value
        value: serde_json::Value,
    },
    /// Field must not equal value
    NotEquals {
        /// Field to check
        field: String,
        /// Excluded value
        value: serde_json::Value,
    },
    /// Field must contain substring
    Contains {
        /// Field to check
        field: String,
        /// Substring to find
        substring: String,
    },
    /// Field must not contain substring
    NotContains {
        /// Field to check
        field: String,
        /// Substring to exclude
        substring: String,
    },
    /// Field must match regex pattern
    Matches {
        /// Field to check
        field: String,
        /// Regex pattern
        pattern: String,
    },
    /// Field must be in allowed set
    In {
        /// Field to check
        field: String,
        /// Allowed values
        values: Vec<serde_json::Value>,
    },
    /// Field must not be in excluded set
    NotIn {
        /// Field to check
        field: String,
        /// Excluded values
        values: Vec<serde_json::Value>,
    },
    /// Numeric field must be less than value
    LessThan {
        /// Field to check
        field: String,
        /// Upper bound
        value: f64,
    },
    /// Numeric field must be greater than value
    GreaterThan {
        /// Field to check
        field: String,
        /// Lower bound
        value: f64,
    },
    /// Field must exist in context
    Exists {
        /// Field to check
        field: String,
    },
    /// All sub-constraints must be satisfied
    All(Vec<ConstraintOp>),
    /// At least one sub-constraint must be satisfied
    Any(Vec<ConstraintOp>),
    /// Sub-constraint must not be satisfied
    Not(Box<ConstraintOp>),
}

// ============================================================================
// Constitutional Rules
// ============================================================================

/// A constitutional rule that must be satisfied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionalRule {
    /// Unique rule identifier
    pub id: String,
    /// The principle this rule implements
    pub principle_id: String,
    /// Human-readable description
    pub description: String,
    /// When this rule is enforced
    pub enforcement_point: EnforcementPoint,
    /// The constraint to evaluate
    pub constraint: ConstraintOp,
    /// Whether violation blocks the action (vs. just warns)
    pub blocking: bool,
    /// Whether violation requires human review
    pub requires_human_review: bool,
    /// Priority within enforcement point
    pub priority: u32,
}

impl ConstitutionalRule {
    /// Create a new constitutional rule
    pub fn new(
        id: impl Into<String>,
        principle_id: impl Into<String>,
        description: impl Into<String>,
        constraint: ConstraintOp,
    ) -> Self {
        Self {
            id: id.into(),
            principle_id: principle_id.into(),
            description: description.into(),
            enforcement_point: EnforcementPoint::PreExecution,
            constraint,
            blocking: true,
            requires_human_review: false,
            priority: 0,
        }
    }

    /// Set enforcement point
    pub fn with_enforcement_point(mut self, point: EnforcementPoint) -> Self {
        self.enforcement_point = point;
        self
    }

    /// Set blocking behavior
    pub fn with_blocking(mut self, blocking: bool) -> Self {
        self.blocking = blocking;
        self
    }

    /// Set human review requirement
    pub fn with_human_review(mut self, required: bool) -> Self {
        self.requires_human_review = required;
        self
    }

    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
}

// ============================================================================
// Constitution (Collection of Principles and Rules)
// ============================================================================

/// A complete constitution defining principles and rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Constitution {
    /// Constitution name
    pub name: String,
    /// Version
    pub version: String,
    /// Description
    pub description: String,
    /// Fundamental principles
    pub principles: Vec<Principle>,
    /// Constitutional rules implementing the principles
    pub rules: Vec<ConstitutionalRule>,
    /// Cryptographic hash of the constitution (for tamper detection)
    pub hash: String,
    /// Whether the constitution is locked (immutable)
    pub locked: bool,
    /// Creation timestamp
    pub created_at: u64,
}

impl Constitution {
    /// Create a new empty constitution
    pub fn new(name: impl Into<String>, version: impl Into<String>) -> Self {
        let name = name.into();
        let version = version.into();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut constitution = Self {
            name,
            version,
            description: String::new(),
            principles: Vec::new(),
            rules: Vec::new(),
            hash: String::new(),
            locked: false,
            created_at,
        };
        constitution.hash = constitution.compute_hash();
        constitution
    }

    /// Create the default safety constitution
    pub fn default_safety_constitution() -> Self {
        let mut constitution = Self::new("VAK Safety Constitution", "1.0.0");
        constitution.description = "Fundamental safety principles for AI agent behavior".to_string();

        // Principle 1: No harm
        let p1 = Principle::new(
            "P-001",
            "No Harm",
            "Agent actions must not cause harm to humans or systems",
        )
        .with_priority(100);

        // Principle 2: Transparency
        let p2 = Principle::new(
            "P-002",
            "Transparency",
            "All agent actions must be auditable and explainable",
        )
        .with_priority(90);

        // Principle 3: Least Privilege
        let p3 = Principle::new(
            "P-003",
            "Least Privilege",
            "Agents must operate with minimum necessary permissions",
        )
        .with_priority(80);

        // Principle 4: Data Protection
        let p4 = Principle::new(
            "P-004",
            "Data Protection",
            "Sensitive data must be protected at all times",
        )
        .with_priority(70);

        // Principle 5: Human Override
        let p5 = Principle::new(
            "P-005",
            "Human Override",
            "Humans must be able to override or halt agent actions",
        )
        .with_priority(100);

        constitution.principles = vec![p1, p2, p3, p4, p5];

        // Rule: Block destructive system operations
        let r1 = ConstitutionalRule::new(
            "R-001",
            "P-001",
            "Block destructive system operations",
            ConstraintOp::NotIn {
                field: "action".to_string(),
                values: vec![
                    serde_json::json!("delete_system"),
                    serde_json::json!("format_disk"),
                    serde_json::json!("shutdown_kernel"),
                    serde_json::json!("disable_audit"),
                    serde_json::json!("bypass_policy"),
                ],
            },
        )
        .with_enforcement_point(EnforcementPoint::PrePolicy)
        .with_priority(100);

        // Rule: Require audit trail for all actions
        let r2 = ConstitutionalRule::new(
            "R-002",
            "P-002",
            "All actions must have an agent_id for audit",
            ConstraintOp::Exists {
                field: "agent_id".to_string(),
            },
        )
        .with_enforcement_point(EnforcementPoint::PrePolicy)
        .with_priority(90);

        // Rule: Block access to system credentials
        let r3 = ConstitutionalRule::new(
            "R-003",
            "P-004",
            "Block direct access to credentials and secrets",
            ConstraintOp::NotContains {
                field: "resource".to_string(),
                substring: "credentials".to_string(),
            },
        )
        .with_enforcement_point(EnforcementPoint::PreExecution)
        .with_priority(80);

        // Rule: Block policy bypass attempts
        let r4 = ConstitutionalRule::new(
            "R-004",
            "P-003",
            "Prevent policy engine bypass attempts",
            ConstraintOp::NotEquals {
                field: "action".to_string(),
                value: serde_json::json!("modify_policy_engine"),
            },
        )
        .with_enforcement_point(EnforcementPoint::PrePolicy)
        .with_priority(100);

        // Rule: Block audit tampering
        let r5 = ConstitutionalRule::new(
            "R-005",
            "P-002",
            "Prevent audit log modification",
            ConstraintOp::NotIn {
                field: "action".to_string(),
                values: vec![
                    serde_json::json!("delete_audit"),
                    serde_json::json!("modify_audit"),
                    serde_json::json!("truncate_audit"),
                ],
            },
        )
        .with_enforcement_point(EnforcementPoint::PrePolicy)
        .with_priority(100);

        constitution.rules = vec![r1, r2, r3, r4, r5];
        constitution.hash = constitution.compute_hash();
        constitution
    }

    /// Add a principle
    pub fn add_principle(&mut self, principle: Principle) -> ConstitutionResult<()> {
        if self.locked {
            return Err(ConstitutionError::ConstitutionLocked);
        }
        self.principles.push(principle);
        self.hash = self.compute_hash();
        Ok(())
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: ConstitutionalRule) -> ConstitutionResult<()> {
        if self.locked {
            return Err(ConstitutionError::ConstitutionLocked);
        }

        // Verify the principle exists
        if !self.principles.iter().any(|p| p.id == rule.principle_id) {
            return Err(ConstitutionError::InvalidConstitution(format!(
                "Principle '{}' not found",
                rule.principle_id
            )));
        }

        self.rules.push(rule);
        self.hash = self.compute_hash();
        Ok(())
    }

    /// Lock the constitution (make immutable)
    pub fn lock(&mut self) {
        self.locked = true;
        self.hash = self.compute_hash();
    }

    /// Verify the constitution hasn't been tampered with
    pub fn verify_integrity(&self) -> bool {
        self.hash == self.compute_hash()
    }

    /// Compute cryptographic hash of the constitution
    fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.name.as_bytes());
        hasher.update(self.version.as_bytes());
        hasher.update(self.description.as_bytes());

        for principle in &self.principles {
            hasher.update(principle.id.as_bytes());
            hasher.update(principle.name.as_bytes());
            hasher.update(principle.description.as_bytes());
            hasher.update(&principle.priority.to_le_bytes());
        }

        for rule in &self.rules {
            hasher.update(rule.id.as_bytes());
            hasher.update(rule.principle_id.as_bytes());
            hasher.update(rule.description.as_bytes());
            hasher.update(rule.enforcement_point.to_string().as_bytes());
        }

        hasher.update(&[self.locked as u8]);

        hex::encode(hasher.finalize())
    }

    /// Get rules for a specific enforcement point
    pub fn rules_for_point(&self, point: EnforcementPoint) -> Vec<&ConstitutionalRule> {
        let mut rules: Vec<_> = self
            .rules
            .iter()
            .filter(|r| r.enforcement_point == point || r.enforcement_point == EnforcementPoint::All)
            .collect();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        rules
    }
}

// ============================================================================
// Constitutional Decision
// ============================================================================

/// Outcome of a constitutional evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionalDecision {
    /// Whether the action is allowed
    pub allowed: bool,
    /// Violated rules (if any)
    pub violations: Vec<RuleViolation>,
    /// Warnings (non-blocking violations)
    pub warnings: Vec<RuleViolation>,
    /// Whether human review is required
    pub requires_human_review: bool,
    /// Evaluation time in microseconds
    pub evaluation_time_us: u64,
    /// Constitution hash at time of evaluation
    pub constitution_hash: String,
}

impl ConstitutionalDecision {
    /// Check if the action is allowed
    pub fn is_allowed(&self) -> bool {
        self.allowed && !self.requires_human_review
    }

    /// Check if the action is allowed (ignoring human review)
    pub fn is_policy_allowed(&self) -> bool {
        self.allowed
    }
}

/// Details about a rule violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleViolation {
    /// Rule that was violated
    pub rule_id: String,
    /// Principle that was violated
    pub principle_id: String,
    /// Human-readable violation description
    pub description: String,
    /// Whether this violation blocks the action
    pub blocking: bool,
    /// The field that caused the violation
    pub field: Option<String>,
    /// The violating value
    pub value: Option<serde_json::Value>,
}

// ============================================================================
// Constitutional Engine
// ============================================================================

/// Engine for evaluating constitutional rules
#[derive(Debug)]
pub struct ConstitutionalEngine {
    config: ConstitutionConfig,
    constitution: Constitution,
    evaluation_count: std::sync::atomic::AtomicU64,
    violation_count: std::sync::atomic::AtomicU64,
}

impl ConstitutionalEngine {
    /// Create a new constitutional engine
    pub fn new(config: ConstitutionConfig, constitution: Constitution) -> Self {
        Self {
            config,
            constitution,
            evaluation_count: std::sync::atomic::AtomicU64::new(0),
            violation_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Create with default safety constitution
    pub fn with_default_constitution() -> Self {
        Self::new(
            ConstitutionConfig::default(),
            Constitution::default_safety_constitution(),
        )
    }

    /// Evaluate an action against the constitution
    pub fn evaluate(&self, context: &serde_json::Value) -> ConstitutionResult<ConstitutionalDecision> {
        self.evaluate_at_point(context, None)
    }

    /// Evaluate at a specific enforcement point
    pub fn evaluate_at_point(
        &self,
        context: &serde_json::Value,
        point: Option<EnforcementPoint>,
    ) -> ConstitutionResult<ConstitutionalDecision> {
        let start = std::time::Instant::now();

        if !self.config.enabled {
            return Ok(ConstitutionalDecision {
                allowed: true,
                violations: Vec::new(),
                warnings: Vec::new(),
                requires_human_review: false,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                constitution_hash: self.constitution.hash.clone(),
            });
        }

        self.evaluation_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let rules = if let Some(point) = point {
            self.constitution.rules_for_point(point)
        } else {
            // Evaluate all rules
            let mut all_rules: Vec<_> = self.constitution.rules.iter().collect();
            all_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
            all_rules
        };

        let mut violations = Vec::new();
        let mut warnings = Vec::new();
        let mut requires_human_review = false;

        for rule in &rules {
            let result = self.evaluate_constraint(&rule.constraint, context);

            match result {
                Ok(true) => {
                    // Constraint satisfied, rule passes
                }
                Ok(false) => {
                    let violation = RuleViolation {
                        rule_id: rule.id.clone(),
                        principle_id: rule.principle_id.clone(),
                        description: rule.description.clone(),
                        blocking: rule.blocking,
                        field: self.extract_field_from_constraint(&rule.constraint),
                        value: self.extract_value_from_context(
                            context,
                            &self.extract_field_from_constraint(&rule.constraint).unwrap_or_default(),
                        ),
                    };

                    if rule.blocking {
                        violations.push(violation);
                    } else {
                        warnings.push(violation);
                    }

                    if rule.requires_human_review && self.config.enable_human_review {
                        requires_human_review = true;
                    }
                }
                Err(_) => {
                    // Context missing required field - treat as violation for blocking rules
                    if rule.blocking {
                        violations.push(RuleViolation {
                            rule_id: rule.id.clone(),
                            principle_id: rule.principle_id.clone(),
                            description: format!(
                                "{} (evaluation error: missing context)",
                                rule.description
                            ),
                            blocking: true,
                            field: None,
                            value: None,
                        });
                    }
                }
            }
        }

        if !violations.is_empty() {
            self.violation_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        Ok(ConstitutionalDecision {
            allowed: violations.is_empty(),
            violations,
            warnings,
            requires_human_review,
            evaluation_time_us: start.elapsed().as_micros() as u64,
            constitution_hash: self.constitution.hash.clone(),
        })
    }

    /// Evaluate a constraint against context
    fn evaluate_constraint(
        &self,
        constraint: &ConstraintOp,
        context: &serde_json::Value,
    ) -> ConstitutionResult<bool> {
        match constraint {
            ConstraintOp::Equals { field, value } => {
                let ctx_value = self.get_field(context, field)?;
                Ok(ctx_value == *value)
            }
            ConstraintOp::NotEquals { field, value } => {
                let ctx_value = self.get_field(context, field)?;
                Ok(ctx_value != *value)
            }
            ConstraintOp::Contains { field, substring } => {
                let ctx_value = self.get_field(context, field)?;
                let string_repr = ctx_value.to_string();
                let s = ctx_value.as_str().unwrap_or(&string_repr);
                Ok(s.contains(substring))
            }
            ConstraintOp::NotContains { field, substring } => {
                let ctx_value = self.get_field(context, field)?;
                let string_repr = ctx_value.to_string();
                let s = ctx_value.as_str().unwrap_or(&string_repr);
                Ok(!s.contains(substring))
            }
            ConstraintOp::Matches { field, pattern } => {
                let ctx_value = self.get_field(context, field)?;
                let string_repr = ctx_value.to_string();
                let s = ctx_value.as_str().unwrap_or(&string_repr);
                let re = regex::Regex::new(pattern).map_err(|e| {
                    ConstitutionError::RuleEvaluationFailed {
                        rule_id: String::new(),
                        reason: format!("Invalid regex: {}", e),
                    }
                })?;
                Ok(re.is_match(s))
            }
            ConstraintOp::In { field, values } => {
                let ctx_value = self.get_field(context, field)?;
                Ok(values.contains(&ctx_value))
            }
            ConstraintOp::NotIn { field, values } => {
                let ctx_value = self.get_field(context, field)?;
                Ok(!values.contains(&ctx_value))
            }
            ConstraintOp::LessThan { field, value } => {
                let ctx_value = self.get_field(context, field)?;
                let num = ctx_value.as_f64().ok_or_else(|| {
                    ConstitutionError::RuleEvaluationFailed {
                        rule_id: String::new(),
                        reason: format!("Field '{}' is not a number", field),
                    }
                })?;
                Ok(num < *value)
            }
            ConstraintOp::GreaterThan { field, value } => {
                let ctx_value = self.get_field(context, field)?;
                let num = ctx_value.as_f64().ok_or_else(|| {
                    ConstitutionError::RuleEvaluationFailed {
                        rule_id: String::new(),
                        reason: format!("Field '{}' is not a number", field),
                    }
                })?;
                Ok(num > *value)
            }
            ConstraintOp::Exists { field } => {
                Ok(context.get(field).is_some())
            }
            ConstraintOp::All(constraints) => {
                for c in constraints {
                    if !self.evaluate_constraint(c, context)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            ConstraintOp::Any(constraints) => {
                for c in constraints {
                    if self.evaluate_constraint(c, context)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            ConstraintOp::Not(constraint) => {
                Ok(!self.evaluate_constraint(constraint, context)?)
            }
        }
    }

    /// Get a field value from context
    fn get_field(
        &self,
        context: &serde_json::Value,
        field: &str,
    ) -> ConstitutionResult<serde_json::Value> {
        // Support dotted field access (e.g., "agent.role")
        let parts: Vec<&str> = field.split('.').collect();
        let mut current = context.clone();

        for part in &parts {
            current = current
                .get(part)
                .cloned()
                .ok_or_else(|| ConstitutionError::MissingContextField(field.to_string()))?;
        }

        Ok(current)
    }

    /// Extract the primary field name from a constraint
    fn extract_field_from_constraint(&self, constraint: &ConstraintOp) -> Option<String> {
        match constraint {
            ConstraintOp::Equals { field, .. }
            | ConstraintOp::NotEquals { field, .. }
            | ConstraintOp::Contains { field, .. }
            | ConstraintOp::NotContains { field, .. }
            | ConstraintOp::Matches { field, .. }
            | ConstraintOp::In { field, .. }
            | ConstraintOp::NotIn { field, .. }
            | ConstraintOp::LessThan { field, .. }
            | ConstraintOp::GreaterThan { field, .. }
            | ConstraintOp::Exists { field } => Some(field.clone()),
            _ => None,
        }
    }

    /// Extract a value from context for reporting
    fn extract_value_from_context(
        &self,
        context: &serde_json::Value,
        field: &str,
    ) -> Option<serde_json::Value> {
        if field.is_empty() {
            return None;
        }
        context.get(field).cloned()
    }

    /// Get the underlying constitution
    pub fn constitution(&self) -> &Constitution {
        &self.constitution
    }

    /// Get evaluation statistics
    pub fn stats(&self) -> ConstitutionStats {
        ConstitutionStats {
            total_evaluations: self.evaluation_count.load(std::sync::atomic::Ordering::Relaxed),
            total_violations: self.violation_count.load(std::sync::atomic::Ordering::Relaxed),
            rule_count: self.constitution.rules.len(),
            principle_count: self.constitution.principles.len(),
            constitution_locked: self.constitution.locked,
        }
    }
}

/// Statistics about constitutional enforcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstitutionStats {
    /// Total evaluations performed
    pub total_evaluations: u64,
    /// Total violations detected
    pub total_violations: u64,
    /// Number of active rules
    pub rule_count: usize,
    /// Number of principles
    pub principle_count: usize,
    /// Whether the constitution is locked
    pub constitution_locked: bool,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context(action: &str, resource: &str) -> serde_json::Value {
        serde_json::json!({
            "agent_id": "agent-001",
            "action": action,
            "resource": resource,
        })
    }

    #[test]
    fn test_default_constitution_allows_safe_actions() {
        let engine = ConstitutionalEngine::with_default_constitution();

        let context = test_context("read_file", "/data/public.csv");
        let decision = engine.evaluate(&context).unwrap();

        assert!(decision.is_allowed());
        assert!(decision.violations.is_empty());
    }

    #[test]
    fn test_default_constitution_blocks_destructive_actions() {
        let engine = ConstitutionalEngine::with_default_constitution();

        let context = test_context("delete_system", "/system");
        let decision = engine.evaluate(&context).unwrap();

        assert!(!decision.is_allowed());
        assert!(!decision.violations.is_empty());
    }

    #[test]
    fn test_default_constitution_blocks_audit_tampering() {
        let engine = ConstitutionalEngine::with_default_constitution();

        let context = test_context("delete_audit", "/audit/logs");
        let decision = engine.evaluate(&context).unwrap();

        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_default_constitution_blocks_policy_bypass() {
        let engine = ConstitutionalEngine::with_default_constitution();

        let context = test_context("modify_policy_engine", "/system/policy");
        let decision = engine.evaluate(&context).unwrap();

        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_default_constitution_blocks_credential_access() {
        let engine = ConstitutionalEngine::with_default_constitution();

        let context = test_context("read_file", "/system/credentials/admin.key");
        let decision = engine.evaluate(&context).unwrap();

        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_requires_agent_id() {
        let engine = ConstitutionalEngine::with_default_constitution();

        // No agent_id in context
        let context = serde_json::json!({
            "action": "read_file",
            "resource": "/data/public.csv",
        });
        let decision = engine.evaluate(&context).unwrap();

        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_custom_constitution() {
        let mut constitution = Constitution::new("Custom", "1.0.0");

        let principle = Principle::new("CP-001", "Custom Principle", "Test principle");
        constitution.add_principle(principle).unwrap();

        let rule = ConstitutionalRule::new(
            "CR-001",
            "CP-001",
            "Action must be 'read'",
            ConstraintOp::Equals {
                field: "action".to_string(),
                value: serde_json::json!("read"),
            },
        );
        constitution.add_rule(rule).unwrap();

        let engine = ConstitutionalEngine::new(ConstitutionConfig::default(), constitution);

        let allowed = engine.evaluate(&serde_json::json!({"action": "read"})).unwrap();
        assert!(allowed.is_allowed());

        let denied = engine.evaluate(&serde_json::json!({"action": "write"})).unwrap();
        assert!(!denied.is_allowed());
    }

    #[test]
    fn test_compound_constraints() {
        let mut constitution = Constitution::new("Compound", "1.0.0");
        let principle = Principle::new("CP-001", "Test", "Test");
        constitution.add_principle(principle).unwrap();

        let rule = ConstitutionalRule::new(
            "CR-001",
            "CP-001",
            "Must have both action and resource",
            ConstraintOp::All(vec![
                ConstraintOp::Exists {
                    field: "action".to_string(),
                },
                ConstraintOp::Exists {
                    field: "resource".to_string(),
                },
            ]),
        );
        constitution.add_rule(rule).unwrap();

        let engine = ConstitutionalEngine::new(ConstitutionConfig::default(), constitution);

        let full = engine
            .evaluate(&serde_json::json!({"action": "read", "resource": "/file"}))
            .unwrap();
        assert!(full.is_allowed());

        let partial = engine
            .evaluate(&serde_json::json!({"action": "read"}))
            .unwrap();
        assert!(!partial.is_allowed());
    }

    #[test]
    fn test_not_constraint() {
        let mut constitution = Constitution::new("Not", "1.0.0");
        let principle = Principle::new("CP-001", "Test", "Test");
        constitution.add_principle(principle).unwrap();

        let rule = ConstitutionalRule::new(
            "CR-001",
            "CP-001",
            "Action must not be 'delete'",
            ConstraintOp::Not(Box::new(ConstraintOp::Equals {
                field: "action".to_string(),
                value: serde_json::json!("delete"),
            })),
        );
        constitution.add_rule(rule).unwrap();

        let engine = ConstitutionalEngine::new(ConstitutionConfig::default(), constitution);

        let read = engine
            .evaluate(&serde_json::json!({"action": "read"}))
            .unwrap();
        assert!(read.is_allowed());

        let delete = engine
            .evaluate(&serde_json::json!({"action": "delete"}))
            .unwrap();
        assert!(!delete.is_allowed());
    }

    #[test]
    fn test_any_constraint() {
        let mut constitution = Constitution::new("Any", "1.0.0");
        let principle = Principle::new("CP-001", "Test", "Test");
        constitution.add_principle(principle).unwrap();

        let rule = ConstitutionalRule::new(
            "CR-001",
            "CP-001",
            "Action must be read or list",
            ConstraintOp::Any(vec![
                ConstraintOp::Equals {
                    field: "action".to_string(),
                    value: serde_json::json!("read"),
                },
                ConstraintOp::Equals {
                    field: "action".to_string(),
                    value: serde_json::json!("list"),
                },
            ]),
        );
        constitution.add_rule(rule).unwrap();

        let engine = ConstitutionalEngine::new(ConstitutionConfig::default(), constitution);

        assert!(engine
            .evaluate(&serde_json::json!({"action": "read"}))
            .unwrap()
            .is_allowed());
        assert!(engine
            .evaluate(&serde_json::json!({"action": "list"}))
            .unwrap()
            .is_allowed());
        assert!(!engine
            .evaluate(&serde_json::json!({"action": "delete"}))
            .unwrap()
            .is_allowed());
    }

    #[test]
    fn test_numeric_constraints() {
        let mut constitution = Constitution::new("Numeric", "1.0.0");
        let principle = Principle::new("CP-001", "Test", "Test");
        constitution.add_principle(principle).unwrap();

        let rule = ConstitutionalRule::new(
            "CR-001",
            "CP-001",
            "Amount must be less than 1000",
            ConstraintOp::LessThan {
                field: "amount".to_string(),
                value: 1000.0,
            },
        );
        constitution.add_rule(rule).unwrap();

        let engine = ConstitutionalEngine::new(ConstitutionConfig::default(), constitution);

        assert!(engine
            .evaluate(&serde_json::json!({"amount": 500}))
            .unwrap()
            .is_allowed());
        assert!(!engine
            .evaluate(&serde_json::json!({"amount": 1500}))
            .unwrap()
            .is_allowed());
    }

    #[test]
    fn test_locked_constitution() {
        let mut constitution = Constitution::new("Locked", "1.0.0");
        let principle = Principle::new("CP-001", "Test", "Test");
        constitution.add_principle(principle).unwrap();
        constitution.lock();

        let result = constitution.add_principle(Principle::new("CP-002", "Test2", "Test2"));
        assert!(matches!(result, Err(ConstitutionError::ConstitutionLocked)));
    }

    #[test]
    fn test_constitution_integrity() {
        let constitution = Constitution::default_safety_constitution();
        assert!(constitution.verify_integrity());
    }

    #[test]
    fn test_enforcement_point_filtering() {
        let constitution = Constitution::default_safety_constitution();

        let pre_policy = constitution.rules_for_point(EnforcementPoint::PrePolicy);
        assert!(!pre_policy.is_empty());

        let pre_exec = constitution.rules_for_point(EnforcementPoint::PreExecution);
        assert!(!pre_exec.is_empty());
    }

    #[test]
    fn test_disabled_constitution() {
        let config = ConstitutionConfig {
            enabled: false,
            ..ConstitutionConfig::default()
        };
        let engine = ConstitutionalEngine::new(
            config,
            Constitution::default_safety_constitution(),
        );

        let context = test_context("delete_system", "/system");
        let decision = engine.evaluate(&context).unwrap();
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_non_blocking_violation() {
        let mut constitution = Constitution::new("Warn", "1.0.0");
        let principle = Principle::new("CP-001", "Test", "Test");
        constitution.add_principle(principle).unwrap();

        let rule = ConstitutionalRule::new(
            "CR-001",
            "CP-001",
            "Prefer read actions",
            ConstraintOp::Equals {
                field: "action".to_string(),
                value: serde_json::json!("read"),
            },
        )
        .with_blocking(false);
        constitution.add_rule(rule).unwrap();

        let engine = ConstitutionalEngine::new(ConstitutionConfig::default(), constitution);

        let decision = engine
            .evaluate(&serde_json::json!({"action": "write"}))
            .unwrap();
        assert!(decision.is_allowed());
        assert!(!decision.warnings.is_empty());
    }

    #[test]
    fn test_engine_stats() {
        let engine = ConstitutionalEngine::with_default_constitution();

        engine
            .evaluate(&test_context("read", "/data"))
            .unwrap();
        engine
            .evaluate(&test_context("delete_system", "/system"))
            .unwrap();

        let stats = engine.stats();
        assert_eq!(stats.total_evaluations, 2);
        assert_eq!(stats.total_violations, 1);
        assert_eq!(stats.principle_count, 5);
    }

    #[test]
    fn test_invalid_rule_principle() {
        let mut constitution = Constitution::new("Test", "1.0.0");

        let rule = ConstitutionalRule::new(
            "CR-001",
            "NONEXISTENT",
            "Test",
            ConstraintOp::Exists {
                field: "test".to_string(),
            },
        );

        let result = constitution.add_rule(rule);
        assert!(matches!(result, Err(ConstitutionError::InvalidConstitution(_))));
    }
}
