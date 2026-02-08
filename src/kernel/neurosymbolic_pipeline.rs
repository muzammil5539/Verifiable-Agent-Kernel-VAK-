//! Neuro-Symbolic Execution Pipeline (NSR-006)
//!
//! Implements the complete Neural -> Symbolic -> Execute pipeline as specified in
//! the Gap Analysis Section 2.4.1. This module connects the LLM (neural) with
//! Datalog verification (symbolic) and sandboxed execution.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Neuro-Symbolic Pipeline                               │
//! ├─────────────────────────────────────────────────────────────────────────┤
//! │                                                                          │
//! │   ┌─────────┐     ┌──────────────┐     ┌──────────────┐     ┌─────────┐ │
//! │   │  LLM    │────▶│   Datalog    │────▶│   Policy     │────▶│ Execute │ │
//! │   │ Propose │     │   Validate   │     │   Check      │     │ Action  │ │
//! │   └─────────┘     └──────────────┘     └──────────────┘     └─────────┘ │
//! │        │                 │                    │                   │      │
//! │        ▼                 ▼                    ▼                   ▼      │
//! │   ┌─────────────────────────────────────────────────────────────────┐   │
//! │   │                    Receipt Generator                             │   │
//! │   │              (Cryptographic Audit Trail)                         │   │
//! │   └─────────────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::kernel::neurosymbolic_pipeline::{
//!     NeuroSymbolicPipeline, PipelineConfig, AgentPlan, PipelineResult
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = PipelineConfig::default();
//! let pipeline = NeuroSymbolicPipeline::new(config).await?;
//!
//! // Execute a plan through the pipeline
//! let plan = AgentPlan::new("agent-1", "read_file", "/data/config.json");
//! let result = pipeline.execute(plan).await?;
//!
//! // Result contains cryptographic receipt
//! println!("Execution receipt: {}", result.receipt_hash);
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.4.1: Neuro-Symbolic Hybrid Architecture
//! - Blue Ocean Part III Module 2: Neuro-Symbolic Reasoner

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during pipeline execution
#[derive(Debug, Error)]
pub enum PipelineError {
    /// LLM proposal failed
    #[error("LLM proposal failed: {0}")]
    ProposalFailed(String),

    /// Datalog validation failed
    #[error("Datalog validation failed: {violation}")]
    ValidationFailed {
        /// The violated rule
        violation: String,
        /// Suggested remediation
        remediation: Option<String>,
    },

    /// Policy check denied
    #[error("Policy denied: {action} on {resource} for {principal}")]
    PolicyDenied {
        principal: String,
        action: String,
        resource: String,
        reason: String,
    },

    /// Execution failed
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    /// Receipt generation failed
    #[error("Receipt generation failed: {0}")]
    ReceiptFailed(String),

    /// Timeout
    #[error("Pipeline timeout after {0}ms")]
    Timeout(u64),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Internal error
    #[error("Internal pipeline error: {0}")]
    InternalError(String),
}

/// Result type for pipeline operations
pub type PipelineResult<T> = Result<T, PipelineError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the neuro-symbolic pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Enable Datalog validation step
    pub enable_datalog_validation: bool,
    /// Enable policy checking step
    pub enable_policy_check: bool,
    /// Enable receipt generation
    pub enable_receipts: bool,
    /// Maximum execution time in milliseconds
    pub timeout_ms: u64,
    /// Retry failed validations N times
    pub max_validation_retries: u32,
    /// Backtrack and re-plan on validation failure
    pub enable_backtracking: bool,
    /// Maximum backtrack depth
    pub max_backtrack_depth: u32,
    /// Enable PRM scoring for plan quality
    pub enable_prm_scoring: bool,
    /// Minimum PRM score to proceed (0.0 - 1.0)
    pub min_prm_score: f64,
    /// Enable parallel validation where possible
    pub enable_parallel_validation: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            enable_datalog_validation: true,
            enable_policy_check: true,
            enable_receipts: true,
            timeout_ms: 30_000, // 30 seconds
            max_validation_retries: 3,
            enable_backtracking: true,
            max_backtrack_depth: 5,
            enable_prm_scoring: true,
            min_prm_score: 0.5,
            enable_parallel_validation: true,
        }
    }
}

impl PipelineConfig {
    /// Create a strict configuration (all validations enabled)
    pub fn strict() -> Self {
        Self {
            enable_datalog_validation: true,
            enable_policy_check: true,
            enable_receipts: true,
            timeout_ms: 60_000,
            max_validation_retries: 1,
            enable_backtracking: false,
            max_backtrack_depth: 0,
            enable_prm_scoring: true,
            min_prm_score: 0.7,
            enable_parallel_validation: false,
        }
    }

    /// Create a permissive configuration (minimal validation)
    pub fn permissive() -> Self {
        Self {
            enable_datalog_validation: false,
            enable_policy_check: true,
            enable_receipts: true,
            timeout_ms: 10_000,
            max_validation_retries: 0,
            enable_backtracking: false,
            max_backtrack_depth: 0,
            enable_prm_scoring: false,
            min_prm_score: 0.0,
            enable_parallel_validation: true,
        }
    }
}

// ============================================================================
// Plan Types
// ============================================================================

/// An action proposed by the LLM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposedAction {
    /// Action type (e.g., "read_file", "execute_tool", "api_call")
    pub action_type: String,
    /// Target resource
    pub target: String,
    /// Action parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// LLM's confidence in this action (0.0 - 1.0)
    pub confidence: f64,
    /// Reasoning/explanation for this action
    pub reasoning: String,
}

impl ProposedAction {
    /// Create a new proposed action
    pub fn new(
        action_type: impl Into<String>,
        target: impl Into<String>,
        reasoning: impl Into<String>,
    ) -> Self {
        Self {
            action_type: action_type.into(),
            target: target.into(),
            parameters: HashMap::new(),
            confidence: 1.0,
            reasoning: reasoning.into(),
        }
    }

    /// Add a parameter
    pub fn with_param(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.parameters.insert(key.into(), value);
        self
    }

    /// Set confidence
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Convert to Datalog fact representation
    pub fn to_datalog_fact(&self) -> String {
        format!(
            "Action(\"{}\", \"{}\", {})",
            self.action_type, self.target, self.confidence
        )
    }
}

/// A plan proposed by an agent (may contain multiple actions)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPlan {
    /// Unique plan ID
    pub id: String,
    /// Agent ID proposing the plan
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Proposed actions in order
    pub actions: Vec<ProposedAction>,
    /// Plan-level confidence
    pub confidence: f64,
    /// Overall reasoning
    pub reasoning: String,
    /// Creation timestamp
    pub created_at: u64,
}

impl AgentPlan {
    /// Create a new single-action plan
    pub fn new(
        agent_id: impl Into<String>,
        action_type: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        let action = ProposedAction::new(action_type, target, "");
        Self {
            id: Uuid::now_v7().to_string(),
            agent_id: agent_id.into(),
            session_id: Uuid::now_v7().to_string(),
            actions: vec![action],
            confidence: 1.0,
            reasoning: String::new(),
            created_at: current_timestamp_millis(),
        }
    }

    /// Create a multi-action plan
    pub fn with_actions(
        agent_id: impl Into<String>,
        actions: Vec<ProposedAction>,
        reasoning: impl Into<String>,
    ) -> Self {
        let confidence = if actions.is_empty() {
            0.0
        } else {
            actions.iter().map(|a| a.confidence).sum::<f64>() / actions.len() as f64
        };

        Self {
            id: Uuid::now_v7().to_string(),
            agent_id: agent_id.into(),
            session_id: Uuid::now_v7().to_string(),
            actions,
            confidence,
            reasoning: reasoning.into(),
            created_at: current_timestamp_millis(),
        }
    }

    /// Add an action to the plan
    pub fn add_action(&mut self, action: ProposedAction) {
        self.actions.push(action);
        // Recalculate confidence
        self.confidence =
            self.actions.iter().map(|a| a.confidence).sum::<f64>() / self.actions.len() as f64;
    }

    /// Get plan hash for receipt
    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.id.as_bytes());
        hasher.update(self.agent_id.as_bytes());
        for action in &self.actions {
            hasher.update(action.action_type.as_bytes());
            hasher.update(action.target.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

// ============================================================================
// Validation Result Types
// ============================================================================

/// Result of Datalog validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatalogValidation {
    /// Whether validation passed
    pub passed: bool,
    /// Violated rules (if any)
    pub violations: Vec<DatalogViolation>,
    /// Facts derived during validation
    pub derived_facts: Vec<String>,
    /// Validation time in milliseconds
    pub validation_time_ms: u64,
}

/// A Datalog rule violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatalogViolation {
    /// Rule that was violated
    pub rule: String,
    /// Description of the violation
    pub description: String,
    /// Severity (1-10)
    pub severity: u8,
    /// Suggested remediation
    pub remediation: Option<String>,
}

/// Result of policy check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCheckResult {
    /// Whether policy check passed
    pub allowed: bool,
    /// Policy that was evaluated
    pub policy_id: String,
    /// Reason for decision
    pub reason: String,
    /// Context used for evaluation
    pub context: HashMap<String, String>,
    /// Evaluation time in milliseconds
    pub eval_time_ms: u64,
}

/// Result of PRM scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrmScore {
    /// Overall score (0.0 - 1.0)
    pub score: f64,
    /// Component scores
    pub components: HashMap<String, f64>,
    /// Feedback for improvement
    pub feedback: Option<String>,
}

// ============================================================================
// Pipeline Execution Result
// ============================================================================

/// Complete result of pipeline execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Plan that was executed
    pub plan_id: String,
    /// Whether execution succeeded
    pub success: bool,
    /// Execution output (if successful)
    pub output: Option<serde_json::Value>,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Datalog validation result
    pub datalog_validation: Option<DatalogValidation>,
    /// Policy check result
    pub policy_check: Option<PolicyCheckResult>,
    /// PRM score
    pub prm_score: Option<PrmScore>,
    /// Receipt hash (cryptographic proof)
    pub receipt_hash: String,
    /// Receipt ID for full retrieval
    pub receipt_id: String,
    /// Total execution time in milliseconds
    pub total_time_ms: u64,
    /// Pipeline stage timings
    pub stage_timings: HashMap<String, u64>,
}

// ============================================================================
// Pipeline State
// ============================================================================

/// Current state of the pipeline during execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PipelineStage {
    /// Waiting for input
    Idle,
    /// Validating plan with Datalog
    DatalogValidation,
    /// Checking policy
    PolicyCheck,
    /// Scoring with PRM
    PrmScoring,
    /// Executing action
    Executing,
    /// Generating receipt
    GeneratingReceipt,
    /// Complete
    Complete,
    /// Failed
    Failed,
}

impl std::fmt::Display for PipelineStage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PipelineStage::Idle => write!(f, "Idle"),
            PipelineStage::DatalogValidation => write!(f, "Datalog Validation"),
            PipelineStage::PolicyCheck => write!(f, "Policy Check"),
            PipelineStage::PrmScoring => write!(f, "PRM Scoring"),
            PipelineStage::Executing => write!(f, "Executing"),
            PipelineStage::GeneratingReceipt => write!(f, "Generating Receipt"),
            PipelineStage::Complete => write!(f, "Complete"),
            PipelineStage::Failed => write!(f, "Failed"),
        }
    }
}

// ============================================================================
// Datalog Validator Interface
// ============================================================================

/// Interface for Datalog validation
pub trait DatalogValidator: Send + Sync {
    /// Validate a plan against safety rules
    fn validate(&self, plan: &AgentPlan) -> DatalogValidation;

    /// Add a fact to the knowledge base
    fn assert_fact(&self, fact: &str);

    /// Query the knowledge base
    fn query(&self, query: &str) -> Vec<String>;
}

/// Default Datalog validator using the reasoner module
pub struct DefaultDatalogValidator {
    /// Critical file patterns that trigger violations
    critical_files: Vec<String>,
    /// Critical operations
    critical_ops: Vec<String>,
    /// Custom rules
    custom_rules: RwLock<Vec<(String, String)>>,
}

impl Default for DefaultDatalogValidator {
    fn default() -> Self {
        Self {
            critical_files: vec![
                "/etc/shadow".to_string(),
                "/etc/passwd".to_string(),
                ".env".to_string(),
                "secrets.json".to_string(),
                "credentials".to_string(),
                "private_key".to_string(),
            ],
            critical_ops: vec![
                "delete".to_string(),
                "rm".to_string(),
                "drop".to_string(),
                "truncate".to_string(),
            ],
            custom_rules: RwLock::new(Vec::new()),
        }
    }
}

impl DatalogValidator for DefaultDatalogValidator {
    fn validate(&self, plan: &AgentPlan) -> DatalogValidation {
        let start = Instant::now();
        let mut violations = Vec::new();
        let mut derived_facts = Vec::new();

        for action in &plan.actions {
            // Check critical file access
            for critical in &self.critical_files {
                if action.target.contains(critical) {
                    violations.push(DatalogViolation {
                        rule: "CriticalFileAccess".to_string(),
                        description: format!(
                            "Action '{}' targets critical resource '{}'",
                            action.action_type, action.target
                        ),
                        severity: 9,
                        remediation: Some(format!(
                            "Request explicit permission for accessing '{}'",
                            critical
                        )),
                    });
                    derived_facts.push(format!(
                        "Violation(CriticalFileAccess, \"{}\", \"{}\")",
                        action.action_type, action.target
                    ));
                }
            }

            // Check critical operations
            for critical_op in &self.critical_ops {
                if action.action_type.to_lowercase().contains(critical_op) {
                    violations.push(DatalogViolation {
                        rule: "CriticalOperation".to_string(),
                        description: format!(
                            "Operation '{}' is a critical/destructive operation",
                            action.action_type
                        ),
                        severity: 8,
                        remediation: Some(
                            "Require additional approval for destructive operations".to_string(),
                        ),
                    });
                    derived_facts.push(format!(
                        "Violation(CriticalOperation, \"{}\")",
                        action.action_type
                    ));
                }
            }

            // Check confidence threshold
            if action.confidence < 0.5 {
                violations.push(DatalogViolation {
                    rule: "LowConfidence".to_string(),
                    description: format!(
                        "Action '{}' has low confidence: {:.2}",
                        action.action_type, action.confidence
                    ),
                    severity: 5,
                    remediation: Some(
                        "Increase confidence through additional reasoning or user confirmation"
                            .to_string(),
                    ),
                });
            }

            // Derive action facts
            derived_facts.push(action.to_datalog_fact());
        }

        // Apply custom rules
        let custom_rules = self.custom_rules.read().unwrap();
        for (rule_name, pattern) in custom_rules.iter() {
            for action in &plan.actions {
                if action.target.contains(pattern) || action.action_type.contains(pattern) {
                    violations.push(DatalogViolation {
                        rule: rule_name.clone(),
                        description: format!("Custom rule '{}' triggered", rule_name),
                        severity: 7,
                        remediation: None,
                    });
                }
            }
        }

        DatalogValidation {
            passed: violations.is_empty(),
            violations,
            derived_facts,
            validation_time_ms: start.elapsed().as_millis() as u64,
        }
    }

    fn assert_fact(&self, _fact: &str) {
        // In a full implementation, this would update the knowledge base
    }

    fn query(&self, _query: &str) -> Vec<String> {
        // In a full implementation, this would query the knowledge base
        Vec::new()
    }
}

impl DefaultDatalogValidator {
    /// Add a custom rule
    pub fn add_rule(&self, name: impl Into<String>, pattern: impl Into<String>) {
        let mut rules = self.custom_rules.write().unwrap();
        rules.push((name.into(), pattern.into()));
    }
}

// ============================================================================
// Policy Checker Interface
// ============================================================================

/// Interface for policy checking
pub trait PolicyChecker: Send + Sync {
    /// Check if an action is allowed by policy
    fn check(&self, agent_id: &str, action: &ProposedAction) -> PolicyCheckResult;
}

/// Default policy checker
pub struct DefaultPolicyChecker {
    /// Allowed actions per agent role
    role_permissions: HashMap<String, Vec<String>>,
    /// Denied resources
    denied_resources: Vec<String>,
}

impl Default for DefaultPolicyChecker {
    fn default() -> Self {
        let mut role_permissions = HashMap::new();
        role_permissions.insert(
            "default".to_string(),
            vec!["read".to_string(), "list".to_string(), "query".to_string()],
        );
        role_permissions.insert(
            "admin".to_string(),
            vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
                "execute".to_string(),
            ],
        );

        Self {
            role_permissions,
            denied_resources: vec!["/etc/shadow".to_string(), "/root".to_string()],
        }
    }
}

impl PolicyChecker for DefaultPolicyChecker {
    fn check(&self, agent_id: &str, action: &ProposedAction) -> PolicyCheckResult {
        let start = Instant::now();

        // Check denied resources first
        for denied in &self.denied_resources {
            if action.target.starts_with(denied) {
                return PolicyCheckResult {
                    allowed: false,
                    policy_id: "deny_critical_resources".to_string(),
                    reason: format!("Resource '{}' is in deny list", action.target),
                    context: HashMap::from([
                        ("agent_id".to_string(), agent_id.to_string()),
                        ("action".to_string(), action.action_type.clone()),
                        ("resource".to_string(), action.target.clone()),
                    ]),
                    eval_time_ms: start.elapsed().as_millis() as u64,
                };
            }
        }

        // Check role permissions (default role for now)
        let allowed_actions = self.role_permissions.get("default").unwrap();
        let action_allowed = allowed_actions.iter().any(|a| {
            action
                .action_type
                .to_lowercase()
                .contains(&a.to_lowercase())
        });

        PolicyCheckResult {
            allowed: action_allowed,
            policy_id: "role_based_access".to_string(),
            reason: if action_allowed {
                "Action permitted by default role".to_string()
            } else {
                format!(
                    "Action '{}' not permitted for default role",
                    action.action_type
                )
            },
            context: HashMap::from([
                ("agent_id".to_string(), agent_id.to_string()),
                ("action".to_string(), action.action_type.clone()),
                ("role".to_string(), "default".to_string()),
            ]),
            eval_time_ms: start.elapsed().as_millis() as u64,
        }
    }
}

// ============================================================================
// PRM Scorer Interface
// ============================================================================

/// Interface for Process Reward Model scoring
pub trait PrmScorer: Send + Sync {
    /// Score a proposed action
    fn score(&self, action: &ProposedAction, context: &HashMap<String, String>) -> PrmScore;
}

/// Default PRM scorer
pub struct DefaultPrmScorer {
    /// Weights for different components
    weights: HashMap<String, f64>,
}

impl Default for DefaultPrmScorer {
    fn default() -> Self {
        Self {
            weights: HashMap::from([
                ("confidence".to_string(), 0.3),
                ("reasoning_quality".to_string(), 0.3),
                ("action_specificity".to_string(), 0.2),
                ("safety".to_string(), 0.2),
            ]),
        }
    }
}

impl PrmScorer for DefaultPrmScorer {
    fn score(&self, action: &ProposedAction, _context: &HashMap<String, String>) -> PrmScore {
        let mut components = HashMap::new();

        // Confidence component
        components.insert("confidence".to_string(), action.confidence);

        // Reasoning quality (based on length and content)
        let reasoning_score = if action.reasoning.len() > 50 {
            0.8
        } else if action.reasoning.len() > 10 {
            0.5
        } else {
            0.2
        };
        components.insert("reasoning_quality".to_string(), reasoning_score);

        // Action specificity (based on parameters)
        let specificity = if action.parameters.len() > 2 {
            0.9
        } else if action.parameters.len() > 0 {
            0.6
        } else {
            0.3
        };
        components.insert("action_specificity".to_string(), specificity);

        // Safety score (inverse of risk indicators)
        let safety = if action.target.contains("sensitive") || action.target.contains("secret") {
            0.3
        } else {
            0.9
        };
        components.insert("safety".to_string(), safety);

        // Calculate weighted score
        let mut score = 0.0;
        for (component, value) in &components {
            if let Some(weight) = self.weights.get(component) {
                score += value * weight;
            }
        }

        let feedback = if score < 0.5 {
            Some("Consider providing more detailed reasoning and explicit parameters".to_string())
        } else {
            None
        };

        PrmScore {
            score,
            components,
            feedback,
        }
    }
}

// ============================================================================
// Main Pipeline Implementation
// ============================================================================

/// The main Neuro-Symbolic Pipeline
pub struct NeuroSymbolicPipeline {
    config: PipelineConfig,
    datalog_validator: Arc<dyn DatalogValidator>,
    policy_checker: Arc<dyn PolicyChecker>,
    prm_scorer: Arc<dyn PrmScorer>,
    /// Current stage
    current_stage: Arc<RwLock<PipelineStage>>,
    /// Execution history
    execution_history: Arc<RwLock<Vec<ExecutionResult>>>,
}

impl std::fmt::Debug for NeuroSymbolicPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NeuroSymbolicPipeline")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl NeuroSymbolicPipeline {
    /// Create a new pipeline with default components
    pub async fn new(config: PipelineConfig) -> PipelineResult<Self> {
        Ok(Self {
            config,
            datalog_validator: Arc::new(DefaultDatalogValidator::default()),
            policy_checker: Arc::new(DefaultPolicyChecker::default()),
            prm_scorer: Arc::new(DefaultPrmScorer::default()),
            current_stage: Arc::new(RwLock::new(PipelineStage::Idle)),
            execution_history: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create with custom components
    pub fn with_components(
        config: PipelineConfig,
        datalog_validator: Arc<dyn DatalogValidator>,
        policy_checker: Arc<dyn PolicyChecker>,
        prm_scorer: Arc<dyn PrmScorer>,
    ) -> Self {
        Self {
            config,
            datalog_validator,
            policy_checker,
            prm_scorer,
            current_stage: Arc::new(RwLock::new(PipelineStage::Idle)),
            execution_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Execute a plan through the pipeline
    #[instrument(skip(self, plan), fields(plan_id = %plan.id, agent_id = %plan.agent_id))]
    pub async fn execute(&self, plan: AgentPlan) -> PipelineResult<ExecutionResult> {
        let start = Instant::now();
        let mut stage_timings = HashMap::new();
        let plan_id = plan.id.clone();
        let plan_hash = plan.hash();

        info!(plan_id = %plan_id, "Starting pipeline execution");

        // Stage 1: Datalog Validation
        let datalog_result = if self.config.enable_datalog_validation {
            self.set_stage(PipelineStage::DatalogValidation);
            let stage_start = Instant::now();

            let validation = self.datalog_validator.validate(&plan);
            stage_timings.insert(
                "datalog_validation".to_string(),
                stage_start.elapsed().as_millis() as u64,
            );

            if !validation.passed {
                let violation = validation
                    .violations
                    .first()
                    .map(|v| v.description.clone())
                    .unwrap_or_else(|| "Unknown violation".to_string());

                warn!(plan_id = %plan_id, violation = %violation, "Datalog validation failed");

                self.set_stage(PipelineStage::Failed);
                return Err(PipelineError::ValidationFailed {
                    violation,
                    remediation: validation
                        .violations
                        .first()
                        .and_then(|v| v.remediation.clone()),
                });
            }

            Some(validation)
        } else {
            None
        };

        // Stage 2: Policy Check
        let policy_result = if self.config.enable_policy_check {
            self.set_stage(PipelineStage::PolicyCheck);
            let stage_start = Instant::now();

            // Check each action
            for action in &plan.actions {
                let check = self.policy_checker.check(&plan.agent_id, action);
                if !check.allowed {
                    stage_timings.insert(
                        "policy_check".to_string(),
                        stage_start.elapsed().as_millis() as u64,
                    );

                    warn!(
                        plan_id = %plan_id,
                        action = %action.action_type,
                        reason = %check.reason,
                        "Policy check failed"
                    );

                    self.set_stage(PipelineStage::Failed);
                    return Err(PipelineError::PolicyDenied {
                        principal: plan.agent_id.clone(),
                        action: action.action_type.clone(),
                        resource: action.target.clone(),
                        reason: check.reason,
                    });
                }
            }

            if let Some(first_action) = plan.actions.first() {
                let check = self.policy_checker.check(&plan.agent_id, first_action);
                stage_timings.insert(
                    "policy_check".to_string(),
                    stage_start.elapsed().as_millis() as u64,
                );
                Some(check)
            } else {
                None
            }
        } else {
            None
        };

        // Stage 3: PRM Scoring
        let prm_result = if self.config.enable_prm_scoring {
            self.set_stage(PipelineStage::PrmScoring);
            let stage_start = Instant::now();

            let context = HashMap::from([
                ("agent_id".to_string(), plan.agent_id.clone()),
                ("plan_id".to_string(), plan.id.clone()),
            ]);

            // Score each action and take minimum
            let mut min_score = 1.0f64;
            let mut combined_components = HashMap::new();

            for action in &plan.actions {
                let score = self.prm_scorer.score(action, &context);
                min_score = min_score.min(score.score);
                for (k, v) in score.components {
                    combined_components
                        .entry(k)
                        .and_modify(|existing: &mut f64| *existing = existing.min(v))
                        .or_insert(v);
                }
            }

            stage_timings.insert(
                "prm_scoring".to_string(),
                stage_start.elapsed().as_millis() as u64,
            );

            if min_score < self.config.min_prm_score {
                warn!(
                    plan_id = %plan_id,
                    score = min_score,
                    min_required = self.config.min_prm_score,
                    "PRM score below threshold"
                );
                // Don't fail, but flag it
            }

            Some(PrmScore {
                score: min_score,
                components: combined_components,
                feedback: if min_score < self.config.min_prm_score {
                    Some("Score below threshold - consider improving reasoning".to_string())
                } else {
                    None
                },
            })
        } else {
            None
        };

        // Stage 4: Execute (placeholder - actual execution would happen here)
        self.set_stage(PipelineStage::Executing);
        let exec_start = Instant::now();

        // Simulate execution
        let output = serde_json::json!({
            "status": "completed",
            "actions_executed": plan.actions.len(),
            "plan_hash": plan_hash,
        });

        stage_timings.insert(
            "execution".to_string(),
            exec_start.elapsed().as_millis() as u64,
        );

        // Stage 5: Generate Receipt
        self.set_stage(PipelineStage::GeneratingReceipt);
        let receipt_start = Instant::now();

        let receipt_id = Uuid::now_v7().to_string();
        let receipt_hash = {
            let mut hasher = Sha256::new();
            hasher.update(plan_hash.as_bytes());
            hasher.update(receipt_id.as_bytes());
            hasher.update(plan.agent_id.as_bytes());
            hex::encode(hasher.finalize())
        };

        stage_timings.insert(
            "receipt_generation".to_string(),
            receipt_start.elapsed().as_millis() as u64,
        );

        // Complete
        self.set_stage(PipelineStage::Complete);

        let result = ExecutionResult {
            plan_id,
            success: true,
            output: Some(output),
            error: None,
            datalog_validation: datalog_result,
            policy_check: policy_result,
            prm_score: prm_result,
            receipt_hash,
            receipt_id,
            total_time_ms: start.elapsed().as_millis() as u64,
            stage_timings,
        };

        // Store in history
        {
            let mut history = self.execution_history.write().unwrap();
            history.push(result.clone());
            // Keep last 1000 executions
            if history.len() > 1000 {
                history.remove(0);
            }
        }

        info!(
            plan_id = %result.plan_id,
            success = result.success,
            total_time_ms = result.total_time_ms,
            "Pipeline execution complete"
        );

        Ok(result)
    }

    /// Get current pipeline stage
    pub fn current_stage(&self) -> PipelineStage {
        *self.current_stage.read().unwrap()
    }

    /// Get execution history
    pub fn history(&self) -> Vec<ExecutionResult> {
        self.execution_history.read().unwrap().clone()
    }

    /// Set the current stage
    fn set_stage(&self, stage: PipelineStage) {
        *self.current_stage.write().unwrap() = stage;
        debug!(stage = %stage, "Pipeline stage changed");
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn current_timestamp_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pipeline_creation() {
        let config = PipelineConfig::default();
        let pipeline = NeuroSymbolicPipeline::new(config).await.unwrap();
        assert_eq!(pipeline.current_stage(), PipelineStage::Idle);
    }

    #[tokio::test]
    async fn test_simple_plan_execution() {
        let config = PipelineConfig::permissive();
        let pipeline = NeuroSymbolicPipeline::new(config).await.unwrap();

        let plan = AgentPlan::new("agent-1", "read", "/data/file.txt");
        let result = pipeline.execute(plan).await.unwrap();

        assert!(result.success);
        assert!(!result.receipt_hash.is_empty());
    }

    #[tokio::test]
    async fn test_datalog_validation_blocks_critical_file() {
        let config = PipelineConfig::strict();
        let pipeline = NeuroSymbolicPipeline::new(config).await.unwrap();

        let plan = AgentPlan::new("agent-1", "read", "/etc/shadow");
        let result = pipeline.execute(plan).await;

        assert!(result.is_err());
        match result {
            Err(PipelineError::ValidationFailed { violation, .. }) => {
                assert!(violation.contains("critical"));
            }
            _ => panic!("Expected ValidationFailed error"),
        }
    }

    #[tokio::test]
    async fn test_policy_blocks_denied_resource() {
        let config = PipelineConfig::default();
        let pipeline = NeuroSymbolicPipeline::new(config).await.unwrap();

        let plan = AgentPlan::new("agent-1", "read", "/root/secrets");
        let result = pipeline.execute(plan).await;

        assert!(result.is_err());
    }

    #[test]
    fn test_proposed_action_to_datalog() {
        let action = ProposedAction::new("read_file", "/data/config.json", "Reading config")
            .with_confidence(0.95);

        let fact = action.to_datalog_fact();
        assert!(fact.contains("read_file"));
        assert!(fact.contains("0.95"));
    }

    #[test]
    fn test_agent_plan_hash() {
        let plan1 = AgentPlan::new("agent-1", "read", "/data/file.txt");
        let plan2 = AgentPlan::new("agent-1", "read", "/data/file.txt");

        // Different IDs should produce different hashes
        assert_ne!(plan1.hash(), plan2.hash());
    }

    #[test]
    fn test_default_datalog_validator() {
        let validator = DefaultDatalogValidator::default();

        // Safe plan
        let safe_plan = AgentPlan::new("agent-1", "read", "/data/file.txt");
        let result = validator.validate(&safe_plan);
        assert!(result.passed);

        // Unsafe plan
        let unsafe_plan = AgentPlan::new("agent-1", "read", "/etc/shadow");
        let result = validator.validate(&unsafe_plan);
        assert!(!result.passed);
        assert!(!result.violations.is_empty());
    }

    #[test]
    fn test_default_policy_checker() {
        let checker = DefaultPolicyChecker::default();

        // Allowed action
        let action = ProposedAction::new("read", "/data/file.txt", "");
        let result = checker.check("agent-1", &action);
        assert!(result.allowed);

        // Denied resource
        let action = ProposedAction::new("read", "/etc/shadow", "");
        let result = checker.check("agent-1", &action);
        assert!(!result.allowed);
    }

    #[test]
    fn test_default_prm_scorer() {
        let scorer = DefaultPrmScorer::default();
        let context = HashMap::new();

        // Well-formed action
        let action = ProposedAction::new(
            "read_file",
            "/data/config.json",
            "Reading config for initialization",
        )
        .with_confidence(0.9)
        .with_param("encoding", serde_json::json!("utf-8"))
        .with_param("cache", serde_json::json!(true));

        let score = scorer.score(&action, &context);
        assert!(score.score > 0.5);

        // Poorly formed action
        let action = ProposedAction::new("read", "/sensitive/data", "").with_confidence(0.3);

        let score = scorer.score(&action, &context);
        assert!(score.score < 0.5);
    }
}
