//! Reasoning Host Functions (NSR-003)
//!
//! This module exposes the neuro-symbolic reasoning engine to WASM agents,
//! allowing them to verify plans against safety rules before execution.
//!
//! # Architecture
//!
//! The verify_plan host function implements the "Neuro-Symbolic Sandwich":
//! 1. Agent (Neural) proposes a plan via LLM
//! 2. This host function (Symbolic) validates against Datalog rules
//! 3. Only if validation passes does execution proceed
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::reasoning_host::{ReasoningHost, ReasoningConfig, PlanVerification};
//!
//! let mut host = ReasoningHost::new(ReasoningConfig::default());
//!
//! // Add safety rules
//! host.add_critical_file("/etc/shadow");
//! host.add_critical_file("/etc/passwd");
//!
//! // Verify a plan
//! let result = host.verify_plan(&PlanVerification {
//!     agent_id: "agent-1".to_string(),
//!     action_type: "delete_file".to_string(),
//!     target: "/etc/shadow".to_string(),
//!     confidence: 0.9,
//!     params: Default::default(),
//! });
//!
//! assert!(result.is_violation());
//! ```
//!
//! # Guests are untrusted
//!
//! Everything a guest passes is checked as hostile input. A plan's
//! `agent_id` is replaced by the store's agent; its `confidence` is clamped
//! to 0.0..=1.0; a guest may raise its own risk score, never lower it; and
//! pointers are bounds-checked without overflow. Functions registered by
//! [`register_reasoning_functions`], which has no state to verify against,
//! trap rather than approve.
//!
//! # References
//!
//! - Gap Analysis Section 2.4.1: Neuro-Symbolic Hybrid Architecture
//! - Gap Analysis Sprint 4, T4.3: Reasoning host function
//! - NSR-003: verify_plan host function exposed to WASM

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::{debug, info, warn};
use wasmtime::{format_err, Result as HostResult};
use wasmtime::{Caller, Linker};

use super::runtime::guest_range;
use crate::reasoner::datalog::{
    canonical_path, DatalogError, Fact, SafetyEngine, SafetyVerdict, Violation,
};

/// Errors that can occur in reasoning host functions
#[derive(Debug, Error)]
pub enum ReasoningHostError {
    /// Plan verification failed with violations
    #[error("Plan verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid plan format
    #[error("Invalid plan format: {0}")]
    InvalidPlan(String),

    /// Datalog evaluation error
    #[error("Datalog error: {0}")]
    DatalogError(#[from] DatalogError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Memory access error
    #[error("Memory access error: {0}")]
    MemoryError(String),
}

/// Result type for reasoning operations
pub type ReasoningResult<T> = Result<T, ReasoningHostError>;

/// Configuration for the reasoning host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningConfig {
    /// Enable strict mode (any violation = rejection)
    pub strict_mode: bool,
    /// Maximum violations before automatic rejection
    pub max_violations: usize,
    /// Risk score threshold for high-risk actions (0.0-1.0)
    pub high_risk_threshold: f64,
    /// Enable detailed violation logging
    pub detailed_logging: bool,
}

impl Default for ReasoningConfig {
    fn default() -> Self {
        Self {
            strict_mode: true,
            max_violations: 0, // Any violation = rejection
            high_risk_threshold: 0.7,
            detailed_logging: true,
        }
    }
}

impl ReasoningConfig {
    /// Create a permissive config for testing
    pub fn permissive() -> Self {
        Self {
            strict_mode: false,
            max_violations: 5,
            high_risk_threshold: 0.9,
            detailed_logging: false,
        }
    }
}

/// Plan verification request from WASM agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanVerification {
    /// Agent making the request
    pub agent_id: String,
    /// Type of action (e.g., "delete_file", "network_request")
    pub action_type: String,
    /// Target resource
    pub target: String,
    /// Confidence score from PRM (0.0-1.0)
    #[serde(default = "default_confidence")]
    pub confidence: f64,
    /// Optional additional parameters
    #[serde(default)]
    pub params: std::collections::HashMap<String, serde_json::Value>,
}

fn default_confidence() -> f64 {
    1.0
}

/// Result of plan verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the plan is allowed
    pub allowed: bool,
    /// List of violations (if any)
    pub violations: Vec<ViolationInfo>,
    /// Risk score of the plan (0.0-1.0)
    pub risk_score: f64,
    /// Detailed verdict
    pub verdict: String,
}

impl VerificationResult {
    /// Create an allowed result
    pub fn allowed() -> Self {
        Self {
            allowed: true,
            violations: vec![],
            risk_score: 0.0,
            verdict: "Plan approved".to_string(),
        }
    }

    /// Create a denied result
    pub fn denied(violations: Vec<ViolationInfo>, risk_score: f64) -> Self {
        let verdict = if violations.is_empty() {
            "Plan denied: high risk".to_string()
        } else {
            format!("Plan denied: {} violation(s)", violations.len())
        };
        Self {
            allowed: false,
            violations,
            risk_score,
            verdict,
        }
    }

    /// Check if result indicates a violation
    pub fn is_violation(&self) -> bool {
        !self.allowed
    }
}

/// Information about a specific violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViolationInfo {
    /// Type of violation
    pub violation_type: String,
    /// Affected resource
    pub resource: String,
    /// Rule that was violated
    pub rule: String,
    /// Severity (0.0-1.0)
    pub severity: f64,
}

impl From<&Violation> for ViolationInfo {
    fn from(v: &Violation) -> Self {
        Self {
            violation_type: v.action.clone(),
            resource: v.target.clone(),
            rule: v.rule_id.clone(),
            severity: v.severity,
        }
    }
}

/// Reasoning host that provides neuro-symbolic verification to WASM agents
pub struct ReasoningHost {
    /// The underlying safety engine
    engine: SafetyEngine,
    /// Configuration
    config: ReasoningConfig,
    /// Set of critical files (cached for quick lookup)
    critical_files: HashSet<String>,
    /// Set of restricted tools
    restricted_tools: HashSet<String>,
    /// Each agent's risk score, mirrored as one `AgentRiskScore` fact.
    risk_scores: HashMap<String, f64>,
    /// Rule violations found in each agent's plans.
    violations: HashMap<String, usize>,
}

/// A confidence as the risk calculation reads it: within 0.0..=1.0, and 0.0
/// (no discount) if it isn't a number.
fn unit_confidence(confidence: f64) -> f64 {
    if confidence.is_finite() {
        confidence.clamp(0.0, 1.0)
    } else {
        0.0
    }
}

/// A risk score within 0.0..=1.0, and 1.0 if it isn't a number.
fn unit_risk(score: f64) -> f64 {
    if score.is_finite() {
        score.clamp(0.0, 1.0)
    } else {
        1.0
    }
}

impl std::fmt::Debug for ReasoningHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReasoningHost")
            .field("config", &self.config)
            .field("critical_files_count", &self.critical_files.len())
            .field("restricted_tools_count", &self.restricted_tools.len())
            .finish()
    }
}

impl ReasoningHost {
    /// Create a new reasoning host with default safety rules
    pub fn new(config: ReasoningConfig) -> Self {
        let mut engine = SafetyEngine::new();

        // Add default critical files
        let default_critical = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
            "/root/.ssh/authorized_keys",
            "/var/log/audit",
        ];

        for path in default_critical {
            engine.add_fact(Fact::critical_file(path));
        }

        // Add default system paths
        let default_system_paths = ["/etc", "/usr", "/bin", "/sbin", "/var/log"];

        for path in default_system_paths {
            engine.add_fact(Fact::system_path(path));
        }

        Self {
            engine,
            config,
            critical_files: default_critical.iter().map(|s| canonical_path(s)).collect(),
            restricted_tools: HashSet::new(),
            risk_scores: HashMap::new(),
            violations: HashMap::new(),
        }
    }

    /// Create with permissive config for testing
    pub fn permissive() -> Self {
        Self::new(ReasoningConfig::permissive())
    }

    /// Add a critical file that cannot be deleted/modified
    pub fn add_critical_file(&mut self, path: impl Into<String>) {
        let path = path.into();
        self.engine.add_fact(Fact::critical_file(&path));
        self.critical_files.insert(canonical_path(&path));
    }

    /// Add a sensitive file that requires extra authorization
    pub fn add_sensitive_file(&mut self, path: impl Into<String>) {
        self.engine.add_fact(Fact::sensitive_file(path));
    }

    /// Add a restricted tool
    pub fn add_restricted_tool(&mut self, tool: impl Into<String>) {
        let tool = tool.into();
        self.engine.add_fact(Fact::RestrictedTool(tool.clone()));
        self.restricted_tools.insert(tool);
    }

    /// Sets an agent's risk score (affects what actions are allowed),
    /// replacing any earlier one. The score is clamped to 0.0..=1.0, and one
    /// that isn't a number counts as 1.0.
    ///
    /// It used to add a fact beside the earlier ones; the engine reads
    /// whichever it finds first, so which score applied was arbitrary.
    pub fn set_agent_risk(&mut self, agent_id: impl Into<String>, score: f64) {
        let agent_id = agent_id.into();
        let score = unit_risk(score);
        if let Some(old) = self.risk_scores.insert(agent_id.clone(), score) {
            self.engine
                .remove_fact(&Fact::agent_risk(agent_id.clone(), old));
        }
        self.engine.add_fact(Fact::agent_risk(agent_id, score));
    }

    /// Raises an agent's risk score to `score` if that is higher, and returns
    /// the score that applies. It never lowers one: this is what a guest's
    /// `vak.set_risk_score` does, and sandboxed code may report itself
    /// riskier, never safer.
    pub fn raise_agent_risk(&mut self, agent_id: &str, score: f64) -> f64 {
        let score = unit_risk(score);
        let current = self.agent_risk(agent_id);
        if score > current {
            self.set_agent_risk(agent_id, score);
            score
        } else {
            current
        }
    }

    /// An agent's risk score; 0.0 if none was set.
    pub fn agent_risk(&self, agent_id: &str) -> f64 {
        self.risk_scores.get(agent_id).copied().unwrap_or(0.0)
    }

    /// Verify a proposed plan against safety rules
    ///
    /// This is the main entry point for the neuro-symbolic verification.
    pub fn verify_plan(&mut self, plan: &PlanVerification) -> VerificationResult {
        info!(
            agent_id = %plan.agent_id,
            action = %plan.action_type,
            target = %plan.target,
            confidence = plan.confidence,
            "Verifying plan"
        );

        // Run the safety check for this agent. It used to check as agent
        // "unknown", so rules about an agent's risk or capabilities never
        // saw the agent. (It also added each plan as a `ProposedAction`
        // fact, which no rule reads: memory a guest could grow at will.)
        let verdict =
            self.engine
                .check_action_with_agent(&plan.action_type, &plan.target, &plan.agent_id);

        // Convert violations - use the violations() method which returns Option<&[Violation]>
        let violations: Vec<ViolationInfo> = verdict
            .violations()
            .map(|v| v.iter().map(|vi| vi.into()).collect())
            .unwrap_or_default();

        // Calculate risk score
        let risk_score = self.calculate_risk_score(plan, &verdict);
        if !violations.is_empty() {
            *self.violations.entry(plan.agent_id.clone()).or_default() += violations.len();
        }

        // Determine if allowed
        let allowed = if self.config.strict_mode {
            verdict.is_safe() && risk_score < self.config.high_risk_threshold
        } else {
            violations.len() <= self.config.max_violations
                && risk_score < self.config.high_risk_threshold
        };

        if !allowed {
            warn!(
                agent_id = %plan.agent_id,
                action = %plan.action_type,
                target = %plan.target,
                violations = violations.len(),
                risk_score = risk_score,
                "Plan verification failed"
            );
        } else {
            debug!(
                agent_id = %plan.agent_id,
                action = %plan.action_type,
                "Plan verification passed"
            );
        }

        if allowed {
            VerificationResult::allowed()
        } else {
            VerificationResult::denied(violations, risk_score)
        }
    }

    /// Calculate risk score for a plan
    fn calculate_risk_score(&self, plan: &PlanVerification, verdict: &SafetyVerdict) -> f64 {
        let mut score = 0.0;

        // Base risk from action type
        score += match plan.action_type.as_str() {
            "delete_file" | "delete" => 0.4,
            "write_file" | "write" | "modify" => 0.3,
            "execute" | "run" | "shell" => 0.5,
            "network_request" | "http" => 0.2,
            "read_file" | "read" => 0.1,
            _ => 0.2,
        };

        // Add risk from violations (use the violations() method)
        let violation_count = verdict.violations().map(|v| v.len()).unwrap_or(0);
        score += violation_count as f64 * 0.2;

        // Add risk from targeting system paths
        if plan.target.starts_with("/etc")
            || plan.target.starts_with("/usr")
            || plan.target.starts_with("/var")
        {
            score += 0.2;
        }

        // Reduce risk based on confidence (high confidence = lower risk), at
        // most by 30%. Confidence comes from the caller, a guest included: a
        // confidence above 1 used to push the score below zero, clamped to
        // a risk of 0, so any plan without violations passed.
        score *= 1.0 - (unit_confidence(plan.confidence) * 0.3);

        // Clamp to 0.0-1.0
        score.clamp(0.0, 1.0)
    }

    /// Get the underlying safety engine for advanced operations
    pub fn safety_engine(&self) -> &SafetyEngine {
        &self.engine
    }

    /// Get a mutable reference to the safety engine
    pub fn safety_engine_mut(&mut self) -> &mut SafetyEngine {
        &mut self.engine
    }

    /// The same as [`set_agent_risk`](Self::set_agent_risk).
    ///
    /// It used to take `&self` and only log the request, so no score was
    /// ever set.
    pub fn set_agent_risk_score(&mut self, agent_id: &str, score: f64) {
        self.set_agent_risk(agent_id, score);
    }

    /// The number of rule violations found in the agent's plans so far,
    /// whether or not the plan was allowed. It used to be 0 always.
    pub fn get_violation_count(&self, agent_id: &str) -> usize {
        self.violations.get(agent_id).copied().unwrap_or(0)
    }

    /// Whether the agent is high-risk: its risk score is at least
    /// `high_risk_threshold`, or its plans have had more than
    /// `max_violations` violations (in the default, strict config, any).
    /// It used to be `false` always.
    pub fn is_high_risk_agent(&self, agent_id: &str) -> bool {
        self.agent_risk(agent_id) >= self.config.high_risk_threshold
            || self.get_violation_count(agent_id) > self.config.max_violations
    }

    /// Check if a file is marked as critical, after canonicalising the path
    /// as the safety engine does (`/etc//shadow` is `/etc/shadow`).
    pub fn is_critical_file(&self, path: &str) -> bool {
        self.critical_files.contains(&canonical_path(path))
    }

    /// Check if a tool is restricted
    pub fn is_restricted_tool(&self, tool: &str) -> bool {
        self.restricted_tools.contains(tool)
    }

    /// Get the current config
    pub fn config(&self) -> &ReasoningConfig {
        &self.config
    }
}

/// State for reasoning host functions in WASM
#[derive(Debug)]
pub struct ReasoningHostState {
    /// The reasoning host instance
    pub host: ReasoningHost,
    /// Agent ID for the current session
    pub agent_id: String,
}

impl ReasoningHostState {
    /// Create new reasoning host state
    pub fn new(agent_id: impl Into<String>, config: ReasoningConfig) -> Self {
        Self {
            host: ReasoningHost::new(config),
            agent_id: agent_id.into(),
        }
    }

    /// Create with default config
    pub fn with_defaults(agent_id: impl Into<String>) -> Self {
        Self::new(agent_id, ReasoningConfig::default())
    }

    /// Create with permissive config for testing
    pub fn permissive(agent_id: impl Into<String>) -> Self {
        Self::new(agent_id, ReasoningConfig::permissive())
    }
}

impl AsRef<ReasoningHostState> for ReasoningHostState {
    fn as_ref(&self) -> &ReasoningHostState {
        self
    }
}

impl AsMut<ReasoningHostState> for ReasoningHostState {
    fn as_mut(&mut self) -> &mut ReasoningHostState {
        self
    }
}

/// The trap a function registered without reasoning state raises.
fn needs_state(function: &str) -> wasmtime::Error {
    format_err!(
        "vak.{function} can't run: it was registered by register_reasoning_functions, \
         which has no reasoning state; use register_reasoning_functions_with_state"
    )
}

/// Registers `vak.verify_plan`, `vak.add_critical_file` and
/// `vak.set_risk_score` for a store with no reasoning state, so a module
/// importing them links. Each one traps when called: without state there
/// is nothing to verify against, record or score.
///
/// They used to succeed doing nothing, and `verify_plan` returned 0,
/// "allowed", for every plan. Use [`register_reasoning_functions_with_state`].
pub fn register_reasoning_functions<T>(linker: &mut Linker<T>) -> Result<(), ReasoningHostError>
where
    T: 'static,
{
    // vak_verify_plan: Verify a proposed plan
    // Input: JSON-encoded PlanVerification (ptr, len)
    // Output: none; it traps.
    linker
        .func_wrap(
            "vak",
            "verify_plan",
            |_caller: Caller<'_, T>, _plan_ptr: i32, _plan_len: i32| -> HostResult<i64> {
                Err(needs_state("verify_plan"))
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    // vak_add_critical_file: Mark a file as critical
    linker
        .func_wrap(
            "vak",
            "add_critical_file",
            |_caller: Caller<'_, T>, _path_ptr: i32, _path_len: i32| -> HostResult<()> {
                Err(needs_state("add_critical_file"))
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    // vak_set_risk_score: Set agent risk score
    linker
        .func_wrap(
            "vak",
            "set_risk_score",
            |_caller: Caller<'_, T>, _score_x1000: i32| -> HostResult<()> {
                Err(needs_state("set_risk_score"))
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    Ok(())
}

/// Register reasoning host functions with full state access
///
/// This version provides complete WASM memory reading and state management.
/// Use this when you need full reasoning capabilities with the sandbox.
///
/// # Type Parameters
///
/// * `T` - State type that implements `AsRef<ReasoningHostState>`
///
/// # Example
///
/// ```rust,ignore
/// use vak::sandbox::reasoning_host::{ReasoningHostState, register_reasoning_functions_with_state};
///
/// struct MyState {
///     reasoning: ReasoningHostState,
///     // other fields...
/// }
///
/// impl AsRef<ReasoningHostState> for MyState {
///     fn as_ref(&self) -> &ReasoningHostState {
///         &self.reasoning
///     }
/// }
/// ```
pub fn register_reasoning_functions_with_state<T>(
    linker: &mut Linker<T>,
) -> Result<(), ReasoningHostError>
where
    T: AsRef<ReasoningHostState> + AsMut<ReasoningHostState> + 'static,
{
    // vak_verify_plan: Verify a proposed plan with full state access
    // Input: JSON-encoded PlanVerification (ptr, len)
    // Output: 0 = allowed; > 0 = denied, the number of violations (1 for a
    // plan denied for its risk alone); -1 = the plan isn't within guest
    // memory. A plan that isn't UTF-8 JSON traps.
    linker
        .func_wrap(
            "vak",
            "verify_plan",
            |mut caller: Caller<'_, T>, plan_ptr: i32, plan_len: i32| -> HostResult<i64> {
                // Get memory from the WASM instance
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| format_err!("Failed to get WASM memory"))?;

                // Read the plan before borrowing the caller mutably. The
                // bounds used to be sign-extended and added unchecked, so a
                // negative pointer panicked the host.
                let mut plan: PlanVerification = {
                    let data = memory.data(&caller);
                    let Some(range) = guest_range(plan_ptr, plan_len, data.len()) else {
                        warn!(
                            ptr = plan_ptr,
                            len = plan_len,
                            data_len = data.len(),
                            "Memory bounds exceeded"
                        );
                        return Ok(-1i64); // Memory error
                    };
                    let plan_json = std::str::from_utf8(&data[range])
                        .map_err(|e| format_err!("Invalid UTF-8 in plan: {}", e))?;
                    serde_json::from_str(plan_json)
                        .map_err(|e| format_err!("Failed to parse plan JSON: {}", e))?
                };

                // The guest wrote the plan, agent and all. The store's agent
                // is the one asking, so the plan is verified as that agent,
                // whatever it claims.
                let state = caller.data_mut().as_mut();
                if plan.agent_id != state.agent_id {
                    warn!(
                        claimed = %plan.agent_id,
                        agent_id = %state.agent_id,
                        "A plan named another agent; verifying it as the caller"
                    );
                    plan.agent_id = state.agent_id.clone();
                }

                debug!(
                    agent_id = %plan.agent_id,
                    action = %plan.action_type,
                    target = %plan.target,
                    "Verifying plan from WASM"
                );

                let result = state.host.verify_plan(&plan);
                if result.allowed {
                    return Ok(0);
                }
                // A plan denied for its risk alone has no violations; its
                // count of 0 used to read as "allowed".
                let code = i64::try_from(result.violations.len())
                    .unwrap_or(i64::MAX)
                    .max(1);
                info!(
                    agent_id = %plan.agent_id,
                    violations = result.violations.len(),
                    "Plan verification failed"
                );
                Ok(code)
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    // vak_add_critical_file: Mark a file as critical
    linker
        .func_wrap(
            "vak",
            "add_critical_file",
            |mut caller: Caller<'_, T>, path_ptr: i32, path_len: i32| -> HostResult<()> {
                // Get memory
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| format_err!("Failed to get WASM memory"))?;

                // Read path from WASM memory before mutable borrow
                let path: String = {
                    let data = memory.data(&caller);
                    let range = guest_range(path_ptr, path_len, data.len())
                        .ok_or_else(|| format_err!("Memory bounds exceeded"))?;
                    std::str::from_utf8(&data[range])
                        .map_err(|e| format_err!("Invalid UTF-8 in path: {}", e))?
                        .to_string()
                };

                // Add to critical files
                let state = caller.data_mut().as_mut();
                state.host.add_critical_file(&path);

                debug!(path = %path, "Added critical file via WASM");
                Ok(())
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    // vak_set_risk_score: Raise the calling agent's risk score
    // Input: the score * 1000. It only raises: a lower score is ignored.
    // It used to call a method that only logged, so nothing was set.
    linker
        .func_wrap(
            "vak",
            "set_risk_score",
            |mut caller: Caller<'_, T>, score_x1000: i32| -> HostResult<()> {
                let score = f64::from(score_x1000) / 1000.0;
                let state = caller.data_mut().as_mut();
                let agent_id = state.agent_id.clone();
                let applied = state.host.raise_agent_risk(&agent_id, score);
                debug!(agent_id = %agent_id, requested = score, applied, "Agent risk score via WASM");
                Ok(())
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    // vak_get_violation_count: Get number of violations for current agent
    linker
        .func_wrap(
            "vak",
            "get_violation_count",
            |caller: Caller<'_, T>| -> HostResult<i32> {
                let state = caller.data().as_ref();
                let count = state.host.get_violation_count(&state.agent_id);
                Ok(count as i32)
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    // vak_is_high_risk: Check if agent is in high-risk state
    linker
        .func_wrap(
            "vak",
            "is_high_risk",
            |caller: Caller<'_, T>| -> HostResult<i32> {
                let state = caller.data().as_ref();
                let is_high_risk = state.host.is_high_risk_agent(&state.agent_id);
                Ok(if is_high_risk { 1 } else { 0 })
            },
        )
        .map_err(|e| {
            ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string()))
        })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reasoning_host_creation() {
        let host = ReasoningHost::new(ReasoningConfig::default());
        assert!(!host.critical_files.is_empty());
    }

    #[test]
    fn test_verify_allowed_plan() {
        let mut host = ReasoningHost::new(ReasoningConfig::default());

        let plan = PlanVerification {
            agent_id: "agent-1".to_string(),
            action_type: "read_file".to_string(),
            target: "/tmp/test.txt".to_string(),
            confidence: 0.9,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        assert!(result.allowed);
    }

    #[test]
    fn test_verify_denied_critical_file() {
        let mut host = ReasoningHost::new(ReasoningConfig::default());

        let plan = PlanVerification {
            agent_id: "agent-1".to_string(),
            action_type: "delete_file".to_string(),
            target: "/etc/shadow".to_string(),
            confidence: 0.9,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        assert!(!result.allowed);
        assert!(!result.violations.is_empty());
    }

    #[test]
    fn test_add_custom_critical_file() {
        let mut host = ReasoningHost::new(ReasoningConfig::default());
        host.add_critical_file("/custom/important.conf");

        let plan = PlanVerification {
            agent_id: "agent-1".to_string(),
            action_type: "delete_file".to_string(),
            target: "/custom/important.conf".to_string(),
            confidence: 0.9,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        assert!(!result.allowed);
    }

    #[test]
    fn test_risk_score_calculation() {
        let mut host = ReasoningHost::new(ReasoningConfig::default());

        // High risk action targeting a system path to ensure denial
        let plan = PlanVerification {
            agent_id: "agent-1".to_string(),
            action_type: "delete_file".to_string(), // Must match rule action
            target: "/etc/shadow".to_string(),      // Critical file in system path
            confidence: 0.5,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        // Should be denied and have a risk score > 0
        assert!(!result.allowed, "Expected plan to be denied");
        assert!(
            result.risk_score > 0.0,
            "Expected positive risk score, got {}",
            result.risk_score
        );
    }

    #[test]
    fn test_verification_result_serialization() {
        let result = VerificationResult::denied(
            vec![ViolationInfo {
                violation_type: "critical_file".to_string(),
                resource: "/etc/shadow".to_string(),
                rule: "CriticalFileDelete".to_string(),
                severity: 1.0,
            }],
            0.8,
        );

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("critical_file"));

        let parsed: VerificationResult = serde_json::from_str(&json).unwrap();
        assert!(!parsed.allowed);
    }

    #[test]
    fn test_reasoning_host_state_creation() {
        let state = ReasoningHostState::new("agent-1", ReasoningConfig::default());
        assert_eq!(state.agent_id, "agent-1");
    }

    #[test]
    fn test_reasoning_host_state_with_defaults() {
        let state = ReasoningHostState::with_defaults("agent-2");
        assert_eq!(state.agent_id, "agent-2");
        assert!(state.host.config().strict_mode); // Default is strict
    }

    #[test]
    fn test_reasoning_host_state_permissive() {
        let state = ReasoningHostState::permissive("agent-3");
        assert_eq!(state.agent_id, "agent-3");
        assert!(!state.host.config().strict_mode); // Permissive mode
    }

    #[test]
    fn test_reasoning_host_critical_file_check() {
        let host = ReasoningHost::new(ReasoningConfig::default());

        // Default critical files should be present
        assert!(host.is_critical_file("/etc/shadow"));
        assert!(host.is_critical_file("/etc/passwd"));
        assert!(!host.is_critical_file("/tmp/random.txt"));
    }

    #[test]
    fn test_reasoning_host_restricted_tool_check() {
        let mut host = ReasoningHost::new(ReasoningConfig::default());

        // No restricted tools by default
        assert!(!host.is_restricted_tool("calculator"));

        // Add a restricted tool
        host.add_restricted_tool("dangerous_tool");
        assert!(host.is_restricted_tool("dangerous_tool"));
        assert!(!host.is_restricted_tool("safe_tool"));
    }

    #[test]
    fn test_reasoning_host_as_ref() {
        let state = ReasoningHostState::with_defaults("agent-4");
        let state_ref: &ReasoningHostState = state.as_ref();
        assert_eq!(state_ref.agent_id, "agent-4");
    }

    #[test]
    fn test_reasoning_host_as_mut() {
        let mut state = ReasoningHostState::with_defaults("agent-5");
        {
            let state_mut: &mut ReasoningHostState = state.as_mut();
            state_mut.host.add_critical_file("/custom/secret.key");
        }
        assert!(state.host.is_critical_file("/custom/secret.key"));
    }

    use wasmtime::{Engine, Instance, Module, Store};

    /// A guest importing every stateful reasoning function. Plans are
    /// written into its memory from the test.
    const REASONING_WAT: &str = r#"
        (module
          (import "vak" "verify_plan" (func $verify (param i32 i32) (result i64)))
          (import "vak" "add_critical_file" (func $critical (param i32 i32)))
          (import "vak" "set_risk_score" (func $risk (param i32)))
          (import "vak" "get_violation_count" (func $count (result i32)))
          (import "vak" "is_high_risk" (func $high (result i32)))
          (memory (export "memory") 1)
          (func (export "verify") (param i32 i32) (result i64)
            (call $verify (local.get 0) (local.get 1)))
          (func (export "critical") (param i32 i32)
            (call $critical (local.get 0) (local.get 1)))
          (func (export "risk") (param i32) (call $risk (local.get 0)))
          (func (export "count") (result i32) (call $count))
          (func (export "high") (result i32) (call $high)))
    "#;

    struct Guest {
        store: Store<ReasoningHostState>,
        instance: Instance,
    }

    impl Guest {
        fn new(state: ReasoningHostState) -> Self {
            let engine = Engine::default();
            let mut linker = Linker::new(&engine);
            register_reasoning_functions_with_state(&mut linker).unwrap();
            let module = Module::new(&engine, REASONING_WAT).unwrap();
            let mut store = Store::new(&engine, state);
            let instance = linker.instantiate(&mut store, &module).unwrap();
            Self { store, instance }
        }

        /// Writes `bytes` at offset 0 and returns their range.
        fn put(&mut self, bytes: &[u8]) -> (i32, i32) {
            let memory = self.instance.get_memory(&mut self.store, "memory").unwrap();
            memory.write(&mut self.store, 0, bytes).unwrap();
            (0, i32::try_from(bytes.len()).unwrap())
        }

        fn verify_at(&mut self, (ptr, len): (i32, i32)) -> wasmtime::Result<i64> {
            self.instance
                .get_typed_func::<(i32, i32), i64>(&mut self.store, "verify")
                .unwrap()
                .call(&mut self.store, (ptr, len))
        }

        fn verify(&mut self, plan: serde_json::Value) -> i64 {
            let range = self.put(plan.to_string().as_bytes());
            self.verify_at(range).unwrap()
        }

        fn critical_at(&mut self, (ptr, len): (i32, i32)) -> wasmtime::Result<()> {
            self.instance
                .get_typed_func::<(i32, i32), ()>(&mut self.store, "critical")
                .unwrap()
                .call(&mut self.store, (ptr, len))
        }

        fn set_risk(&mut self, score_x1000: i32) {
            self.instance
                .get_typed_func::<i32, ()>(&mut self.store, "risk")
                .unwrap()
                .call(&mut self.store, score_x1000)
                .unwrap();
        }

        fn query(&mut self, name: &str) -> i32 {
            self.instance
                .get_typed_func::<(), i32>(&mut self.store, name)
                .unwrap()
                .call(&mut self.store, ())
                .unwrap()
        }
    }

    fn plan(agent: &str, action: &str, target: &str, confidence: f64) -> serde_json::Value {
        serde_json::json!({
            "agent_id": agent, "action_type": action, "target": target, "confidence": confidence,
        })
    }

    #[test]
    fn test_the_stateless_functions_fail_closed() {
        // verify_plan returned 0, "allowed", for every plan; the others
        // succeeded doing nothing.
        let engine = Engine::default();
        let mut linker = Linker::<()>::new(&engine);
        register_reasoning_functions(&mut linker).unwrap();
        let wat = r#"
            (module
              (import "vak" "verify_plan" (func $verify (param i32 i32) (result i64)))
              (import "vak" "add_critical_file" (func $critical (param i32 i32)))
              (import "vak" "set_risk_score" (func $risk (param i32)))
              (memory (export "memory") 1)
              (func (export "verify") (result i64) (call $verify (i32.const 0) (i32.const 2)))
              (func (export "critical") (call $critical (i32.const 0) (i32.const 2)))
              (func (export "risk") (call $risk (i32.const 1000))))
        "#;
        let module = Module::new(&engine, wat).unwrap();
        let mut store = Store::new(&engine, ());
        let instance = linker.instantiate(&mut store, &module).unwrap();
        let verify = instance
            .get_typed_func::<(), i64>(&mut store, "verify")
            .unwrap();
        let err = verify.call(&mut store, ()).unwrap_err();
        assert!(
            format!("{err:#}").contains("vak.verify_plan can't run"),
            "{err:#}"
        );
        for name in ["critical", "risk"] {
            let call = instance.get_typed_func::<(), ()>(&mut store, name).unwrap();
            let err = call.call(&mut store, ()).unwrap_err();
            assert!(
                format!("{err:#}").contains("register_reasoning_functions_with_state"),
                "{name}: {err:#}"
            );
        }
    }

    #[test]
    fn test_a_plan_denied_for_its_risk_alone_is_not_allowed() {
        // No rule covers "execute", so the denial is the risk score's, with
        // no violations; the count of 0 used to read as "allowed".
        let risky = plan("agent-1", "execute", "/etc/cron.d/job", 0.0);
        let mut host = ReasoningHost::new(ReasoningConfig::default());
        let result = host.verify_plan(&serde_json::from_value(risky.clone()).unwrap());
        assert!(
            !result.allowed && result.violations.is_empty(),
            "{result:?}"
        );
        assert_eq!(result.verdict, "Plan denied: high risk");

        let mut guest = Guest::new(ReasoningHostState::with_defaults("agent-1"));
        assert_eq!(guest.verify(risky), 1);
        assert_eq!(guest.verify(plan("agent-1", "execute", "/tmp/job", 1.0)), 0);
        // A denial with violations returns their count.
        assert!(guest.verify(plan("agent-1", "delete_file", "/etc/shadow", 1.0)) >= 2);
    }

    #[test]
    fn test_confidence_cannot_buy_approval() {
        // Confidence above 1 pushed the risk below zero, clamped to 0.
        let config = ReasoningConfig {
            high_risk_threshold: 0.3,
            ..ReasoningConfig::default()
        };
        let mut host = ReasoningHost::new(config.clone());
        for confidence in [1.0, 1000.0, f64::INFINITY, f64::NAN, -5.0] {
            let p: PlanVerification =
                serde_json::from_value(plan("a", "execute", "/tmp/job", 0.0)).unwrap();
            let p = PlanVerification { confidence, ..p };
            assert!(!host.verify_plan(&p).allowed, "confidence {confidence}");
        }
        let mut guest = Guest::new(ReasoningHostState::new("agent-1", config));
        assert_eq!(
            guest.verify(plan("agent-1", "execute", "/tmp/job", 1000.0)),
            1
        );
    }

    #[test]
    fn test_a_plan_is_verified_as_the_calling_agent() {
        // Rules used to see agent "unknown", so an agent's capabilities and
        // risk never applied. Now they do, and the plan can't name another
        // agent to borrow its capabilities.
        let capable = |agent: &str| {
            let mut state = ReasoningHostState::with_defaults(agent);
            state
                .host
                .safety_engine_mut()
                .add_fact(Fact::agent_capability("agent-1", "network"));
            state
        };
        let fetch = |agent: &str| plan(agent, "fetch", "api.example.com", 1.0);

        let mut guest = Guest::new(capable("agent-1"));
        assert_eq!(guest.verify(fetch("agent-1")), 0, "agent-1 may fetch");
        assert_eq!(
            guest.verify(fetch("someone-else")),
            0,
            "verified as agent-1"
        );

        let mut impostor = Guest::new(capable("agent-2"));
        assert_eq!(
            impostor.verify(fetch("agent-1")),
            1,
            "agent-2 lacks the capability"
        );
        assert_eq!(impostor.store.data().host.get_violation_count("agent-2"), 1);
        assert_eq!(impostor.store.data().host.get_violation_count("agent-1"), 0);
    }

    #[test]
    fn test_a_guest_can_raise_its_risk_but_never_lower_it() {
        let mut state = ReasoningHostState::with_defaults("agent-1");
        state
            .host
            .safety_engine_mut()
            .add_fact(Fact::agent_capability("agent-1", "network"));
        let mut guest = Guest::new(state);
        let fetch = plan("agent-1", "fetch", "api.example.com", 1.0);
        assert_eq!(guest.verify(fetch.clone()), 0);
        assert_eq!(guest.query("high"), 0);

        // It used to call a method that only logged.
        guest.set_risk(900);
        assert_eq!(guest.store.data().host.agent_risk("agent-1"), 0.9);
        assert_eq!(
            guest.verify(fetch.clone()),
            1,
            "high-risk agents can't fetch"
        );
        assert_eq!(guest.query("high"), 1);

        for lower in [0, -5_000, 500] {
            guest.set_risk(lower);
            assert_eq!(guest.store.data().host.agent_risk("agent-1"), 0.9);
        }
        assert_eq!(guest.verify(fetch), 1);
        guest.set_risk(5_000);
        assert_eq!(
            guest.store.data().host.agent_risk("agent-1"),
            1.0,
            "clamped"
        );
    }

    #[test]
    fn test_violations_are_counted_and_make_an_agent_high_risk() {
        // Both queries returned constants: 0, and false.
        let mut guest = Guest::new(ReasoningHostState::with_defaults("agent-1"));
        assert_eq!((guest.query("count"), guest.query("high")), (0, 0));
        let found = guest.verify(plan("agent-1", "delete_file", "/etc/shadow", 1.0));
        assert_eq!(i64::from(guest.query("count")), found);
        assert_eq!(guest.query("high"), 1, "strict: any violation");

        // Permissive allows up to five, and counts them all the same.
        let mut guest = Guest::new(ReasoningHostState::permissive("agent-1"));
        let mut total = 0;
        for _ in 0..3 {
            assert_eq!(
                guest.verify(plan("agent-1", "read_file", "/srv/.env", 1.0)),
                0
            );
            total += 1;
        }
        assert_eq!(guest.query("count"), total);
        assert_eq!(guest.query("high"), 0);
        for _ in 0..3 {
            guest.verify(plan("agent-1", "read_file", "/srv/.env", 1.0));
        }
        assert_eq!(guest.query("high"), 1, "more than five");
    }

    #[test]
    fn test_guest_memory_is_bounds_checked() {
        // Pointers were sign-extended and added unchecked: a host panic.
        let mut guest = Guest::new(ReasoningHostState::with_defaults("agent-1"));
        for range in [(-1, 2), (i32::MAX, i32::MAX), (0, -1), (65_530, 10)] {
            assert_eq!(guest.verify_at(range).unwrap(), -1, "{range:?}");
            let err = guest.critical_at(range).unwrap_err();
            assert!(
                format!("{err:#}").contains("Memory bounds exceeded"),
                "{range:?}: {err:#}"
            );
        }
        let range = guest.put(b"{not json");
        assert!(format!("{:#}", guest.verify_at(range).unwrap_err()).contains("parse plan JSON"));
        let range = guest.put(b"\xff\xfe");
        assert!(format!("{:#}", guest.verify_at(range).unwrap_err()).contains("UTF-8"));
        assert!(format!("{:#}", guest.critical_at(range).unwrap_err()).contains("UTF-8"));
    }

    #[test]
    fn test_a_guest_can_protect_a_file() {
        let mut guest = Guest::new(ReasoningHostState::with_defaults("agent-1"));
        let delete = plan("agent-1", "delete_file", "/srv/app.conf", 1.0);
        assert_eq!(guest.verify(delete.clone()), 0);
        let range = guest.put(b"/srv//app.conf");
        guest.critical_at(range).unwrap();
        assert!(guest.store.data().host.is_critical_file("/srv/app.conf"));
        assert!(guest.verify(delete) >= 1);
    }

    #[test]
    fn test_one_risk_score_per_agent() {
        // Each call added a fact beside the earlier ones, and the engine
        // read whichever it found first.
        let mut host = ReasoningHost::new(ReasoningConfig::default());
        host.set_agent_risk("a", 0.9);
        host.set_agent_risk("a", 0.1);
        assert_eq!(host.agent_risk("a"), 0.1);
        assert!(!host.safety_engine().has_fact(&Fact::agent_risk("a", 0.9)));
        assert!(host.safety_engine().has_fact(&Fact::agent_risk("a", 0.1)));
        assert_eq!(host.raise_agent_risk("a", 0.05), 0.1);
        assert_eq!(host.raise_agent_risk("a", 0.4), 0.4);

        // set_agent_risk_score only logged.
        host.set_agent_risk_score("b", 0.8);
        assert_eq!(host.agent_risk("b"), 0.8);
        assert!(host.is_high_risk_agent("b"));
        host.set_agent_risk("c", f64::NAN);
        assert_eq!(host.agent_risk("c"), 1.0, "not a number is the most risk");
        assert_eq!(host.agent_risk("nobody"), 0.0);
        assert!(!host.is_high_risk_agent("nobody"));
    }

    #[test]
    fn test_plans_add_no_facts() {
        // Each plan was added as a fact no rule reads, so a guest could
        // grow the host's memory at will.
        let mut host = ReasoningHost::new(ReasoningConfig::default());
        let facts = host.safety_engine().fact_count();
        for i in 0..50 {
            let p: PlanVerification =
                serde_json::from_value(plan("a", "read_file", &format!("/tmp/{i}"), 1.0)).unwrap();
            host.verify_plan(&p);
        }
        assert_eq!(host.safety_engine().fact_count(), facts);
    }

    #[test]
    fn test_critical_paths_are_canonical() {
        let mut host = ReasoningHost::new(ReasoningConfig::default());
        assert!(host.is_critical_file("/etc//shadow"));
        assert!(host.is_critical_file("/etc/./ssh/../shadow"));
        host.add_critical_file("/custom//x.conf");
        assert!(host.is_critical_file("/custom/x.conf"));
        host.add_sensitive_file("/srv/token");
        host.set_agent_risk("a", 0.2);
        assert!(format!("{host:?}").contains("critical_files_count"));
        let p: PlanVerification = serde_json::from_str(
            r#"{"agent_id":"a","action_type":"read_file","target":"/srv/token"}"#,
        )
        .unwrap();
        assert_eq!(p.confidence, 1.0, "the default");
        assert!(!host.verify_plan(&p).allowed, "sensitive");
        assert!(ReasoningHost::permissive().config().max_violations > 0);
        assert!(VerificationResult::denied(vec![], 0.9)
            .verdict
            .contains("high risk"));
    }
}
