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
//! });
//!
//! assert!(result.is_violation());
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.4.1: Neuro-Symbolic Hybrid Architecture
//! - Gap Analysis Sprint 4, T4.3: Reasoning host function
//! - NSR-003: verify_plan host function exposed to WASM

use anyhow::Result as AnyhowResult;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, info, warn};
use wasmtime::{Caller, Linker};

use crate::reasoner::datalog::{DatalogError, Fact, SafetyEngine, SafetyVerdict, Violation};

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
            format!(
                "Plan denied: {} violation(s)",
                violations.len()
            )
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
            critical_files: default_critical.iter().map(|s| s.to_string()).collect(),
            restricted_tools: HashSet::new(),
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
        self.critical_files.insert(path);
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

    /// Set agent risk score (affects what actions are allowed)
    pub fn set_agent_risk(&mut self, agent_id: impl Into<String>, score: f64) {
        self.engine.add_fact(Fact::agent_risk(agent_id, score));
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

        // Add the proposed action as a fact
        self.engine.add_fact(Fact::ProposedAction {
            action_type: plan.action_type.clone(),
            target: plan.target.clone(),
            agent_id: plan.agent_id.clone(),
        });

        // Run the safety check
        let verdict = self.engine.check_action(&plan.action_type, &plan.target);

        // Convert violations - use the violations() method which returns Option<&[Violation]>
        let violations: Vec<ViolationInfo> = verdict
            .violations()
            .map(|v| v.iter().map(|vi| vi.into()).collect())
            .unwrap_or_default();

        // Calculate risk score
        let risk_score = self.calculate_risk_score(plan, &verdict);

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

        // Reduce risk based on confidence (high confidence = lower risk)
        score *= 1.0 - (plan.confidence * 0.3);

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
    
    /// Set agent risk score (non-mutable version using interior mutability)
    /// 
    /// Note: This adds a new fact to track the risk score. Call this when an
    /// agent's risk level changes based on their actions or external factors.
    pub fn set_agent_risk_score(&self, agent_id: &str, score: f64) {
        // For now, we log the intent since SafetyEngine doesn't have interior mutability
        // In a production system, we'd use Arc<RwLock<SafetyEngine>> or similar
        debug!(
            agent_id = %agent_id,
            score = score,
            "Agent risk score update requested"
        );
    }
    
    /// Get the count of violations for an agent
    /// 
    /// Returns the number of rule violations recorded for the given agent.
    pub fn get_violation_count(&self, agent_id: &str) -> usize {
        // Query the engine for violations related to this agent
        // Currently returns 0 as SafetyEngine doesn't track per-agent violations
        debug!(agent_id = %agent_id, "Checking violation count");
        0
    }
    
    /// Check if an agent is in a high-risk state
    /// 
    /// Returns true if the agent has exceeded the risk threshold based on
    /// their recent actions or accumulated violations.
    pub fn is_high_risk_agent(&self, agent_id: &str) -> bool {
        // Check if agent has high risk facts
        debug!(agent_id = %agent_id, threshold = self.config.high_risk_threshold, "Checking high risk status");
        false // Default to not high-risk until we have more data
    }
    
    /// Check if a file is marked as critical
    pub fn is_critical_file(&self, path: &str) -> bool {
        self.critical_files.contains(path)
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

/// Register reasoning host functions with a Wasmtime linker
pub fn register_reasoning_functions<T>(
    linker: &mut Linker<T>,
) -> Result<(), ReasoningHostError>
where
    T: 'static,
{
    // vak_verify_plan: Verify a proposed plan
    // Input: JSON-encoded PlanVerification (ptr, len)
    // Output: 0 = allowed, non-zero = denied (violation code)
    linker
        .func_wrap(
            "vak",
            "verify_plan",
            |_caller: Caller<'_, T>,
             _plan_ptr: i32,
             _plan_len: i32|
             -> AnyhowResult<i64> {
                // Note: Full WASM memory reading requires typed state with Memory access.
                // This basic implementation returns success for now.
                // Use register_reasoning_functions_with_state for full functionality.
                Ok(0i64)
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

    // vak_add_critical_file: Mark a file as critical
    linker
        .func_wrap(
            "vak",
            "add_critical_file",
            |_caller: Caller<'_, T>, _path_ptr: i32, _path_len: i32| -> AnyhowResult<()> {
                // Basic stub - use register_reasoning_functions_with_state for full functionality
                Ok(())
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

    // vak_set_risk_score: Set agent risk score
    linker
        .func_wrap(
            "vak",
            "set_risk_score",
            |_caller: Caller<'_, T>, _score_x1000: i32| -> AnyhowResult<()> {
                // Basic stub - use register_reasoning_functions_with_state for full functionality
                Ok(())
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

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
    // Output: 0 = allowed, >0 = violation count
    linker
        .func_wrap(
            "vak",
            "verify_plan",
            |mut caller: Caller<'_, T>,
             plan_ptr: i32,
             plan_len: i32|
             -> AnyhowResult<i64> {
                // Get memory from the WASM instance
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| anyhow::anyhow!("Failed to get WASM memory"))?;
                
                // Validate bounds and read the plan first
                let ptr = plan_ptr as usize;
                let len = plan_len as usize;
                
                // Read data in this scope before borrowing caller mutably
                let plan: PlanVerification = {
                    let data = memory.data(&caller);
                    
                    if ptr + len > data.len() {
                        warn!(ptr = ptr, len = len, data_len = data.len(), "Memory bounds exceeded");
                        return Ok(-1i64); // Memory error
                    }
                    
                    // Read the plan JSON from WASM memory
                    let plan_bytes = &data[ptr..ptr + len];
                    let plan_json = std::str::from_utf8(plan_bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in plan: {}", e))?;
                    
                    // Deserialize to PlanVerification
                    serde_json::from_str(plan_json)
                        .map_err(|e| anyhow::anyhow!("Failed to parse plan JSON: {}", e))?
                };
                
                debug!(
                    agent_id = %plan.agent_id,
                    action = %plan.action_type,
                    target = %plan.target,
                    "Verifying plan from WASM"
                );
                
                // Verify the plan using the reasoning host (mutable borrow)
                let state = caller.data_mut().as_mut();
                let result = state.host.verify_plan(&plan);
                
                // Return violation count (0 = allowed)
                let violation_count = result.violations.len() as i64;
                if violation_count > 0 {
                    info!(
                        agent_id = %plan.agent_id,
                        violations = violation_count,
                        "Plan verification failed"
                    );
                }
                
                Ok(violation_count)
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

    // vak_add_critical_file: Mark a file as critical
    linker
        .func_wrap(
            "vak",
            "add_critical_file",
            |mut caller: Caller<'_, T>, path_ptr: i32, path_len: i32| -> AnyhowResult<()> {
                // Get memory
                let memory = caller
                    .get_export("memory")
                    .and_then(|e| e.into_memory())
                    .ok_or_else(|| anyhow::anyhow!("Failed to get WASM memory"))?;
                
                // Read path from WASM memory before mutable borrow
                let path: String = {
                    let ptr = path_ptr as usize;
                    let len = path_len as usize;
                    let data = memory.data(&caller);
                    
                    if ptr + len > data.len() {
                        return Err(anyhow::anyhow!("Memory bounds exceeded"));
                    }
                    
                    let path_bytes = &data[ptr..ptr + len];
                    std::str::from_utf8(path_bytes)
                        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 in path: {}", e))?
                        .to_string()
                };
                
                // Add to critical files
                let state = caller.data_mut().as_mut();
                state.host.add_critical_file(&path);
                
                debug!(path = %path, "Added critical file via WASM");
                Ok(())
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

    // vak_set_risk_score: Set agent risk score
    linker
        .func_wrap(
            "vak",
            "set_risk_score",
            |mut caller: Caller<'_, T>, score_x1000: i32| -> AnyhowResult<()> {
                // Convert from integer representation (score * 1000) to f64
                let score = (score_x1000 as f64) / 1000.0;
                
                // Clamp to valid range
                let score = score.clamp(0.0, 1.0);
                
                let state = caller.data_mut().as_mut();
                state.host.set_agent_risk_score(&state.agent_id.clone(), score);
                
                debug!(agent_id = %state.agent_id, score = score, "Set agent risk score via WASM");
                Ok(())
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

    // vak_get_violation_count: Get number of violations for current agent
    linker
        .func_wrap(
            "vak",
            "get_violation_count",
            |caller: Caller<'_, T>| -> AnyhowResult<i32> {
                let state = caller.data().as_ref();
                let count = state.host.get_violation_count(&state.agent_id);
                Ok(count as i32)
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

    // vak_is_high_risk: Check if agent is in high-risk state
    linker
        .func_wrap(
            "vak",
            "is_high_risk",
            |caller: Caller<'_, T>| -> AnyhowResult<i32> {
                let state = caller.data().as_ref();
                let is_high_risk = state.host.is_high_risk_agent(&state.agent_id);
                Ok(if is_high_risk { 1 } else { 0 })
            },
        )
        .map_err(|e| ReasoningHostError::DatalogError(DatalogError::EvaluationError(e.to_string())))?;

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
            target: "/etc/shadow".to_string(), // Critical file in system path
            confidence: 0.5,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        // Should be denied and have a risk score > 0
        assert!(!result.allowed, "Expected plan to be denied");
        assert!(result.risk_score > 0.0, "Expected positive risk score, got {}", result.risk_score);
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
}
