//! PRM Gating and Backtracking (Issue #47)
//!
//! This module provides Process Reward Model (PRM) integration with the kernel
//! for safety gating and automatic backtracking when reasoning quality is poor.
//!
//! # Overview
//!
//! The PRM gating system:
//! - Scores each reasoning step before tool execution
//! - Blocks actions that fall below configurable thresholds
//! - Triggers backtracking to safer alternatives
//! - Logs all PRM decisions to the audit trail
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::reasoner::prm_gating::{PrmGate, GateConfig, GateDecision};
//!
//! let config = GateConfig::default()
//!     .with_threshold(0.7)
//!     .with_max_retries(3);
//!
//! let gate = PrmGate::new(config, prm_scorer);
//!
//! // Gate an action
//! let decision = gate.evaluate(thought, action, context).await;
//! match decision {
//!     GateDecision::Allow => { /* proceed */ }
//!     GateDecision::Deny(reason) => { /* block action */ }
//!     GateDecision::Backtrack(alternative) => { /* try alternative */ }
//! }
//! ```

use crate::reasoner::prm::{PrmError, PrmScorer, ReasoningStep, ThoughtScore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during PRM gating
#[derive(Debug, Error)]
pub enum GateError {
    /// PRM scoring error
    #[error("PRM scoring error: {0}")]
    ScoringError(#[from] PrmError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Backtracking limit exceeded
    #[error("Backtracking limit exceeded after {0} attempts")]
    BacktrackLimitExceeded(usize),

    /// No alternatives available
    #[error("No alternatives available for backtracking")]
    NoAlternatives,

    /// Gate timeout
    #[error("Gate evaluation timed out after {0}ms")]
    Timeout(u64),
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for PRM gating
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateConfig {
    /// Score threshold for allowing actions (0.0-1.0)
    pub allow_threshold: f64,
    /// Score threshold for triggering backtracking (0.0-1.0)
    pub backtrack_threshold: f64,
    /// Maximum backtracking attempts
    pub max_retries: usize,
    /// Enable automatic backtracking
    pub auto_backtrack: bool,
    /// Minimum confidence required for decisions
    pub min_confidence: f64,
    /// Enable PRM gating (can be disabled for testing)
    pub enabled: bool,
    /// Timeout for PRM evaluation (milliseconds)
    pub timeout_ms: u64,
    /// Log all PRM decisions to audit
    pub audit_decisions: bool,
    /// High-risk actions requiring stricter thresholds
    pub high_risk_actions: Vec<String>,
    /// Threshold for high-risk actions
    pub high_risk_threshold: f64,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            allow_threshold: 0.7,
            backtrack_threshold: 0.4,
            max_retries: 3,
            auto_backtrack: true,
            min_confidence: 0.5,
            enabled: true,
            timeout_ms: 5000,
            audit_decisions: true,
            high_risk_actions: vec![
                "delete".to_string(),
                "write".to_string(),
                "execute".to_string(),
                "transfer".to_string(),
                "modify".to_string(),
            ],
            high_risk_threshold: 0.85,
        }
    }
}

impl GateConfig {
    /// Set the allow threshold
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.allow_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Set maximum retries
    pub fn with_max_retries(mut self, retries: usize) -> Self {
        self.max_retries = retries;
        self
    }

    /// Disable automatic backtracking
    pub fn without_backtracking(mut self) -> Self {
        self.auto_backtrack = false;
        self
    }

    /// Add a high-risk action
    pub fn with_high_risk_action(mut self, action: impl Into<String>) -> Self {
        self.high_risk_actions.push(action.into());
        self
    }

    /// Set high-risk threshold
    pub fn with_high_risk_threshold(mut self, threshold: f64) -> Self {
        self.high_risk_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Create a permissive config for testing
    pub fn permissive() -> Self {
        Self {
            allow_threshold: 0.3,
            backtrack_threshold: 0.1,
            max_retries: 10,
            auto_backtrack: false,
            min_confidence: 0.1,
            enabled: false,
            timeout_ms: 30000,
            audit_decisions: false,
            high_risk_actions: vec![],
            high_risk_threshold: 0.5,
        }
    }

    /// Create a strict config for production
    pub fn strict() -> Self {
        Self {
            allow_threshold: 0.8,
            backtrack_threshold: 0.5,
            max_retries: 2,
            auto_backtrack: true,
            min_confidence: 0.7,
            enabled: true,
            timeout_ms: 3000,
            audit_decisions: true,
            high_risk_actions: vec![
                "delete".to_string(),
                "write".to_string(),
                "execute".to_string(),
                "transfer".to_string(),
                "modify".to_string(),
                "admin".to_string(),
                "sudo".to_string(),
            ],
            high_risk_threshold: 0.95,
        }
    }
}

// ============================================================================
// Gate Decision
// ============================================================================

/// Decision from PRM gate evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GateDecision {
    /// Allow the action to proceed
    Allow {
        score: f64,
        confidence: f64,
        reasoning: String,
    },
    /// Deny the action
    Deny {
        score: f64,
        reason: String,
        suggestion: Option<String>,
    },
    /// Backtrack and try alternative
    Backtrack {
        score: f64,
        reason: String,
        alternative: Option<AlternativeAction>,
        retry_count: usize,
    },
    /// Gating is disabled, pass through
    Bypassed,
}

impl GateDecision {
    /// Check if the decision allows the action
    pub fn is_allowed(&self) -> bool {
        matches!(self, GateDecision::Allow { .. } | GateDecision::Bypassed)
    }

    /// Get the score if available
    pub fn score(&self) -> Option<f64> {
        match self {
            GateDecision::Allow { score, .. } => Some(*score),
            GateDecision::Deny { score, .. } => Some(*score),
            GateDecision::Backtrack { score, .. } => Some(*score),
            GateDecision::Bypassed => None,
        }
    }
}

/// An alternative action suggested during backtracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlternativeAction {
    /// Alternative thought/reasoning
    pub thought: String,
    /// Alternative action
    pub action: String,
    /// Expected score for this alternative
    pub expected_score: f64,
    /// How this alternative was generated
    pub generation_method: String,
}

// ============================================================================
// Gate Context
// ============================================================================

/// Context for gate evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateContext {
    /// Current agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: Option<String>,
    /// Current task description
    pub task: String,
    /// Previous reasoning steps
    pub history: Vec<ReasoningStep>,
    /// Environment attributes
    pub environment: HashMap<String, serde_json::Value>,
    /// Request metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl GateContext {
    /// Create a new gate context
    pub fn new(agent_id: impl Into<String>, task: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            session_id: None,
            task: task.into(),
            history: Vec::new(),
            environment: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Add a reasoning step to history
    pub fn with_step(mut self, step: ReasoningStep) -> Self {
        self.history.push(step);
        self
    }

    /// Add environment attribute
    pub fn with_env(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.environment.insert(key.into(), value);
        self
    }
}

// ============================================================================
// PRM Gate
// ============================================================================

/// PRM-based gate for action safety evaluation
pub struct PrmGate<S: PrmScorer + Send + Sync> {
    config: GateConfig,
    scorer: Arc<S>,
    /// Statistics
    stats: GateStats,
    /// Backtrack state per session
    backtrack_state: RwLock<HashMap<String, BacktrackState>>,
}

/// Statistics about gate decisions
#[derive(Debug, Default)]
pub struct GateStats {
    pub total_evaluations: AtomicU64,
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
    pub backtracked: AtomicU64,
    pub bypassed: AtomicU64,
    pub timeouts: AtomicU64,
    pub errors: AtomicU64,
}

impl GateStats {
    /// Get allow rate
    pub fn allow_rate(&self) -> f64 {
        let total = self.total_evaluations.load(Ordering::Relaxed) as f64;
        if total == 0.0 {
            return 0.0;
        }
        self.allowed.load(Ordering::Relaxed) as f64 / total
    }

    /// Get summary as JSON
    pub fn summary(&self) -> serde_json::Value {
        serde_json::json!({
            "total_evaluations": self.total_evaluations.load(Ordering::Relaxed),
            "allowed": self.allowed.load(Ordering::Relaxed),
            "denied": self.denied.load(Ordering::Relaxed),
            "backtracked": self.backtracked.load(Ordering::Relaxed),
            "bypassed": self.bypassed.load(Ordering::Relaxed),
            "timeouts": self.timeouts.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "allow_rate": self.allow_rate(),
        })
    }
}

/// Backtrack state for a session
#[derive(Debug, Default)]
struct BacktrackState {
    retry_count: usize,
    failed_actions: Vec<(String, f64)>,
    last_score: Option<f64>,
}

impl<S: PrmScorer + Send + Sync> PrmGate<S> {
    /// Create a new PRM gate
    pub fn new(config: GateConfig, scorer: Arc<S>) -> Self {
        Self {
            config,
            scorer,
            stats: GateStats::default(),
            backtrack_state: RwLock::new(HashMap::new()),
        }
    }

    /// Check if an action is high-risk
    fn is_high_risk_action(&self, action: &str) -> bool {
        let action_lower = action.to_lowercase();
        self.config
            .high_risk_actions
            .iter()
            .any(|hr| action_lower.contains(hr))
    }

    /// Get the threshold for an action
    fn get_threshold(&self, action: &str) -> f64 {
        if self.is_high_risk_action(action) {
            self.config.high_risk_threshold
        } else {
            self.config.allow_threshold
        }
    }

    /// Evaluate a thought/action pair
    pub async fn evaluate(
        &self,
        thought: &str,
        action: &str,
        context: &GateContext,
    ) -> Result<GateDecision, GateError> {
        self.stats.total_evaluations.fetch_add(1, Ordering::Relaxed);

        // Check if gating is enabled
        if !self.config.enabled {
            self.stats.bypassed.fetch_add(1, Ordering::Relaxed);
            return Ok(GateDecision::Bypassed);
        }

        // Create reasoning step
        let step = ReasoningStep::new(context.history.len() + 1, thought).with_action(action);

        // Score the step
        let score = self.scorer.score_step(&step, &context.history).await?;

        // Get session-specific state
        let session_key = context
            .session_id
            .clone()
            .unwrap_or_else(|| context.agent_id.clone());

        let retry_count = {
            let state = self.backtrack_state.read().await;
            state.get(&session_key).map(|s| s.retry_count).unwrap_or(0)
        };

        // Determine threshold
        let threshold = self.get_threshold(action);

        // Make decision
        let decision = if score.score >= threshold && score.confidence >= self.config.min_confidence
        {
            // Score is good enough - allow
            self.stats.allowed.fetch_add(1, Ordering::Relaxed);

            // Reset backtrack state on success
            {
                let mut state = self.backtrack_state.write().await;
                state.remove(&session_key);
            }

            GateDecision::Allow {
                score: score.score,
                confidence: score.confidence,
                reasoning: score.reasoning.clone(),
            }
        } else if score.score >= self.config.backtrack_threshold && self.config.auto_backtrack {
            // Score is low but not terrible - suggest backtracking
            self.stats.backtracked.fetch_add(1, Ordering::Relaxed);

            // Update backtrack state
            {
                let mut state = self.backtrack_state.write().await;
                let session_state = state.entry(session_key).or_default();
                session_state.retry_count += 1;
                session_state
                    .failed_actions
                    .push((action.to_string(), score.score));
                session_state.last_score = Some(score.score);
            }

            // Check retry limit
            if retry_count >= self.config.max_retries {
                self.stats.denied.fetch_add(1, Ordering::Relaxed);
                return Ok(GateDecision::Deny {
                    score: score.score,
                    reason: format!("Backtracking limit exceeded after {} attempts", retry_count),
                    suggestion: Some(
                        "Consider reformulating the task or seeking human guidance".to_string(),
                    ),
                });
            }

            // Generate alternative suggestion
            let alternative = self
                .suggest_alternative(thought, action, &score, context)
                .await;

            GateDecision::Backtrack {
                score: score.score,
                reason: format!(
                    "Score {:.2} below threshold {:.2}: {}",
                    score.score, threshold, score.reasoning
                ),
                alternative,
                retry_count: retry_count + 1,
            }
        } else {
            // Score is too low - deny
            self.stats.denied.fetch_add(1, Ordering::Relaxed);

            GateDecision::Deny {
                score: score.score,
                reason: format!(
                    "Score {:.2} too low (threshold {:.2}): {}",
                    score.score, threshold, score.reasoning
                ),
                suggestion: Some(format!(
                    "Consider a safer approach. The current reasoning quality is insufficient for action '{}'",
                    action
                )),
            }
        };

        // Log decision to audit if enabled
        if self.config.audit_decisions {
            self.log_decision(&decision, thought, action, context);
        }

        Ok(decision)
    }

    /// Suggest an alternative action through backtracking
    async fn suggest_alternative(
        &self,
        original_thought: &str,
        original_action: &str,
        _score: &ThoughtScore,
        _context: &GateContext,
    ) -> Option<AlternativeAction> {
        // Generate alternative based on the score feedback
        // In a real implementation, this would use the LLM to propose alternatives

        let is_high_risk = self.is_high_risk_action(original_action);

        if is_high_risk {
            // For high-risk actions, suggest a read-only alternative
            Some(AlternativeAction {
                thought: format!(
                    "Instead of {}, let me first verify the current state",
                    original_thought
                ),
                action: format!(
                    "read_{}",
                    original_action
                        .replace("write", "")
                        .replace("delete", "")
                        .replace("modify", "")
                ),
                expected_score: 0.8,
                generation_method: "high_risk_mitigation".to_string(),
            })
        } else {
            // For other actions, suggest breaking into smaller steps
            Some(AlternativeAction {
                thought: format!(
                    "Let me break this down: first verify the preconditions for '{}'",
                    original_action
                ),
                action: "verify_preconditions".to_string(),
                expected_score: 0.75,
                generation_method: "step_decomposition".to_string(),
            })
        }
    }

    /// Log a decision (placeholder for audit integration)
    fn log_decision(
        &self,
        decision: &GateDecision,
        _thought: &str,
        action: &str,
        context: &GateContext,
    ) {
        let decision_type = match decision {
            GateDecision::Allow { .. } => "allow",
            GateDecision::Deny { .. } => "deny",
            GateDecision::Backtrack { .. } => "backtrack",
            GateDecision::Bypassed => "bypass",
        };

        tracing::info!(
            target: "prm_gate",
            agent_id = %context.agent_id,
            decision = decision_type,
            action = action,
            score = ?decision.score(),
            "PRM gate decision"
        );
    }

    /// Get gate statistics
    pub fn stats(&self) -> &GateStats {
        &self.stats
    }

    /// Reset backtrack state for a session
    pub async fn reset_session(&self, session_id: &str) {
        let mut state = self.backtrack_state.write().await;
        state.remove(session_id);
    }

    /// Check if configuration is valid
    pub fn validate_config(&self) -> Result<(), GateError> {
        if self.config.allow_threshold <= self.config.backtrack_threshold {
            return Err(GateError::ConfigError(
                "allow_threshold must be greater than backtrack_threshold".to_string(),
            ));
        }
        if self.config.high_risk_threshold < self.config.allow_threshold {
            return Err(GateError::ConfigError(
                "high_risk_threshold should be >= allow_threshold".to_string(),
            ));
        }
        Ok(())
    }
}

// ============================================================================
// Batch Gate
// ============================================================================

/// Batch evaluation result
#[derive(Debug)]
pub struct BatchGateResult {
    pub decisions: Vec<(usize, GateDecision)>,
    pub all_allowed: bool,
    pub first_denial_idx: Option<usize>,
}

impl<S: PrmScorer + Send + Sync> PrmGate<S> {
    /// Evaluate multiple steps as a trajectory
    pub async fn evaluate_trajectory(
        &self,
        steps: &[(String, String)], // (thought, action) pairs
        context: &GateContext,
    ) -> Result<BatchGateResult, GateError> {
        let mut decisions = Vec::new();
        let mut all_allowed = true;
        let mut first_denial_idx = None;

        for (idx, (thought, action)) in steps.iter().enumerate() {
            let decision = self.evaluate(thought, action, context).await?;

            if !decision.is_allowed() {
                all_allowed = false;
                if first_denial_idx.is_none() {
                    first_denial_idx = Some(idx);
                }
            }

            decisions.push((idx, decision));
        }

        Ok(BatchGateResult {
            decisions,
            all_allowed,
            first_denial_idx,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reasoner::prm::TrajectoryScore;
    use async_trait::async_trait;

    // Mock PRM scorer for testing
    struct MockPrmScorer {
        score: f64,
        confidence: f64,
    }

    impl MockPrmScorer {
        fn new(score: f64, confidence: f64) -> Self {
            Self { score, confidence }
        }
    }

    #[async_trait]
    impl PrmScorer for MockPrmScorer {
        async fn score_step(
            &self,
            _step: &ReasoningStep,
            _history: &[ReasoningStep],
        ) -> Result<ThoughtScore, PrmError> {
            ThoughtScore::new(self.score, self.confidence, "Mock reasoning")
        }

        async fn score_trajectory(
            &self,
            _steps: &[ReasoningStep],
        ) -> Result<TrajectoryScore, PrmError> {
            Ok(TrajectoryScore {
                overall_score: self.score,
                step_scores: vec![],
                reasoning: "Mock trajectory".to_string(),
            })
        }
    }

    #[tokio::test]
    async fn test_allow_decision() {
        let scorer = Arc::new(MockPrmScorer::new(0.85, 0.9));
        let config = GateConfig::default();
        let gate = PrmGate::new(config, scorer);

        let context = GateContext::new("test-agent", "test task");
        let decision = gate
            .evaluate("good thought", "read", &context)
            .await
            .unwrap();

        assert!(decision.is_allowed());
        match decision {
            GateDecision::Allow { score, .. } => assert!(score >= 0.7),
            _ => panic!("Expected Allow decision"),
        }
    }

    #[tokio::test]
    async fn test_deny_decision() {
        let scorer = Arc::new(MockPrmScorer::new(0.2, 0.9));
        let config = GateConfig::default();
        let gate = PrmGate::new(config, scorer);

        let context = GateContext::new("test-agent", "test task");
        let decision = gate
            .evaluate("poor thought", "delete", &context)
            .await
            .unwrap();

        assert!(!decision.is_allowed());
        match decision {
            GateDecision::Deny { score, .. } => assert!(score < 0.4),
            _ => panic!("Expected Deny decision"),
        }
    }

    #[tokio::test]
    async fn test_backtrack_decision() {
        let scorer = Arc::new(MockPrmScorer::new(0.5, 0.9));
        let config = GateConfig::default();
        let gate = PrmGate::new(config, scorer);

        let context = GateContext::new("test-agent", "test task");
        let decision = gate
            .evaluate("mediocre thought", "read", &context)
            .await
            .unwrap();

        match decision {
            GateDecision::Backtrack {
                score, alternative, ..
            } => {
                assert!(score < 0.7);
                assert!(alternative.is_some());
            }
            _ => panic!("Expected Backtrack decision"),
        }
    }

    #[tokio::test]
    async fn test_high_risk_action() {
        let scorer = Arc::new(MockPrmScorer::new(0.8, 0.9));
        let config = GateConfig::default();
        let gate = PrmGate::new(config, scorer);

        let context = GateContext::new("test-agent", "test task");

        // 0.8 is enough for read but not for delete (high-risk)
        let read_decision = gate.evaluate("thought", "read", &context).await.unwrap();
        let delete_decision = gate.evaluate("thought", "delete", &context).await.unwrap();

        assert!(read_decision.is_allowed());
        assert!(!delete_decision.is_allowed()); // Requires 0.85 threshold
    }

    #[tokio::test]
    async fn test_bypass_when_disabled() {
        let scorer = Arc::new(MockPrmScorer::new(0.0, 0.0));
        let config = GateConfig::permissive(); // disabled
        let gate = PrmGate::new(config, scorer);

        let context = GateContext::new("test-agent", "test task");
        let decision = gate
            .evaluate("any thought", "any action", &context)
            .await
            .unwrap();

        assert!(matches!(decision, GateDecision::Bypassed));
    }

    #[tokio::test]
    async fn test_backtrack_limit() {
        let scorer = Arc::new(MockPrmScorer::new(0.5, 0.9));
        let config = GateConfig::default().with_max_retries(2);
        let gate = PrmGate::new(config, scorer);

        let context = GateContext::new("test-agent", "test task").with_session("test-session");

        // First two attempts should backtrack
        for _ in 0..2 {
            let decision = gate.evaluate("thought", "action", &context).await.unwrap();
            assert!(matches!(decision, GateDecision::Backtrack { .. }));
        }

        // Third attempt should deny
        let decision = gate.evaluate("thought", "action", &context).await.unwrap();
        assert!(matches!(decision, GateDecision::Deny { .. }));
    }

    #[test]
    fn test_config_validation() {
        let good_config = GateConfig::default();
        let gate = PrmGate::new(good_config, Arc::new(MockPrmScorer::new(0.5, 0.5)));
        assert!(gate.validate_config().is_ok());

        let bad_config = GateConfig {
            allow_threshold: 0.3,
            backtrack_threshold: 0.5, // Higher than allow - invalid
            ..Default::default()
        };
        let gate = PrmGate::new(bad_config, Arc::new(MockPrmScorer::new(0.5, 0.5)));
        assert!(gate.validate_config().is_err());
    }

    #[test]
    fn test_gate_stats() {
        let stats = GateStats::default();

        stats.total_evaluations.fetch_add(10, Ordering::Relaxed);
        stats.allowed.fetch_add(7, Ordering::Relaxed);
        stats.denied.fetch_add(2, Ordering::Relaxed);
        stats.backtracked.fetch_add(1, Ordering::Relaxed);

        assert_eq!(stats.allow_rate(), 0.7);

        let summary = stats.summary();
        assert_eq!(summary["total_evaluations"], 10);
        assert_eq!(summary["allowed"], 7);
    }
}
