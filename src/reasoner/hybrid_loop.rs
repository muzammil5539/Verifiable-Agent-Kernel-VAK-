//! Neuro-Symbolic Hybrid Loop (NSR-006)
//!
//! Implements the complete Neural -> Symbolic -> Neural sandwich architecture
//! for verifiable agent reasoning.
//!
//! # Overview
//!
//! The hybrid loop provides:
//! - LLM proposes a plan (Neural phase)
//! - Datalog validates against invariant rules (Symbolic phase)
//! - Execute only if validation passes (Execution phase)
//! - PRM scoring for step quality assessment
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Neuro-Symbolic Loop                       │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────┐    ┌──────────┐    ┌──────────┐    ┌────────┐ │
//! │  │ NEURAL  │───►│ SYMBOLIC │───►│   PRM    │───►│ EXEC   │ │
//! │  │ (Plan)  │    │(Validate)│    │ (Score)  │    │        │ │
//! │  └─────────┘    └──────────┘    └──────────┘    └────────┘ │
//! │       ▲              │                │              │      │
//! │       │              │                │              │      │
//! │       └──────────────┴────────────────┴──────────────┘      │
//! │                    (Feedback Loop)                           │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::reasoner::hybrid_loop::{HybridLoop, HybridLoopConfig, LoopPhase};
//! use vak::reasoner::{SafetyEngine, ProcessRewardModel, MockPrm};
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create the hybrid loop
//! let config = HybridLoopConfig::default();
//! let safety_engine = SafetyEngine::new_default();
//! let prm = Arc::new(MockPrm::new(0.8)); // Mock PRM with 0.8 score
//!
//! let mut hybrid = HybridLoop::new(config, safety_engine, prm);
//!
//! // Execute a reasoning cycle
//! let plan = "I will read the config file and then apply changes";
//! let result = hybrid.execute_cycle(plan).await?;
//!
//! if result.is_valid() {
//!     println!("Plan validated, executing...");
//! } else {
//!     println!("Plan rejected: {:?}", result.violations());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.4.1: Neuro-Symbolic Hybrid Architecture
//! - Blue Ocean Section 2.2: Neuro-Symbolic Trust

use crate::reasoner::datalog::{DatalogError, Fact, SafetyEngine, SafetyVerdict, Violation};
use crate::reasoner::prm::{ProcessRewardModel, ReasoningStep};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in the hybrid loop
#[derive(Debug, Error)]
pub enum HybridLoopError {
    /// Neural phase failed (LLM error)
    #[error("Neural phase failed: {0}")]
    NeuralError(String),

    /// Symbolic validation failed
    #[error("Symbolic validation failed: {0}")]
    SymbolicError(#[from] DatalogError),

    /// PRM scoring failed
    #[error("PRM scoring failed: {0}")]
    PrmError(String),

    /// Execution blocked by safety rules
    #[error("Execution blocked: {violations:?}")]
    ExecutionBlocked { violations: Vec<Violation> },

    /// PRM score too low
    #[error("PRM score {score:.2} below threshold {threshold:.2}")]
    LowPrmScore { score: f64, threshold: f64 },

    /// Maximum iterations exceeded
    #[error("Maximum iterations ({0}) exceeded")]
    MaxIterationsExceeded(usize),

    /// Timeout
    #[error("Operation timed out after {0}ms")]
    Timeout(u64),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for hybrid loop operations
pub type HybridResult<T> = Result<T, HybridLoopError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the hybrid loop
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridLoopConfig {
    /// Minimum PRM score to proceed
    pub min_prm_score: f64,
    /// Maximum iterations before giving up
    pub max_iterations: usize,
    /// Timeout per cycle in milliseconds
    pub timeout_ms: u64,
    /// Enable backtracking on low scores
    pub enable_backtracking: bool,
    /// Number of alternative plans to generate on failure
    pub alternative_count: usize,
    /// Enable detailed logging
    pub verbose: bool,
    /// Require all safety checks to pass
    pub strict_safety: bool,
    /// Enable caching of validation results
    pub enable_cache: bool,
}

impl Default for HybridLoopConfig {
    fn default() -> Self {
        Self {
            min_prm_score: 0.7,
            max_iterations: 5,
            timeout_ms: 30000,
            enable_backtracking: true,
            alternative_count: 3,
            verbose: false,
            strict_safety: true,
            enable_cache: true,
        }
    }
}

impl HybridLoopConfig {
    /// Create a strict configuration
    pub fn strict() -> Self {
        Self {
            min_prm_score: 0.85,
            max_iterations: 3,
            strict_safety: true,
            ..Default::default()
        }
    }

    /// Create a lenient configuration (for development)
    pub fn lenient() -> Self {
        Self {
            min_prm_score: 0.5,
            max_iterations: 10,
            strict_safety: false,
            ..Default::default()
        }
    }
}

// ============================================================================
// Loop Phases
// ============================================================================

/// Current phase of the hybrid loop
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoopPhase {
    /// Neural phase - LLM generating plan
    Neural,
    /// Symbolic phase - Datalog validation
    Symbolic,
    /// PRM phase - scoring the plan
    Prm,
    /// Execution phase - carrying out the plan
    Execution,
    /// Backtracking - generating alternatives
    Backtracking,
    /// Complete
    Complete,
    /// Failed
    Failed,
}

impl LoopPhase {
    /// Get display name for the phase
    pub fn display_name(&self) -> &'static str {
        match self {
            LoopPhase::Neural => "Neural (Planning)",
            LoopPhase::Symbolic => "Symbolic (Validation)",
            LoopPhase::Prm => "PRM (Scoring)",
            LoopPhase::Execution => "Execution",
            LoopPhase::Backtracking => "Backtracking",
            LoopPhase::Complete => "Complete",
            LoopPhase::Failed => "Failed",
        }
    }
}

// ============================================================================
// Cycle Result
// ============================================================================

/// Result of a single hybrid loop cycle
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleResult {
    /// The plan that was evaluated
    pub plan: String,
    /// Current phase
    pub phase: LoopPhase,
    /// Safety verdict from symbolic validation
    pub safety_verdict: Option<SafetyVerdict>,
    /// PRM score
    pub prm_score: Option<f64>,
    /// Violations found
    pub violations: Vec<Violation>,
    /// Whether the plan is valid for execution
    pub is_valid: bool,
    /// Iteration number
    pub iteration: usize,
    /// Duration of this cycle in milliseconds
    pub duration_ms: u64,
    /// Feedback for the neural phase (if backtracking)
    pub feedback: Option<String>,
}

impl CycleResult {
    /// Create a new cycle result
    pub fn new(plan: impl Into<String>, iteration: usize) -> Self {
        Self {
            plan: plan.into(),
            phase: LoopPhase::Neural,
            safety_verdict: None,
            prm_score: None,
            violations: Vec::new(),
            is_valid: false,
            iteration,
            duration_ms: 0,
            feedback: None,
        }
    }

    /// Check if the plan is valid
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Get violations
    pub fn violations(&self) -> &[Violation] {
        &self.violations
    }

    /// Get PRM score
    pub fn score(&self) -> Option<f64> {
        self.prm_score
    }
}

// ============================================================================
// Execution Plan
// ============================================================================

/// A parsed execution plan from the neural phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// Plan ID
    pub id: String,
    /// Raw plan text
    pub raw_text: String,
    /// Parsed steps
    pub steps: Vec<PlanStep>,
    /// Extracted facts for Datalog
    pub facts: Vec<Fact>,
    /// Confidence score from LLM
    pub confidence: f64,
}

/// A single step in the execution plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    /// Step number
    pub sequence: usize,
    /// Action to perform
    pub action: String,
    /// Target resource
    pub target: Option<String>,
    /// Parameters
    pub params: HashMap<String, String>,
    /// Pre-conditions
    pub preconditions: Vec<String>,
    /// Post-conditions
    pub postconditions: Vec<String>,
}

// ============================================================================
// Plan Parser
// ============================================================================

/// Parser for converting LLM output to structured plans
pub struct PlanParser {
    /// Action keywords to look for
    action_keywords: Vec<String>,
}

impl PlanParser {
    /// Create a new plan parser
    pub fn new() -> Self {
        Self {
            action_keywords: vec![
                "read".to_string(),
                "write".to_string(),
                "delete".to_string(),
                "create".to_string(),
                "update".to_string(),
                "execute".to_string(),
                "call".to_string(),
                "send".to_string(),
                "fetch".to_string(),
            ],
        }
    }

    /// Parse a raw plan text into a structured plan
    pub fn parse(&self, raw_text: &str) -> ExecutionPlan {
        let id = uuid::Uuid::new_v4().to_string();
        let mut steps = Vec::new();
        let mut facts = Vec::new();

        // Simple parsing: look for numbered steps or action keywords
        let lines: Vec<&str> = raw_text.lines().collect();
        let mut sequence = 0;

        for line in &lines {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Try to extract action and target
            for keyword in &self.action_keywords {
                if line.to_lowercase().contains(keyword) {
                    sequence += 1;
                    
                    // Extract target (simple heuristic: look for paths or quoted strings)
                    let target = self.extract_target(line);
                    
                    let step = PlanStep {
                        sequence,
                        action: keyword.clone(),
                        target: target.clone(),
                        params: HashMap::new(),
                        preconditions: Vec::new(),
                        postconditions: Vec::new(),
                    };
                    steps.push(step);

                    // Generate Datalog fact
                    if let Some(ref t) = target {
                        facts.push(Fact::custom("action", vec![keyword.clone(), t.clone()]));
                    }
                    
                    break;
                }
            }
        }

        ExecutionPlan {
            id,
            raw_text: raw_text.to_string(),
            steps,
            facts,
            confidence: 0.8, // Default confidence
        }
    }

    /// Extract target from a line
    fn extract_target(&self, line: &str) -> Option<String> {
        // Look for quoted strings
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start + 1..].find('"') {
                return Some(line[start + 1..start + 1 + end].to_string());
            }
        }

        // Look for paths starting with /
        for word in line.split_whitespace() {
            if word.starts_with('/') || word.starts_with("./") {
                return Some(word.trim_matches(|c| c == ',' || c == '.').to_string());
            }
        }

        None
    }
}

impl Default for PlanParser {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Hybrid Loop
// ============================================================================

/// The main neuro-symbolic hybrid loop
pub struct HybridLoop<P: ProcessRewardModel> {
    config: HybridLoopConfig,
    safety_engine: SafetyEngine,
    prm: Arc<P>,
    parser: PlanParser,
    /// Current iteration
    iteration: usize,
    /// Phase history for debugging
    phase_history: Vec<(LoopPhase, Duration)>,
    /// Validation cache
    cache: RwLock<HashMap<String, CycleResult>>,
}

impl<P: ProcessRewardModel + Send + Sync> HybridLoop<P> {
    /// Create a new hybrid loop
    pub fn new(config: HybridLoopConfig, safety_engine: SafetyEngine, prm: Arc<P>) -> Self {
        Self {
            config,
            safety_engine,
            prm,
            parser: PlanParser::new(),
            iteration: 0,
            phase_history: Vec::new(),
            cache: RwLock::new(HashMap::new()),
        }
    }

    /// Execute a complete reasoning cycle
    pub async fn execute_cycle(&mut self, plan_text: &str) -> HybridResult<CycleResult> {
        let start = Instant::now();
        self.iteration += 1;

        // Check cache
        if self.config.enable_cache {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(plan_text) {
                debug!(plan = %plan_text, "Returning cached result");
                return Ok(cached.clone());
            }
        }

        let mut result = CycleResult::new(plan_text, self.iteration);

        // Phase 1: Neural - Parse the plan
        result.phase = LoopPhase::Neural;
        self.record_phase(LoopPhase::Neural);
        let plan = self.parser.parse(plan_text);

        if self.config.verbose {
            info!(
                iteration = self.iteration,
                steps = plan.steps.len(),
                facts = plan.facts.len(),
                "Parsed plan"
            );
        }

        // Phase 2: Symbolic - Validate with Datalog
        result.phase = LoopPhase::Symbolic;
        self.record_phase(LoopPhase::Symbolic);
        
        let verdict = self.validate_symbolic(&plan).await?;
        result.safety_verdict = Some(verdict.clone());
        
        // Get violations from verdict if any
        let violations_opt = verdict.violations().map(|v| v.to_vec());
        result.violations = violations_opt.clone().unwrap_or_default();

        if !verdict.is_safe() {
            if self.config.strict_safety {
                result.phase = LoopPhase::Failed;
                result.feedback = Some(format!(
                    "Safety violations found: {:?}",
                    violations_opt
                ));
                result.duration_ms = start.elapsed().as_millis() as u64;
                
                warn!(
                    iteration = self.iteration,
                    violations = ?violations_opt,
                    "Plan rejected by symbolic validation"
                );
                
                return Err(HybridLoopError::ExecutionBlocked {
                    violations: result.violations.clone(),
                });
            } else {
                warn!(
                    iteration = self.iteration,
                    violations = ?violations_opt,
                    "Safety violations found but strict mode disabled"
                );
            }
        }

        // Phase 3: PRM - Score the plan
        result.phase = LoopPhase::Prm;
        self.record_phase(LoopPhase::Prm);
        
        let prm_score = self.score_plan(&plan).await?;
        result.prm_score = Some(prm_score);

        if prm_score < self.config.min_prm_score {
            result.phase = LoopPhase::Failed;
            result.feedback = Some(format!(
                "PRM score {:.2} below threshold {:.2}",
                prm_score, self.config.min_prm_score
            ));
            result.duration_ms = start.elapsed().as_millis() as u64;

            warn!(
                iteration = self.iteration,
                score = prm_score,
                threshold = self.config.min_prm_score,
                "Plan rejected by PRM scoring"
            );

            return Err(HybridLoopError::LowPrmScore {
                score: prm_score,
                threshold: self.config.min_prm_score,
            });
        }

        // Phase 4: Ready for execution
        result.phase = LoopPhase::Complete;
        result.is_valid = true;
        result.duration_ms = start.elapsed().as_millis() as u64;

        if self.config.verbose {
            info!(
                iteration = self.iteration,
                score = prm_score,
                duration_ms = result.duration_ms,
                "Plan validated successfully"
            );
        }

        // Cache the result
        if self.config.enable_cache {
            let mut cache = self.cache.write().await;
            cache.insert(plan_text.to_string(), result.clone());
        }

        Ok(result)
    }

    /// Validate plan using Datalog safety engine
    async fn validate_symbolic(&self, plan: &ExecutionPlan) -> HybridResult<SafetyVerdict> {
        // Create a fresh safety engine instance
        let mut engine = SafetyEngine::new();
        
        // Add facts from the plan to the engine
        for fact in &plan.facts {
            engine.add_fact(fact.clone());
        }

        // Convert steps to plan format expected by verify_plan
        let plan_steps: Vec<(&str, &str)> = plan.steps.iter()
            .filter_map(|step| {
                step.target.as_ref().map(|t| (step.action.as_str(), t.as_str()))
            })
            .collect();

        // Verify the plan using safety engine
        let verdict = if plan_steps.is_empty() {
            SafetyVerdict::Safe
        } else {
            engine.verify_plan(&plan_steps, "default_agent")
        };
        
        Ok(verdict)
    }

    /// Score the plan using PRM
    async fn score_plan(&self, plan: &ExecutionPlan) -> HybridResult<f64> {
        // Create a reasoning step from the plan
        let step = ReasoningStep::new(plan.steps.len(), &plan.raw_text);
        
        // Score with PRM
        let score_result = self.prm.score_step(&step, "").await
            .map_err(|e| HybridLoopError::PrmError(e.to_string()))?;

        Ok(score_result.score)
    }

    /// Execute with backtracking on failure
    pub async fn execute_with_backtracking<F, Fut>(
        &mut self,
        initial_plan: &str,
        generate_alternative: F,
    ) -> HybridResult<CycleResult>
    where
        F: Fn(&str, &CycleResult) -> Fut,
        Fut: std::future::Future<Output = Option<String>>,
    {
        let mut current_plan = initial_plan.to_string();
        
        for i in 0..self.config.max_iterations {
            match self.execute_cycle(&current_plan).await {
                Ok(result) if result.is_valid => {
                    return Ok(result);
                }
                Ok(result) => {
                    // Valid but not executable - try alternative
                    if !self.config.enable_backtracking {
                        return Ok(result);
                    }

                    self.record_phase(LoopPhase::Backtracking);
                    
                    if let Some(alternative) = generate_alternative(&current_plan, &result).await {
                        debug!(
                            iteration = i,
                            "Generated alternative plan"
                        );
                        current_plan = alternative;
                    } else {
                        return Ok(result);
                    }
                }
                Err(HybridLoopError::ExecutionBlocked { violations }) => {
                    if !self.config.enable_backtracking {
                        return Err(HybridLoopError::ExecutionBlocked { violations });
                    }

                    let result = CycleResult {
                        plan: current_plan.clone(),
                        phase: LoopPhase::Failed,
                        safety_verdict: None,
                        prm_score: None,
                        violations: violations.clone(),
                        is_valid: false,
                        iteration: i,
                        duration_ms: 0,
                        feedback: Some(format!("Blocked: {:?}", violations)),
                    };

                    self.record_phase(LoopPhase::Backtracking);
                    
                    if let Some(alternative) = generate_alternative(&current_plan, &result).await {
                        current_plan = alternative;
                    } else {
                        return Err(HybridLoopError::ExecutionBlocked { violations });
                    }
                }
                Err(HybridLoopError::LowPrmScore { score, threshold }) => {
                    if !self.config.enable_backtracking {
                        return Err(HybridLoopError::LowPrmScore { score, threshold });
                    }

                    let result = CycleResult {
                        plan: current_plan.clone(),
                        phase: LoopPhase::Failed,
                        safety_verdict: None,
                        prm_score: Some(score),
                        violations: Vec::new(),
                        is_valid: false,
                        iteration: i,
                        duration_ms: 0,
                        feedback: Some(format!("Low score: {:.2}", score)),
                    };

                    self.record_phase(LoopPhase::Backtracking);
                    
                    if let Some(alternative) = generate_alternative(&current_plan, &result).await {
                        current_plan = alternative;
                    } else {
                        return Err(HybridLoopError::LowPrmScore { score, threshold });
                    }
                }
                Err(e) => return Err(e),
            }
        }

        Err(HybridLoopError::MaxIterationsExceeded(self.config.max_iterations))
    }

    /// Record a phase transition
    fn record_phase(&mut self, phase: LoopPhase) {
        let duration = if let Some((_, last_start)) = self.phase_history.last() {
            *last_start
        } else {
            Duration::ZERO
        };
        self.phase_history.push((phase, duration));
    }

    /// Get phase history
    pub fn phase_history(&self) -> &[(LoopPhase, Duration)] {
        &self.phase_history
    }

    /// Clear the validation cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get current iteration
    pub fn iteration(&self) -> usize {
        self.iteration
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reasoner::prm::MockPrm;

    #[test]
    fn test_plan_parser() {
        let parser = PlanParser::new();
        
        let text = r#"
        1. First, I will read the config file "/etc/app.conf"
        2. Then I will update the settings
        3. Finally, I will write the changes to "/var/log/app.log"
        "#;

        let plan = parser.parse(text);
        
        assert!(!plan.steps.is_empty());
        assert!(plan.steps.iter().any(|s| s.action == "read"));
        assert!(plan.steps.iter().any(|s| s.action == "write"));
    }

    #[test]
    fn test_plan_parser_target_extraction() {
        let parser = PlanParser::new();
        
        let text = r#"I need to read "/data/config.json" and then delete /tmp/cache"#;
        let plan = parser.parse(text);
        
        // Check that targets were extracted
        let targets: Vec<_> = plan.steps.iter()
            .filter_map(|s| s.target.as_ref())
            .collect();
        
        assert!(targets.iter().any(|t| t.contains("config.json")));
    }

    #[tokio::test]
    async fn test_hybrid_loop_basic() {
        let config = HybridLoopConfig::lenient();
        let safety_engine = SafetyEngine::new();
        let prm = Arc::new(MockPrm::new(0.8, 0.9));

        let mut hybrid = HybridLoop::new(config, safety_engine, prm);

        let result = hybrid.execute_cycle("I will read the documentation").await;
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert!(result.prm_score.is_some());
    }

    #[tokio::test]
    async fn test_hybrid_loop_low_prm() {
        let config = HybridLoopConfig::strict();
        let safety_engine = SafetyEngine::new();
        let prm = Arc::new(MockPrm::new(0.5, 0.9)); // Low score

        let mut hybrid = HybridLoop::new(config, safety_engine, prm);

        let result = hybrid.execute_cycle("Some questionable plan").await;
        assert!(matches!(result, Err(HybridLoopError::LowPrmScore { .. })));
    }

    #[test]
    fn test_cycle_result() {
        let result = CycleResult::new("test plan", 1);
        assert!(!result.is_valid());
        assert!(result.violations().is_empty());
    }

    #[test]
    fn test_config_variants() {
        let strict = HybridLoopConfig::strict();
        let lenient = HybridLoopConfig::lenient();

        assert!(strict.min_prm_score > lenient.min_prm_score);
        assert!(strict.strict_safety);
        assert!(!lenient.strict_safety);
    }
}
