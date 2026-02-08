//! Neuro-Symbolic Hybrid Reasoning Loop (NSR-006)
//!
//! This module implements a hybrid reasoning loop that combines:
//! - Neural phase: LLM-based planning
//! - Symbolic phase: Safety rule validation via Datalog
//! - Execution phase: Validated action execution
//!
//! The loop iterates until a valid plan is found or max iterations exceeded.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::llm::{CompletionRequest, LlmProvider, Message};
use crate::reasoner::datalog::{SafetyEngine, SafetyVerdict, Violation};

/// Errors that can occur during hybrid reasoning
#[derive(Debug, Error)]
pub enum HybridError {
    /// Error from the LLM provider
    #[error("LLM error: {0}")]
    LlmError(String),
    /// Error during validation phase
    #[error("Validation error: {0}")]
    ValidationError(String),
    /// Error during execution phase
    #[error("Execution error: {0}")]
    ExecutionError(String),
    /// Maximum iterations exceeded without finding valid plan
    #[error("Maximum iterations ({0}) exceeded")]
    MaxIterationsExceeded(usize),
    /// Plan was rejected by safety rules
    #[error("Plan rejected: {0}")]
    PlanRejected(String),
}

/// Result type for hybrid reasoning operations
pub type HybridResult<T> = Result<T, HybridError>;

/// Configuration for the hybrid reasoning loop
#[derive(Debug, Clone)]
pub struct HybridConfig {
    /// Maximum number of planning iterations
    pub max_iterations: usize,
    /// Timeout for each iteration
    pub iteration_timeout: Duration,
    /// Model to use for planning
    pub planning_model: String,
    /// Temperature for planning model
    pub planning_temperature: f32,
    /// Maximum tokens for plan generation
    pub max_plan_tokens: usize,
    /// Whether to include previous violations in prompts
    pub include_violations_in_prompt: bool,
    /// Whether to enable verbose logging
    pub verbose_logging: bool,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self {
            max_iterations: 5,
            iteration_timeout: Duration::from_secs(30),
            planning_model: "gpt-4".to_string(),
            planning_temperature: 0.3,
            max_plan_tokens: 1024,
            include_violations_in_prompt: true,
            verbose_logging: true,
        }
    }
}

impl HybridConfig {
    /// Set maximum iterations
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// Set planning model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.planning_model = model.into();
        self
    }
}

/// A single action in a plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanAction {
    /// The action type (e.g., "read_file", "execute_tool")
    pub action: String,
    /// The target of the action (e.g., file path, endpoint)
    pub target: String,
    /// Parameters for the action
    pub parameters: serde_json::Value,
    /// Optional reasoning for this action
    pub reasoning: Option<String>,
    /// Optional risk level assessment
    pub risk_level: Option<String>,
}

/// An execution plan consisting of multiple actions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    /// Unique plan identifier
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Ordered list of actions to execute
    pub actions: Vec<PlanAction>,
    /// Overall reasoning for the plan
    pub reasoning: String,
    /// Expected outcome of the plan
    pub expected_outcome: String,
}

impl ExecutionPlan {
    /// Create a new execution plan
    pub fn new(description: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::now_v7().to_string(),
            description: description.into(),
            actions: Vec::new(),
            reasoning: String::new(),
            expected_outcome: String::new(),
        }
    }

    /// Add an action to the plan
    pub fn with_action(mut self, action: PlanAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Set the reasoning for the plan
    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = reasoning.into();
        self
    }
}

/// Record of a single loop iteration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopIteration {
    /// Iteration number (0-indexed)
    pub iteration: usize,
    /// The plan generated in this iteration
    pub plan: ExecutionPlan,
    /// Validation outcome
    pub validation: ValidationOutcome,
    /// Whether this iteration succeeded
    pub success: bool,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Outcome of the validation (symbolic) phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationOutcome {
    /// Whether the plan passed validation
    pub passed: bool,
    /// The safety verdict
    pub verdict: SafetyVerdict,
    /// List of violations found
    pub violations: Vec<Violation>,
    /// Suggested refinements for the plan
    pub refinements: Vec<String>,
}

/// Result of executing a plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// The executed plan
    pub plan: ExecutionPlan,
    /// Results for each action
    pub action_results: Vec<ActionResult>,
    /// Overall success status
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Observations from execution
    pub observations: Vec<String>,
}

/// Result of executing a single action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// The action that was executed
    pub action: PlanAction,
    /// Whether the action succeeded
    pub success: bool,
    /// Output from the action
    pub output: serde_json::Value,
    /// Error message if failed
    pub error: Option<String>,
}

/// The hybrid neuro-symbolic reasoning loop
pub struct HybridReasoningLoop<L: LlmProvider> {
    /// LLM provider for neural phase
    llm: Arc<L>,
    /// Safety engine for symbolic phase
    safety_engine: SafetyEngine,
    /// Configuration
    config: HybridConfig,
    /// History of iterations
    history: Vec<LoopIteration>,
}

impl<L: LlmProvider> HybridReasoningLoop<L> {
    /// Create a new hybrid reasoning loop
    pub fn new(llm: Arc<L>, safety_engine: SafetyEngine, config: HybridConfig) -> Self {
        Self {
            llm,
            safety_engine,
            config,
            history: Vec::new(),
        }
    }

    /// Create with default configuration
    pub fn with_defaults(llm: Arc<L>) -> Self {
        Self::new(llm, SafetyEngine::new(), HybridConfig::default())
    }

    /// Run the hybrid reasoning loop
    pub async fn run(
        &mut self,
        task: &str,
        context: &serde_json::Value,
    ) -> HybridResult<ExecutionResult> {
        info!(task = %task, "Starting hybrid reasoning loop");
        let mut last_violations: Vec<Violation> = Vec::new();

        for iteration in 0..self.config.max_iterations {
            let start = std::time::Instant::now();
            if self.config.verbose_logging {
                debug!(iteration = iteration, "Beginning iteration");
            }

            // Neural phase: Generate plan using LLM
            let plan = self.neural_phase(task, context, &last_violations).await?;
            if self.config.verbose_logging {
                debug!(
                    iteration = iteration,
                    actions = plan.actions.len(),
                    "Plan generated"
                );
            }

            // Symbolic phase: Validate plan using safety rules
            let validation = self.symbolic_phase(&plan)?;
            let iteration_result = LoopIteration {
                iteration,
                plan: plan.clone(),
                validation: validation.clone(),
                success: validation.passed,
                duration_ms: start.elapsed().as_millis() as u64,
            };
            self.history.push(iteration_result);

            if validation.passed {
                info!(iteration = iteration, "Plan validated, executing");
                return self.execution_phase(&plan).await;
            } else {
                warn!(
                    iteration = iteration,
                    violations = validation.violations.len(),
                    "Plan rejected"
                );
                last_violations = validation.violations;
            }
        }

        Err(HybridError::MaxIterationsExceeded(
            self.config.max_iterations,
        ))
    }

    /// Neural phase: Generate a plan using the LLM
    async fn neural_phase(
        &self,
        task: &str,
        context: &serde_json::Value,
        previous_violations: &[Violation],
    ) -> HybridResult<ExecutionPlan> {
        let system_prompt = self.build_system_prompt();
        let user_prompt = self.build_user_prompt(task, context, previous_violations);

        let request = CompletionRequest::new(&self.config.planning_model)
            .with_message(Message::system(&system_prompt))
            .with_message(Message::user(&user_prompt))
            .with_temperature(self.config.planning_temperature)
            .with_max_tokens(self.config.max_plan_tokens);

        let response = self
            .llm
            .complete(request)
            .await
            .map_err(|e| HybridError::LlmError(e.to_string()))?;

        self.parse_plan(&response.content)
    }

    /// Symbolic phase: Validate plan using safety rules
    fn symbolic_phase(&mut self, plan: &ExecutionPlan) -> HybridResult<ValidationOutcome> {
        let mut all_violations = Vec::new();
        let mut refinements = Vec::new();

        for action in &plan.actions {
            // Check each action against safety rules
            let verdict = self
                .safety_engine
                .check_action(&action.action, &action.target);

            if let SafetyVerdict::Violation(violations) = &verdict {
                for v in violations {
                    all_violations.push(v.clone());
                    refinements.push(format!("Violation of {}: {}", v.rule_id, v.description));
                }
            }
        }

        let passed = all_violations.is_empty();
        let verdict = if passed {
            SafetyVerdict::Safe
        } else {
            SafetyVerdict::Violation(all_violations.clone())
        };

        Ok(ValidationOutcome {
            passed,
            verdict,
            violations: all_violations,
            refinements,
        })
    }

    /// Execution phase: Execute the validated plan
    async fn execution_phase(&self, plan: &ExecutionPlan) -> HybridResult<ExecutionResult> {
        let mut action_results = Vec::new();
        let mut observations = Vec::new();

        for action in &plan.actions {
            // In a real implementation, this would execute the action
            // For now, we simulate successful execution
            let result = ActionResult {
                action: action.clone(),
                success: true,
                output: serde_json::json!({"status": "simulated"}),
                error: None,
            };

            if let Some(obs) = result.output.get("observation").and_then(|o| o.as_str()) {
                observations.push(obs.to_string());
            }
            action_results.push(result);
        }

        Ok(ExecutionResult {
            plan: plan.clone(),
            action_results,
            success: true,
            error: None,
            observations,
        })
    }

    /// Build the system prompt for planning
    fn build_system_prompt(&self) -> String {
        r#"You are a planning agent. Output JSON: {"description": "...", "actions": [{"action": "...", "target": "...", "parameters": {...}}], "reasoning": "...", "expected_outcome": "..."}"#.to_string()
    }

    /// Build the user prompt including task and context
    fn build_user_prompt(
        &self,
        task: &str,
        context: &serde_json::Value,
        previous_violations: &[Violation],
    ) -> String {
        let mut prompt = format!("Task: {}\nContext: {}\n", task, context);

        if !previous_violations.is_empty() && self.config.include_violations_in_prompt {
            prompt.push_str("\nPrevious violations:\n");
            for v in previous_violations {
                prompt.push_str(&format!("- {}: {}\n", v.rule_id, v.description));
            }
        }
        prompt
    }

    /// Parse a plan from LLM response
    fn parse_plan(&self, response: &str) -> HybridResult<ExecutionPlan> {
        let json_str = if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                &response[start..=end]
            } else {
                response
            }
        } else {
            response
        };

        let parsed: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| HybridError::LlmError(format!("Parse error: {}", e)))?;

        let mut plan = ExecutionPlan::new(
            parsed
                .get("description")
                .and_then(|d| d.as_str())
                .unwrap_or("Plan"),
        );

        if let Some(actions) = parsed.get("actions").and_then(|a| a.as_array()) {
            for a in actions {
                plan.actions.push(PlanAction {
                    action: a
                        .get("action")
                        .and_then(|x| x.as_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    target: a
                        .get("target")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    parameters: a
                        .get("parameters")
                        .cloned()
                        .unwrap_or(serde_json::json!({})),
                    reasoning: a
                        .get("reasoning")
                        .and_then(|x| x.as_str())
                        .map(String::from),
                    risk_level: None,
                });
            }
        }

        if let Some(r) = parsed.get("reasoning").and_then(|x| x.as_str()) {
            plan.reasoning = r.to_string();
        }

        Ok(plan)
    }

    /// Get the history of iterations
    pub fn history(&self) -> &[LoopIteration] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::MockLlmProvider;

    #[tokio::test]
    async fn test_hybrid_loop() {
        let plan_json = r#"{"description": "Test", "actions": [{"action": "read", "target": "/data/file.txt", "parameters": {}}], "reasoning": "Test", "expected_outcome": "Success"}"#;
        let llm = Arc::new(MockLlmProvider::always(plan_json));
        let mut loop_ = HybridReasoningLoop::with_defaults(llm);
        let result = loop_.run("Read a file", &serde_json::json!({})).await;
        assert!(result.is_ok());
    }
}
