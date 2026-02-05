//! Neuro-Symbolic Hybrid Reasoning Loop (NSR-006)

use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::llm::{CompletionRequest, LlmProvider, Message};
use crate::reasoner::datalog::{SafetyRules, SafetyVerdict, Violation};

#[derive(Debug, Error)]
pub enum HybridError {
    #[error("LLM error: {0}")]
    LlmError(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Execution error: {0}")]
    ExecutionError(String),
    #[error("Maximum iterations ({0}) exceeded")]
    MaxIterationsExceeded(usize),
    #[error("Plan rejected: {0}")]
    PlanRejected(String),
}

pub type HybridResult<T> = Result<T, HybridError>;

#[derive(Debug, Clone)]
pub struct HybridConfig {
    pub max_iterations: usize,
    pub iteration_timeout: Duration,
    pub planning_model: String,
    pub planning_temperature: f32,
    pub max_plan_tokens: usize,
    pub include_violations_in_prompt: bool,
    pub verbose_logging: bool,
}

impl Default for HybridConfig {
    fn default() -> Self {
        Self { max_iterations: 5, iteration_timeout: Duration::from_secs(30), planning_model: "gpt-4".to_string(), planning_temperature: 0.3, max_plan_tokens: 1024, include_violations_in_prompt: true, verbose_logging: true }
    }
}

impl HybridConfig {
    pub fn with_max_iterations(mut self, max: usize) -> Self { self.max_iterations = max; self }
    pub fn with_model(mut self, model: impl Into<String>) -> Self { self.planning_model = model.into(); self }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanAction {
    pub action: String,
    pub target: String,
    pub parameters: serde_json::Value,
    pub reasoning: Option<String>,
    pub risk_level: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPlan {
    pub id: String,
    pub description: String,
    pub actions: Vec<PlanAction>,
    pub reasoning: String,
    pub expected_outcome: String,
}

impl ExecutionPlan {
    pub fn new(description: impl Into<String>) -> Self {
        Self { id: uuid::Uuid::now_v7().to_string(), description: description.into(), actions: Vec::new(), reasoning: String::new(), expected_outcome: String::new() }
    }
    pub fn with_action(mut self, action: PlanAction) -> Self { self.actions.push(action); self }
    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self { self.reasoning = reasoning.into(); self }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoopIteration {
    pub iteration: usize,
    pub plan: ExecutionPlan,
    pub validation: ValidationOutcome,
    pub success: bool,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationOutcome {
    pub passed: bool,
    pub verdict: SafetyVerdict,
    pub violations: Vec<Violation>,
    pub refinements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub plan: ExecutionPlan,
    pub action_results: Vec<ActionResult>,
    pub success: bool,
    pub error: Option<String>,
    pub observations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    pub action: PlanAction,
    pub success: bool,
    pub output: serde_json::Value,
    pub error: Option<String>,
}

pub struct HybridReasoningLoop<L: LlmProvider> {
    llm: Arc<L>,
    safety_rules: SafetyRules,
    config: HybridConfig,
    history: Vec<LoopIteration>,
}

impl<L: LlmProvider> HybridReasoningLoop<L> {
    pub fn new(llm: Arc<L>, safety_rules: SafetyRules, config: HybridConfig) -> Self {
        Self { llm, safety_rules, config, history: Vec::new() }
    }

    pub fn with_defaults(llm: Arc<L>) -> Self {
        Self::new(llm, SafetyRules::new(), HybridConfig::default())
    }

    pub async fn run(&mut self, task: &str, context: &serde_json::Value) -> HybridResult<ExecutionResult> {
        info!(task = %task, "Starting hybrid reasoning loop");
        let mut last_violations: Vec<Violation> = Vec::new();
        
        for iteration in 0..self.config.max_iterations {
            let start = std::time::Instant::now();
            if self.config.verbose_logging { debug!(iteration = iteration, "Beginning iteration"); }

            let plan = self.neural_phase(task, context, &last_violations).await?;
            if self.config.verbose_logging { debug!(iteration = iteration, actions = plan.actions.len(), "Plan generated"); }

            let validation = self.symbolic_phase(&plan)?;
            let iteration_result = LoopIteration { iteration, plan: plan.clone(), validation: validation.clone(), success: validation.passed, duration_ms: start.elapsed().as_millis() as u64 };
            self.history.push(iteration_result);

            if validation.passed {
                info!(iteration = iteration, "Plan validated, executing");
                return self.execution_phase(&plan).await;
            } else {
                warn!(iteration = iteration, violations = validation.violations.len(), "Plan rejected");
                last_violations = validation.violations;
            }
        }
        Err(HybridError::MaxIterationsExceeded(self.config.max_iterations))
    }

    async fn neural_phase(&self, task: &str, context: &serde_json::Value, previous_violations: &[Violation]) -> HybridResult<ExecutionPlan> {
        let system_prompt = self.build_system_prompt();
        let user_prompt = self.build_user_prompt(task, context, previous_violations);

        let request = CompletionRequest::new(&self.config.planning_model)
            .with_message(Message::system(&system_prompt))
            .with_message(Message::user(&user_prompt))
            .with_temperature(self.config.planning_temperature)
            .with_max_tokens(self.config.max_plan_tokens);

        let response = self.llm.complete(request).await.map_err(|e| HybridError::LlmError(e.to_string()))?;
        self.parse_plan(&response.content)
    }

    fn symbolic_phase(&self, plan: &ExecutionPlan) -> HybridResult<ValidationOutcome> {
        let mut all_violations = Vec::new();
        let mut refinements = Vec::new();

        for action in &plan.actions {
            let facts = self.action_to_facts(action);
            let verdict = self.safety_rules.evaluate(&facts);
            if !verdict.safe {
                all_violations.extend(verdict.violations.clone());
                for v in &verdict.violations {
                    refinements.push(format!("Violation of {}: {}", v.rule_name, v.message));
                }
            }
        }

        let passed = all_violations.is_empty();
        Ok(ValidationOutcome { passed, verdict: SafetyVerdict { safe: passed, violations: all_violations.clone(), risk_score: if passed { 0.0 } else { 0.8 } }, violations: all_violations, refinements })
    }

    async fn execution_phase(&self, plan: &ExecutionPlan) -> HybridResult<ExecutionResult> {
        let mut action_results = Vec::new();
        let mut observations = Vec::new();

        for action in &plan.actions {
            let result = ActionResult { action: action.clone(), success: true, output: serde_json::json!({"status": "simulated"}), error: None };
            if let Some(obs) = result.output.get("observation").and_then(|o| o.as_str()) { observations.push(obs.to_string()); }
            action_results.push(result);
        }
        Ok(ExecutionResult { plan: plan.clone(), action_results, success: true, error: None, observations })
    }

    fn build_system_prompt(&self) -> String {
        r#"You are a planning agent. Output JSON: {"description": "...", "actions": [{"action": "...", "target": "...", "parameters": {...}}], "reasoning": "...", "expected_outcome": "..."}"#.to_string()
    }

    fn build_user_prompt(&self, task: &str, context: &serde_json::Value, previous_violations: &[Violation]) -> String {
        let mut prompt = format!("Task: {}\nContext: {}\n", task, context);
        if !previous_violations.is_empty() && self.config.include_violations_in_prompt {
            prompt.push_str("\nPrevious violations:\n");
            for v in previous_violations { prompt.push_str(&format!("- {}: {}\n", v.rule_name, v.message)); }
        }
        prompt
    }

    fn parse_plan(&self, response: &str) -> HybridResult<ExecutionPlan> {
        let json_str = if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') { &response[start..=end] } else { response }
        } else { response };

        let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| HybridError::LlmError(format!("Parse error: {}", e)))?;
        let mut plan = ExecutionPlan::new(parsed.get("description").and_then(|d| d.as_str()).unwrap_or("Plan"));

        if let Some(actions) = parsed.get("actions").and_then(|a| a.as_array()) {
            for a in actions {
                plan.actions.push(PlanAction {
                    action: a.get("action").and_then(|x| x.as_str()).unwrap_or("unknown").to_string(),
                    target: a.get("target").and_then(|x| x.as_str()).unwrap_or("").to_string(),
                    parameters: a.get("parameters").cloned().unwrap_or(serde_json::json!({})),
                    reasoning: a.get("reasoning").and_then(|x| x.as_str()).map(String::from),
                    risk_level: None,
                });
            }
        }
        if let Some(r) = parsed.get("reasoning").and_then(|x| x.as_str()) { plan.reasoning = r.to_string(); }
        Ok(plan)
    }

    fn action_to_facts(&self, action: &PlanAction) -> Vec<String> {
        vec![format!("Action(agent, \"{}\", \"{}\").", action.action, action.target)]
    }

    pub fn history(&self) -> &[LoopIteration] { &self.history }
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
