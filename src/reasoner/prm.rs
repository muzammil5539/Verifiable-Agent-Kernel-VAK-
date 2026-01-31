//! Process Reward Model (PRM) implementation
//!
//! This module provides the core PRM functionality for scoring reasoning steps
//! and trajectories. The PRM uses an LLM to evaluate the quality and correctness
//! of each step in a reasoning chain.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;

use crate::llm::{CompletionRequest, LlmError, LlmProvider, Message};

/// Errors that can occur during PRM operations
#[derive(Debug, Error)]
pub enum PrmError {
    /// Error from the underlying LLM provider
    #[error("LLM error: {0}")]
    LlmError(#[from] LlmError),

    /// Failed to parse the LLM response into a score
    #[error("Failed to parse score from LLM response: {0}")]
    ParseError(String),

    /// Invalid score value (not in range 0.0-1.0)
    #[error("Invalid score value: {0} (must be between 0.0 and 1.0)")]
    InvalidScore(f64),

    /// Invalid confidence value (not in range 0.0-1.0)
    #[error("Invalid confidence value: {0} (must be between 0.0 and 1.0)")]
    InvalidConfidence(f64),

    /// Empty reasoning trajectory provided
    #[error("Empty reasoning trajectory provided")]
    EmptyTrajectory,

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// A score for a single reasoning step
///
/// Contains the numeric score, a confidence measure, and the reasoning
/// behind the score assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThoughtScore {
    /// Score value between 0.0 (incorrect/poor) and 1.0 (correct/excellent)
    pub score: f64,

    /// Confidence in the score assignment (0.0 to 1.0)
    pub confidence: f64,

    /// Explanation of why this score was assigned
    pub reasoning: String,
}

impl ThoughtScore {
    /// Create a new ThoughtScore with validation
    ///
    /// # Arguments
    /// * `score` - Score value (0.0 to 1.0)
    /// * `confidence` - Confidence in the score (0.0 to 1.0)
    /// * `reasoning` - Explanation for the score
    ///
    /// # Returns
    /// * `Ok(ThoughtScore)` - Valid score
    /// * `Err(PrmError)` - If score or confidence is out of range
    pub fn new(
        score: f64,
        confidence: f64,
        reasoning: impl Into<String>,
    ) -> Result<Self, PrmError> {
        if !(0.0..=1.0).contains(&score) {
            return Err(PrmError::InvalidScore(score));
        }
        if !(0.0..=1.0).contains(&confidence) {
            return Err(PrmError::InvalidConfidence(confidence));
        }

        Ok(Self {
            score,
            confidence,
            reasoning: reasoning.into(),
        })
    }

    /// Create a ThoughtScore without validation (for internal use)
    ///
    /// # Safety
    /// Caller must ensure score and confidence are in valid ranges
    pub(crate) fn new_unchecked(score: f64, confidence: f64, reasoning: String) -> Self {
        Self {
            score: score.clamp(0.0, 1.0),
            confidence: confidence.clamp(0.0, 1.0),
            reasoning,
        }
    }

    /// Check if this score indicates a high-quality step
    pub fn is_good(&self, threshold: f64) -> bool {
        self.score >= threshold
    }

    /// Check if this score indicates a low-quality step that may need revision
    pub fn is_poor(&self, threshold: f64) -> bool {
        self.score < threshold
    }

    /// Get the weighted score (score * confidence)
    pub fn weighted_score(&self) -> f64 {
        self.score * self.confidence
    }
}

impl Default for ThoughtScore {
    fn default() -> Self {
        Self {
            score: 0.5,
            confidence: 0.5,
            reasoning: String::new(),
        }
    }
}

impl fmt::Display for ThoughtScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Score: {:.2} (confidence: {:.2}) - {}",
            self.score, self.confidence, self.reasoning
        )
    }
}

/// Aggregate score for a complete reasoning trajectory
///
/// Contains the overall score, individual step scores, and reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrajectoryScore {
    /// Overall score for the trajectory (0.0-1.0)
    pub overall_score: f64,
    /// Individual step scores
    pub step_scores: Vec<ThoughtScore>,
    /// Reasoning for the overall score
    pub reasoning: String,
}

impl TrajectoryScore {
    /// Create a new trajectory score
    pub fn new(overall_score: f64, step_scores: Vec<ThoughtScore>, reasoning: impl Into<String>) -> Self {
        Self {
            overall_score,
            step_scores,
            reasoning: reasoning.into(),
        }
    }
}

/// Alternative trait for PRM scoring (compatibility alias for prm_gating)
///
/// This trait provides an alternative interface for PRM scoring that takes
/// history instead of context, for use with the gating module.
#[async_trait]
pub trait PrmScorer: Send + Sync {
    /// Score a single reasoning step given history
    async fn score_step(
        &self,
        step: &ReasoningStep,
        history: &[ReasoningStep],
    ) -> Result<ThoughtScore, PrmError>;

    /// Score a complete reasoning trajectory
    async fn score_trajectory(
        &self,
        steps: &[ReasoningStep],
    ) -> Result<TrajectoryScore, PrmError>;
}

/// A single step in a reasoning chain
///
/// Represents the thought, action, and observation at each step of
/// chain-of-thought reasoning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningStep {
    /// Step number in the sequence (1-indexed)
    pub step_number: usize,

    /// The thought/reasoning at this step
    pub thought: String,

    /// The action taken (if any)
    pub action: Option<String>,

    /// The observation/result from the action (if any)
    pub observation: Option<String>,

    /// Optional metadata for the step
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl ReasoningStep {
    /// Create a new reasoning step
    ///
    /// # Arguments
    /// * `step_number` - The step number (1-indexed)
    /// * `thought` - The reasoning/thought at this step
    pub fn new(step_number: usize, thought: impl Into<String>) -> Self {
        Self {
            step_number,
            thought: thought.into(),
            action: None,
            observation: None,
            metadata: None,
        }
    }

    /// Add an action to this step
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Add an observation to this step
    pub fn with_observation(mut self, observation: impl Into<String>) -> Self {
        self.observation = Some(observation.into());
        self
    }

    /// Add metadata to this step
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Format this step for display in prompts
    pub fn format_for_prompt(&self) -> String {
        let mut output = format!("Step {}: {}", self.step_number, self.thought);

        if let Some(ref action) = self.action {
            output.push_str(&format!("\nAction: {}", action));
        }

        if let Some(ref observation) = self.observation {
            output.push_str(&format!("\nObservation: {}", observation));
        }

        output
    }
}

impl fmt::Display for ReasoningStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_for_prompt())
    }
}

/// Configuration for the Process Reward Model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrmConfig {
    /// Model name to use for scoring
    pub model: String,

    /// System prompt for the scoring LLM
    pub system_prompt: String,

    /// Template for scoring individual steps
    /// Placeholders: {context}, {step}, {step_number}
    pub step_scoring_template: String,

    /// Template for scoring trajectories
    /// Placeholders: {context}, {trajectory}
    pub trajectory_scoring_template: String,

    /// Default threshold for backtracking decisions
    pub backtrack_threshold: f64,

    /// Temperature for LLM scoring (lower = more deterministic)
    pub temperature: f32,

    /// Maximum tokens for scoring response
    pub max_tokens: usize,
}

impl PrmConfig {
    /// Create a new PRM configuration
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            ..Default::default()
        }
    }

    /// Set the system prompt
    pub fn with_system_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.system_prompt = prompt.into();
        self
    }

    /// Set the step scoring template
    pub fn with_step_template(mut self, template: impl Into<String>) -> Self {
        self.step_scoring_template = template.into();
        self
    }

    /// Set the trajectory scoring template
    pub fn with_trajectory_template(mut self, template: impl Into<String>) -> Self {
        self.trajectory_scoring_template = template.into();
        self
    }

    /// Set the backtrack threshold
    pub fn with_backtrack_threshold(mut self, threshold: f64) -> Self {
        self.backtrack_threshold = threshold;
        self
    }

    /// Set the temperature
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature;
        self
    }

    /// Set the max tokens
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = max_tokens;
        self
    }
}

impl Default for PrmConfig {
    fn default() -> Self {
        Self {
            model: "gpt-4".to_string(),
            system_prompt: DEFAULT_SYSTEM_PROMPT.to_string(),
            step_scoring_template: DEFAULT_STEP_TEMPLATE.to_string(),
            trajectory_scoring_template: DEFAULT_TRAJECTORY_TEMPLATE.to_string(),
            backtrack_threshold: 0.5,
            temperature: 0.1,
            max_tokens: 512,
        }
    }
}

/// Default system prompt for PRM scoring
const DEFAULT_SYSTEM_PROMPT: &str = r#"You are a Process Reward Model (PRM) that evaluates reasoning steps.

Your task is to score each reasoning step on:
1. Logical correctness - Is the reasoning valid?
2. Relevance - Does this step help solve the problem?
3. Progress - Does this step move toward the solution?

Respond in the following JSON format:
{
    "score": <float between 0.0 and 1.0>,
    "confidence": <float between 0.0 and 1.0>,
    "reasoning": "<brief explanation>"
}

Score guidelines:
- 1.0: Perfect step, logically sound and highly relevant
- 0.8-0.9: Good step with minor issues
- 0.6-0.7: Acceptable but could be improved
- 0.4-0.5: Questionable step, may lead to errors
- 0.2-0.3: Likely incorrect or irrelevant
- 0.0-0.1: Clearly wrong or harmful to the solution"#;

/// Default template for scoring individual steps
const DEFAULT_STEP_TEMPLATE: &str = r#"Context/Problem: {context}

Evaluate the following reasoning step:

{step}

This is step {step_number} in the reasoning chain.

Provide your evaluation as JSON with score, confidence, and reasoning."#;

/// Default template for scoring trajectories
const DEFAULT_TRAJECTORY_TEMPLATE: &str = r#"Context/Problem: {context}

Evaluate the following complete reasoning trajectory:

{trajectory}

For each step, provide your evaluation. Respond with a JSON array where each element has:
- step_number: the step being evaluated
- score: float between 0.0 and 1.0
- confidence: float between 0.0 and 1.0
- reasoning: brief explanation"#;

/// Trait for Process Reward Models
///
/// Defines the interface for scoring reasoning steps and trajectories.
/// Implementations can use LLMs, learned models, or rule-based approaches.
#[async_trait]
pub trait ProcessRewardModel: Send + Sync {
    /// Score a single reasoning step
    ///
    /// # Arguments
    /// * `step` - The reasoning step to score
    /// * `context` - The problem/task context
    ///
    /// # Returns
    /// * `Ok(ThoughtScore)` - The score for this step
    /// * `Err(PrmError)` - If scoring failed
    async fn score_step(
        &self,
        step: &ReasoningStep,
        context: &str,
    ) -> Result<ThoughtScore, PrmError>;

    /// Score a complete reasoning trajectory
    ///
    /// # Arguments
    /// * `steps` - The reasoning steps to score
    /// * `context` - The problem/task context
    ///
    /// # Returns
    /// * `Ok(Vec<ThoughtScore>)` - Scores for each step
    /// * `Err(PrmError)` - If scoring failed
    async fn score_trajectory(
        &self,
        steps: &[ReasoningStep],
        context: &str,
    ) -> Result<Vec<ThoughtScore>, PrmError>;

    /// Determine if backtracking is recommended based on a score
    ///
    /// # Arguments
    /// * `score` - The score to evaluate
    /// * `threshold` - The minimum acceptable score
    ///
    /// # Returns
    /// `true` if the score is below threshold and backtracking is recommended
    fn should_backtrack(&self, score: &ThoughtScore, threshold: f64) -> bool;
}

/// LLM-based Process Reward Model implementation
///
/// Uses an LLM provider to score reasoning steps by prompting the model
/// to evaluate the quality and correctness of each step.
#[derive(Debug)]
pub struct LlmPrm<P: LlmProvider> {
    /// The LLM provider to use for scoring
    provider: Arc<P>,

    /// Configuration for the PRM
    config: PrmConfig,
}

impl<P: LlmProvider> LlmPrm<P> {
    /// Create a new LLM-based PRM
    ///
    /// # Arguments
    /// * `provider` - The LLM provider to use for scoring
    /// * `config` - Configuration for the PRM
    pub fn new(provider: Arc<P>, config: PrmConfig) -> Self {
        Self { provider, config }
    }

    /// Create a new LLM-based PRM with default configuration
    pub fn with_defaults(provider: Arc<P>) -> Self {
        Self::new(provider, PrmConfig::default())
    }

    /// Get the configuration
    pub fn config(&self) -> &PrmConfig {
        &self.config
    }

    /// Update the configuration
    pub fn set_config(&mut self, config: PrmConfig) {
        self.config = config;
    }

    /// Build the prompt for scoring a single step
    fn build_step_prompt(&self, step: &ReasoningStep, context: &str) -> String {
        self.config
            .step_scoring_template
            .replace("{context}", context)
            .replace("{step}", &step.format_for_prompt())
            .replace("{step_number}", &step.step_number.to_string())
    }

    /// Build the prompt for scoring a trajectory
    fn build_trajectory_prompt(&self, steps: &[ReasoningStep], context: &str) -> String {
        let trajectory = steps
            .iter()
            .map(|s| s.format_for_prompt())
            .collect::<Vec<_>>()
            .join("\n\n");

        self.config
            .trajectory_scoring_template
            .replace("{context}", context)
            .replace("{trajectory}", &trajectory)
    }

    /// Parse a score response from the LLM
    fn parse_score_response(&self, response: &str) -> Result<ThoughtScore, PrmError> {
        // Try to parse as JSON first
        if let Ok(parsed) = serde_json::from_str::<ScoreResponse>(response) {
            return ThoughtScore::new(parsed.score, parsed.confidence, parsed.reasoning);
        }

        // Try to extract JSON from the response (LLM might include extra text)
        if let Some(json_start) = response.find('{') {
            if let Some(json_end) = response.rfind('}') {
                let json_str = &response[json_start..=json_end];
                if let Ok(parsed) = serde_json::from_str::<ScoreResponse>(json_str) {
                    return ThoughtScore::new(parsed.score, parsed.confidence, parsed.reasoning);
                }
            }
        }

        // Fallback: try to extract numbers from the response
        self.parse_score_fallback(response)
    }

    /// Fallback parser when JSON parsing fails
    fn parse_score_fallback(&self, response: &str) -> Result<ThoughtScore, PrmError> {
        // Look for patterns like "score: 0.8" or "Score: 0.8"
        let score = self
            .extract_number(response, &["score:", "Score:"])
            .ok_or_else(|| PrmError::ParseError("Could not find score in response".to_string()))?;

        let confidence = self
            .extract_number(response, &["confidence:", "Confidence:"])
            .unwrap_or(0.7); // Default confidence if not found

        ThoughtScore::new(score, confidence, response.to_string())
    }

    /// Extract a number following one of the given prefixes
    fn extract_number(&self, text: &str, prefixes: &[&str]) -> Option<f64> {
        for prefix in prefixes {
            if let Some(idx) = text.to_lowercase().find(&prefix.to_lowercase()) {
                let start = idx + prefix.len();
                let remaining = &text[start..];
                // Find the number
                let num_str: String = remaining
                    .chars()
                    .skip_while(|c| c.is_whitespace())
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if let Ok(num) = num_str.parse::<f64>() {
                    return Some(num.clamp(0.0, 1.0));
                }
            }
        }
        None
    }

    /// Parse trajectory scores from LLM response
    fn parse_trajectory_response(
        &self,
        response: &str,
        expected_count: usize,
    ) -> Result<Vec<ThoughtScore>, PrmError> {
        // Try to parse as JSON array
        if let Ok(parsed) = serde_json::from_str::<Vec<ScoreResponse>>(response) {
            return parsed
                .into_iter()
                .map(|r| ThoughtScore::new(r.score, r.confidence, r.reasoning))
                .collect();
        }

        // Try to extract JSON array from response
        if let Some(arr_start) = response.find('[') {
            if let Some(arr_end) = response.rfind(']') {
                let json_str = &response[arr_start..=arr_end];
                if let Ok(parsed) = serde_json::from_str::<Vec<ScoreResponse>>(json_str) {
                    return parsed
                        .into_iter()
                        .map(|r| ThoughtScore::new(r.score, r.confidence, r.reasoning))
                        .collect();
                }
            }
        }

        // Fallback: return default scores with a warning
        tracing::warn!(
            "Could not parse trajectory scores from LLM response, using defaults. Response: {}",
            &response[..response.len().min(200)]
        );

        Ok((0..expected_count)
            .map(|i| {
                ThoughtScore::new_unchecked(
                    0.5,
                    0.3,
                    format!("Failed to parse score for step {}", i + 1),
                )
            })
            .collect())
    }
}

/// Internal struct for parsing LLM score responses
#[derive(Debug, Deserialize)]
struct ScoreResponse {
    score: f64,
    confidence: f64,
    reasoning: String,
}

#[async_trait]
impl<P: LlmProvider + 'static> ProcessRewardModel for LlmPrm<P> {
    async fn score_step(
        &self,
        step: &ReasoningStep,
        context: &str,
    ) -> Result<ThoughtScore, PrmError> {
        let prompt = self.build_step_prompt(step, context);

        let request = CompletionRequest::new(&self.config.model)
            .with_message(Message::system(&self.config.system_prompt))
            .with_message(Message::user(prompt))
            .with_temperature(self.config.temperature)
            .with_max_tokens(self.config.max_tokens);

        let response = self.provider.complete(request).await?;

        self.parse_score_response(&response.content)
    }

    async fn score_trajectory(
        &self,
        steps: &[ReasoningStep],
        context: &str,
    ) -> Result<Vec<ThoughtScore>, PrmError> {
        if steps.is_empty() {
            return Err(PrmError::EmptyTrajectory);
        }

        // For small trajectories, score each step individually for better accuracy
        if steps.len() <= 3 {
            let mut scores = Vec::with_capacity(steps.len());
            for step in steps {
                let score = self.score_step(step, context).await?;
                scores.push(score);
            }
            return Ok(scores);
        }

        // For larger trajectories, use batch scoring
        let prompt = self.build_trajectory_prompt(steps, context);

        let request = CompletionRequest::new(&self.config.model)
            .with_message(Message::system(&self.config.system_prompt))
            .with_message(Message::user(prompt))
            .with_temperature(self.config.temperature)
            .with_max_tokens(self.config.max_tokens * 2); // More tokens for multiple scores

        let response = self.provider.complete(request).await?;

        self.parse_trajectory_response(&response.content, steps.len())
    }

    fn should_backtrack(&self, score: &ThoughtScore, threshold: f64) -> bool {
        // Consider both score and confidence
        // If confidence is very low, be more conservative
        let effective_threshold = if score.confidence < 0.3 {
            threshold * 0.8 // Lower threshold when uncertain
        } else {
            threshold
        };

        score.score < effective_threshold
    }
}

/// A mock PRM for testing purposes
#[derive(Debug, Clone)]
pub struct MockPrm {
    /// Default score to return
    pub default_score: f64,
    /// Default confidence to return
    pub default_confidence: f64,
    /// Backtrack threshold
    pub threshold: f64,
}

impl MockPrm {
    /// Create a new mock PRM
    pub fn new(default_score: f64, default_confidence: f64) -> Self {
        Self {
            default_score,
            default_confidence,
            threshold: 0.5,
        }
    }

    /// Set the backtrack threshold
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.threshold = threshold;
        self
    }
}

impl Default for MockPrm {
    fn default() -> Self {
        Self::new(0.8, 0.9)
    }
}

#[async_trait]
impl ProcessRewardModel for MockPrm {
    async fn score_step(
        &self,
        step: &ReasoningStep,
        _context: &str,
    ) -> Result<ThoughtScore, PrmError> {
        Ok(ThoughtScore::new_unchecked(
            self.default_score,
            self.default_confidence,
            format!("Mock score for step {}", step.step_number),
        ))
    }

    async fn score_trajectory(
        &self,
        steps: &[ReasoningStep],
        _context: &str,
    ) -> Result<Vec<ThoughtScore>, PrmError> {
        if steps.is_empty() {
            return Err(PrmError::EmptyTrajectory);
        }

        Ok(steps
            .iter()
            .map(|step| {
                ThoughtScore::new_unchecked(
                    self.default_score,
                    self.default_confidence,
                    format!("Mock score for step {}", step.step_number),
                )
            })
            .collect())
    }

    fn should_backtrack(&self, score: &ThoughtScore, threshold: f64) -> bool {
        score.score < threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::{MockLlmProvider, MockResponse};

    #[test]
    fn test_thought_score_creation() {
        // Valid scores
        let score = ThoughtScore::new(0.8, 0.9, "Good step").unwrap();
        assert!((score.score - 0.8).abs() < f64::EPSILON);
        assert!((score.confidence - 0.9).abs() < f64::EPSILON);
        assert_eq!(score.reasoning, "Good step");

        // Invalid score
        let result = ThoughtScore::new(1.5, 0.9, "Invalid");
        assert!(matches!(result, Err(PrmError::InvalidScore(_))));

        // Invalid confidence
        let result = ThoughtScore::new(0.8, -0.1, "Invalid");
        assert!(matches!(result, Err(PrmError::InvalidConfidence(_))));
    }

    #[test]
    fn test_thought_score_is_good() {
        let score = ThoughtScore::new(0.8, 0.9, "Good").unwrap();
        assert!(score.is_good(0.5));
        assert!(score.is_good(0.8));
        assert!(!score.is_good(0.9));
    }

    #[test]
    fn test_thought_score_weighted() {
        let score = ThoughtScore::new(0.8, 0.5, "Test").unwrap();
        assert!((score.weighted_score() - 0.4).abs() < f64::EPSILON);
    }

    #[test]
    fn test_reasoning_step_creation() {
        let step = ReasoningStep::new(1, "Think about the problem")
            .with_action("Calculate 2+2")
            .with_observation("Result is 4");

        assert_eq!(step.step_number, 1);
        assert_eq!(step.thought, "Think about the problem");
        assert_eq!(step.action, Some("Calculate 2+2".to_string()));
        assert_eq!(step.observation, Some("Result is 4".to_string()));
    }

    #[test]
    fn test_reasoning_step_format() {
        let step = ReasoningStep::new(1, "Think")
            .with_action("Do")
            .with_observation("See");

        let formatted = step.format_for_prompt();
        assert!(formatted.contains("Step 1: Think"));
        assert!(formatted.contains("Action: Do"));
        assert!(formatted.contains("Observation: See"));
    }

    #[test]
    fn test_prm_config_builder() {
        let config = PrmConfig::new("gpt-4")
            .with_backtrack_threshold(0.6)
            .with_temperature(0.2)
            .with_max_tokens(256);

        assert_eq!(config.model, "gpt-4");
        assert!((config.backtrack_threshold - 0.6).abs() < f64::EPSILON);
        assert!((config.temperature - 0.2).abs() < f32::EPSILON);
        assert_eq!(config.max_tokens, 256);
    }

    #[tokio::test]
    async fn test_mock_prm_score_step() {
        let prm = MockPrm::new(0.85, 0.95);
        let step = ReasoningStep::new(1, "Test thought");

        let score = prm.score_step(&step, "Test context").await.unwrap();
        assert!((score.score - 0.85).abs() < f64::EPSILON);
        assert!((score.confidence - 0.95).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_mock_prm_score_trajectory() {
        let prm = MockPrm::default();
        let steps = vec![
            ReasoningStep::new(1, "First thought"),
            ReasoningStep::new(2, "Second thought"),
        ];

        let scores = prm.score_trajectory(&steps, "Test context").await.unwrap();
        assert_eq!(scores.len(), 2);
    }

    #[tokio::test]
    async fn test_mock_prm_empty_trajectory() {
        let prm = MockPrm::default();
        let result = prm.score_trajectory(&[], "Test context").await;
        assert!(matches!(result, Err(PrmError::EmptyTrajectory)));
    }

    #[test]
    fn test_should_backtrack() {
        let prm = MockPrm::default();

        let good_score = ThoughtScore::new(0.8, 0.9, "Good").unwrap();
        assert!(!prm.should_backtrack(&good_score, 0.5));

        let bad_score = ThoughtScore::new(0.3, 0.9, "Bad").unwrap();
        assert!(prm.should_backtrack(&bad_score, 0.5));
    }

    #[tokio::test]
    async fn test_llm_prm_with_mock_provider() {
        let mock_response =
            r#"{"score": 0.85, "confidence": 0.9, "reasoning": "Good logical step"}"#;
        let provider =
            Arc::new(MockLlmProvider::new().with_response(MockResponse::success(mock_response)));

        let prm = LlmPrm::new(provider, PrmConfig::default());
        let step = ReasoningStep::new(1, "Calculate the sum of 2 and 3");

        let score = prm.score_step(&step, "What is 2 + 3?").await.unwrap();
        assert!((score.score - 0.85).abs() < f64::EPSILON);
        assert!((score.confidence - 0.9).abs() < f64::EPSILON);
        assert_eq!(score.reasoning, "Good logical step");
    }

    #[tokio::test]
    async fn test_llm_prm_parse_with_extra_text() {
        let mock_response = r#"Let me evaluate this step.

{"score": 0.75, "confidence": 0.8, "reasoning": "Reasonable approach"}

That's my assessment."#;

        let provider =
            Arc::new(MockLlmProvider::new().with_response(MockResponse::success(mock_response)));

        let prm = LlmPrm::new(provider, PrmConfig::default());
        let step = ReasoningStep::new(1, "Test step");

        let score = prm.score_step(&step, "Test").await.unwrap();
        assert!((score.score - 0.75).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_llm_prm_trajectory_individual_scoring() {
        // For small trajectories (<=3 steps), LlmPrm scores each step individually
        let responses = vec![
            MockResponse::success(
                r#"{"score": 0.9, "confidence": 0.95, "reasoning": "Step 1 good"}"#,
            ),
            MockResponse::success(
                r#"{"score": 0.85, "confidence": 0.9, "reasoning": "Step 2 good"}"#,
            ),
        ];

        let provider = Arc::new(MockLlmProvider::new().with_responses(responses));
        let prm = LlmPrm::new(provider, PrmConfig::default());

        let steps = vec![
            ReasoningStep::new(1, "First step"),
            ReasoningStep::new(2, "Second step"),
        ];

        let scores = prm.score_trajectory(&steps, "Test context").await.unwrap();
        assert_eq!(scores.len(), 2);
        assert!((scores[0].score - 0.9).abs() < f64::EPSILON);
        assert!((scores[1].score - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn test_prm_error_display() {
        let err = PrmError::InvalidScore(1.5);
        assert!(err.to_string().contains("1.5"));

        let err = PrmError::EmptyTrajectory;
        assert!(err.to_string().contains("Empty"));

        let err = PrmError::ParseError("test".to_string());
        assert!(err.to_string().contains("test"));
    }

    #[test]
    fn test_reasoning_step_serialization() {
        let step = ReasoningStep::new(1, "Think")
            .with_action("Act")
            .with_observation("Observe");

        let json = serde_json::to_string(&step).unwrap();
        let parsed: ReasoningStep = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.step_number, step.step_number);
        assert_eq!(parsed.thought, step.thought);
        assert_eq!(parsed.action, step.action);
        assert_eq!(parsed.observation, step.observation);
    }

    #[test]
    fn test_thought_score_serialization() {
        let score = ThoughtScore::new(0.8, 0.9, "Good").unwrap();

        let json = serde_json::to_string(&score).unwrap();
        let parsed: ThoughtScore = serde_json::from_str(&json).unwrap();

        assert!((parsed.score - score.score).abs() < f64::EPSILON);
        assert!((parsed.confidence - score.confidence).abs() < f64::EPSILON);
        assert_eq!(parsed.reasoning, score.reasoning);
    }

    #[test]
    fn test_prm_config_serialization() {
        let config = PrmConfig::new("gpt-4").with_backtrack_threshold(0.6);

        let json = serde_json::to_string(&config).unwrap();
        let parsed: PrmConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.model, config.model);
        assert!((parsed.backtrack_threshold - config.backtrack_threshold).abs() < f64::EPSILON);
    }
}
