//! Enhanced PRM Fine-Tuning Toolkit (FUT-003)
//!
//! Provides tools for evaluating, calibrating, and fine-tuning Process Reward
//! Models (PRMs). The toolkit enables dataset management, model evaluation,
//! calibration analysis, and A/B testing of different PRM configurations.
//!
//! # Features
//!
//! - **Dataset Management**: Load, validate, and split training/evaluation datasets
//! - **Evaluation Metrics**: Accuracy, calibration, precision, recall, F1, and disagreement rate
//! - **Calibration Analysis**: Expected vs. actual calibration curves
//! - **Model Comparison**: A/B testing of PRM versions
//! - **Prompt Optimization**: Generate optimized scoring prompts for LLMs
//! - **Export**: Generate fine-tuning datasets in JSONL format
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::reasoner::prm_toolkit::{
//!     PrmToolkit, ToolkitConfig, TrainingExample,
//!     EvaluationDataset, EvaluationMetrics,
//! };
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = ToolkitConfig::default();
//! let toolkit = PrmToolkit::new(config);
//!
//! // Create a dataset
//! let examples = vec![
//!     TrainingExample::new("Calculate 2+2", "2+2=4", 0.95, true),
//!     TrainingExample::new("Calculate 2+2", "2+2=5", 0.1, false),
//! ];
//!
//! let dataset = EvaluationDataset::from_examples(examples);
//! let metrics = toolkit.evaluate_dataset(&dataset);
//!
//! println!("Accuracy: {:.2}%", metrics.accuracy * 100.0);
//! println!("Calibration error: {:.4}", metrics.calibration_error);
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during PRM toolkit operations
#[derive(Debug, Error)]
pub enum ToolkitError {
    /// Empty dataset provided
    #[error("Empty dataset provided")]
    EmptyDataset,

    /// Invalid training example
    #[error("Invalid training example: {0}")]
    InvalidExample(String),

    /// Invalid score value
    #[error("Invalid score value: {0} (must be between 0.0 and 1.0)")]
    InvalidScore(f64),

    /// Invalid threshold
    #[error("Invalid threshold: {0}")]
    InvalidThreshold(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// Parse error
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Model comparison requires at least 2 models
    #[error("Model comparison requires at least 2 model results")]
    InsufficientModels,
}

/// Result type for toolkit operations
pub type ToolkitResult<T> = Result<T, ToolkitError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the PRM toolkit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolkitConfig {
    /// Default threshold for binary classification
    pub default_threshold: f64,
    /// Number of calibration bins
    pub calibration_bins: usize,
    /// Enable detailed per-example logging
    pub detailed_logging: bool,
    /// Validation split ratio (0.0-1.0)
    pub validation_split: f64,
    /// Random seed for reproducibility
    pub random_seed: u64,
}

impl Default for ToolkitConfig {
    fn default() -> Self {
        Self {
            default_threshold: 0.5,
            calibration_bins: 10,
            detailed_logging: false,
            validation_split: 0.2,
            random_seed: 42,
        }
    }
}

impl ToolkitConfig {
    /// Create a strict configuration for production evaluation
    pub fn strict() -> Self {
        Self {
            default_threshold: 0.7,
            calibration_bins: 20,
            detailed_logging: true,
            validation_split: 0.3,
            random_seed: 42,
        }
    }

    /// Set threshold
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.default_threshold = threshold;
        self
    }

    /// Set calibration bins
    pub fn with_calibration_bins(mut self, bins: usize) -> Self {
        self.calibration_bins = bins;
        self
    }
}

// ============================================================================
// Training / Evaluation Data
// ============================================================================

/// A single training/evaluation example
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    /// The context/problem being solved
    pub context: String,
    /// The reasoning step text
    pub step_text: String,
    /// Ground truth score (0.0-1.0)
    pub ground_truth_score: f64,
    /// Whether this step is considered correct
    pub is_correct: bool,
    /// Model predicted score (if available)
    pub predicted_score: Option<f64>,
    /// Step number in the chain
    pub step_number: Option<usize>,
    /// Additional metadata
    pub metadata: Option<HashMap<String, serde_json::Value>>,
}

impl TrainingExample {
    /// Create a new training example
    pub fn new(
        context: impl Into<String>,
        step_text: impl Into<String>,
        ground_truth_score: f64,
        is_correct: bool,
    ) -> Self {
        Self {
            context: context.into(),
            step_text: step_text.into(),
            ground_truth_score,
            is_correct,
            predicted_score: None,
            step_number: None,
            metadata: None,
        }
    }

    /// Set predicted score
    pub fn with_predicted_score(mut self, score: f64) -> Self {
        self.predicted_score = Some(score);
        self
    }

    /// Set step number
    pub fn with_step_number(mut self, number: usize) -> Self {
        self.step_number = Some(number);
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Validate the example
    pub fn validate(&self) -> ToolkitResult<()> {
        if !(0.0..=1.0).contains(&self.ground_truth_score) {
            return Err(ToolkitError::InvalidScore(self.ground_truth_score));
        }
        if let Some(predicted) = self.predicted_score {
            if !(0.0..=1.0).contains(&predicted) {
                return Err(ToolkitError::InvalidScore(predicted));
            }
        }
        if self.context.is_empty() {
            return Err(ToolkitError::InvalidExample(
                "Context cannot be empty".to_string(),
            ));
        }
        if self.step_text.is_empty() {
            return Err(ToolkitError::InvalidExample(
                "Step text cannot be empty".to_string(),
            ));
        }
        Ok(())
    }
}

/// A dataset for evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationDataset {
    /// Dataset name
    pub name: String,
    /// Training/evaluation examples
    pub examples: Vec<TrainingExample>,
    /// Dataset metadata
    pub metadata: HashMap<String, String>,
}

impl EvaluationDataset {
    /// Create a dataset from examples
    pub fn from_examples(examples: Vec<TrainingExample>) -> Self {
        Self {
            name: "unnamed".to_string(),
            examples,
            metadata: HashMap::new(),
        }
    }

    /// Create a named dataset
    pub fn new(name: impl Into<String>, examples: Vec<TrainingExample>) -> Self {
        Self {
            name: name.into(),
            examples,
            metadata: HashMap::new(),
        }
    }

    /// Set metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Get the number of examples
    pub fn len(&self) -> usize {
        self.examples.len()
    }

    /// Check if dataset is empty
    pub fn is_empty(&self) -> bool {
        self.examples.is_empty()
    }

    /// Count correct examples
    pub fn correct_count(&self) -> usize {
        self.examples.iter().filter(|e| e.is_correct).count()
    }

    /// Count incorrect examples
    pub fn incorrect_count(&self) -> usize {
        self.examples.iter().filter(|e| !e.is_correct).count()
    }

    /// Split into training and validation sets
    pub fn split(&self, ratio: f64) -> (EvaluationDataset, EvaluationDataset) {
        let split_idx = (self.examples.len() as f64 * (1.0 - ratio)) as usize;

        let train = EvaluationDataset {
            name: format!("{}_train", self.name),
            examples: self.examples[..split_idx].to_vec(),
            metadata: self.metadata.clone(),
        };

        let val = EvaluationDataset {
            name: format!("{}_val", self.name),
            examples: self.examples[split_idx..].to_vec(),
            metadata: self.metadata.clone(),
        };

        (train, val)
    }

    /// Validate all examples
    pub fn validate(&self) -> ToolkitResult<()> {
        if self.is_empty() {
            return Err(ToolkitError::EmptyDataset);
        }
        for (i, example) in self.examples.iter().enumerate() {
            example.validate().map_err(|e| {
                ToolkitError::InvalidExample(format!("Example {}: {}", i, e))
            })?;
        }
        Ok(())
    }

    /// Export to JSONL format
    pub fn to_jsonl(&self) -> ToolkitResult<String> {
        let mut lines = Vec::new();
        for example in &self.examples {
            let json = serde_json::to_string(example)
                .map_err(|e| ToolkitError::ParseError(e.to_string()))?;
            lines.push(json);
        }
        Ok(lines.join("\n"))
    }

    /// Parse from JSONL format
    pub fn from_jsonl(name: &str, jsonl: &str) -> ToolkitResult<Self> {
        let mut examples = Vec::new();
        for (i, line) in jsonl.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let example: TrainingExample = serde_json::from_str(line)
                .map_err(|e| ToolkitError::ParseError(format!("Line {}: {}", i + 1, e)))?;
            examples.push(example);
        }
        Ok(Self::new(name, examples))
    }
}

// ============================================================================
// Evaluation Metrics
// ============================================================================

/// Comprehensive evaluation metrics for a PRM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationMetrics {
    /// Overall accuracy (correct predictions / total)
    pub accuracy: f64,
    /// Precision (true positives / (true positives + false positives))
    pub precision: f64,
    /// Recall (true positives / (true positives + false negatives))
    pub recall: f64,
    /// F1 score (harmonic mean of precision and recall)
    pub f1_score: f64,
    /// Expected Calibration Error
    pub calibration_error: f64,
    /// Mean absolute error of predicted vs. ground truth scores
    pub mean_absolute_error: f64,
    /// Root mean squared error
    pub root_mean_squared_error: f64,
    /// Area under the ROC curve (approximate)
    pub auroc: f64,
    /// Number of examples evaluated
    pub total_examples: usize,
    /// True positives count
    pub true_positives: usize,
    /// True negatives count
    pub true_negatives: usize,
    /// False positives count
    pub false_positives: usize,
    /// False negatives count
    pub false_negatives: usize,
    /// Threshold used for classification
    pub threshold: f64,
    /// Per-bin calibration data
    pub calibration_bins: Vec<CalibrationBin>,
}

impl fmt::Display for EvaluationMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== PRM Evaluation Metrics ===")?;
        writeln!(f, "Total examples: {}", self.total_examples)?;
        writeln!(f, "Threshold:      {:.2}", self.threshold)?;
        writeln!(f, "Accuracy:       {:.4} ({:.1}%)", self.accuracy, self.accuracy * 100.0)?;
        writeln!(f, "Precision:      {:.4}", self.precision)?;
        writeln!(f, "Recall:         {:.4}", self.recall)?;
        writeln!(f, "F1 Score:       {:.4}", self.f1_score)?;
        writeln!(f, "AUROC:          {:.4}", self.auroc)?;
        writeln!(f, "Calibration:    {:.4} (ECE)", self.calibration_error)?;
        writeln!(f, "MAE:            {:.4}", self.mean_absolute_error)?;
        writeln!(f, "RMSE:           {:.4}", self.root_mean_squared_error)?;
        writeln!(
            f,
            "Confusion:      TP={} TN={} FP={} FN={}",
            self.true_positives, self.true_negatives, self.false_positives, self.false_negatives
        )?;
        Ok(())
    }
}

/// A single calibration bin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationBin {
    /// Bin lower bound
    pub lower: f64,
    /// Bin upper bound
    pub upper: f64,
    /// Average predicted score in this bin
    pub avg_predicted: f64,
    /// Fraction of actually correct examples in this bin
    pub fraction_correct: f64,
    /// Number of examples in this bin
    pub count: usize,
}

/// Model comparison report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    /// Metrics for each model
    pub models: Vec<ModelResult>,
    /// Winner by accuracy
    pub best_accuracy: String,
    /// Winner by calibration
    pub best_calibration: String,
    /// Winner by F1
    pub best_f1: String,
    /// Per-example disagreement rate
    pub disagreement_rate: f64,
}

/// Results for a single model in a comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelResult {
    /// Model identifier
    pub model_id: String,
    /// Evaluation metrics
    pub metrics: EvaluationMetrics,
}

impl fmt::Display for ComparisonReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== PRM Model Comparison ===")?;
        writeln!(f, "Models compared: {}", self.models.len())?;
        writeln!(f, "Best accuracy:     {}", self.best_accuracy)?;
        writeln!(f, "Best calibration:  {}", self.best_calibration)?;
        writeln!(f, "Best F1:           {}", self.best_f1)?;
        writeln!(f, "Disagreement rate: {:.2}%", self.disagreement_rate * 100.0)?;
        writeln!(f)?;
        for model in &self.models {
            writeln!(f, "--- {} ---", model.model_id)?;
            writeln!(f, "  Accuracy:    {:.4}", model.metrics.accuracy)?;
            writeln!(f, "  F1:          {:.4}", model.metrics.f1_score)?;
            writeln!(f, "  Calibration: {:.4}", model.metrics.calibration_error)?;
        }
        Ok(())
    }
}

/// A prompt template for PRM evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptTemplate {
    /// Template name
    pub name: String,
    /// System prompt
    pub system_prompt: String,
    /// Step scoring template
    pub step_template: String,
    /// Trajectory scoring template
    pub trajectory_template: String,
    /// Temperature
    pub temperature: f32,
    /// Description
    pub description: String,
}

// ============================================================================
// PRM Toolkit
// ============================================================================

/// Main toolkit for PRM evaluation and fine-tuning
#[derive(Debug, Clone)]
pub struct PrmToolkit {
    config: ToolkitConfig,
}

impl PrmToolkit {
    /// Create a new toolkit with the given configuration
    pub fn new(config: ToolkitConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ToolkitConfig::default())
    }

    /// Evaluate a dataset with predicted scores against ground truth
    pub fn evaluate_dataset(&self, dataset: &EvaluationDataset) -> EvaluationMetrics {
        self.evaluate_with_threshold(dataset, self.config.default_threshold)
    }

    /// Evaluate with a specific threshold
    pub fn evaluate_with_threshold(
        &self,
        dataset: &EvaluationDataset,
        threshold: f64,
    ) -> EvaluationMetrics {
        let mut tp = 0usize;
        let mut tn = 0usize;
        let mut fp = 0usize;
        let mut r#fn = 0usize;
        let mut total_abs_error = 0.0f64;
        let mut total_sq_error = 0.0f64;

        for example in &dataset.examples {
            let predicted = example.predicted_score.unwrap_or(example.ground_truth_score);
            let predicted_positive = predicted >= threshold;
            let actually_positive = example.is_correct;

            match (predicted_positive, actually_positive) {
                (true, true) => tp += 1,
                (true, false) => fp += 1,
                (false, true) => r#fn += 1,
                (false, false) => tn += 1,
            }

            let error = (predicted - example.ground_truth_score).abs();
            total_abs_error += error;
            total_sq_error += error * error;
        }

        let total = dataset.examples.len().max(1) as f64;
        let accuracy = (tp + tn) as f64 / total;
        let precision = if tp + fp > 0 {
            tp as f64 / (tp + fp) as f64
        } else {
            0.0
        };
        let recall = if tp + r#fn > 0 {
            tp as f64 / (tp + r#fn) as f64
        } else {
            0.0
        };
        let f1_score = if precision + recall > 0.0 {
            2.0 * precision * recall / (precision + recall)
        } else {
            0.0
        };

        let mean_absolute_error = total_abs_error / total;
        let root_mean_squared_error = (total_sq_error / total).sqrt();

        // Calculate calibration
        let calibration_bins = self.compute_calibration_bins(dataset);
        let calibration_error = self.compute_ece(&calibration_bins, dataset.examples.len());

        // Approximate AUROC
        let auroc = self.approximate_auroc(dataset);

        EvaluationMetrics {
            accuracy,
            precision,
            recall,
            f1_score,
            calibration_error,
            mean_absolute_error,
            root_mean_squared_error,
            auroc,
            total_examples: dataset.examples.len(),
            true_positives: tp,
            true_negatives: tn,
            false_positives: fp,
            false_negatives: r#fn,
            threshold,
            calibration_bins,
        }
    }

    /// Compute calibration bins
    fn compute_calibration_bins(&self, dataset: &EvaluationDataset) -> Vec<CalibrationBin> {
        let num_bins = self.config.calibration_bins;
        let bin_width = 1.0 / num_bins as f64;
        let mut bins: Vec<CalibrationBin> = (0..num_bins)
            .map(|i| CalibrationBin {
                lower: i as f64 * bin_width,
                upper: (i + 1) as f64 * bin_width,
                avg_predicted: 0.0,
                fraction_correct: 0.0,
                count: 0,
            })
            .collect();

        // Assign examples to bins
        for example in &dataset.examples {
            let score = example.predicted_score.unwrap_or(example.ground_truth_score);
            let bin_idx = ((score * num_bins as f64).floor() as usize).min(num_bins - 1);
            bins[bin_idx].count += 1;
            bins[bin_idx].avg_predicted += score;
            if example.is_correct {
                bins[bin_idx].fraction_correct += 1.0;
            }
        }

        // Compute averages
        for bin in &mut bins {
            if bin.count > 0 {
                bin.avg_predicted /= bin.count as f64;
                bin.fraction_correct /= bin.count as f64;
            }
        }

        bins
    }

    /// Compute Expected Calibration Error
    fn compute_ece(&self, bins: &[CalibrationBin], total: usize) -> f64 {
        if total == 0 {
            return 0.0;
        }

        bins.iter()
            .map(|bin| {
                let weight = bin.count as f64 / total as f64;
                weight * (bin.avg_predicted - bin.fraction_correct).abs()
            })
            .sum()
    }

    /// Approximate AUROC using trapezoidal rule
    fn approximate_auroc(&self, dataset: &EvaluationDataset) -> f64 {
        if dataset.examples.is_empty() {
            return 0.5;
        }

        // Collect (predicted_score, is_correct) pairs
        let mut scored: Vec<(f64, bool)> = dataset
            .examples
            .iter()
            .map(|e| {
                (
                    e.predicted_score.unwrap_or(e.ground_truth_score),
                    e.is_correct,
                )
            })
            .collect();

        // Sort by predicted score descending
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        let total_positive = scored.iter().filter(|(_, c)| *c).count() as f64;
        let total_negative = scored.iter().filter(|(_, c)| !*c).count() as f64;

        if total_positive == 0.0 || total_negative == 0.0 {
            return 0.5;
        }

        let mut auc = 0.0;
        let mut true_pos = 0.0;
        let mut false_pos = 0.0;
        let mut prev_fpr = 0.0;
        let mut prev_tpr = 0.0;

        for (_, is_correct) in &scored {
            if *is_correct {
                true_pos += 1.0;
            } else {
                false_pos += 1.0;
            }

            let tpr = true_pos / total_positive;
            let fpr = false_pos / total_negative;

            // Trapezoidal rule
            auc += 0.5 * (fpr - prev_fpr) * (tpr + prev_tpr);

            prev_tpr = tpr;
            prev_fpr = fpr;
        }

        auc
    }

    /// Compare multiple model results on the same dataset
    pub fn compare_models(
        &self,
        results: Vec<(String, &EvaluationDataset)>,
    ) -> ToolkitResult<ComparisonReport> {
        if results.len() < 2 {
            return Err(ToolkitError::InsufficientModels);
        }

        let mut models = Vec::new();
        for (model_id, dataset) in &results {
            let metrics = self.evaluate_dataset(dataset);
            models.push(ModelResult {
                model_id: model_id.clone(),
                metrics,
            });
        }

        let best_accuracy = models
            .iter()
            .max_by(|a, b| {
                a.metrics
                    .accuracy
                    .partial_cmp(&b.metrics.accuracy)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|m| m.model_id.clone())
            .unwrap_or_default();

        let best_calibration = models
            .iter()
            .min_by(|a, b| {
                a.metrics
                    .calibration_error
                    .partial_cmp(&b.metrics.calibration_error)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|m| m.model_id.clone())
            .unwrap_or_default();

        let best_f1 = models
            .iter()
            .max_by(|a, b| {
                a.metrics
                    .f1_score
                    .partial_cmp(&b.metrics.f1_score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|m| m.model_id.clone())
            .unwrap_or_default();

        // Compute disagreement rate
        let disagreement_rate = self.compute_disagreement_rate(&results);

        Ok(ComparisonReport {
            models,
            best_accuracy,
            best_calibration,
            best_f1,
            disagreement_rate,
        })
    }

    /// Compute disagreement rate between models
    fn compute_disagreement_rate(&self, results: &[(String, &EvaluationDataset)]) -> f64 {
        if results.len() < 2 {
            return 0.0;
        }

        let first = &results[0].1.examples;
        let second = &results[1].1.examples;

        let min_len = first.len().min(second.len());
        if min_len == 0 {
            return 0.0;
        }

        let mut disagreements = 0;
        for i in 0..min_len {
            let s1 = first[i]
                .predicted_score
                .unwrap_or(first[i].ground_truth_score);
            let s2 = second[i]
                .predicted_score
                .unwrap_or(second[i].ground_truth_score);

            let p1 = s1 >= self.config.default_threshold;
            let p2 = s2 >= self.config.default_threshold;

            if p1 != p2 {
                disagreements += 1;
            }
        }

        disagreements as f64 / min_len as f64
    }

    /// Find the optimal threshold that maximizes F1 score
    pub fn find_optimal_threshold(&self, dataset: &EvaluationDataset) -> (f64, EvaluationMetrics) {
        let mut best_threshold = 0.5;
        let mut best_f1 = 0.0;
        let mut best_metrics = self.evaluate_with_threshold(dataset, 0.5);

        for i in 1..100 {
            let threshold = i as f64 / 100.0;
            let metrics = self.evaluate_with_threshold(dataset, threshold);
            if metrics.f1_score > best_f1 {
                best_f1 = metrics.f1_score;
                best_threshold = threshold;
                best_metrics = metrics;
            }
        }

        (best_threshold, best_metrics)
    }

    /// Generate optimized prompt templates based on dataset characteristics
    pub fn generate_prompt_templates(&self, dataset: &EvaluationDataset) -> Vec<PromptTemplate> {
        let avg_step_length = if dataset.is_empty() {
            100
        } else {
            dataset.examples.iter().map(|e| e.step_text.len()).sum::<usize>() / dataset.len()
        };

        let correct_ratio = if dataset.is_empty() {
            0.5
        } else {
            dataset.correct_count() as f64 / dataset.len() as f64
        };

        let mut templates = Vec::new();

        // Standard template
        templates.push(PromptTemplate {
            name: "standard".to_string(),
            system_prompt: "You are a Process Reward Model evaluating reasoning steps. Score each step from 0.0 (incorrect) to 1.0 (correct). Respond with JSON: {\"score\": float, \"confidence\": float, \"reasoning\": string}".to_string(),
            step_template: "Context: {context}\n\nEvaluate this reasoning step:\n{step}\n\nStep {step_number} in the chain.".to_string(),
            trajectory_template: "Context: {context}\n\nEvaluate the trajectory:\n{trajectory}".to_string(),
            temperature: 0.1,
            description: "Standard balanced prompt template".to_string(),
        });

        // Strict template (for datasets with many incorrect examples)
        if correct_ratio < 0.6 {
            templates.push(PromptTemplate {
                name: "strict".to_string(),
                system_prompt: "You are a strict PRM evaluator. Be critical of reasoning errors. Score conservatively - only give high scores to clearly correct steps. Respond with JSON: {\"score\": float, \"confidence\": float, \"reasoning\": string}".to_string(),
                step_template: "Problem: {context}\n\nCritically evaluate this reasoning step for logical errors:\n{step}\n\nThis is step {step_number}.".to_string(),
                trajectory_template: "Problem: {context}\n\nCritically evaluate each step:\n{trajectory}".to_string(),
                temperature: 0.05,
                description: "Strict template for datasets with many incorrect examples".to_string(),
            });
        }

        // Detailed template (for long reasoning steps)
        if avg_step_length > 200 {
            templates.push(PromptTemplate {
                name: "detailed".to_string(),
                system_prompt: "You are a detailed PRM evaluator. Given complex reasoning steps, evaluate: (1) logical validity, (2) factual accuracy, (3) relevance to the problem, (4) progress toward solution. Respond with JSON: {\"score\": float, \"confidence\": float, \"reasoning\": string}".to_string(),
                step_template: "Problem Statement: {context}\n\nReasoning Step {step_number}:\n{step}\n\nEvaluate the above step on all four criteria.".to_string(),
                trajectory_template: "Problem: {context}\n\nFull Reasoning Chain:\n{trajectory}\n\nEvaluate each step.".to_string(),
                temperature: 0.15,
                description: "Detailed template for long-form reasoning".to_string(),
            });
        }

        templates
    }

    /// Generate a fine-tuning dataset in JSONL format
    pub fn generate_finetuning_data(
        &self,
        dataset: &EvaluationDataset,
        template: &PromptTemplate,
    ) -> ToolkitResult<String> {
        let mut lines = Vec::new();

        for example in &dataset.examples {
            let prompt = template
                .step_template
                .replace("{context}", &example.context)
                .replace("{step}", &example.step_text)
                .replace(
                    "{step_number}",
                    &example.step_number.unwrap_or(1).to_string(),
                );

            let entry = serde_json::json!({
                "messages": [
                    {
                        "role": "system",
                        "content": template.system_prompt
                    },
                    {
                        "role": "user",
                        "content": prompt
                    },
                    {
                        "role": "assistant",
                        "content": serde_json::json!({
                            "score": example.ground_truth_score,
                            "confidence": if example.is_correct { 0.9 } else { 0.8 },
                            "reasoning": format!(
                                "Step is {} based on evaluation",
                                if example.is_correct { "correct" } else { "incorrect" }
                            )
                        }).to_string()
                    }
                ]
            });

            let json_line = serde_json::to_string(&entry)
                .map_err(|e| ToolkitError::ParseError(e.to_string()))?;
            lines.push(json_line);
        }

        Ok(lines.join("\n"))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dataset() -> EvaluationDataset {
        let examples = vec![
            TrainingExample::new("Calc", "2+2=4", 0.95, true).with_predicted_score(0.9),
            TrainingExample::new("Calc", "2+2=5", 0.1, false).with_predicted_score(0.15),
            TrainingExample::new("Calc", "3*3=9", 0.9, true).with_predicted_score(0.85),
            TrainingExample::new("Calc", "3*3=6", 0.2, false).with_predicted_score(0.3),
            TrainingExample::new("Calc", "5-1=4", 0.95, true).with_predicted_score(0.92),
            TrainingExample::new("Calc", "5-1=3", 0.05, false).with_predicted_score(0.08),
            TrainingExample::new("Calc", "10/2=5", 0.9, true).with_predicted_score(0.88),
            TrainingExample::new("Calc", "10/2=3", 0.1, false).with_predicted_score(0.12),
        ];
        EvaluationDataset::new("test_math", examples)
    }

    #[test]
    fn test_basic_evaluation() {
        let toolkit = PrmToolkit::with_defaults();
        let dataset = sample_dataset();

        let metrics = toolkit.evaluate_dataset(&dataset);

        assert!(metrics.accuracy > 0.9, "Expected high accuracy, got {}", metrics.accuracy);
        assert_eq!(metrics.total_examples, 8);
        assert!(metrics.precision > 0.0);
        assert!(metrics.recall > 0.0);
        assert!(metrics.f1_score > 0.0);
    }

    #[test]
    fn test_perfect_predictions() {
        let examples = vec![
            TrainingExample::new("Q", "correct", 1.0, true).with_predicted_score(0.9),
            TrainingExample::new("Q", "wrong", 0.0, false).with_predicted_score(0.1),
        ];
        let dataset = EvaluationDataset::from_examples(examples);
        let toolkit = PrmToolkit::with_defaults();

        let metrics = toolkit.evaluate_dataset(&dataset);
        assert_eq!(metrics.accuracy, 1.0);
        assert_eq!(metrics.precision, 1.0);
        assert_eq!(metrics.recall, 1.0);
    }

    #[test]
    fn test_calibration_bins() {
        let toolkit = PrmToolkit::new(ToolkitConfig {
            calibration_bins: 5,
            ..ToolkitConfig::default()
        });
        let dataset = sample_dataset();

        let metrics = toolkit.evaluate_dataset(&dataset);
        assert_eq!(metrics.calibration_bins.len(), 5);
    }

    #[test]
    fn test_dataset_split() {
        let dataset = sample_dataset();
        let (train, val) = dataset.split(0.25);

        assert_eq!(train.len() + val.len(), dataset.len());
        assert!(val.len() >= 1);
    }

    #[test]
    fn test_dataset_jsonl_roundtrip() {
        let dataset = sample_dataset();
        let jsonl = dataset.to_jsonl().unwrap();
        let roundtrip = EvaluationDataset::from_jsonl("roundtrip", &jsonl).unwrap();

        assert_eq!(dataset.len(), roundtrip.len());
    }

    #[test]
    fn test_model_comparison() {
        let toolkit = PrmToolkit::with_defaults();

        let model_a = sample_dataset();
        let model_b_examples: Vec<_> = sample_dataset()
            .examples
            .into_iter()
            .map(|mut e| {
                e.predicted_score = Some(e.predicted_score.unwrap_or(0.5) * 0.9);
                e
            })
            .collect();
        let model_b = EvaluationDataset::new("model_b", model_b_examples);

        let report = toolkit
            .compare_models(vec![
                ("model_a".to_string(), &model_a),
                ("model_b".to_string(), &model_b),
            ])
            .unwrap();

        assert_eq!(report.models.len(), 2);
        assert!(!report.best_accuracy.is_empty());
        assert!(!report.best_f1.is_empty());
    }

    #[test]
    fn test_insufficient_models_comparison() {
        let toolkit = PrmToolkit::with_defaults();
        let dataset = sample_dataset();

        let result = toolkit.compare_models(vec![("single".to_string(), &dataset)]);
        assert!(matches!(result, Err(ToolkitError::InsufficientModels)));
    }

    #[test]
    fn test_find_optimal_threshold() {
        let toolkit = PrmToolkit::with_defaults();
        let dataset = sample_dataset();

        let (threshold, metrics) = toolkit.find_optimal_threshold(&dataset);
        assert!(threshold > 0.0 && threshold < 1.0);
        assert!(metrics.f1_score > 0.0);
    }

    #[test]
    fn test_generate_prompt_templates() {
        let toolkit = PrmToolkit::with_defaults();
        let dataset = sample_dataset();

        let templates = toolkit.generate_prompt_templates(&dataset);
        assert!(!templates.is_empty());
        assert_eq!(templates[0].name, "standard");
    }

    #[test]
    fn test_finetuning_data_generation() {
        let toolkit = PrmToolkit::with_defaults();
        let dataset = sample_dataset();
        let templates = toolkit.generate_prompt_templates(&dataset);

        let finetuning_data = toolkit
            .generate_finetuning_data(&dataset, &templates[0])
            .unwrap();

        let lines: Vec<&str> = finetuning_data.lines().collect();
        assert_eq!(lines.len(), dataset.len());

        // Each line should be valid JSON
        for line in lines {
            assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
        }
    }

    #[test]
    fn test_training_example_validation() {
        let valid = TrainingExample::new("context", "step", 0.5, true);
        assert!(valid.validate().is_ok());

        let invalid_score = TrainingExample::new("context", "step", 1.5, true);
        assert!(invalid_score.validate().is_err());

        let empty_context = TrainingExample::new("", "step", 0.5, true);
        assert!(empty_context.validate().is_err());
    }

    #[test]
    fn test_dataset_validation() {
        let empty = EvaluationDataset::from_examples(vec![]);
        assert!(empty.validate().is_err());

        let valid = sample_dataset();
        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_auroc_calculation() {
        let toolkit = PrmToolkit::with_defaults();
        let dataset = sample_dataset();

        let metrics = toolkit.evaluate_dataset(&dataset);
        assert!(
            metrics.auroc >= 0.0 && metrics.auroc <= 1.0,
            "AUROC should be between 0 and 1, got {}",
            metrics.auroc
        );
    }

    #[test]
    fn test_evaluation_display() {
        let toolkit = PrmToolkit::with_defaults();
        let dataset = sample_dataset();

        let metrics = toolkit.evaluate_dataset(&dataset);
        let display = format!("{}", metrics);
        assert!(display.contains("Accuracy"));
        assert!(display.contains("Precision"));
        assert!(display.contains("F1 Score"));
    }

    #[test]
    fn test_dataset_counts() {
        let dataset = sample_dataset();
        assert_eq!(dataset.correct_count(), 4);
        assert_eq!(dataset.incorrect_count(), 4);
        assert_eq!(dataset.len(), 8);
    }
}
