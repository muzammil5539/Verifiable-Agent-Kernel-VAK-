//! Reasoner module for the Verifiable Agent Kernel
//!
//! This module provides reasoning capabilities with step-by-step validation
//! using Process Reward Models (PRM) and formal verification via constraint checking.
//!
//! # Overview
//!
//! The reasoner module enables:
//! - Step-by-step scoring of reasoning chains via PRM
//! - Early detection of reasoning errors
//! - Backtracking when confidence drops below threshold
//! - Integration with LLM providers for scoring
//! - Formal verification of constraints using a simple DSL
//! - Safety constraint checking and counterexample generation
//!
//! # Example: Process Reward Model
//!
//! ```rust,no_run
//! use vak::reasoner::{LlmPrm, PrmConfig, ProcessRewardModel, ReasoningStep};
//! use vak::llm::{LiteLlmClient, LlmConfig};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create an LLM provider
//!     let llm_config = LlmConfig::new("http://localhost:4000", "your-api-key");
//!     let llm_client = Arc::new(LiteLlmClient::new(llm_config)?);
//!     
//!     // Create the PRM with default configuration
//!     let prm_config = PrmConfig::default();
//!     let prm = LlmPrm::new(llm_client, prm_config);
//!     
//!     // Score a reasoning step
//!     let step = ReasoningStep::new(1, "I need to calculate 2 + 2")
//!         .with_action("Calculate: 2 + 2 = 4")
//!         .with_observation("The result is 4");
//!     
//!     let score = prm.score_step(&step, "Calculate 2 + 2").await?;
//!     println!("Step score: {}, confidence: {}", score.score, score.confidence);
//!     
//!     Ok(())
//! }
//! ```
//!
//! # Example: Formal Verification
//!
//! ```rust
//! use vak::reasoner::{ConstraintVerifier, Constraint, ConstraintKind, FormalVerifier};
//! use std::collections::HashMap;
//!
//! let verifier = ConstraintVerifier::new();
//!
//! // Define a constraint: amount must be less than 1000
//! let constraint = Constraint::new("max_refund", ConstraintKind::LessThan {
//!     field: "amount".to_string(),
//!     value: 1000.into(),
//! });
//!
//! // Create context with field values
//! let mut context = HashMap::new();
//! context.insert("amount".to_string(), 500.into());
//!
//! // Verify the constraint
//! let result = verifier.verify(&constraint, &context).unwrap();
//! assert!(result.is_satisfied());
//! ```

pub mod constrained_decoding;
pub mod datalog;
pub mod hybrid_loop;
mod prm;
pub mod prm_gating;
pub mod prompt_injection;
pub mod tree_search;
pub mod verification_gateway;
pub mod verifier;
pub mod z3_verifier;

// Re-export all public types from PRM
pub use prm::{
    LlmPrm, MockPrm, PrmConfig, PrmError, PrmScorer, ProcessRewardModel, ReasoningStep,
    ThoughtScore, TrajectoryScore,
};

// Re-export Datalog safety engine types (NSR-001, NSR-002)
pub use datalog::{
    DatalogError, DatalogResult, Fact, SafetyConfig, SafetyEngine, SafetyEngineBuilder, SafetyRule,
    SafetyStats, SafetyVerdict, Violation,
};

// Re-export PRM gating types (Issue #47)
pub use prm_gating::{
    AlternativeAction, BatchGateResult, GateConfig, GateContext, GateDecision, GateError,
    GateStats, PrmGate,
};

// Re-export Neuro-Symbolic Hybrid Loop types (NSR-006)
pub use hybrid_loop::{
    ActionResult, ExecutionPlan, ExecutionResult, HybridConfig, HybridError, HybridReasoningLoop,
    HybridResult, LoopIteration, PlanAction, ValidationOutcome,
};

// Re-export all public types from tree_search (NSR-003)
pub use tree_search::{
    NodeId, NodeState, NodeStats, SearchNode, SearchResult, SearchTree, SimpleThoughtGenerator,
    ThoughtGenerator, TreeOfThoughts, TreeOfThoughtsBuilder, TreeSearchConfig, TreeSearchError,
    TreeSearchResult,
};

// Re-export all public types from verifier
pub use verifier::{
    BatchVerificationResult, Constraint, ConstraintFile, ConstraintKind, ConstraintValue,
    ConstraintVerifier, Counterexample, FormalVerifier, VerificationError, VerificationResult,
    VerificationStatus, VerifierConfig, Z3Config, Z3Verifier,
};

// Re-export Z3 formal verifier types (Issue #12)
pub use z3_verifier::{
    SmtLibBuilder, Z3Config as Z3SolverConfig, Z3Error, Z3FormalVerifier, Z3Output,
};

// Re-export verification gateway types (Issue #48)
pub use verification_gateway::{
    ActionCategory, ConditionResult, ForbiddenPattern, GatewayConfig, GatewayError, GatewayResult,
    GatewayVerificationResult, HighStakesAction, RiskLevel, VerificationGateway, VerificationStats,
    ViolationDetail,
};

// Re-export prompt injection detection types (SEC-004)
//
// The prompt injection module provides comprehensive detection for LLM prompt
// injection attacks. Integration points:
//
// 1. Input validation: Use `PromptInjectionDetector::analyze()` before processing
// 2. Context-aware: Use `analyze_with_context()` for multi-turn conversations
// 3. Configuration: Use `DetectorConfig::strict()` for high-security scenarios
//
// Example integration:
// ```rust,ignore
// let detector = PromptInjectionDetector::new(DetectorConfig::default());
// let result = detector.analyze(&user_input);
// if result.should_block() {
//     return Err("Input blocked due to potential prompt injection");
// }
// ```
pub use prompt_injection::{
    DetectionResult, DetectorConfig, DetectorStats, HeuristicFlag, InjectionError, InjectionResult,
    InjectionType, PatternMatch, PromptInjectionDetector, RecommendedAction,
};

pub use constrained_decoding::{
    ConstrainedDecoder, ConstraintError, ConstraintResult, ErrorSeverity, GrammarRule, GrammarType,
    OutputGrammar, RepairSuggestion, RepairType, ValidationError, ValidationResult,
};
