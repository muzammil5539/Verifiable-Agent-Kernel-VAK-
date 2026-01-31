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

mod prm;
pub mod verifier;

// Re-export all public types from PRM
pub use prm::{
    LlmPrm, MockPrm, PrmConfig, PrmError, ProcessRewardModel, ReasoningStep, ThoughtScore,
};

// Re-export all public types from verifier
pub use verifier::{
    BatchVerificationResult, Constraint, ConstraintFile, ConstraintKind, ConstraintValue,
    ConstraintVerifier, Counterexample, FormalVerifier, VerificationError, VerificationResult,
    VerificationStatus, VerifierConfig, Z3Config, Z3Verifier,
};
