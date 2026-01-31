//! Reasoner module for the Verifiable Agent Kernel
//!
//! This module provides reasoning capabilities with step-by-step validation
//! using Process Reward Models (PRM). PRMs score individual reasoning steps
//! to detect errors early and enable backtracking when needed.
//!
//! # Overview
//!
//! The reasoner module enables:
//! - Step-by-step scoring of reasoning chains
//! - Early detection of reasoning errors
//! - Backtracking when confidence drops below threshold
//! - Integration with LLM providers for scoring
//!
//! # Example
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

mod prm;

// Re-export all public types
pub use prm::{
    LlmPrm, MockPrm, PrmConfig, PrmError, ProcessRewardModel, ReasoningStep, ThoughtScore,
};
