//! LLM Interface Module for the Verifiable Agent Kernel
//!
//! This module provides abstractions for interacting with Large Language Models (LLMs)
//! through a unified interface. It supports multiple backends including:
//! - LiteLLM proxy
//! - OpenAI API
//! - Ollama
//! - Any OpenAI-compatible API
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::llm::{LiteLlmClient, LlmConfig, LlmProvider, CompletionRequest, Message, Role};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = LlmConfig::new("http://localhost:4000", "your-api-key");
//!     let client = LiteLlmClient::new(config)?;
//!     
//!     let request = CompletionRequest::new("gpt-3.5-turbo")
//!         .with_message(Message::system("You are a helpful assistant."))
//!         .with_message(Message::user("Hello!"));
//!     
//!     let response = client.complete(request).await?;
//!     println!("Response: {}", response.content);
//!     Ok(())
//! }
//! ```

mod litellm;
mod mock;
mod traits;

// Re-export all public types
pub use litellm::LiteLlmClient;
pub use mock::{MockLlmProvider, MockResponse};
pub use traits::{
    CompletionRequest, CompletionResponse, LlmConfig, LlmError, LlmProvider, Message, Role,
    StreamChunk, Usage,
};
