//! LLM abstraction traits and types
//!
//! This module defines the core traits and types for interacting with LLM providers.

use async_trait::async_trait;
use futures::Stream;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::pin::Pin;
use std::time::Duration;

/// Error types for LLM operations
#[derive(Debug, Clone)]
pub enum LlmError {
    /// Error during HTTP request
    RequestError(String),
    /// API returned an error response
    ApiError {
        /// HTTP status code
        status: u16,
        /// Error message from the API
        message: String,
    },
    /// Failed to parse response
    ParseError(String),
    /// Request timed out
    Timeout,
    /// Rate limit exceeded
    RateLimited {
        /// Duration to wait before retrying, if provided by the API
        retry_after: Option<Duration>,
    },
    /// Authentication failed
    AuthenticationError(String),
    /// Invalid configuration
    ConfigError(String),
    /// Stream error during streaming response
    StreamError(String),
    /// Model not found or not available
    ModelNotFound(String),
    /// Context length exceeded
    ContextLengthExceeded {
        /// Maximum tokens allowed by the model
        max_tokens: usize,
        /// Number of tokens requested
        requested: usize,
    },
}

impl std::error::Error for LlmError {}

impl fmt::Display for LlmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmError::RequestError(msg) => write!(f, "Request error: {}", msg),
            LlmError::ApiError { status, message } => {
                write!(f, "API error (status {}): {}", status, message)
            }
            LlmError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            LlmError::Timeout => write!(f, "Request timed out"),
            LlmError::RateLimited { retry_after } => {
                if let Some(duration) = retry_after {
                    write!(f, "Rate limited, retry after {:?}", duration)
                } else {
                    write!(f, "Rate limited")
                }
            }
            LlmError::AuthenticationError(msg) => write!(f, "Authentication error: {}", msg),
            LlmError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            LlmError::StreamError(msg) => write!(f, "Stream error: {}", msg),
            LlmError::ModelNotFound(model) => write!(f, "Model not found: {}", model),
            LlmError::ContextLengthExceeded {
                max_tokens,
                requested,
            } => {
                write!(
                    f,
                    "Context length exceeded: max {} tokens, requested {}",
                    max_tokens, requested
                )
            }
        }
    }
}

/// Role of a message in the conversation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System message that sets the behavior of the assistant
    System,
    /// User message
    User,
    /// Assistant (LLM) response
    Assistant,
    /// Function/tool call result
    Function,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::System => write!(f, "system"),
            Role::User => write!(f, "user"),
            Role::Assistant => write!(f, "assistant"),
            Role::Function => write!(f, "function"),
        }
    }
}

/// A message in a conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Role of the message sender
    pub role: Role,
    /// Content of the message
    pub content: String,
    /// Optional name for the message sender (used with function role)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Message {
    /// Create a new message with the given role and content
    pub fn new(role: Role, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
            name: None,
        }
    }

    /// Create a system message
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(Role::System, content)
    }

    /// Create a user message
    pub fn user(content: impl Into<String>) -> Self {
        Self::new(Role::User, content)
    }

    /// Create an assistant message
    pub fn assistant(content: impl Into<String>) -> Self {
        Self::new(Role::Assistant, content)
    }

    /// Create a function result message
    pub fn function(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Function,
            content: content.into(),
            name: Some(name.into()),
        }
    }

    /// Set the name for this message
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// Token usage information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Number of tokens in the prompt
    pub prompt_tokens: usize,
    /// Number of tokens in the completion
    pub completion_tokens: usize,
    /// Total number of tokens used
    pub total_tokens: usize,
}

impl Usage {
    /// Create a new Usage with the given token counts
    pub fn new(prompt_tokens: usize, completion_tokens: usize) -> Self {
        Self {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        }
    }
}

/// Request for a completion from the LLM
#[derive(Debug, Clone, Serialize)]
pub struct CompletionRequest {
    /// The model to use for completion
    pub model: String,
    /// Messages in the conversation
    pub messages: Vec<Message>,
    /// Sampling temperature (0.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Maximum tokens to generate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<usize>,
    /// Stop sequences to end generation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop: Option<Vec<String>>,
    /// Whether to stream the response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Top-p (nucleus) sampling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    /// Frequency penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    /// Presence penalty (-2.0 to 2.0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    /// User identifier for tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl CompletionRequest {
    /// Create a new completion request for the given model
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            messages: Vec::new(),
            temperature: None,
            max_tokens: None,
            stop: None,
            stream: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
            user: None,
        }
    }

    /// Add a message to the request
    pub fn with_message(mut self, message: Message) -> Self {
        self.messages.push(message);
        self
    }

    /// Add multiple messages to the request
    pub fn with_messages(mut self, messages: impl IntoIterator<Item = Message>) -> Self {
        self.messages.extend(messages);
        self
    }

    /// Set the temperature
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = Some(temperature);
        self
    }

    /// Set the maximum tokens
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = Some(max_tokens);
        self
    }

    /// Set stop sequences
    pub fn with_stop_sequences(mut self, stop: Vec<String>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Set streaming mode
    pub fn with_stream(mut self, stream: bool) -> Self {
        self.stream = Some(stream);
        self
    }

    /// Set top-p sampling
    pub fn with_top_p(mut self, top_p: f32) -> Self {
        self.top_p = Some(top_p);
        self
    }

    /// Set frequency penalty
    pub fn with_frequency_penalty(mut self, penalty: f32) -> Self {
        self.frequency_penalty = Some(penalty);
        self
    }

    /// Set presence penalty
    pub fn with_presence_penalty(mut self, penalty: f32) -> Self {
        self.presence_penalty = Some(penalty);
        self
    }

    /// Set user identifier
    pub fn with_user(mut self, user: impl Into<String>) -> Self {
        self.user = Some(user.into());
        self
    }
}

/// Response from a completion request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletionResponse {
    /// The generated content
    pub content: String,
    /// The model that generated the response
    pub model: String,
    /// Token usage information
    pub usage: Usage,
    /// Finish reason (e.g., "stop", "length", "content_filter")
    pub finish_reason: Option<String>,
    /// Unique identifier for the completion
    pub id: Option<String>,
}

impl CompletionResponse {
    /// Create a new completion response
    pub fn new(content: impl Into<String>, model: impl Into<String>, usage: Usage) -> Self {
        Self {
            content: content.into(),
            model: model.into(),
            usage,
            finish_reason: None,
            id: None,
        }
    }

    /// Set the finish reason
    pub fn with_finish_reason(mut self, reason: impl Into<String>) -> Self {
        self.finish_reason = Some(reason.into());
        self
    }

    /// Set the completion ID
    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }
}

/// A chunk of a streaming response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamChunk {
    /// The content delta for this chunk
    pub content: String,
    /// The model generating the response
    pub model: Option<String>,
    /// Finish reason if this is the final chunk
    pub finish_reason: Option<String>,
    /// Chunk index
    pub index: usize,
}

impl StreamChunk {
    /// Create a new stream chunk
    pub fn new(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            model: None,
            finish_reason: None,
            index: 0,
        }
    }

    /// Set the model
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self
    }

    /// Set the finish reason
    pub fn with_finish_reason(mut self, reason: impl Into<String>) -> Self {
        self.finish_reason = Some(reason.into());
        self
    }

    /// Set the chunk index
    pub fn with_index(mut self, index: usize) -> Self {
        self.index = index;
        self
    }

    /// Check if this is the final chunk
    pub fn is_final(&self) -> bool {
        self.finish_reason.is_some()
    }
}

/// Configuration for an LLM provider
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Base URL for the API (e.g., "https://api.openai.com/v1" or "http://localhost:4000")
    pub api_base_url: String,
    /// API key for authentication
    pub api_key: Option<String>,
    /// Default model to use if not specified in request
    pub default_model: Option<String>,
    /// Timeout for requests in seconds
    pub timeout_secs: u64,
    /// Maximum number of retries for failed requests
    pub max_retries: u32,
    /// Organization ID (for OpenAI)
    pub organization: Option<String>,
}

impl LlmConfig {
    /// Create a new configuration with the given base URL and API key
    pub fn new(api_base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            api_base_url: api_base_url.into(),
            api_key: Some(api_key.into()),
            default_model: None,
            timeout_secs: 60,
            max_retries: 3,
            organization: None,
        }
    }

    /// Create a configuration without an API key (for local models)
    pub fn without_auth(api_base_url: impl Into<String>) -> Self {
        Self {
            api_base_url: api_base_url.into(),
            api_key: None,
            default_model: None,
            timeout_secs: 60,
            max_retries: 3,
            organization: None,
        }
    }

    /// Set the default model
    pub fn with_default_model(mut self, model: impl Into<String>) -> Self {
        self.default_model = Some(model.into());
        self
    }

    /// Set the timeout in seconds
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Set the maximum number of retries
    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    /// Set the organization ID
    pub fn with_organization(mut self, organization: impl Into<String>) -> Self {
        self.organization = Some(organization.into());
        self
    }

    /// Get the timeout as a Duration
    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            api_base_url: "http://localhost:4000".to_string(),
            api_key: None,
            default_model: None,
            timeout_secs: 60,
            max_retries: 3,
            organization: None,
        }
    }
}

/// Trait for LLM providers
///
/// This trait defines the interface for interacting with LLM backends.
/// Implementations can support various providers like OpenAI, LiteLLM, Ollama, etc.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Generate a completion for the given request
    ///
    /// # Arguments
    /// * `request` - The completion request with messages and parameters
    ///
    /// # Returns
    /// * `Ok(CompletionResponse)` - The generated completion
    /// * `Err(LlmError)` - An error if the request failed
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError>;

    /// Generate a streaming completion for the given request
    ///
    /// # Arguments
    /// * `request` - The completion request with messages and parameters
    ///
    /// # Returns
    /// * `Ok(Stream)` - A stream of completion chunks
    /// * `Err(LlmError)` - An error if the request failed
    async fn complete_streaming(
        &self,
        request: CompletionRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamChunk, LlmError>> + Send>>, LlmError>;

    /// Generate embeddings for the given texts
    ///
    /// # Arguments
    /// * `texts` - The texts to embed
    ///
    /// # Returns
    /// * `Ok(Vec<Vec<f32>>)` - The embedding vectors
    /// * `Err(LlmError)` - An error if the request failed
    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>, LlmError>;

    /// Get the name of this provider
    fn name(&self) -> &str;

    /// Check if the provider is available and properly configured
    async fn health_check(&self) -> Result<(), LlmError> {
        // Default implementation: try a simple completion
        let request = CompletionRequest::new("gpt-3.5-turbo")
            .with_message(Message::user("ping"))
            .with_max_tokens(1);
        self.complete(request).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let system = Message::system("You are helpful");
        assert_eq!(system.role, Role::System);
        assert_eq!(system.content, "You are helpful");

        let user = Message::user("Hello");
        assert_eq!(user.role, Role::User);
        assert_eq!(user.content, "Hello");

        let assistant = Message::assistant("Hi there!");
        assert_eq!(assistant.role, Role::Assistant);
        assert_eq!(assistant.content, "Hi there!");

        let function = Message::function("get_weather", r#"{"temp": 72}"#);
        assert_eq!(function.role, Role::Function);
        assert_eq!(function.name, Some("get_weather".to_string()));
    }

    #[test]
    fn test_completion_request_builder() {
        let request = CompletionRequest::new("gpt-4")
            .with_message(Message::system("Be helpful"))
            .with_message(Message::user("Hello"))
            .with_temperature(0.7)
            .with_max_tokens(100)
            .with_stop_sequences(vec!["END".to_string()]);

        assert_eq!(request.model, "gpt-4");
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.temperature, Some(0.7));
        assert_eq!(request.max_tokens, Some(100));
        assert_eq!(request.stop, Some(vec!["END".to_string()]));
    }

    #[test]
    fn test_usage_calculation() {
        let usage = Usage::new(100, 50);
        assert_eq!(usage.prompt_tokens, 100);
        assert_eq!(usage.completion_tokens, 50);
        assert_eq!(usage.total_tokens, 150);
    }

    #[test]
    fn test_llm_config_builder() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test")
            .with_default_model("gpt-4")
            .with_timeout(120)
            .with_max_retries(5)
            .with_organization("org-123");

        assert_eq!(config.api_base_url, "https://api.openai.com/v1");
        assert_eq!(config.api_key, Some("sk-test".to_string()));
        assert_eq!(config.default_model, Some("gpt-4".to_string()));
        assert_eq!(config.timeout_secs, 120);
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.organization, Some("org-123".to_string()));
    }

    #[test]
    fn test_llm_config_without_auth() {
        let config = LlmConfig::without_auth("http://localhost:11434");
        assert_eq!(config.api_base_url, "http://localhost:11434");
        assert_eq!(config.api_key, None);
    }

    #[test]
    fn test_stream_chunk() {
        let chunk = StreamChunk::new("Hello").with_model("gpt-4").with_index(0);

        assert_eq!(chunk.content, "Hello");
        assert_eq!(chunk.model, Some("gpt-4".to_string()));
        assert_eq!(chunk.index, 0);
        assert!(!chunk.is_final());

        let final_chunk = StreamChunk::new("").with_finish_reason("stop");
        assert!(final_chunk.is_final());
    }

    #[test]
    fn test_llm_error_display() {
        let err = LlmError::ApiError {
            status: 429,
            message: "Rate limit exceeded".to_string(),
        };
        assert!(err.to_string().contains("429"));
        assert!(err.to_string().contains("Rate limit"));

        let timeout = LlmError::Timeout;
        assert!(timeout.to_string().contains("timed out"));
    }

    #[test]
    fn test_role_serialization() {
        assert_eq!(serde_json::to_string(&Role::System).unwrap(), "\"system\"");
        assert_eq!(serde_json::to_string(&Role::User).unwrap(), "\"user\"");
        assert_eq!(
            serde_json::to_string(&Role::Assistant).unwrap(),
            "\"assistant\""
        );
    }

    #[test]
    fn test_message_serialization() {
        let msg = Message::user("Hello world");
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"role\":\"user\""));
        assert!(json.contains("\"content\":\"Hello world\""));
        // name should be omitted when None
        assert!(!json.contains("name"));
    }
}
