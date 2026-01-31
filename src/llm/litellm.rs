//! LiteLLM/OpenAI-compatible API client implementation
//!
//! This module provides a client that works with any OpenAI-compatible API,
//! including LiteLLM proxy, OpenAI, Azure OpenAI, Ollama, and others.

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::traits::{
    CompletionRequest, CompletionResponse, LlmConfig, LlmError, LlmProvider, Message, StreamChunk,
    Usage,
};

/// OpenAI-compatible API client
///
/// This client works with:
/// - LiteLLM proxy (recommended for multi-provider support)
/// - OpenAI API directly
/// - Azure OpenAI
/// - Ollama (with OpenAI compatibility mode)
/// - Any other OpenAI-compatible endpoint
#[derive(Debug)]
pub struct LiteLlmClient {
    client: Client,
    config: LlmConfig,
}

// OpenAI API response structures
#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    id: Option<String>,
    model: String,
    choices: Vec<OpenAiChoice>,
    usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: Option<OpenAiMessage>,
    delta: Option<OpenAiDelta>,
    finish_reason: Option<String>,
    #[allow(dead_code)]
    index: usize,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    #[allow(dead_code)]
    role: String,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiDelta {
    #[allow(dead_code)]
    role: Option<String>,
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: usize,
    completion_tokens: usize,
    total_tokens: usize,
}

#[derive(Debug, Deserialize)]
struct OpenAiError {
    error: OpenAiErrorDetail,
}

#[derive(Debug, Deserialize)]
struct OpenAiErrorDetail {
    message: String,
    #[serde(rename = "type")]
    error_type: Option<String>,
    code: Option<String>,
}

// Embedding structures
#[derive(Debug, Serialize)]
struct EmbeddingRequest {
    input: Vec<String>,
    model: String,
}

#[derive(Debug, Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
    #[allow(dead_code)]
    usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
    index: usize,
}

impl LiteLlmClient {
    /// Create a new LiteLLM client with the given configuration
    ///
    /// # Arguments
    /// * `config` - The LLM configuration
    ///
    /// # Returns
    /// * `Ok(LiteLlmClient)` - The configured client
    /// * `Err(LlmError)` - If the client could not be created
    pub fn new(config: LlmConfig) -> Result<Self, LlmError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| LlmError::ConfigError(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { client, config })
    }

    /// Create a client for OpenAI API
    pub fn openai(api_key: impl Into<String>) -> Result<Self, LlmError> {
        let config = LlmConfig::new("https://api.openai.com/v1", api_key)
            .with_default_model("gpt-3.5-turbo");
        Self::new(config)
    }

    /// Create a client for a local LiteLLM proxy
    pub fn litellm_proxy(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Result<Self, LlmError> {
        let config = LlmConfig::new(base_url, api_key);
        Self::new(config)
    }

    /// Create a client for local Ollama
    pub fn ollama(model: impl Into<String>) -> Result<Self, LlmError> {
        let config = LlmConfig::without_auth("http://localhost:11434/v1").with_default_model(model);
        Self::new(config)
    }

    /// Get the completion endpoint URL
    fn completion_url(&self) -> String {
        format!(
            "{}/chat/completions",
            self.config.api_base_url.trim_end_matches('/')
        )
    }

    /// Get the embeddings endpoint URL
    fn embeddings_url(&self) -> String {
        format!(
            "{}/embeddings",
            self.config.api_base_url.trim_end_matches('/')
        )
    }

    /// Build the authorization headers
    fn auth_headers(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut builder = builder;

        if let Some(ref api_key) = self.config.api_key {
            builder = builder.header("Authorization", format!("Bearer {}", api_key));
        }

        if let Some(ref org) = self.config.organization {
            builder = builder.header("OpenAI-Organization", org);
        }

        builder
    }

    /// Parse an error response from the API
    fn parse_error(&self, status: StatusCode, body: &str) -> LlmError {
        // Try to parse as OpenAI error format
        if let Ok(error) = serde_json::from_str::<OpenAiError>(body) {
            let message = error.error.message;

            // Check for specific error types
            if let Some(ref error_type) = error.error.error_type {
                if error_type == "insufficient_quota" || error_type == "rate_limit_exceeded" {
                    return LlmError::RateLimited { retry_after: None };
                }
            }

            if let Some(ref code) = error.error.code {
                if code == "model_not_found" {
                    return LlmError::ModelNotFound(message);
                }
                if code == "context_length_exceeded" {
                    return LlmError::ContextLengthExceeded {
                        max_tokens: 0,
                        requested: 0,
                    };
                }
            }

            return match status {
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                    LlmError::AuthenticationError(message)
                }
                StatusCode::TOO_MANY_REQUESTS => LlmError::RateLimited { retry_after: None },
                _ => LlmError::ApiError {
                    status: status.as_u16(),
                    message,
                },
            };
        }

        // Fallback to generic error
        LlmError::ApiError {
            status: status.as_u16(),
            message: body.to_string(),
        }
    }

    /// Execute a request with retries
    async fn execute_with_retry<T, F, Fut>(&self, mut operation: F) -> Result<T, LlmError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, LlmError>>,
    {
        let mut last_error = LlmError::RequestError("No attempts made".to_string());
        let mut retry_delay = Duration::from_millis(500);

        for attempt in 0..=self.config.max_retries {
            match operation().await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    last_error = e.clone();

                    // Don't retry on certain errors
                    match &e {
                        LlmError::AuthenticationError(_)
                        | LlmError::ConfigError(_)
                        | LlmError::ModelNotFound(_)
                        | LlmError::ContextLengthExceeded { .. } => {
                            return Err(e);
                        }
                        LlmError::RateLimited { retry_after } => {
                            if let Some(duration) = retry_after {
                                retry_delay = *duration;
                            }
                        }
                        _ => {}
                    }

                    if attempt < self.config.max_retries {
                        tokio::time::sleep(retry_delay).await;
                        retry_delay *= 2; // Exponential backoff
                    }
                }
            }
        }

        Err(last_error)
    }
}

#[async_trait]
impl LlmProvider for LiteLlmClient {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        self.execute_with_retry(|| async {
            let url = self.completion_url();

            // Build the request
            let mut req = CompletionRequest {
                stream: Some(false),
                ..request.clone()
            };

            // Use default model if not specified
            if req.model.is_empty() {
                if let Some(ref default_model) = self.config.default_model {
                    req.model = default_model.clone();
                } else {
                    return Err(LlmError::ConfigError(
                        "No model specified and no default model configured".to_string(),
                    ));
                }
            }

            let request_builder = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&req);

            let request_builder = self.auth_headers(request_builder);

            let response = request_builder.send().await.map_err(|e| {
                if e.is_timeout() {
                    LlmError::Timeout
                } else {
                    LlmError::RequestError(e.to_string())
                }
            })?;

            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|e| LlmError::ParseError(e.to_string()))?;

            if !status.is_success() {
                return Err(self.parse_error(status, &body));
            }

            let api_response: OpenAiResponse = serde_json::from_str(&body)
                .map_err(|e| LlmError::ParseError(format!("Failed to parse response: {}", e)))?;

            let choice = api_response
                .choices
                .first()
                .ok_or_else(|| LlmError::ParseError("No choices in response".to_string()))?;

            let content = choice
                .message
                .as_ref()
                .and_then(|m| m.content.clone())
                .unwrap_or_default();

            let usage = api_response
                .usage
                .map(|u| Usage {
                    prompt_tokens: u.prompt_tokens,
                    completion_tokens: u.completion_tokens,
                    total_tokens: u.total_tokens,
                })
                .unwrap_or_default();

            Ok(CompletionResponse {
                content,
                model: api_response.model,
                usage,
                finish_reason: choice.finish_reason.clone(),
                id: api_response.id,
            })
        })
        .await
    }

    async fn complete_streaming(
        &self,
        request: CompletionRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamChunk, LlmError>> + Send>>, LlmError> {
        let url = self.completion_url();

        // Build the request with streaming enabled
        let mut req = CompletionRequest {
            stream: Some(true),
            ..request
        };

        // Use default model if not specified
        if req.model.is_empty() {
            if let Some(ref default_model) = self.config.default_model {
                req.model = default_model.clone();
            } else {
                return Err(LlmError::ConfigError(
                    "No model specified and no default model configured".to_string(),
                ));
            }
        }

        let request_builder = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&req);

        let request_builder = self.auth_headers(request_builder);

        let response = request_builder.send().await.map_err(|e| {
            if e.is_timeout() {
                LlmError::Timeout
            } else {
                LlmError::RequestError(e.to_string())
            }
        })?;

        let status = response.status();
        if !status.is_success() {
            let body = response
                .text()
                .await
                .map_err(|e| LlmError::ParseError(e.to_string()))?;
            return Err(self.parse_error(status, &body));
        }

        // Create a channel to send chunks
        let (tx, rx) = mpsc::channel(100);

        // Spawn a task to process the SSE stream
        let bytes_stream = response.bytes_stream();
        tokio::spawn(async move {
            let mut stream = bytes_stream;
            let mut buffer = String::new();
            let mut chunk_index = 0usize;

            while let Some(chunk_result) = stream.next().await {
                match chunk_result {
                    Ok(bytes) => {
                        let text = String::from_utf8_lossy(&bytes);
                        buffer.push_str(&text);

                        // Process complete SSE events
                        while let Some(event_end) = buffer.find("\n\n") {
                            let event = buffer[..event_end].to_string();
                            buffer = buffer[event_end + 2..].to_string();

                            // Parse SSE data lines
                            for line in event.lines() {
                                if let Some(data) = line.strip_prefix("data: ") {
                                    if data == "[DONE]" {
                                        return;
                                    }

                                    match serde_json::from_str::<OpenAiResponse>(data) {
                                        Ok(response) => {
                                            if let Some(choice) = response.choices.first() {
                                                let content = choice
                                                    .delta
                                                    .as_ref()
                                                    .and_then(|d| d.content.clone())
                                                    .unwrap_or_default();

                                                let chunk = StreamChunk {
                                                    content,
                                                    model: Some(response.model.clone()),
                                                    finish_reason: choice.finish_reason.clone(),
                                                    index: chunk_index,
                                                };
                                                chunk_index += 1;

                                                if tx.send(Ok(chunk)).await.is_err() {
                                                    return;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            // Only send error for non-empty data
                                            if !data.trim().is_empty() {
                                                let _ = tx
                                                    .send(Err(LlmError::ParseError(format!(
                                                        "Failed to parse SSE data: {}",
                                                        e
                                                    ))))
                                                    .await;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        let _ = tx.send(Err(LlmError::StreamError(e.to_string()))).await;
                        return;
                    }
                }
            }
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>, LlmError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        self.execute_with_retry(|| async {
            let url = self.embeddings_url();

            // Determine the embedding model
            let model = self
                .config
                .default_model
                .clone()
                .unwrap_or_else(|| "text-embedding-ada-002".to_string());

            let request = EmbeddingRequest {
                input: texts.clone(),
                model,
            };

            let request_builder = self
                .client
                .post(&url)
                .header("Content-Type", "application/json")
                .json(&request);

            let request_builder = self.auth_headers(request_builder);

            let response = request_builder.send().await.map_err(|e| {
                if e.is_timeout() {
                    LlmError::Timeout
                } else {
                    LlmError::RequestError(e.to_string())
                }
            })?;

            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|e| LlmError::ParseError(e.to_string()))?;

            if !status.is_success() {
                return Err(self.parse_error(status, &body));
            }

            let api_response: EmbeddingResponse = serde_json::from_str(&body)
                .map_err(|e| LlmError::ParseError(format!("Failed to parse response: {}", e)))?;

            // Sort by index to ensure correct order
            let mut embeddings: Vec<_> = api_response.data.into_iter().collect();
            embeddings.sort_by_key(|e| e.index);

            Ok(embeddings.into_iter().map(|e| e.embedding).collect())
        })
        .await
    }

    fn name(&self) -> &str {
        "LiteLLM/OpenAI-compatible"
    }

    async fn health_check(&self) -> Result<(), LlmError> {
        // Try to list models as a lightweight health check
        let url = format!("{}/models", self.config.api_base_url.trim_end_matches('/'));

        let request_builder = self.client.get(&url);
        let request_builder = self.auth_headers(request_builder);

        let response = request_builder.send().await.map_err(|e| {
            if e.is_timeout() {
                LlmError::Timeout
            } else {
                LlmError::RequestError(e.to_string())
            }
        })?;

        if response.status().is_success() {
            Ok(())
        } else {
            // Fall back to default health check
            let request = CompletionRequest::new(
                self.config
                    .default_model
                    .clone()
                    .unwrap_or_else(|| "gpt-3.5-turbo".to_string()),
            )
            .with_message(Message::user("ping"))
            .with_max_tokens(1);
            self.complete(request).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test");
        let client = LiteLlmClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn test_openai_client() {
        let client = LiteLlmClient::openai("sk-test");
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.config.api_base_url, "https://api.openai.com/v1");
    }

    #[test]
    fn test_ollama_client() {
        let client = LiteLlmClient::ollama("llama2");
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.config.api_base_url, "http://localhost:11434/v1");
        assert_eq!(client.config.default_model, Some("llama2".to_string()));
    }

    #[test]
    fn test_completion_url() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test");
        let client = LiteLlmClient::new(config).unwrap();
        assert_eq!(
            client.completion_url(),
            "https://api.openai.com/v1/chat/completions"
        );

        // Test with trailing slash
        let config = LlmConfig::new("https://api.openai.com/v1/", "sk-test");
        let client = LiteLlmClient::new(config).unwrap();
        assert_eq!(
            client.completion_url(),
            "https://api.openai.com/v1/chat/completions"
        );
    }

    #[test]
    fn test_embeddings_url() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test");
        let client = LiteLlmClient::new(config).unwrap();
        assert_eq!(
            client.embeddings_url(),
            "https://api.openai.com/v1/embeddings"
        );
    }

    #[test]
    fn test_parse_error_rate_limit() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test");
        let client = LiteLlmClient::new(config).unwrap();

        let error_body =
            r#"{"error": {"message": "Rate limit exceeded", "type": "rate_limit_exceeded"}}"#;
        let error = client.parse_error(StatusCode::TOO_MANY_REQUESTS, error_body);

        assert!(matches!(error, LlmError::RateLimited { .. }));
    }

    #[test]
    fn test_parse_error_auth() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test");
        let client = LiteLlmClient::new(config).unwrap();

        let error_body = r#"{"error": {"message": "Invalid API key"}}"#;
        let error = client.parse_error(StatusCode::UNAUTHORIZED, error_body);

        assert!(matches!(error, LlmError::AuthenticationError(_)));
    }

    #[test]
    fn test_parse_error_model_not_found() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test");
        let client = LiteLlmClient::new(config).unwrap();

        let error_body = r#"{"error": {"message": "Model not found", "code": "model_not_found"}}"#;
        let error = client.parse_error(StatusCode::NOT_FOUND, error_body);

        assert!(matches!(error, LlmError::ModelNotFound(_)));
    }

    #[tokio::test]
    async fn test_embed_empty() {
        let config = LlmConfig::new("https://api.openai.com/v1", "sk-test");
        let client = LiteLlmClient::new(config).unwrap();

        let result = client.embed(vec![]).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }
}
