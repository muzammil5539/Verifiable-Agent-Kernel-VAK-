//! Mock LLM provider for testing
//!
//! This module provides a mock LLM provider that can be configured to return
//! specific responses, making it useful for testing code that depends on LLM providers.

use async_trait::async_trait;
use futures::Stream;
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::traits::{
    CompletionRequest, CompletionResponse, LlmError, LlmProvider, StreamChunk, Usage,
};

/// A configurable mock response
#[derive(Debug, Clone)]
pub struct MockResponse {
    /// The content to return
    pub content: String,
    /// Optional error to return instead of content
    pub error: Option<LlmError>,
    /// Simulated token usage
    pub usage: Usage,
    /// Model name to return
    pub model: String,
    /// Finish reason
    pub finish_reason: Option<String>,
    /// Delay before returning response (in milliseconds)
    pub delay_ms: u64,
}

impl MockResponse {
    /// Create a successful mock response with the given content
    pub fn success(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            error: None,
            usage: Usage::new(10, 20),
            model: "mock-model".to_string(),
            finish_reason: Some("stop".to_string()),
            delay_ms: 0,
        }
    }

    /// Create a mock response that returns an error
    pub fn error(error: LlmError) -> Self {
        Self {
            content: String::new(),
            error: Some(error),
            usage: Usage::default(),
            model: String::new(),
            finish_reason: None,
            delay_ms: 0,
        }
    }

    /// Set the model name
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Set the token usage
    pub fn with_usage(mut self, prompt_tokens: usize, completion_tokens: usize) -> Self {
        self.usage = Usage::new(prompt_tokens, completion_tokens);
        self
    }

    /// Set the finish reason
    pub fn with_finish_reason(mut self, reason: impl Into<String>) -> Self {
        self.finish_reason = Some(reason.into());
        self
    }

    /// Set a delay before returning the response
    pub fn with_delay(mut self, delay_ms: u64) -> Self {
        self.delay_ms = delay_ms;
        self
    }
}

impl Default for MockResponse {
    fn default() -> Self {
        Self::success("Mock response")
    }
}

/// A recorded call to the mock provider
#[derive(Debug, Clone)]
pub struct RecordedCall {
    /// The request that was made
    pub request: CompletionRequest,
    /// Timestamp when the call was made
    pub timestamp: std::time::Instant,
}

/// Mock embeddings configuration
#[derive(Debug, Clone)]
pub struct MockEmbeddings {
    /// The dimension of embedding vectors
    pub dimension: usize,
    /// Optional error to return
    pub error: Option<LlmError>,
    /// Custom embeddings to return (if set, ignores dimension)
    pub custom: Option<Vec<Vec<f32>>>,
}

impl Default for MockEmbeddings {
    fn default() -> Self {
        Self {
            dimension: 1536,
            error: None,
            custom: None,
        }
    }
}

/// Mock LLM provider for testing
///
/// This provider can be configured to return specific responses and records
/// all calls for later inspection.
///
/// # Example
///
/// ```rust
/// use vak::llm::{MockLlmProvider, MockResponse, LlmProvider, CompletionRequest, Message};
///
/// #[tokio::main]
/// async fn main() {
///     let mock = MockLlmProvider::new()
///         .with_response(MockResponse::success("Hello!"));
///     
///     let request = CompletionRequest::new("test-model")
///         .with_message(Message::user("Hi"));
///     
///     let response = mock.complete(request).await.unwrap();
///     assert_eq!(response.content, "Hello!");
///     
///     // Check that the call was recorded
///     assert_eq!(mock.call_count(), 1);
/// }
/// ```
#[derive(Clone)]
pub struct MockLlmProvider {
    /// Queue of responses to return
    responses: Arc<Mutex<VecDeque<MockResponse>>>,
    /// Default response when queue is empty
    default_response: Arc<Mutex<MockResponse>>,
    /// Recorded calls
    calls: Arc<Mutex<Vec<RecordedCall>>>,
    /// Embeddings configuration
    embeddings: Arc<Mutex<MockEmbeddings>>,
    /// Provider name
    name: String,
}

impl std::fmt::Debug for MockLlmProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockLlmProvider")
            .field("name", &self.name)
            .field("call_count", &self.call_count())
            .field("queued_responses", &self.responses.lock().unwrap().len())
            .finish()
    }
}

impl MockLlmProvider {
    /// Create a new mock provider with default settings
    pub fn new() -> Self {
        Self {
            responses: Arc::new(Mutex::new(VecDeque::new())),
            default_response: Arc::new(Mutex::new(MockResponse::default())),
            calls: Arc::new(Mutex::new(Vec::new())),
            embeddings: Arc::new(Mutex::new(MockEmbeddings::default())),
            name: "MockLlmProvider".to_string(),
        }
    }

    /// Create a mock provider that always returns the given content
    pub fn always(content: impl Into<String>) -> Self {
        let provider = Self::new();
        *provider.default_response.lock().unwrap() = MockResponse::success(content);
        provider
    }

    /// Create a mock provider that always returns an error
    pub fn always_error(error: LlmError) -> Self {
        let provider = Self::new();
        *provider.default_response.lock().unwrap() = MockResponse::error(error);
        provider
    }

    /// Set the provider name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Add a response to the queue
    ///
    /// Responses are returned in order. When the queue is empty,
    /// the default response is used.
    pub fn with_response(self, response: MockResponse) -> Self {
        self.responses.lock().unwrap().push_back(response);
        self
    }

    /// Add multiple responses to the queue
    pub fn with_responses(self, responses: impl IntoIterator<Item = MockResponse>) -> Self {
        let mut queue = self.responses.lock().unwrap();
        for response in responses {
            queue.push_back(response);
        }
        drop(queue);
        self
    }

    /// Set the default response (used when queue is empty)
    pub fn with_default_response(self, response: MockResponse) -> Self {
        *self.default_response.lock().unwrap() = response;
        self
    }

    /// Configure embeddings behavior
    pub fn with_embeddings(self, embeddings: MockEmbeddings) -> Self {
        *self.embeddings.lock().unwrap() = embeddings;
        self
    }

    /// Set the embedding dimension
    pub fn with_embedding_dimension(self, dimension: usize) -> Self {
        self.embeddings.lock().unwrap().dimension = dimension;
        self
    }

    /// Set custom embeddings to return
    pub fn with_custom_embeddings(self, embeddings: Vec<Vec<f32>>) -> Self {
        self.embeddings.lock().unwrap().custom = Some(embeddings);
        self
    }

    /// Get the number of calls made to this provider
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    /// Get all recorded calls
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().unwrap().clone()
    }

    /// Get the last call made to this provider
    pub fn last_call(&self) -> Option<RecordedCall> {
        self.calls.lock().unwrap().last().cloned()
    }

    /// Clear all recorded calls
    pub fn clear_calls(&self) {
        self.calls.lock().unwrap().clear();
    }

    /// Clear the response queue
    pub fn clear_responses(&self) {
        self.responses.lock().unwrap().clear();
    }

    /// Reset the provider to its initial state
    pub fn reset(&self) {
        self.clear_calls();
        self.clear_responses();
    }

    /// Get the next response (from queue or default)
    fn get_next_response(&self) -> MockResponse {
        let mut queue = self.responses.lock().unwrap();
        queue
            .pop_front()
            .unwrap_or_else(|| self.default_response.lock().unwrap().clone())
    }

    /// Record a call
    fn record_call(&self, request: CompletionRequest) {
        self.calls.lock().unwrap().push(RecordedCall {
            request,
            timestamp: std::time::Instant::now(),
        });
    }
}

impl Default for MockLlmProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmProvider for MockLlmProvider {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse, LlmError> {
        self.record_call(request.clone());

        let response = self.get_next_response();

        // Apply delay if configured
        if response.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(response.delay_ms)).await;
        }

        // Return error if configured
        if let Some(error) = response.error {
            return Err(error);
        }

        // Use the model from request or response
        let model = if request.model.is_empty() {
            response.model
        } else {
            request.model
        };

        Ok(CompletionResponse {
            content: response.content,
            model,
            usage: response.usage,
            finish_reason: response.finish_reason,
            id: Some(format!("mock-{}", uuid::Uuid::new_v4())),
        })
    }

    async fn complete_streaming(
        &self,
        request: CompletionRequest,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamChunk, LlmError>> + Send>>, LlmError> {
        self.record_call(request.clone());

        let response = self.get_next_response();

        // Return error if configured
        if let Some(error) = response.error {
            return Err(error);
        }

        // Create a channel to send chunks
        let (tx, rx) = mpsc::channel(100);
        let content = response.content.clone();
        let model = if request.model.is_empty() {
            response.model.clone()
        } else {
            request.model.clone()
        };
        let delay_ms = response.delay_ms;
        let finish_reason = response.finish_reason.clone();

        // Spawn a task to send chunks
        tokio::spawn(async move {
            // Split content into words for streaming simulation
            let words: Vec<&str> = content.split_whitespace().collect();

            for (i, word) in words.iter().enumerate() {
                if delay_ms > 0 {
                    // Distribute delay across chunks
                    let chunk_delay = delay_ms / (words.len() as u64).max(1);
                    tokio::time::sleep(std::time::Duration::from_millis(chunk_delay)).await;
                }

                // Add space before word (except first word)
                let chunk_content = if i == 0 {
                    word.to_string()
                } else {
                    format!(" {}", word)
                };

                let chunk = StreamChunk {
                    content: chunk_content,
                    model: Some(model.clone()),
                    finish_reason: None,
                    index: i,
                };

                if tx.send(Ok(chunk)).await.is_err() {
                    return;
                }
            }

            // Send final chunk
            let final_chunk = StreamChunk {
                content: String::new(),
                model: Some(model),
                finish_reason,
                index: words.len(),
            };
            let _ = tx.send(Ok(final_chunk)).await;
        });

        Ok(Box::pin(ReceiverStream::new(rx)))
    }

    async fn embed(&self, texts: Vec<String>) -> Result<Vec<Vec<f32>>, LlmError> {
        let embeddings = self.embeddings.lock().unwrap().clone();

        // Return error if configured
        if let Some(error) = embeddings.error {
            return Err(error);
        }

        // Return custom embeddings if set
        if let Some(custom) = embeddings.custom {
            return Ok(custom);
        }

        // Generate deterministic mock embeddings
        let result = texts
            .iter()
            .enumerate()
            .map(|(i, text)| {
                // Generate a simple deterministic embedding based on text
                let seed = text.len() as f32 + i as f32;
                (0..embeddings.dimension)
                    .map(|j| {
                        
                        ((seed + j as f32) * 0.1).sin() * 0.5
                    })
                    .collect()
            })
            .collect();

        Ok(result)
    }

    fn name(&self) -> &str {
        &self.name
    }

    async fn health_check(&self) -> Result<(), LlmError> {
        // Mock health check always succeeds unless configured otherwise
        let response = self.default_response.lock().unwrap().clone();
        if let Some(error) = response.error {
            Err(error)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::Message;

    #[tokio::test]
    async fn test_mock_provider_basic() {
        let mock = MockLlmProvider::new().with_response(MockResponse::success("Hello!"));

        let request = CompletionRequest::new("test-model").with_message(Message::user("Hi"));

        let response = mock.complete(request).await.unwrap();
        assert_eq!(response.content, "Hello!");
        assert_eq!(mock.call_count(), 1);
    }

    #[tokio::test]
    async fn test_mock_provider_always() {
        let mock = MockLlmProvider::always("Always this response");

        for _ in 0..3 {
            let request = CompletionRequest::new("test").with_message(Message::user("test"));
            let response = mock.complete(request).await.unwrap();
            assert_eq!(response.content, "Always this response");
        }

        assert_eq!(mock.call_count(), 3);
    }

    #[tokio::test]
    async fn test_mock_provider_error() {
        let mock = MockLlmProvider::always_error(LlmError::Timeout);

        let request = CompletionRequest::new("test").with_message(Message::user("test"));
        let result = mock.complete(request).await;

        assert!(matches!(result, Err(LlmError::Timeout)));
    }

    #[tokio::test]
    async fn test_mock_provider_queue() {
        let mock = MockLlmProvider::new()
            .with_response(MockResponse::success("First"))
            .with_response(MockResponse::success("Second"))
            .with_default_response(MockResponse::success("Default"));

        let request = || CompletionRequest::new("test").with_message(Message::user("test"));

        assert_eq!(mock.complete(request()).await.unwrap().content, "First");
        assert_eq!(mock.complete(request()).await.unwrap().content, "Second");
        assert_eq!(mock.complete(request()).await.unwrap().content, "Default");
        assert_eq!(mock.complete(request()).await.unwrap().content, "Default");
    }

    #[tokio::test]
    async fn test_mock_provider_call_recording() {
        let mock = MockLlmProvider::new();

        let request1 = CompletionRequest::new("model1")
            .with_message(Message::system("You are helpful"))
            .with_message(Message::user("Hello"));

        let request2 = CompletionRequest::new("model2").with_message(Message::user("Goodbye"));

        mock.complete(request1).await.unwrap();
        mock.complete(request2).await.unwrap();

        let calls = mock.calls();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].request.model, "model1");
        assert_eq!(calls[0].request.messages.len(), 2);
        assert_eq!(calls[1].request.model, "model2");
        assert_eq!(calls[1].request.messages.len(), 1);
    }

    #[tokio::test]
    async fn test_mock_provider_last_call() {
        let mock = MockLlmProvider::new();

        let request = CompletionRequest::new("test")
            .with_message(Message::user("Hello"))
            .with_temperature(0.7);

        mock.complete(request).await.unwrap();

        let last = mock.last_call().unwrap();
        assert_eq!(last.request.model, "test");
        assert_eq!(last.request.temperature, Some(0.7));
    }

    #[tokio::test]
    async fn test_mock_provider_reset() {
        let mock = MockLlmProvider::new()
            .with_response(MockResponse::success("One"))
            .with_response(MockResponse::success("Two"));

        let request = || CompletionRequest::new("test").with_message(Message::user("test"));

        mock.complete(request()).await.unwrap();
        assert_eq!(mock.call_count(), 1);

        mock.reset();

        assert_eq!(mock.call_count(), 0);
        // Queue should be empty, so default response
        assert_eq!(
            mock.complete(request()).await.unwrap().content,
            "Mock response"
        );
    }

    #[tokio::test]
    async fn test_mock_provider_streaming() {
        use futures::StreamExt;

        let mock =
            MockLlmProvider::new().with_response(MockResponse::success("Hello world streaming"));

        let request = CompletionRequest::new("test").with_message(Message::user("test"));

        let mut stream = mock.complete_streaming(request).await.unwrap();
        let mut content = String::new();

        while let Some(chunk) = stream.next().await {
            let chunk = chunk.unwrap();
            content.push_str(&chunk.content);
        }

        assert_eq!(content, "Hello world streaming");
    }

    #[tokio::test]
    async fn test_mock_provider_embeddings() {
        let mock = MockLlmProvider::new().with_embedding_dimension(768);

        let texts = vec!["Hello".to_string(), "World".to_string()];
        let embeddings = mock.embed(texts).await.unwrap();

        assert_eq!(embeddings.len(), 2);
        assert_eq!(embeddings[0].len(), 768);
        assert_eq!(embeddings[1].len(), 768);
    }

    #[tokio::test]
    async fn test_mock_provider_custom_embeddings() {
        let custom = vec![vec![0.1, 0.2, 0.3], vec![0.4, 0.5, 0.6]];

        let mock = MockLlmProvider::new().with_custom_embeddings(custom.clone());

        let texts = vec!["a".to_string(), "b".to_string()];
        let embeddings = mock.embed(texts).await.unwrap();

        assert_eq!(embeddings, custom);
    }

    #[tokio::test]
    async fn test_mock_provider_embeddings_error() {
        let mock = MockLlmProvider::new().with_embeddings(MockEmbeddings {
            dimension: 1536,
            error: Some(LlmError::ApiError {
                status: 500,
                message: "Embedding service unavailable".to_string(),
            }),
            custom: None,
        });

        let result = mock.embed(vec!["test".to_string()]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mock_provider_delay() {
        let mock =
            MockLlmProvider::new().with_response(MockResponse::success("Delayed").with_delay(100));

        let request = CompletionRequest::new("test").with_message(Message::user("test"));

        let start = std::time::Instant::now();
        mock.complete(request).await.unwrap();
        let elapsed = start.elapsed();

        assert!(elapsed >= std::time::Duration::from_millis(100));
    }

    #[tokio::test]
    async fn test_mock_provider_with_usage() {
        let mock = MockLlmProvider::new()
            .with_response(MockResponse::success("Response").with_usage(50, 100));

        let request = CompletionRequest::new("test").with_message(Message::user("test"));

        let response = mock.complete(request).await.unwrap();
        assert_eq!(response.usage.prompt_tokens, 50);
        assert_eq!(response.usage.completion_tokens, 100);
        assert_eq!(response.usage.total_tokens, 150);
    }

    #[tokio::test]
    async fn test_mock_provider_health_check() {
        let mock = MockLlmProvider::new();
        assert!(mock.health_check().await.is_ok());

        let failing_mock = MockLlmProvider::always_error(LlmError::Timeout);
        assert!(failing_mock.health_check().await.is_err());
    }

    #[test]
    fn test_mock_provider_debug() {
        let mock = MockLlmProvider::new()
            .with_name("TestProvider")
            .with_response(MockResponse::success("test"));

        let debug = format!("{:?}", mock);
        assert!(debug.contains("TestProvider"));
    }
}
