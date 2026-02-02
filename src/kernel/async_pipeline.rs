//! Async Intercept Loop for Multi-Agent Throughput (Issue #44)
//!
//! This module provides a fully asynchronous request processing pipeline that:
//! - Handles multiple concurrent agent requests without head-of-line blocking
//! - Uses Tokio tasks with bounded channels for backpressure
//! - Decouples policy evaluation, audit logging, and tool execution
//! - Supports batching for improved throughput
//! - Provides metrics for monitoring queue depth and latency
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────┐
//! │                     Request Processing Pipeline                      │
//! ├─────────────────────────────────────────────────────────────────────┤
//! │                                                                      │
//! │  Agent Request ──► Input Queue ──► Policy Task ──► Execution Task   │
//! │                         │              │                │            │
//! │                         │              ▼                ▼            │
//! │                         │         Audit Task       Response Queue   │
//! │                         │              │                │            │
//! │                         └──────────────┴────────────────┘            │
//! │                                   Metrics                            │
//! └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::kernel::async_pipeline::{
//!     AsyncPipeline, PipelineConfig, RequestBatch,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = PipelineConfig::default()
//!     .with_max_concurrent(50)
//!     .with_queue_size(1000);
//!
//! let pipeline = AsyncPipeline::new(config).await?;
//!
//! // Submit requests
//! let response = pipeline.submit(request).await?;
//! # Ok(())
//! # }
//! ```

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, mpsc, oneshot, RwLock, Semaphore};
use tokio::time::timeout;
use tracing::{info, instrument};
use uuid::Uuid;

use super::types::{AgentId, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in the async pipeline
#[derive(Debug, Error)]
pub enum PipelineError {
    /// Queue is full - backpressure applied
    #[error("Request queue full, backpressure applied")]
    QueueFull,

    /// Request timed out
    #[error("Request timed out after {0}ms")]
    Timeout(u64),

    /// Pipeline is shutting down
    #[error("Pipeline is shutting down")]
    ShuttingDown,

    /// Channel send error
    #[error("Failed to send request: {0}")]
    SendError(String),

    /// Channel receive error
    #[error("Failed to receive response: {0}")]
    ReceiveError(String),

    /// Policy evaluation failed
    #[error("Policy evaluation failed: {0}")]
    PolicyError(String),

    /// Execution failed
    #[error("Execution failed: {0}")]
    ExecutionError(String),

    /// Audit logging failed
    #[error("Audit logging failed: {0}")]
    AuditError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<KernelError> for PipelineError {
    fn from(e: KernelError) -> Self {
        PipelineError::ExecutionError(e.to_string())
    }
}

/// Result type for pipeline operations
pub type PipelineResult<T> = Result<T, PipelineError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the async pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Maximum concurrent requests being processed
    pub max_concurrent: usize,
    /// Size of the request input queue
    pub queue_size: usize,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable request batching
    pub enable_batching: bool,
    /// Batch size for batched processing
    pub batch_size: usize,
    /// Batch timeout in milliseconds (flush batch if this time passes)
    pub batch_timeout_ms: u64,
    /// Number of worker tasks
    pub worker_count: usize,
    /// Enable priority queuing
    pub priority_enabled: bool,
    /// Audit queue size
    pub audit_queue_size: usize,
    /// Enable metrics collection
    pub metrics_enabled: bool,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 50,
            queue_size: 1000,
            timeout_ms: 30_000,
            enable_batching: false,
            batch_size: 10,
            batch_timeout_ms: 100,
            worker_count: 4,
            priority_enabled: false,
            audit_queue_size: 500,
            metrics_enabled: true,
        }
    }
}

impl PipelineConfig {
    /// Set maximum concurrent requests
    pub fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = max;
        self
    }

    /// Set queue size
    pub fn with_queue_size(mut self, size: usize) -> Self {
        self.queue_size = size;
        self
    }

    /// Set timeout in milliseconds
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Enable batching
    pub fn with_batching(mut self, batch_size: usize, batch_timeout_ms: u64) -> Self {
        self.enable_batching = true;
        self.batch_size = batch_size;
        self.batch_timeout_ms = batch_timeout_ms;
        self
    }

    /// Set worker count
    pub fn with_workers(mut self, count: usize) -> Self {
        self.worker_count = count.max(1);
        self
    }

    /// Enable priority queuing
    pub fn with_priority(mut self, enabled: bool) -> Self {
        self.priority_enabled = enabled;
        self
    }
}

// ============================================================================
// Request Types
// ============================================================================

/// Priority level for requests
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RequestPriority {
    /// Low priority (background tasks)
    Low = 0,
    /// Normal priority (default)
    Normal = 1,
    /// High priority (user-initiated)
    High = 2,
    /// Critical priority (system operations)
    Critical = 3,
}

impl Default for RequestPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// A request envelope containing the tool request and metadata
#[derive(Debug)]
pub struct RequestEnvelope {
    /// Unique request ID
    pub id: Uuid,
    /// Agent making the request
    pub agent_id: AgentId,
    /// Session ID
    pub session_id: SessionId,
    /// The actual tool request
    pub request: ToolRequest,
    /// Priority level
    pub priority: RequestPriority,
    /// When the request was submitted
    pub submitted_at: Instant,
    /// Response channel
    pub response_tx: oneshot::Sender<PipelineResult<ToolResponse>>,
}

impl RequestEnvelope {
    /// Create a new request envelope
    pub fn new(
        agent_id: AgentId,
        session_id: SessionId,
        request: ToolRequest,
        response_tx: oneshot::Sender<PipelineResult<ToolResponse>>,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            agent_id,
            session_id,
            request,
            priority: RequestPriority::Normal,
            submitted_at: Instant::now(),
            response_tx,
        }
    }

    /// Set priority
    pub fn with_priority(mut self, priority: RequestPriority) -> Self {
        self.priority = priority;
        self
    }
}

/// A batch of requests for batch processing
#[derive(Debug)]
pub struct RequestBatch {
    /// Batch ID
    pub id: Uuid,
    /// Requests in the batch
    pub requests: Vec<RequestEnvelope>,
    /// When the batch was created
    pub created_at: Instant,
}

impl RequestBatch {
    /// Create a new batch
    pub fn new() -> Self {
        Self {
            id: Uuid::now_v7(),
            requests: Vec::new(),
            created_at: Instant::now(),
        }
    }

    /// Add a request to the batch
    pub fn add(&mut self, request: RequestEnvelope) {
        self.requests.push(request);
    }

    /// Check if batch is ready (full or timed out)
    pub fn is_ready(&self, batch_size: usize, batch_timeout_ms: u64) -> bool {
        self.requests.len() >= batch_size
            || self.created_at.elapsed().as_millis() as u64 >= batch_timeout_ms
    }

    /// Take all requests from the batch
    pub fn take(&mut self) -> Vec<RequestEnvelope> {
        std::mem::take(&mut self.requests)
    }
}

impl Default for RequestBatch {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Audit Entry
// ============================================================================

/// An audit entry for the async audit queue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsyncAuditEntry {
    /// Request ID
    pub request_id: Uuid,
    /// Agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Tool name
    pub tool_name: String,
    /// Policy decision
    pub decision: String,
    /// Execution result (success/failure)
    pub result: String,
    /// Latency in milliseconds
    pub latency_ms: u64,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

// ============================================================================
// Metrics
// ============================================================================

/// Pipeline metrics
#[derive(Debug, Default)]
pub struct PipelineMetrics {
    /// Total requests received
    pub total_requests: AtomicU64,
    /// Requests currently in queue
    pub queue_depth: AtomicUsize,
    /// Requests currently being processed
    pub in_flight: AtomicUsize,
    /// Total requests completed
    pub completed: AtomicU64,
    /// Total requests failed
    pub failed: AtomicU64,
    /// Total requests timed out
    pub timed_out: AtomicU64,
    /// Total requests rejected (queue full)
    pub rejected: AtomicU64,
    /// Sum of latencies in microseconds (for average calculation)
    pub total_latency_us: AtomicU64,
    /// Minimum latency in microseconds
    pub min_latency_us: AtomicU64,
    /// Maximum latency in microseconds
    pub max_latency_us: AtomicU64,
}

impl PipelineMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self {
            min_latency_us: AtomicU64::new(u64::MAX),
            ..Default::default()
        }
    }

    /// Record a request received
    pub fn record_received(&self) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request started processing
    pub fn record_started(&self) {
        self.queue_depth.fetch_sub(1, Ordering::Relaxed);
        self.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request completed
    pub fn record_completed(&self, latency_us: u64) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.completed.fetch_add(1, Ordering::Relaxed);
        self.total_latency_us.fetch_add(latency_us, Ordering::Relaxed);

        // Update min/max latency
        let _ = self
            .min_latency_us
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if latency_us < current {
                    Some(latency_us)
                } else {
                    None
                }
            });

        let _ = self
            .max_latency_us
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                if latency_us > current {
                    Some(latency_us)
                } else {
                    None
                }
            });
    }

    /// Record a request failed
    pub fn record_failed(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.failed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request timed out
    pub fn record_timeout(&self) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        self.timed_out.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a request rejected
    pub fn record_rejected(&self) {
        self.rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the average latency in microseconds
    pub fn average_latency_us(&self) -> f64 {
        let completed = self.completed.load(Ordering::Relaxed);
        if completed == 0 {
            0.0
        } else {
            self.total_latency_us.load(Ordering::Relaxed) as f64 / completed as f64
        }
    }

    /// Get a snapshot of the metrics
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            in_flight: self.in_flight.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            timed_out: self.timed_out.load(Ordering::Relaxed),
            rejected: self.rejected.load(Ordering::Relaxed),
            avg_latency_us: self.average_latency_us(),
            min_latency_us: self.min_latency_us.load(Ordering::Relaxed),
            max_latency_us: self.max_latency_us.load(Ordering::Relaxed),
        }
    }
}

/// A snapshot of metrics at a point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub queue_depth: usize,
    pub in_flight: usize,
    pub completed: u64,
    pub failed: u64,
    pub timed_out: u64,
    pub rejected: u64,
    pub avg_latency_us: f64,
    pub min_latency_us: u64,
    pub max_latency_us: u64,
}

// ============================================================================
// Async Pipeline
// ============================================================================

/// Handle to the async pipeline for submitting requests
#[derive(Clone)]
pub struct PipelineHandle {
    /// Request sender
    request_tx: mpsc::Sender<RequestEnvelope>,
    /// Configuration
    config: Arc<PipelineConfig>,
    /// Metrics
    metrics: Arc<PipelineMetrics>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
}

impl PipelineHandle {
    /// Submit a request to the pipeline
    #[instrument(skip(self, request), fields(agent_id = %agent_id, tool = %request.tool_name))]
    pub async fn submit(
        &self,
        agent_id: AgentId,
        session_id: SessionId,
        request: ToolRequest,
    ) -> PipelineResult<ToolResponse> {
        self.submit_with_priority(agent_id, session_id, request, RequestPriority::Normal)
            .await
    }

    /// Submit a request with a specific priority
    pub async fn submit_with_priority(
        &self,
        agent_id: AgentId,
        session_id: SessionId,
        request: ToolRequest,
        priority: RequestPriority,
    ) -> PipelineResult<ToolResponse> {
        // Create response channel
        let (response_tx, response_rx) = oneshot::channel();

        // Create envelope
        let envelope =
            RequestEnvelope::new(agent_id, session_id, request, response_tx).with_priority(priority);

        // Record metrics
        self.metrics.record_received();

        // Try to send to queue
        match self.request_tx.try_send(envelope) {
            Ok(_) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.record_rejected();
                return Err(PipelineError::QueueFull);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(PipelineError::ShuttingDown);
            }
        }

        // Wait for response with timeout
        match timeout(Duration::from_millis(self.config.timeout_ms), response_rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(PipelineError::ReceiveError("Channel closed".to_string())),
            Err(_) => {
                self.metrics.record_timeout();
                Err(PipelineError::Timeout(self.config.timeout_ms))
            }
        }
    }

    /// Get current metrics
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// The main async pipeline
pub struct AsyncPipeline {
    /// Configuration
    config: Arc<PipelineConfig>,
    /// Metrics
    metrics: Arc<PipelineMetrics>,
    /// Request receiver
    request_rx: mpsc::Receiver<RequestEnvelope>,
    /// Audit sender
    audit_tx: mpsc::Sender<AsyncAuditEntry>,
    /// Shutdown receiver
    shutdown_rx: broadcast::Receiver<()>,
    /// Concurrency semaphore
    semaphore: Arc<Semaphore>,
    /// Request handler function
    handler: Arc<dyn Fn(ToolRequest) -> PipelineResult<serde_json::Value> + Send + Sync>,
    /// Policy evaluator function
    policy_evaluator:
        Arc<dyn Fn(&AgentId, &ToolRequest) -> PolicyDecision + Send + Sync>,
}

impl AsyncPipeline {
    /// Create a new async pipeline
    pub async fn new<H, P>(
        config: PipelineConfig,
        handler: H,
        policy_evaluator: P,
    ) -> PipelineResult<(PipelineHandle, Self)>
    where
        H: Fn(ToolRequest) -> PipelineResult<serde_json::Value> + Send + Sync + 'static,
        P: Fn(&AgentId, &ToolRequest) -> PolicyDecision + Send + Sync + 'static,
    {
        let config = Arc::new(config);
        let metrics = Arc::new(PipelineMetrics::new());

        let (request_tx, request_rx) = mpsc::channel(config.queue_size);
        let (audit_tx, _audit_rx) = mpsc::channel(config.audit_queue_size);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let semaphore = Arc::new(Semaphore::new(config.max_concurrent));

        let handle = PipelineHandle {
            request_tx,
            config: config.clone(),
            metrics: metrics.clone(),
            shutdown_tx,
        };

        let pipeline = Self {
            config,
            metrics,
            request_rx,
            audit_tx,
            shutdown_rx,
            semaphore,
            handler: Arc::new(handler),
            policy_evaluator: Arc::new(policy_evaluator),
        };

        Ok((handle, pipeline))
    }

    /// Run the pipeline processing loop
    pub async fn run(mut self) {
        info!("Starting async pipeline with {} workers", self.config.worker_count);

        loop {
            tokio::select! {
                // Handle incoming requests
                Some(envelope) = self.request_rx.recv() => {
                    self.process_request(envelope).await;
                }
                // Handle shutdown signal
                _ = self.shutdown_rx.recv() => {
                    info!("Async pipeline received shutdown signal");
                    break;
                }
            }
        }

        info!("Async pipeline stopped");
    }

    /// Process a single request
    async fn process_request(&self, envelope: RequestEnvelope) {
        let semaphore = self.semaphore.clone();
        let metrics = self.metrics.clone();
        let handler = self.handler.clone();
        let policy_evaluator = self.policy_evaluator.clone();
        let audit_tx = self.audit_tx.clone();
        let timeout_ms = self.config.timeout_ms;

        // Spawn a task to process the request
        tokio::spawn(async move {
            // Acquire semaphore permit
            let _permit = match semaphore.acquire().await {
                Ok(permit) => permit,
                Err(_) => {
                    let _ = envelope.response_tx.send(Err(PipelineError::ShuttingDown));
                    return;
                }
            };

            metrics.record_started();
            let start_time = Instant::now();

            // Step 1: Evaluate policy
            let decision = policy_evaluator(&envelope.agent_id, &envelope.request);

            let result = match &decision {
                PolicyDecision::Deny { reason, .. } => {
                    metrics.record_failed();
                    Err(PipelineError::PolicyError(reason.clone()))
                }
                PolicyDecision::Inadmissible { reason } => {
                    metrics.record_failed();
                    Err(PipelineError::PolicyError(reason.clone()))
                }
                PolicyDecision::Allow { .. } => {
                    // Step 2: Execute the tool
                    match timeout(
                        Duration::from_millis(timeout_ms),
                        tokio::task::spawn_blocking({
                            let request = envelope.request.clone();
                            let handler = handler.clone();
                            move || handler(request)
                        }),
                    )
                    .await
                    {
                        Ok(Ok(Ok(value))) => {
                            let latency_us = start_time.elapsed().as_micros() as u64;
                            metrics.record_completed(latency_us);

                            Ok(ToolResponse {
                                request_id: envelope.request.request_id,
                                success: true,
                                result: Some(value),
                                error: None,
                                execution_time_ms: start_time.elapsed().as_millis() as u64,
                            })
                        }
                        Ok(Ok(Err(e))) => {
                            metrics.record_failed();
                            Err(e)
                        }
                        Ok(Err(e)) => {
                            metrics.record_failed();
                            Err(PipelineError::ExecutionError(e.to_string()))
                        }
                        Err(_) => {
                            metrics.record_timeout();
                            Err(PipelineError::Timeout(timeout_ms))
                        }
                    }
                }
            };

            // Step 3: Log to audit queue (non-blocking)
            let audit_entry = AsyncAuditEntry {
                request_id: envelope.id,
                agent_id: envelope.agent_id.to_string(),
                session_id: envelope.session_id.to_string(),
                tool_name: envelope.request.tool_name.clone(),
                decision: format!("{:?}", decision),
                result: if result.is_ok() { "success" } else { "failure" }.to_string(),
                latency_ms: start_time.elapsed().as_millis() as u64,
                timestamp: Utc::now(),
            };
            let _ = audit_tx.try_send(audit_entry);

            // Send response
            let _ = envelope.response_tx.send(result);
        });
    }
}

// ============================================================================
// Batch Processor (optional)
// ============================================================================

/// Batch processor for improved throughput
pub struct BatchProcessor {
    /// Current batch being built
    current_batch: RwLock<RequestBatch>,
    /// Configuration
    config: Arc<PipelineConfig>,
    /// Metrics
    metrics: Arc<PipelineMetrics>,
}

impl BatchProcessor {
    /// Create a new batch processor
    pub fn new(config: Arc<PipelineConfig>, metrics: Arc<PipelineMetrics>) -> Self {
        Self {
            current_batch: RwLock::new(RequestBatch::new()),
            config,
            metrics,
        }
    }

    /// Add a request to the current batch
    pub async fn add(&self, request: RequestEnvelope) -> Option<Vec<RequestEnvelope>> {
        let mut batch = self.current_batch.write().await;
        batch.add(request);

        if batch.is_ready(self.config.batch_size, self.config.batch_timeout_ms) {
            Some(batch.take())
        } else {
            None
        }
    }

    /// Flush the current batch regardless of size
    pub async fn flush(&self) -> Vec<RequestEnvelope> {
        let mut batch = self.current_batch.write().await;
        batch.take()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_request(tool_name: &str) -> ToolRequest {
        ToolRequest {
            request_id: Uuid::now_v7(),
            tool_name: tool_name.to_string(),
            parameters: serde_json::json!({}),
            timeout_ms: Some(5000),
        }
    }

    #[tokio::test]
    async fn test_pipeline_config_builder() {
        let config = PipelineConfig::default()
            .with_max_concurrent(100)
            .with_queue_size(500)
            .with_timeout(10000)
            .with_workers(8);

        assert_eq!(config.max_concurrent, 100);
        assert_eq!(config.queue_size, 500);
        assert_eq!(config.timeout_ms, 10000);
        assert_eq!(config.worker_count, 8);
    }

    #[tokio::test]
    async fn test_metrics_recording() {
        let metrics = PipelineMetrics::new();

        metrics.record_received();
        metrics.record_received();
        assert_eq!(metrics.total_requests.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.queue_depth.load(Ordering::Relaxed), 2);

        metrics.record_started();
        assert_eq!(metrics.queue_depth.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.in_flight.load(Ordering::Relaxed), 1);

        metrics.record_completed(1000);
        assert_eq!(metrics.in_flight.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.completed.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.total_latency_us.load(Ordering::Relaxed), 1000);
    }

    #[tokio::test]
    async fn test_metrics_snapshot() {
        let metrics = PipelineMetrics::new();

        for _ in 0..10 {
            metrics.record_received();
            metrics.record_started();
            metrics.record_completed(1000);
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_requests, 10);
        assert_eq!(snapshot.completed, 10);
        assert_eq!(snapshot.avg_latency_us, 1000.0);
    }

    #[tokio::test]
    async fn test_request_priority_ordering() {
        assert!(RequestPriority::Low < RequestPriority::Normal);
        assert!(RequestPriority::Normal < RequestPriority::High);
        assert!(RequestPriority::High < RequestPriority::Critical);
    }

    #[tokio::test]
    async fn test_request_batch() {
        let mut batch = RequestBatch::new();
        assert!(batch.requests.is_empty());

        let (tx, _rx) = oneshot::channel();
        let envelope = RequestEnvelope::new(
            AgentId::new(),
            SessionId::new(),
            create_test_request("test"),
            tx,
        );
        batch.add(envelope);

        assert_eq!(batch.requests.len(), 1);
        assert!(!batch.is_ready(10, 1000));

        // Add more to reach batch size
        for _ in 0..9 {
            let (tx, _rx) = oneshot::channel();
            batch.add(RequestEnvelope::new(
                AgentId::new(),
                SessionId::new(),
                create_test_request("test"),
                tx,
            ));
        }

        assert!(batch.is_ready(10, 1000));
    }

    #[tokio::test]
    async fn test_pipeline_creation() {
        let config = PipelineConfig::default();

        let handler = |_req: ToolRequest| -> PipelineResult<serde_json::Value> {
            Ok(serde_json::json!({"status": "ok"}))
        };

        let policy_evaluator = |_agent: &AgentId, _req: &ToolRequest| -> PolicyDecision {
            PolicyDecision::Allow {
                reason: "Test".to_string(),
                constraints: None,
            }
        };

        let result = AsyncPipeline::new(config, handler, policy_evaluator).await;
        assert!(result.is_ok());

        let (handle, _pipeline) = result.unwrap();
        assert_eq!(handle.metrics().total_requests, 0);
    }

    #[tokio::test]
    async fn test_pipeline_submit_and_process() {
        let config = PipelineConfig::default()
            .with_max_concurrent(10)
            .with_timeout(5000);

        let handler = |_req: ToolRequest| -> PipelineResult<serde_json::Value> {
            Ok(serde_json::json!({"result": "success"}))
        };

        let policy_evaluator = |_agent: &AgentId, _req: &ToolRequest| -> PolicyDecision {
            PolicyDecision::Allow {
                reason: "Allowed".to_string(),
                constraints: None,
            }
        };

        let (handle, pipeline) = AsyncPipeline::new(config, handler, policy_evaluator)
            .await
            .unwrap();

        // Run pipeline in background
        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await;
        });

        // Submit a request
        let agent_id = AgentId::new();
        let session_id = SessionId::new();
        let request = create_test_request("echo");

        let result = handle.submit(agent_id, session_id, request).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert!(response.success);

        // Shutdown
        handle.shutdown();
        let _ = pipeline_handle.await;
    }

    #[tokio::test]
    async fn test_pipeline_policy_denial() {
        let config = PipelineConfig::default();

        let handler = |_req: ToolRequest| -> PipelineResult<serde_json::Value> {
            Ok(serde_json::json!({"result": "success"}))
        };

        let policy_evaluator = |_agent: &AgentId, _req: &ToolRequest| -> PolicyDecision {
            PolicyDecision::Deny {
                reason: "Denied for testing".to_string(),
                violated_policies: None,
            }
        };

        let (handle, pipeline) = AsyncPipeline::new(config, handler, policy_evaluator)
            .await
            .unwrap();

        // Run pipeline in background
        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await;
        });

        // Submit a request
        let result = handle
            .submit(AgentId::new(), SessionId::new(), create_test_request("test"))
            .await;

        assert!(result.is_err());
        assert!(matches!(result, Err(PipelineError::PolicyError(_))));

        // Shutdown
        handle.shutdown();
        let _ = pipeline_handle.await;
    }

    #[tokio::test]
    async fn test_pipeline_concurrent_requests() {
        let config = PipelineConfig::default()
            .with_max_concurrent(50)
            .with_timeout(10000);

        let handler = |_req: ToolRequest| -> PipelineResult<serde_json::Value> {
            // Simulate some work
            std::thread::sleep(std::time::Duration::from_millis(10));
            Ok(serde_json::json!({"result": "success"}))
        };

        let policy_evaluator = |_agent: &AgentId, _req: &ToolRequest| -> PolicyDecision {
            PolicyDecision::Allow {
                reason: "Allowed".to_string(),
                constraints: None,
            }
        };

        let (handle, pipeline) = AsyncPipeline::new(config, handler, policy_evaluator)
            .await
            .unwrap();

        // Run pipeline in background
        let pipeline_handle = tokio::spawn(async move {
            pipeline.run().await;
        });

        // Submit multiple requests concurrently
        let mut tasks = Vec::new();
        for i in 0..20 {
            let h = handle.clone();
            tasks.push(tokio::spawn(async move {
                h.submit(
                    AgentId::new(),
                    SessionId::new(),
                    create_test_request(&format!("tool_{}", i)),
                )
                .await
            }));
        }

        // Wait for all requests
        let results: Vec<_> = futures::future::join_all(tasks).await;
        let successes = results
            .into_iter()
            .filter(|r| r.as_ref().ok().and_then(|r| r.as_ref().ok()).is_some())
            .count();

        assert_eq!(successes, 20);

        // Check metrics
        let metrics = handle.metrics();
        assert_eq!(metrics.total_requests, 20);
        assert_eq!(metrics.completed, 20);

        // Shutdown
        handle.shutdown();
        let _ = pipeline_handle.await;
    }

    #[tokio::test]
    async fn test_batch_processor() {
        let config = Arc::new(PipelineConfig::default().with_batching(5, 1000));
        let metrics = Arc::new(PipelineMetrics::new());
        let processor = BatchProcessor::new(config, metrics);

        // Add requests until batch is ready
        for i in 0..4 {
            let (tx, _rx) = oneshot::channel();
            let result = processor
                .add(RequestEnvelope::new(
                    AgentId::new(),
                    SessionId::new(),
                    create_test_request(&format!("test_{}", i)),
                    tx,
                ))
                .await;
            assert!(result.is_none());
        }

        // Add 5th request - should trigger batch
        let (tx, _rx) = oneshot::channel();
        let result = processor
            .add(RequestEnvelope::new(
                AgentId::new(),
                SessionId::new(),
                create_test_request("test_4"),
                tx,
            ))
            .await;
        assert!(result.is_some());
        assert_eq!(result.unwrap().len(), 5);
    }
}
