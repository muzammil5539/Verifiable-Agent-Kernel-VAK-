//! OpenTelemetry Distributed Tracing Integration (OBS-001)
//!
//! Provides distributed tracing capabilities using OpenTelemetry standards.
//! Creates spans for key operations: Inference, Logic Check, Policy Eval, Tool Exec.
//!
//! # Overview
//!
//! The tracing module enables:
//! - Distributed tracing across agent operations
//! - Span creation for each kernel operation type
//! - Context propagation for request correlation
//! - Export to multiple backends (Jaeger, Zipkin, OTLP)
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::audit::otel::{VakTracer, TracingConfig, SpanKind};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = TracingConfig::default();
//! let tracer = VakTracer::new(config)?;
//!
//! // Create a span for an operation
//! let mut span = tracer.start_trace("policy_eval", SpanKind::PolicyEval).await;
//! // ... perform operation ...
//! span.end();
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 3.4: Distributed Tracing
//! - OpenTelemetry Specification: https://opentelemetry.io/docs/specs/otel/

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during tracing operations
#[derive(Debug, Error)]
pub enum TracingError {
    /// Tracer not initialized
    #[error("Tracer not initialized")]
    NotInitialized,

    /// Span not found
    #[error("Span not found: {0}")]
    SpanNotFound(String),

    /// Export failed
    #[error("Export failed: {0}")]
    ExportFailed(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for tracing operations
pub type TracingResult<T> = Result<T, TracingError>;

// ============================================================================
// Span Types
// ============================================================================

/// Types of spans in the VAK system
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanKind {
    /// LLM inference operation
    Inference,
    /// Logic/Datalog verification check
    LogicCheck,
    /// Policy evaluation
    PolicyEval,
    /// Tool/skill execution
    ToolExec,
    /// Memory operation (read/write)
    MemoryOp,
    /// Swarm communication
    SwarmComm,
    /// MCP request handling
    McpRequest,
    /// Audit logging
    AuditLog,
    /// Custom span type
    Custom,
}

impl std::fmt::Display for SpanKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpanKind::Inference => write!(f, "inference"),
            SpanKind::LogicCheck => write!(f, "logic_check"),
            SpanKind::PolicyEval => write!(f, "policy_eval"),
            SpanKind::ToolExec => write!(f, "tool_exec"),
            SpanKind::MemoryOp => write!(f, "memory_op"),
            SpanKind::SwarmComm => write!(f, "swarm_comm"),
            SpanKind::McpRequest => write!(f, "mcp_request"),
            SpanKind::AuditLog => write!(f, "audit_log"),
            SpanKind::Custom => write!(f, "custom"),
        }
    }
}

/// Status of a span
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpanStatus {
    /// Span completed successfully
    Ok,
    /// Span completed with error
    Error,
    /// Span was cancelled
    Cancelled,
    /// Span is still in progress
    InProgress,
}

// ============================================================================
// Trace Context
// ============================================================================

/// Trace context for distributed tracing propagation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// Trace ID (128-bit identifier)
    pub trace_id: String,
    /// Span ID (64-bit identifier)
    pub span_id: String,
    /// Parent span ID (if any)
    pub parent_span_id: Option<String>,
    /// Trace flags
    pub trace_flags: u8,
    /// Trace state (vendor-specific)
    pub trace_state: HashMap<String, String>,
}

impl TraceContext {
    /// Create a new trace context
    pub fn new() -> Self {
        Self {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: None,
            trace_flags: 0x01, // sampled
            trace_state: HashMap::new(),
        }
    }

    /// Create a child context
    pub fn child(&self) -> Self {
        Self {
            trace_id: self.trace_id.clone(),
            span_id: generate_span_id(),
            parent_span_id: Some(self.span_id.clone()),
            trace_flags: self.trace_flags,
            trace_state: self.trace_state.clone(),
        }
    }

    /// Parse from W3C traceparent header
    pub fn from_traceparent(header: &str) -> Option<Self> {
        let parts: Vec<&str> = header.split('-').collect();
        if parts.len() != 4 {
            return None;
        }

        Some(Self {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            parent_span_id: None,
            trace_flags: u8::from_str_radix(parts[3], 16).unwrap_or(0),
            trace_state: HashMap::new(),
        })
    }

    /// Convert to W3C traceparent header
    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id, self.span_id, self.trace_flags
        )
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Span
// ============================================================================

/// A span representing a unit of work
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Span {
    /// Span name/operation
    pub name: String,
    /// Span kind
    pub kind: SpanKind,
    /// Trace context
    pub context: TraceContext,
    /// Start time (Unix timestamp nanoseconds)
    pub start_time_ns: u64,
    /// End time (Unix timestamp nanoseconds)
    pub end_time_ns: Option<u64>,
    /// Span status
    pub status: SpanStatus,
    /// Status message (for errors)
    pub status_message: Option<String>,
    /// Attributes/tags
    pub attributes: HashMap<String, AttributeValue>,
    /// Events within the span
    pub events: Vec<SpanEvent>,
    /// Links to other spans
    pub links: Vec<SpanLink>,
}

impl Span {
    /// Create a new span
    pub fn new(name: impl Into<String>, kind: SpanKind, context: TraceContext) -> Self {
        Self {
            name: name.into(),
            kind,
            context,
            start_time_ns: current_time_ns(),
            end_time_ns: None,
            status: SpanStatus::InProgress,
            status_message: None,
            attributes: HashMap::new(),
            events: Vec::new(),
            links: Vec::new(),
        }
    }

    /// Set an attribute
    pub fn set_attribute(&mut self, key: impl Into<String>, value: impl Into<AttributeValue>) {
        self.attributes.insert(key.into(), value.into());
    }

    /// Add an event
    pub fn add_event(&mut self, name: impl Into<String>) {
        self.events.push(SpanEvent {
            name: name.into(),
            timestamp_ns: current_time_ns(),
            attributes: HashMap::new(),
        });
    }

    /// Add an event with attributes
    pub fn add_event_with_attrs(
        &mut self,
        name: impl Into<String>,
        attrs: HashMap<String, AttributeValue>,
    ) {
        self.events.push(SpanEvent {
            name: name.into(),
            timestamp_ns: current_time_ns(),
            attributes: attrs,
        });
    }

    /// Add a link to another span
    pub fn add_link(&mut self, context: TraceContext) {
        self.links.push(SpanLink {
            context,
            attributes: HashMap::new(),
        });
    }

    /// End the span successfully
    pub fn end(&mut self) {
        self.end_time_ns = Some(current_time_ns());
        self.status = SpanStatus::Ok;
    }

    /// End the span with error
    pub fn end_with_error(&mut self, message: impl Into<String>) {
        self.end_time_ns = Some(current_time_ns());
        self.status = SpanStatus::Error;
        self.status_message = Some(message.into());
    }

    /// Get duration in nanoseconds
    pub fn duration_ns(&self) -> Option<u64> {
        self.end_time_ns
            .map(|end| end.saturating_sub(self.start_time_ns))
    }

    /// Get duration as Duration
    pub fn duration(&self) -> Option<Duration> {
        self.duration_ns().map(Duration::from_nanos)
    }

    /// Check if span is finished
    pub fn is_finished(&self) -> bool {
        self.end_time_ns.is_some()
    }
}

/// An event within a span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanEvent {
    /// Event name
    pub name: String,
    /// Event timestamp (nanoseconds)
    pub timestamp_ns: u64,
    /// Event attributes
    pub attributes: HashMap<String, AttributeValue>,
}

/// A link to another span
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpanLink {
    /// Linked span context
    pub context: TraceContext,
    /// Link attributes
    pub attributes: HashMap<String, AttributeValue>,
}

/// Attribute value types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// String value
    String(String),
    /// Integer value
    Int(i64),
    /// Float value
    Float(f64),
    /// Boolean value
    Bool(bool),
    /// Array of strings
    StringArray(Vec<String>),
    /// Array of integers
    IntArray(Vec<i64>),
}

impl From<String> for AttributeValue {
    fn from(v: String) -> Self {
        AttributeValue::String(v)
    }
}

impl From<&str> for AttributeValue {
    fn from(v: &str) -> Self {
        AttributeValue::String(v.to_string())
    }
}

impl From<i64> for AttributeValue {
    fn from(v: i64) -> Self {
        AttributeValue::Int(v)
    }
}

impl From<i32> for AttributeValue {
    fn from(v: i32) -> Self {
        AttributeValue::Int(v as i64)
    }
}

impl From<f64> for AttributeValue {
    fn from(v: f64) -> Self {
        AttributeValue::Float(v)
    }
}

impl From<bool> for AttributeValue {
    fn from(v: bool) -> Self {
        AttributeValue::Bool(v)
    }
}

// ============================================================================
// Tracer Configuration
// ============================================================================

/// Configuration for the VAK tracer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Enable tracing
    pub enabled: bool,
    /// Service name
    pub service_name: String,
    /// Service version
    pub service_version: String,
    /// Sampling rate (0.0 to 1.0)
    pub sampling_rate: f64,
    /// Maximum spans to buffer
    pub max_buffer_size: usize,
    /// Export interval in seconds
    pub export_interval_secs: u64,
    /// Export endpoint (OTLP)
    pub otlp_endpoint: Option<String>,
    /// Include detailed attributes
    pub detailed_attributes: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            service_name: "vak-kernel".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            sampling_rate: 1.0,
            max_buffer_size: 10000,
            export_interval_secs: 30,
            otlp_endpoint: None,
            detailed_attributes: true,
        }
    }
}

// ============================================================================
// VAK Tracer
// ============================================================================

/// The main tracer for VAK operations
pub struct VakTracer {
    /// Configuration
    config: TracingConfig,
    /// Active spans
    active_spans: Arc<RwLock<HashMap<String, Span>>>,
    /// Completed spans buffer (for export)
    completed_spans: Arc<RwLock<Vec<Span>>>,
    /// Span counter
    span_count: AtomicU64,
    /// Current trace context (thread-local alternative)
    current_context: Arc<RwLock<Option<TraceContext>>>,
}

impl VakTracer {
    /// Create a new tracer
    pub fn new(config: TracingConfig) -> TracingResult<Self> {
        if config.sampling_rate < 0.0 || config.sampling_rate > 1.0 {
            return Err(TracingError::ConfigError(
                "Sampling rate must be between 0.0 and 1.0".to_string(),
            ));
        }

        Ok(Self {
            config,
            active_spans: Arc::new(RwLock::new(HashMap::new())),
            completed_spans: Arc::new(RwLock::new(Vec::new())),
            span_count: AtomicU64::new(0),
            current_context: Arc::new(RwLock::new(None)),
        })
    }

    /// Start a new trace
    pub async fn start_trace(&self, name: impl Into<String>, kind: SpanKind) -> Span {
        let context = TraceContext::new();
        self.start_span_with_context(name, kind, context).await
    }

    /// Start a span with an existing context
    pub async fn start_span_with_context(
        &self,
        name: impl Into<String>,
        kind: SpanKind,
        context: TraceContext,
    ) -> Span {
        let span = Span::new(name, kind, context.clone());

        // Store as active
        {
            let mut active = self.active_spans.write().await;
            active.insert(span.context.span_id.clone(), span.clone());
        }

        // Update current context
        {
            let mut current = self.current_context.write().await;
            *current = Some(context);
        }

        self.span_count.fetch_add(1, Ordering::Relaxed);
        span
    }

    /// Start a child span of the current context
    pub async fn start_child_span(&self, name: impl Into<String>, kind: SpanKind) -> Span {
        let context = {
            let current = self.current_context.read().await;
            current
                .as_ref()
                .map(|c| c.child())
                .unwrap_or_else(TraceContext::new)
        };

        self.start_span_with_context(name, kind, context).await
    }

    /// End a span
    pub async fn end_span(&self, span_id: &str) -> TracingResult<Span> {
        let mut active = self.active_spans.write().await;
        let mut span = active
            .remove(span_id)
            .ok_or_else(|| TracingError::SpanNotFound(span_id.to_string()))?;

        span.end();

        // Add to completed buffer
        {
            let mut completed = self.completed_spans.write().await;
            if completed.len() < self.config.max_buffer_size {
                completed.push(span.clone());
            }
        }

        Ok(span)
    }

    /// End a span with error
    pub async fn end_span_with_error(
        &self,
        span_id: &str,
        error: impl Into<String>,
    ) -> TracingResult<Span> {
        let mut active = self.active_spans.write().await;
        let mut span = active
            .remove(span_id)
            .ok_or_else(|| TracingError::SpanNotFound(span_id.to_string()))?;

        span.end_with_error(error);

        // Add to completed buffer
        {
            let mut completed = self.completed_spans.write().await;
            if completed.len() < self.config.max_buffer_size {
                completed.push(span.clone());
            }
        }

        Ok(span)
    }

    /// Add an attribute to an active span
    pub async fn set_span_attribute(
        &self,
        span_id: &str,
        key: impl Into<String>,
        value: impl Into<AttributeValue>,
    ) -> TracingResult<()> {
        let mut active = self.active_spans.write().await;
        let span = active
            .get_mut(span_id)
            .ok_or_else(|| TracingError::SpanNotFound(span_id.to_string()))?;

        span.set_attribute(key, value);
        Ok(())
    }

    /// Add an event to an active span
    pub async fn add_span_event(
        &self,
        span_id: &str,
        event: impl Into<String>,
    ) -> TracingResult<()> {
        let mut active = self.active_spans.write().await;
        let span = active
            .get_mut(span_id)
            .ok_or_else(|| TracingError::SpanNotFound(span_id.to_string()))?;

        span.add_event(event);
        Ok(())
    }

    /// Get completed spans for export
    pub async fn drain_completed_spans(&self) -> Vec<Span> {
        let mut completed = self.completed_spans.write().await;
        std::mem::take(&mut *completed)
    }

    /// Get tracer statistics
    pub async fn stats(&self) -> TracerStats {
        let active = self.active_spans.read().await;
        let completed = self.completed_spans.read().await;

        TracerStats {
            total_spans_created: self.span_count.load(Ordering::Relaxed),
            active_spans: active.len(),
            buffered_spans: completed.len(),
            service_name: self.config.service_name.clone(),
        }
    }

    /// Create a span context helper for convenient span management
    pub async fn span_context(&self, name: impl Into<String>, kind: SpanKind) -> SpanContext<'_> {
        let span = self.start_child_span(name, kind).await;
        SpanContext {
            tracer: self,
            span_id: span.context.span_id.clone(),
        }
    }
}

impl std::fmt::Debug for VakTracer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VakTracer")
            .field("config", &self.config)
            .field("span_count", &self.span_count.load(Ordering::Relaxed))
            .finish()
    }
}

/// Helper for RAII-style span management
pub struct SpanContext<'a> {
    tracer: &'a VakTracer,
    span_id: String,
}

impl<'a> SpanContext<'a> {
    /// Get the span ID
    pub fn span_id(&self) -> &str {
        &self.span_id
    }

    /// Set an attribute on this span
    pub async fn set_attribute(&self, key: impl Into<String>, value: impl Into<AttributeValue>) {
        let _ = self
            .tracer
            .set_span_attribute(&self.span_id, key, value)
            .await;
    }

    /// Add an event to this span
    pub async fn add_event(&self, event: impl Into<String>) {
        let _ = self.tracer.add_span_event(&self.span_id, event).await;
    }

    /// End the span successfully
    pub async fn end(self) {
        let _ = self.tracer.end_span(&self.span_id).await;
    }

    /// End the span with error
    pub async fn end_with_error(self, error: impl Into<String>) {
        let _ = self.tracer.end_span_with_error(&self.span_id, error).await;
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Tracer statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerStats {
    /// Total spans created
    pub total_spans_created: u64,
    /// Currently active spans
    pub active_spans: usize,
    /// Spans buffered for export
    pub buffered_spans: usize,
    /// Service name
    pub service_name: String,
}

// ============================================================================
// OTLP Export (Simplified)
// ============================================================================

/// Simplified OTLP exporter for spans
#[derive(Debug)]
pub struct OtlpExporter {
    /// Endpoint URL
    endpoint: String,
    /// HTTP client
    client: reqwest::Client,
}

impl OtlpExporter {
    /// Create a new OTLP exporter
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Export spans to OTLP endpoint
    pub async fn export(&self, spans: Vec<Span>) -> TracingResult<()> {
        if spans.is_empty() {
            return Ok(());
        }

        // Convert to OTLP format (simplified)
        let payload = serde_json::json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": []
                },
                "scopeSpans": [{
                    "scope": {
                        "name": "vak-kernel"
                    },
                    "spans": spans.iter().map(|s| {
                        serde_json::json!({
                            "traceId": s.context.trace_id,
                            "spanId": s.context.span_id,
                            "parentSpanId": s.context.parent_span_id,
                            "name": s.name,
                            "kind": format!("{}", s.kind),
                            "startTimeUnixNano": s.start_time_ns,
                            "endTimeUnixNano": s.end_time_ns,
                            "status": {
                                "code": match s.status {
                                    SpanStatus::Ok => 1,
                                    SpanStatus::Error => 2,
                                    _ => 0,
                                },
                                "message": s.status_message
                            },
                            "attributes": s.attributes.iter().map(|(k, v)| {
                                serde_json::json!({
                                    "key": k,
                                    "value": match v {
                                        AttributeValue::String(s) => serde_json::json!({"stringValue": s}),
                                        AttributeValue::Int(i) => serde_json::json!({"intValue": i}),
                                        AttributeValue::Float(f) => serde_json::json!({"doubleValue": f}),
                                        AttributeValue::Bool(b) => serde_json::json!({"boolValue": b}),
                                        _ => serde_json::json!({"stringValue": format!("{:?}", v)}),
                                    }
                                })
                            }).collect::<Vec<_>>()
                        })
                    }).collect::<Vec<_>>()
                }]
            }]
        });

        self.client
            .post(&format!("{}/v1/traces", self.endpoint))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| TracingError::ExportFailed(e.to_string()))?;

        tracing::debug!(spans_exported = spans.len(), "Exported spans to OTLP");
        Ok(())
    }
}

// ============================================================================
// Kernel-Specific Tracing Helpers (OBS-001)
// ============================================================================

impl VakTracer {
    /// Start a span for inference operations
    ///
    /// Use this when an LLM is being called or reasoning is happening.
    pub async fn trace_inference(&self, operation: impl Into<String>) -> SpanContext<'_> {
        let name = format!("inference::{}", operation.into());
        self.span_context(name, SpanKind::Inference).await
    }

    /// Start a span for logic/Datalog verification
    ///
    /// Use this when validating plans against safety rules.
    pub async fn trace_logic_check(&self, rule_set: impl Into<String>) -> SpanContext<'_> {
        let name = format!("logic_check::{}", rule_set.into());
        self.span_context(name, SpanKind::LogicCheck).await
    }

    /// Start a span for policy evaluation
    ///
    /// Use this when Cedar policies are being evaluated.
    pub async fn trace_policy_eval(
        &self,
        principal: impl Into<String>,
        action: impl Into<String>,
    ) -> SpanContext<'_> {
        let name = format!("policy_eval::{}::{}", principal.into(), action.into());
        self.span_context(name, SpanKind::PolicyEval).await
    }

    /// Start a span for tool/skill execution
    ///
    /// Use this when a WASM skill or built-in tool is being executed.
    pub async fn trace_tool_exec(&self, tool_name: impl Into<String>) -> SpanContext<'_> {
        let name = format!("tool_exec::{}", tool_name.into());
        self.span_context(name, SpanKind::ToolExec).await
    }

    /// Start a span for memory operations
    ///
    /// Use this when reading/writing to the memory system (Merkle DAG, vector store, etc.)
    pub async fn trace_memory_op(&self, operation: impl Into<String>) -> SpanContext<'_> {
        let name = format!("memory_op::{}", operation.into());
        self.span_context(name, SpanKind::MemoryOp).await
    }

    /// Start a span for swarm communication
    ///
    /// Use this when agents are communicating in a multi-agent scenario.
    pub async fn trace_swarm_comm(&self, protocol: impl Into<String>) -> SpanContext<'_> {
        let name = format!("swarm_comm::{}", protocol.into());
        self.span_context(name, SpanKind::SwarmComm).await
    }

    /// Start a span for MCP request handling
    ///
    /// Use this when processing Model Context Protocol requests.
    pub async fn trace_mcp_request(&self, method: impl Into<String>) -> SpanContext<'_> {
        let name = format!("mcp_request::{}", method.into());
        self.span_context(name, SpanKind::McpRequest).await
    }
}

/// A traced operation that automatically records timing and status
///
/// This is a convenience wrapper for executing operations with automatic tracing.
///
/// # Example
///
/// ```rust,no_run
/// use vak::audit::otel::{VakTracer, TracingConfig, traced_operation, SpanKind};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let tracer = VakTracer::new(TracingConfig::default())?;
///
/// let result = traced_operation(&tracer, "my_operation", SpanKind::ToolExec, async {
///     // Your async operation here
///     Ok::<_, String>("result")
/// }).await;
/// # Ok(())
/// # }
/// ```
pub async fn traced_operation<T, E, F>(
    tracer: &VakTracer,
    name: impl Into<String>,
    kind: SpanKind,
    operation: F,
) -> Result<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let span = tracer.span_context(name, kind).await;

    match operation.await {
        Ok(result) => {
            span.end().await;
            Ok(result)
        }
        Err(e) => {
            span.end_with_error(e.to_string()).await;
            Err(e)
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a 128-bit trace ID
fn generate_trace_id() -> String {
    let uuid = Uuid::new_v4();
    hex::encode(uuid.as_bytes())
}

/// Generate a 64-bit span ID
fn generate_span_id() -> String {
    let bytes: [u8; 8] = rand::random();
    hex::encode(bytes)
}

/// Get current time in nanoseconds
fn current_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

// ============================================================================
// Convenience Macros
// ============================================================================

/// Create a span for inference operations
#[macro_export]
macro_rules! trace_inference {
    ($tracer:expr, $name:expr) => {
        $tracer.span_context($name, $crate::audit::tracing::SpanKind::Inference)
    };
}

/// Create a span for logic check operations
#[macro_export]
macro_rules! trace_logic_check {
    ($tracer:expr, $name:expr) => {
        $tracer.span_context($name, $crate::audit::tracing::SpanKind::LogicCheck)
    };
}

/// Create a span for policy evaluation
#[macro_export]
macro_rules! trace_policy_eval {
    ($tracer:expr, $name:expr) => {
        $tracer.span_context($name, $crate::audit::tracing::SpanKind::PolicyEval)
    };
}

/// Create a span for tool execution
#[macro_export]
macro_rules! trace_tool_exec {
    ($tracer:expr, $name:expr) => {
        $tracer.span_context($name, $crate::audit::tracing::SpanKind::ToolExec)
    };
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_context_creation() {
        let ctx = TraceContext::new();
        assert!(!ctx.trace_id.is_empty());
        assert!(!ctx.span_id.is_empty());
        assert!(ctx.parent_span_id.is_none());
    }

    #[test]
    fn test_trace_context_child() {
        let parent = TraceContext::new();
        let child = parent.child();

        assert_eq!(parent.trace_id, child.trace_id);
        assert_ne!(parent.span_id, child.span_id);
        assert_eq!(child.parent_span_id, Some(parent.span_id.clone()));
    }

    #[test]
    fn test_traceparent_roundtrip() {
        let ctx = TraceContext::new();
        let header = ctx.to_traceparent();
        let parsed = TraceContext::from_traceparent(&header).unwrap();

        assert_eq!(ctx.trace_id, parsed.trace_id);
        assert_eq!(ctx.span_id, parsed.span_id);
    }

    #[test]
    fn test_span_creation() {
        let ctx = TraceContext::new();
        let mut span = Span::new("test_op", SpanKind::ToolExec, ctx);

        assert_eq!(span.name, "test_op");
        assert_eq!(span.kind, SpanKind::ToolExec);
        assert_eq!(span.status, SpanStatus::InProgress);
        assert!(!span.is_finished());

        span.set_attribute("key", "value");
        span.add_event("something happened");
        span.end();

        assert!(span.is_finished());
        assert_eq!(span.status, SpanStatus::Ok);
        assert!(span.duration().is_some());
    }

    #[test]
    fn test_span_error() {
        let ctx = TraceContext::new();
        let mut span = Span::new("failing_op", SpanKind::PolicyEval, ctx);

        span.end_with_error("Permission denied");

        assert_eq!(span.status, SpanStatus::Error);
        assert_eq!(span.status_message, Some("Permission denied".to_string()));
    }

    #[tokio::test]
    async fn test_tracer_basic() {
        let tracer = VakTracer::new(TracingConfig::default()).unwrap();

        // Start a trace
        let span = tracer
            .start_trace("test_operation", SpanKind::ToolExec)
            .await;
        let span_id = span.context.span_id.clone();

        // Add attributes
        tracer
            .set_span_attribute(&span_id, "agent_id", "agent-001")
            .await
            .unwrap();
        tracer
            .add_span_event(&span_id, "started processing")
            .await
            .unwrap();

        // End span
        let finished = tracer.end_span(&span_id).await.unwrap();

        assert_eq!(finished.status, SpanStatus::Ok);
        assert!(finished.attributes.contains_key("agent_id"));
        assert_eq!(finished.events.len(), 1);

        // Check stats
        let stats = tracer.stats().await;
        assert_eq!(stats.total_spans_created, 1);
        assert_eq!(stats.active_spans, 0);
        assert_eq!(stats.buffered_spans, 1);
    }

    #[tokio::test]
    async fn test_tracer_child_spans() {
        let tracer = VakTracer::new(TracingConfig::default()).unwrap();

        // Start parent
        let parent = tracer.start_trace("parent_op", SpanKind::Inference).await;
        let parent_id = parent.context.span_id.clone();
        let trace_id = parent.context.trace_id.clone();

        // Start child
        let child = tracer
            .start_child_span("child_op", SpanKind::LogicCheck)
            .await;
        let child_id = child.context.span_id.clone();

        // Child should have same trace ID but different span ID
        assert_eq!(child.context.trace_id, trace_id);
        assert_ne!(child.context.span_id, parent_id);
        assert_eq!(child.context.parent_span_id, Some(parent_id.clone()));

        // End both
        tracer.end_span(&child_id).await.unwrap();
        tracer.end_span(&parent_id).await.unwrap();

        let stats = tracer.stats().await;
        assert_eq!(stats.total_spans_created, 2);
    }

    #[test]
    fn test_attribute_conversions() {
        let s: AttributeValue = "test".into();
        assert!(matches!(s, AttributeValue::String(_)));

        let i: AttributeValue = 42i64.into();
        assert!(matches!(i, AttributeValue::Int(42)));

        let f: AttributeValue = 3.14f64.into();
        assert!(matches!(f, AttributeValue::Float(_)));

        let b: AttributeValue = true.into();
        assert!(matches!(b, AttributeValue::Bool(true)));
    }
}
