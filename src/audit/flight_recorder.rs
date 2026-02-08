//! Flight Recorder for Shadow Mode (Issue #43)
//!
//! Provides shadow-mode flight recording capabilities for:
//! - Mirroring all requests/responses for later replay
//! - Policy evaluation without side effects
//! - Forensic analysis and debugging
//! - Replay-based regression testing
//!
//! # Overview
//!
//! The flight recorder captures:
//! - All kernel requests and responses
//! - Policy evaluation decisions
//! - Tool execution attempts (with optional execution in shadow mode)
//! - Timing and performance data
//! - Chain hashes for verification
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::audit::flight_recorder::{FlightRecorder, FlightEvent, RecorderConfig};
//!
//! // Create a flight recorder in shadow mode
//! let config = RecorderConfig::shadow_mode();
//! let mut recorder = FlightRecorder::new(config);
//!
//! // Record events
//! recorder.record_request("agent-1", "read", "/data/file.txt", None);
//! recorder.record_policy_decision("agent-1", "allow", "rule-1", 5);
//! recorder.record_response("agent-1", "read", true, Some("file contents"));
//!
//! // Generate trace receipt
//! let receipt = recorder.generate_receipt();
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::Instant;
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the flight recorder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecorderConfig {
    /// Enable shadow mode (record but don't execute)
    pub shadow_mode: bool,
    /// Enable request/response recording
    pub record_requests: bool,
    /// Enable policy decision recording
    pub record_policy_decisions: bool,
    /// Enable tool execution recording
    pub record_tool_executions: bool,
    /// Enable timing measurements
    pub record_timing: bool,
    /// Maximum events to keep in memory
    pub max_memory_events: usize,
    /// Path for persistent storage (optional)
    pub storage_path: Option<PathBuf>,
    /// Redact sensitive fields in logs
    pub redact_sensitive: bool,
    /// Sensitive field patterns to redact
    pub sensitive_patterns: Vec<String>,
    /// Enable chain hashing for integrity
    pub enable_chain_hashing: bool,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            shadow_mode: false,
            record_requests: true,
            record_policy_decisions: true,
            record_tool_executions: true,
            record_timing: true,
            max_memory_events: 10000,
            storage_path: None,
            redact_sensitive: true,
            sensitive_patterns: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "api_key".to_string(),
                "credential".to_string(),
            ],
            enable_chain_hashing: true,
        }
    }
}

impl RecorderConfig {
    /// Create a shadow-mode configuration
    pub fn shadow_mode() -> Self {
        Self {
            shadow_mode: true,
            ..Default::default()
        }
    }

    /// Create a minimal recording configuration
    pub fn minimal() -> Self {
        Self {
            shadow_mode: false,
            record_requests: true,
            record_policy_decisions: true,
            record_tool_executions: false,
            record_timing: false,
            max_memory_events: 1000,
            storage_path: None,
            redact_sensitive: true,
            sensitive_patterns: vec![],
            enable_chain_hashing: false,
        }
    }

    /// Create a full recording configuration
    pub fn full(storage_path: impl Into<PathBuf>) -> Self {
        Self {
            shadow_mode: false,
            record_requests: true,
            record_policy_decisions: true,
            record_tool_executions: true,
            record_timing: true,
            max_memory_events: 50000,
            storage_path: Some(storage_path.into()),
            redact_sensitive: true,
            sensitive_patterns: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "api_key".to_string(),
            ],
            enable_chain_hashing: true,
        }
    }
}

// ============================================================================
// Event Types
// ============================================================================

/// Types of flight recorder events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Request received
    Request,
    /// Response sent
    Response,
    /// Policy evaluation
    PolicyEvaluation,
    /// Tool execution
    ToolExecution,
    /// Error occurred
    Error,
    /// Trace started
    TraceStart,
    /// Trace ended
    TraceEnd,
    /// Span started
    SpanStart,
    /// Span ended
    SpanEnd,
    /// Custom event
    Custom(String),
}

/// A flight recorder event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlightEvent {
    /// Unique event ID
    pub event_id: String,
    /// Trace ID for correlated events
    pub trace_id: String,
    /// Span ID (optional)
    pub span_id: Option<String>,
    /// Parent span ID (optional)
    pub parent_span_id: Option<String>,
    /// Timestamp (Unix timestamp in microseconds)
    pub timestamp: u64,
    /// Event type
    pub event_type: EventType,
    /// Agent ID
    pub agent_id: String,
    /// Session ID (optional)
    pub session_id: Option<String>,
    /// Action being performed
    pub action: Option<String>,
    /// Resource being accessed
    pub resource: Option<String>,
    /// Input data (may be redacted)
    pub input: Option<serde_json::Value>,
    /// Output data (may be redacted)
    pub output: Option<serde_json::Value>,
    /// Decision (for policy events)
    pub decision: Option<String>,
    /// Duration in microseconds (for completed operations)
    pub duration_us: Option<u64>,
    /// Error message (if any)
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
    /// Whether this is a shadow mode event
    pub shadow_mode: bool,
    /// State hash (for deterministic replay)
    pub state_hash: Option<String>,
    /// Hash of this event (for chain integrity)
    pub hash: String,
    /// Hash of previous event (chain linkage)
    pub prev_hash: String,
}

impl FlightEvent {
    /// Create a new flight event
    pub fn new(
        trace_id: impl Into<String>,
        event_type: EventType,
        agent_id: impl Into<String>,
    ) -> Self {
        let event_id = Uuid::new_v4().to_string();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        Self {
            event_id,
            trace_id: trace_id.into(),
            span_id: None,
            parent_span_id: None,
            timestamp,
            event_type,
            agent_id: agent_id.into(),
            session_id: None,
            action: None,
            resource: None,
            input: None,
            output: None,
            decision: None,
            duration_us: None,
            error: None,
            metadata: None,
            shadow_mode: false,
            state_hash: None,
            hash: String::new(),
            prev_hash: String::new(),
        }
    }

    /// Builder: set span ID
    pub fn with_span(mut self, span_id: impl Into<String>) -> Self {
        self.span_id = Some(span_id.into());
        self
    }

    /// Builder: set parent span ID
    pub fn with_parent_span(mut self, parent_span_id: impl Into<String>) -> Self {
        self.parent_span_id = Some(parent_span_id.into());
        self
    }

    /// Builder: set session ID
    pub fn with_session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Builder: set action
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Builder: set resource
    pub fn with_resource(mut self, resource: impl Into<String>) -> Self {
        self.resource = Some(resource.into());
        self
    }

    /// Builder: set input
    pub fn with_input(mut self, input: serde_json::Value) -> Self {
        self.input = Some(input);
        self
    }

    /// Builder: set output
    pub fn with_output(mut self, output: serde_json::Value) -> Self {
        self.output = Some(output);
        self
    }

    /// Builder: set decision
    pub fn with_decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    /// Builder: set duration
    pub fn with_duration(mut self, duration_us: u64) -> Self {
        self.duration_us = Some(duration_us);
        self
    }

    /// Builder: set error
    pub fn with_error(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Builder: set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Builder: mark as shadow mode
    pub fn as_shadow(mut self) -> Self {
        self.shadow_mode = true;
        self
    }

    /// Builder: set state hash
    pub fn with_state_hash(mut self, state_hash: impl Into<String>) -> Self {
        self.state_hash = Some(state_hash.into());
        self
    }

    /// Calculate and set the hash for this event
    pub fn compute_hash(&mut self, prev_hash: &str) {
        self.prev_hash = prev_hash.to_string();

        // Hash the event content (excluding hash fields)
        let content = format!(
            "{}:{}:{}:{}:{}:{:?}:{:?}:{:?}:{:?}:{}:{:?}",
            self.event_id,
            self.trace_id,
            self.timestamp,
            self.agent_id,
            self.event_type_str(),
            self.action,
            self.resource,
            self.decision,
            self.shadow_mode,
            self.prev_hash,
            self.state_hash
        );

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        self.hash = hex::encode(hasher.finalize());
    }

    /// Get event type as string
    fn event_type_str(&self) -> String {
        match &self.event_type {
            EventType::Request => "request".to_string(),
            EventType::Response => "response".to_string(),
            EventType::PolicyEvaluation => "policy_evaluation".to_string(),
            EventType::ToolExecution => "tool_execution".to_string(),
            EventType::Error => "error".to_string(),
            EventType::TraceStart => "trace_start".to_string(),
            EventType::TraceEnd => "trace_end".to_string(),
            EventType::SpanStart => "span_start".to_string(),
            EventType::SpanEnd => "span_end".to_string(),
            EventType::Custom(name) => format!("custom:{}", name),
        }
    }
}

// ============================================================================
// Trace Receipt
// ============================================================================

/// A cryptographic receipt for a recorded trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReceipt {
    /// Trace ID
    pub trace_id: String,
    /// Start timestamp
    pub start_time: u64,
    /// End timestamp
    pub end_time: u64,
    /// Total number of events
    pub event_count: usize,
    /// Root hash (first event hash)
    pub root_hash: String,
    /// Final hash (last event hash)
    pub final_hash: String,
    /// Whether trace was in shadow mode
    pub shadow_mode: bool,
    /// Summary of decisions
    pub decision_summary: HashMap<String, u32>,
    /// Summary of event types
    pub event_type_summary: HashMap<String, u32>,
}

// ============================================================================
// Flight Recorder
// ============================================================================

/// Flight recorder for shadow mode and trace recording
pub struct FlightRecorder {
    config: RecorderConfig,
    /// Current trace ID
    current_trace_id: RwLock<Option<String>>,
    /// Events in memory
    events: RwLock<Vec<FlightEvent>>,
    /// Event count
    event_count: AtomicU64,
    /// Last event hash (for chain linking)
    last_hash: RwLock<String>,
    /// File handle for persistent storage
    file_handle: Mutex<Option<File>>,
    /// Active spans for timing
    active_spans: RwLock<HashMap<String, Instant>>,
}

impl FlightRecorder {
    /// Create a new flight recorder
    pub fn new(config: RecorderConfig) -> Self {
        let file_handle = config
            .storage_path
            .as_ref()
            .map(|path| {
                // Ensure directory exists
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                OpenOptions::new().create(true).append(true).open(path).ok()
            })
            .flatten();

        Self {
            config,
            current_trace_id: RwLock::new(None),
            events: RwLock::new(Vec::new()),
            event_count: AtomicU64::new(0),
            last_hash: RwLock::new("genesis".to_string()),
            file_handle: Mutex::new(file_handle),
            active_spans: RwLock::new(HashMap::new()),
        }
    }

    /// Check if shadow mode is enabled
    pub fn is_shadow_mode(&self) -> bool {
        self.config.shadow_mode
    }

    /// Start a new trace
    pub fn start_trace(&self, agent_id: &str) -> String {
        let trace_id = Uuid::new_v4().to_string();

        {
            let mut current = self.current_trace_id.write().unwrap();
            *current = Some(trace_id.clone());
        }

        // Record trace start event
        let mut event = FlightEvent::new(&trace_id, EventType::TraceStart, agent_id);
        if self.config.shadow_mode {
            event = event.as_shadow();
        }
        self.record_event(event);

        trace_id
    }

    /// End the current trace
    pub fn end_trace(&self, agent_id: &str) -> Option<TraceReceipt> {
        let trace_id = {
            let mut current = self.current_trace_id.write().unwrap();
            current.take()
        }?;

        // Record trace end event
        let mut event = FlightEvent::new(&trace_id, EventType::TraceEnd, agent_id);
        if self.config.shadow_mode {
            event = event.as_shadow();
        }
        self.record_event(event);

        // Generate receipt
        Some(self.generate_receipt_for_trace(&trace_id))
    }

    /// Start a span within a trace
    pub fn start_span(&self, span_id: &str, parent_span_id: Option<&str>, agent_id: &str) {
        // Record span start time
        {
            let mut spans = self.active_spans.write().unwrap();
            spans.insert(span_id.to_string(), Instant::now());
        }

        // Record span start event
        let trace_id = self
            .get_current_trace_id()
            .unwrap_or_else(|| "default".to_string());
        let mut event =
            FlightEvent::new(&trace_id, EventType::SpanStart, agent_id).with_span(span_id);

        if let Some(parent) = parent_span_id {
            event = event.with_parent_span(parent);
        }

        if self.config.shadow_mode {
            event = event.as_shadow();
        }

        self.record_event(event);
    }

    /// End a span
    pub fn end_span(&self, span_id: &str, agent_id: &str) {
        let duration_us = {
            let mut spans = self.active_spans.write().unwrap();
            spans
                .remove(span_id)
                .map(|start| start.elapsed().as_micros() as u64)
        };

        let trace_id = self
            .get_current_trace_id()
            .unwrap_or_else(|| "default".to_string());
        let mut event =
            FlightEvent::new(&trace_id, EventType::SpanEnd, agent_id).with_span(span_id);

        if let Some(dur) = duration_us {
            event = event.with_duration(dur);
        }

        if self.config.shadow_mode {
            event = event.as_shadow();
        }

        self.record_event(event);
    }

    /// Record a request event
    pub fn record_request(
        &self,
        agent_id: &str,
        action: &str,
        resource: &str,
        input: Option<serde_json::Value>,
    ) {
        if !self.config.record_requests {
            return;
        }

        let trace_id = self
            .get_current_trace_id()
            .unwrap_or_else(|| "default".to_string());
        let mut event = FlightEvent::new(&trace_id, EventType::Request, agent_id)
            .with_action(action)
            .with_resource(resource);

        if let Some(inp) = input {
            let redacted = if self.config.redact_sensitive {
                self.redact_sensitive_fields(inp)
            } else {
                inp
            };
            event = event.with_input(redacted);
        }

        if self.config.shadow_mode {
            event = event.as_shadow();
        }

        self.record_event(event);
    }

    /// Record a response event
    pub fn record_response(
        &self,
        agent_id: &str,
        action: &str,
        success: bool,
        output: Option<serde_json::Value>,
    ) {
        if !self.config.record_requests {
            return;
        }

        let trace_id = self
            .get_current_trace_id()
            .unwrap_or_else(|| "default".to_string());
        let mut event = FlightEvent::new(&trace_id, EventType::Response, agent_id)
            .with_action(action)
            .with_decision(if success { "success" } else { "failure" });

        if let Some(out) = output {
            let redacted = if self.config.redact_sensitive {
                self.redact_sensitive_fields(out)
            } else {
                out
            };
            event = event.with_output(redacted);
        }

        if self.config.shadow_mode {
            event = event.as_shadow();
        }

        self.record_event(event);
    }

    /// Record a policy evaluation
    pub fn record_policy_decision(
        &self,
        agent_id: &str,
        decision: &str,
        matched_rule: Option<&str>,
        evaluation_time_us: u64,
    ) {
        if !self.config.record_policy_decisions {
            return;
        }

        let trace_id = self
            .get_current_trace_id()
            .unwrap_or_else(|| "default".to_string());
        let mut event = FlightEvent::new(&trace_id, EventType::PolicyEvaluation, agent_id)
            .with_decision(decision)
            .with_duration(evaluation_time_us);

        if let Some(rule) = matched_rule {
            event = event.with_metadata(serde_json::json!({
                "matched_rule": rule
            }));
        }

        if self.config.shadow_mode {
            event = event.as_shadow();
        }

        self.record_event(event);
    }

    /// Record a tool execution
    pub fn record_tool_execution(
        &self,
        agent_id: &str,
        tool_name: &str,
        success: bool,
        duration_us: u64,
        error: Option<&str>,
    ) {
        if !self.config.record_tool_executions {
            return;
        }

        let trace_id = self
            .get_current_trace_id()
            .unwrap_or_else(|| "default".to_string());
        let mut event = FlightEvent::new(&trace_id, EventType::ToolExecution, agent_id)
            .with_action(tool_name)
            .with_decision(if success { "success" } else { "failure" })
            .with_duration(duration_us);

        if let Some(err) = error {
            event = event.with_error(err);
        }

        if self.config.shadow_mode {
            event = event.as_shadow();
        }

        self.record_event(event);
    }

    /// Record an error event
    pub fn record_error(
        &self,
        agent_id: &str,
        error_message: &str,
        context: Option<serde_json::Value>,
    ) {
        let trace_id = self
            .get_current_trace_id()
            .unwrap_or_else(|| "default".to_string());
        let mut event =
            FlightEvent::new(&trace_id, EventType::Error, agent_id).with_error(error_message);

        if let Some(ctx) = context {
            event = event.with_metadata(ctx);
        }

        if self.config.shadow_mode {
            event = event.as_shadow();
        }

        self.record_event(event);
    }

    /// Record a generic event
    fn record_event(&self, mut event: FlightEvent) {
        // Compute hash chain
        if self.config.enable_chain_hashing {
            let prev_hash = self.last_hash.read().unwrap().clone();
            event.compute_hash(&prev_hash);

            {
                let mut last = self.last_hash.write().unwrap();
                *last = event.hash.clone();
            }
        }

        // Persist to file if configured
        if let Ok(mut guard) = self.file_handle.lock() {
            if let Some(ref mut file) = *guard {
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = writeln!(file, "{}", json);
                }
            }
        }

        // Store in memory
        {
            let mut events = self.events.write().unwrap();
            events.push(event);

            // Trim if over limit
            if events.len() > self.config.max_memory_events {
                let drain_count = events.len() - self.config.max_memory_events;
                events.drain(0..drain_count);
            }
        }

        self.event_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current trace ID
    pub fn get_current_trace_id(&self) -> Option<String> {
        self.current_trace_id.read().unwrap().clone()
    }

    /// Get all events for a trace
    pub fn get_trace_events(&self, trace_id: &str) -> Vec<FlightEvent> {
        let events = self.events.read().unwrap();
        events
            .iter()
            .filter(|e| e.trace_id == trace_id)
            .cloned()
            .collect()
    }

    /// Generate a receipt for the current trace
    pub fn generate_receipt(&self) -> Option<TraceReceipt> {
        let trace_id = self.get_current_trace_id()?;
        Some(self.generate_receipt_for_trace(&trace_id))
    }

    /// Generate a receipt for a specific trace
    pub fn generate_receipt_for_trace(&self, trace_id: &str) -> TraceReceipt {
        let events = self.get_trace_events(trace_id);

        let start_time = events.first().map(|e| e.timestamp).unwrap_or(0);
        let end_time = events.last().map(|e| e.timestamp).unwrap_or(0);
        let root_hash = events.first().map(|e| e.hash.clone()).unwrap_or_default();
        let final_hash = events.last().map(|e| e.hash.clone()).unwrap_or_default();

        let mut decision_summary: HashMap<String, u32> = HashMap::new();
        let mut event_type_summary: HashMap<String, u32> = HashMap::new();
        let mut shadow_mode = false;

        for event in &events {
            // Count event types
            let type_key = event.event_type_str();
            *event_type_summary.entry(type_key).or_insert(0) += 1;

            // Count decisions
            if let Some(ref decision) = event.decision {
                *decision_summary.entry(decision.clone()).or_insert(0) += 1;
            }

            // Check shadow mode
            if event.shadow_mode {
                shadow_mode = true;
            }
        }

        TraceReceipt {
            trace_id: trace_id.to_string(),
            start_time,
            end_time,
            event_count: events.len(),
            root_hash,
            final_hash,
            shadow_mode,
            decision_summary,
            event_type_summary,
        }
    }

    /// Verify chain integrity for a trace
    pub fn verify_chain_integrity(&self, trace_id: &str) -> bool {
        if !self.config.enable_chain_hashing {
            return true;
        }

        let events = self.get_trace_events(trace_id);
        if events.is_empty() {
            return true;
        }

        let mut expected_prev = "genesis".to_string();
        for event in &events {
            if event.prev_hash != expected_prev {
                return false;
            }
            expected_prev = event.hash.clone();
        }

        true
    }

    /// Get event count
    pub fn event_count(&self) -> u64 {
        self.event_count.load(Ordering::Relaxed)
    }

    /// Clear all events (for testing)
    pub fn clear(&self) {
        let mut events = self.events.write().unwrap();
        events.clear();
        self.event_count.store(0, Ordering::Relaxed);

        let mut last_hash = self.last_hash.write().unwrap();
        *last_hash = "genesis".to_string();
    }

    /// Redact sensitive fields from JSON value
    fn redact_sensitive_fields(&self, value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(mut map) => {
                for (key, val) in map.clone() {
                    let key_lower = key.to_lowercase();
                    if self
                        .config
                        .sensitive_patterns
                        .iter()
                        .any(|p| key_lower.contains(p))
                    {
                        map.insert(key, serde_json::Value::String("[REDACTED]".to_string()));
                    } else {
                        map.insert(key, self.redact_sensitive_fields(val));
                    }
                }
                serde_json::Value::Object(map)
            }
            serde_json::Value::Array(arr) => serde_json::Value::Array(
                arr.into_iter()
                    .map(|v| self.redact_sensitive_fields(v))
                    .collect(),
            ),
            other => other,
        }
    }
}

impl std::fmt::Debug for FlightRecorder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlightRecorder")
            .field("config", &self.config)
            .field("event_count", &self.event_count.load(Ordering::Relaxed))
            .field("shadow_mode", &self.config.shadow_mode)
            .finish()
    }
}

// ============================================================================
// Replay Engine
// ============================================================================

/// Replays recorded traces for validation
pub struct ReplayEngine {
    events: Vec<FlightEvent>,
}

impl ReplayEngine {
    /// Create a replay engine from recorded events
    pub fn new(events: Vec<FlightEvent>) -> Self {
        Self { events }
    }

    /// Load events from a JSONL file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if let Ok(event) = serde_json::from_str::<FlightEvent>(&line) {
                events.push(event);
            }
        }

        Ok(Self { events })
    }

    /// Get all events
    pub fn events(&self) -> &[FlightEvent] {
        &self.events
    }

    /// Get events for a specific trace
    pub fn get_trace(&self, trace_id: &str) -> Vec<&FlightEvent> {
        self.events
            .iter()
            .filter(|e| e.trace_id == trace_id)
            .collect()
    }

    /// Get all unique trace IDs
    pub fn trace_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.events.iter().map(|e| e.trace_id.clone()).collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Verify chain integrity
    pub fn verify_chain(&self, trace_id: &str) -> bool {
        let events: Vec<_> = self.get_trace(trace_id);
        if events.is_empty() {
            return true;
        }

        let mut expected_prev = "genesis".to_string();
        for event in events {
            if event.prev_hash != expected_prev {
                return false;
            }
            expected_prev = event.hash.clone();
        }

        true
    }

    /// Get summary statistics
    pub fn summary(&self) -> ReplaySummary {
        let mut summary = ReplaySummary::default();

        for event in &self.events {
            summary.total_events += 1;

            if event.shadow_mode {
                summary.shadow_events += 1;
            }

            match &event.event_type {
                EventType::Request => summary.request_count += 1,
                EventType::Response => summary.response_count += 1,
                EventType::PolicyEvaluation => summary.policy_evaluations += 1,
                EventType::ToolExecution => summary.tool_executions += 1,
                EventType::Error => summary.error_count += 1,
                _ => {}
            }

            if let Some(ref decision) = event.decision {
                *summary.decisions.entry(decision.clone()).or_insert(0) += 1;
            }
        }

        summary.trace_count = self.trace_ids().len();
        summary
    }

    /// Replay a trace using a provided executor
    ///
    /// This method allows deterministic replay of a recorded trace by executing
    /// the actions again and comparing the results with the recorded outputs.
    ///
    /// # Arguments
    /// * `trace_id` - The trace to replay
    /// * `executor` - Async closure that takes an event and returns the execution result
    pub async fn replay_trace<F, Fut>(
        &self,
        trace_id: &str,
        mut executor: F,
    ) -> Result<ReplayReport, String>
    where
        F: FnMut(&FlightEvent) -> Fut,
        Fut: std::future::Future<Output = Result<Option<serde_json::Value>, String>>,
    {
        let events = self.get_trace(trace_id);
        if events.is_empty() {
            return Err(format!("Trace {} not found", trace_id));
        }

        let mut report = ReplayReport {
            trace_id: trace_id.to_string(),
            events_replayed: 0,
            matches: 0,
            mismatches: 0,
            errors: 0,
            mismatch_details: Vec::new(),
        };

        for event in events {
            // Only replay events that imply action/computation
            match event.event_type {
                EventType::ToolExecution | EventType::PolicyEvaluation | EventType::Request => {
                    report.events_replayed += 1;
                    match executor(event).await {
                        Ok(actual_output) => {
                            // Compare output if recorded
                            if let Some(recorded_output) = &event.output {
                                if let Some(actual) = &actual_output {
                                    if recorded_output == actual {
                                        report.matches += 1;
                                    } else {
                                        report.mismatches += 1;
                                        report.mismatch_details.push(MismatchDetail {
                                            event_id: event.event_id.clone(),
                                            expected: recorded_output.clone(),
                                            actual: actual.clone(),
                                        });
                                    }
                                } else {
                                    // Recorded output exists but actual is None
                                    report.mismatches += 1;
                                    report.mismatch_details.push(MismatchDetail {
                                        event_id: event.event_id.clone(),
                                        expected: recorded_output.clone(),
                                        actual: serde_json::Value::Null,
                                    });
                                }
                            } else {
                                // No recorded output to compare
                                report.matches += 1;
                            }
                        }
                        Err(e) => {
                            report.errors += 1;
                            report.mismatch_details.push(MismatchDetail {
                                event_id: event.event_id.clone(),
                                expected: serde_json::Value::String("Success".to_string()),
                                actual: serde_json::Value::String(format!("Error: {}", e)),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(report)
    }
}

/// Summary of replay statistics
#[derive(Debug, Default)]
pub struct ReplaySummary {
    pub total_events: usize,
    pub shadow_events: usize,
    pub trace_count: usize,
    pub request_count: usize,
    pub response_count: usize,
    pub policy_evaluations: usize,
    pub tool_executions: usize,
    pub error_count: usize,
    pub decisions: HashMap<String, usize>,
}

/// Report from a replay execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    pub trace_id: String,
    pub events_replayed: usize,
    pub matches: usize,
    pub mismatches: usize,
    pub errors: usize,
    pub mismatch_details: Vec<MismatchDetail>,
}

/// Detail of a replay mismatch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchDetail {
    pub event_id: String,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flight_recorder_basic() {
        let config = RecorderConfig::default();
        let recorder = FlightRecorder::new(config);

        let trace_id = recorder.start_trace("test-agent");

        recorder.record_request("test-agent", "read", "/data/file.txt", None);
        recorder.record_policy_decision("test-agent", "allow", Some("rule-1"), 100);
        recorder.record_response("test-agent", "read", true, None);

        let receipt = recorder.end_trace("test-agent").unwrap();

        assert_eq!(receipt.trace_id, trace_id);
        assert!(receipt.event_count >= 4); // start, request, policy, response, end
    }

    #[test]
    fn test_shadow_mode() {
        let config = RecorderConfig::shadow_mode();
        let recorder = FlightRecorder::new(config);

        assert!(recorder.is_shadow_mode());

        let trace_id = recorder.start_trace("test-agent");
        recorder.record_request("test-agent", "write", "/data/file.txt", None);

        let events = recorder.get_trace_events(&trace_id);
        assert!(events.iter().all(|e| e.shadow_mode));
    }

    #[test]
    fn test_chain_integrity() {
        let config = RecorderConfig::default();
        let recorder = FlightRecorder::new(config);

        let trace_id = recorder.start_trace("test-agent");
        recorder.record_request("test-agent", "read", "/resource", None);
        recorder.record_response("test-agent", "read", true, None);
        recorder.end_trace("test-agent");

        assert!(recorder.verify_chain_integrity(&trace_id));
    }

    #[test]
    fn test_sensitive_data_redaction() {
        let config = RecorderConfig::default();
        let recorder = FlightRecorder::new(config);

        let input = serde_json::json!({
            "username": "user",
            "password": "secret123",
            "api_key": "key123",
            "data": {
                "token": "abc",
                "value": 42
            }
        });

        recorder.start_trace("test-agent");
        recorder.record_request("test-agent", "login", "/auth", Some(input));

        let events = recorder.events.read().unwrap();
        let request = events
            .iter()
            .find(|e| matches!(e.event_type, EventType::Request))
            .unwrap();

        let input = request.input.as_ref().unwrap();
        assert_eq!(input["password"], "[REDACTED]");
        assert_eq!(input["api_key"], "[REDACTED]");
        assert_eq!(input["data"]["token"], "[REDACTED]");
        assert_eq!(input["username"], "user"); // Not redacted
    }

    #[test]
    fn test_replay_engine() {
        let config = RecorderConfig::default();
        let recorder = FlightRecorder::new(config);

        let trace_id = recorder.start_trace("agent-1");
        recorder.record_request("agent-1", "test", "/res", None);
        recorder.end_trace("agent-1");

        let events = recorder.events.read().unwrap().clone();
        let replay = ReplayEngine::new(events);

        let summary = replay.summary();
        assert!(summary.total_events >= 3);
        assert_eq!(summary.trace_count, 1);
    }

    #[test]
    fn test_spans() {
        let config = RecorderConfig::default();
        let recorder = FlightRecorder::new(config);

        recorder.start_trace("agent-1");
        recorder.start_span("span-1", None, "agent-1");
        recorder.start_span("span-2", Some("span-1"), "agent-1");

        std::thread::sleep(std::time::Duration::from_millis(10));

        recorder.end_span("span-2", "agent-1");
        recorder.end_span("span-1", "agent-1");
        recorder.end_trace("agent-1");

        let events = recorder.events.read().unwrap();
        let span_ends: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.event_type, EventType::SpanEnd))
            .collect();

        assert_eq!(span_ends.len(), 2);
        // Duration should be recorded
        assert!(span_ends.iter().all(|e| e.duration_us.is_some()));
    }
}
