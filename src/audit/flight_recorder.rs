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
//! The flight recorder captures what its caller records. `Kernel::execute`
//! doesn't write to it. It can hold:
//! - requests and responses;
//! - policy evaluation decisions;
//! - tool execution attempts;
//! - errors, timing and spans.
//!
//! Every event is hash-chained to the one before it, across traces.
//! [`FlightRecorder::verify_chain_integrity`] and [`ReplayEngine::verify_chain`]
//! recompute every hash, so an edited, removed or reordered event is
//! detected ([`verify_events`]).
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
//! recorder.record_policy_decision("agent-1", "allow", Some("rule-1"), 5);
//! recorder.record_response("agent-1", "read", true, Some(serde_json::json!("file contents")));
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

// Configuration

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

// Event Types

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

    /// Links this event to `prev_hash` and sets its hash.
    pub fn compute_hash(&mut self, prev_hash: &str) {
        self.prev_hash = prev_hash.to_string();
        self.hash = self.expected_hash();
    }

    /// The hash this event should carry: SHA-256 over a domain tag and the
    /// event's JSON with `hash` left empty. It covers every other field,
    /// `prev_hash`, input, output, error and metadata included, so changing
    /// any of them is detected.
    ///
    /// Version 1 hashed only some fields, joined with `:`. Its input,
    /// output, error and metadata could change without changing the hash,
    /// and events recorded with it no longer verify.
    pub fn expected_hash(&self) -> String {
        let mut unhashed = self.clone();
        unhashed.hash = String::new();
        // Serializing these types can't fail: every map key is a string.
        let body = serde_json::to_vec(&unhashed).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update((EVENT_HASH_TAG.len() as u64).to_be_bytes());
        hasher.update(EVENT_HASH_TAG);
        hasher.update((body.len() as u64).to_be_bytes());
        hasher.update(&body);
        hex::encode(hasher.finalize())
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

/// Domain tag of an event hash (version 2).
const EVENT_HASH_TAG: &[u8] = b"vak-flight-event-v2";

/// The `prev_hash` of a recorder's first event.
pub const GENESIS: &str = "genesis";

/// Checks a run of consecutive events from one recorder: each links to the
/// one before it, the first to `anchor`, and each carries the hash its
/// contents give.
///
/// A recorder chains every event it records, whatever its trace, so a trace
/// is checked by checking the run that holds it.
///
/// # Errors
///
/// The index of the first event that doesn't link or whose hash doesn't
/// match.
pub fn verify_events(events: &[FlightEvent], anchor: &str) -> Result<(), usize> {
    let mut expected_prev = anchor;
    for (index, event) in events.iter().enumerate() {
        if event.prev_hash != expected_prev || event.hash != event.expected_hash() {
            return Err(index);
        }
        expected_prev = &event.hash;
    }
    Ok(())
}

// Trace Receipt

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

// Flight Recorder

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
    /// What the first event in memory links to: genesis, or the hash of the
    /// last event trimmed off by `max_memory_events`.
    anchor: RwLock<String>,
    /// File handle for persistent storage
    file_handle: Mutex<Option<File>>,
    /// Active spans for timing
    active_spans: RwLock<HashMap<String, Instant>>,
}

impl FlightRecorder {
    /// Create a new flight recorder
    pub fn new(config: RecorderConfig) -> Self {
        let file_handle = config.storage_path.as_ref().and_then(|path| {
            // Ensure directory exists
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).ok();
            }
            OpenOptions::new().create(true).append(true).open(path).ok()
        });

        Self {
            config,
            current_trace_id: RwLock::new(None),
            events: RwLock::new(Vec::new()),
            event_count: AtomicU64::new(0),
            last_hash: RwLock::new(GENESIS.to_string()),
            anchor: RwLock::new(GENESIS.to_string()),
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

        if let Ok(mut current) = self.current_trace_id.write() {
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
        let trace_id = if let Ok(mut current) = self.current_trace_id.write() {
            current.take()
        } else {
            None
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
        if let Ok(mut spans) = self.active_spans.write() {
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
        let duration_us = if let Ok(mut spans) = self.active_spans.write() {
            spans
                .remove(span_id)
                .map(|start| start.elapsed().as_micros() as u64)
        } else {
            None
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
            let prev_hash = self.last_hash.read().map(|h| h.clone()).unwrap_or_default();
            event.compute_hash(&prev_hash);

            if let Ok(mut last) = self.last_hash.write() {
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
        if let Ok(mut events) = self.events.write() {
            events.push(event);

            // Trim if over limit, remembering what the new first event
            // links to so the rest still verifies.
            if events.len() > self.config.max_memory_events {
                let drain_count = events.len() - self.config.max_memory_events;
                if let (Some(last_dropped), Ok(mut anchor)) =
                    (events.get(drain_count - 1), self.anchor.write())
                {
                    *anchor = last_dropped.hash.clone();
                }
                events.drain(0..drain_count);
            }
        }

        self.event_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the current trace ID
    pub fn get_current_trace_id(&self) -> Option<String> {
        self.current_trace_id.read().ok()?.clone()
    }

    /// Get all events for a trace
    pub fn get_trace_events(&self, trace_id: &str) -> Vec<FlightEvent> {
        if let Ok(events) = self.events.read() {
            events
                .iter()
                .filter(|e| e.trace_id == trace_id)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
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

    /// Whether the events in memory form an intact chain and hold `trace_id`.
    ///
    /// Every event is chained, whatever its trace, so this checks every
    /// event in memory, not only the trace's: each must link to the one
    /// before and carry the hash its contents give. After
    /// `max_memory_events` has trimmed old events, the check starts from the
    /// last one trimmed.
    ///
    /// `false` if any event fails, if no event belongs to `trace_id`, or if
    /// `enable_chain_hashing` is off, since then there is nothing to check
    /// against.
    pub fn verify_chain_integrity(&self, trace_id: &str) -> bool {
        if !self.config.enable_chain_hashing {
            return false;
        }
        let (Ok(events), Ok(anchor)) = (self.events.read(), self.anchor.read()) else {
            return false;
        };
        events.iter().any(|e| e.trace_id == trace_id) && verify_events(&events, &anchor).is_ok()
    }

    /// Get event count
    pub fn event_count(&self) -> u64 {
        self.event_count.load(Ordering::Relaxed)
    }

    /// Clear all events (for testing)
    pub fn clear(&self) {
        if let Ok(mut events) = self.events.write() {
            events.clear();
        }
        self.event_count.store(0, Ordering::Relaxed);

        if let Ok(mut last_hash) = self.last_hash.write() {
            *last_hash = GENESIS.to_string();
        }
        if let Ok(mut anchor) = self.anchor.write() {
            *anchor = GENESIS.to_string();
        }
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

// Replay Engine

/// Replays recorded traces for validation
pub struct ReplayEngine {
    events: Vec<FlightEvent>,
}

impl ReplayEngine {
    /// Create a replay engine from recorded events
    pub fn new(events: Vec<FlightEvent>) -> Self {
        Self { events }
    }

    /// Load events from a JSONL file, as a recorder with `storage_path`
    /// writes it.
    ///
    /// # Errors
    ///
    /// The file can't be read, or a line isn't an event. A line that doesn't
    /// parse is an error rather than skipped: skipping it would drop an
    /// event from the record without a trace.
    pub fn from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for (number, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event = serde_json::from_str::<FlightEvent>(&line).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("line {}: {e}", number + 1),
                )
            })?;
            events.push(event);
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

    /// Whether the events form an intact chain from genesis and hold
    /// `trace_id`. As for [`FlightRecorder::verify_chain_integrity`], every
    /// event is checked, since every event is chained.
    pub fn verify_chain(&self, trace_id: &str) -> bool {
        self.events.iter().any(|e| e.trace_id == trace_id)
            && verify_events(&self.events, GENESIS).is_ok()
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
    /// Total number of events in the replay
    pub total_events: usize,
    /// Number of shadow mode events
    pub shadow_events: usize,
    /// Number of unique traces
    pub trace_count: usize,
    /// Number of request events
    pub request_count: usize,
    /// Number of response events
    pub response_count: usize,
    /// Number of policy evaluation events
    pub policy_evaluations: usize,
    /// Number of tool execution events
    pub tool_executions: usize,
    /// Number of error events
    pub error_count: usize,
    /// Map of decision types to their counts
    pub decisions: HashMap<String, usize>,
}

/// Report from a replay execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    /// Trace ID associated with this report
    pub trace_id: String,
    /// Number of events that were replayed
    pub events_replayed: usize,
    /// Number of events that matched the expected output
    pub matches: usize,
    /// Number of events that did not match the expected output
    pub mismatches: usize,
    /// Number of events that produced errors during replay
    pub errors: usize,
    /// Details of each mismatch encountered
    pub mismatch_details: Vec<MismatchDetail>,
}

/// Detail of a replay mismatch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchDetail {
    /// Event ID where the mismatch occurred
    pub event_id: String,
    /// Expected output value from the original recording
    pub expected: serde_json::Value,
    /// Actual output value produced during replay
    pub actual: serde_json::Value,
}

// Tests

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

        let events = recorder.events.read().expect("Lock poisoned");
        let request = events
            .iter()
            .find(|e| matches!(e.event_type, EventType::Request))
            .expect("Request event not found");

        let input = request.input.as_ref().expect("Input is None");
        assert_eq!(input["password"], "[REDACTED]");
        assert_eq!(input["api_key"], "[REDACTED]");
        assert_eq!(input["data"]["token"], "[REDACTED]");
        assert_eq!(input["username"], "user"); // Not redacted
    }

    #[test]
    fn test_replay_engine() {
        let config = RecorderConfig::default();
        let recorder = FlightRecorder::new(config);

        let _trace_id = recorder.start_trace("agent-1");
        recorder.record_request("agent-1", "test", "/res", None);
        recorder.end_trace("agent-1");

        let events = recorder.events.read().expect("Lock poisoned").clone();
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

        let events = recorder.events.read().expect("Lock poisoned");
        let span_ends: Vec<_> = events
            .iter()
            .filter(|e| matches!(e.event_type, EventType::SpanEnd))
            .collect();

        assert_eq!(span_ends.len(), 2);
        // Duration should be recorded
        assert!(span_ends.iter().all(|e| e.duration_us.is_some()));
    }

    /// A recorder with chain hashing, three traces recorded one after the
    /// other, and the events it holds.
    fn three_traces() -> (FlightRecorder, Vec<String>) {
        let recorder = FlightRecorder::new(RecorderConfig::default());
        let mut traces = Vec::new();
        for agent in ["a", "b", "c"] {
            traces.push(recorder.start_trace(agent));
            recorder.record_request(agent, "read", "/file", None);
            recorder.record_policy_decision(agent, "allow", Some("rule-1"), 10);
            recorder.record_response(agent, "read", true, Some(serde_json::json!({"n": 1})));
            recorder.end_trace(agent);
        }
        (recorder, traces)
    }

    #[test]
    fn test_every_trace_verifies_not_only_the_first() {
        // Every event is chained, whatever its trace. Each trace's first
        // event used to be expected to link to genesis, so any trace after
        // the first was reported as broken.
        let (recorder, traces) = three_traces();
        for trace in &traces {
            assert!(recorder.verify_chain_integrity(trace), "{trace}");
        }
        let replay = ReplayEngine::new(recorder.events.read().unwrap().clone());
        for trace in &traces {
            assert!(replay.verify_chain(trace), "{trace}");
        }
        assert_eq!(replay.trace_ids().len(), 3);
    }

    #[test]
    fn test_a_rewritten_event_is_detected() {
        // Verification used to check only that each event named the one
        // before it, so rewriting what an event said went unnoticed.
        type Tamper = fn(&mut FlightEvent);
        let tamperings: [(&str, Tamper); 6] = [
            ("decision", |e| e.decision = Some("deny".into())),
            ("output", |e| e.output = Some(serde_json::json!({"n": 2}))),
            ("input", |e| e.input = Some(serde_json::json!({"x": 1}))),
            ("error", |e| e.error = Some("covered up".into())),
            ("metadata", |e| {
                e.metadata = Some(serde_json::json!({"m": 1}))
            }),
            ("duration", |e| e.duration_us = Some(1)),
        ];
        for (field, tamper) in tamperings {
            let (recorder, traces) = three_traces();
            {
                let mut events = recorder.events.write().unwrap();
                let response = events
                    .iter_mut()
                    .filter(|e| e.trace_id == traces[1])
                    .find(|e| e.event_type == EventType::Response)
                    .unwrap();
                tamper(response);
            }
            for trace in &traces {
                assert!(
                    !recorder.verify_chain_integrity(trace),
                    "rewriting the {field} must not verify"
                );
            }
            let events = recorder.events.read().unwrap().clone();
            assert!(!ReplayEngine::new(events.clone()).verify_chain(&traces[1]));
            assert!(verify_events(&events, GENESIS).is_err());
        }
    }

    #[test]
    fn test_a_removed_or_reordered_event_is_detected() {
        let (recorder, traces) = three_traces();
        let events = recorder.events.read().unwrap().clone();
        assert_eq!(verify_events(&events, GENESIS), Ok(()));

        let mut removed = events.clone();
        removed.remove(5);
        assert_eq!(verify_events(&removed, GENESIS), Err(5));

        let mut swapped = events.clone();
        swapped.swap(3, 4);
        assert_eq!(verify_events(&swapped, GENESIS), Err(3));

        assert_eq!(
            verify_events(&events[1..], GENESIS),
            Err(0),
            "not from genesis"
        );
        assert!(!ReplayEngine::new(removed).verify_chain(&traces[0]));
    }

    #[test]
    fn test_the_chain_still_verifies_after_old_events_are_trimmed() {
        let recorder = FlightRecorder::new(RecorderConfig {
            max_memory_events: 4,
            ..RecorderConfig::default()
        });
        recorder.start_trace("a");
        for i in 0..10 {
            recorder.record_request("a", "read", &format!("/file/{i}"), None);
        }
        let trace = recorder.get_current_trace_id().unwrap();
        assert_eq!(recorder.events.read().unwrap().len(), 4);
        assert_eq!(recorder.event_count(), 11, "the count keeps every event");
        assert!(recorder.verify_chain_integrity(&trace));

        recorder.events.write().unwrap()[1].resource = Some("/elsewhere".into());
        assert!(!recorder.verify_chain_integrity(&trace));
    }

    #[test]
    fn test_nothing_to_check_is_not_verified() {
        let (recorder, _) = three_traces();
        assert!(
            !recorder.verify_chain_integrity("no-such-trace"),
            "an absent trace isn't vouched for"
        );
        assert!(!ReplayEngine::new(Vec::new()).verify_chain("no-such-trace"));

        let unchained = FlightRecorder::new(RecorderConfig::minimal());
        let trace = unchained.start_trace("a");
        assert!(
            !unchained.verify_chain_integrity(&trace),
            "without chain hashing there is nothing to verify against"
        );
    }

    #[test]
    fn test_clear_starts_a_new_chain() {
        // Trimmed first, so the anchor has moved off genesis.
        let recorder = FlightRecorder::new(RecorderConfig {
            max_memory_events: 2,
            ..RecorderConfig::default()
        });
        recorder.start_trace("a");
        for _ in 0..5 {
            recorder.record_request("a", "read", "/f", None);
        }
        recorder.end_trace("a");
        recorder.clear();
        assert_eq!(recorder.event_count(), 0);
        let trace = recorder.start_trace("a");
        assert_eq!(recorder.events.read().unwrap()[0].prev_hash, GENESIS);
        assert!(recorder.verify_chain_integrity(&trace));
    }

    #[test]
    fn test_a_recording_on_disk_replays_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("trace.jsonl");
        let recorder = FlightRecorder::new(RecorderConfig::full(&path));
        let trace = recorder.start_trace("agent-1");
        recorder.record_request(
            "agent-1",
            "login",
            "/auth",
            Some(serde_json::json!({"password": "hunter2", "user": "u"})),
        );
        recorder.record_tool_execution("agent-1", "lookup", false, 25, Some("timeout"));
        recorder.record_error(
            "agent-1",
            "gave up",
            Some(serde_json::json!({"retries": 3})),
        );
        recorder.end_trace("agent-1");

        let replay = ReplayEngine::from_file(&path).unwrap();
        assert_eq!(replay.events().len(), 5);
        assert!(replay.verify_chain(&trace));
        let recorded = replay.get_trace(&trace);
        let login = recorded[1];
        assert_eq!(
            login.input.as_ref().unwrap()["password"],
            "[REDACTED]",
            "secrets never reach the file"
        );
        let summary = replay.summary();
        assert_eq!(
            (
                summary.request_count,
                summary.tool_executions,
                summary.error_count
            ),
            (1, 1, 1)
        );
        assert_eq!(summary.decisions["failure"], 1);

        // A line that doesn't parse is an error, not a silently dropped
        // event.
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            text.replacen("\"trace_start\"", "\"trace_stort\"", 1),
        )
        .unwrap();
        let err = ReplayEngine::from_file(&path).err().expect("refused");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("line 1"), "{err}");
        assert!(ReplayEngine::from_file(dir.path().join("missing.jsonl")).is_err());
    }

    #[test]
    fn test_what_is_recorded_follows_the_config() {
        let recorder = FlightRecorder::new(RecorderConfig {
            record_requests: false,
            record_policy_decisions: false,
            record_tool_executions: false,
            ..RecorderConfig::default()
        });
        let trace = recorder.start_trace("a");
        recorder.record_request("a", "read", "/f", None);
        recorder.record_response("a", "read", true, None);
        recorder.record_policy_decision("a", "allow", None, 1);
        recorder.record_tool_execution("a", "t", true, 1, None);
        recorder.record_error("a", "always recorded", None);
        let kinds: Vec<EventType> = recorder
            .get_trace_events(&trace)
            .into_iter()
            .map(|e| e.event_type)
            .collect();
        assert_eq!(kinds, vec![EventType::TraceStart, EventType::Error]);

        let unredacted = FlightRecorder::new(RecorderConfig {
            redact_sensitive: false,
            ..RecorderConfig::default()
        });
        unredacted.start_trace("a");
        unredacted.record_response("a", "read", true, Some(serde_json::json!([{"token": "t"}])));
        let events = unredacted.events.read().unwrap();
        assert_eq!(events[1].output.as_ref().unwrap()[0]["token"], "t");
    }

    #[test]
    fn test_receipts_summarise_a_trace() {
        let recorder = FlightRecorder::new(RecorderConfig::shadow_mode());
        assert!(recorder.generate_receipt().is_none(), "no trace yet");
        assert!(recorder.end_trace("a").is_none());

        let trace = recorder.start_trace("a");
        recorder.record_policy_decision("a", "allow", None, 5);
        recorder.record_policy_decision("a", "deny", Some("r"), 5);
        recorder.record_tool_execution("a", "t", true, 5, None);
        let receipt = recorder.generate_receipt().unwrap();
        assert_eq!(receipt.trace_id, trace);
        assert_eq!(receipt.event_count, 4);
        assert!(receipt.shadow_mode);
        assert_eq!(receipt.decision_summary["allow"], 1);
        assert_eq!(receipt.decision_summary["deny"], 1);
        assert_eq!(receipt.decision_summary["success"], 1);
        assert_eq!(receipt.event_type_summary["policy_evaluation"], 2);
        let events = recorder.get_trace_events(&trace);
        assert_eq!(receipt.root_hash, events[0].hash);
        assert_eq!(receipt.final_hash, events[3].hash);
        assert!(receipt.end_time >= receipt.start_time);

        let empty = recorder.generate_receipt_for_trace("none");
        assert_eq!((empty.event_count, empty.start_time), (0, 0));
        assert!(format!("{recorder:?}").contains("shadow_mode: true"));
    }

    #[test]
    fn test_custom_events_and_builders_are_hashed() {
        let mut event = FlightEvent::new("t", EventType::Custom("probe".into()), "a")
            .with_session("s")
            .with_parent_span("p")
            .with_state_hash("state");
        event.compute_hash(GENESIS);
        assert_eq!(event.event_type_str(), "custom:probe");
        assert_eq!(event.hash, event.expected_hash());
        let before = event.hash.clone();
        event.session_id = Some("other".into());
        assert_ne!(event.expected_hash(), before, "the session is covered");
    }

    #[tokio::test]
    async fn test_replay_compares_outputs() {
        let recorder = FlightRecorder::new(RecorderConfig::default());
        let trace = recorder.start_trace("a");
        recorder.record_request("a", "read", "/f", None);
        recorder.record_tool_execution("a", "t", true, 1, None);
        recorder.record_policy_decision("a", "allow", None, 1);
        {
            let mut events = recorder.events.write().unwrap();
            events[2].output = Some(serde_json::json!("recorded"));
            events[3].output = Some(serde_json::json!("recorded"));
        }
        let replay = ReplayEngine::new(recorder.events.read().unwrap().clone());

        let report = replay
            .replay_trace(&trace, |event| {
                let output = match event.event_type {
                    EventType::Request => Ok(None),
                    EventType::ToolExecution => Ok(Some(serde_json::json!("recorded"))),
                    _ => Ok(Some(serde_json::json!("different"))),
                };
                async move { output }
            })
            .await
            .unwrap();
        assert_eq!(report.events_replayed, 3);
        assert_eq!(
            (report.matches, report.mismatches, report.errors),
            (2, 1, 0)
        );
        assert_eq!(report.mismatch_details[0].actual, "different");

        let failing = replay
            .replay_trace(&trace, |event| {
                let output = match event.event_type {
                    EventType::ToolExecution => Ok(None),
                    _ => Err("down".to_string()),
                };
                async move { output }
            })
            .await
            .unwrap();
        assert_eq!((failing.mismatches, failing.errors), (1, 2));
        assert!(replay
            .replay_trace("none", |_| async { Ok(None) })
            .await
            .is_err());
    }
}
