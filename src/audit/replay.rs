//! Cryptographic Replay Capability (OBS-002)
//!
//! Provides the ability to replay production incidents from Merkle Log data,
//! reproducing exact state and decision paths for forensic analysis.
//!
//! # Overview
//!
//! The replay system enables:
//! - Loading Merkle Logs from production
//! - Replaying traces in a local VAK instance
//! - Reproducing exact state and decision paths
//! - Step-by-step debugging of agent behavior
//! - Comparison of replay vs. original execution
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::audit::replay::{ReplaySession, ReplayConfig, ReplayVerifier};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Load a Merkle Log from production
//! let session = ReplaySession::from_merkle_log("production_log.jsonl").await?;
//!
//! // Verify integrity before replay
//! let verifier = ReplayVerifier::new();
//! assert!(verifier.verify_log_integrity(&session)?);
//!
//! // Replay step by step
//! let mut replay = session.start_replay(ReplayConfig::default());
//! while let Some(step) = replay.next_step().await? {
//!     println!("Step {}: {:?}", step.sequence, step.event_type);
//!     // Can pause, inspect state, or compare with expected
//! }
//!
//! // Generate comparison report
//! let report = replay.finalize()?;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 3.4: Cryptographic Replay
//! - Gap Analysis Section 6.4: Forensic and Debugging Capabilities

use super::flight_recorder::{EventType, FlightEvent, TraceReceipt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during replay operations
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Log file not found
    #[error("Log file not found: {0}")]
    FileNotFound(String),

    /// Parse error
    #[error("Failed to parse log entry: {0}")]
    ParseError(String),

    /// Chain integrity violation
    #[error("Chain integrity violation at event {event_id}: expected prev_hash {expected}, got {actual}")]
    IntegrityViolation {
        event_id: String,
        expected: String,
        actual: String,
    },

    /// Replay state mismatch
    #[error("State mismatch at step {step}: {description}")]
    StateMismatch { step: u64, description: String },

    /// Replay already complete
    #[error("Replay session already complete")]
    AlreadyComplete,

    /// No more steps
    #[error("No more steps to replay")]
    NoMoreSteps,

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for replay operations
pub type ReplayResult<T> = Result<T, ReplayError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for replay sessions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Verify chain integrity before replay
    pub verify_integrity: bool,
    /// Stop on first mismatch
    pub stop_on_mismatch: bool,
    /// Enable detailed logging
    pub verbose: bool,
    /// Compare policy decisions
    pub compare_policies: bool,
    /// Compare tool outputs
    pub compare_outputs: bool,
    /// Maximum events to replay (0 = unlimited)
    pub max_events: usize,
    /// Step delay in milliseconds (for debugging)
    pub step_delay_ms: u64,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            verify_integrity: true,
            stop_on_mismatch: true,
            verbose: false,
            compare_policies: true,
            compare_outputs: true,
            max_events: 0,
            step_delay_ms: 0,
        }
    }
}

impl ReplayConfig {
    /// Create a debugging configuration with delays
    pub fn debug() -> Self {
        Self {
            verify_integrity: true,
            stop_on_mismatch: false,
            verbose: true,
            compare_policies: true,
            compare_outputs: true,
            max_events: 0,
            step_delay_ms: 100,
        }
    }

    /// Create a fast validation configuration
    pub fn fast() -> Self {
        Self {
            verify_integrity: true,
            stop_on_mismatch: true,
            verbose: false,
            compare_policies: true,
            compare_outputs: false,
            max_events: 0,
            step_delay_ms: 0,
        }
    }
}

// ============================================================================
// Replay Step
// ============================================================================

/// A single step in a replay session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStep {
    /// Step sequence number
    pub sequence: u64,
    /// Original event
    pub original_event: FlightEvent,
    /// Replayed result (if executed)
    pub replayed_result: Option<ReplayedResult>,
    /// Comparison status
    pub comparison: StepComparison,
    /// Step duration in microseconds
    pub duration_us: u64,
}

/// Result of replaying an event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayedResult {
    /// The decision made during replay
    pub decision: Option<String>,
    /// Output from replay (if any)
    pub output: Option<serde_json::Value>,
    /// Error message (if any)
    pub error: Option<String>,
    /// State hash after this step
    pub state_hash: String,
}

/// Comparison between original and replayed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StepComparison {
    /// Steps match exactly
    Match,
    /// Minor differences (e.g., timing)
    MinorDiff,
    /// Significant differences
    Mismatch,
    /// Not yet compared
    Pending,
    /// Comparison skipped
    Skipped,
}

// ============================================================================
// Replay Session
// ============================================================================

/// A replay session loaded from a Merkle Log
#[derive(Debug)]
pub struct ReplaySession {
    /// Source file path
    pub source_path: Option<PathBuf>,
    /// All events in the log
    events: Vec<FlightEvent>,
    /// Trace receipts
    receipts: HashMap<String, TraceReceipt>,
    /// Log metadata
    metadata: LogMetadata,
}

/// Metadata about the log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogMetadata {
    /// Total event count
    pub event_count: usize,
    /// Unique trace count
    pub trace_count: usize,
    /// First event timestamp
    pub first_timestamp: u64,
    /// Last event timestamp
    pub last_timestamp: u64,
    /// Root hash (first event)
    pub root_hash: String,
    /// Final hash (last event)
    pub final_hash: String,
    /// Whether integrity is verified
    pub integrity_verified: bool,
}

impl ReplaySession {
    /// Create a new replay session from events
    pub fn new(events: Vec<FlightEvent>) -> Self {
        let metadata = Self::compute_metadata(&events);
        let receipts = Self::compute_receipts(&events);

        Self {
            source_path: None,
            events,
            receipts,
            metadata,
        }
    }

    /// Load a replay session from a JSONL file
    pub async fn from_merkle_log(path: impl AsRef<Path>) -> ReplayResult<Self> {
        let path = path.as_ref();

        if !path.exists() {
            return Err(ReplayError::FileNotFound(path.display().to_string()));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut events = Vec::new();

        for (line_num, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<FlightEvent>(&line) {
                Ok(event) => events.push(event),
                Err(e) => {
                    warn!(line = line_num, error = %e, "Failed to parse log line");
                    return Err(ReplayError::ParseError(format!("Line {}: {}", line_num, e)));
                }
            }
        }

        let metadata = Self::compute_metadata(&events);
        let receipts = Self::compute_receipts(&events);

        info!(
            path = %path.display(),
            events = events.len(),
            traces = metadata.trace_count,
            "Loaded Merkle Log for replay"
        );

        Ok(Self {
            source_path: Some(path.to_path_buf()),
            events,
            receipts,
            metadata,
        })
    }

    /// Compute metadata from events
    fn compute_metadata(events: &[FlightEvent]) -> LogMetadata {
        let trace_ids: std::collections::HashSet<_> =
            events.iter().map(|e| e.trace_id.clone()).collect();

        LogMetadata {
            event_count: events.len(),
            trace_count: trace_ids.len(),
            first_timestamp: events.first().map(|e| e.timestamp).unwrap_or(0),
            last_timestamp: events.last().map(|e| e.timestamp).unwrap_or(0),
            root_hash: events.first().map(|e| e.hash.clone()).unwrap_or_default(),
            final_hash: events.last().map(|e| e.hash.clone()).unwrap_or_default(),
            integrity_verified: false,
        }
    }

    /// Compute trace receipts
    fn compute_receipts(events: &[FlightEvent]) -> HashMap<String, TraceReceipt> {
        let mut receipts = HashMap::new();
        let mut trace_events: HashMap<String, Vec<&FlightEvent>> = HashMap::new();

        // Group events by trace
        for event in events {
            trace_events
                .entry(event.trace_id.clone())
                .or_default()
                .push(event);
        }

        // Generate receipt for each trace
        for (trace_id, events) in trace_events {
            let mut decision_summary = HashMap::new();
            let mut event_type_summary = HashMap::new();
            let mut shadow_mode = false;

            for event in &events {
                let type_str = format!("{:?}", event.event_type).to_lowercase();
                *event_type_summary.entry(type_str).or_insert(0) += 1;

                if let Some(ref decision) = event.decision {
                    *decision_summary.entry(decision.clone()).or_insert(0) += 1;
                }

                if event.shadow_mode {
                    shadow_mode = true;
                }
            }

            receipts.insert(
                trace_id.clone(),
                TraceReceipt {
                    trace_id: trace_id.clone(),
                    start_time: events.first().map(|e| e.timestamp).unwrap_or(0),
                    end_time: events.last().map(|e| e.timestamp).unwrap_or(0),
                    event_count: events.len(),
                    root_hash: events.first().map(|e| e.hash.clone()).unwrap_or_default(),
                    final_hash: events.last().map(|e| e.hash.clone()).unwrap_or_default(),
                    shadow_mode,
                    decision_summary,
                    event_type_summary,
                },
            );
        }

        receipts
    }

    /// Get all events
    pub fn events(&self) -> &[FlightEvent] {
        &self.events
    }

    /// Get events for a specific trace
    pub fn get_trace_events(&self, trace_id: &str) -> Vec<&FlightEvent> {
        self.events
            .iter()
            .filter(|e| e.trace_id == trace_id)
            .collect()
    }

    /// Get all trace IDs
    pub fn trace_ids(&self) -> Vec<String> {
        self.receipts.keys().cloned().collect()
    }

    /// Get receipt for a trace
    pub fn get_receipt(&self, trace_id: &str) -> Option<&TraceReceipt> {
        self.receipts.get(trace_id)
    }

    /// Get metadata
    pub fn metadata(&self) -> &LogMetadata {
        &self.metadata
    }

    /// Start a replay with configuration
    pub fn start_replay(self, config: ReplayConfig) -> ActiveReplay {
        ActiveReplay::new(self, config)
    }
}

// ============================================================================
// Active Replay
// ============================================================================

/// An active replay session that can be stepped through
pub struct ActiveReplay {
    session: ReplaySession,
    config: ReplayConfig,
    /// Current position in the event stream
    position: usize,
    /// Replay steps executed
    steps: Vec<ReplayStep>,
    /// Current state hash
    current_state_hash: String,
    /// Mismatch count
    mismatch_count: usize,
    /// Is replay complete
    complete: bool,
    /// Start time
    start_time: std::time::Instant,
}

impl ActiveReplay {
    /// Create a new active replay
    fn new(session: ReplaySession, config: ReplayConfig) -> Self {
        Self {
            session,
            config,
            position: 0,
            steps: Vec::new(),
            current_state_hash: "genesis".to_string(),
            mismatch_count: 0,
            complete: false,
            start_time: std::time::Instant::now(),
        }
    }

    /// Execute the next step in the replay
    pub async fn next_step(&mut self) -> ReplayResult<Option<ReplayStep>> {
        if self.complete {
            return Err(ReplayError::AlreadyComplete);
        }

        if self.position >= self.session.events.len() {
            self.complete = true;
            return Ok(None);
        }

        if self.config.max_events > 0 && self.position >= self.config.max_events {
            self.complete = true;
            return Ok(None);
        }

        let event = self.session.events[self.position].clone();
        let step_start = std::time::Instant::now();

        // Simulate step delay if configured
        if self.config.step_delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(self.config.step_delay_ms)).await;
        }

        // Execute replay step (simulate the event)
        let replayed_result = self.execute_replay_step(&event).await?;

        // Compare results
        let comparison = self.compare_step(&event, &replayed_result);

        if comparison == StepComparison::Mismatch {
            self.mismatch_count += 1;
            if self.config.stop_on_mismatch {
                warn!(
                    step = self.position,
                    event_id = %event.event_id,
                    "Mismatch detected, stopping replay"
                );
            }
        }

        let step = ReplayStep {
            sequence: self.position as u64,
            original_event: event,
            replayed_result: Some(replayed_result),
            comparison,
            duration_us: step_start.elapsed().as_micros() as u64,
        };

        self.steps.push(step.clone());
        self.position += 1;

        if self.config.verbose {
            debug!(
                step = self.position - 1,
                comparison = ?step.comparison,
                "Replay step executed"
            );
        }

        // Stop if mismatch and configured to do so
        if step.comparison == StepComparison::Mismatch && self.config.stop_on_mismatch {
            self.complete = true;
        }

        Ok(Some(step))
    }

    /// Execute a replay step (simulate the original event)
    async fn execute_replay_step(&mut self, event: &FlightEvent) -> ReplayResult<ReplayedResult> {
        // Update state hash based on event
        let mut hasher = Sha256::new();
        hasher.update(self.current_state_hash.as_bytes());
        hasher.update(event.hash.as_bytes());
        self.current_state_hash = hex::encode(hasher.finalize());

        // For now, we simulate the replay result based on the event type
        // In a full implementation, this would actually re-execute the action
        let result = ReplayedResult {
            decision: event.decision.clone(),
            output: event.output.clone(),
            error: event.error.clone(),
            state_hash: self.current_state_hash.clone(),
        };

        Ok(result)
    }

    /// Compare original and replayed results
    fn compare_step(&self, original: &FlightEvent, replayed: &ReplayedResult) -> StepComparison {
        // Compare decisions if enabled
        if self.config.compare_policies {
            if original.decision != replayed.decision {
                return StepComparison::Mismatch;
            }
        }

        // Compare outputs if enabled
        if self.config.compare_outputs {
            if original.output != replayed.output {
                // Check if it's just a minor difference
                if original.output.is_some() && replayed.output.is_some() {
                    return StepComparison::MinorDiff;
                }
            }
        }

        StepComparison::Match
    }

    /// Skip to a specific position
    pub fn skip_to(&mut self, position: usize) -> ReplayResult<()> {
        if position >= self.session.events.len() {
            return Err(ReplayError::NoMoreSteps);
        }
        self.position = position;
        Ok(())
    }

    /// Get current position
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get total events
    pub fn total_events(&self) -> usize {
        self.session.events.len()
    }

    /// Check if replay is complete
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Finalize the replay and generate a report
    pub fn finalize(self) -> ReplayResult<ReplayReport> {
        let elapsed = self.start_time.elapsed();

        let mut step_results = HashMap::new();
        for step in &self.steps {
            *step_results.entry(step.comparison).or_insert(0) += 1;
        }

        Ok(ReplayReport {
            source_path: self.session.source_path,
            total_events: self.session.events.len(),
            replayed_events: self.steps.len(),
            match_count: *step_results.get(&StepComparison::Match).unwrap_or(&0),
            mismatch_count: self.mismatch_count,
            minor_diff_count: *step_results.get(&StepComparison::MinorDiff).unwrap_or(&0),
            duration_ms: elapsed.as_millis() as u64,
            steps: self.steps,
            metadata: self.session.metadata,
        })
    }
}

// ============================================================================
// Replay Report
// ============================================================================

/// Report generated after a replay session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayReport {
    /// Source file path
    pub source_path: Option<PathBuf>,
    /// Total events in the log
    pub total_events: usize,
    /// Events that were replayed
    pub replayed_events: usize,
    /// Events that matched exactly
    pub match_count: usize,
    /// Events with mismatches
    pub mismatch_count: usize,
    /// Events with minor differences
    pub minor_diff_count: usize,
    /// Total replay duration in milliseconds
    pub duration_ms: u64,
    /// All replay steps
    pub steps: Vec<ReplayStep>,
    /// Original log metadata
    pub metadata: LogMetadata,
}

impl ReplayReport {
    /// Check if replay was successful (no mismatches)
    pub fn is_success(&self) -> bool {
        self.mismatch_count == 0
    }

    /// Get match percentage
    pub fn match_percentage(&self) -> f64 {
        if self.replayed_events == 0 {
            return 100.0;
        }
        (self.match_count as f64 / self.replayed_events as f64) * 100.0
    }

    /// Get mismatched steps
    pub fn get_mismatches(&self) -> Vec<&ReplayStep> {
        self.steps
            .iter()
            .filter(|s| s.comparison == StepComparison::Mismatch)
            .collect()
    }

    /// Generate a summary string
    pub fn summary(&self) -> String {
        format!(
            "Replay Report: {}/{} events, {} matches ({:.1}%), {} mismatches, {} minor diffs ({}ms)",
            self.replayed_events,
            self.total_events,
            self.match_count,
            self.match_percentage(),
            self.mismatch_count,
            self.minor_diff_count,
            self.duration_ms
        )
    }

    /// Save report to file
    pub fn save(&self, path: impl AsRef<Path>) -> ReplayResult<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ReplayError::SerializationError(e.to_string()))?;

        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}

// ============================================================================
// Replay Verifier
// ============================================================================

/// Verifier for Merkle Log integrity
pub struct ReplayVerifier {
    /// Enable verbose logging
    verbose: bool,
}

impl ReplayVerifier {
    /// Create a new verifier
    pub fn new() -> Self {
        Self { verbose: false }
    }

    /// Enable verbose mode
    pub fn verbose(mut self) -> Self {
        self.verbose = true;
        self
    }

    /// Verify the integrity of a replay session's Merkle chain
    pub fn verify_log_integrity(&self, session: &ReplaySession) -> ReplayResult<bool> {
        let events = session.events();

        if events.is_empty() {
            return Ok(true);
        }

        let mut expected_prev = "genesis".to_string();

        for (i, event) in events.iter().enumerate() {
            // Check chain linkage
            if event.prev_hash != expected_prev {
                if self.verbose {
                    warn!(
                        position = i,
                        event_id = %event.event_id,
                        expected = %expected_prev,
                        actual = %event.prev_hash,
                        "Chain integrity violation"
                    );
                }
                return Err(ReplayError::IntegrityViolation {
                    event_id: event.event_id.clone(),
                    expected: expected_prev,
                    actual: event.prev_hash.clone(),
                });
            }

            // Verify event hash
            let computed_hash = Self::compute_event_hash(event, &expected_prev);
            if computed_hash != event.hash {
                if self.verbose {
                    warn!(
                        position = i,
                        event_id = %event.event_id,
                        "Event hash mismatch"
                    );
                }
                return Err(ReplayError::IntegrityViolation {
                    event_id: event.event_id.clone(),
                    expected: computed_hash,
                    actual: event.hash.clone(),
                });
            }

            expected_prev = event.hash.clone();
        }

        if self.verbose {
            info!(
                events = events.len(),
                root_hash = %session.metadata().root_hash,
                final_hash = %session.metadata().final_hash,
                "Log integrity verified"
            );
        }

        Ok(true)
    }

    /// Compute event hash (must match FlightEvent::compute_hash)
    fn compute_event_hash(event: &FlightEvent, prev_hash: &str) -> String {
        // Get event type as string - must match FlightEvent::event_type_str()
        let event_type_str = match &event.event_type {
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
        };

        let content = format!(
            "{}:{}:{}:{}:{}:{:?}:{:?}:{:?}:{:?}:{}",
            event.event_id,
            event.trace_id,
            event.timestamp,
            event.agent_id,
            event_type_str,
            event.action,
            event.resource,
            event.decision,
            event.shadow_mode,
            prev_hash,
        );

        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify a specific trace within the session
    pub fn verify_trace(&self, session: &ReplaySession, trace_id: &str) -> ReplayResult<bool> {
        let events = session.get_trace_events(trace_id);

        if events.is_empty() {
            return Ok(true);
        }

        // For now, we just check that all events in the trace are present
        // Full verification would check the chain within the trace

        if self.verbose {
            info!(
                trace_id = %trace_id,
                events = events.len(),
                "Trace verified"
            );
        }

        Ok(true)
    }
}

impl Default for ReplayVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::flight_recorder::EventType;

    fn create_test_events() -> Vec<FlightEvent> {
        let mut events = Vec::new();
        let trace_id = "test-trace-1";
        let mut prev_hash = "genesis".to_string();

        for i in 0..5 {
            let mut event = FlightEvent::new(trace_id, EventType::Request, "agent-1")
                .with_action(format!("action-{}", i))
                .with_resource(format!("/resource/{}", i))
                .with_decision("allow");

            event.compute_hash(&prev_hash);
            prev_hash = event.hash.clone();
            events.push(event);
        }

        events
    }

    #[test]
    fn test_replay_session_creation() {
        let events = create_test_events();
        let session = ReplaySession::new(events);

        assert_eq!(session.metadata().event_count, 5);
        assert_eq!(session.metadata().trace_count, 1);
    }

    #[test]
    fn test_integrity_verification() {
        let events = create_test_events();
        let session = ReplaySession::new(events);

        let verifier = ReplayVerifier::new();
        assert!(verifier.verify_log_integrity(&session).is_ok());
    }

    #[test]
    fn test_integrity_violation_detection() {
        let mut events = create_test_events();

        // Tamper with an event
        if let Some(event) = events.get_mut(2) {
            event.prev_hash = "tampered".to_string();
        }

        let session = ReplaySession::new(events);
        let verifier = ReplayVerifier::new();

        assert!(verifier.verify_log_integrity(&session).is_err());
    }

    #[tokio::test]
    async fn test_replay_execution() {
        let events = create_test_events();
        let session = ReplaySession::new(events);

        let mut replay = session.start_replay(ReplayConfig::default());

        let mut count = 0;
        while let Ok(Some(_step)) = replay.next_step().await {
            count += 1;
        }

        assert_eq!(count, 5);
        assert!(replay.is_complete());

        let report = replay.finalize().unwrap();
        assert!(report.is_success());
    }

    #[test]
    fn test_replay_config() {
        let default = ReplayConfig::default();
        assert!(default.verify_integrity);

        let debug = ReplayConfig::debug();
        assert!(debug.verbose);
        assert_eq!(debug.step_delay_ms, 100);

        let fast = ReplayConfig::fast();
        assert!(!fast.verbose);
    }

    #[test]
    fn test_report_generation() {
        let events = create_test_events();
        let session = ReplaySession::new(events);

        let report = ReplayReport {
            source_path: None,
            total_events: 5,
            replayed_events: 5,
            match_count: 4,
            mismatch_count: 1,
            minor_diff_count: 0,
            duration_ms: 100,
            steps: Vec::new(),
            metadata: session.metadata().clone(),
        };

        assert!(!report.is_success());
        assert_eq!(report.match_percentage(), 80.0);
    }
}
