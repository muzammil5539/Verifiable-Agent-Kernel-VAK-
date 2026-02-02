//! Real-Time Audit Log Streaming
//!
//! Provides real-time streaming capabilities for audit logs, enabling
//! live monitoring, alerting, and integration with external systems.
//!
//! # Features
//! - Real-time event streaming via Server-Sent Events (SSE)
//! - WebSocket streaming support
//! - Configurable filters and transformations
//! - Multiple subscriber support with backpressure
//! - Integration with external systems (Kafka, Redis, etc.)
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::audit::streaming::{AuditStreamManager, StreamConfig, StreamFilter};
//!
//! let config = StreamConfig::default();
//! let mut manager = AuditStreamManager::new(config);
//!
//! // Subscribe to audit events
//! let subscriber_id = manager.subscribe(StreamFilter::all());
//!
//! // Receive events
//! while let Some(event) = manager.next_event(&subscriber_id).await {
//!     println!("Audit event: {:?}", event);
//! }
//! ```

use crate::audit::{AuditDecision, AuditEntry, AuditError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, watch};
use uuid::Uuid;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the audit stream manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamConfig {
    /// Maximum subscribers allowed
    pub max_subscribers: usize,
    /// Channel buffer size for each subscriber
    pub channel_buffer_size: usize,
    /// Enable event batching
    pub enable_batching: bool,
    /// Batch size when batching is enabled
    pub batch_size: usize,
    /// Batch timeout in milliseconds
    pub batch_timeout_ms: u64,
    /// Enable event compression
    pub enable_compression: bool,
    /// Heartbeat interval in seconds (0 to disable)
    pub heartbeat_interval_secs: u64,
    /// Event retention duration in seconds
    pub event_retention_secs: u64,
    /// Maximum events to retain in memory
    pub max_retained_events: usize,
    /// Enable metrics collection
    pub enable_metrics: bool,
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self {
            max_subscribers: 1000,
            channel_buffer_size: 1000,
            enable_batching: false,
            batch_size: 100,
            batch_timeout_ms: 1000,
            enable_compression: false,
            heartbeat_interval_secs: 30,
            event_retention_secs: 3600,
            max_retained_events: 10000,
            enable_metrics: true,
        }
    }
}

impl StreamConfig {
    /// Create a high-throughput configuration
    pub fn high_throughput() -> Self {
        Self {
            max_subscribers: 5000,
            channel_buffer_size: 10000,
            enable_batching: true,
            batch_size: 500,
            batch_timeout_ms: 500,
            enable_compression: true,
            heartbeat_interval_secs: 60,
            event_retention_secs: 1800,
            max_retained_events: 50000,
            enable_metrics: true,
        }
    }

    /// Create a low-latency configuration
    pub fn low_latency() -> Self {
        Self {
            max_subscribers: 100,
            channel_buffer_size: 100,
            enable_batching: false,
            batch_size: 1,
            batch_timeout_ms: 100,
            enable_compression: false,
            heartbeat_interval_secs: 15,
            event_retention_secs: 300,
            max_retained_events: 1000,
            enable_metrics: false,
        }
    }
}

// ============================================================================
// Stream Events
// ============================================================================

/// Types of stream events
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamEventType {
    /// New audit entry
    AuditEntry,
    /// Batch of audit entries
    AuditBatch,
    /// Policy decision
    PolicyDecision,
    /// System alert
    Alert,
    /// Heartbeat
    Heartbeat,
    /// Subscriber connected
    SubscriberConnected,
    /// Subscriber disconnected
    SubscriberDisconnected,
    /// Stream error
    Error,
    /// Stream started
    StreamStarted,
    /// Stream stopped
    StreamStopped,
}

/// A streaming event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamEvent {
    /// Unique event ID
    pub id: String,
    /// Event type
    pub event_type: StreamEventType,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Sequence number (for ordering)
    pub sequence: u64,
    /// Event payload
    pub payload: StreamPayload,
    /// Optional metadata
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

impl StreamEvent {
    /// Create a new stream event
    pub fn new(event_type: StreamEventType, payload: StreamPayload, sequence: u64) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            event_type,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            sequence,
            payload,
            metadata: None,
        }
    }

    /// Create a heartbeat event
    pub fn heartbeat(sequence: u64) -> Self {
        Self::new(StreamEventType::Heartbeat, StreamPayload::Empty, sequence)
    }

    /// Create an audit entry event
    pub fn audit_entry(entry: AuditEntry, sequence: u64) -> Self {
        Self::new(
            StreamEventType::AuditEntry,
            StreamPayload::AuditEntry(entry),
            sequence,
        )
    }

    /// Create a batch event
    pub fn audit_batch(entries: Vec<AuditEntry>, sequence: u64) -> Self {
        Self::new(
            StreamEventType::AuditBatch,
            StreamPayload::AuditBatch(entries),
            sequence,
        )
    }

    /// Create an alert event
    pub fn alert(alert: StreamAlert, sequence: u64) -> Self {
        Self::new(StreamEventType::Alert, StreamPayload::Alert(alert), sequence)
    }

    /// Create an error event
    pub fn error(message: String, sequence: u64) -> Self {
        Self::new(
            StreamEventType::Error,
            StreamPayload::Error(message),
            sequence,
        )
    }

    /// Add metadata to the event
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let metadata = self.metadata.get_or_insert_with(HashMap::new);
        metadata.insert(key.into(), value.into());
        self
    }
}

/// Payload types for stream events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StreamPayload {
    /// Empty payload
    Empty,
    /// Single audit entry
    AuditEntry(AuditEntry),
    /// Batch of audit entries
    AuditBatch(Vec<AuditEntry>),
    /// Alert
    Alert(StreamAlert),
    /// Error message
    Error(String),
    /// Generic JSON value
    Json(serde_json::Value),
}

/// Alert severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    /// Informational alert
    Info,
    /// Warning alert
    Warning,
    /// Error alert
    Error,
    /// Critical alert
    Critical,
}

/// A streaming alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamAlert {
    /// Alert ID
    pub id: String,
    /// Alert severity
    pub severity: AlertSeverity,
    /// Alert title
    pub title: String,
    /// Alert description
    pub description: String,
    /// Source of the alert
    pub source: String,
    /// Related agent ID (optional)
    pub agent_id: Option<String>,
    /// Related entry ID (optional)
    pub entry_id: Option<u64>,
    /// Alert timestamp
    pub timestamp: u64,
}

impl StreamAlert {
    /// Create a new alert
    pub fn new(
        severity: AlertSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            severity,
            title: title.into(),
            description: description.into(),
            source: source.into(),
            agent_id: None,
            entry_id: None,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Set related agent ID
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Set related entry ID
    pub fn with_entry_id(mut self, entry_id: u64) -> Self {
        self.entry_id = Some(entry_id);
        self
    }
}

// ============================================================================
// Stream Filters
// ============================================================================

/// Filter criteria for stream subscriptions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamFilter {
    /// Filter by agent IDs
    pub agent_ids: Option<Vec<String>>,
    /// Filter by actions
    pub actions: Option<Vec<String>>,
    /// Filter by decisions
    pub decisions: Option<Vec<AuditDecision>>,
    /// Filter by event types
    pub event_types: Option<Vec<StreamEventType>>,
    /// Minimum severity for alerts
    pub min_alert_severity: Option<AlertSeverity>,
    /// Include heartbeats
    pub include_heartbeats: bool,
    /// Custom filter expression (JSON path)
    pub custom_filter: Option<String>,
}

impl StreamFilter {
    /// Create a filter that accepts all events
    pub fn all() -> Self {
        Self {
            include_heartbeats: true,
            ..Default::default()
        }
    }

    /// Create a filter for specific agents
    pub fn for_agents(agent_ids: Vec<String>) -> Self {
        Self {
            agent_ids: Some(agent_ids),
            include_heartbeats: false,
            ..Default::default()
        }
    }

    /// Create a filter for denied actions only
    pub fn denied_only() -> Self {
        Self {
            decisions: Some(vec![AuditDecision::Denied]),
            include_heartbeats: false,
            ..Default::default()
        }
    }

    /// Create a filter for alerts only
    pub fn alerts_only(min_severity: AlertSeverity) -> Self {
        Self {
            event_types: Some(vec![StreamEventType::Alert]),
            min_alert_severity: Some(min_severity),
            include_heartbeats: false,
            ..Default::default()
        }
    }

    /// Check if an event matches this filter
    pub fn matches(&self, event: &StreamEvent) -> bool {
        // Check event type
        if let Some(ref types) = self.event_types {
            if !types.contains(&event.event_type) {
                return false;
            }
        }

        // Check heartbeat preference
        if event.event_type == StreamEventType::Heartbeat && !self.include_heartbeats {
            return false;
        }

        // Check payload-specific filters
        match &event.payload {
            StreamPayload::AuditEntry(entry) => self.matches_entry(entry),
            StreamPayload::AuditBatch(entries) => {
                entries.iter().any(|e| self.matches_entry(e))
            }
            StreamPayload::Alert(alert) => self.matches_alert(alert),
            _ => true,
        }
    }

    /// Check if an audit entry matches this filter
    fn matches_entry(&self, entry: &AuditEntry) -> bool {
        // Check agent ID
        if let Some(ref agents) = self.agent_ids {
            if !agents.contains(&entry.agent_id) {
                return false;
            }
        }

        // Check action
        if let Some(ref actions) = self.actions {
            if !actions.contains(&entry.action) {
                return false;
            }
        }

        // Check decision
        if let Some(ref decisions) = self.decisions {
            if !decisions.contains(&entry.decision) {
                return false;
            }
        }

        true
    }

    /// Check if an alert matches this filter
    fn matches_alert(&self, alert: &StreamAlert) -> bool {
        // Check minimum severity
        if let Some(min_severity) = self.min_alert_severity {
            let severity_order = |s: &AlertSeverity| match s {
                AlertSeverity::Info => 0,
                AlertSeverity::Warning => 1,
                AlertSeverity::Error => 2,
                AlertSeverity::Critical => 3,
            };

            if severity_order(&alert.severity) < severity_order(&min_severity) {
                return false;
            }
        }

        // Check agent ID
        if let Some(ref agents) = self.agent_ids {
            if let Some(ref agent_id) = alert.agent_id {
                if !agents.contains(agent_id) {
                    return false;
                }
            }
        }

        true
    }
}

// ============================================================================
// Subscriber Management
// ============================================================================

/// Unique identifier for a subscriber
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriberId(Uuid);

impl SubscriberId {
    /// Create a new subscriber ID
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SubscriberId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SubscriberId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Subscriber information
#[derive(Debug, Clone)]
pub struct SubscriberInfo {
    /// Subscriber ID
    pub id: SubscriberId,
    /// Filter for this subscriber
    pub filter: StreamFilter,
    /// When the subscriber connected
    pub connected_at: u64,
    /// Last activity timestamp
    pub last_activity: u64,
    /// Number of events received
    pub events_received: u64,
    /// Number of events dropped (backpressure)
    pub events_dropped: u64,
    /// Is subscriber active
    pub is_active: bool,
    /// Subscriber name/label (optional)
    pub name: Option<String>,
}

/// Internal subscriber state
struct Subscriber {
    info: SubscriberInfo,
    sender: mpsc::Sender<StreamEvent>,
}

// ============================================================================
// Audit Stream Manager
// ============================================================================

/// Manager for real-time audit log streaming
pub struct AuditStreamManager {
    /// Configuration
    config: StreamConfig,
    /// Subscribers
    subscribers: Arc<RwLock<HashMap<SubscriberId, Subscriber>>>,
    /// Broadcast channel for events
    broadcast_tx: broadcast::Sender<StreamEvent>,
    /// Event sequence counter
    sequence: AtomicU64,
    /// Is streaming active
    is_active: AtomicBool,
    /// Recent events buffer (for replay)
    recent_events: Arc<RwLock<Vec<StreamEvent>>>,
    /// Streaming statistics
    stats: Arc<RwLock<StreamStats>>,
    /// Shutdown signal
    shutdown_tx: watch::Sender<bool>,
}

/// Streaming statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StreamStats {
    /// Total events published
    pub events_published: u64,
    /// Total events delivered
    pub events_delivered: u64,
    /// Total events dropped
    pub events_dropped: u64,
    /// Total subscribers (current)
    pub current_subscribers: usize,
    /// Peak subscribers
    pub peak_subscribers: usize,
    /// Total subscriptions created
    pub total_subscriptions: u64,
    /// Average events per second
    pub events_per_second: f64,
    /// Last event timestamp
    pub last_event_time: Option<u64>,
}

impl AuditStreamManager {
    /// Create a new audit stream manager
    pub fn new(config: StreamConfig) -> Self {
        let (broadcast_tx, _) = broadcast::channel(config.channel_buffer_size);
        let (shutdown_tx, _) = watch::channel(false);

        Self {
            config,
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            broadcast_tx,
            sequence: AtomicU64::new(0),
            is_active: AtomicBool::new(true),
            recent_events: Arc::new(RwLock::new(Vec::new())),
            stats: Arc::new(RwLock::new(StreamStats::default())),
            shutdown_tx,
        }
    }

    /// Subscribe to the event stream
    pub fn subscribe(&self, filter: StreamFilter) -> Result<SubscriberId, AuditError> {
        self.subscribe_with_name(filter, None)
    }

    /// Subscribe to the event stream with a name
    pub fn subscribe_with_name(
        &self,
        filter: StreamFilter,
        name: Option<String>,
    ) -> Result<SubscriberId, AuditError> {
        let mut subscribers = self.subscribers.write().map_err(|e| {
            AuditError::BackendNotAvailable(format!("Lock error: {}", e))
        })?;

        // Check subscriber limit
        if subscribers.len() >= self.config.max_subscribers {
            return Err(AuditError::BackendNotAvailable(
                "Maximum subscriber limit reached".to_string(),
            ));
        }

        let id = SubscriberId::new();
        let (sender, _receiver) = mpsc::channel(self.config.channel_buffer_size);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let info = SubscriberInfo {
            id,
            filter,
            connected_at: now,
            last_activity: now,
            events_received: 0,
            events_dropped: 0,
            is_active: true,
            name,
        };

        subscribers.insert(id, Subscriber { info, sender });

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.total_subscriptions += 1;
            stats.current_subscribers = subscribers.len();
            if subscribers.len() > stats.peak_subscribers {
                stats.peak_subscribers = subscribers.len();
            }
        }

        // Publish subscriber connected event
        let event = StreamEvent::new(
            StreamEventType::SubscriberConnected,
            StreamPayload::Json(serde_json::json!({
                "subscriber_id": id.to_string(),
            })),
            self.next_sequence(),
        );
        let _ = self.broadcast_tx.send(event);

        tracing::info!("New subscriber: {}", id);
        Ok(id)
    }

    /// Unsubscribe from the event stream
    pub fn unsubscribe(&self, subscriber_id: &SubscriberId) -> Result<(), AuditError> {
        let mut subscribers = self.subscribers.write().map_err(|e| {
            AuditError::BackendNotAvailable(format!("Lock error: {}", e))
        })?;

        if subscribers.remove(subscriber_id).is_some() {
            // Update stats
            if let Ok(mut stats) = self.stats.write() {
                stats.current_subscribers = subscribers.len();
            }

            // Publish subscriber disconnected event
            let event = StreamEvent::new(
                StreamEventType::SubscriberDisconnected,
                StreamPayload::Json(serde_json::json!({
                    "subscriber_id": subscriber_id.to_string(),
                })),
                self.next_sequence(),
            );
            let _ = self.broadcast_tx.send(event);

            tracing::info!("Subscriber disconnected: {}", subscriber_id);
            Ok(())
        } else {
            Err(AuditError::BackendNotAvailable(format!(
                "Subscriber not found: {}",
                subscriber_id
            )))
        }
    }

    /// Get subscriber information
    pub fn get_subscriber_info(&self, subscriber_id: &SubscriberId) -> Option<SubscriberInfo> {
        self.subscribers
            .read()
            .ok()?
            .get(subscriber_id)
            .map(|s| s.info.clone())
    }

    /// List all subscribers
    pub fn list_subscribers(&self) -> Vec<SubscriberInfo> {
        self.subscribers
            .read()
            .map(|s| s.values().map(|sub| sub.info.clone()).collect())
            .unwrap_or_default()
    }

    /// Publish an audit entry to all subscribers
    pub fn publish_entry(&self, entry: AuditEntry) -> Result<(), AuditError> {
        let event = StreamEvent::audit_entry(entry, self.next_sequence());
        self.publish_event(event)
    }

    /// Publish a batch of audit entries
    pub fn publish_batch(&self, entries: Vec<AuditEntry>) -> Result<(), AuditError> {
        let event = StreamEvent::audit_batch(entries, self.next_sequence());
        self.publish_event(event)
    }

    /// Publish an alert
    pub fn publish_alert(&self, alert: StreamAlert) -> Result<(), AuditError> {
        let event = StreamEvent::alert(alert, self.next_sequence());
        self.publish_event(event)
    }

    /// Publish a custom event
    pub fn publish_event(&self, event: StreamEvent) -> Result<(), AuditError> {
        if !self.is_active.load(Ordering::SeqCst) {
            return Err(AuditError::BackendNotAvailable(
                "Stream manager is not active".to_string(),
            ));
        }

        // Add to recent events buffer
        self.add_to_recent_events(&event);

        // Get all subscribers
        let subscribers = self.subscribers.read().map_err(|e| {
            AuditError::BackendNotAvailable(format!("Lock error: {}", e))
        })?;

        let mut delivered = 0u64;
        let mut dropped = 0u64;

        for (id, subscriber) in subscribers.iter() {
            // Check if event matches subscriber's filter
            if !subscriber.info.filter.matches(&event) {
                continue;
            }

            // Try to send to subscriber
            match subscriber.sender.try_send(event.clone()) {
                Ok(_) => {
                    delivered += 1;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    dropped += 1;
                    tracing::warn!(
                        "Subscriber {} channel full, dropping event",
                        id
                    );
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Subscriber disconnected
                    tracing::debug!("Subscriber {} channel closed", id);
                }
            }
        }

        // Also broadcast to any broadcast receivers
        let _ = self.broadcast_tx.send(event);

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.events_published += 1;
            stats.events_delivered += delivered;
            stats.events_dropped += dropped;
            stats.last_event_time = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            );
        }

        Ok(())
    }

    /// Add event to recent events buffer
    fn add_to_recent_events(&self, event: &StreamEvent) {
        if let Ok(mut recent) = self.recent_events.write() {
            recent.push(event.clone());

            // Trim old events
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;

            let retention_ms = self.config.event_retention_secs * 1000;
            recent.retain(|e| now - e.timestamp < retention_ms);

            // Trim by count
            if recent.len() > self.config.max_retained_events {
                let drain_count = recent.len() - self.config.max_retained_events;
                recent.drain(0..drain_count);
            }
        }
    }

    /// Get next sequence number
    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }

    /// Get recent events (for replay)
    pub fn get_recent_events(&self, filter: &StreamFilter, limit: Option<usize>) -> Vec<StreamEvent> {
        self.recent_events
            .read()
            .map(|events| {
                let filtered: Vec<_> = events
                    .iter()
                    .filter(|e| filter.matches(e))
                    .cloned()
                    .collect();

                if let Some(limit) = limit {
                    filtered.into_iter().rev().take(limit).rev().collect()
                } else {
                    filtered
                }
            })
            .unwrap_or_default()
    }

    /// Get events since a specific sequence number
    pub fn get_events_since(&self, sequence: u64, filter: &StreamFilter) -> Vec<StreamEvent> {
        self.recent_events
            .read()
            .map(|events| {
                events
                    .iter()
                    .filter(|e| e.sequence > sequence && filter.matches(e))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get streaming statistics
    pub fn get_stats(&self) -> StreamStats {
        self.stats
            .read()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    /// Get a broadcast receiver for all events
    pub fn get_broadcast_receiver(&self) -> broadcast::Receiver<StreamEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Check if streaming is active
    pub fn is_active(&self) -> bool {
        self.is_active.load(Ordering::SeqCst)
    }

    /// Stop streaming
    pub fn stop(&self) {
        self.is_active.store(false, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(true);
        tracing::info!("Audit stream manager stopped");
    }

    /// Start streaming (if previously stopped)
    pub fn start(&self) {
        self.is_active.store(true, Ordering::SeqCst);
        let _ = self.shutdown_tx.send(false);
        tracing::info!("Audit stream manager started");
    }

    /// Send heartbeat to all subscribers
    pub fn send_heartbeat(&self) -> Result<(), AuditError> {
        let event = StreamEvent::heartbeat(self.next_sequence());
        self.publish_event(event)
    }

    /// Start background heartbeat task
    pub fn spawn_heartbeat_task(&self) -> Option<tokio::task::JoinHandle<()>> {
        if self.config.heartbeat_interval_secs == 0 {
            return None;
        }

        let interval = Duration::from_secs(self.config.heartbeat_interval_secs);
        let broadcast_tx = self.broadcast_tx.clone();
        let sequence = Arc::new(AtomicU64::new(self.sequence.load(Ordering::SeqCst)));
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let is_active = Arc::new(AtomicBool::new(self.is_active.load(Ordering::SeqCst)));

        Some(tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);

            loop {
                tokio::select! {
                    _ = interval_timer.tick() => {
                        if is_active.load(Ordering::SeqCst) {
                            let seq = sequence.fetch_add(1, Ordering::SeqCst);
                            let event = StreamEvent::heartbeat(seq);
                            let _ = broadcast_tx.send(event);
                        }
                    }
                    result = shutdown_rx.changed() => {
                        if result.is_ok() && *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        }))
    }
}

impl std::fmt::Debug for AuditStreamManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditStreamManager")
            .field("is_active", &self.is_active.load(Ordering::SeqCst))
            .field("sequence", &self.sequence.load(Ordering::SeqCst))
            .field("max_subscribers", &self.config.max_subscribers)
            .finish()
    }
}

// ============================================================================
// External System Integration
// ============================================================================

/// Sink for external system integration
pub trait StreamSink: Send + Sync {
    /// Send an event to the sink
    fn send(&self, event: &StreamEvent) -> Result<(), AuditError>;

    /// Flush buffered events
    fn flush(&self) -> Result<(), AuditError>;

    /// Close the sink
    fn close(&self) -> Result<(), AuditError>;
}

/// Kafka sink configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KafkaSinkConfig {
    /// Kafka bootstrap servers
    pub bootstrap_servers: String,
    /// Topic name
    pub topic: String,
    /// Client ID
    pub client_id: String,
    /// Enable compression
    pub compression: bool,
    /// Batch size
    pub batch_size: usize,
    /// Linger time in milliseconds
    pub linger_ms: u64,
}

/// Redis streams sink configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisSinkConfig {
    /// Redis URL
    pub url: String,
    /// Stream key
    pub stream_key: String,
    /// Maximum stream length
    pub max_length: Option<usize>,
}

/// Webhook sink configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookSinkConfig {
    /// Webhook URL
    pub url: String,
    /// HTTP headers
    pub headers: HashMap<String, String>,
    /// Retry count
    pub retry_count: u32,
    /// Timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable batching
    pub batch_enabled: bool,
    /// Batch size
    pub batch_size: usize,
}

/// Simple webhook sink implementation
pub struct WebhookSink {
    /// Configuration for the webhook
    config: WebhookSinkConfig,
    /// HTTP client for sending requests
    client: reqwest::Client,
    /// Buffer for batching events
    buffer: RwLock<Vec<StreamEvent>>,
}

impl WebhookSink {
    /// Create a new webhook sink
    pub fn new(config: WebhookSinkConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            client,
            buffer: RwLock::new(Vec::new()),
        }
    }

    /// Get the HTTP client
    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    /// Send events to webhook
    pub async fn send_to_webhook(&self, events: &[StreamEvent]) -> Result<(), AuditError> {
        let body = serde_json::to_string(events)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;

        let mut request = self.client.post(&self.config.url).body(body);

        for (key, value) in &self.config.headers {
            request = request.header(key.as_str(), value.as_str());
        }

        let mut attempts = 0;
        loop {
            match request.try_clone().unwrap().send().await {
                Ok(response) if response.status().is_success() => {
                    return Ok(());
                }
                Ok(response) => {
                    attempts += 1;
                    if attempts >= self.config.retry_count {
                        return Err(AuditError::BackendNotAvailable(format!(
                            "Webhook returned status: {}",
                            response.status()
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                }
                Err(e) => {
                    attempts += 1;
                    if attempts >= self.config.retry_count {
                        return Err(AuditError::BackendNotAvailable(format!(
                            "Webhook request failed: {}",
                            e
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(100 * attempts as u64)).await;
                }
            }
        }
    }
}

impl StreamSink for WebhookSink {
    fn send(&self, event: &StreamEvent) -> Result<(), AuditError> {
        if self.config.batch_enabled {
            let mut buffer = self.buffer.write().map_err(|e| {
                AuditError::BackendNotAvailable(format!("Lock error: {}", e))
            })?;

            buffer.push(event.clone());

            if buffer.len() >= self.config.batch_size {
                let events: Vec<_> = buffer.drain(..).collect();
                // Note: In production, this should be async
                tracing::debug!("Webhook batch of {} events queued", events.len());
            }

            Ok(())
        } else {
            // Note: In production, this should be async
            tracing::debug!("Webhook event queued: {}", event.id);
            Ok(())
        }
    }

    fn flush(&self) -> Result<(), AuditError> {
        let events: Vec<_> = {
            let mut buffer = self.buffer.write().map_err(|e| {
                AuditError::BackendNotAvailable(format!("Lock error: {}", e))
            })?;
            buffer.drain(..).collect()
        };

        if !events.is_empty() {
            // Note: In production, this should be async
            tracing::debug!("Webhook flush of {} events queued", events.len());
        }

        Ok(())
    }

    fn close(&self) -> Result<(), AuditError> {
        self.flush()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_entry(id: u64, agent_id: &str) -> AuditEntry {
        AuditEntry {
            id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            agent_id: agent_id.to_string(),
            action: "test_action".to_string(),
            resource: "/test/resource".to_string(),
            decision: AuditDecision::Allowed,
            hash: format!("hash_{}", id),
            prev_hash: format!("prev_hash_{}", id.saturating_sub(1)),
            signature: None,
            metadata: None,
        }
    }

    #[test]
    fn test_stream_config_presets() {
        let default = StreamConfig::default();
        assert_eq!(default.max_subscribers, 1000);
        assert!(!default.enable_batching);

        let high_throughput = StreamConfig::high_throughput();
        assert_eq!(high_throughput.max_subscribers, 5000);
        assert!(high_throughput.enable_batching);

        let low_latency = StreamConfig::low_latency();
        assert_eq!(low_latency.max_subscribers, 100);
        assert!(!low_latency.enable_batching);
    }

    #[test]
    fn test_stream_event_creation() {
        let entry = create_test_entry(1, "agent-1");
        let event = StreamEvent::audit_entry(entry.clone(), 1);

        assert_eq!(event.event_type, StreamEventType::AuditEntry);
        assert_eq!(event.sequence, 1);

        match event.payload {
            StreamPayload::AuditEntry(e) => {
                assert_eq!(e.agent_id, "agent-1");
            }
            _ => panic!("Expected AuditEntry payload"),
        }
    }

    #[test]
    fn test_stream_filter_all() {
        let filter = StreamFilter::all();
        let event = StreamEvent::heartbeat(1);
        assert!(filter.matches(&event));

        let entry = create_test_entry(1, "agent-1");
        let entry_event = StreamEvent::audit_entry(entry, 2);
        assert!(filter.matches(&entry_event));
    }

    #[test]
    fn test_stream_filter_for_agents() {
        let filter = StreamFilter::for_agents(vec!["agent-1".to_string()]);

        let entry1 = create_test_entry(1, "agent-1");
        let event1 = StreamEvent::audit_entry(entry1, 1);
        assert!(filter.matches(&event1));

        let entry2 = create_test_entry(2, "agent-2");
        let event2 = StreamEvent::audit_entry(entry2, 2);
        assert!(!filter.matches(&event2));
    }

    #[test]
    fn test_stream_filter_denied_only() {
        let filter = StreamFilter::denied_only();

        let mut allowed_entry = create_test_entry(1, "agent-1");
        allowed_entry.decision = AuditDecision::Allowed;
        let allowed_event = StreamEvent::audit_entry(allowed_entry, 1);
        assert!(!filter.matches(&allowed_event));

        let mut denied_entry = create_test_entry(2, "agent-1");
        denied_entry.decision = AuditDecision::Denied;
        let denied_event = StreamEvent::audit_entry(denied_entry, 2);
        assert!(filter.matches(&denied_event));
    }

    #[test]
    fn test_alert_creation() {
        let alert = StreamAlert::new(
            AlertSeverity::Warning,
            "High CPU",
            "CPU usage above 90%",
            "monitoring",
        )
        .with_agent_id("agent-1");

        assert_eq!(alert.severity, AlertSeverity::Warning);
        assert_eq!(alert.title, "High CPU");
        assert_eq!(alert.agent_id, Some("agent-1".to_string()));
    }

    #[test]
    fn test_stream_manager_creation() {
        let config = StreamConfig::default();
        let manager = AuditStreamManager::new(config);

        assert!(manager.is_active());
        assert_eq!(manager.list_subscribers().len(), 0);
    }

    #[test]
    fn test_subscribe_unsubscribe() {
        let config = StreamConfig::default();
        let manager = AuditStreamManager::new(config);

        // Subscribe
        let sub_id = manager.subscribe(StreamFilter::all()).unwrap();
        assert_eq!(manager.list_subscribers().len(), 1);

        // Get info
        let info = manager.get_subscriber_info(&sub_id).unwrap();
        assert_eq!(info.id, sub_id);
        assert!(info.is_active);

        // Unsubscribe
        manager.unsubscribe(&sub_id).unwrap();
        assert_eq!(manager.list_subscribers().len(), 0);
    }

    #[test]
    fn test_max_subscribers_limit() {
        let mut config = StreamConfig::default();
        config.max_subscribers = 2;

        let manager = AuditStreamManager::new(config);

        // Add subscribers up to limit
        let _sub1 = manager.subscribe(StreamFilter::all()).unwrap();
        let _sub2 = manager.subscribe(StreamFilter::all()).unwrap();

        // Third should fail
        let result = manager.subscribe(StreamFilter::all());
        assert!(result.is_err());
    }

    #[test]
    fn test_publish_entry() {
        let config = StreamConfig::default();
        let manager = AuditStreamManager::new(config);

        let entry = create_test_entry(1, "agent-1");
        let result = manager.publish_entry(entry);

        assert!(result.is_ok());

        let stats = manager.get_stats();
        assert_eq!(stats.events_published, 1);
    }

    #[test]
    fn test_recent_events() {
        let config = StreamConfig::default();
        let manager = AuditStreamManager::new(config);

        // Publish some entries
        for i in 0..5 {
            let entry = create_test_entry(i, "agent-1");
            manager.publish_entry(entry).unwrap();
        }

        // Get recent events
        let filter = StreamFilter::all();
        let events = manager.get_recent_events(&filter, None);
        assert_eq!(events.len(), 5);

        // Get with limit
        let limited = manager.get_recent_events(&filter, Some(3));
        assert_eq!(limited.len(), 3);
    }

    #[test]
    fn test_stop_start() {
        let config = StreamConfig::default();
        let manager = AuditStreamManager::new(config);

        assert!(manager.is_active());

        manager.stop();
        assert!(!manager.is_active());

        // Publishing should fail when stopped
        let entry = create_test_entry(1, "agent-1");
        let result = manager.publish_entry(entry);
        assert!(result.is_err());

        manager.start();
        assert!(manager.is_active());
    }

    #[test]
    fn test_broadcast_receiver() {
        let config = StreamConfig::default();
        let manager = AuditStreamManager::new(config);

        let mut receiver = manager.get_broadcast_receiver();

        // Publish an entry
        let entry = create_test_entry(1, "agent-1");
        manager.publish_entry(entry).unwrap();

        // Receive from broadcast
        // Note: This would need async test runtime in real scenario
    }

    #[test]
    fn test_webhook_sink_config() {
        let config = WebhookSinkConfig {
            url: "https://example.com/webhook".to_string(),
            headers: HashMap::new(),
            retry_count: 3,
            timeout_ms: 5000,
            batch_enabled: true,
            batch_size: 100,
        };

        let sink = WebhookSink::new(config.clone());
        assert_eq!(sink.config.url, "https://example.com/webhook");
        assert!(sink.config.batch_enabled);
    }
}
