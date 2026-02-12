//! Agent-to-Agent (A2A) Protocol Support (SWM-001)
//!
//! Implements standard A2A protocol for inter-agent communication,
//! including AgentCard discovery, message routing, and capability exchange.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in A2A protocol operations
#[derive(Debug, Error)]
pub enum A2AError {
    /// The specified agent was not found in the registry
    #[error("Agent not found: {0}")]
    AgentNotFound(String),
    /// Message delivery to the target agent failed
    #[error("Message delivery failed: {0}")]
    DeliveryFailed(String),
    /// A protocol-level error occurred during communication
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    /// The requested capability is not supported by the agent
    #[error("Capability not supported: {0}")]
    CapabilityNotSupported(String),
    /// The operation exceeded the configured timeout duration
    #[error("Operation timed out")]
    Timeout,
}

/// Result type alias for A2A protocol operations
pub type A2AResult<T> = Result<T, A2AError>;

// ============================================================================
// Agent Card
// ============================================================================

/// Describes an agent's identity, capabilities, and connectivity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Unique identifier for the agent
    pub id: String,
    /// Human-readable name of the agent
    pub name: String,
    /// Description of the agent's purpose
    pub description: String,
    /// Protocol version the agent supports
    pub version: String,
    /// List of capabilities this agent offers
    pub capabilities: Vec<A2ACapability>,
    /// Network endpoint for reaching this agent
    pub endpoint: Option<String>,
    /// Public key for message signature verification
    pub public_key: Option<String>,
    /// Additional agent-specific metadata
    pub metadata: HashMap<String, serde_json::Value>,
    /// Timestamp when the agent card was created
    pub created_at: SystemTime,
    /// Timestamp when the agent card was last updated
    pub updated_at: SystemTime,
}

impl AgentCard {
    /// Create a new agent card with the given ID and name
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            version: "1.0.0".to_string(),
            capabilities: Vec::new(),
            endpoint: None,
            public_key: None,
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Set the agent's description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Add a capability to this agent card
    pub fn with_capability(mut self, capability: A2ACapability) -> Self {
        self.capabilities.push(capability);
        self
    }

    /// Set the agent's network endpoint
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Check if this agent has a specific capability type
    pub fn has_capability(&self, capability_type: &str) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.capability_type == capability_type)
    }
}

// ============================================================================
// Capability
// ============================================================================

/// Represents a capability that an agent can advertise and provide
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2ACapability {
    /// Type identifier for this capability
    pub capability_type: String,
    /// Version of this capability implementation
    pub version: String,
    /// Human-readable description of the capability
    pub description: String,
    /// JSON schema for expected input
    pub input_schema: Option<serde_json::Value>,
    /// JSON schema for expected output
    pub output_schema: Option<serde_json::Value>,
    /// Whether this capability is currently enabled
    pub enabled: bool,
}

impl A2ACapability {
    /// Create a new capability with the given type identifier
    pub fn new(capability_type: impl Into<String>) -> Self {
        Self {
            capability_type: capability_type.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            input_schema: None,
            output_schema: None,
            enabled: true,
        }
    }

    /// Set the capability's description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

// ============================================================================
// Message Types
// ============================================================================

/// Types of messages exchanged between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum A2AMessageType {
    /// A query requesting information from another agent
    Query,
    /// A response to a previously received query
    Response,
    /// A proposal for consensus or collaborative decision
    Proposal,
    /// A vote on a proposal
    Vote,
    /// A consensus result from a group decision
    Consensus,
    /// A heartbeat signal indicating liveness
    Heartbeat,
    /// An error notification
    Error,
    /// A custom message type with a user-defined name
    Custom(String),
}

/// A message sent between agents following the A2A protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AMessage {
    /// Unique message identifier
    pub id: String,
    /// The type of this message
    pub message_type: A2AMessageType,
    /// Sender agent ID
    pub from: String,
    /// Recipient agent ID
    pub to: String,
    /// Message payload as a JSON value
    pub payload: serde_json::Value,
    /// Correlation ID linking this message to a prior message
    pub correlation_id: Option<String>,
    /// Timestamp when the message was created
    pub timestamp: SystemTime,
    /// Optional cryptographic signature of the message
    pub signature: Option<String>,
    /// Protocol version used for this message
    pub protocol_version: String,
}

impl A2AMessage {
    /// Create a new A2A message with the given type, sender, recipient, and payload
    pub fn new(
        message_type: A2AMessageType,
        from: impl Into<String>,
        to: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            message_type,
            from: from.into(),
            to: to.into(),
            payload,
            correlation_id: None,
            timestamp: SystemTime::now(),
            signature: None,
            protocol_version: "1.0".to_string(),
        }
    }

    /// Create a query message to send to another agent
    pub fn query(from: impl Into<String>, to: impl Into<String>, query: serde_json::Value) -> Self {
        Self::new(A2AMessageType::Query, from, to, query)
    }

    /// Create a response message correlated to a prior query
    pub fn response(
        from: impl Into<String>,
        to: impl Into<String>,
        response: serde_json::Value,
        correlation_id: impl Into<String>,
    ) -> Self {
        let mut msg = Self::new(A2AMessageType::Response, from, to, response);
        msg.correlation_id = Some(correlation_id.into());
        msg
    }

    /// Create a heartbeat message to signal liveness
    pub fn heartbeat(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::new(A2AMessageType::Heartbeat, from, to, serde_json::json!({}))
    }
}

// ============================================================================
// Discovery Service
// ============================================================================

/// Service for discovering and tracking registered agents
pub struct DiscoveryService {
    agents: RwLock<HashMap<String, AgentCard>>,
    last_seen: RwLock<HashMap<String, SystemTime>>,
    heartbeat_timeout: Duration,
}

impl DiscoveryService {
    /// Create a new discovery service with default settings
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            last_seen: RwLock::new(HashMap::new()),
            heartbeat_timeout: Duration::from_secs(60),
        }
    }

    /// Register an agent with the discovery service
    pub async fn register(&self, card: AgentCard) -> A2AResult<()> {
        let id = card.id.clone();
        let mut agents = self.agents.write().await;
        let mut last_seen = self.last_seen.write().await;
        agents.insert(id.clone(), card);
        last_seen.insert(id.clone(), SystemTime::now());
        info!(agent_id = %id, "Agent registered");
        Ok(())
    }

    /// Unregister an agent from the discovery service
    pub async fn unregister(&self, agent_id: &str) -> A2AResult<()> {
        let mut agents = self.agents.write().await;
        let mut last_seen = self.last_seen.write().await;
        agents.remove(agent_id);
        last_seen.remove(agent_id);
        info!(agent_id = %agent_id, "Agent unregistered");
        Ok(())
    }

    /// Retrieve an agent card by agent ID
    pub async fn get_agent(&self, agent_id: &str) -> Option<AgentCard> {
        let agents = self.agents.read().await;
        agents.get(agent_id).cloned()
    }

    /// List all registered agent cards
    pub async fn list_agents(&self) -> Vec<AgentCard> {
        let agents = self.agents.read().await;
        agents.values().cloned().collect()
    }

    /// Find all agents that advertise a specific capability type
    pub async fn find_by_capability(&self, capability_type: &str) -> Vec<AgentCard> {
        let agents = self.agents.read().await;
        agents
            .values()
            .filter(|a| a.has_capability(capability_type))
            .cloned()
            .collect()
    }

    /// Record a heartbeat for the given agent, updating its last-seen time
    pub async fn heartbeat(&self, agent_id: &str) -> A2AResult<()> {
        let mut last_seen = self.last_seen.write().await;
        if last_seen.contains_key(agent_id) {
            last_seen.insert(agent_id.to_string(), SystemTime::now());
            Ok(())
        } else {
            Err(A2AError::AgentNotFound(agent_id.to_string()))
        }
    }

    /// Check whether an agent is considered alive based on heartbeat timeout
    pub async fn is_alive(&self, agent_id: &str) -> bool {
        let last_seen = self.last_seen.read().await;
        if let Some(time) = last_seen.get(agent_id) {
            time.elapsed()
                .map(|d| d < self.heartbeat_timeout)
                .unwrap_or(false)
        } else {
            false
        }
    }

    /// Remove agents that have not sent a heartbeat within the timeout period
    pub async fn prune_dead_agents(&self) -> Vec<String> {
        let mut agents = self.agents.write().await;
        let mut last_seen = self.last_seen.write().await;
        let mut pruned = Vec::new();

        let dead: Vec<_> = last_seen
            .iter()
            .filter(|(_, time)| {
                time.elapsed()
                    .map(|d| d >= self.heartbeat_timeout)
                    .unwrap_or(true)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in dead {
            agents.remove(&id);
            last_seen.remove(&id);
            pruned.push(id);
        }

        if !pruned.is_empty() {
            warn!(count = pruned.len(), "Pruned dead agents");
        }
        pruned
    }
}

impl Default for DiscoveryService {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// A2A Protocol
// ============================================================================

/// Core A2A protocol handler for sending and receiving inter-agent messages
pub struct A2AProtocol {
    discovery: Arc<DiscoveryService>,
    message_handlers: RwLock<HashMap<String, Vec<Box<dyn Fn(&A2AMessage) + Send + Sync>>>>,
    pending_responses: RwLock<HashMap<String, tokio::sync::oneshot::Sender<A2AMessage>>>,
}

impl A2AProtocol {
    /// Create a new A2A protocol instance with a fresh discovery service
    pub fn new() -> Self {
        Self {
            discovery: Arc::new(DiscoveryService::new()),
            message_handlers: RwLock::new(HashMap::new()),
            pending_responses: RwLock::new(HashMap::new()),
        }
    }

    /// Get a reference to the underlying discovery service
    pub fn discovery(&self) -> &Arc<DiscoveryService> {
        &self.discovery
    }

    /// Send a message to the target agent
    pub async fn send(&self, message: A2AMessage) -> A2AResult<()> {
        let agents = self.discovery.agents.read().await;
        if !agents.contains_key(&message.to) {
            return Err(A2AError::AgentNotFound(message.to.clone()));
        }

        let handlers = self.message_handlers.read().await;
        if let Some(agent_handlers) = handlers.get(&message.to) {
            for handler in agent_handlers {
                handler(&message);
            }
        }

        debug!(from = %message.from, to = %message.to, "Message sent");
        Ok(())
    }

    /// Send a message and wait for a correlated response within the given timeout
    pub async fn send_and_wait(
        &self,
        message: A2AMessage,
        timeout: Duration,
    ) -> A2AResult<A2AMessage> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let msg_id = message.id.clone();

        {
            let mut pending = self.pending_responses.write().await;
            pending.insert(msg_id.clone(), tx);
        }

        self.send(message).await?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(A2AError::DeliveryFailed("Channel closed".to_string())),
            Err(_) => {
                let mut pending = self.pending_responses.write().await;
                pending.remove(&msg_id);
                Err(A2AError::Timeout)
            }
        }
    }

    /// Handle an incoming response message by resolving pending request futures
    pub async fn handle_response(&self, response: A2AMessage) {
        if let Some(correlation_id) = &response.correlation_id {
            let mut pending = self.pending_responses.write().await;
            if let Some(tx) = pending.remove(correlation_id) {
                let _ = tx.send(response);
            }
        }
    }
}

impl Default for A2AProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// AgentCard Discovery Service (SWM-002)
// ============================================================================

/// Configuration for agent card discovery (SWM-002)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Cache TTL for discovered agent cards (seconds)
    pub cache_ttl_secs: u64,
    /// HTTP timeout for fetching remote agent cards (seconds)
    pub http_timeout_secs: u64,
    /// Well-known path for agent card discovery
    pub well_known_path: String,
    /// Maximum number of cached entries
    pub max_cache_size: usize,
    /// Enable mDNS/broadcast discovery
    pub enable_broadcast: bool,
    /// Broadcast discovery port
    pub broadcast_port: u16,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            cache_ttl_secs: 300,
            http_timeout_secs: 10,
            well_known_path: "/.well-known/agent.json".to_string(),
            max_cache_size: 1000,
            enable_broadcast: false,
            broadcast_port: 9420,
        }
    }
}

/// Validation result for an agent card (SWM-002)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCardValidation {
    /// Whether the card is valid
    pub valid: bool,
    /// Validation errors
    pub errors: Vec<String>,
    /// Validation warnings
    pub warnings: Vec<String>,
}

/// Cached agent card entry with TTL (SWM-002)
#[derive(Debug, Clone)]
struct CachedAgentCard {
    /// The agent card
    card: AgentCard,
    /// When the entry was cached
    cached_at: SystemTime,
    /// Source URL (if fetched remotely)
    #[allow(dead_code)]
    source_url: Option<String>,
}

/// Enhanced discovery service with HTTP fetch, caching, and validation (SWM-002)
pub struct AgentCardDiscovery {
    /// Configuration
    config: DiscoveryConfig,
    /// Local discovery service (base registry)
    local: DiscoveryService,
    /// Remote agent card cache
    cache: RwLock<HashMap<String, CachedAgentCard>>,
    /// Known endpoint URLs for discovery
    known_endpoints: RwLock<Vec<String>>,
}

impl AgentCardDiscovery {
    /// Create a new agent card discovery service
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            local: DiscoveryService::new(),
            cache: RwLock::new(HashMap::new()),
            known_endpoints: RwLock::new(Vec::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(DiscoveryConfig::default())
    }

    /// Get the underlying local discovery service
    pub fn local(&self) -> &DiscoveryService {
        &self.local
    }

    /// Register a local agent card
    pub async fn register_local(&self, card: AgentCard) -> A2AResult<()> {
        self.local.register(card).await
    }

    /// Add a known endpoint URL for discovery
    pub async fn add_endpoint(&self, url: impl Into<String>) {
        let mut endpoints = self.known_endpoints.write().await;
        let url = url.into();
        if !endpoints.contains(&url) {
            endpoints.push(url);
        }
    }

    /// Validate an agent card against the schema (SWM-002)
    pub fn validate_card(card: &AgentCard) -> AgentCardValidation {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Required fields
        if card.id.is_empty() {
            errors.push("Agent ID is required".to_string());
        }
        if card.name.is_empty() {
            errors.push("Agent name is required".to_string());
        }
        if card.version.is_empty() {
            errors.push("Version is required".to_string());
        }

        // Version format validation (semver-like)
        if !card.version.is_empty() {
            let parts: Vec<&str> = card.version.split('.').collect();
            if parts.len() < 2 || parts.len() > 3 {
                warnings.push(format!(
                    "Version '{}' does not follow semver format",
                    card.version
                ));
            }
        }

        // Capabilities validation
        if card.capabilities.is_empty() {
            warnings.push("Agent has no capabilities declared".to_string());
        }

        for cap in &card.capabilities {
            if cap.capability_type.is_empty() {
                errors.push("Capability type cannot be empty".to_string());
            }
        }

        // Endpoint validation
        if let Some(ref endpoint) = card.endpoint {
            if endpoint.is_empty() {
                warnings.push("Endpoint is set but empty".to_string());
            } else if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
                warnings.push(format!(
                    "Endpoint '{}' does not use HTTP/HTTPS scheme",
                    endpoint
                ));
            }
        }

        // Description warning
        if card.description.is_empty() {
            warnings.push("Agent description is empty".to_string());
        }

        AgentCardValidation {
            valid: errors.is_empty(),
            errors,
            warnings,
        }
    }

    /// Fetch an agent card from a well-known URL (SWM-002)
    pub async fn fetch_from_url(&self, base_url: &str) -> A2AResult<AgentCard> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(cached) = cache.get(base_url) {
                let elapsed = cached
                    .cached_at
                    .elapsed()
                    .unwrap_or(Duration::from_secs(u64::MAX));
                if elapsed < Duration::from_secs(self.config.cache_ttl_secs) {
                    debug!(url = %base_url, "Returning cached agent card");
                    return Ok(cached.card.clone());
                }
            }
        }

        // Build the well-known URL
        let url = format!(
            "{}{}",
            base_url.trim_end_matches('/'),
            self.config.well_known_path
        );

        info!(url = %url, "Fetching agent card from well-known endpoint");

        // Fetch via HTTP
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(self.config.http_timeout_secs))
            .build()
            .map_err(|e| A2AError::ProtocolError(format!("HTTP client error: {}", e)))?;

        let response = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| A2AError::DeliveryFailed(format!("HTTP fetch failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(A2AError::DeliveryFailed(format!(
                "HTTP {} from {}",
                response.status(),
                url
            )));
        }

        let card: AgentCard = response
            .json()
            .await
            .map_err(|e| A2AError::ProtocolError(format!("JSON parse error: {}", e)))?;

        // Validate received card
        let validation = Self::validate_card(&card);
        if !validation.valid {
            return Err(A2AError::ProtocolError(format!(
                "Invalid agent card: {}",
                validation.errors.join(", ")
            )));
        }

        // Cache the result
        {
            let mut cache = self.cache.write().await;

            // Evict old entries if cache is full
            if cache.len() >= self.config.max_cache_size {
                let oldest_key = cache
                    .iter()
                    .min_by_key(|(_, v)| v.cached_at)
                    .map(|(k, _)| k.clone());
                if let Some(key) = oldest_key {
                    cache.remove(&key);
                }
            }

            cache.insert(
                base_url.to_string(),
                CachedAgentCard {
                    card: card.clone(),
                    cached_at: SystemTime::now(),
                    source_url: Some(url),
                },
            );
        }

        Ok(card)
    }

    /// Discover agents from all known endpoints (SWM-002)
    pub async fn discover_all(&self) -> Vec<(String, Result<AgentCard, A2AError>)> {
        let endpoints = self.known_endpoints.read().await.clone();
        let mut results = Vec::new();

        for endpoint in endpoints {
            let result = self.fetch_from_url(&endpoint).await;
            results.push((endpoint, result));
        }

        results
    }

    /// Look up an agent by ID from local registry and cache (SWM-002)
    pub async fn lookup(&self, agent_id: &str) -> Option<AgentCard> {
        // Check local first
        if let Some(card) = self.local.get_agent(agent_id).await {
            return Some(card);
        }

        // Check cache
        let cache = self.cache.read().await;
        for entry in cache.values() {
            if entry.card.id == agent_id {
                let elapsed = entry
                    .cached_at
                    .elapsed()
                    .unwrap_or(Duration::from_secs(u64::MAX));
                if elapsed < Duration::from_secs(self.config.cache_ttl_secs) {
                    return Some(entry.card.clone());
                }
            }
        }

        None
    }

    /// Search for agents by capability across local and cached (SWM-002)
    pub async fn search_by_capability(&self, capability_type: &str) -> Vec<AgentCard> {
        let mut results = self.local.find_by_capability(capability_type).await;

        // Also search cache
        let cache = self.cache.read().await;
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        for entry in cache.values() {
            let elapsed = entry.cached_at.elapsed().unwrap_or(Duration::from_secs(u64::MAX));
            if elapsed < ttl && entry.card.has_capability(capability_type) {
                // Avoid duplicates
                if !results.iter().any(|r| r.id == entry.card.id) {
                    results.push(entry.card.clone());
                }
            }
        }

        results
    }

    /// Search for agents by name (partial match) (SWM-002)
    pub async fn search_by_name(&self, query: &str) -> Vec<AgentCard> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        // Search local
        let local_agents = self.local.list_agents().await;
        for agent in local_agents {
            if agent.name.to_lowercase().contains(&query_lower) {
                results.push(agent);
            }
        }

        // Search cache
        let cache = self.cache.read().await;
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        for entry in cache.values() {
            let elapsed = entry.cached_at.elapsed().unwrap_or(Duration::from_secs(u64::MAX));
            if elapsed < ttl && entry.card.name.to_lowercase().contains(&query_lower) {
                if !results.iter().any(|r| r.id == entry.card.id) {
                    results.push(entry.card.clone());
                }
            }
        }

        results
    }

    /// Get all agents (local + valid cache entries) (SWM-002)
    pub async fn list_all_agents(&self) -> Vec<AgentCard> {
        let mut results = self.local.list_agents().await;

        let cache = self.cache.read().await;
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        for entry in cache.values() {
            let elapsed = entry.cached_at.elapsed().unwrap_or(Duration::from_secs(u64::MAX));
            if elapsed < ttl {
                if !results.iter().any(|r| r.id == entry.card.id) {
                    results.push(entry.card.clone());
                }
            }
        }

        results
    }

    /// Clear expired cache entries (SWM-002)
    pub async fn clear_expired_cache(&self) -> usize {
        let mut cache = self.cache.write().await;
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        let before = cache.len();

        cache.retain(|_, entry| {
            entry
                .cached_at
                .elapsed()
                .map(|d| d < ttl)
                .unwrap_or(false)
        });

        let removed = before - cache.len();
        if removed > 0 {
            info!(count = removed, "Cleared expired agent card cache entries");
        }
        removed
    }

    /// Get the well-known agent card JSON for serving (SWM-002)
    ///
    /// This generates the JSON that should be served at `/.well-known/agent.json`
    pub fn generate_well_known_json(card: &AgentCard) -> serde_json::Value {
        serde_json::json!({
            "id": card.id,
            "name": card.name,
            "description": card.description,
            "version": card.version,
            "capabilities": card.capabilities.iter().map(|c| {
                serde_json::json!({
                    "type": c.capability_type,
                    "version": c.version,
                    "description": c.description,
                    "enabled": c.enabled,
                })
            }).collect::<Vec<_>>(),
            "endpoint": card.endpoint,
            "publicKey": card.public_key,
            "metadata": card.metadata,
        })
    }

    /// Get cache statistics (SWM-002)
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);
        let total = cache.len();
        let valid = cache
            .values()
            .filter(|e| {
                e.cached_at
                    .elapsed()
                    .map(|d| d < ttl)
                    .unwrap_or(false)
            })
            .count();
        (total, valid)
    }
}

impl Default for AgentCardDiscovery {
    fn default() -> Self {
        Self::with_defaults()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_card_creation() {
        let card = AgentCard::new("agent-1", "Test Agent")
            .with_description("A test agent")
            .with_capability(A2ACapability::new("reasoning"));

        assert_eq!(card.id, "agent-1");
        assert!(card.has_capability("reasoning"));
        assert!(!card.has_capability("coding"));
    }

    #[test]
    fn test_message_creation() {
        let msg = A2AMessage::query("agent-1", "agent-2", serde_json::json!({"query": "test"}));
        assert!(matches!(msg.message_type, A2AMessageType::Query));
        assert_eq!(msg.from, "agent-1");
        assert_eq!(msg.to, "agent-2");
    }

    #[tokio::test]
    async fn test_discovery_service() {
        let service = DiscoveryService::new();
        let card = AgentCard::new("agent-1", "Test Agent");

        service.register(card).await.unwrap();

        assert!(service.get_agent("agent-1").await.is_some());
        assert!(service.get_agent("nonexistent").await.is_none());

        service.unregister("agent-1").await.unwrap();
        assert!(service.get_agent("agent-1").await.is_none());
    }

    #[tokio::test]
    async fn test_find_by_capability() {
        let service = DiscoveryService::new();

        let card1 =
            AgentCard::new("agent-1", "Agent 1").with_capability(A2ACapability::new("reasoning"));
        let card2 =
            AgentCard::new("agent-2", "Agent 2").with_capability(A2ACapability::new("coding"));

        service.register(card1).await.unwrap();
        service.register(card2).await.unwrap();

        let reasoning_agents = service.find_by_capability("reasoning").await;
        assert_eq!(reasoning_agents.len(), 1);
        assert_eq!(reasoning_agents[0].id, "agent-1");
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let service = DiscoveryService::new();
        let card = AgentCard::new("agent-1", "Test Agent");

        service.register(card).await.unwrap();
        assert!(service.is_alive("agent-1").await);

        service.heartbeat("agent-1").await.unwrap();
        assert!(service.is_alive("agent-1").await);
    }

    #[tokio::test]
    async fn test_protocol_send() {
        let protocol = A2AProtocol::new();

        let card = AgentCard::new("agent-1", "Test Agent");
        protocol.discovery().register(card).await.unwrap();

        let msg = A2AMessage::heartbeat("agent-2", "agent-1");
        let result = protocol.send(msg).await;
        assert!(result.is_ok());
    }

    // SWM-002 Tests

    #[test]
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.cache_ttl_secs, 300);
        assert_eq!(config.well_known_path, "/.well-known/agent.json");
        assert_eq!(config.max_cache_size, 1000);
    }

    #[test]
    fn test_validate_valid_card() {
        let card = AgentCard::new("agent-1", "Test Agent")
            .with_description("A test agent")
            .with_capability(A2ACapability::new("reasoning"));

        let result = AgentCardDiscovery::validate_card(&card);
        assert!(result.valid);
        assert!(result.errors.is_empty());
    }

    #[test]
    fn test_validate_invalid_card_empty_id() {
        let card = AgentCard::new("", "Test Agent");

        let result = AgentCardDiscovery::validate_card(&card);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("Agent ID")));
    }

    #[test]
    fn test_validate_invalid_card_empty_name() {
        let card = AgentCard::new("agent-1", "");

        let result = AgentCardDiscovery::validate_card(&card);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("name")));
    }

    #[test]
    fn test_validate_card_warnings() {
        let card = AgentCard::new("agent-1", "Test Agent");

        let result = AgentCardDiscovery::validate_card(&card);
        assert!(result.valid);
        assert!(!result.warnings.is_empty());
        // Should warn about empty description and no capabilities
        assert!(result.warnings.iter().any(|w| w.contains("description")));
        assert!(result.warnings.iter().any(|w| w.contains("capabilities")));
    }

    #[test]
    fn test_validate_card_endpoint_warning() {
        let card = AgentCard::new("agent-1", "Test Agent")
            .with_endpoint("tcp://localhost:8080");

        let result = AgentCardDiscovery::validate_card(&card);
        assert!(result.valid);
        assert!(result.warnings.iter().any(|w| w.contains("HTTP/HTTPS")));
    }

    #[tokio::test]
    async fn test_agent_card_discovery_local() {
        let discovery = AgentCardDiscovery::with_defaults();

        let card = AgentCard::new("agent-1", "Test Agent")
            .with_capability(A2ACapability::new("reasoning"));
        discovery.register_local(card).await.unwrap();

        let found = discovery.lookup("agent-1").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Test Agent");
    }

    #[tokio::test]
    async fn test_agent_card_discovery_search_by_capability() {
        let discovery = AgentCardDiscovery::with_defaults();

        let card1 = AgentCard::new("agent-1", "Reasoner")
            .with_capability(A2ACapability::new("reasoning"));
        let card2 = AgentCard::new("agent-2", "Coder")
            .with_capability(A2ACapability::new("coding"));

        discovery.register_local(card1).await.unwrap();
        discovery.register_local(card2).await.unwrap();

        let reasoners = discovery.search_by_capability("reasoning").await;
        assert_eq!(reasoners.len(), 1);
        assert_eq!(reasoners[0].id, "agent-1");

        let all = discovery.list_all_agents().await;
        assert_eq!(all.len(), 2);
    }

    #[tokio::test]
    async fn test_agent_card_discovery_search_by_name() {
        let discovery = AgentCardDiscovery::with_defaults();

        let card = AgentCard::new("agent-1", "Smart Reasoner");
        discovery.register_local(card).await.unwrap();

        let results = discovery.search_by_name("smart").await;
        assert_eq!(results.len(), 1);

        let results = discovery.search_by_name("nonexistent").await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_add_endpoint() {
        let discovery = AgentCardDiscovery::with_defaults();

        discovery.add_endpoint("https://agent1.example.com").await;
        discovery.add_endpoint("https://agent2.example.com").await;
        discovery.add_endpoint("https://agent1.example.com").await; // duplicate

        let endpoints = discovery.known_endpoints.read().await;
        assert_eq!(endpoints.len(), 2);
    }

    #[test]
    fn test_generate_well_known_json() {
        let card = AgentCard::new("agent-1", "Test Agent")
            .with_description("A test agent")
            .with_capability(A2ACapability::new("reasoning").with_description("Can reason"))
            .with_endpoint("https://example.com");

        let json = AgentCardDiscovery::generate_well_known_json(&card);

        assert_eq!(json["id"], "agent-1");
        assert_eq!(json["name"], "Test Agent");
        assert_eq!(json["description"], "A test agent");
        assert_eq!(json["endpoint"], "https://example.com");

        let caps = json["capabilities"].as_array().unwrap();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0]["type"], "reasoning");
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let discovery = AgentCardDiscovery::with_defaults();

        let (total, valid) = discovery.cache_stats().await;
        assert_eq!(total, 0);
        assert_eq!(valid, 0);
    }

    #[tokio::test]
    async fn test_clear_expired_cache() {
        let discovery = AgentCardDiscovery::with_defaults();

        let removed = discovery.clear_expired_cache().await;
        assert_eq!(removed, 0);
    }
}
