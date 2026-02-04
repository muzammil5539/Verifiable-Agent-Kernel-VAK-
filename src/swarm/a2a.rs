//! Agent-to-Agent (A2A) Protocol Support (SWM-001, SWM-002)
//!
//! Implements the Agent-to-Agent protocol for agent discovery and capability
//! exchange. Allows VAK agents to find and collaborate with other agents
//! on the network.
//!
//! # Overview
//!
//! The A2A protocol enables:
//! - Agent discovery via AgentCard
//! - Capability negotiation between agents
//! - Structured interface definitions
//! - Protocol version compatibility checks
//!
//! # Example
//!
//! ```rust
//! use vak::swarm::a2a::{AgentCard, Capability, A2AProtocol, A2AConfig};
//!
//! // Create an agent card
//! let card = AgentCard::builder()
//!     .id("agent-001")
//!     .name("Code Auditor")
//!     .version("1.0.0")
//!     .capability(Capability::new("code_review", "Reviews code for security issues"))
//!     .capability(Capability::new("vulnerability_scan", "Scans for CVEs"))
//!     .build();
//!
//! // Create protocol handler
//! let protocol = A2AProtocol::new(A2AConfig::default());
//! protocol.register_agent(card);
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 3.3: A2A Handshake
//! - Gap Analysis Phase 5.2: A2A Protocol Support
//! - a2a-types crate: https://docs.rs/a2a-types

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in A2A operations
#[derive(Debug, Error)]
pub enum A2AError {
    /// Agent not found
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// Agent already registered
    #[error("Agent already registered: {0}")]
    AgentAlreadyRegistered(String),

    /// Capability not found
    #[error("Capability not found: {0}")]
    CapabilityNotFound(String),

    /// Protocol version mismatch
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: String, actual: String },

    /// Invalid agent card
    #[error("Invalid agent card: {0}")]
    InvalidAgentCard(String),

    /// Handshake failed
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Communication error
    #[error("Communication error: {0}")]
    CommunicationError(String),

    /// Timeout
    #[error("Operation timed out after {0}ms")]
    Timeout(u64),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Result type for A2A operations
pub type A2AResult<T> = Result<T, A2AError>;

// ============================================================================
// Capability Types
// ============================================================================

/// A capability that an agent can provide
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capability {
    /// Unique identifier for this capability
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what this capability does
    pub description: String,
    /// Version of this capability
    pub version: String,
    /// Input schema (JSON Schema format)
    pub input_schema: Option<serde_json::Value>,
    /// Output schema (JSON Schema format)
    pub output_schema: Option<serde_json::Value>,
    /// Whether this capability requires authentication
    pub requires_auth: bool,
    /// Rate limit (requests per minute)
    pub rate_limit: Option<u32>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl Capability {
    /// Create a new capability with basic info
    pub fn new(id: impl Into<String>, description: impl Into<String>) -> Self {
        let id_str = id.into();
        Self {
            id: id_str.clone(),
            name: id_str,
            description: description.into(),
            version: "1.0.0".to_string(),
            input_schema: None,
            output_schema: None,
            requires_auth: false,
            rate_limit: None,
            tags: Vec::new(),
        }
    }

    /// Set the name
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Set the input schema
    pub fn with_input_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema = Some(schema);
        self
    }

    /// Set the output schema
    pub fn with_output_schema(mut self, schema: serde_json::Value) -> Self {
        self.output_schema = Some(schema);
        self
    }

    /// Require authentication
    pub fn with_auth(mut self) -> Self {
        self.requires_auth = true;
        self
    }

    /// Set rate limit
    pub fn with_rate_limit(mut self, rpm: u32) -> Self {
        self.rate_limit = Some(rpm);
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }
}

// ============================================================================
// Agent Card
// ============================================================================

/// An AgentCard represents an agent's identity and capabilities
/// for discovery and negotiation purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Unique agent identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Agent description
    pub description: String,
    /// Agent version
    pub version: String,
    /// Protocol version supported
    pub protocol_version: String,
    /// List of capabilities this agent provides
    pub capabilities: Vec<Capability>,
    /// Endpoint URL for communication
    pub endpoint: Option<String>,
    /// Authentication methods supported
    pub auth_methods: Vec<String>,
    /// Metadata for extensibility
    pub metadata: HashMap<String, serde_json::Value>,
    /// When this card was created
    pub created_at: u64,
    /// When this card was last updated
    pub updated_at: u64,
    /// Time-to-live for caching (seconds)
    pub ttl: u64,
    /// Digital signature for verification
    pub signature: Option<String>,
}

impl AgentCard {
    /// Current protocol version
    pub const PROTOCOL_VERSION: &'static str = "1.0.0";

    /// Create a new AgentCard builder
    pub fn builder() -> AgentCardBuilder {
        AgentCardBuilder::new()
    }

    /// Get a capability by ID
    pub fn get_capability(&self, id: &str) -> Option<&Capability> {
        self.capabilities.iter().find(|c| c.id == id)
    }

    /// Check if this agent has a specific capability
    pub fn has_capability(&self, id: &str) -> bool {
        self.capabilities.iter().any(|c| c.id == id)
    }

    /// Get all capability IDs
    pub fn capability_ids(&self) -> Vec<&str> {
        self.capabilities.iter().map(|c| c.id.as_str()).collect()
    }

    /// Validate the agent card
    pub fn validate(&self) -> A2AResult<()> {
        if self.id.is_empty() {
            return Err(A2AError::InvalidAgentCard("ID cannot be empty".to_string()));
        }
        if self.name.is_empty() {
            return Err(A2AError::InvalidAgentCard("Name cannot be empty".to_string()));
        }
        if self.version.is_empty() {
            return Err(A2AError::InvalidAgentCard("Version cannot be empty".to_string()));
        }
        Ok(())
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> A2AResult<String> {
        serde_json::to_string(self)
            .map_err(|e| A2AError::SerializationError(e.to_string()))
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> A2AResult<Self> {
        serde_json::from_str(json)
            .map_err(|e| A2AError::SerializationError(e.to_string()))
    }

    /// Serialize to pretty JSON
    pub fn to_json_pretty(&self) -> A2AResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| A2AError::SerializationError(e.to_string()))
    }
}

/// Builder for AgentCard
#[derive(Debug, Default)]
pub struct AgentCardBuilder {
    id: Option<String>,
    name: Option<String>,
    description: String,
    version: String,
    capabilities: Vec<Capability>,
    endpoint: Option<String>,
    auth_methods: Vec<String>,
    metadata: HashMap<String, serde_json::Value>,
    ttl: u64,
}

impl AgentCardBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            id: None,
            name: None,
            description: String::new(),
            version: "1.0.0".to_string(),
            capabilities: Vec::new(),
            endpoint: None,
            auth_methods: Vec::new(),
            metadata: HashMap::new(),
            ttl: 3600, // 1 hour default
        }
    }

    /// Set the agent ID
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the agent name
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the description
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the version
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Add a capability
    pub fn capability(mut self, cap: Capability) -> Self {
        self.capabilities.push(cap);
        self
    }

    /// Set the endpoint
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Add an auth method
    pub fn auth_method(mut self, method: impl Into<String>) -> Self {
        self.auth_methods.push(method.into());
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Set TTL
    pub fn ttl(mut self, seconds: u64) -> Self {
        self.ttl = seconds;
        self
    }

    /// Build the AgentCard
    pub fn build(self) -> AgentCard {
        let now = current_timestamp();
        let id = self.id.unwrap_or_else(|| Uuid::now_v7().to_string());
        let name = self.name.unwrap_or_else(|| id.clone());

        AgentCard {
            id,
            name,
            description: self.description,
            version: self.version,
            protocol_version: AgentCard::PROTOCOL_VERSION.to_string(),
            capabilities: self.capabilities,
            endpoint: self.endpoint,
            auth_methods: self.auth_methods,
            metadata: self.metadata,
            created_at: now,
            updated_at: now,
            ttl: self.ttl,
            signature: None,
        }
    }
}

// ============================================================================
// Handshake Protocol
// ============================================================================

/// Request to initiate a handshake with another agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// The requester's agent card
    pub card: AgentCard,
    /// Requested capabilities
    pub requested_capabilities: Vec<String>,
    /// Offered capabilities
    pub offered_capabilities: Vec<String>,
    /// Session nonce for replay protection
    pub nonce: String,
    /// Request timestamp
    pub timestamp: u64,
}

impl HandshakeRequest {
    /// Create a new handshake request
    pub fn new(card: AgentCard) -> Self {
        Self {
            card,
            requested_capabilities: Vec::new(),
            offered_capabilities: Vec::new(),
            nonce: Uuid::new_v4().to_string(),
            timestamp: current_timestamp(),
        }
    }

    /// Request specific capabilities
    pub fn request_capabilities(mut self, caps: Vec<String>) -> Self {
        self.requested_capabilities = caps;
        self
    }

    /// Offer specific capabilities
    pub fn offer_capabilities(mut self, caps: Vec<String>) -> Self {
        self.offered_capabilities = caps;
        self
    }
}

/// Response to a handshake request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// The responder's agent card
    pub card: AgentCard,
    /// Whether the handshake is accepted
    pub accepted: bool,
    /// Capabilities granted
    pub granted_capabilities: Vec<String>,
    /// Capabilities requested from the initiator
    pub requested_capabilities: Vec<String>,
    /// Session token for future communication
    pub session_token: Option<String>,
    /// Error message if rejected
    pub error: Option<String>,
    /// Echo of the request nonce
    pub nonce: String,
    /// Response timestamp
    pub timestamp: u64,
}

impl HandshakeResponse {
    /// Create an accepting response
    pub fn accept(card: AgentCard, nonce: String) -> Self {
        Self {
            card,
            accepted: true,
            granted_capabilities: Vec::new(),
            requested_capabilities: Vec::new(),
            session_token: Some(Uuid::new_v4().to_string()),
            error: None,
            nonce,
            timestamp: current_timestamp(),
        }
    }

    /// Create a rejecting response
    pub fn reject(card: AgentCard, nonce: String, reason: impl Into<String>) -> Self {
        Self {
            card,
            accepted: false,
            granted_capabilities: Vec::new(),
            requested_capabilities: Vec::new(),
            session_token: None,
            error: Some(reason.into()),
            nonce,
            timestamp: current_timestamp(),
        }
    }

    /// Grant capabilities
    pub fn with_granted(mut self, caps: Vec<String>) -> Self {
        self.granted_capabilities = caps;
        self
    }
}

// ============================================================================
// Capability Exchange
// ============================================================================

/// A capability exchange request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequest {
    /// Session token from handshake
    pub session_token: String,
    /// Capability ID to invoke
    pub capability_id: String,
    /// Input data
    pub input: serde_json::Value,
    /// Request ID for correlation
    pub request_id: String,
    /// Timeout in milliseconds
    pub timeout_ms: u64,
}

impl CapabilityRequest {
    /// Create a new capability request
    pub fn new(session_token: String, capability_id: String, input: serde_json::Value) -> Self {
        Self {
            session_token,
            capability_id,
            input,
            request_id: Uuid::now_v7().to_string(),
            timeout_ms: 30000, // 30s default
        }
    }

    /// Set timeout
    pub fn with_timeout(mut self, ms: u64) -> Self {
        self.timeout_ms = ms;
        self
    }
}

/// Response to a capability request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityResponse {
    /// Request ID for correlation
    pub request_id: String,
    /// Whether the request succeeded
    pub success: bool,
    /// Output data
    pub output: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution time in milliseconds
    pub execution_time_ms: u64,
}

impl CapabilityResponse {
    /// Create a successful response
    pub fn success(request_id: String, output: serde_json::Value, exec_time_ms: u64) -> Self {
        Self {
            request_id,
            success: true,
            output: Some(output),
            error: None,
            execution_time_ms: exec_time_ms,
        }
    }

    /// Create an error response
    pub fn error(request_id: String, error: impl Into<String>) -> Self {
        Self {
            request_id,
            success: false,
            output: None,
            error: Some(error.into()),
            execution_time_ms: 0,
        }
    }
}

// ============================================================================
// A2A Protocol Configuration
// ============================================================================

/// Configuration for the A2A protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AConfig {
    /// Enable A2A protocol
    pub enabled: bool,
    /// Default timeout for operations (ms)
    pub default_timeout_ms: u64,
    /// Maximum number of registered agents
    pub max_agents: usize,
    /// Enable capability caching
    pub cache_capabilities: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Require signature verification
    pub require_signatures: bool,
    /// Allowed protocol versions
    pub allowed_versions: Vec<String>,
}

impl Default for A2AConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_timeout_ms: 30000,
            max_agents: 1000,
            cache_capabilities: true,
            cache_ttl_secs: 300,
            require_signatures: false,
            allowed_versions: vec!["1.0.0".to_string()],
        }
    }
}

// ============================================================================
// A2A Protocol Handler
// ============================================================================

/// Registered agent entry
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RegisteredAgent {
    card: AgentCard,
    registered_at: u64,
    last_seen: u64,
    active_sessions: HashMap<String, SessionInfo>,
}

/// Session information
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct SessionInfo {
    peer_id: String,
    token: String,
    created_at: u64,
    granted_capabilities: Vec<String>,
}

/// The A2A Protocol handler manages agent discovery and communication
pub struct A2AProtocol {
    /// Configuration
    config: A2AConfig,
    /// Registered agents
    agents: Arc<RwLock<HashMap<String, RegisteredAgent>>>,
    /// Our agent card
    our_card: Arc<RwLock<Option<AgentCard>>>,
}

impl A2AProtocol {
    /// Create a new A2A protocol handler
    pub fn new(config: A2AConfig) -> Self {
        Self {
            config,
            agents: Arc::new(RwLock::new(HashMap::new())),
            our_card: Arc::new(RwLock::new(None)),
        }
    }

    /// Set our agent card
    pub async fn set_our_card(&self, card: AgentCard) -> A2AResult<()> {
        card.validate()?;
        let mut our_card = self.our_card.write().await;
        *our_card = Some(card);
        Ok(())
    }

    /// Get our agent card
    pub async fn get_our_card(&self) -> Option<AgentCard> {
        self.our_card.read().await.clone()
    }

    /// Register a remote agent
    pub async fn register_agent(&self, card: AgentCard) -> A2AResult<()> {
        card.validate()?;

        let mut agents = self.agents.write().await;

        if agents.len() >= self.config.max_agents {
            return Err(A2AError::CommunicationError(
                "Maximum number of agents reached".to_string(),
            ));
        }

        if agents.contains_key(&card.id) {
            return Err(A2AError::AgentAlreadyRegistered(card.id.clone()));
        }

        let now = current_timestamp();
        agents.insert(
            card.id.clone(),
            RegisteredAgent {
                card,
                registered_at: now,
                last_seen: now,
                active_sessions: HashMap::new(),
            },
        );

        info!("Registered agent");
        Ok(())
    }

    /// Unregister an agent
    pub async fn unregister_agent(&self, agent_id: &str) -> A2AResult<()> {
        let mut agents = self.agents.write().await;
        agents
            .remove(agent_id)
            .ok_or_else(|| A2AError::AgentNotFound(agent_id.to_string()))?;
        info!(agent_id = %agent_id, "Unregistered agent");
        Ok(())
    }

    /// Get an agent's card
    pub async fn get_agent(&self, agent_id: &str) -> A2AResult<AgentCard> {
        let agents = self.agents.read().await;
        agents
            .get(agent_id)
            .map(|a| a.card.clone())
            .ok_or_else(|| A2AError::AgentNotFound(agent_id.to_string()))
    }

    /// List all registered agents
    pub async fn list_agents(&self) -> Vec<AgentCard> {
        let agents = self.agents.read().await;
        agents.values().map(|a| a.card.clone()).collect()
    }

    /// Find agents by capability
    pub async fn find_agents_with_capability(&self, capability_id: &str) -> Vec<AgentCard> {
        let agents = self.agents.read().await;
        agents
            .values()
            .filter(|a| a.card.has_capability(capability_id))
            .map(|a| a.card.clone())
            .collect()
    }

    /// Initiate a handshake with another agent
    pub async fn initiate_handshake(
        &self,
        target_agent_id: &str,
        requested_caps: Vec<String>,
    ) -> A2AResult<HandshakeRequest> {
        let our_card = self
            .our_card
            .read()
            .await
            .clone()
            .ok_or_else(|| A2AError::InvalidAgentCard("Our agent card not set".to_string()))?;

        // Verify target exists
        let _target = self.get_agent(target_agent_id).await?;

        let offered_caps: Vec<String> = our_card.capability_ids().iter().map(|s| s.to_string()).collect();

        Ok(HandshakeRequest::new(our_card)
            .request_capabilities(requested_caps)
            .offer_capabilities(offered_caps))
    }

    /// Handle an incoming handshake request
    pub async fn handle_handshake(
        &self,
        request: HandshakeRequest,
    ) -> A2AResult<HandshakeResponse> {
        // Validate the incoming card
        request.card.validate()?;

        // Check protocol version
        if !self.config.allowed_versions.contains(&request.card.protocol_version) {
            return Err(A2AError::VersionMismatch {
                expected: self.config.allowed_versions.join(", "),
                actual: request.card.protocol_version,
            });
        }

        let our_card = self
            .our_card
            .read()
            .await
            .clone()
            .ok_or_else(|| A2AError::InvalidAgentCard("Our agent card not set".to_string()))?;

        // Determine which capabilities we can grant
        let granted: Vec<String> = request
            .requested_capabilities
            .iter()
            .filter(|c| our_card.has_capability(c))
            .cloned()
            .collect();

        // Register the requesting agent if not already known
        {
            let mut agents = self.agents.write().await;
            let now = current_timestamp();
            agents
                .entry(request.card.id.clone())
                .and_modify(|a| {
                    a.card = request.card.clone();
                    a.last_seen = now;
                })
                .or_insert_with(|| RegisteredAgent {
                    card: request.card.clone(),
                    registered_at: now,
                    last_seen: now,
                    active_sessions: HashMap::new(),
                });
        }

        let response = HandshakeResponse::accept(our_card, request.nonce)
            .with_granted(granted);

        // Store session info
        if let Some(ref token) = response.session_token {
            let mut agents = self.agents.write().await;
            if let Some(agent) = agents.get_mut(&request.card.id) {
                agent.active_sessions.insert(
                    token.clone(),
                    SessionInfo {
                        peer_id: request.card.id.clone(),
                        token: token.clone(),
                        created_at: current_timestamp(),
                        granted_capabilities: response.granted_capabilities.clone(),
                    },
                );
            }
        }

        Ok(response)
    }

    /// Execute a capability request
    pub async fn execute_capability<F, Fut>(
        &self,
        request: CapabilityRequest,
        executor: F,
    ) -> A2AResult<CapabilityResponse>
    where
        F: FnOnce(String, serde_json::Value) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, String>>,
    {
        let start = std::time::Instant::now();

        // Validate session (simplified - in production would verify token)
        if request.session_token.is_empty() {
            return Ok(CapabilityResponse::error(
                request.request_id,
                "Invalid session token",
            ));
        }

        // Execute the capability
        match executor(request.capability_id.clone(), request.input).await {
            Ok(output) => Ok(CapabilityResponse::success(
                request.request_id,
                output,
                start.elapsed().as_millis() as u64,
            )),
            Err(e) => Ok(CapabilityResponse::error(request.request_id, e)),
        }
    }

    /// Get statistics about registered agents
    pub async fn stats(&self) -> A2AStats {
        let agents = self.agents.read().await;
        let total_agents = agents.len();
        let total_capabilities: usize = agents.values().map(|a| a.capabilities()).sum();
        let total_sessions: usize = agents.values().map(|a| a.active_sessions.len()).sum();

        A2AStats {
            total_agents,
            total_capabilities,
            total_sessions,
        }
    }
}

impl std::fmt::Debug for A2AProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("A2AProtocol")
            .field("config", &self.config)
            .finish()
    }
}

impl RegisteredAgent {
    fn capabilities(&self) -> usize {
        self.card.capabilities.len()
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics about A2A protocol usage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AStats {
    /// Number of registered agents
    pub total_agents: usize,
    /// Total capabilities across all agents
    pub total_capabilities: usize,
    /// Total active sessions
    pub total_sessions: usize,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// Discovery Mechanism (SWM-002)
// ============================================================================

/// Discovery configuration for finding agents on the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Enable active discovery
    pub enabled: bool,
    /// Discovery methods to use
    pub methods: Vec<DiscoveryMethod>,
    /// Discovery interval in seconds
    pub interval_secs: u64,
    /// Maximum agents to discover per cycle
    pub max_per_cycle: usize,
    /// Cache discovered agents
    pub cache_results: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            methods: vec![DiscoveryMethod::Local, DiscoveryMethod::Registry],
            interval_secs: 60,
            max_per_cycle: 100,
            cache_results: true,
            cache_ttl_secs: 300,
        }
    }
}

/// Methods for discovering agents
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Local network broadcast
    Local,
    /// Central registry lookup
    Registry,
    /// DNS-based discovery
    Dns,
    /// Peer exchange (gossip)
    PeerExchange,
    /// Static configuration
    Static,
}

/// Result of an agent discovery operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryResult {
    /// Discovered agents
    pub agents: Vec<DiscoveredAgent>,
    /// Methods used
    pub methods_used: Vec<DiscoveryMethod>,
    /// Discovery time in milliseconds
    pub discovery_time_ms: u64,
    /// Errors encountered
    pub errors: Vec<String>,
}

/// A discovered agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAgent {
    /// Agent card
    pub card: AgentCard,
    /// How the agent was discovered
    pub discovery_method: DiscoveryMethod,
    /// When the agent was discovered
    pub discovered_at: u64,
    /// Discovery score (higher = more reliable)
    pub reliability_score: f64,
    /// Network latency estimate (ms)
    pub latency_estimate_ms: Option<u64>,
}

/// Agent discovery service (SWM-002)
pub struct AgentDiscoveryService {
    /// Configuration
    config: DiscoveryConfig,
    /// Known agents cache
    cache: Arc<RwLock<Vec<DiscoveredAgent>>>,
    /// Registry endpoints
    registry_endpoints: Vec<String>,
    /// Our agent card for announcements
    our_card: Arc<RwLock<Option<AgentCard>>>,
}

impl AgentDiscoveryService {
    /// Create a new discovery service
    pub fn new(config: DiscoveryConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(Vec::new())),
            registry_endpoints: Vec::new(),
            our_card: Arc::new(RwLock::new(None)),
        }
    }

    /// Set our agent card
    pub async fn set_our_card(&self, card: AgentCard) {
        let mut our_card = self.our_card.write().await;
        *our_card = Some(card);
    }

    /// Add a registry endpoint
    pub fn add_registry_endpoint(&mut self, endpoint: impl Into<String>) {
        self.registry_endpoints.push(endpoint.into());
    }

    /// Discover agents using configured methods
    pub async fn discover(&self) -> DiscoveryResult {
        let start = std::time::Instant::now();
        let mut all_agents = Vec::new();
        let mut errors = Vec::new();
        let mut methods_used = Vec::new();

        for method in &self.config.methods {
            match method {
                DiscoveryMethod::Local => {
                    match self.discover_local().await {
                        Ok(agents) => {
                            all_agents.extend(agents);
                            methods_used.push(DiscoveryMethod::Local);
                        }
                        Err(e) => errors.push(format!("Local discovery failed: {}", e)),
                    }
                }
                DiscoveryMethod::Registry => {
                    match self.discover_from_registry().await {
                        Ok(agents) => {
                            all_agents.extend(agents);
                            methods_used.push(DiscoveryMethod::Registry);
                        }
                        Err(e) => errors.push(format!("Registry discovery failed: {}", e)),
                    }
                }
                DiscoveryMethod::Dns => {
                    match self.discover_via_dns().await {
                        Ok(agents) => {
                            all_agents.extend(agents);
                            methods_used.push(DiscoveryMethod::Dns);
                        }
                        Err(e) => errors.push(format!("DNS discovery failed: {}", e)),
                    }
                }
                DiscoveryMethod::PeerExchange => {
                    match self.discover_via_peers().await {
                        Ok(agents) => {
                            all_agents.extend(agents);
                            methods_used.push(DiscoveryMethod::PeerExchange);
                        }
                        Err(e) => errors.push(format!("Peer exchange failed: {}", e)),
                    }
                }
                DiscoveryMethod::Static => {
                    // Static agents are added manually, no discovery needed
                    methods_used.push(DiscoveryMethod::Static);
                }
            }
        }

        // Deduplicate by agent ID
        let mut seen = std::collections::HashSet::new();
        all_agents.retain(|a| seen.insert(a.card.id.clone()));

        // Limit results
        if all_agents.len() > self.config.max_per_cycle {
            all_agents.truncate(self.config.max_per_cycle);
        }

        // Update cache
        if self.config.cache_results {
            let mut cache = self.cache.write().await;
            *cache = all_agents.clone();
        }

        DiscoveryResult {
            agents: all_agents,
            methods_used,
            discovery_time_ms: start.elapsed().as_millis() as u64,
            errors,
        }
    }

    /// Discover local network agents
    async fn discover_local(&self) -> Result<Vec<DiscoveredAgent>, String> {
        // Simplified: In production, this would use mDNS/Bonjour or UDP broadcast
        let now = current_timestamp();
        Ok(vec![]) // No local agents discovered in simplified implementation
    }

    /// Discover agents from registry
    async fn discover_from_registry(&self) -> Result<Vec<DiscoveredAgent>, String> {
        let mut discovered = Vec::new();
        let now = current_timestamp();

        for endpoint in &self.registry_endpoints {
            // In production, this would make HTTP requests to the registry
            // Simplified implementation
            info!(endpoint = %endpoint, "Querying agent registry");
            
            // Simulate registry response
            // In production: let response = reqwest::get(endpoint).await?;
        }

        Ok(discovered)
    }

    /// Discover agents via DNS SRV records
    async fn discover_via_dns(&self) -> Result<Vec<DiscoveredAgent>, String> {
        // In production, this would resolve DNS SRV records like:
        // _vak-agent._tcp.example.com
        Ok(vec![])
    }

    /// Discover agents via peer exchange
    async fn discover_via_peers(&self) -> Result<Vec<DiscoveredAgent>, String> {
        let cache = self.cache.read().await;
        let mut discovered = Vec::new();

        // In production, this would query known peers for their peer lists
        for cached_agent in cache.iter() {
            if cached_agent.card.endpoint.is_some() {
                // Would query this agent for its known peers
            }
        }

        Ok(discovered)
    }

    /// Get cached agents
    pub async fn get_cached(&self) -> Vec<DiscoveredAgent> {
        self.cache.read().await.clone()
    }

    /// Find agents by capability from cache
    pub async fn find_by_capability(&self, capability_id: &str) -> Vec<DiscoveredAgent> {
        let cache = self.cache.read().await;
        cache
            .iter()
            .filter(|a| a.card.has_capability(capability_id))
            .cloned()
            .collect()
    }

    /// Find agents by tag from cache
    pub async fn find_by_tag(&self, tag: &str) -> Vec<DiscoveredAgent> {
        let cache = self.cache.read().await;
        cache
            .iter()
            .filter(|a| {
                a.card.capabilities.iter().any(|c| c.tags.contains(&tag.to_string()))
            })
            .cloned()
            .collect()
    }

    /// Announce our presence to registries
    pub async fn announce(&self) -> Result<(), String> {
        let our_card = self.our_card.read().await;
        let card = our_card
            .as_ref()
            .ok_or_else(|| "Our agent card not set".to_string())?;

        for endpoint in &self.registry_endpoints {
            // In production, this would POST our card to the registry
            info!(endpoint = %endpoint, agent_id = %card.id, "Announcing to registry");
        }

        Ok(())
    }

    /// Start background discovery loop
    pub fn start_discovery_loop(&self) -> DiscoveryHandle {
        let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let running_clone = running.clone();
        let interval = std::time::Duration::from_secs(self.config.interval_secs);
        let cache = Arc::clone(&self.cache);
        let methods = self.config.methods.clone();
        let max_per_cycle = self.config.max_per_cycle;

        tokio::spawn(async move {
            while running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                tokio::time::sleep(interval).await;
                
                // Simplified discovery in background
                info!("Running background agent discovery");
            }
            info!("Discovery loop stopped");
        });

        DiscoveryHandle { running }
    }
}

/// Handle to control the discovery loop
pub struct DiscoveryHandle {
    running: Arc<std::sync::atomic::AtomicBool>,
}

impl DiscoveryHandle {
    /// Stop the discovery loop
    pub fn stop(&self) {
        self.running.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Drop for DiscoveryHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Query for filtering discovered agents
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DiscoveryQuery {
    /// Filter by capability IDs
    pub capabilities: Vec<String>,
    /// Filter by tags
    pub tags: Vec<String>,
    /// Minimum reliability score
    pub min_reliability: Option<f64>,
    /// Maximum latency in milliseconds
    pub max_latency_ms: Option<u64>,
    /// Maximum results to return
    pub limit: Option<usize>,
}

impl DiscoveryQuery {
    /// Create a new query
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter by capability
    pub fn with_capability(mut self, cap: impl Into<String>) -> Self {
        self.capabilities.push(cap.into());
        self
    }

    /// Filter by tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Set minimum reliability
    pub fn with_min_reliability(mut self, score: f64) -> Self {
        self.min_reliability = Some(score);
        self
    }

    /// Set maximum latency
    pub fn with_max_latency(mut self, ms: u64) -> Self {
        self.max_latency_ms = Some(ms);
        self
    }

    /// Set result limit
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Apply query to a list of agents
    pub fn apply(&self, agents: &[DiscoveredAgent]) -> Vec<DiscoveredAgent> {
        let mut result: Vec<_> = agents
            .iter()
            .filter(|a| {
                // Check capabilities
                if !self.capabilities.is_empty() {
                    let has_all = self.capabilities.iter().all(|c| a.card.has_capability(c));
                    if !has_all {
                        return false;
                    }
                }

                // Check tags
                if !self.tags.is_empty() {
                    let has_tag = self.tags.iter().any(|tag| {
                        a.card.capabilities.iter().any(|c| c.tags.contains(tag))
                    });
                    if !has_tag {
                        return false;
                    }
                }

                // Check reliability
                if let Some(min) = self.min_reliability {
                    if a.reliability_score < min {
                        return false;
                    }
                }

                // Check latency
                if let Some(max) = self.max_latency_ms {
                    if let Some(latency) = a.latency_estimate_ms {
                        if latency > max {
                            return false;
                        }
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Apply limit
        if let Some(limit) = self.limit {
            result.truncate(limit);
        }

        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_creation() {
        let cap = Capability::new("code_review", "Reviews code for security issues")
            .with_name("Code Review")
            .with_version("2.0.0")
            .with_tag("security")
            .with_tag("audit")
            .with_rate_limit(100);

        assert_eq!(cap.id, "code_review");
        assert_eq!(cap.name, "Code Review");
        assert_eq!(cap.version, "2.0.0");
        assert_eq!(cap.tags, vec!["security", "audit"]);
        assert_eq!(cap.rate_limit, Some(100));
    }

    #[test]
    fn test_agent_card_builder() {
        let card = AgentCard::builder()
            .id("agent-001")
            .name("Test Agent")
            .description("A test agent")
            .version("1.0.0")
            .capability(Capability::new("test", "Test capability"))
            .endpoint("http://localhost:8080")
            .auth_method("bearer")
            .ttl(7200)
            .build();

        assert_eq!(card.id, "agent-001");
        assert_eq!(card.name, "Test Agent");
        assert_eq!(card.capabilities.len(), 1);
        assert!(card.has_capability("test"));
        assert!(!card.has_capability("nonexistent"));
    }

    #[test]
    fn test_agent_card_validation() {
        let valid_card = AgentCard::builder()
            .id("test")
            .name("Test")
            .build();
        assert!(valid_card.validate().is_ok());

        let invalid_card = AgentCard::builder().build();
        // Builder provides defaults, so this should still be valid
        assert!(invalid_card.validate().is_ok());
    }

    #[test]
    fn test_handshake_request() {
        let card = AgentCard::builder()
            .id("agent-001")
            .name("Test Agent")
            .capability(Capability::new("test", "Test"))
            .build();

        let request = HandshakeRequest::new(card)
            .request_capabilities(vec!["cap1".to_string(), "cap2".to_string()])
            .offer_capabilities(vec!["cap3".to_string()]);

        assert_eq!(request.requested_capabilities, vec!["cap1", "cap2"]);
        assert_eq!(request.offered_capabilities, vec!["cap3"]);
        assert!(!request.nonce.is_empty());
    }

    #[tokio::test]
    async fn test_a2a_protocol_registration() {
        let protocol = A2AProtocol::new(A2AConfig::default());

        let card = AgentCard::builder()
            .id("agent-001")
            .name("Test Agent")
            .capability(Capability::new("test", "Test capability"))
            .build();

        // Register agent
        assert!(protocol.register_agent(card.clone()).await.is_ok());

        // Can't register same agent twice
        assert!(protocol.register_agent(card).await.is_err());

        // Can retrieve agent
        let retrieved = protocol.get_agent("agent-001").await;
        assert!(retrieved.is_ok());
        assert_eq!(retrieved.unwrap().name, "Test Agent");

        // Can list agents
        let agents = protocol.list_agents().await;
        assert_eq!(agents.len(), 1);

        // Can find by capability
        let found = protocol.find_agents_with_capability("test").await;
        assert_eq!(found.len(), 1);

        let not_found = protocol.find_agents_with_capability("nonexistent").await;
        assert!(not_found.is_empty());
    }

    #[tokio::test]
    async fn test_handshake_flow() {
        let protocol = A2AProtocol::new(A2AConfig::default());

        // Set our card
        let our_card = AgentCard::builder()
            .id("server")
            .name("Server Agent")
            .capability(Capability::new("process_data", "Processes data"))
            .build();
        protocol.set_our_card(our_card).await.unwrap();

        // Register a client
        let client_card = AgentCard::builder()
            .id("client")
            .name("Client Agent")
            .capability(Capability::new("send_data", "Sends data"))
            .build();
        protocol.register_agent(client_card.clone()).await.unwrap();

        // Create handshake request
        let request = HandshakeRequest::new(client_card)
            .request_capabilities(vec!["process_data".to_string()]);

        // Handle handshake
        let response = protocol.handle_handshake(request).await.unwrap();

        assert!(response.accepted);
        assert!(response.session_token.is_some());
        assert!(response.granted_capabilities.contains(&"process_data".to_string()));
    }
}
