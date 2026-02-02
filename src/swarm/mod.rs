//! Swarm Consensus Protocol (SWM-001)
//!
//! This module provides multi-agent coordination and consensus mechanisms
//! for the Verifiable Agent Kernel. It enables multiple agents to collaborate,
//! debate, and reach consensus on decisions.
//!
//! # Overview
//!
//! The Swarm Consensus module includes:
//! - **Quadratic Voting**: Weighted voting mechanism to prevent sycophancy
//! - **Protocol Router**: Dynamic selection of collaboration topologies
//! - **Message Types**: Structured inter-agent communication
//! - **Consensus Mechanisms**: Various consensus algorithms (majority, weighted, BFT)
//! - **A2A Protocol**: Agent-to-Agent discovery and capability exchange (SWM-001, SWM-002)
//!
//! # Example
//!
//! ```rust
//! use vak::swarm::{SwarmCoordinator, SwarmConfig, Vote, QuadraticVoting};
//!
//! // Create a swarm coordinator
//! let config = SwarmConfig::default();
//! let coordinator = SwarmCoordinator::new(config);
//!
//! // Create a voting system
//! let voting = QuadraticVoting::new(100); // 100 credits per agent
//! ```

pub mod a2a;
pub mod consensus;
pub mod messages;
pub mod router;
pub mod voting;

pub use a2a::{
    A2AConfig, A2AError, A2AProtocol, A2AResult, A2AStats, AgentCard, AgentCardBuilder,
    Capability, CapabilityRequest, CapabilityResponse, HandshakeRequest, HandshakeResponse,
};

pub use voting::{
    AgentCredits, QuadraticVoting, Vote, VoteResult, VotingConfig, VotingError, VotingOutcome,
    VotingSession,
};

pub use router::{
    ProtocolRouter, RouterConfig, RoutingDecision, RoutingError, TaskComplexity, Topology,
    TopologySelection,
};

pub use messages::{
    Agreement, Critique, Disagreement, Evidence, MessageId, MessagePriority, MessageType, Proposal,
    SwarmMessage,
};

pub use consensus::{
    BftConsensus, ConsensusConfig, ConsensusError, ConsensusMechanism, ConsensusProtocol,
    ConsensusResult, MajorityConsensus, WeightedConsensus,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{broadcast, RwLock};
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in swarm operations
#[derive(Debug, Error)]
pub enum SwarmError {
    /// Agent not found in the swarm
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// Agent already exists in the swarm
    #[error("Agent already exists: {0}")]
    AgentAlreadyExists(String),

    /// Message delivery failed
    #[error("Message delivery failed: {0}")]
    MessageDeliveryFailed(String),

    /// Consensus failed to reach
    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),

    /// Invalid swarm configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Channel closed
    #[error("Channel closed")]
    ChannelClosed,

    /// Timeout occurred
    #[error("Operation timed out after {0} ms")]
    Timeout(u64),

    /// Voting error
    #[error("Voting error: {0}")]
    VotingError(#[from] VotingError),

    /// Routing error
    #[error("Routing error: {0}")]
    RoutingError(#[from] RoutingError),

    /// Consensus error
    #[error("Consensus error: {0}")]
    ConsensusError(#[from] ConsensusError),
}

/// Result type for swarm operations
pub type SwarmResult<T> = Result<T, SwarmError>;

// ============================================================================
// Agent Identity
// ============================================================================

/// Unique identifier for a swarm agent
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SwarmAgentId(pub Uuid);

impl SwarmAgentId {
    /// Create a new unique agent ID
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Create from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for SwarmAgentId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SwarmAgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SwarmAgent({})", self.0)
    }
}

// ============================================================================
// Agent Role
// ============================================================================

/// Role of an agent in the swarm
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    /// Leader agent that coordinates tasks
    Leader,
    /// Worker agent that executes tasks
    Worker,
    /// Reviewer agent that critiques work
    Reviewer,
    /// Arbitrator agent that resolves disputes
    Arbitrator,
    /// Observer agent that monitors without participating
    Observer,
    /// Custom role with a name
    Custom(String),
}

impl Default for AgentRole {
    fn default() -> Self {
        AgentRole::Worker
    }
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRole::Leader => write!(f, "Leader"),
            AgentRole::Worker => write!(f, "Worker"),
            AgentRole::Reviewer => write!(f, "Reviewer"),
            AgentRole::Arbitrator => write!(f, "Arbitrator"),
            AgentRole::Observer => write!(f, "Observer"),
            AgentRole::Custom(name) => write!(f, "Custom({})", name),
        }
    }
}

// ============================================================================
// Swarm Agent
// ============================================================================

/// Represents an agent participating in the swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmAgent {
    /// Unique identifier for this agent
    pub id: SwarmAgentId,
    /// Human-readable name
    pub name: String,
    /// Role in the swarm
    pub role: AgentRole,
    /// Capabilities of this agent
    pub capabilities: Vec<String>,
    /// Current reputation score (0.0 to 1.0)
    pub reputation: f64,
    /// Available voting credits
    pub credits: u64,
    /// Whether the agent is active
    pub active: bool,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl SwarmAgent {
    /// Create a new swarm agent
    pub fn new(name: impl Into<String>, role: AgentRole) -> Self {
        Self {
            id: SwarmAgentId::new(),
            name: name.into(),
            role,
            capabilities: Vec::new(),
            reputation: 0.5, // Start with neutral reputation
            credits: 100,    // Default voting credits
            active: true,
            metadata: HashMap::new(),
        }
    }

    /// Add a capability to this agent
    pub fn with_capability(mut self, capability: impl Into<String>) -> Self {
        self.capabilities.push(capability.into());
        self
    }

    /// Set the initial credits
    pub fn with_credits(mut self, credits: u64) -> Self {
        self.credits = credits;
        self
    }

    /// Set the initial reputation
    pub fn with_reputation(mut self, reputation: f64) -> Self {
        self.reputation = reputation.clamp(0.0, 1.0);
        self
    }

    /// Check if agent has a specific capability
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }

    /// Update reputation based on performance
    pub fn update_reputation(&mut self, delta: f64) {
        self.reputation = (self.reputation + delta).clamp(0.0, 1.0);
    }

    /// Deduct credits (returns false if insufficient)
    pub fn deduct_credits(&mut self, amount: u64) -> bool {
        if self.credits >= amount {
            self.credits -= amount;
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Swarm Configuration
// ============================================================================

/// Configuration for the swarm coordinator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmConfig {
    /// Maximum number of agents in the swarm
    pub max_agents: usize,
    /// Default voting credits for new agents
    pub default_credits: u64,
    /// Consensus timeout in milliseconds
    pub consensus_timeout_ms: u64,
    /// Minimum participation rate for valid consensus (0.0 to 1.0)
    pub min_participation: f64,
    /// Whether to allow observer agents
    pub allow_observers: bool,
    /// Default consensus mechanism
    pub default_consensus: ConsensusMechanism,
    /// Message buffer size
    pub message_buffer_size: usize,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            max_agents: 100,
            default_credits: 100,
            consensus_timeout_ms: 30000,
            min_participation: 0.5,
            allow_observers: true,
            default_consensus: ConsensusMechanism::QuadraticMajority,
            message_buffer_size: 1000,
        }
    }
}

impl SwarmConfig {
    /// Create a new configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of agents
    pub fn with_max_agents(mut self, max: usize) -> Self {
        self.max_agents = max;
        self
    }

    /// Set the consensus timeout
    pub fn with_consensus_timeout(mut self, timeout_ms: u64) -> Self {
        self.consensus_timeout_ms = timeout_ms;
        self
    }

    /// Set the minimum participation rate
    pub fn with_min_participation(mut self, rate: f64) -> Self {
        self.min_participation = rate.clamp(0.0, 1.0);
        self
    }

    /// Set the default consensus mechanism
    pub fn with_consensus_mechanism(mut self, mechanism: ConsensusMechanism) -> Self {
        self.default_consensus = mechanism;
        self
    }
}

// ============================================================================
// Swarm Coordinator
// ============================================================================

/// Central coordinator for swarm operations
pub struct SwarmCoordinator {
    /// Configuration
    config: SwarmConfig,
    /// Registered agents
    agents: Arc<RwLock<HashMap<SwarmAgentId, SwarmAgent>>>,
    /// Message broadcast channel
    broadcast: broadcast::Sender<SwarmMessage>,
    /// Voting sessions
    voting_sessions: Arc<RwLock<HashMap<String, VotingSession>>>,
    /// Protocol router for topology selection
    router: ProtocolRouter,
}

impl SwarmCoordinator {
    /// Create a new swarm coordinator
    pub fn new(config: SwarmConfig) -> Self {
        let (broadcast, _) = broadcast::channel(config.message_buffer_size);

        Self {
            router: ProtocolRouter::new(RouterConfig::default()),
            config,
            agents: Arc::new(RwLock::new(HashMap::new())),
            broadcast,
            voting_sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new agent in the swarm
    pub async fn register_agent(&self, mut agent: SwarmAgent) -> SwarmResult<SwarmAgentId> {
        let mut agents = self.agents.write().await;

        if agents.len() >= self.config.max_agents {
            return Err(SwarmError::InvalidConfig(
                "Maximum agent limit reached".to_string(),
            ));
        }

        if agents.contains_key(&agent.id) {
            return Err(SwarmError::AgentAlreadyExists(agent.id.to_string()));
        }

        // Set default credits if not specified
        if agent.credits == 0 {
            agent.credits = self.config.default_credits;
        }

        let id = agent.id.clone();
        agents.insert(agent.id.clone(), agent);

        Ok(id)
    }

    /// Unregister an agent from the swarm
    pub async fn unregister_agent(&self, agent_id: &SwarmAgentId) -> SwarmResult<SwarmAgent> {
        let mut agents = self.agents.write().await;
        agents
            .remove(agent_id)
            .ok_or_else(|| SwarmError::AgentNotFound(agent_id.to_string()))
    }

    /// Get an agent by ID
    pub async fn get_agent(&self, agent_id: &SwarmAgentId) -> SwarmResult<SwarmAgent> {
        let agents = self.agents.read().await;
        agents
            .get(agent_id)
            .cloned()
            .ok_or_else(|| SwarmError::AgentNotFound(agent_id.to_string()))
    }

    /// List all agents
    pub async fn list_agents(&self) -> Vec<SwarmAgent> {
        let agents = self.agents.read().await;
        agents.values().cloned().collect()
    }

    /// List agents by role
    pub async fn list_agents_by_role(&self, role: &AgentRole) -> Vec<SwarmAgent> {
        let agents = self.agents.read().await;
        agents
            .values()
            .filter(|a| &a.role == role)
            .cloned()
            .collect()
    }

    /// Get the number of active agents
    pub async fn active_agent_count(&self) -> usize {
        let agents = self.agents.read().await;
        agents.values().filter(|a| a.active).count()
    }

    /// Broadcast a message to all agents
    pub async fn broadcast_message(&self, message: SwarmMessage) -> SwarmResult<usize> {
        let receivers = self.broadcast.receiver_count();
        self.broadcast
            .send(message)
            .map_err(|_| SwarmError::MessageDeliveryFailed("Broadcast failed".to_string()))?;
        Ok(receivers)
    }

    /// Subscribe to swarm messages
    pub fn subscribe(&self) -> broadcast::Receiver<SwarmMessage> {
        self.broadcast.subscribe()
    }

    /// Create a new voting session
    pub async fn create_voting_session(
        &self,
        proposal: Proposal,
        voting_config: VotingConfig,
    ) -> SwarmResult<String> {
        let session_id = Uuid::now_v7().to_string();
        let session = VotingSession::new(session_id.clone(), proposal, voting_config);

        let mut sessions = self.voting_sessions.write().await;
        sessions.insert(session_id.clone(), session);

        Ok(session_id)
    }

    /// Cast a vote in a session
    pub async fn cast_vote(
        &self,
        session_id: &str,
        agent_id: &SwarmAgentId,
        vote: Vote,
    ) -> SwarmResult<()> {
        // Get agent and check credits
        let mut agents = self.agents.write().await;
        let agent = agents
            .get_mut(agent_id)
            .ok_or_else(|| SwarmError::AgentNotFound(agent_id.to_string()))?;

        // Calculate cost (quadratic for strong votes)
        let cost = vote.strength * vote.strength;
        if !agent.deduct_credits(cost) {
            return Err(SwarmError::VotingError(VotingError::InsufficientCredits(
                agent.credits,
                cost,
            )));
        }

        // Record the vote
        let mut sessions = self.voting_sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or_else(|| {
            SwarmError::InvalidConfig(format!("Session not found: {}", session_id))
        })?;

        session.record_vote(agent_id.clone(), vote)?;

        Ok(())
    }

    /// Finalize a voting session and get the result
    pub async fn finalize_voting(&self, session_id: &str) -> SwarmResult<VotingOutcome> {
        let mut sessions = self.voting_sessions.write().await;
        let session = sessions.get_mut(session_id).ok_or_else(|| {
            SwarmError::InvalidConfig(format!("Session not found: {}", session_id))
        })?;

        let outcome = session.finalize()?;
        Ok(outcome)
    }

    /// Select the best topology for a task
    pub async fn select_topology(&self, task: &str, complexity: TaskComplexity) -> RoutingDecision {
        self.router
            .route(task, complexity, self.active_agent_count().await)
    }

    /// Get the current configuration
    pub fn config(&self) -> &SwarmConfig {
        &self.config
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_swarm_agent_id() {
        let id1 = SwarmAgentId::new();
        let id2 = SwarmAgentId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_swarm_agent_creation() {
        let agent = SwarmAgent::new("TestAgent", AgentRole::Worker)
            .with_capability("coding")
            .with_capability("review")
            .with_credits(200)
            .with_reputation(0.8);

        assert_eq!(agent.name, "TestAgent");
        assert_eq!(agent.role, AgentRole::Worker);
        assert_eq!(agent.capabilities.len(), 2);
        assert!(agent.has_capability("coding"));
        assert!(!agent.has_capability("design"));
        assert_eq!(agent.credits, 200);
        assert!((agent.reputation - 0.8).abs() < 0.001);
    }

    #[test]
    fn test_agent_credits() {
        let mut agent = SwarmAgent::new("TestAgent", AgentRole::Worker).with_credits(100);

        assert!(agent.deduct_credits(50));
        assert_eq!(agent.credits, 50);
        assert!(!agent.deduct_credits(100)); // Not enough
        assert_eq!(agent.credits, 50); // Unchanged
    }

    #[test]
    fn test_agent_reputation() {
        let mut agent = SwarmAgent::new("TestAgent", AgentRole::Worker).with_reputation(0.5);

        agent.update_reputation(0.3);
        assert!((agent.reputation - 0.8).abs() < 0.001);

        agent.update_reputation(0.5); // Would exceed 1.0
        assert!((agent.reputation - 1.0).abs() < 0.001); // Clamped

        agent.update_reputation(-1.5); // Would go below 0.0
        assert!(agent.reputation >= 0.0); // Clamped
    }

    #[test]
    fn test_swarm_config_default() {
        let config = SwarmConfig::default();
        assert_eq!(config.max_agents, 100);
        assert_eq!(config.default_credits, 100);
        assert_eq!(config.consensus_timeout_ms, 30000);
    }

    #[test]
    fn test_swarm_config_builder() {
        let config = SwarmConfig::new()
            .with_max_agents(50)
            .with_consensus_timeout(5000)
            .with_min_participation(0.75);

        assert_eq!(config.max_agents, 50);
        assert_eq!(config.consensus_timeout_ms, 5000);
        assert!((config.min_participation - 0.75).abs() < 0.001);
    }

    #[tokio::test]
    async fn test_swarm_coordinator_creation() {
        let config = SwarmConfig::default();
        let coordinator = SwarmCoordinator::new(config);

        assert_eq!(coordinator.active_agent_count().await, 0);
    }

    #[tokio::test]
    async fn test_register_agent() {
        let coordinator = SwarmCoordinator::new(SwarmConfig::default());

        let agent = SwarmAgent::new("Agent1", AgentRole::Worker);
        let id = coordinator.register_agent(agent).await.unwrap();

        assert_eq!(coordinator.active_agent_count().await, 1);

        let retrieved = coordinator.get_agent(&id).await.unwrap();
        assert_eq!(retrieved.name, "Agent1");
    }

    #[tokio::test]
    async fn test_unregister_agent() {
        let coordinator = SwarmCoordinator::new(SwarmConfig::default());

        let agent = SwarmAgent::new("Agent1", AgentRole::Worker);
        let id = coordinator.register_agent(agent).await.unwrap();

        let removed = coordinator.unregister_agent(&id).await.unwrap();
        assert_eq!(removed.name, "Agent1");
        assert_eq!(coordinator.active_agent_count().await, 0);
    }

    #[tokio::test]
    async fn test_list_agents_by_role() {
        let coordinator = SwarmCoordinator::new(SwarmConfig::default());

        coordinator
            .register_agent(SwarmAgent::new("Worker1", AgentRole::Worker))
            .await
            .unwrap();
        coordinator
            .register_agent(SwarmAgent::new("Worker2", AgentRole::Worker))
            .await
            .unwrap();
        coordinator
            .register_agent(SwarmAgent::new("Leader1", AgentRole::Leader))
            .await
            .unwrap();

        let workers = coordinator.list_agents_by_role(&AgentRole::Worker).await;
        assert_eq!(workers.len(), 2);

        let leaders = coordinator.list_agents_by_role(&AgentRole::Leader).await;
        assert_eq!(leaders.len(), 1);
    }

    #[tokio::test]
    async fn test_max_agents_limit() {
        let config = SwarmConfig::new().with_max_agents(2);
        let coordinator = SwarmCoordinator::new(config);

        coordinator
            .register_agent(SwarmAgent::new("Agent1", AgentRole::Worker))
            .await
            .unwrap();
        coordinator
            .register_agent(SwarmAgent::new("Agent2", AgentRole::Worker))
            .await
            .unwrap();

        // Third agent should fail
        let result = coordinator
            .register_agent(SwarmAgent::new("Agent3", AgentRole::Worker))
            .await;

        assert!(matches!(result, Err(SwarmError::InvalidConfig(_))));
    }

    #[test]
    fn test_agent_role_display() {
        assert_eq!(format!("{}", AgentRole::Leader), "Leader");
        assert_eq!(format!("{}", AgentRole::Worker), "Worker");
        assert_eq!(
            format!("{}", AgentRole::Custom("Expert".to_string())),
            "Custom(Expert)"
        );
    }
}
