//! Consensus Mechanisms
//!
//! This module implements various consensus mechanisms for multi-agent
//! decision-making. Each mechanism has different properties and use cases.
//!
//! # Mechanisms
//!
//! - **Majority**: Simple majority voting
//! - **Weighted**: Weighted voting based on reputation/expertise
//! - **BFT**: Byzantine Fault Tolerant consensus
//! - **Quadratic**: Quadratic voting (integrates with voting module)
//!
//! # Example
//!
//! ```rust
//! use vak::swarm::consensus::{MajorityConsensus, ConsensusProtocol, ConsensusConfig};
//!
//! let config = ConsensusConfig::default();
//! let consensus = MajorityConsensus::new(config);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use super::SwarmAgentId;
use super::voting::VoteDirection;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during consensus operations
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// Not enough participants
    #[error("Insufficient participants: need {0}, have {1}")]
    InsufficientParticipants(usize, usize),

    /// Consensus failed to converge
    #[error("Consensus failed to converge after {0} rounds")]
    FailedToConverge(usize),

    /// Byzantine fault detected
    #[error("Byzantine fault detected: {0}")]
    ByzantineFault(String),

    /// Timeout occurred
    #[error("Consensus timed out after {0} ms")]
    Timeout(u64),

    /// Invalid vote
    #[error("Invalid vote from agent {0}")]
    InvalidVote(String),

    /// Agent not found
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// Protocol violation
    #[error("Protocol violation: {0}")]
    ProtocolViolation(String),
}

// ============================================================================
// Consensus Mechanism
// ============================================================================

/// Types of consensus mechanisms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMechanism {
    /// Simple majority (>50%)
    SimpleMajority,
    /// Super majority (>66%)
    SuperMajority,
    /// Unanimous agreement
    Unanimous,
    /// Weighted by reputation
    WeightedReputation,
    /// Weighted by expertise
    WeightedExpertise,
    /// Byzantine fault tolerant
    ByzantineFaultTolerant,
    /// Quadratic voting
    QuadraticMajority,
}

impl Default for ConsensusMechanism {
    fn default() -> Self {
        ConsensusMechanism::SimpleMajority
    }
}

// ============================================================================
// Consensus Configuration
// ============================================================================

/// Configuration for consensus operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Mechanism to use
    pub mechanism: ConsensusMechanism,
    /// Minimum participants required
    pub min_participants: usize,
    /// Maximum rounds before timeout
    pub max_rounds: usize,
    /// Timeout per round in milliseconds
    pub round_timeout_ms: u64,
    /// Threshold for passing (0.0 to 1.0)
    pub pass_threshold: f64,
    /// Whether to require explicit votes (no abstentions)
    pub require_explicit: bool,
    /// Byzantine fault tolerance level (f in n = 3f + 1)
    pub byzantine_tolerance: usize,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            mechanism: ConsensusMechanism::SimpleMajority,
            min_participants: 3,
            max_rounds: 10,
            round_timeout_ms: 5000,
            pass_threshold: 0.5,
            require_explicit: false,
            byzantine_tolerance: 1,
        }
    }
}

impl ConsensusConfig {
    /// Create a new configuration
    pub fn new(mechanism: ConsensusMechanism) -> Self {
        let pass_threshold = match mechanism {
            ConsensusMechanism::SimpleMajority => 0.5,
            ConsensusMechanism::SuperMajority => 0.67,
            ConsensusMechanism::Unanimous => 1.0,
            ConsensusMechanism::QuadraticMajority => 0.5,
            _ => 0.5,
        };

        Self {
            mechanism,
            pass_threshold,
            ..Default::default()
        }
    }

    /// Set the minimum participants
    pub fn with_min_participants(mut self, min: usize) -> Self {
        self.min_participants = min;
        self
    }

    /// Set the pass threshold
    pub fn with_pass_threshold(mut self, threshold: f64) -> Self {
        self.pass_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Set the maximum rounds
    pub fn with_max_rounds(mut self, rounds: usize) -> Self {
        self.max_rounds = rounds;
        self
    }

    /// Set the round timeout
    pub fn with_round_timeout(mut self, timeout_ms: u64) -> Self {
        self.round_timeout_ms = timeout_ms;
        self
    }

    /// Set Byzantine tolerance
    pub fn with_byzantine_tolerance(mut self, tolerance: usize) -> Self {
        self.byzantine_tolerance = tolerance;
        self
    }
}

// ============================================================================
// Consensus Vote
// ============================================================================

/// A vote in a consensus round
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusVote {
    /// Agent casting the vote
    pub agent_id: SwarmAgentId,
    /// Vote direction
    pub direction: VoteDirection,
    /// Vote weight (1.0 = standard)
    pub weight: f64,
    /// Round number
    pub round: usize,
    /// Justification
    pub justification: Option<String>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ConsensusVote {
    /// Create a new consensus vote
    pub fn new(agent_id: SwarmAgentId, direction: VoteDirection) -> Self {
        Self {
            agent_id,
            direction,
            weight: 1.0,
            round: 0,
            justification: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Set the weight
    pub fn with_weight(mut self, weight: f64) -> Self {
        self.weight = weight.max(0.0);
        self
    }

    /// Set the round
    pub fn with_round(mut self, round: usize) -> Self {
        self.round = round;
        self
    }

    /// Add justification
    pub fn with_justification(mut self, justification: impl Into<String>) -> Self {
        self.justification = Some(justification.into());
        self
    }
}

// ============================================================================
// Consensus Result
// ============================================================================

/// Result of a consensus operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusResult {
    /// Whether consensus was reached
    pub reached: bool,
    /// Whether the proposal passed
    pub passed: bool,
    /// Final vote tally
    pub votes_for: f64,
    /// Final vote tally against
    pub votes_against: f64,
    /// Number of abstentions
    pub abstentions: usize,
    /// Total participants
    pub participants: usize,
    /// Rounds taken
    pub rounds: usize,
    /// Time taken in milliseconds
    pub time_ms: u64,
    /// Individual votes
    pub votes: Vec<ConsensusVote>,
    /// Any detected faults
    pub faults: Vec<String>,
}

impl ConsensusResult {
    /// Get the pass percentage
    pub fn pass_percentage(&self) -> f64 {
        let total = self.votes_for + self.votes_against;
        if total == 0.0 {
            0.5
        } else {
            self.votes_for / total
        }
    }

    /// Get the participation rate
    pub fn participation_rate(&self, eligible: usize) -> f64 {
        if eligible == 0 {
            0.0
        } else {
            self.participants as f64 / eligible as f64
        }
    }

    /// Get the margin
    pub fn margin(&self) -> f64 {
        self.votes_for - self.votes_against
    }
}

// ============================================================================
// Consensus Protocol Trait
// ============================================================================

/// Trait for consensus protocols
pub trait ConsensusProtocol: Send + Sync {
    /// Run the consensus protocol
    fn run_consensus(
        &self,
        votes: &[ConsensusVote],
        eligible_voters: usize,
    ) -> Result<ConsensusResult, ConsensusError>;

    /// Get the configuration
    fn config(&self) -> &ConsensusConfig;

    /// Check if enough votes are present
    fn has_quorum(&self, vote_count: usize, eligible: usize) -> bool;
}

// ============================================================================
// Majority Consensus
// ============================================================================

/// Simple majority consensus implementation
#[derive(Debug, Clone)]
pub struct MajorityConsensus {
    config: ConsensusConfig,
}

impl MajorityConsensus {
    /// Create a new majority consensus
    pub fn new(config: ConsensusConfig) -> Self {
        Self { config }
    }
}

impl ConsensusProtocol for MajorityConsensus {
    fn run_consensus(
        &self,
        votes: &[ConsensusVote],
        _eligible_voters: usize,
    ) -> Result<ConsensusResult, ConsensusError> {
        if votes.len() < self.config.min_participants {
            return Err(ConsensusError::InsufficientParticipants(
                self.config.min_participants,
                votes.len(),
            ));
        }

        let mut votes_for = 0.0;
        let mut votes_against = 0.0;
        let mut abstentions = 0;

        for vote in votes {
            match vote.direction {
                VoteDirection::For => votes_for += vote.weight,
                VoteDirection::Against => votes_against += vote.weight,
                VoteDirection::Abstain => abstentions += 1,
            }
        }

        let total = votes_for + votes_against;
        let pass_percentage = if total > 0.0 {
            votes_for / total
        } else {
            0.0
        };

        let passed = pass_percentage > self.config.pass_threshold;
        let reached = pass_percentage > self.config.pass_threshold
            || (1.0 - pass_percentage) > self.config.pass_threshold;

        Ok(ConsensusResult {
            reached,
            passed,
            votes_for,
            votes_against,
            abstentions,
            participants: votes.len(),
            rounds: 1,
            time_ms: 0,
            votes: votes.to_vec(),
            faults: Vec::new(),
        })
    }

    fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    fn has_quorum(&self, vote_count: usize, eligible: usize) -> bool {
        let min_needed = (eligible as f64 * self.config.pass_threshold).ceil() as usize;
        vote_count >= min_needed.max(self.config.min_participants)
    }
}

// ============================================================================
// Weighted Consensus
// ============================================================================

/// Agent weight information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWeight {
    /// Agent ID
    pub agent_id: SwarmAgentId,
    /// Weight based on reputation
    pub reputation_weight: f64,
    /// Weight based on expertise
    pub expertise_weight: f64,
    /// Role-based weight
    pub role_weight: f64,
}

impl AgentWeight {
    /// Create new agent weight
    pub fn new(agent_id: SwarmAgentId) -> Self {
        Self {
            agent_id,
            reputation_weight: 1.0,
            expertise_weight: 1.0,
            role_weight: 1.0,
        }
    }

    /// Total weight
    pub fn total_weight(&self) -> f64 {
        (self.reputation_weight + self.expertise_weight + self.role_weight) / 3.0
    }

    /// Set reputation weight
    pub fn with_reputation(mut self, weight: f64) -> Self {
        self.reputation_weight = weight.max(0.0);
        self
    }

    /// Set expertise weight
    pub fn with_expertise(mut self, weight: f64) -> Self {
        self.expertise_weight = weight.max(0.0);
        self
    }

    /// Set role weight
    pub fn with_role(mut self, weight: f64) -> Self {
        self.role_weight = weight.max(0.0);
        self
    }
}

/// Weighted consensus implementation
#[derive(Debug, Clone)]
pub struct WeightedConsensus {
    config: ConsensusConfig,
    weights: HashMap<SwarmAgentId, AgentWeight>,
}

impl WeightedConsensus {
    /// Create a new weighted consensus
    pub fn new(config: ConsensusConfig) -> Self {
        Self {
            config,
            weights: HashMap::new(),
        }
    }

    /// Set agent weights
    pub fn with_weights(mut self, weights: HashMap<SwarmAgentId, AgentWeight>) -> Self {
        self.weights = weights;
        self
    }

    /// Add or update an agent's weight
    pub fn set_weight(&mut self, weight: AgentWeight) {
        self.weights.insert(weight.agent_id.clone(), weight);
    }

    /// Get an agent's weight
    pub fn get_weight(&self, agent_id: &SwarmAgentId) -> f64 {
        self.weights
            .get(agent_id)
            .map(|w| w.total_weight())
            .unwrap_or(1.0)
    }
}

impl ConsensusProtocol for WeightedConsensus {
    fn run_consensus(
        &self,
        votes: &[ConsensusVote],
        _eligible_voters: usize,
    ) -> Result<ConsensusResult, ConsensusError> {
        if votes.len() < self.config.min_participants {
            return Err(ConsensusError::InsufficientParticipants(
                self.config.min_participants,
                votes.len(),
            ));
        }

        let mut votes_for = 0.0;
        let mut votes_against = 0.0;
        let mut abstentions = 0;

        for vote in votes {
            let weight = self.get_weight(&vote.agent_id) * vote.weight;
            match vote.direction {
                VoteDirection::For => votes_for += weight,
                VoteDirection::Against => votes_against += weight,
                VoteDirection::Abstain => abstentions += 1,
            }
        }

        let total = votes_for + votes_against;
        let pass_percentage = if total > 0.0 {
            votes_for / total
        } else {
            0.0
        };

        let passed = pass_percentage > self.config.pass_threshold;
        let reached = pass_percentage > self.config.pass_threshold
            || (1.0 - pass_percentage) > self.config.pass_threshold;

        Ok(ConsensusResult {
            reached,
            passed,
            votes_for,
            votes_against,
            abstentions,
            participants: votes.len(),
            rounds: 1,
            time_ms: 0,
            votes: votes.to_vec(),
            faults: Vec::new(),
        })
    }

    fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    fn has_quorum(&self, vote_count: usize, eligible: usize) -> bool {
        let min_needed = (eligible as f64 * self.config.pass_threshold).ceil() as usize;
        vote_count >= min_needed.max(self.config.min_participants)
    }
}

// ============================================================================
// BFT Consensus
// ============================================================================

/// Byzantine Fault Tolerant consensus implementation
#[derive(Debug, Clone)]
pub struct BftConsensus {
    config: ConsensusConfig,
}

impl BftConsensus {
    /// Create a new BFT consensus
    pub fn new(config: ConsensusConfig) -> Self {
        Self { config }
    }

    /// Calculate required nodes for BFT (n = 3f + 1)
    pub fn required_nodes(&self) -> usize {
        3 * self.config.byzantine_tolerance + 1
    }

    /// Calculate required votes for BFT (2f + 1)
    pub fn required_votes(&self) -> usize {
        2 * self.config.byzantine_tolerance + 1
    }
}

impl ConsensusProtocol for BftConsensus {
    fn run_consensus(
        &self,
        votes: &[ConsensusVote],
        eligible_voters: usize,
    ) -> Result<ConsensusResult, ConsensusError> {
        let required_nodes = self.required_nodes();
        if eligible_voters < required_nodes {
            return Err(ConsensusError::InsufficientParticipants(
                required_nodes,
                eligible_voters,
            ));
        }

        let required_votes = self.required_votes();
        if votes.len() < required_votes {
            return Err(ConsensusError::InsufficientParticipants(
                required_votes,
                votes.len(),
            ));
        }

        let mut votes_for = 0.0;
        let mut votes_against = 0.0;
        let mut abstentions = 0;
        let mut faults = Vec::new();

        // Check for Byzantine behavior (duplicate votes, contradictory votes)
        let mut seen_agents: HashMap<SwarmAgentId, VoteDirection> = HashMap::new();
        
        for vote in votes {
            if let Some(prev_direction) = seen_agents.get(&vote.agent_id) {
                if *prev_direction != vote.direction {
                    faults.push(format!(
                        "Byzantine fault: Agent {} changed vote",
                        vote.agent_id
                    ));
                }
                continue; // Skip duplicate votes
            }
            seen_agents.insert(vote.agent_id.clone(), vote.direction.clone());

            match vote.direction {
                VoteDirection::For => votes_for += vote.weight,
                VoteDirection::Against => votes_against += vote.weight,
                VoteDirection::Abstain => abstentions += 1,
            }
        }

        // BFT requires > 2/3 agreement
        let total = votes_for + votes_against;
        let pass_percentage = if total > 0.0 {
            votes_for / total
        } else {
            0.0
        };

        // For BFT, we need more than 2/3 to pass
        let bft_threshold = 2.0 / 3.0;
        let passed = pass_percentage > bft_threshold;
        let reached = pass_percentage > bft_threshold || (1.0 - pass_percentage) > bft_threshold;

        Ok(ConsensusResult {
            reached,
            passed,
            votes_for,
            votes_against,
            abstentions,
            participants: seen_agents.len(),
            rounds: 1,
            time_ms: 0,
            votes: votes.to_vec(),
            faults,
        })
    }

    fn config(&self) -> &ConsensusConfig {
        &self.config
    }

    fn has_quorum(&self, vote_count: usize, eligible: usize) -> bool {
        vote_count >= self.required_votes() && eligible >= self.required_nodes()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vote(direction: VoteDirection) -> ConsensusVote {
        ConsensusVote::new(SwarmAgentId::new(), direction)
    }

    fn make_weighted_vote(direction: VoteDirection, weight: f64) -> ConsensusVote {
        ConsensusVote::new(SwarmAgentId::new(), direction).with_weight(weight)
    }

    #[test]
    fn test_consensus_config_default() {
        let config = ConsensusConfig::default();
        assert_eq!(config.mechanism, ConsensusMechanism::SimpleMajority);
        assert_eq!(config.min_participants, 3);
    }

    #[test]
    fn test_consensus_config_builder() {
        let config = ConsensusConfig::new(ConsensusMechanism::SuperMajority)
            .with_min_participants(5)
            .with_pass_threshold(0.75);

        assert_eq!(config.mechanism, ConsensusMechanism::SuperMajority);
        assert_eq!(config.min_participants, 5);
        assert!((config.pass_threshold - 0.75).abs() < 0.001);
    }

    #[test]
    fn test_consensus_vote_creation() {
        let agent_id = SwarmAgentId::new();
        let vote = ConsensusVote::new(agent_id.clone(), VoteDirection::For)
            .with_weight(2.0)
            .with_round(1)
            .with_justification("Strong support");

        assert_eq!(vote.agent_id, agent_id);
        assert_eq!(vote.direction, VoteDirection::For);
        assert!((vote.weight - 2.0).abs() < 0.001);
        assert_eq!(vote.round, 1);
        assert!(vote.justification.is_some());
    }

    #[test]
    fn test_majority_consensus_pass() {
        let config = ConsensusConfig::new(ConsensusMechanism::SimpleMajority)
            .with_min_participants(3);
        let consensus = MajorityConsensus::new(config);

        let votes = vec![
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::Against),
        ];

        let result = consensus.run_consensus(&votes, 3).unwrap();
        assert!(result.passed); // 2 for, 1 against = 66%
        assert!(result.reached);
    }

    #[test]
    fn test_majority_consensus_fail() {
        let config = ConsensusConfig::new(ConsensusMechanism::SimpleMajority)
            .with_min_participants(3);
        let consensus = MajorityConsensus::new(config);

        let votes = vec![
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::Against),
            make_vote(VoteDirection::Against),
        ];

        let result = consensus.run_consensus(&votes, 3).unwrap();
        assert!(!result.passed); // 1 for, 2 against = 33%
        assert!(result.reached);
    }

    #[test]
    fn test_majority_consensus_insufficient_participants() {
        let config = ConsensusConfig::new(ConsensusMechanism::SimpleMajority)
            .with_min_participants(5);
        let consensus = MajorityConsensus::new(config);

        let votes = vec![
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::For),
        ];

        let result = consensus.run_consensus(&votes, 5);
        assert!(matches!(
            result,
            Err(ConsensusError::InsufficientParticipants(5, 2))
        ));
    }

    #[test]
    fn test_weighted_consensus() {
        let config = ConsensusConfig::new(ConsensusMechanism::WeightedReputation)
            .with_min_participants(2);
        let consensus = WeightedConsensus::new(config);

        // Even though there are 2 against, the for vote has higher weight
        let votes = vec![
            make_weighted_vote(VoteDirection::For, 3.0),
            make_weighted_vote(VoteDirection::Against, 1.0),
            make_weighted_vote(VoteDirection::Against, 1.0),
        ];

        let result = consensus.run_consensus(&votes, 3).unwrap();
        assert!(result.passed); // 3.0 for vs 2.0 against
        assert!((result.votes_for - 3.0).abs() < 0.001);
        assert!((result.votes_against - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_weighted_consensus_with_agent_weights() {
        let config = ConsensusConfig::new(ConsensusMechanism::WeightedReputation)
            .with_min_participants(2);
        
        let agent1 = SwarmAgentId::new();
        let agent2 = SwarmAgentId::new();
        
        let mut weights = HashMap::new();
        weights.insert(
            agent1.clone(),
            AgentWeight::new(agent1.clone())
                .with_reputation(2.0)
                .with_expertise(1.5)
                .with_role(1.0),
        );
        
        let consensus = WeightedConsensus::new(config).with_weights(weights);
        
        // Agent1's weight = (2.0 + 1.5 + 1.0) / 3 = 1.5
        // Agent2's weight = 1.0 (default)
        let votes = vec![
            ConsensusVote::new(agent1, VoteDirection::For),
            ConsensusVote::new(agent2, VoteDirection::Against),
        ];

        let result = consensus.run_consensus(&votes, 2).unwrap();
        assert!(result.passed); // 1.5 for vs 1.0 against
    }

    #[test]
    fn test_bft_consensus_required_nodes() {
        let config = ConsensusConfig::default().with_byzantine_tolerance(1);
        let bft = BftConsensus::new(config);

        // For f=1, need n=3f+1=4 nodes
        assert_eq!(bft.required_nodes(), 4);
        // Need 2f+1=3 votes
        assert_eq!(bft.required_votes(), 3);
    }

    #[test]
    fn test_bft_consensus_pass() {
        let config = ConsensusConfig::default().with_byzantine_tolerance(1);
        let bft = BftConsensus::new(config);

        // Need 3 votes for, 4 eligible voters
        let votes = vec![
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::Against),
        ];

        let result = bft.run_consensus(&votes, 4).unwrap();
        assert!(result.passed); // 3 for, 1 against = 75% > 66.7%
    }

    #[test]
    fn test_bft_consensus_insufficient_nodes() {
        let config = ConsensusConfig::default().with_byzantine_tolerance(1);
        let bft = BftConsensus::new(config);

        let votes = vec![
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::For),
        ];

        // Only 2 eligible voters, need 4
        let result = bft.run_consensus(&votes, 2);
        assert!(matches!(result, Err(ConsensusError::InsufficientParticipants(_, _))));
    }

    #[test]
    fn test_bft_consensus_detects_duplicate_votes() {
        let config = ConsensusConfig::default().with_byzantine_tolerance(1);
        let bft = BftConsensus::new(config);

        let agent = SwarmAgentId::new();
        
        // Same agent votes twice with different directions (Byzantine behavior)
        let votes = vec![
            ConsensusVote::new(agent.clone(), VoteDirection::For),
            ConsensusVote::new(agent.clone(), VoteDirection::Against),
            make_vote(VoteDirection::For),
            make_vote(VoteDirection::For),
        ];

        let result = bft.run_consensus(&votes, 4).unwrap();
        assert!(!result.faults.is_empty()); // Should detect the fault
    }

    #[test]
    fn test_consensus_result_calculations() {
        let result = ConsensusResult {
            reached: true,
            passed: true,
            votes_for: 3.0,
            votes_against: 1.0,
            abstentions: 1,
            participants: 5,
            rounds: 1,
            time_ms: 100,
            votes: Vec::new(),
            faults: Vec::new(),
        };

        assert!((result.pass_percentage() - 0.75).abs() < 0.001);
        assert!((result.participation_rate(10) - 0.5).abs() < 0.001);
        assert!((result.margin() - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_agent_weight() {
        let agent_id = SwarmAgentId::new();
        let weight = AgentWeight::new(agent_id)
            .with_reputation(2.0)
            .with_expertise(3.0)
            .with_role(1.0);

        // (2.0 + 3.0 + 1.0) / 3 = 2.0
        assert!((weight.total_weight() - 2.0).abs() < 0.001);
    }

    #[test]
    fn test_has_quorum() {
        let config = ConsensusConfig::new(ConsensusMechanism::SimpleMajority)
            .with_min_participants(3)
            .with_pass_threshold(0.5);
        let consensus = MajorityConsensus::new(config);

        assert!(consensus.has_quorum(5, 10)); // 5/10 >= 50%
        assert!(consensus.has_quorum(3, 5));  // 3/5 >= 50%
        assert!(!consensus.has_quorum(2, 10)); // 2/10 < 50%
    }
}
