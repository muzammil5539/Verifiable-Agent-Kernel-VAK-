//! Quadratic Voting System for Multi-Agent Consensus
//!
//! This module implements a quadratic voting mechanism that allows agents
//! to express preference intensity while preventing vote manipulation.
//!
//! # Overview
//!
//! Quadratic voting costs votes quadratically (1 vote = 1 credit, 2 votes = 4 credits),
//! which encourages thoughtful allocation of voting power and prevents wealthy
//! agents from dominating decisions.
//!
//! # Example
//!
//! ```rust,ignore
//! use vak::swarm::voting::{QuadraticVoting, Vote, VotingSession, VotingConfig, Proposal};
//! use vak::swarm::SwarmAgentId;
//!
//! let qv = QuadraticVoting::new(100);
//! assert_eq!(qv.calculate_cost(5), 25); // 5² = 25 credits
//!
//! let proposal = Proposal::new("Adopt new policy");
//! let config = VotingConfig::default();
//! let mut session = VotingSession::new("session-1".to_string(), proposal, config);
//!
//! let agent = SwarmAgentId::new();
//! session.record_vote(agent, Vote::for_proposal(3)).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

use super::SwarmAgentId;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during voting operations
#[derive(Debug, Error, Clone)]
pub enum VotingError {
    /// Agent has already voted in this session
    #[error("Agent {0} has already voted")]
    AlreadyVoted(String),

    /// Insufficient credits for the vote strength
    #[error("Insufficient credits: have {0}, need {1}")]
    InsufficientCredits(u64, u64),

    /// Vote strength exceeds maximum allowed
    #[error("Vote strength {0} exceeds maximum {1}")]
    StrengthExceedsMax(u64, u64),

    /// Voting session is closed
    #[error("Voting session is closed")]
    SessionClosed,

    /// Minimum participation not met
    #[error("Minimum participation not met: {0}% required, {1}% achieved")]
    MinParticipationNotMet(f64, f64),

    /// Invalid vote direction
    #[error("Invalid vote direction")]
    InvalidDirection,
}

// ============================================================================
// Vote Types
// ============================================================================

/// Direction of a vote
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteDirection {
    /// Vote in favor
    For,
    /// Vote against
    Against,
    /// Abstain from voting
    Abstain,
}

/// A single vote cast by an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Direction of the vote (for/against/abstain)
    pub direction: VoteDirection,
    /// Strength of the vote (1-10 typically)
    pub strength: u64,
    /// Optional reasoning for the vote
    pub reasoning: Option<String>,
    /// Timestamp when vote was cast
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Vote {
    /// Create a vote in favor with given strength
    pub fn for_proposal(strength: u64) -> Self {
        Self {
            direction: VoteDirection::For,
            strength,
            reasoning: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a vote against with given strength
    pub fn against_proposal(strength: u64) -> Self {
        Self {
            direction: VoteDirection::Against,
            strength,
            reasoning: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create an abstain vote
    pub fn abstain() -> Self {
        Self {
            direction: VoteDirection::Abstain,
            strength: 0,
            reasoning: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Add reasoning to the vote
    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }

    /// Calculate effective votes (positive for For, negative for Against)
    pub fn effective_votes(&self) -> i64 {
        match self.direction {
            VoteDirection::For => self.strength as i64,
            VoteDirection::Against => -(self.strength as i64),
            VoteDirection::Abstain => 0,
        }
    }
}

// ============================================================================
// Agent Credits
// ============================================================================

/// Voting credits available to an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredits {
    /// Total credits allocated
    pub total: u64,
    /// Remaining credits available
    pub remaining: u64,
    /// Credits spent so far
    pub spent: u64,
}

impl AgentCredits {
    /// Create new credits allocation
    pub fn new(total: u64) -> Self {
        Self {
            total,
            remaining: total,
            spent: 0,
        }
    }

    /// Spend credits, returns error if insufficient
    pub fn spend(&mut self, amount: u64) -> Result<(), VotingError> {
        if self.remaining < amount {
            return Err(VotingError::InsufficientCredits(self.remaining, amount));
        }
        self.remaining -= amount;
        self.spent += amount;
        Ok(())
    }

    /// Refund credits
    pub fn refund(&mut self, amount: u64) {
        let refund = amount.min(self.spent);
        self.remaining += refund;
        self.spent -= refund;
    }

    /// Reset credits to initial state
    pub fn reset(&mut self) {
        self.remaining = self.total;
        self.spent = 0;
    }
}

// ============================================================================
// Voting Configuration
// ============================================================================

/// Configuration for a voting session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingConfig {
    /// Credits allocated per agent
    pub credits_per_agent: u64,
    /// Maximum vote strength allowed
    pub max_strength: u64,
    /// Minimum participation rate (0.0-1.0)
    pub min_participation: f64,
    /// Whether to use quadratic voting
    pub quadratic: bool,
    /// Timeout for the voting session in seconds
    pub timeout_secs: u64,
}

impl Default for VotingConfig {
    fn default() -> Self {
        Self {
            credits_per_agent: 100,
            max_strength: 10,
            min_participation: 0.5,
            quadratic: true,
            timeout_secs: 3600,
        }
    }
}

impl VotingConfig {
    /// Create a new configuration with specified credits
    pub fn new(credits_per_agent: u64) -> Self {
        Self {
            credits_per_agent,
            ..Default::default()
        }
    }

    /// Set maximum vote strength
    pub fn with_max_strength(mut self, max: u64) -> Self {
        self.max_strength = max;
        self
    }

    /// Set minimum participation rate
    pub fn with_min_participation(mut self, rate: f64) -> Self {
        self.min_participation = rate.clamp(0.0, 1.0);
        self
    }

    /// Enable or disable quadratic voting
    pub fn with_quadratic(mut self, enabled: bool) -> Self {
        self.quadratic = enabled;
        self
    }
}

// ============================================================================
// Quadratic Voting
// ============================================================================

/// Quadratic voting calculator
#[derive(Debug, Clone)]
pub struct QuadraticVoting {
    /// Maximum credits available
    pub max_credits: u64,
}

impl QuadraticVoting {
    /// Create a new quadratic voting calculator
    pub fn new(max_credits: u64) -> Self {
        Self { max_credits }
    }

    /// Calculate the cost for a given vote strength
    pub fn calculate_cost(&self, strength: u64) -> u64 {
        strength * strength
    }

    /// Calculate maximum affordable strength given available credits
    pub fn max_affordable_strength(&self, available_credits: u64) -> u64 {
        (available_credits as f64).sqrt().floor() as u64
    }

    /// Validate a set of votes against available credits
    pub fn validate_votes(&self, votes: &[(u64, u64)], available_credits: u64) -> bool {
        let total_cost: u64 = votes
            .iter()
            .map(|(strength, count)| self.calculate_cost(*strength) * count)
            .sum();
        total_cost <= available_credits
    }
}

// ============================================================================
// Proposal
// ============================================================================

/// A proposal to be voted on
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique identifier
    pub id: String,
    /// Title of the proposal
    pub title: String,
    /// Detailed description
    pub description: Option<String>,
    /// Who proposed it
    pub proposer: Option<String>,
    /// When it was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Proposal {
    /// Create a new proposal
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            title: title.into(),
            description: None,
            proposer: None,
            created_at: chrono::Utc::now(),
        }
    }

    /// Add a description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the proposer
    pub fn with_proposer(mut self, proposer: impl Into<String>) -> Self {
        self.proposer = Some(proposer.into());
        self
    }
}

// ============================================================================
// Vote Receipt
// ============================================================================

/// Receipt returned after recording a vote
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteReceipt {
    /// Session ID
    pub session_id: String,
    /// Agent who voted
    pub agent_id: SwarmAgentId,
    /// Credits consumed
    pub credits_consumed: u64,
    /// Credits remaining
    pub credits_remaining: u64,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Voting Outcome
// ============================================================================

/// Outcome of a finalized voting session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingOutcome {
    /// Whether the proposal passed
    pub passed: bool,
    /// Total votes in favor
    pub votes_for: i64,
    /// Total votes against
    pub votes_against: i64,
    /// Number of participants
    pub participants: usize,
    /// Participation rate
    pub participation_rate: f64,
    /// When voting was finalized
    pub finalized_at: chrono::DateTime<chrono::Utc>,
}

// ============================================================================
// Voting Session
// ============================================================================

/// Session state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session is open for voting
    Open,
    /// Session is closed
    Closed,
    /// Session has been finalized
    Finalized,
}

/// A voting session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingSession {
    /// Session identifier
    pub id: String,
    /// The proposal being voted on
    pub proposal: Proposal,
    /// Configuration
    pub config: VotingConfig,
    /// Current state
    pub state: SessionState,
    /// Recorded votes
    pub votes: HashMap<SwarmAgentId, Vote>,
    /// Agent credits
    pub credits: HashMap<SwarmAgentId, AgentCredits>,
    /// Expected number of voters (for participation calculation)
    pub expected_voters: usize,
    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl VotingSession {
    /// Create a new voting session
    pub fn new(id: String, proposal: Proposal, config: VotingConfig) -> Self {
        Self {
            id,
            proposal,
            config,
            state: SessionState::Open,
            votes: HashMap::new(),
            credits: HashMap::new(),
            expected_voters: 0,
            created_at: chrono::Utc::now(),
        }
    }

    /// Check if the session is open for voting
    pub fn is_open(&self) -> bool {
        self.state == SessionState::Open
    }

    /// Record a vote from an agent
    pub fn record_vote(
        &mut self,
        agent_id: SwarmAgentId,
        vote: Vote,
    ) -> Result<VoteReceipt, VotingError> {
        // Check session is open
        if !self.is_open() {
            return Err(VotingError::SessionClosed);
        }

        // Check not already voted
        if self.votes.contains_key(&agent_id) {
            return Err(VotingError::AlreadyVoted(agent_id.to_string()));
        }

        // Check strength limit
        if vote.strength > self.config.max_strength {
            return Err(VotingError::StrengthExceedsMax(
                vote.strength,
                self.config.max_strength,
            ));
        }

        // Calculate cost
        let cost = if self.config.quadratic {
            vote.strength * vote.strength
        } else {
            vote.strength
        };

        // Get or create credits
        let credits = self
            .credits
            .entry(agent_id.clone())
            .or_insert_with(|| AgentCredits::new(self.config.credits_per_agent));

        // Spend credits
        credits.spend(cost)?;

        let remaining = credits.remaining;

        // Record vote
        self.votes.insert(agent_id.clone(), vote);

        Ok(VoteReceipt {
            session_id: self.id.clone(),
            agent_id,
            credits_consumed: cost,
            credits_remaining: remaining,
            timestamp: chrono::Utc::now(),
        })
    }

    /// Finalize the voting session
    pub fn finalize(&mut self) -> Result<VotingOutcome, VotingError> {
        // Close the session
        self.state = SessionState::Finalized;

        // Calculate results
        let mut votes_for: i64 = 0;
        let mut votes_against: i64 = 0;

        for vote in self.votes.values() {
            match vote.direction {
                VoteDirection::For => votes_for += vote.strength as i64,
                VoteDirection::Against => votes_against += vote.strength as i64,
                VoteDirection::Abstain => {}
            }
        }

        let participants = self.votes.len();
        let participation_rate = if self.expected_voters > 0 {
            participants as f64 / self.expected_voters as f64
        } else {
            1.0
        };

        // Check minimum participation
        if participation_rate < self.config.min_participation {
            return Err(VotingError::MinParticipationNotMet(
                self.config.min_participation * 100.0,
                participation_rate * 100.0,
            ));
        }

        Ok(VotingOutcome {
            passed: votes_for > votes_against,
            votes_for,
            votes_against,
            participants,
            participation_rate,
            finalized_at: chrono::Utc::now(),
        })
    }

    /// Set expected number of voters
    pub fn with_expected_voters(mut self, count: usize) -> Self {
        self.expected_voters = count;
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vote_creation() {
        let vote = Vote::for_proposal(5).with_reasoning("Strong support");

        assert_eq!(vote.direction, VoteDirection::For);
        assert_eq!(vote.strength, 5);
        assert!(vote.reasoning.is_some());
    }

    #[test]
    fn test_vote_effective_votes() {
        let for_vote = Vote::for_proposal(3);
        assert_eq!(for_vote.effective_votes(), 3);

        let against_vote = Vote::against_proposal(2);
        assert_eq!(against_vote.effective_votes(), -2);

        let abstain = Vote::abstain();
        assert_eq!(abstain.effective_votes(), 0);
    }

    #[test]
    fn test_agent_credits() {
        let mut credits = AgentCredits::new(100);

        assert_eq!(credits.total, 100);
        assert_eq!(credits.remaining, 100);
        assert_eq!(credits.spent, 0);

        credits.spend(25).unwrap();
        assert_eq!(credits.remaining, 75);
        assert_eq!(credits.spent, 25);

        let result = credits.spend(100);
        assert!(matches!(
            result,
            Err(VotingError::InsufficientCredits(75, 100))
        ));

        credits.refund(10);
        assert_eq!(credits.remaining, 85);
        assert_eq!(credits.spent, 15);

        credits.reset();
        assert_eq!(credits.remaining, 100);
        assert_eq!(credits.spent, 0);
    }

    #[test]
    fn test_voting_config() {
        let config = VotingConfig::new(200)
            .with_max_strength(5)
            .with_min_participation(0.75)
            .with_quadratic(true);

        assert_eq!(config.credits_per_agent, 200);
        assert_eq!(config.max_strength, 5);
        assert!((config.min_participation - 0.75).abs() < 0.001);
        assert!(config.quadratic);
    }

    #[test]
    fn test_quadratic_cost() {
        let qv = QuadraticVoting::new(100);

        assert_eq!(qv.calculate_cost(1), 1);
        assert_eq!(qv.calculate_cost(2), 4);
        assert_eq!(qv.calculate_cost(3), 9);
        assert_eq!(qv.calculate_cost(10), 100);
    }

    #[test]
    fn test_max_affordable_strength() {
        let qv = QuadraticVoting::new(100);

        assert_eq!(qv.max_affordable_strength(100), 10);
        assert_eq!(qv.max_affordable_strength(81), 9);
        assert_eq!(qv.max_affordable_strength(50), 7);
        assert_eq!(qv.max_affordable_strength(1), 1);
        assert_eq!(qv.max_affordable_strength(0), 0);
    }

    #[test]
    fn test_validate_votes() {
        let qv = QuadraticVoting::new(100);

        assert!(qv.validate_votes(&[(10, 1)], 100));
        assert!(!qv.validate_votes(&[(10, 1)], 99));
        assert!(qv.validate_votes(&[(2, 5), (3, 2)], 100));
        assert!(!qv.validate_votes(&[(5, 3), (4, 2)], 100));
    }

    #[test]
    fn test_voting_session_creation() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::default();
        let session = VotingSession::new("session1".to_string(), proposal, config);

        assert!(session.is_open());
        assert!(session.votes.is_empty());
    }

    #[test]
    fn test_voting_session_record_vote() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::default();
        let mut session = VotingSession::new("session1".to_string(), proposal, config);

        let agent_id = SwarmAgentId::new();
        let vote = Vote::for_proposal(5);

        let result = session.record_vote(agent_id.clone(), vote).unwrap();

        assert_eq!(result.credits_consumed, 25);
        assert_eq!(result.credits_remaining, 75);

        let result = session.record_vote(agent_id, Vote::against_proposal(3));
        assert!(matches!(result, Err(VotingError::AlreadyVoted(_))));
    }

    #[test]
    fn test_voting_session_strength_limit() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::new(100).with_max_strength(5);
        let mut session = VotingSession::new("session1".to_string(), proposal, config);

        let agent_id = SwarmAgentId::new();
        let vote = Vote::for_proposal(10);

        let result = session.record_vote(agent_id, vote);
        assert!(matches!(
            result,
            Err(VotingError::StrengthExceedsMax(10, 5))
        ));
    }

    #[test]
    fn test_voting_session_finalize() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::default();
        let mut session = VotingSession::new("session1".to_string(), proposal, config);

        let agent1 = SwarmAgentId::new();
        let agent2 = SwarmAgentId::new();
        let agent3 = SwarmAgentId::new();

        session.record_vote(agent1, Vote::for_proposal(5)).unwrap();
        session.record_vote(agent2, Vote::for_proposal(3)).unwrap();
        session
            .record_vote(agent3, Vote::against_proposal(4))
            .unwrap();

        let outcome = session.finalize().unwrap();

        assert!(outcome.passed);
        assert_eq!(outcome.votes_for, 8);
        assert_eq!(outcome.votes_against, 4);
        assert_eq!(outcome.participants, 3);
    }

    #[test]
    fn test_voting_session_minimum_participation() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::default().with_min_participation(0.5);
        let mut session =
            VotingSession::new("session1".to_string(), proposal, config).with_expected_voters(10);

        let agent1 = SwarmAgentId::new();
        session.record_vote(agent1, Vote::for_proposal(5)).unwrap();

        // Only 1 out of 10 expected voters - should fail
        let result = session.finalize();
        assert!(matches!(
            result,
            Err(VotingError::MinParticipationNotMet(_, _))
        ));
    }
}
