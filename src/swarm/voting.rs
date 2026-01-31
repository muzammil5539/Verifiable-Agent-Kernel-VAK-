//! Quadratic Voting Implementation (SWM-002)
//!
//! This module implements Quadratic Voting for multi-agent consensus.
//! Quadratic voting prevents sycophancy by making strong votes exponentially
//! more expensive, forcing agents to express high confidence only when justified.
//!
//! # Overview
//!
//! In Quadratic Voting:
//! - Each agent has a budget of "voice credits"
//! - Casting N votes on an option costs N² credits
//! - This naturally limits strong opinions and encourages nuanced positions
//!
//! # Example
//!
//! ```rust
//! use vak::swarm::voting::{QuadraticVoting, Vote, VotingConfig};
//!
//! // Create a voting system with 100 credits per agent
//! let voting = QuadraticVoting::new(100);
//!
//! // A vote with strength 3 costs 9 credits (3²)
//! let cost = voting.calculate_cost(3);
//! assert_eq!(cost, 9);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use super::SwarmAgentId;
use super::messages::Proposal;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during voting operations
#[derive(Debug, Error)]
pub enum VotingError {
    /// Insufficient credits to cast vote
    #[error("Insufficient credits: have {0}, need {1}")]
    InsufficientCredits(u64, u64),

    /// Vote strength exceeds maximum
    #[error("Vote strength {0} exceeds maximum {1}")]
    StrengthExceedsMax(u64, u64),

    /// Agent already voted
    #[error("Agent {0} has already voted")]
    AlreadyVoted(String),

    /// Voting session is closed
    #[error("Voting session is closed")]
    SessionClosed,

    /// Voting session not found
    #[error("Voting session not found: {0}")]
    SessionNotFound(String),

    /// Invalid vote direction
    #[error("Invalid vote direction")]
    InvalidDirection,

    /// Minimum participation not met
    #[error("Minimum participation not met: {0:.1}% < {1:.1}%")]
    InsufficientParticipation(f64, f64),
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

impl Default for VoteDirection {
    fn default() -> Self {
        VoteDirection::Abstain
    }
}

/// A vote cast by an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Direction of the vote
    pub direction: VoteDirection,
    /// Strength of the vote (1-10 typically)
    pub strength: u64,
    /// Optional reasoning for the vote
    pub reasoning: Option<String>,
    /// Timestamp when vote was cast
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl Vote {
    /// Create a new vote
    pub fn new(direction: VoteDirection, strength: u64) -> Self {
        Self {
            direction,
            strength,
            reasoning: None,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Create a vote in favor
    pub fn for_proposal(strength: u64) -> Self {
        Self::new(VoteDirection::For, strength)
    }

    /// Create a vote against
    pub fn against_proposal(strength: u64) -> Self {
        Self::new(VoteDirection::Against, strength)
    }

    /// Create an abstention
    pub fn abstain() -> Self {
        Self::new(VoteDirection::Abstain, 0)
    }

    /// Add reasoning to the vote
    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }

    /// Get the effective votes (strength as votes)
    pub fn effective_votes(&self) -> i64 {
        match self.direction {
            VoteDirection::For => self.strength as i64,
            VoteDirection::Against => -(self.strength as i64),
            VoteDirection::Abstain => 0,
        }
    }
}

// ============================================================================
// Vote Result
// ============================================================================

/// Result of a single vote cast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResult {
    /// Agent who cast the vote
    pub agent_id: SwarmAgentId,
    /// The vote that was cast
    pub vote: Vote,
    /// Credits consumed
    pub credits_consumed: u64,
    /// Remaining credits
    pub credits_remaining: u64,
}

// ============================================================================
// Agent Credits
// ============================================================================

/// Tracks an agent's voting credits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCredits {
    /// Total credits allocated
    pub total: u64,
    /// Credits remaining
    pub remaining: u64,
    /// Credits spent
    pub spent: u64,
}

impl AgentCredits {
    /// Create new agent credits
    pub fn new(total: u64) -> Self {
        Self {
            total,
            remaining: total,
            spent: 0,
        }
    }

    /// Attempt to spend credits
    pub fn spend(&mut self, amount: u64) -> Result<(), VotingError> {
        if self.remaining < amount {
            return Err(VotingError::InsufficientCredits(self.remaining, amount));
        }
        self.remaining -= amount;
        self.spent += amount;
        Ok(())
    }

    /// Refund credits (e.g., if vote is cancelled)
    pub fn refund(&mut self, amount: u64) {
        let refund = amount.min(self.spent);
        self.remaining += refund;
        self.spent -= refund;
    }

    /// Reset credits to initial allocation
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
    /// Credits allocated to each agent
    pub credits_per_agent: u64,
    /// Maximum vote strength allowed
    pub max_strength: u64,
    /// Minimum participation rate (0.0 to 1.0)
    pub min_participation: f64,
    /// Whether to use quadratic voting
    pub quadratic: bool,
    /// Timeout in seconds
    pub timeout_seconds: u64,
    /// Whether abstentions count toward participation
    pub abstentions_count: bool,
}

impl Default for VotingConfig {
    fn default() -> Self {
        Self {
            credits_per_agent: 100,
            max_strength: 10,
            min_participation: 0.5,
            quadratic: true,
            timeout_seconds: 300, // 5 minutes
            abstentions_count: false,
        }
    }
}

impl VotingConfig {
    /// Create a new voting configuration
    pub fn new(credits_per_agent: u64) -> Self {
        Self {
            credits_per_agent,
            ..Default::default()
        }
    }

    /// Set the maximum vote strength
    pub fn with_max_strength(mut self, max: u64) -> Self {
        self.max_strength = max;
        self
    }

    /// Set the minimum participation rate
    pub fn with_min_participation(mut self, rate: f64) -> Self {
        self.min_participation = rate.clamp(0.0, 1.0);
        self
    }

    /// Enable or disable quadratic voting
    pub fn with_quadratic(mut self, enabled: bool) -> Self {
        self.quadratic = enabled;
        self
    }

    /// Set the timeout
    pub fn with_timeout(mut self, seconds: u64) -> Self {
        self.timeout_seconds = seconds;
        self
    }
}

// ============================================================================
// Voting Outcome
// ============================================================================

/// Outcome of a completed voting session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingOutcome {
    /// Session ID
    pub session_id: String,
    /// Whether the proposal passed
    pub passed: bool,
    /// Total votes for
    pub votes_for: i64,
    /// Total votes against
    pub votes_against: i64,
    /// Number of abstentions
    pub abstentions: usize,
    /// Total participants
    pub participants: usize,
    /// Participation rate
    pub participation_rate: f64,
    /// Individual vote details
    pub votes: HashMap<SwarmAgentId, Vote>,
    /// Timestamp when voting concluded
    pub concluded_at: chrono::DateTime<chrono::Utc>,
}

impl VotingOutcome {
    /// Get the margin of victory/defeat
    pub fn margin(&self) -> i64 {
        self.votes_for - self.votes_against
    }

    /// Get the percentage for
    pub fn percentage_for(&self) -> f64 {
        let total = self.votes_for.abs() + self.votes_against.abs();
        if total == 0 {
            0.5
        } else {
            self.votes_for.abs() as f64 / total as f64
        }
    }
}

// ============================================================================
// Voting Session
// ============================================================================

/// State of a voting session
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionState {
    /// Session is open for voting
    Open,
    /// Session is closed, awaiting finalization
    Closed,
    /// Session has been finalized
    Finalized,
    /// Session was cancelled
    Cancelled,
}

/// A voting session for a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VotingSession {
    /// Unique session ID
    pub id: String,
    /// The proposal being voted on
    pub proposal: Proposal,
    /// Configuration for this session
    pub config: VotingConfig,
    /// Current state
    pub state: SessionState,
    /// Recorded votes
    pub votes: HashMap<SwarmAgentId, Vote>,
    /// Agent credits
    pub agent_credits: HashMap<SwarmAgentId, AgentCredits>,
    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the session was closed
    pub closed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Expected number of eligible voters
    pub eligible_voters: usize,
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
            agent_credits: HashMap::new(),
            created_at: chrono::Utc::now(),
            closed_at: None,
            eligible_voters: 0,
        }
    }

    /// Set the number of eligible voters
    pub fn with_eligible_voters(mut self, count: usize) -> Self {
        self.eligible_voters = count;
        self
    }

    /// Check if the session is open
    pub fn is_open(&self) -> bool {
        self.state == SessionState::Open
    }

    /// Record a vote from an agent
    pub fn record_vote(&mut self, agent_id: SwarmAgentId, vote: Vote) -> Result<VoteResult, VotingError> {
        if !self.is_open() {
            return Err(VotingError::SessionClosed);
        }

        if self.votes.contains_key(&agent_id) {
            return Err(VotingError::AlreadyVoted(agent_id.to_string()));
        }

        if vote.strength > self.config.max_strength {
            return Err(VotingError::StrengthExceedsMax(vote.strength, self.config.max_strength));
        }

        // Calculate cost
        let cost = if self.config.quadratic {
            vote.strength * vote.strength
        } else {
            vote.strength
        };

        // Get or create agent credits
        let credits = self.agent_credits
            .entry(agent_id.clone())
            .or_insert_with(|| AgentCredits::new(self.config.credits_per_agent));

        // Spend credits
        credits.spend(cost)?;
        let remaining = credits.remaining;

        // Record the vote
        self.votes.insert(agent_id.clone(), vote.clone());

        Ok(VoteResult {
            agent_id,
            vote,
            credits_consumed: cost,
            credits_remaining: remaining,
        })
    }

    /// Close the voting session
    pub fn close(&mut self) {
        if self.state == SessionState::Open {
            self.state = SessionState::Closed;
            self.closed_at = Some(chrono::Utc::now());
        }
    }

    /// Finalize the voting session and compute outcome
    pub fn finalize(&mut self) -> Result<VotingOutcome, VotingError> {
        // Close if still open
        if self.state == SessionState::Open {
            self.close();
        }

        if self.state == SessionState::Finalized {
            // Return cached result if already finalized
            return Ok(self.compute_outcome());
        }

        // Check participation
        let participation_rate = if self.eligible_voters > 0 {
            self.votes.len() as f64 / self.eligible_voters as f64
        } else {
            1.0 // If no eligible voters specified, assume 100% participation
        };

        if participation_rate < self.config.min_participation {
            return Err(VotingError::InsufficientParticipation(
                participation_rate * 100.0,
                self.config.min_participation * 100.0,
            ));
        }

        self.state = SessionState::Finalized;
        Ok(self.compute_outcome())
    }

    /// Compute the voting outcome
    fn compute_outcome(&self) -> VotingOutcome {
        let mut votes_for: i64 = 0;
        let mut votes_against: i64 = 0;
        let mut abstentions = 0;

        for vote in self.votes.values() {
            match vote.direction {
                VoteDirection::For => votes_for += vote.strength as i64,
                VoteDirection::Against => votes_against += vote.strength as i64,
                VoteDirection::Abstain => abstentions += 1,
            }
        }

        let participants = if self.config.abstentions_count {
            self.votes.len()
        } else {
            self.votes.len() - abstentions
        };

        let participation_rate = if self.eligible_voters > 0 {
            participants as f64 / self.eligible_voters as f64
        } else {
            1.0
        };

        VotingOutcome {
            session_id: self.id.clone(),
            passed: votes_for > votes_against,
            votes_for,
            votes_against,
            abstentions,
            participants,
            participation_rate,
            votes: self.votes.clone(),
            concluded_at: self.closed_at.unwrap_or_else(chrono::Utc::now),
        }
    }

    /// Cancel the voting session
    pub fn cancel(&mut self) {
        self.state = SessionState::Cancelled;
        self.closed_at = Some(chrono::Utc::now());
    }

    /// Get the current vote tally
    pub fn current_tally(&self) -> (i64, i64) {
        let mut votes_for: i64 = 0;
        let mut votes_against: i64 = 0;

        for vote in self.votes.values() {
            match vote.direction {
                VoteDirection::For => votes_for += vote.strength as i64,
                VoteDirection::Against => votes_against += vote.strength as i64,
                VoteDirection::Abstain => {}
            }
        }

        (votes_for, votes_against)
    }
}

// ============================================================================
// Quadratic Voting Calculator
// ============================================================================

/// Quadratic voting calculator
#[derive(Debug, Clone)]
pub struct QuadraticVoting {
    /// Credits per agent
    pub credits_per_agent: u64,
}

impl QuadraticVoting {
    /// Create a new quadratic voting calculator
    pub fn new(credits_per_agent: u64) -> Self {
        Self { credits_per_agent }
    }

    /// Calculate the cost of a vote with given strength
    pub fn calculate_cost(&self, strength: u64) -> u64 {
        strength * strength
    }

    /// Calculate the maximum strength affordable with given credits
    pub fn max_affordable_strength(&self, credits: u64) -> u64 {
        (credits as f64).sqrt().floor() as u64
    }

    /// Calculate how many votes of each strength are affordable
    pub fn affordable_distribution(&self, credits: u64) -> HashMap<u64, u64> {
        let mut distribution = HashMap::new();
        
        for strength in 1..=self.max_affordable_strength(credits) {
            let cost = self.calculate_cost(strength);
            let affordable = credits / cost;
            if affordable > 0 {
                distribution.insert(strength, affordable);
            }
        }
        
        distribution
    }

    /// Validate a set of votes against available credits
    pub fn validate_votes(&self, votes: &[(u64, u64)], available_credits: u64) -> bool {
        let total_cost: u64 = votes.iter()
            .map(|(strength, count)| self.calculate_cost(*strength) * count)
            .sum();
        
        total_cost <= available_credits
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
        assert!(matches!(result, Err(VotingError::InsufficientCredits(75, 100))));

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
        assert_eq!(qv.max_affordable_strength(50), 7); // sqrt(50) ≈ 7.07
        assert_eq!(qv.max_affordable_strength(1), 1);
        assert_eq!(qv.max_affordable_strength(0), 0);
    }

    #[test]
    fn test_validate_votes() {
        let qv = QuadraticVoting::new(100);

        // Single vote of strength 10 costs 100
        assert!(qv.validate_votes(&[(10, 1)], 100));
        assert!(!qv.validate_votes(&[(10, 1)], 99));

        // Multiple votes
        assert!(qv.validate_votes(&[(2, 5), (3, 2)], 100)); // 4*5 + 9*2 = 38
        assert!(!qv.validate_votes(&[(5, 3), (4, 2)], 100)); // 25*3 + 16*2 = 107
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
        
        assert_eq!(result.credits_consumed, 25); // 5² = 25
        assert_eq!(result.credits_remaining, 75); // 100 - 25

        // Try to vote again
        let result = session.record_vote(agent_id, Vote::against_proposal(3));
        assert!(matches!(result, Err(VotingError::AlreadyVoted(_))));
    }

    #[test]
    fn test_voting_session_strength_limit() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::new(100).with_max_strength(5);
        let mut session = VotingSession::new("session1".to_string(), proposal, config);

        let agent_id = SwarmAgentId::new();
        let vote = Vote::for_proposal(10); // Exceeds max of 5
        
        let result = session.record_vote(agent_id, vote);
        assert!(matches!(result, Err(VotingError::StrengthExceedsMax(10, 5))));
    }

    #[test]
    fn test_voting_session_finalize() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::default();
        let mut session = VotingSession::new("session1".to_string(), proposal, config);

        // Cast some votes
        let agent1 = SwarmAgentId::new();
        let agent2 = SwarmAgentId::new();
        let agent3 = SwarmAgentId::new();

        session.record_vote(agent1, Vote::for_proposal(5)).unwrap();
        session.record_vote(agent2, Vote::for_proposal(3)).unwrap();
        session.record_vote(agent3, Vote::against_proposal(4)).unwrap();

        let outcome = session.finalize().unwrap();

        assert!(outcome.passed); // 5 + 3 = 8 > 4
        assert_eq!(outcome.votes_for, 8);
        assert_eq!(outcome.votes_against, 4);
        assert_eq!(outcome.participants, 3);
    }

    #[test]
    fn test_voting_session_minimum_participation() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::default().with_min_participation(0.5);
        let mut session = VotingSession::new("session1".to_string(), proposal, config)
            .with_eligible_voters(10);

        // Only 4 out of 10 vote (40% < 50%)
        for i in 0..4 {
            session.record_vote(SwarmAgentId::new(), Vote::for_proposal(1)).unwrap();
        }

        let result = session.finalize();
        assert!(matches!(result, Err(VotingError::InsufficientParticipation(_, _))));
    }

    #[test]
    fn test_current_tally() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::default();
        let mut session = VotingSession::new("session1".to_string(), proposal, config);

        session.record_vote(SwarmAgentId::new(), Vote::for_proposal(5)).unwrap();
        session.record_vote(SwarmAgentId::new(), Vote::against_proposal(3)).unwrap();

        let (votes_for, votes_against) = session.current_tally();
        assert_eq!(votes_for, 5);
        assert_eq!(votes_against, 3);
    }

    #[test]
    fn test_voting_outcome_margin() {
        let outcome = VotingOutcome {
            session_id: "test".to_string(),
            passed: true,
            votes_for: 10,
            votes_against: 4,
            abstentions: 0,
            participants: 3,
            participation_rate: 1.0,
            votes: HashMap::new(),
            concluded_at: chrono::Utc::now(),
        };

        assert_eq!(outcome.margin(), 6);
        assert!((outcome.percentage_for() - 0.714).abs() < 0.01);
    }

    #[test]
    fn test_linear_voting() {
        let proposal = Proposal::new("Test Proposal");
        let config = VotingConfig::new(100).with_quadratic(false);
        let mut session = VotingSession::new("session1".to_string(), proposal, config);

        let agent_id = SwarmAgentId::new();
        let vote = Vote::for_proposal(5);
        
        let result = session.record_vote(agent_id, vote).unwrap();
        
        // Linear cost: strength = cost
        assert_eq!(result.credits_consumed, 5);
        assert_eq!(result.credits_remaining, 95);
    }
}
