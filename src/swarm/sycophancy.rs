//! Sycophancy Detection Metrics (SWM-003)
//!
//! Provides metrics and analysis for detecting consensus collapse and sycophancy
//! patterns in multi-agent systems. Monitors vote diversity, disagreement rates,
//! and opinion clustering to alert on potential groupthink.
//!
//! # Overview
//!
//! Sycophancy occurs when agents:
//! - Agree with each other regardless of evidence
//! - Follow dominant opinions rather than objective analysis
//! - Collapse into unanimous decisions too quickly
//!
//! This module provides:
//! - Vote diversity metrics (Shannon entropy)
//! - Disagreement rate tracking
//! - Opinion clustering detection
//! - Temporal pattern analysis
//! - Alerts for suspicious consensus patterns
//!
//! # Example
//!
//! ```rust
//! use vak::swarm::sycophancy::{SycophancyDetector, DetectorConfig, VoteRecord};
//!
//! let detector = SycophancyDetector::new(DetectorConfig::default());
//!
//! // Record votes from agents
//! detector.record_vote("session-1", "agent-1", "option-a", 3);
//! detector.record_vote("session-1", "agent-2", "option-a", 5);
//! detector.record_vote("session-1", "agent-3", "option-b", 2);
//!
//! // Check for sycophancy patterns
//! let analysis = detector.analyze_session("session-1").unwrap();
//! if analysis.sycophancy_risk > 0.7 {
//!     println!("Warning: High sycophancy risk detected!");
//! }
//! ```
//!
//! # References
//!
//! - Blue Ocean Section 1.3: Multi-Agent Coordination Failure
//! - Gap Analysis: Sycophancy and consensus collapse

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during sycophancy detection
#[derive(Debug, Error)]
pub enum SycophancyError {
    /// Session not found
    #[error("Voting session not found: {0}")]
    SessionNotFound(String),

    /// Insufficient data for analysis
    #[error("Insufficient data for analysis: need {needed} votes, have {have}")]
    InsufficientData {
        /// Votes needed
        needed: usize,
        /// Votes available
        have: usize,
    },

    /// Analysis failed
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),
}

/// Result type for sycophancy operations
pub type SycophancyResult<T> = Result<T, SycophancyError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for sycophancy detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Enable sycophancy detection
    pub enabled: bool,
    /// Minimum votes required for analysis
    pub min_votes_for_analysis: usize,
    /// Entropy threshold below which consensus is suspicious (0.0 to 1.0)
    pub low_entropy_threshold: f64,
    /// Unanimous agreement threshold (percentage)
    pub unanimous_threshold_percent: f64,
    /// Time window for rapid consensus detection (seconds)
    pub rapid_consensus_window_secs: u64,
    /// Minimum disagreement rate for healthy debate
    pub min_healthy_disagreement_rate: f64,
    /// Maximum voting sessions to retain
    pub max_sessions: usize,
    /// Alert on high sycophancy risk
    pub alert_enabled: bool,
    /// Risk threshold for alerts (0.0 to 1.0)
    pub alert_risk_threshold: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_votes_for_analysis: 3,
            low_entropy_threshold: 0.3,
            unanimous_threshold_percent: 95.0,
            rapid_consensus_window_secs: 30,
            min_healthy_disagreement_rate: 0.1,
            max_sessions: 1000,
            alert_enabled: true,
            alert_risk_threshold: 0.7,
        }
    }
}

impl DetectorConfig {
    /// Create a strict configuration for high-stakes decisions
    pub fn strict() -> Self {
        Self {
            enabled: true,
            min_votes_for_analysis: 5,
            low_entropy_threshold: 0.4,
            unanimous_threshold_percent: 90.0,
            rapid_consensus_window_secs: 60,
            min_healthy_disagreement_rate: 0.15,
            max_sessions: 500,
            alert_enabled: true,
            alert_risk_threshold: 0.5,
        }
    }

    /// Create a relaxed configuration for low-stakes decisions
    pub fn relaxed() -> Self {
        Self {
            enabled: true,
            min_votes_for_analysis: 2,
            low_entropy_threshold: 0.2,
            unanimous_threshold_percent: 98.0,
            rapid_consensus_window_secs: 15,
            min_healthy_disagreement_rate: 0.05,
            max_sessions: 2000,
            alert_enabled: false,
            alert_risk_threshold: 0.9,
        }
    }
}

// ============================================================================
// Vote Record
// ============================================================================

/// A single vote record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    /// Agent who cast the vote
    pub agent_id: String,
    /// Option voted for
    pub option: String,
    /// Vote strength (from quadratic voting)
    pub strength: u64,
    /// Timestamp of vote
    pub timestamp: u64,
    /// Optional reasoning provided
    pub reasoning: Option<String>,
    /// Confidence level (0.0 to 1.0)
    pub confidence: Option<f64>,
}

impl VoteRecord {
    /// Create a new vote record
    pub fn new(agent_id: &str, option: &str, strength: u64) -> Self {
        Self {
            agent_id: agent_id.to_string(),
            option: option.to_string(),
            strength,
            timestamp: current_timestamp_millis(),
            reasoning: None,
            confidence: None,
        }
    }

    /// Add reasoning
    pub fn with_reasoning(mut self, reasoning: &str) -> Self {
        self.reasoning = Some(reasoning.to_string());
        self
    }

    /// Add confidence
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = Some(confidence.clamp(0.0, 1.0));
        self
    }
}

// ============================================================================
// Voting Session Analysis
// ============================================================================

/// Analysis of a voting session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionAnalysis {
    /// Session ID
    pub session_id: String,
    /// Number of voters
    pub voter_count: usize,
    /// Number of unique options voted for
    pub option_count: usize,
    /// Total votes cast
    pub total_votes: usize,
    /// Shannon entropy of vote distribution (0.0 = all same, higher = more diverse)
    pub vote_entropy: f64,
    /// Normalized entropy (0.0 to 1.0)
    pub normalized_entropy: f64,
    /// Disagreement rate (proportion of minority votes)
    pub disagreement_rate: f64,
    /// Whether consensus was reached
    pub consensus_reached: bool,
    /// Time to consensus (if reached)
    pub time_to_consensus_ms: Option<u64>,
    /// Majority option
    pub majority_option: Option<String>,
    /// Majority percentage
    pub majority_percent: f64,
    /// Opinion clusters detected
    pub opinion_clusters: Vec<OpinionCluster>,
    /// Risk indicators
    pub risk_indicators: Vec<RiskIndicator>,
    /// Overall sycophancy risk score (0.0 to 1.0)
    pub sycophancy_risk: f64,
    /// Recommendation
    pub recommendation: AnalysisRecommendation,
}

impl SessionAnalysis {
    /// Check if analysis indicates healthy debate
    pub fn is_healthy(&self) -> bool {
        self.sycophancy_risk < 0.5
    }

    /// Get human-readable summary
    pub fn summary(&self) -> String {
        format!(
            "Session {}: {} voters, {} options, entropy={:.2}, risk={:.2} ({})",
            self.session_id,
            self.voter_count,
            self.option_count,
            self.normalized_entropy,
            self.sycophancy_risk,
            self.recommendation.action
        )
    }
}

/// A cluster of agents with similar opinions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpinionCluster {
    /// Option this cluster supports
    pub option: String,
    /// Agents in this cluster
    pub agents: Vec<String>,
    /// Total strength of this cluster
    pub total_strength: u64,
    /// Percentage of total votes
    pub percentage: f64,
}

/// Risk indicators for sycophancy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskIndicator {
    /// Indicator type
    pub indicator_type: RiskIndicatorType,
    /// Severity (0.0 to 1.0)
    pub severity: f64,
    /// Description
    pub description: String,
}

/// Types of risk indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskIndicatorType {
    /// Very low vote entropy
    LowEntropy,
    /// Unanimous or near-unanimous agreement
    UnanimousAgreement,
    /// Consensus reached too quickly
    RapidConsensus,
    /// No substantive disagreement
    NoDisagreement,
    /// Agents changing votes to match majority
    VoteFlipping,
    /// Similar reasoning across agents
    ReasoningHomogeneity,
    /// Voting in temporal order (bandwagon effect)
    BandwagonEffect,
}

impl RiskIndicatorType {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            RiskIndicatorType::LowEntropy => "Low Entropy",
            RiskIndicatorType::UnanimousAgreement => "Unanimous Agreement",
            RiskIndicatorType::RapidConsensus => "Rapid Consensus",
            RiskIndicatorType::NoDisagreement => "No Disagreement",
            RiskIndicatorType::VoteFlipping => "Vote Flipping",
            RiskIndicatorType::ReasoningHomogeneity => "Reasoning Homogeneity",
            RiskIndicatorType::BandwagonEffect => "Bandwagon Effect",
        }
    }
}

/// Recommendation based on analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisRecommendation {
    /// Recommended action
    pub action: RecommendedAction,
    /// Confidence in recommendation
    pub confidence: f64,
    /// Explanation
    pub explanation: String,
}

/// Recommended actions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedAction {
    /// Accept the consensus
    Accept,
    /// Request additional deliberation
    RequestMoreDebate,
    /// Introduce adversarial agent
    IntroduceAdversary,
    /// Reset and re-vote
    ResetVoting,
    /// Flag for human review
    HumanReview,
    /// Block the decision
    BlockDecision,
}

impl std::fmt::Display for RecommendedAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

impl RecommendedAction {
    /// Get display name
    pub fn display_name(&self) -> &'static str {
        match self {
            RecommendedAction::Accept => "Accept",
            RecommendedAction::RequestMoreDebate => "Request More Debate",
            RecommendedAction::IntroduceAdversary => "Introduce Adversary",
            RecommendedAction::ResetVoting => "Reset Voting",
            RecommendedAction::HumanReview => "Human Review",
            RecommendedAction::BlockDecision => "Block Decision",
        }
    }
}

// ============================================================================
// Sycophancy Detector
// ============================================================================

/// Main sycophancy detection system
pub struct SycophancyDetector {
    config: DetectorConfig,
    /// Active voting sessions
    sessions: Arc<RwLock<HashMap<String, Vec<VoteRecord>>>>,
    /// Analysis cache
    analyses: Arc<RwLock<HashMap<String, SessionAnalysis>>>,
    /// Global counters
    sessions_analyzed: AtomicU64,
    alerts_triggered: AtomicU64,
    high_risk_sessions: AtomicU64,
}

impl std::fmt::Debug for SycophancyDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SycophancyDetector")
            .field("config", &self.config)
            .field("sessions_analyzed", &self.sessions_analyzed.load(Ordering::Relaxed))
            .field("alerts_triggered", &self.alerts_triggered.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SycophancyDetector {
    /// Create a new sycophancy detector
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            analyses: Arc::new(RwLock::new(HashMap::new())),
            sessions_analyzed: AtomicU64::new(0),
            alerts_triggered: AtomicU64::new(0),
            high_risk_sessions: AtomicU64::new(0),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(DetectorConfig::default())
    }

    /// Record a vote
    pub async fn record_vote(
        &self,
        session_id: &str,
        agent_id: &str,
        option: &str,
        strength: u64,
    ) {
        if !self.config.enabled {
            return;
        }

        let record = VoteRecord::new(agent_id, option, strength);

        let mut sessions = self.sessions.write().await;
        sessions
            .entry(session_id.to_string())
            .or_insert_with(Vec::new)
            .push(record);

        debug!(session_id, agent_id, option, strength, "Vote recorded");
    }

    /// Record a vote with full details
    pub async fn record_vote_detailed(&self, session_id: &str, record: VoteRecord) {
        if !self.config.enabled {
            return;
        }

        let mut sessions = self.sessions.write().await;
        sessions
            .entry(session_id.to_string())
            .or_insert_with(Vec::new)
            .push(record);
    }

    /// Analyze a voting session
    pub async fn analyze_session(&self, session_id: &str) -> SycophancyResult<SessionAnalysis> {
        let sessions = self.sessions.read().await;
        let votes = sessions
            .get(session_id)
            .ok_or_else(|| SycophancyError::SessionNotFound(session_id.to_string()))?;

        if votes.len() < self.config.min_votes_for_analysis {
            return Err(SycophancyError::InsufficientData {
                needed: self.config.min_votes_for_analysis,
                have: votes.len(),
            });
        }

        let analysis = self.perform_analysis(session_id, votes);
        self.sessions_analyzed.fetch_add(1, Ordering::Relaxed);

        // Check for alerts
        if self.config.alert_enabled && analysis.sycophancy_risk >= self.config.alert_risk_threshold
        {
            self.alerts_triggered.fetch_add(1, Ordering::Relaxed);
            self.high_risk_sessions.fetch_add(1, Ordering::Relaxed);
            warn!(
                session_id,
                risk = analysis.sycophancy_risk,
                "High sycophancy risk detected"
            );
        }

        // Cache analysis
        let mut analyses = self.analyses.write().await;
        analyses.insert(session_id.to_string(), analysis.clone());

        Ok(analysis)
    }

    /// Perform the actual analysis
    fn perform_analysis(&self, session_id: &str, votes: &[VoteRecord]) -> SessionAnalysis {
        // Calculate vote distribution
        let mut option_counts: HashMap<String, u64> = HashMap::new();
        let mut option_strengths: HashMap<String, u64> = HashMap::new();
        let mut agents_per_option: HashMap<String, Vec<String>> = HashMap::new();

        for vote in votes {
            *option_counts.entry(vote.option.clone()).or_default() += 1;
            *option_strengths.entry(vote.option.clone()).or_default() += vote.strength;
            agents_per_option
                .entry(vote.option.clone())
                .or_default()
                .push(vote.agent_id.clone());
        }

        let total_votes = votes.len();
        let total_strength: u64 = option_strengths.values().sum();
        let unique_voters: std::collections::HashSet<_> = votes.iter().map(|v| &v.agent_id).collect();

        // Calculate Shannon entropy
        let entropy = self.calculate_entropy(&option_counts, total_votes);
        let max_entropy = (option_counts.len() as f64).ln();
        let normalized_entropy = if max_entropy > 0.0 {
            entropy / max_entropy
        } else {
            0.0
        };

        // Find majority
        let (majority_option, majority_count) = option_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(opt, count)| (Some(opt.clone()), *count))
            .unwrap_or((None, 0));

        let majority_percent = if total_votes > 0 {
            majority_count as f64 / total_votes as f64 * 100.0
        } else {
            0.0
        };

        // Calculate disagreement rate
        let minority_votes = total_votes as u64 - majority_count;
        let disagreement_rate = if total_votes > 0 {
            minority_votes as f64 / total_votes as f64
        } else {
            0.0
        };

        // Detect time to consensus
        let timestamps: Vec<u64> = votes.iter().map(|v| v.timestamp).collect();
        let time_to_consensus = if !timestamps.is_empty() {
            let first = *timestamps.iter().min().unwrap();
            let last = *timestamps.iter().max().unwrap();
            Some(last - first)
        } else {
            None
        };

        // Build opinion clusters
        let opinion_clusters: Vec<OpinionCluster> = option_strengths
            .iter()
            .map(|(option, strength)| {
                let agents = agents_per_option.get(option).cloned().unwrap_or_default();
                let percentage = if total_strength > 0 {
                    *strength as f64 / total_strength as f64 * 100.0
                } else {
                    0.0
                };
                OpinionCluster {
                    option: option.clone(),
                    agents,
                    total_strength: *strength,
                    percentage,
                }
            })
            .collect();

        // Detect risk indicators
        let mut risk_indicators = Vec::new();

        // Low entropy indicator
        if normalized_entropy < self.config.low_entropy_threshold {
            risk_indicators.push(RiskIndicator {
                indicator_type: RiskIndicatorType::LowEntropy,
                severity: 1.0 - normalized_entropy,
                description: format!(
                    "Vote entropy ({:.2}) below threshold ({:.2})",
                    normalized_entropy, self.config.low_entropy_threshold
                ),
            });
        }

        // Unanimous agreement indicator
        if majority_percent >= self.config.unanimous_threshold_percent {
            risk_indicators.push(RiskIndicator {
                indicator_type: RiskIndicatorType::UnanimousAgreement,
                severity: (majority_percent - self.config.unanimous_threshold_percent)
                    / (100.0 - self.config.unanimous_threshold_percent),
                description: format!(
                    "Near-unanimous agreement ({:.1}%) on option '{}'",
                    majority_percent,
                    majority_option.as_deref().unwrap_or("unknown")
                ),
            });
        }

        // Rapid consensus indicator
        if let Some(time_ms) = time_to_consensus {
            let threshold_ms = self.config.rapid_consensus_window_secs * 1000;
            if time_ms < threshold_ms && total_votes >= self.config.min_votes_for_analysis {
                risk_indicators.push(RiskIndicator {
                    indicator_type: RiskIndicatorType::RapidConsensus,
                    severity: 1.0 - (time_ms as f64 / threshold_ms as f64),
                    description: format!(
                        "Consensus reached in {} ms (threshold: {} ms)",
                        time_ms, threshold_ms
                    ),
                });
            }
        }

        // No disagreement indicator
        if disagreement_rate < self.config.min_healthy_disagreement_rate {
            risk_indicators.push(RiskIndicator {
                indicator_type: RiskIndicatorType::NoDisagreement,
                severity: 1.0 - (disagreement_rate / self.config.min_healthy_disagreement_rate),
                description: format!(
                    "Disagreement rate ({:.1}%) below healthy minimum ({:.1}%)",
                    disagreement_rate * 100.0,
                    self.config.min_healthy_disagreement_rate * 100.0
                ),
            });
        }

        // Check for bandwagon effect (votes converging over time)
        if self.detect_bandwagon_effect(votes) {
            risk_indicators.push(RiskIndicator {
                indicator_type: RiskIndicatorType::BandwagonEffect,
                severity: 0.6,
                description: "Later votes tend to follow earlier majority".to_string(),
            });
        }

        // Calculate overall risk score
        let sycophancy_risk = self.calculate_risk_score(&risk_indicators, normalized_entropy);

        // Generate recommendation
        let recommendation = self.generate_recommendation(sycophancy_risk, &risk_indicators);

        SessionAnalysis {
            session_id: session_id.to_string(),
            voter_count: unique_voters.len(),
            option_count: option_counts.len(),
            total_votes,
            vote_entropy: entropy,
            normalized_entropy,
            disagreement_rate,
            consensus_reached: majority_percent >= 50.0,
            time_to_consensus_ms: time_to_consensus,
            majority_option,
            majority_percent,
            opinion_clusters,
            risk_indicators,
            sycophancy_risk,
            recommendation,
        }
    }

    /// Calculate Shannon entropy
    fn calculate_entropy(&self, option_counts: &HashMap<String, u64>, total: usize) -> f64 {
        if total == 0 {
            return 0.0;
        }

        let total_f64 = total as f64;
        option_counts
            .values()
            .map(|&count| {
                let p = count as f64 / total_f64;
                if p > 0.0 {
                    -p * p.ln()
                } else {
                    0.0
                }
            })
            .sum()
    }

    /// Detect bandwagon effect (later votes following early majority)
    fn detect_bandwagon_effect(&self, votes: &[VoteRecord]) -> bool {
        if votes.len() < 4 {
            return false;
        }

        let mut sorted_votes = votes.to_vec();
        sorted_votes.sort_by_key(|v| v.timestamp);

        // Split into early and late halves
        let mid = sorted_votes.len() / 2;
        let early_votes = &sorted_votes[..mid];
        let late_votes = &sorted_votes[mid..];

        // Find majority in early votes
        let mut early_counts: HashMap<&str, usize> = HashMap::new();
        for vote in early_votes {
            *early_counts.entry(&vote.option).or_default() += 1;
        }

        let early_majority = early_counts
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(opt, _)| *opt);

        if let Some(majority_opt) = early_majority {
            // Count late votes following early majority
            let late_following = late_votes
                .iter()
                .filter(|v| v.option == majority_opt)
                .count();

            let following_rate = late_following as f64 / late_votes.len() as f64;

            // If late votes follow early majority significantly more than random
            return following_rate > 0.7;
        }

        false
    }

    /// Calculate overall risk score
    fn calculate_risk_score(
        &self,
        indicators: &[RiskIndicator],
        normalized_entropy: f64,
    ) -> f64 {
        if indicators.is_empty() {
            return (1.0 - normalized_entropy) * 0.3; // Base risk from low entropy
        }

        // Weighted average of indicators
        let weights: HashMap<RiskIndicatorType, f64> = [
            (RiskIndicatorType::UnanimousAgreement, 0.3),
            (RiskIndicatorType::LowEntropy, 0.2),
            (RiskIndicatorType::RapidConsensus, 0.15),
            (RiskIndicatorType::NoDisagreement, 0.15),
            (RiskIndicatorType::BandwagonEffect, 0.1),
            (RiskIndicatorType::VoteFlipping, 0.05),
            (RiskIndicatorType::ReasoningHomogeneity, 0.05),
        ]
        .into_iter()
        .collect();

        let weighted_sum: f64 = indicators
            .iter()
            .map(|ind| {
                let weight = weights.get(&ind.indicator_type).copied().unwrap_or(0.1);
                ind.severity * weight
            })
            .sum();

        let total_weight: f64 = indicators
            .iter()
            .map(|ind| weights.get(&ind.indicator_type).copied().unwrap_or(0.1))
            .sum();

        if total_weight > 0.0 {
            (weighted_sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }

    /// Generate recommendation based on risk
    fn generate_recommendation(
        &self,
        risk_score: f64,
        indicators: &[RiskIndicator],
    ) -> AnalysisRecommendation {
        let (action, explanation) = if risk_score < 0.3 {
            (
                RecommendedAction::Accept,
                "Healthy debate observed, safe to proceed".to_string(),
            )
        } else if risk_score < 0.5 {
            (
                RecommendedAction::RequestMoreDebate,
                "Some consensus patterns detected, additional deliberation recommended".to_string(),
            )
        } else if risk_score < 0.7 {
            let has_unanimous = indicators
                .iter()
                .any(|i| i.indicator_type == RiskIndicatorType::UnanimousAgreement);
            if has_unanimous {
                (
                    RecommendedAction::IntroduceAdversary,
                    "Unanimous agreement detected, consider introducing adversarial perspective"
                        .to_string(),
                )
            } else {
                (
                    RecommendedAction::RequestMoreDebate,
                    "Moderate sycophancy risk, extend deliberation period".to_string(),
                )
            }
        } else if risk_score < 0.85 {
            (
                RecommendedAction::HumanReview,
                "High sycophancy risk detected, recommend human review before proceeding"
                    .to_string(),
            )
        } else {
            (
                RecommendedAction::BlockDecision,
                "Very high sycophancy risk, decision should be blocked until healthy debate occurs"
                    .to_string(),
            )
        };

        AnalysisRecommendation {
            action,
            confidence: 1.0 - (risk_score - 0.5).abs(), // Higher confidence near extremes
            explanation,
        }
    }

    /// Get cached analysis
    pub async fn get_analysis(&self, session_id: &str) -> Option<SessionAnalysis> {
        let analyses = self.analyses.read().await;
        analyses.get(session_id).cloned()
    }

    /// Get statistics
    pub fn get_stats(&self) -> DetectorStats {
        DetectorStats {
            sessions_analyzed: self.sessions_analyzed.load(Ordering::Relaxed),
            alerts_triggered: self.alerts_triggered.load(Ordering::Relaxed),
            high_risk_sessions: self.high_risk_sessions.load(Ordering::Relaxed),
        }
    }

    /// Clear old sessions
    pub async fn cleanup_old_sessions(&self, max_age_secs: u64) {
        let cutoff = current_timestamp_millis() - (max_age_secs * 1000);

        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, votes| {
            votes
                .iter()
                .any(|v| v.timestamp >= cutoff)
        });
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let stats = self.get_stats();

        let mut output = String::new();

        output.push_str(&format!(
            "# HELP vak_sycophancy_sessions_analyzed_total Total voting sessions analyzed\n\
             # TYPE vak_sycophancy_sessions_analyzed_total counter\n\
             vak_sycophancy_sessions_analyzed_total {}\n\n",
            stats.sessions_analyzed
        ));

        output.push_str(&format!(
            "# HELP vak_sycophancy_alerts_triggered_total Total sycophancy alerts triggered\n\
             # TYPE vak_sycophancy_alerts_triggered_total counter\n\
             vak_sycophancy_alerts_triggered_total {}\n\n",
            stats.alerts_triggered
        ));

        output.push_str(&format!(
            "# HELP vak_sycophancy_high_risk_sessions_total Sessions with high sycophancy risk\n\
             # TYPE vak_sycophancy_high_risk_sessions_total counter\n\
             vak_sycophancy_high_risk_sessions_total {}\n\n",
            stats.high_risk_sessions
        ));

        output
    }
}

impl Default for SycophancyDetector {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Detector statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorStats {
    /// Total sessions analyzed
    pub sessions_analyzed: u64,
    /// Total alerts triggered
    pub alerts_triggered: u64,
    /// Total high-risk sessions
    pub high_risk_sessions: u64,
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Get current timestamp in milliseconds
fn current_timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_healthy_voting() {
        // Use relaxed config to avoid rapid_consensus triggering in tests
        let detector = SycophancyDetector::new(DetectorConfig {
            rapid_consensus_window_secs: 0, // Disable rapid consensus detection for test
            min_healthy_disagreement_rate: 0.0, // Don't require disagreement for healthy
            ..Default::default()
        });

        // Diverse votes - each agent votes for a different option
        detector.record_vote("session-1", "agent-1", "option-a", 3).await;
        detector.record_vote("session-1", "agent-2", "option-b", 3).await;
        detector.record_vote("session-1", "agent-3", "option-c", 3).await;
        detector.record_vote("session-1", "agent-4", "option-d", 3).await;

        let analysis = detector.analyze_session("session-1").await.unwrap();
        // With 4 different options and equal distribution, this should be healthy
        assert!(analysis.normalized_entropy > 0.5, "Expected high entropy, got {}", analysis.normalized_entropy);
        assert!(analysis.sycophancy_risk < 0.5, "Expected low risk, got {}. Indicators: {:?}", 
            analysis.sycophancy_risk, analysis.risk_indicators);
    }

    #[tokio::test]
    async fn test_unanimous_agreement() {
        let detector = SycophancyDetector::with_defaults();

        // All agents vote the same
        detector.record_vote("session-1", "agent-1", "option-a", 5).await;
        detector.record_vote("session-1", "agent-2", "option-a", 4).await;
        detector.record_vote("session-1", "agent-3", "option-a", 5).await;

        let analysis = detector.analyze_session("session-1").await.unwrap();
        assert!(analysis.sycophancy_risk > 0.5);
        assert!(analysis
            .risk_indicators
            .iter()
            .any(|i| i.indicator_type == RiskIndicatorType::UnanimousAgreement));
    }

    #[tokio::test]
    async fn test_low_entropy() {
        // Configure to disable rapid consensus and focus on entropy
        let detector = SycophancyDetector::new(DetectorConfig {
            low_entropy_threshold: 0.8, // Higher threshold to ensure it triggers
            min_votes_for_analysis: 3,
            rapid_consensus_window_secs: 0, // Disable rapid consensus for test
            unanimous_threshold_percent: 100.0, // Disable unanimous check
            ..Default::default()
        });

        // Extremely skewed voting - all votes for one option
        // This gives 0 entropy (unanimous), which will trigger low entropy
        detector.record_vote("session-1", "agent-1", "option-a", 5).await;
        detector.record_vote("session-1", "agent-2", "option-a", 5).await;
        detector.record_vote("session-1", "agent-3", "option-a", 5).await;

        let analysis = detector.analyze_session("session-1").await.unwrap();
        // Unanimous votes means entropy = 0, which is definitely below 0.8
        assert!(analysis.normalized_entropy < 0.8, 
            "Expected low entropy, got {}", analysis.normalized_entropy);
        
        // With 0 entropy (or very low), low entropy indicator should be present
        let has_low_entropy = analysis
            .risk_indicators
            .iter()
            .any(|i| i.indicator_type == RiskIndicatorType::LowEntropy);
        
        assert!(has_low_entropy, 
            "Expected LowEntropy risk indicator, normalized_entropy={}, indicators={:?}", 
            analysis.normalized_entropy, analysis.risk_indicators);
    }

    #[test]
    fn test_entropy_calculation() {
        let detector = SycophancyDetector::with_defaults();

        // Equal distribution should have maximum entropy
        let mut counts = HashMap::new();
        counts.insert("a".to_string(), 1);
        counts.insert("b".to_string(), 1);
        counts.insert("c".to_string(), 1);

        let entropy = detector.calculate_entropy(&counts, 3);
        assert!(entropy > 0.0);

        // Single option should have zero entropy
        let mut single = HashMap::new();
        single.insert("a".to_string(), 3);
        let zero_entropy = detector.calculate_entropy(&single, 3);
        assert_eq!(zero_entropy, 0.0);
    }

    #[tokio::test]
    async fn test_recommendation_generation() {
        let detector = SycophancyDetector::with_defaults();

        // High risk scenario
        detector.record_vote("session-1", "agent-1", "option-a", 10).await;
        detector.record_vote("session-1", "agent-2", "option-a", 10).await;
        detector.record_vote("session-1", "agent-3", "option-a", 10).await;

        let analysis = detector.analyze_session("session-1").await.unwrap();
        assert!(matches!(
            analysis.recommendation.action,
            RecommendedAction::IntroduceAdversary
                | RecommendedAction::HumanReview
                | RecommendedAction::BlockDecision
        ));
    }

    #[test]
    fn test_stats() {
        let detector = SycophancyDetector::with_defaults();
        detector.sessions_analyzed.fetch_add(10, Ordering::Relaxed);
        detector.alerts_triggered.fetch_add(2, Ordering::Relaxed);

        let stats = detector.get_stats();
        assert_eq!(stats.sessions_analyzed, 10);
        assert_eq!(stats.alerts_triggered, 2);
    }
}
