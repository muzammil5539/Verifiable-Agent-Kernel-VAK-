//! Sycophancy Detection for Multi-Agent Systems (SWM-003)
//!
//! This module detects "groupthink" or sycophantic behavior in multi-agent
//! voting systems where agents may agree too readily without genuine deliberation.
//!
//! # Overview
//!
//! Sycophancy in AI agent swarms can lead to:
//! - Echo chambers where bad decisions propagate
//! - Loss of diverse perspectives
//! - Reduced system robustness
//!
//! This detector analyzes voting patterns to identify suspicious unanimity.
//!
//! # Detection Methods
//!
//! - **Entropy Analysis**: Low entropy in vote distribution indicates potential groupthink
//! - **Rapid Consensus**: Unusually fast agreement may indicate sycophantic behavior
//! - **Unanimous Agreement**: 100% agreement on complex decisions is suspicious
//!
//! # Example
//!
//! ```rust,ignore
//! use vak::swarm::sycophancy::{SycophancyDetector, DetectorConfig};
//!
//! let detector = SycophancyDetector::with_defaults();
//!
//! // Record votes from a session
//! detector.record_vote("session-1", "agent-1", "option-a", 5).await;
//! detector.record_vote("session-1", "agent-2", "option-a", 4).await;
//! detector.record_vote("session-1", "agent-3", "option-a", 5).await;
//!
//! // Analyze for sycophancy
//! let analysis = detector.analyze_session("session-1").await.unwrap();
//! if analysis.sycophancy_risk > 0.7 {
//!     println!("High sycophancy risk detected!");
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
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the sycophancy detector
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorConfig {
    /// Threshold for low entropy detection (0.0-1.0)
    pub low_entropy_threshold: f64,
    /// Minimum votes needed for analysis
    pub min_votes_for_analysis: usize,
    /// Window in seconds for rapid consensus detection (0 to disable)
    pub rapid_consensus_window_secs: u64,
    /// Threshold percentage for unanimous agreement
    pub unanimous_threshold_percent: f64,
    /// Minimum healthy disagreement rate
    pub min_healthy_disagreement_rate: f64,
    /// Risk threshold for triggering alerts
    pub risk_alert_threshold: f64,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            low_entropy_threshold: 0.3,
            min_votes_for_analysis: 3,
            rapid_consensus_window_secs: 10,
            unanimous_threshold_percent: 95.0,
            min_healthy_disagreement_rate: 0.1,
            risk_alert_threshold: 0.7,
        }
    }
}

// ============================================================================
// Vote Record
// ============================================================================

/// A recorded vote for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRecord {
    /// Agent who cast the vote
    pub agent_id: String,
    /// Option voted for
    pub option: String,
    /// Strength of the vote
    pub strength: u64,
    /// When the vote was cast
    pub timestamp: u64,
}

/// Session data for analysis
#[derive(Debug, Clone, Default)]
pub struct SessionData {
    /// All votes in the session
    pub votes: Vec<VoteRecord>,
    /// When the session started
    pub started_at: Option<u64>,
}

// ============================================================================
// Risk Indicators
// ============================================================================

/// Types of risk indicators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskIndicatorType {
    /// All agents agreed unanimously
    UnanimousAgreement,
    /// Vote distribution has low entropy
    LowEntropy,
    /// Consensus reached too quickly
    RapidConsensus,
    /// Insufficient disagreement
    InsufficientDisagreement,
    /// Vote pattern matches known sycophancy pattern
    PatternMatch,
}

/// A specific risk indicator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskIndicator {
    /// Type of indicator
    pub indicator_type: RiskIndicatorType,
    /// Severity (0.0-1.0)
    pub severity: f64,
    /// Human-readable description
    pub description: String,
}

// ============================================================================
// Recommendations
// ============================================================================

/// Recommended action based on analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// No action needed
    None,
    /// Monitor the situation
    Monitor,
    /// Introduce an adversarial agent
    IntroduceAdversary,
    /// Require human review
    HumanReview,
    /// Block the decision
    BlockDecision,
}

/// Recommendation with reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Recommended action
    pub action: RecommendedAction,
    /// Reasoning for the recommendation
    pub reasoning: String,
    /// Confidence in the recommendation
    pub confidence: f64,
}

// ============================================================================
// Analysis Result
// ============================================================================

/// Result of sycophancy analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SycophancyAnalysis {
    /// Session ID analyzed
    pub session_id: String,
    /// Overall sycophancy risk score (0.0-1.0)
    pub sycophancy_risk: f64,
    /// Normalized entropy of vote distribution (0.0-1.0)
    pub normalized_entropy: f64,
    /// Identified risk indicators
    pub risk_indicators: Vec<RiskIndicator>,
    /// Recommendation based on analysis
    pub recommendation: Recommendation,
    /// Number of votes analyzed
    pub votes_analyzed: usize,
    /// Number of unique options
    pub unique_options: usize,
}

// ============================================================================
// Statistics
// ============================================================================

/// Statistics for the detector
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectorStats {
    /// Number of sessions analyzed
    pub sessions_analyzed: u64,
    /// Number of alerts triggered
    pub alerts_triggered: u64,
    /// Average risk score across sessions
    pub avg_risk_score: f64,
}

// ============================================================================
// Sycophancy Detector
// ============================================================================

/// Detector for sycophantic voting patterns
pub struct SycophancyDetector {
    /// Configuration
    config: DetectorConfig,
    /// Session data storage
    sessions: Arc<RwLock<HashMap<String, SessionData>>>,
    /// Statistics counters
    pub sessions_analyzed: AtomicU64,
    /// Alert counter
    pub alerts_triggered: AtomicU64,
}

impl SycophancyDetector {
    /// Create a new detector with custom configuration
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            sessions_analyzed: AtomicU64::new(0),
            alerts_triggered: AtomicU64::new(0),
        }
    }

    /// Create a detector with default configuration
    pub fn with_defaults() -> Self {
        Self::new(DetectorConfig::default())
    }

    /// Record a vote for analysis
    pub async fn record_vote(
        &self,
        session_id: &str,
        agent_id: &str,
        option: &str,
        strength: u64,
    ) {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .entry(session_id.to_string())
            .or_insert_with(SessionData::default);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if session.started_at.is_none() {
            session.started_at = Some(now);
        }

        session.votes.push(VoteRecord {
            agent_id: agent_id.to_string(),
            option: option.to_string(),
            strength,
            timestamp: now,
        });
    }

    /// Analyze a session for sycophancy
    pub async fn analyze_session(&self, session_id: &str) -> Option<SycophancyAnalysis> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(session_id)?;

        if session.votes.len() < self.config.min_votes_for_analysis {
            return None;
        }

        self.sessions_analyzed.fetch_add(1, Ordering::Relaxed);

        // Count votes per option
        let mut option_counts: HashMap<String, usize> = HashMap::new();
        for vote in &session.votes {
            *option_counts.entry(vote.option.clone()).or_insert(0) += 1;
        }

        let total_votes = session.votes.len();
        let unique_options = option_counts.len();

        // Calculate entropy
        let entropy = self.calculate_entropy(&option_counts, total_votes);
        let max_entropy = (unique_options as f64).ln();
        let normalized_entropy = if max_entropy > 0.0 {
            entropy / max_entropy
        } else {
            0.0
        };

        // Identify risk indicators
        let mut risk_indicators = Vec::new();
        let mut total_risk = 0.0;

        // Check for unanimous agreement
        let max_votes = option_counts.values().max().copied().unwrap_or(0);
        let unanimity_percent = (max_votes as f64 / total_votes as f64) * 100.0;
        if unanimity_percent >= self.config.unanimous_threshold_percent {
            risk_indicators.push(RiskIndicator {
                indicator_type: RiskIndicatorType::UnanimousAgreement,
                severity: 0.9,
                description: format!("{:.1}% of agents agreed on the same option", unanimity_percent),
            });
            total_risk += 0.4;
        }

        // Check for low entropy
        if normalized_entropy < self.config.low_entropy_threshold {
            risk_indicators.push(RiskIndicator {
                indicator_type: RiskIndicatorType::LowEntropy,
                severity: 0.7,
                description: format!(
                    "Low vote diversity (entropy: {:.2})",
                    normalized_entropy
                ),
            });
            total_risk += 0.3;
        }

        // Check for rapid consensus
        if self.config.rapid_consensus_window_secs > 0 {
            if let Some(started) = session.started_at {
                let last_vote_time = session.votes.iter().map(|v| v.timestamp).max().unwrap_or(started);
                let duration = last_vote_time.saturating_sub(started);
                if duration < self.config.rapid_consensus_window_secs && total_votes >= 3 {
                    risk_indicators.push(RiskIndicator {
                        indicator_type: RiskIndicatorType::RapidConsensus,
                        severity: 0.6,
                        description: format!(
                            "Consensus reached in {} seconds with {} votes",
                            duration, total_votes
                        ),
                    });
                    total_risk += 0.2;
                }
            }
        }

        // Check for insufficient disagreement
        let disagreement_rate = 1.0 - (max_votes as f64 / total_votes as f64);
        if disagreement_rate < self.config.min_healthy_disagreement_rate {
            risk_indicators.push(RiskIndicator {
                indicator_type: RiskIndicatorType::InsufficientDisagreement,
                severity: 0.5,
                description: format!(
                    "Only {:.1}% disagreement rate",
                    disagreement_rate * 100.0
                ),
            });
            total_risk += 0.1;
        }

        let sycophancy_risk = total_risk.min(1.0);

        // Generate recommendation
        let recommendation = self.generate_recommendation(sycophancy_risk, &risk_indicators);

        if sycophancy_risk >= self.config.risk_alert_threshold {
            self.alerts_triggered.fetch_add(1, Ordering::Relaxed);
        }

        Some(SycophancyAnalysis {
            session_id: session_id.to_string(),
            sycophancy_risk,
            normalized_entropy,
            risk_indicators,
            recommendation,
            votes_analyzed: total_votes,
            unique_options,
        })
    }

    /// Calculate Shannon entropy
    pub fn calculate_entropy(&self, counts: &HashMap<String, usize>, total: usize) -> f64 {
        if total == 0 {
            return 0.0;
        }

        let mut entropy = 0.0;
        for &count in counts.values() {
            if count > 0 {
                let p = count as f64 / total as f64;
                entropy -= p * p.ln();
            }
        }
        entropy
    }

    /// Generate a recommendation based on analysis
    fn generate_recommendation(
        &self,
        risk_score: f64,
        indicators: &[RiskIndicator],
    ) -> Recommendation {
        let (action, reasoning) = if risk_score >= 0.8 {
            (
                RecommendedAction::BlockDecision,
                "High sycophancy risk - recommend blocking decision pending review".to_string(),
            )
        } else if risk_score >= 0.6 {
            (
                RecommendedAction::HumanReview,
                "Elevated sycophancy risk - human review recommended".to_string(),
            )
        } else if risk_score >= 0.4 {
            (
                RecommendedAction::IntroduceAdversary,
                "Moderate sycophancy risk - consider introducing adversarial viewpoint".to_string(),
            )
        } else if risk_score >= 0.2 {
            (
                RecommendedAction::Monitor,
                "Low sycophancy risk - continue monitoring".to_string(),
            )
        } else {
            (
                RecommendedAction::None,
                "Healthy vote distribution".to_string(),
            )
        };

        Recommendation {
            action,
            reasoning,
            confidence: 1.0 - (risk_score * 0.2), // Higher risk = lower confidence
        }
    }

    /// Get detector statistics
    pub fn get_stats(&self) -> DetectorStats {
        DetectorStats {
            sessions_analyzed: self.sessions_analyzed.load(Ordering::Relaxed),
            alerts_triggered: self.alerts_triggered.load(Ordering::Relaxed),
            avg_risk_score: 0.0, // Would need to track this separately
        }
    }

    /// Clear session data
    pub async fn clear_session(&self, session_id: &str) {
        let mut sessions = self.sessions.write().await;
        sessions.remove(session_id);
    }

    /// Clear all session data
    pub async fn clear_all(&self) {
        let mut sessions = self.sessions.write().await;
        sessions.clear();
    }
}

impl std::fmt::Debug for SycophancyDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SycophancyDetector")
            .field("config", &self.config)
            .field("sessions_analyzed", &self.sessions_analyzed.load(Ordering::Relaxed))
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_healthy_voting() {
        let detector = SycophancyDetector::new(DetectorConfig {
            rapid_consensus_window_secs: 0,
            min_healthy_disagreement_rate: 0.0,
            ..Default::default()
        });

        detector.record_vote("session-1", "agent-1", "option-a", 3).await;
        detector.record_vote("session-1", "agent-2", "option-b", 3).await;
        detector.record_vote("session-1", "agent-3", "option-c", 3).await;
        detector.record_vote("session-1", "agent-4", "option-d", 3).await;

        let analysis = detector.analyze_session("session-1").await.unwrap();
        assert!(analysis.normalized_entropy > 0.5);
        assert!(analysis.sycophancy_risk < 0.5);
    }

    #[tokio::test]
    async fn test_unanimous_agreement() {
        let detector = SycophancyDetector::with_defaults();

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
        let detector = SycophancyDetector::new(DetectorConfig {
            low_entropy_threshold: 0.8,
            min_votes_for_analysis: 3,
            rapid_consensus_window_secs: 0,
            unanimous_threshold_percent: 100.0,
            ..Default::default()
        });

        detector.record_vote("session-1", "agent-1", "option-a", 5).await;
        detector.record_vote("session-1", "agent-2", "option-a", 5).await;
        detector.record_vote("session-1", "agent-3", "option-a", 5).await;

        let analysis = detector.analyze_session("session-1").await.unwrap();
        assert!(analysis.normalized_entropy < 0.8);
        
        let has_low_entropy = analysis
            .risk_indicators
            .iter()
            .any(|i| i.indicator_type == RiskIndicatorType::LowEntropy);
        
        assert!(has_low_entropy);
    }

    #[test]
    fn test_entropy_calculation() {
        let detector = SycophancyDetector::with_defaults();

        let mut counts = HashMap::new();
        counts.insert("a".to_string(), 1);
        counts.insert("b".to_string(), 1);
        counts.insert("c".to_string(), 1);

        let entropy = detector.calculate_entropy(&counts, 3);
        assert!(entropy > 0.0);

        let mut single = HashMap::new();
        single.insert("a".to_string(), 3);
        let zero_entropy = detector.calculate_entropy(&single, 3);
        assert_eq!(zero_entropy, 0.0);
    }

    #[tokio::test]
    async fn test_recommendation_generation() {
        let detector = SycophancyDetector::with_defaults();

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