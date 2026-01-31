//! Protocol Router Implementation (SWM-003)
//!
//! This module implements the Protocol Router for dynamic topology selection.
//! The router analyzes tasks and selects the best collaboration topology
//! based on task complexity, agent count, and other factors.
//!
//! # Topologies
//!
//! - **Hierarchical**: Leader coordinates workers (for complex, structured tasks)
//! - **Debate**: Agents argue positions (for decision-making)
//! - **Voting**: Democratic consensus (for group decisions)
//! - **Broadcast**: All agents receive same info (for announcements)
//! - **Pipeline**: Sequential processing (for workflows)
//! - **Mesh**: All-to-all communication (for collaborative exploration)
//!
//! # Example
//!
//! ```rust
//! use vak::swarm::router::{ProtocolRouter, RouterConfig, TaskComplexity};
//!
//! let router = ProtocolRouter::new(RouterConfig::default());
//! let decision = router.route("Analyze this security vulnerability", TaskComplexity::High, 5);
//!
//! println!("Selected topology: {:?}", decision.topology);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during routing operations
#[derive(Debug, Error)]
pub enum RoutingError {
    /// No suitable topology found
    #[error("No suitable topology found for task")]
    NoSuitableTopology,

    /// Insufficient agents for topology
    #[error("Insufficient agents: need {0}, have {1}")]
    InsufficientAgents(usize, usize),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Routing constraint violation
    #[error("Routing constraint violation: {0}")]
    ConstraintViolation(String),
}

// ============================================================================
// Task Complexity
// ============================================================================

/// Complexity level of a task
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskComplexity {
    /// Simple task, single agent can handle
    Low,
    /// Moderate task, may benefit from collaboration
    Medium,
    /// Complex task, requires multiple agents
    High,
    /// Critical task, requires full swarm
    Critical,
}

impl TaskComplexity {
    /// Get a numeric score for the complexity
    pub fn score(&self) -> u32 {
        match self {
            TaskComplexity::Low => 1,
            TaskComplexity::Medium => 2,
            TaskComplexity::High => 3,
            TaskComplexity::Critical => 4,
        }
    }

    /// Suggested minimum agents for this complexity
    pub fn min_agents(&self) -> usize {
        match self {
            TaskComplexity::Low => 1,
            TaskComplexity::Medium => 2,
            TaskComplexity::High => 3,
            TaskComplexity::Critical => 5,
        }
    }
}

impl Default for TaskComplexity {
    fn default() -> Self {
        TaskComplexity::Medium
    }
}

// ============================================================================
// Topology
// ============================================================================

/// Available collaboration topologies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Topology {
    /// Single agent handles the task
    Solo,
    /// Leader coordinates worker agents
    Hierarchical,
    /// Agents debate and critique each other
    Debate,
    /// Democratic voting on decisions
    Voting,
    /// Broadcast information to all
    Broadcast,
    /// Sequential pipeline processing
    Pipeline,
    /// Full mesh, all-to-all communication
    Mesh,
    /// Expert consultation pattern
    Expert,
    /// Red team vs blue team
    Adversarial,
}

impl Topology {
    /// Get the minimum agents required for this topology
    pub fn min_agents(&self) -> usize {
        match self {
            Topology::Solo => 1,
            Topology::Hierarchical => 2,
            Topology::Debate => 2,
            Topology::Voting => 3,
            Topology::Broadcast => 2,
            Topology::Pipeline => 2,
            Topology::Mesh => 2,
            Topology::Expert => 2,
            Topology::Adversarial => 4,
        }
    }

    /// Get the optimal agent count for this topology
    pub fn optimal_agents(&self) -> usize {
        match self {
            Topology::Solo => 1,
            Topology::Hierarchical => 5,
            Topology::Debate => 3,
            Topology::Voting => 5,
            Topology::Broadcast => 10,
            Topology::Pipeline => 4,
            Topology::Mesh => 4,
            Topology::Expert => 3,
            Topology::Adversarial => 6,
        }
    }

    /// Get the communication overhead factor (1.0 = baseline)
    pub fn overhead_factor(&self) -> f64 {
        match self {
            Topology::Solo => 0.0,
            Topology::Hierarchical => 1.0,
            Topology::Debate => 2.0,
            Topology::Voting => 1.5,
            Topology::Broadcast => 0.5,
            Topology::Pipeline => 0.8,
            Topology::Mesh => 3.0, // N*(N-1)/2 connections
            Topology::Expert => 1.2,
            Topology::Adversarial => 2.5,
        }
    }

    /// Get a description of this topology
    pub fn description(&self) -> &'static str {
        match self {
            Topology::Solo => "Single agent handles the entire task",
            Topology::Hierarchical => "Leader coordinates worker agents",
            Topology::Debate => "Agents argue and critique positions",
            Topology::Voting => "Democratic voting on decisions",
            Topology::Broadcast => "Information broadcast to all agents",
            Topology::Pipeline => "Sequential processing through stages",
            Topology::Mesh => "Full mesh, all-to-all communication",
            Topology::Expert => "Consult domain experts for input",
            Topology::Adversarial => "Red team vs blue team competition",
        }
    }
}

impl Default for Topology {
    fn default() -> Self {
        Topology::Hierarchical
    }
}

// ============================================================================
// Topology Selection
// ============================================================================

/// Factors that influence topology selection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologySelection {
    /// The selected topology
    pub topology: Topology,
    /// Confidence in the selection (0.0 to 1.0)
    pub confidence: f64,
    /// Reasons for the selection
    pub reasons: Vec<String>,
    /// Alternative topologies considered
    pub alternatives: Vec<(Topology, f64)>,
}

impl TopologySelection {
    /// Create a new topology selection
    pub fn new(topology: Topology, confidence: f64) -> Self {
        Self {
            topology,
            confidence,
            reasons: Vec::new(),
            alternatives: Vec::new(),
        }
    }

    /// Add a reason for the selection
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reasons.push(reason.into());
        self
    }

    /// Add an alternative topology
    pub fn with_alternative(mut self, topology: Topology, score: f64) -> Self {
        self.alternatives.push((topology, score));
        self
    }
}

// ============================================================================
// Routing Decision
// ============================================================================

/// A routing decision for a task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Selected topology
    pub topology: Topology,
    /// Confidence in the decision
    pub confidence: f64,
    /// Suggested agent count
    pub suggested_agents: usize,
    /// Estimated overhead
    pub estimated_overhead: f64,
    /// Reasoning for the decision
    pub reasoning: String,
    /// Task characteristics detected
    pub task_characteristics: TaskCharacteristics,
}

/// Detected characteristics of a task
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskCharacteristics {
    /// Is this a decision-making task?
    pub requires_decision: bool,
    /// Does this require critique/review?
    pub requires_review: bool,
    /// Is this time-sensitive?
    pub time_sensitive: bool,
    /// Does this involve risk/security?
    pub involves_risk: bool,
    /// Is this a creative task?
    pub creative: bool,
    /// Does this require sequential steps?
    pub sequential: bool,
    /// Keywords detected
    pub keywords: Vec<String>,
}

// ============================================================================
// Router Configuration
// ============================================================================

/// Configuration for the protocol router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Default topology when no clear match
    pub default_topology: Topology,
    /// Minimum confidence threshold for selection
    pub min_confidence: f64,
    /// Keywords that suggest specific topologies
    pub topology_keywords: HashMap<Topology, Vec<String>>,
    /// Whether to consider agent availability
    pub consider_availability: bool,
    /// Maximum overhead tolerance
    pub max_overhead: f64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        let mut topology_keywords = HashMap::new();
        
        topology_keywords.insert(
            Topology::Debate,
            vec![
                "discuss".to_string(),
                "argue".to_string(),
                "debate".to_string(),
                "pros and cons".to_string(),
                "opinion".to_string(),
            ],
        );
        
        topology_keywords.insert(
            Topology::Voting,
            vec![
                "vote".to_string(),
                "decide".to_string(),
                "choose".to_string(),
                "select".to_string(),
                "prefer".to_string(),
            ],
        );
        
        topology_keywords.insert(
            Topology::Hierarchical,
            vec![
                "coordinate".to_string(),
                "organize".to_string(),
                "delegate".to_string(),
                "manage".to_string(),
                "assign".to_string(),
            ],
        );
        
        topology_keywords.insert(
            Topology::Pipeline,
            vec![
                "step by step".to_string(),
                "sequential".to_string(),
                "workflow".to_string(),
                "process".to_string(),
                "stage".to_string(),
            ],
        );
        
        topology_keywords.insert(
            Topology::Expert,
            vec![
                "expert".to_string(),
                "specialist".to_string(),
                "consult".to_string(),
                "advice".to_string(),
                "knowledge".to_string(),
            ],
        );
        
        topology_keywords.insert(
            Topology::Adversarial,
            vec![
                "security".to_string(),
                "vulnerability".to_string(),
                "red team".to_string(),
                "attack".to_string(),
                "penetration".to_string(),
            ],
        );

        Self {
            default_topology: Topology::Hierarchical,
            min_confidence: 0.3,
            topology_keywords,
            consider_availability: true,
            max_overhead: 5.0,
        }
    }
}

impl RouterConfig {
    /// Create a new router configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the default topology
    pub fn with_default_topology(mut self, topology: Topology) -> Self {
        self.default_topology = topology;
        self
    }

    /// Set the minimum confidence threshold
    pub fn with_min_confidence(mut self, confidence: f64) -> Self {
        self.min_confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Add keywords for a topology
    pub fn with_keywords(mut self, topology: Topology, keywords: Vec<String>) -> Self {
        self.topology_keywords.insert(topology, keywords);
        self
    }
}

// ============================================================================
// Protocol Router
// ============================================================================

/// Protocol router for dynamic topology selection
#[derive(Debug, Clone)]
pub struct ProtocolRouter {
    /// Configuration
    config: RouterConfig,
}

impl ProtocolRouter {
    /// Create a new protocol router
    pub fn new(config: RouterConfig) -> Self {
        Self { config }
    }

    /// Route a task to the best topology
    pub fn route(&self, task: &str, complexity: TaskComplexity, available_agents: usize) -> RoutingDecision {
        let task_lower = task.to_lowercase();
        let characteristics = self.analyze_task(&task_lower);
        
        // Score each topology
        let mut scores: Vec<(Topology, f64)> = Vec::new();
        
        for topology in [
            Topology::Solo,
            Topology::Hierarchical,
            Topology::Debate,
            Topology::Voting,
            Topology::Broadcast,
            Topology::Pipeline,
            Topology::Mesh,
            Topology::Expert,
            Topology::Adversarial,
        ] {
            let score = self.score_topology(
                topology,
                &task_lower,
                &characteristics,
                complexity,
                available_agents,
            );
            scores.push((topology, score));
        }

        // Sort by score (descending)
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        let (best_topology, best_score) = scores[0];
        let confidence = best_score.clamp(0.0, 1.0);

        // Generate reasoning
        let reasoning = self.generate_reasoning(
            best_topology,
            &characteristics,
            complexity,
            available_agents,
        );

        // Calculate suggested agents
        let suggested_agents = self.calculate_suggested_agents(best_topology, complexity, available_agents);

        RoutingDecision {
            topology: best_topology,
            confidence,
            suggested_agents,
            estimated_overhead: best_topology.overhead_factor() * suggested_agents as f64,
            reasoning,
            task_characteristics: characteristics,
        }
    }

    /// Analyze task characteristics
    fn analyze_task(&self, task: &str) -> TaskCharacteristics {
        let decision_keywords = ["decide", "choose", "select", "pick", "determine"];
        let review_keywords = ["review", "critique", "check", "verify", "audit"];
        let time_keywords = ["urgent", "asap", "immediately", "quick", "fast"];
        let risk_keywords = ["security", "vulnerability", "risk", "threat", "danger"];
        let creative_keywords = ["create", "design", "imagine", "brainstorm", "generate"];
        let sequential_keywords = ["then", "after", "next", "step", "first"];

        let mut detected_keywords = Vec::new();
        
        for keyword in &decision_keywords {
            if task.contains(keyword) {
                detected_keywords.push(keyword.to_string());
            }
        }

        TaskCharacteristics {
            requires_decision: decision_keywords.iter().any(|k| task.contains(k)),
            requires_review: review_keywords.iter().any(|k| task.contains(k)),
            time_sensitive: time_keywords.iter().any(|k| task.contains(k)),
            involves_risk: risk_keywords.iter().any(|k| task.contains(k)),
            creative: creative_keywords.iter().any(|k| task.contains(k)),
            sequential: sequential_keywords.iter().any(|k| task.contains(k)),
            keywords: detected_keywords,
        }
    }

    /// Score a topology for a given task
    fn score_topology(
        &self,
        topology: Topology,
        task: &str,
        characteristics: &TaskCharacteristics,
        complexity: TaskComplexity,
        available_agents: usize,
    ) -> f64 {
        let mut score: f64 = 0.5; // Base score

        // Check minimum agents
        if available_agents < topology.min_agents() {
            return 0.0;
        }

        // Check keywords
        if let Some(keywords) = self.config.topology_keywords.get(&topology) {
            for keyword in keywords {
                if task.contains(keyword) {
                    score += 0.2;
                }
            }
        }

        // Adjust based on characteristics
        match topology {
            Topology::Solo => {
                if complexity == TaskComplexity::Low {
                    score += 0.3;
                }
                if !characteristics.requires_review {
                    score += 0.1;
                }
            }
            Topology::Debate => {
                if characteristics.requires_decision {
                    score += 0.2;
                }
                if characteristics.involves_risk {
                    score += 0.2;
                }
            }
            Topology::Voting => {
                if characteristics.requires_decision {
                    score += 0.3;
                }
                if available_agents >= 3 {
                    score += 0.1;
                }
            }
            Topology::Pipeline => {
                if characteristics.sequential {
                    score += 0.3;
                }
            }
            Topology::Expert => {
                if complexity == TaskComplexity::High || complexity == TaskComplexity::Critical {
                    score += 0.2;
                }
            }
            Topology::Adversarial => {
                if characteristics.involves_risk {
                    score += 0.4;
                }
                if available_agents >= 4 {
                    score += 0.1;
                }
            }
            Topology::Hierarchical => {
                if complexity == TaskComplexity::High || complexity == TaskComplexity::Critical {
                    score += 0.2;
                }
                if available_agents >= 3 {
                    score += 0.1;
                }
            }
            _ => {}
        }

        // Adjust for complexity
        if complexity.score() >= 3 && topology == Topology::Solo {
            score -= 0.3;
        }

        // Adjust for overhead
        let overhead = topology.overhead_factor();
        if overhead > self.config.max_overhead {
            score -= 0.2;
        }

        score.clamp(0.0, 1.0)
    }

    /// Generate reasoning for the selection
    fn generate_reasoning(
        &self,
        topology: Topology,
        characteristics: &TaskCharacteristics,
        complexity: TaskComplexity,
        available_agents: usize,
    ) -> String {
        let mut reasons = Vec::new();

        reasons.push(format!(
            "Selected {} topology for {:?} complexity task with {} available agents.",
            format!("{:?}", topology).to_lowercase(),
            complexity,
            available_agents
        ));

        if characteristics.requires_decision {
            reasons.push("Task requires decision-making.".to_string());
        }
        if characteristics.involves_risk {
            reasons.push("Task involves risk/security considerations.".to_string());
        }
        if characteristics.sequential {
            reasons.push("Task has sequential steps.".to_string());
        }

        reasons.push(format!(
            "Estimated communication overhead: {:.1}x",
            topology.overhead_factor()
        ));

        reasons.join(" ")
    }

    /// Calculate suggested number of agents
    fn calculate_suggested_agents(
        &self,
        topology: Topology,
        complexity: TaskComplexity,
        available_agents: usize,
    ) -> usize {
        let min = topology.min_agents();
        let optimal = topology.optimal_agents();
        let complexity_min = complexity.min_agents();

        // Use the maximum of minimum requirements
        let suggested = min.max(complexity_min);
        
        // Cap at optimal or available, whichever is lower
        suggested.min(optimal).min(available_agents)
    }

    /// Get the current configuration
    pub fn config(&self) -> &RouterConfig {
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
    fn test_task_complexity() {
        assert_eq!(TaskComplexity::Low.score(), 1);
        assert_eq!(TaskComplexity::Critical.score(), 4);
        assert_eq!(TaskComplexity::Low.min_agents(), 1);
        assert_eq!(TaskComplexity::Critical.min_agents(), 5);
    }

    #[test]
    fn test_topology_properties() {
        assert_eq!(Topology::Solo.min_agents(), 1);
        assert_eq!(Topology::Adversarial.min_agents(), 4);
        assert!(Topology::Mesh.overhead_factor() > Topology::Solo.overhead_factor());
    }

    #[test]
    fn test_router_config_default() {
        let config = RouterConfig::default();
        assert_eq!(config.default_topology, Topology::Hierarchical);
        assert!(!config.topology_keywords.is_empty());
    }

    #[test]
    fn test_router_creation() {
        let router = ProtocolRouter::new(RouterConfig::default());
        assert_eq!(router.config().default_topology, Topology::Hierarchical);
    }

    #[test]
    fn test_route_simple_task() {
        let router = ProtocolRouter::new(RouterConfig::default());
        let decision = router.route("Calculate 2 + 2", TaskComplexity::Low, 1);
        
        // Should select Solo for simple task with 1 agent
        assert_eq!(decision.topology, Topology::Solo);
    }

    #[test]
    fn test_route_debate_task() {
        let router = ProtocolRouter::new(RouterConfig::default());
        let decision = router.route(
            "Discuss and debate the pros and cons of this approach",
            TaskComplexity::Medium,
            5,
        );
        
        // Should lean towards debate topology
        assert!(decision.confidence > 0.0);
    }

    #[test]
    fn test_route_security_task() {
        let router = ProtocolRouter::new(RouterConfig::default());
        let decision = router.route(
            "Analyze security vulnerabilities in this code",
            TaskComplexity::High,
            6,
        );
        
        // Should select adversarial for security task
        assert_eq!(decision.topology, Topology::Adversarial);
    }

    #[test]
    fn test_route_voting_task() {
        let router = ProtocolRouter::new(RouterConfig::default());
        let decision = router.route(
            "Vote to decide which approach to select",
            TaskComplexity::Medium,
            5,
        );
        
        // Should select voting topology
        assert_eq!(decision.topology, Topology::Voting);
    }

    #[test]
    fn test_route_sequential_task() {
        let router = ProtocolRouter::new(RouterConfig::default());
        let decision = router.route(
            "First process this, then transform it, next validate the result",
            TaskComplexity::Medium,
            4,
        );
        
        // Should lean towards pipeline topology
        assert!(decision.task_characteristics.sequential);
    }

    #[test]
    fn test_insufficient_agents() {
        let router = ProtocolRouter::new(RouterConfig::default());
        let decision = router.route(
            "Complex security analysis",
            TaskComplexity::High,
            1, // Only 1 agent available
        );
        
        // Should fall back to Solo since not enough agents for other topologies
        assert_eq!(decision.topology, Topology::Solo);
    }

    #[test]
    fn test_topology_selection() {
        let selection = TopologySelection::new(Topology::Debate, 0.8)
            .with_reason("Task involves decision-making")
            .with_alternative(Topology::Voting, 0.6);
        
        assert_eq!(selection.topology, Topology::Debate);
        assert_eq!(selection.reasons.len(), 1);
        assert_eq!(selection.alternatives.len(), 1);
    }

    #[test]
    fn test_task_characteristics_detection() {
        let router = ProtocolRouter::new(RouterConfig::default());
        
        // Test decision detection
        let decision = router.route("Choose the best option", TaskComplexity::Medium, 3);
        assert!(decision.task_characteristics.requires_decision);
        
        // Test risk detection
        let decision = router.route("Check for security vulnerabilities", TaskComplexity::Medium, 3);
        assert!(decision.task_characteristics.involves_risk);
    }

    #[test]
    fn test_suggested_agents_calculation() {
        let router = ProtocolRouter::new(RouterConfig::default());
        
        // With plenty of agents
        let decision = router.route("Complex task", TaskComplexity::High, 10);
        assert!(decision.suggested_agents >= TaskComplexity::High.min_agents());
        assert!(decision.suggested_agents <= 10);
        
        // With limited agents
        let decision = router.route("Complex task", TaskComplexity::High, 2);
        assert!(decision.suggested_agents <= 2);
    }
}
