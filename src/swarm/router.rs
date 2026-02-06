//! Protocol Router for Multi-Agent Topology Selection (SWM-004)
//!
//! This module provides intelligent routing of tasks to appropriate
//! multi-agent topologies based on task characteristics and complexity.
//!
//! # Topologies
//!
//! - **Solo**: Single agent execution
//! - **Hierarchical**: Leader-worker structure
//! - **Debate**: Adversarial discussion
//! - **Voting**: Democratic decision making
//! - **Pipeline**: Sequential processing
//! - **Mesh**: Fully connected collaboration
//! - **Adversarial**: Red team / Blue team
//!
//! # Example
//!
//! ```rust,ignore
//! use vak::swarm::router::{ProtocolRouter, RouterConfig, TaskComplexity};
//!
//! let router = ProtocolRouter::new(RouterConfig::default());
//! let decision = router.route("Analyze security vulnerabilities", TaskComplexity::High, 5);
//!
//! println!("Selected topology: {:?}", decision.topology);
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during routing
#[derive(Debug, Error, Clone)]
pub enum RoutingError {
    /// Insufficient agents for the selected topology
    #[error("Insufficient agents: need {0}, have {1}")]
    InsufficientAgents(usize, usize),

    /// Invalid topology configuration
    #[error("Invalid topology configuration: {0}")]
    InvalidConfig(String),

    /// No suitable topology found
    #[error("No suitable topology found for task")]
    NoSuitableTopology,
}

// ============================================================================
// Task Complexity
// ============================================================================

/// Complexity level of a task
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskComplexity {
    /// Simple, straightforward task
    Low,
    /// Moderate complexity
    Medium,
    /// Complex task requiring careful handling
    High,
    /// Critical task with significant impact
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

    /// Get minimum recommended agents for this complexity
    pub fn min_agents(&self) -> usize {
        match self {
            TaskComplexity::Low => 1,
            TaskComplexity::Medium => 2,
            TaskComplexity::High => 3,
            TaskComplexity::Critical => 5,
        }
    }
}

// ============================================================================
// Topology
// ============================================================================

/// Available multi-agent topologies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Topology {
    /// Single agent handles everything
    Solo,
    /// Leader coordinates workers
    Hierarchical,
    /// Agents debate different perspectives
    Debate,
    /// Democratic voting on decisions
    Voting,
    /// Sequential pipeline processing
    Pipeline,
    /// Fully connected mesh
    Mesh,
    /// Red team vs Blue team
    Adversarial,
}

impl Topology {
    /// Get minimum agents required for this topology
    pub fn min_agents(&self) -> usize {
        match self {
            Topology::Solo => 1,
            Topology::Hierarchical => 2,
            Topology::Debate => 2,
            Topology::Voting => 3,
            Topology::Pipeline => 2,
            Topology::Mesh => 3,
            Topology::Adversarial => 4,
        }
    }

    /// Get communication overhead factor
    pub fn overhead_factor(&self) -> f64 {
        match self {
            Topology::Solo => 1.0,
            Topology::Hierarchical => 1.5,
            Topology::Debate => 2.0,
            Topology::Voting => 1.8,
            Topology::Pipeline => 1.3,
            Topology::Mesh => 3.0,
            Topology::Adversarial => 2.5,
        }
    }
}

// ============================================================================
// Task Characteristics
// ============================================================================

/// Characteristics of a task that influence routing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskCharacteristics {
    /// Task requires a final decision
    pub requires_decision: bool,
    /// Task involves security/risk
    pub involves_risk: bool,
    /// Task is sequential in nature
    pub sequential: bool,
    /// Task benefits from diverse perspectives
    pub benefits_from_diversity: bool,
    /// Task is time-sensitive
    pub time_sensitive: bool,
}

// ============================================================================
// Topology Selection
// ============================================================================

/// A topology selection with reasoning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologySelection {
    /// Selected topology
    pub topology: Topology,
    /// Confidence in selection (0.0-1.0)
    pub confidence: f64,
    /// Reasons for selection
    pub reasons: Vec<String>,
    /// Alternative topologies considered
    pub alternatives: Vec<(Topology, f64)>,
}

impl TopologySelection {
    /// Create a new selection
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
    pub fn with_alternative(mut self, topology: Topology, confidence: f64) -> Self {
        self.alternatives.push((topology, confidence));
        self
    }
}

// ============================================================================
// Routing Decision
// ============================================================================

/// Complete routing decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingDecision {
    /// Selected topology
    pub topology: Topology,
    /// Confidence in decision
    pub confidence: f64,
    /// Detected task characteristics
    pub task_characteristics: TaskCharacteristics,
    /// Suggested number of agents
    pub suggested_agents: usize,
    /// Reasons for decision
    pub reasons: Vec<String>,
}

/// Enhanced routing decision with more details
pub type EnhancedRoutingDecision = RoutingDecision;

// ============================================================================
// Router Configuration
// ============================================================================

/// Configuration for the protocol router
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Default topology when no clear match
    pub default_topology: Topology,
    /// Keywords that trigger specific topologies
    pub topology_keywords: HashMap<Topology, Vec<String>>,
    /// Minimum confidence to use detected topology
    pub min_confidence: f64,
}

impl Default for RouterConfig {
    fn default() -> Self {
        let mut keywords = HashMap::new();
        
        keywords.insert(Topology::Debate, vec![
            "debate".to_string(),
            "discuss".to_string(),
            "pros and cons".to_string(),
            "compare".to_string(),
        ]);
        
        keywords.insert(Topology::Voting, vec![
            "vote".to_string(),
            "decide".to_string(),
            "choose".to_string(),
            "select".to_string(),
        ]);
        
        keywords.insert(Topology::Adversarial, vec![
            "security".to_string(),
            "vulnerability".to_string(),
            "attack".to_string(),
            "red team".to_string(),
        ]);
        
        keywords.insert(Topology::Pipeline, vec![
            "first".to_string(),
            "then".to_string(),
            "next".to_string(),
            "step".to_string(),
            "sequential".to_string(),
        ]);

        Self {
            default_topology: Topology::Hierarchical,
            topology_keywords: keywords,
            min_confidence: 0.5,
        }
    }
}

// ============================================================================
// Protocol Router
// ============================================================================

/// Router for selecting multi-agent topologies
#[derive(Debug, Clone)]
pub struct ProtocolRouter {
    /// Configuration
    config: RouterConfig,
}

impl ProtocolRouter {
    /// Create a new router with the given configuration
    pub fn new(config: RouterConfig) -> Self {
        Self { config }
    }

    /// Get the router configuration
    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    /// Route a task to an appropriate topology
    pub fn route(
        &self,
        task: &str,
        complexity: TaskComplexity,
        available_agents: usize,
    ) -> RoutingDecision {
        let task_lower = task.to_lowercase();
        let characteristics = self.detect_characteristics(&task_lower);
        
        // Score each topology
        let mut scores: Vec<(Topology, f64)> = Vec::new();
        
        for (topology, keywords) in &self.config.topology_keywords {
            let keyword_score = keywords
                .iter()
                .filter(|kw| task_lower.contains(kw.as_str()))
                .count() as f64 / keywords.len().max(1) as f64;
            
            if keyword_score > 0.0 && topology.min_agents() <= available_agents {
                scores.push((*topology, keyword_score));
            }
        }
        
        // Sort by score descending
        scores.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        
        // Select topology
        let (topology, confidence) = if let Some((top, conf)) = scores.first() {
            if *conf >= self.config.min_confidence {
                (*top, *conf)
            } else {
                self.fallback_selection(complexity, available_agents, &characteristics)
            }
        } else {
            self.fallback_selection(complexity, available_agents, &characteristics)
        };
        
        // Calculate suggested agents
        let min_for_complexity = complexity.min_agents();
        let min_for_topology = topology.min_agents();
        let suggested = min_for_complexity.max(min_for_topology).min(available_agents);
        
        let mut reasons = Vec::new();
        if !scores.is_empty() {
            reasons.push(format!("Keyword analysis matched {:?}", topology));
        }
        reasons.push(format!("Task complexity: {:?}", complexity));
        reasons.push(format!("Available agents: {}", available_agents));
        
        RoutingDecision {
            topology,
            confidence,
            task_characteristics: characteristics,
            suggested_agents: suggested,
            reasons,
        }
    }

    /// Auto-select the best topology based on task analysis
    pub fn auto_select(&self, task: &str, available_agents: usize) -> EnhancedRoutingDecision {
        let complexity = self.detect_complexity(task);
        self.route(task, complexity, available_agents)
    }

    /// Detect task complexity from description
    fn detect_complexity(&self, task: &str) -> TaskComplexity {
        let task_lower = task.to_lowercase();
        
        if task_lower.contains("critical") || task_lower.contains("urgent") {
            TaskComplexity::Critical
        } else if task_lower.contains("complex") || task_lower.contains("security") {
            TaskComplexity::High
        } else if task_lower.contains("simple") || task_lower.contains("basic") {
            TaskComplexity::Low
        } else {
            TaskComplexity::Medium
        }
    }

    /// Detect task characteristics
    fn detect_characteristics(&self, task: &str) -> TaskCharacteristics {
        TaskCharacteristics {
            requires_decision: task.contains("decide") || task.contains("choose") || task.contains("select"),
            involves_risk: task.contains("security") || task.contains("risk") || task.contains("vulnerability"),
            sequential: task.contains("first") || task.contains("then") || task.contains("next"),
            benefits_from_diversity: task.contains("perspective") || task.contains("opinion") || task.contains("debate"),
            time_sensitive: task.contains("urgent") || task.contains("asap") || task.contains("quickly"),
        }
    }

    /// Fallback selection when keyword matching fails
    fn fallback_selection(
        &self,
        complexity: TaskComplexity,
        available_agents: usize,
        characteristics: &TaskCharacteristics,
    ) -> (Topology, f64) {
        // If only 1 agent, must use Solo
        if available_agents == 1 {
            return (Topology::Solo, 0.9);
        }
        
        // Risk tasks benefit from adversarial review
        if characteristics.involves_risk && available_agents >= Topology::Adversarial.min_agents() {
            return (Topology::Adversarial, 0.7);
        }
        
        // Decision tasks benefit from voting
        if characteristics.requires_decision && available_agents >= Topology::Voting.min_agents() {
            return (Topology::Voting, 0.7);
        }
        
        // Sequential tasks use pipeline
        if characteristics.sequential && available_agents >= Topology::Pipeline.min_agents() {
            return (Topology::Pipeline, 0.7);
        }
        
        // Default based on complexity
        match complexity {
            TaskComplexity::Low => (Topology::Solo, 0.6),
            TaskComplexity::Medium => {
                if available_agents >= 2 {
                    (Topology::Hierarchical, 0.6)
                } else {
                    (Topology::Solo, 0.5)
                }
            }
            TaskComplexity::High | TaskComplexity::Critical => {
                if available_agents >= Topology::Debate.min_agents() {
                    (Topology::Debate, 0.6)
                } else {
                    (self.config.default_topology, 0.5)
                }
            }
        }
    }

    /// Format a routing decision as a human-readable string
    pub fn format_decision(&self, decision: &RoutingDecision) -> String {
        format!(
            "Topology: {:?} (confidence: {:.0}%)\nSuggested agents: {}\nReasons:\n{}",
            decision.topology,
            decision.confidence * 100.0,
            decision.suggested_agents,
            decision.reasons.iter().map(|r| format!("  - {}", r)).collect::<Vec<_>>().join("\n")
        )
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

        assert!(decision.task_characteristics.sequential);
    }

    #[test]
    fn test_insufficient_agents() {
        let router = ProtocolRouter::new(RouterConfig::default());
        let decision = router.route(
            "Complex security analysis",
            TaskComplexity::High,
            1,
        );

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

        let decision = router.route("Choose the best option", TaskComplexity::Medium, 3);
        assert!(decision.task_characteristics.requires_decision);

        let decision = router.route(
            "Check for security vulnerabilities",
            TaskComplexity::Medium,
            3,
        );
        assert!(decision.task_characteristics.involves_risk);
    }

    #[test]
    fn test_suggested_agents_calculation() {
        let router = ProtocolRouter::new(RouterConfig::default());

        let decision = router.route("Complex task", TaskComplexity::High, 10);
        assert!(decision.suggested_agents >= TaskComplexity::High.min_agents());
        assert!(decision.suggested_agents <= 10);

        let decision = router.route("Complex task", TaskComplexity::High, 2);
        assert!(decision.suggested_agents <= 2);
    }
}
