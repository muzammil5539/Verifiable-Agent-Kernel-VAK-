//! Tree of Thoughts (ToT) Search Implementation (NSR-003)
//!
//! This module implements Monte Carlo Tree Search (MCTS) for reasoning exploration.
//! It enables systematic exploration of reasoning paths with backtracking when
//! the Process Reward Model (PRM) indicates poor quality steps.
//!
//! # Overview
//!
//! Tree of Thoughts combines:
//! - **MCTS**: Selection, Expansion, Simulation, Backpropagation
//! - **PRM Integration**: Use PRM scores to guide search
//! - **Backtracking**: Automatically backtrack on low-quality paths
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::reasoner::{TreeOfThoughts, TreeSearchConfig, MockPrm, SimpleThoughtGenerator};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a mock PRM and thought generator
//!     let prm = Arc::new(MockPrm::default());
//!     let generator = Arc::new(SimpleThoughtGenerator::default());
//!     
//!     // Create Tree of Thoughts search
//!     let config = TreeSearchConfig::default();
//!     let tot = TreeOfThoughts::new(prm, generator, config);
//!     
//!     // Search for the best reasoning path
//!     let result = tot.search("What is 2 + 2?", 5).await?;
//!     println!("Best path score: {}", result.best_score);
//!     
//!     Ok(())
//! }
//! ```

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

use super::{PrmError, ProcessRewardModel, ReasoningStep, ThoughtScore};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during tree search operations
#[derive(Debug, Error)]
pub enum TreeSearchError {
    /// PRM scoring failed
    #[error("PRM error: {0}")]
    PrmError(#[from] PrmError),

    /// Search was terminated due to max iterations
    #[error("Search terminated: max iterations ({0}) reached")]
    MaxIterationsReached(usize),

    /// Search was terminated due to timeout
    #[error("Search timeout after {0} ms")]
    Timeout(u64),

    /// No valid path found
    #[error("No valid path found to solution")]
    NoValidPath,

    /// Tree is empty or corrupted
    #[error("Tree is empty or corrupted")]
    EmptyTree,

    /// Invalid node reference
    #[error("Invalid node reference: {0}")]
    InvalidNode(NodeId),

    /// Expansion failed
    #[error("Expansion failed: {0}")]
    ExpansionFailed(String),

    /// Generation callback not provided
    #[error("Thought generator not configured")]
    NoThoughtGenerator,
}

/// Result type for tree search operations
pub type TreeSearchResult<T> = Result<T, TreeSearchError>;

// ============================================================================
// Node Types
// ============================================================================

/// Unique identifier for a node in the search tree
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub usize);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Node({})", self.0)
    }
}

/// Statistics for a tree node
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStats {
    /// Number of times this node was visited
    pub visits: usize,
    /// Total reward accumulated through this node
    pub total_reward: f64,
    /// Best child score observed
    pub best_child_score: f64,
    /// Number of times simulations passed through this node
    pub simulation_count: usize,
}

impl NodeStats {
    /// Calculate the average reward for this node
    pub fn average_reward(&self) -> f64 {
        if self.visits == 0 {
            0.0
        } else {
            self.total_reward / self.visits as f64
        }
    }

    /// Update statistics after a simulation
    pub fn update(&mut self, reward: f64) {
        self.visits += 1;
        self.total_reward += reward;
        self.simulation_count += 1;
        if reward > self.best_child_score {
            self.best_child_score = reward;
        }
    }
}

/// State of a node in the search tree
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeState {
    /// Node is unexplored
    Unexplored,
    /// Node is being expanded
    Expanding,
    /// Node is fully expanded
    Expanded,
    /// Node leads to a solution
    Terminal,
    /// Node leads to a dead end
    DeadEnd,
}

impl Default for NodeState {
    fn default() -> Self {
        NodeState::Unexplored
    }
}

/// A node in the Monte Carlo Tree Search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchNode {
    /// Unique identifier for this node
    pub id: NodeId,
    /// Parent node (None for root)
    pub parent: Option<NodeId>,
    /// Children nodes
    pub children: Vec<NodeId>,
    /// The reasoning step at this node
    pub step: ReasoningStep,
    /// PRM score for this step
    pub score: Option<ThoughtScore>,
    /// Statistics for MCTS
    pub stats: NodeStats,
    /// Current state of the node
    pub state: NodeState,
    /// Depth in the tree (root = 0)
    pub depth: usize,
}

impl SearchNode {
    /// Create a new root node
    pub fn root(id: NodeId, context: impl Into<String>) -> Self {
        Self {
            id,
            parent: None,
            children: Vec::new(),
            step: ReasoningStep::new(0, context),
            score: None,
            stats: NodeStats::default(),
            state: NodeState::Unexplored,
            depth: 0,
        }
    }

    /// Create a new child node
    pub fn child(id: NodeId, parent: NodeId, step: ReasoningStep, depth: usize) -> Self {
        Self {
            id,
            parent: Some(parent),
            children: Vec::new(),
            step,
            score: None,
            stats: NodeStats::default(),
            state: NodeState::Unexplored,
            depth,
        }
    }

    /// Check if this node has unexplored children
    pub fn is_fully_expanded(&self) -> bool {
        matches!(self.state, NodeState::Expanded | NodeState::Terminal | NodeState::DeadEnd)
    }

    /// Check if this node is a leaf (no children)
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Calculate UCT (Upper Confidence Bound for Trees) value
    ///
    /// UCT = average_reward + C * sqrt(ln(parent_visits) / visits)
    pub fn uct_value(&self, parent_visits: usize, exploration_constant: f64) -> f64 {
        if self.stats.visits == 0 {
            f64::INFINITY // Encourage exploration of unvisited nodes
        } else {
            let exploitation = self.stats.average_reward();
            let exploration = exploration_constant
                * ((parent_visits as f64).ln() / self.stats.visits as f64).sqrt();
            exploitation + exploration
        }
    }
}

// ============================================================================
// Search Tree
// ============================================================================

/// The Monte Carlo Tree Search tree structure
#[derive(Debug)]
pub struct SearchTree {
    /// All nodes in the tree
    nodes: HashMap<NodeId, SearchNode>,
    /// Root node ID
    root: NodeId,
    /// Counter for generating unique node IDs
    next_id: AtomicUsize,
}

impl SearchTree {
    /// Create a new search tree with the given context
    pub fn new(context: impl Into<String>) -> Self {
        let root_id = NodeId(0);
        let root_node = SearchNode::root(root_id, context);
        
        let mut nodes = HashMap::new();
        nodes.insert(root_id, root_node);
        
        Self {
            nodes,
            root: root_id,
            next_id: AtomicUsize::new(1),
        }
    }

    /// Get the root node ID
    pub fn root(&self) -> NodeId {
        self.root
    }

    /// Get a node by ID
    pub fn get(&self, id: NodeId) -> Option<&SearchNode> {
        self.nodes.get(&id)
    }

    /// Get a mutable node by ID
    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut SearchNode> {
        self.nodes.get_mut(&id)
    }

    /// Generate a new unique node ID
    pub fn next_node_id(&self) -> NodeId {
        NodeId(self.next_id.fetch_add(1, Ordering::SeqCst))
    }

    /// Add a child node to a parent
    pub fn add_child(&mut self, parent_id: NodeId, step: ReasoningStep) -> TreeSearchResult<NodeId> {
        let parent = self.nodes.get(&parent_id)
            .ok_or(TreeSearchError::InvalidNode(parent_id))?;
        let depth = parent.depth + 1;
        
        let child_id = self.next_node_id();
        let child = SearchNode::child(child_id, parent_id, step, depth);
        
        self.nodes.insert(child_id, child);
        
        if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.children.push(child_id);
        }
        
        Ok(child_id)
    }

    /// Get the path from root to a node
    pub fn path_to(&self, node_id: NodeId) -> Vec<NodeId> {
        let mut path = Vec::new();
        let mut current = Some(node_id);
        
        while let Some(id) = current {
            path.push(id);
            current = self.nodes.get(&id).and_then(|n| n.parent);
        }
        
        path.reverse();
        path
    }

    /// Get all reasoning steps along a path
    pub fn steps_along_path(&self, path: &[NodeId]) -> Vec<ReasoningStep> {
        path.iter()
            .filter_map(|id| self.nodes.get(id))
            .map(|n| n.step.clone())
            .collect()
    }

    /// Get the total number of nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the maximum depth reached
    pub fn max_depth(&self) -> usize {
        self.nodes.values().map(|n| n.depth).max().unwrap_or(0)
    }

    /// Get all leaf nodes
    pub fn leaves(&self) -> Vec<NodeId> {
        self.nodes.values()
            .filter(|n| n.is_leaf())
            .map(|n| n.id)
            .collect()
    }

    /// Get the best leaf (highest average reward)
    pub fn best_leaf(&self) -> Option<NodeId> {
        self.nodes.values()
            .filter(|n| n.is_leaf() && n.stats.visits > 0)
            .max_by(|a, b| {
                a.stats.average_reward()
                    .partial_cmp(&b.stats.average_reward())
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|n| n.id)
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for Tree of Thoughts search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSearchConfig {
    /// Maximum number of MCTS iterations
    pub max_iterations: usize,
    /// Maximum depth of the search tree
    pub max_depth: usize,
    /// Number of children to generate during expansion
    pub expansion_breadth: usize,
    /// Exploration constant for UCT (typically sqrt(2))
    pub exploration_constant: f64,
    /// Minimum score threshold for continuing a path
    pub score_threshold: f64,
    /// Number of simulations per expansion
    pub simulations_per_expansion: usize,
    /// Whether to use progressive widening
    pub progressive_widening: bool,
    /// Progressive widening alpha parameter
    pub pw_alpha: f64,
    /// Timeout in milliseconds (0 = no timeout)
    pub timeout_ms: u64,
    /// Whether to enable early termination on high-confidence solution
    pub early_termination: bool,
    /// Score threshold for early termination
    pub early_termination_threshold: f64,
}

impl Default for TreeSearchConfig {
    fn default() -> Self {
        Self {
            max_iterations: 100,
            max_depth: 10,
            expansion_breadth: 3,
            exploration_constant: 1.414, // sqrt(2)
            score_threshold: 0.3,
            simulations_per_expansion: 5,
            progressive_widening: true,
            pw_alpha: 0.5,
            timeout_ms: 30000, // 30 seconds
            early_termination: true,
            early_termination_threshold: 0.95,
        }
    }
}

impl TreeSearchConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of iterations
    pub fn with_max_iterations(mut self, iterations: usize) -> Self {
        self.max_iterations = iterations;
        self
    }

    /// Set the maximum depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set the expansion breadth
    pub fn with_expansion_breadth(mut self, breadth: usize) -> Self {
        self.expansion_breadth = breadth;
        self
    }

    /// Set the exploration constant
    pub fn with_exploration_constant(mut self, constant: f64) -> Self {
        self.exploration_constant = constant;
        self
    }

    /// Set the score threshold
    pub fn with_score_threshold(mut self, threshold: f64) -> Self {
        self.score_threshold = threshold;
        self
    }

    /// Set the timeout in milliseconds
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Enable or disable early termination
    pub fn with_early_termination(mut self, enabled: bool, threshold: f64) -> Self {
        self.early_termination = enabled;
        self.early_termination_threshold = threshold;
        self
    }
}

// ============================================================================
// Search Result
// ============================================================================

/// Result of a Tree of Thoughts search
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResult {
    /// The best reasoning path found
    pub best_path: Vec<ReasoningStep>,
    /// The score of the best path
    pub best_score: f64,
    /// All scores for steps in the best path
    pub path_scores: Vec<ThoughtScore>,
    /// Total number of iterations performed
    pub iterations: usize,
    /// Total number of nodes explored
    pub nodes_explored: usize,
    /// Maximum depth reached
    pub max_depth_reached: usize,
    /// Total time taken in milliseconds
    pub time_ms: u64,
    /// Whether the search terminated early
    pub early_terminated: bool,
    /// Alternative paths considered (top 3)
    pub alternative_paths: Vec<(Vec<ReasoningStep>, f64)>,
}

impl SearchResult {
    /// Get the final reasoning step
    pub fn final_step(&self) -> Option<&ReasoningStep> {
        self.best_path.last()
    }

    /// Get the average score across all steps
    pub fn average_score(&self) -> f64 {
        if self.path_scores.is_empty() {
            0.0
        } else {
            self.path_scores.iter().map(|s| s.score).sum::<f64>() / self.path_scores.len() as f64
        }
    }

    /// Check if the search found a high-quality solution
    pub fn is_high_quality(&self, threshold: f64) -> bool {
        self.best_score >= threshold
    }
}

// ============================================================================
// Thought Generator Trait
// ============================================================================

/// Trait for generating candidate thoughts during expansion
#[async_trait]
pub trait ThoughtGenerator: Send + Sync {
    /// Generate candidate thoughts for the next step
    ///
    /// # Arguments
    /// * `context` - The original problem/task context
    /// * `previous_steps` - The reasoning steps so far
    /// * `num_candidates` - Number of candidates to generate
    ///
    /// # Returns
    /// A list of candidate reasoning steps
    async fn generate_thoughts(
        &self,
        context: &str,
        previous_steps: &[ReasoningStep],
        num_candidates: usize,
    ) -> TreeSearchResult<Vec<ReasoningStep>>;

    /// Check if a state is terminal (solved or dead-end)
    ///
    /// # Arguments
    /// * `context` - The original problem/task context
    /// * `steps` - The reasoning steps so far
    ///
    /// # Returns
    /// `Some(true)` if solved, `Some(false)` if dead-end, `None` if not terminal
    async fn is_terminal(
        &self,
        context: &str,
        steps: &[ReasoningStep],
    ) -> TreeSearchResult<Option<bool>>;
}

// ============================================================================
// Simple Thought Generator (for testing)
// ============================================================================

/// A simple thought generator for testing purposes
pub struct SimpleThoughtGenerator {
    /// Template for generating thoughts
    pub thought_template: String,
}

impl Default for SimpleThoughtGenerator {
    fn default() -> Self {
        Self {
            thought_template: "Step {step_number}: Continue reasoning about {context}".to_string(),
        }
    }
}

#[async_trait]
impl ThoughtGenerator for SimpleThoughtGenerator {
    async fn generate_thoughts(
        &self,
        context: &str,
        previous_steps: &[ReasoningStep],
        num_candidates: usize,
    ) -> TreeSearchResult<Vec<ReasoningStep>> {
        let next_step_number = previous_steps.len() + 1;
        let mut candidates = Vec::with_capacity(num_candidates);
        
        for i in 0..num_candidates {
            let thought = self.thought_template
                .replace("{step_number}", &next_step_number.to_string())
                .replace("{context}", context)
                .replace("{variant}", &i.to_string());
            
            let step = ReasoningStep::new(next_step_number, thought)
                .with_action(format!("Candidate action {}", i));
            
            candidates.push(step);
        }
        
        Ok(candidates)
    }

    async fn is_terminal(
        &self,
        _context: &str,
        steps: &[ReasoningStep],
    ) -> TreeSearchResult<Option<bool>> {
        // Simple heuristic: terminal after 10 steps
        if steps.len() >= 10 {
            Ok(Some(true))
        } else {
            Ok(None)
        }
    }
}

// ============================================================================
// Tree of Thoughts Search
// ============================================================================

/// Tree of Thoughts (ToT) search implementation using MCTS
///
/// This struct orchestrates the MCTS algorithm with PRM integration
/// for exploring and evaluating reasoning paths.
pub struct TreeOfThoughts<P: ProcessRewardModel, G: ThoughtGenerator> {
    /// The Process Reward Model for scoring steps
    prm: Arc<P>,
    /// The thought generator for expansion
    generator: Arc<G>,
    /// Configuration for the search
    config: TreeSearchConfig,
}

impl<P: ProcessRewardModel, G: ThoughtGenerator> TreeOfThoughts<P, G> {
    /// Create a new Tree of Thoughts search
    pub fn new(prm: Arc<P>, generator: Arc<G>, config: TreeSearchConfig) -> Self {
        Self {
            prm,
            generator,
            config,
        }
    }

    /// Perform MCTS search for the best reasoning path
    ///
    /// # Arguments
    /// * `context` - The problem/task to reason about
    /// * `max_steps` - Maximum number of reasoning steps
    ///
    /// # Returns
    /// * `Ok(SearchResult)` - The search result with the best path
    /// * `Err(TreeSearchError)` - If search fails
    pub async fn search(&self, context: &str, max_steps: usize) -> TreeSearchResult<SearchResult> {
        let start_time = std::time::Instant::now();
        let timeout = if self.config.timeout_ms > 0 {
            Some(std::time::Duration::from_millis(self.config.timeout_ms))
        } else {
            None
        };

        let tree = Arc::new(RwLock::new(SearchTree::new(context)));
        let mut iterations = 0;
        let mut early_terminated = false;

        // Main MCTS loop
        while iterations < self.config.max_iterations {
            // Check timeout
            if let Some(t) = timeout {
                if start_time.elapsed() > t {
                    break;
                }
            }

            // 1. Selection: Select a leaf node using UCT
            let selected = self.select(&tree).await?;

            // 2. Expansion: Expand the selected node
            let expanded = self.expand(&tree, selected, context).await?;

            // 3. Simulation: Run simulation from expanded node
            let reward = self.simulate(&tree, expanded, context, max_steps).await?;

            // 4. Backpropagation: Update statistics along the path
            self.backpropagate(&tree, expanded, reward).await?;

            iterations += 1;

            // Check for early termination
            if self.config.early_termination {
                let tree_read = tree.read().await;
                if let Some(best) = tree_read.best_leaf() {
                    if let Some(node) = tree_read.get(best) {
                        if node.stats.average_reward() >= self.config.early_termination_threshold {
                            early_terminated = true;
                            break;
                        }
                    }
                }
            }
        }

        // Extract the best path
        let tree_read = tree.read().await;
        let best_leaf = tree_read.best_leaf()
            .ok_or(TreeSearchError::NoValidPath)?;
        
        let path = tree_read.path_to(best_leaf);
        let best_path = tree_read.steps_along_path(&path);
        
        // Collect scores
        let mut path_scores = Vec::new();
        let mut best_score: f64 = 0.0;
        for id in &path {
            if let Some(node) = tree_read.get(*id) {
                if let Some(ref score) = node.score {
                    path_scores.push(score.clone());
                    best_score = best_score.max(score.score);
                }
            }
        }

        // Get alternative paths
        let mut alternative_paths = Vec::new();
        let leaves: Vec<_> = tree_read.leaves().into_iter()
            .filter(|&id| id != best_leaf)
            .take(3)
            .collect();
        
        for leaf_id in leaves {
            if let Some(node) = tree_read.get(leaf_id) {
                let alt_path = tree_read.path_to(leaf_id);
                let alt_steps = tree_read.steps_along_path(&alt_path);
                alternative_paths.push((alt_steps, node.stats.average_reward()));
            }
        }

        Ok(SearchResult {
            best_path,
            best_score,
            path_scores,
            iterations,
            nodes_explored: tree_read.node_count(),
            max_depth_reached: tree_read.max_depth(),
            time_ms: start_time.elapsed().as_millis() as u64,
            early_terminated,
            alternative_paths,
        })
    }

    /// Selection phase: Select a leaf node using UCT
    async fn select(&self, tree: &Arc<RwLock<SearchTree>>) -> TreeSearchResult<NodeId> {
        let tree_read = tree.read().await;
        let mut current = tree_read.root();

        loop {
            let node = tree_read.get(current)
                .ok_or(TreeSearchError::InvalidNode(current))?;

            // If this node is a leaf or not fully expanded, select it
            if node.is_leaf() || !node.is_fully_expanded() {
                return Ok(current);
            }

            // Otherwise, select the best child using UCT
            let parent_visits = node.stats.visits;
            let best_child = node.children.iter()
                .filter_map(|&id| tree_read.get(id))
                .max_by(|a, b| {
                    a.uct_value(parent_visits, self.config.exploration_constant)
                        .partial_cmp(&b.uct_value(parent_visits, self.config.exploration_constant))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|n| n.id);

            match best_child {
                Some(child_id) => current = child_id,
                None => return Ok(current),
            }
        }
    }

    /// Expansion phase: Expand a node by generating child thoughts
    async fn expand(
        &self,
        tree: &Arc<RwLock<SearchTree>>,
        node_id: NodeId,
        context: &str,
    ) -> TreeSearchResult<NodeId> {
        // Get current path
        let previous_steps = {
            let tree_read = tree.read().await;
            let path = tree_read.path_to(node_id);
            tree_read.steps_along_path(&path)
        };

        // Check depth limit
        if previous_steps.len() >= self.config.max_depth {
            let mut tree_write = tree.write().await;
            if let Some(node) = tree_write.get_mut(node_id) {
                node.state = NodeState::DeadEnd;
            }
            return Ok(node_id);
        }

        // Check if terminal
        if let Some(is_solved) = self.generator.is_terminal(context, &previous_steps).await? {
            let mut tree_write = tree.write().await;
            if let Some(node) = tree_write.get_mut(node_id) {
                node.state = if is_solved {
                    NodeState::Terminal
                } else {
                    NodeState::DeadEnd
                };
            }
            return Ok(node_id);
        }

        // Generate candidate thoughts
        let candidates = self.generator
            .generate_thoughts(context, &previous_steps, self.config.expansion_breadth)
            .await?;

        // Add children and score them
        let mut best_child = node_id;
        let mut best_score = 0.0;

        for step in candidates {
            let child_id = {
                let mut tree_write = tree.write().await;
                tree_write.add_child(node_id, step.clone())?
            };

            // Score the new step
            let score = self.prm.score_step(&step, context).await?;
            
            // Update the child with the score
            {
                let mut tree_write = tree.write().await;
                if let Some(child) = tree_write.get_mut(child_id) {
                    child.score = Some(score.clone());
                    
                    // Check if score is below threshold
                    if score.score < self.config.score_threshold {
                        child.state = NodeState::DeadEnd;
                    } else if score.score > best_score {
                        best_score = score.score;
                        best_child = child_id;
                    }
                }
            }
        }

        // Mark parent as expanded
        {
            let mut tree_write = tree.write().await;
            if let Some(node) = tree_write.get_mut(node_id) {
                node.state = NodeState::Expanded;
            }
        }

        Ok(best_child)
    }

    /// Simulation phase: Estimate the value of a node through simulation
    async fn simulate(
        &self,
        tree: &Arc<RwLock<SearchTree>>,
        node_id: NodeId,
        context: &str,
        max_steps: usize,
    ) -> TreeSearchResult<f64> {
        let tree_read = tree.read().await;
        let node = tree_read.get(node_id)
            .ok_or(TreeSearchError::InvalidNode(node_id))?;

        // If we have a score, use it as the reward
        if let Some(ref score) = node.score {
            return Ok(score.score);
        }

        // Otherwise, score the current step
        let score = self.prm.score_step(&node.step, context).await?;
        Ok(score.score)
    }

    /// Backpropagation phase: Update statistics along the path
    async fn backpropagate(
        &self,
        tree: &Arc<RwLock<SearchTree>>,
        node_id: NodeId,
        reward: f64,
    ) -> TreeSearchResult<()> {
        let path = {
            let tree_read = tree.read().await;
            tree_read.path_to(node_id)
        };

        let mut tree_write = tree.write().await;
        for id in path {
            if let Some(node) = tree_write.get_mut(id) {
                node.stats.update(reward);
            }
        }

        Ok(())
    }

    /// Get the current configuration
    pub fn config(&self) -> &TreeSearchConfig {
        &self.config
    }

    /// Update the configuration
    pub fn set_config(&mut self, config: TreeSearchConfig) {
        self.config = config;
    }
}

// ============================================================================
// Builder Pattern for TreeOfThoughts
// ============================================================================

/// Builder for creating TreeOfThoughts instances
pub struct TreeOfThoughtsBuilder<P: ProcessRewardModel> {
    prm: Arc<P>,
    config: TreeSearchConfig,
}

impl<P: ProcessRewardModel> TreeOfThoughtsBuilder<P> {
    /// Create a new builder with the given PRM
    pub fn new(prm: Arc<P>) -> Self {
        Self {
            prm,
            config: TreeSearchConfig::default(),
        }
    }

    /// Set the configuration
    pub fn with_config(mut self, config: TreeSearchConfig) -> Self {
        self.config = config;
        self
    }

    /// Set the maximum iterations
    pub fn with_max_iterations(mut self, iterations: usize) -> Self {
        self.config.max_iterations = iterations;
        self
    }

    /// Set the maximum depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.config.max_depth = depth;
        self
    }

    /// Set the expansion breadth
    pub fn with_expansion_breadth(mut self, breadth: usize) -> Self {
        self.config.expansion_breadth = breadth;
        self
    }

    /// Set the exploration constant
    pub fn with_exploration_constant(mut self, constant: f64) -> Self {
        self.config.exploration_constant = constant;
        self
    }

    /// Build the TreeOfThoughts with the given thought generator
    pub fn build<G: ThoughtGenerator>(self, generator: Arc<G>) -> TreeOfThoughts<P, G> {
        TreeOfThoughts::new(self.prm, generator, self.config)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reasoner::MockPrm;

    #[test]
    fn test_node_id() {
        let id = NodeId(42);
        assert_eq!(id.0, 42);
        assert_eq!(format!("{}", id), "Node(42)");
    }

    #[test]
    fn test_node_stats() {
        let mut stats = NodeStats::default();
        assert_eq!(stats.visits, 0);
        assert_eq!(stats.average_reward(), 0.0);

        stats.update(0.8);
        assert_eq!(stats.visits, 1);
        assert_eq!(stats.total_reward, 0.8);
        assert_eq!(stats.average_reward(), 0.8);

        stats.update(0.6);
        assert_eq!(stats.visits, 2);
        assert_eq!(stats.total_reward, 1.4);
        assert_eq!(stats.average_reward(), 0.7);
    }

    #[test]
    fn test_node_state_default() {
        let state = NodeState::default();
        assert_eq!(state, NodeState::Unexplored);
    }

    #[test]
    fn test_search_node_root() {
        let id = NodeId(0);
        let node = SearchNode::root(id, "Test context");
        
        assert_eq!(node.id, id);
        assert!(node.parent.is_none());
        assert!(node.children.is_empty());
        assert_eq!(node.depth, 0);
        assert!(node.is_leaf());
    }

    #[test]
    fn test_search_node_child() {
        let parent_id = NodeId(0);
        let child_id = NodeId(1);
        let step = ReasoningStep::new(1, "Child thought");
        let node = SearchNode::child(child_id, parent_id, step, 1);
        
        assert_eq!(node.id, child_id);
        assert_eq!(node.parent, Some(parent_id));
        assert_eq!(node.depth, 1);
    }

    #[test]
    fn test_uct_value() {
        let mut node = SearchNode::root(NodeId(0), "Test");
        
        // Unvisited node should have infinite UCT
        assert!(node.uct_value(10, 1.414).is_infinite());
        
        // After visits, UCT should be finite
        node.stats.update(0.7);
        let uct = node.uct_value(10, 1.414);
        assert!(uct.is_finite());
        assert!(uct > 0.0);
    }

    #[test]
    fn test_search_tree_creation() {
        let tree = SearchTree::new("Test problem");
        
        assert_eq!(tree.root(), NodeId(0));
        assert_eq!(tree.node_count(), 1);
        assert_eq!(tree.max_depth(), 0);
    }

    #[test]
    fn test_search_tree_add_child() {
        let mut tree = SearchTree::new("Test problem");
        let step = ReasoningStep::new(1, "First step");
        
        let child_id = tree.add_child(NodeId(0), step).unwrap();
        
        assert_eq!(child_id, NodeId(1));
        assert_eq!(tree.node_count(), 2);
        assert_eq!(tree.max_depth(), 1);
        
        let root = tree.get(NodeId(0)).unwrap();
        assert!(root.children.contains(&child_id));
    }

    #[test]
    fn test_search_tree_path() {
        let mut tree = SearchTree::new("Test problem");
        
        let step1 = ReasoningStep::new(1, "Step 1");
        let child1 = tree.add_child(NodeId(0), step1).unwrap();
        
        let step2 = ReasoningStep::new(2, "Step 2");
        let child2 = tree.add_child(child1, step2).unwrap();
        
        let path = tree.path_to(child2);
        assert_eq!(path, vec![NodeId(0), child1, child2]);
    }

    #[test]
    fn test_tree_search_config_default() {
        let config = TreeSearchConfig::default();
        
        assert_eq!(config.max_iterations, 100);
        assert_eq!(config.max_depth, 10);
        assert_eq!(config.expansion_breadth, 3);
        assert!((config.exploration_constant - 1.414).abs() < 0.001);
    }

    #[test]
    fn test_tree_search_config_builder() {
        let config = TreeSearchConfig::new()
            .with_max_iterations(50)
            .with_max_depth(5)
            .with_expansion_breadth(5)
            .with_timeout(5000);
        
        assert_eq!(config.max_iterations, 50);
        assert_eq!(config.max_depth, 5);
        assert_eq!(config.expansion_breadth, 5);
        assert_eq!(config.timeout_ms, 5000);
    }

    #[test]
    fn test_search_result() {
        let result = SearchResult {
            best_path: vec![
                ReasoningStep::new(1, "Step 1"),
                ReasoningStep::new(2, "Step 2"),
            ],
            best_score: 0.9,
            path_scores: vec![
                ThoughtScore::new(0.8, 0.9, "Good").unwrap(),
                ThoughtScore::new(0.9, 0.95, "Excellent").unwrap(),
            ],
            iterations: 50,
            nodes_explored: 25,
            max_depth_reached: 5,
            time_ms: 1000,
            early_terminated: false,
            alternative_paths: Vec::new(),
        };
        
        assert!((result.average_score() - 0.85).abs() < 1e-10);
        assert!(result.is_high_quality(0.8));
        assert!(!result.is_high_quality(0.95));
        assert_eq!(result.final_step().unwrap().step_number, 2);
    }

    #[tokio::test]
    async fn test_simple_thought_generator() {
        let generator = SimpleThoughtGenerator::default();
        
        let thoughts = generator
            .generate_thoughts("Test problem", &[], 3)
            .await
            .unwrap();
        
        assert_eq!(thoughts.len(), 3);
        assert_eq!(thoughts[0].step_number, 1);
    }

    #[tokio::test]
    async fn test_simple_thought_generator_terminal() {
        let generator = SimpleThoughtGenerator::default();
        
        // Not terminal with few steps
        let result = generator
            .is_terminal("Test", &[ReasoningStep::new(1, "Step 1")])
            .await
            .unwrap();
        assert!(result.is_none());
        
        // Terminal with 10+ steps
        let many_steps: Vec<_> = (1..=10)
            .map(|i| ReasoningStep::new(i, format!("Step {}", i)))
            .collect();
        let result = generator.is_terminal("Test", &many_steps).await.unwrap();
        assert_eq!(result, Some(true));
    }

    #[tokio::test]
    async fn test_tree_of_thoughts_creation() {
        let prm = Arc::new(MockPrm::default());
        let generator = Arc::new(SimpleThoughtGenerator::default());
        let config = TreeSearchConfig::default();
        
        let tot = TreeOfThoughts::new(prm, generator, config.clone());
        assert_eq!(tot.config().max_iterations, config.max_iterations);
    }

    #[tokio::test]
    async fn test_tree_of_thoughts_search() {
        let prm = Arc::new(MockPrm::new(0.8, 0.9));
        
        let generator = Arc::new(SimpleThoughtGenerator::default());
        
        let config = TreeSearchConfig::new()
            .with_max_iterations(10)
            .with_max_depth(3)
            .with_expansion_breadth(2);
        
        let tot = TreeOfThoughts::new(prm, generator, config);
        
        let result = tot.search("What is 2 + 2?", 5).await.unwrap();
        
        assert!(result.nodes_explored > 1);
        assert!(result.iterations <= 10);
        assert!(result.best_score > 0.0);
    }

    #[tokio::test]
    async fn test_tree_of_thoughts_builder() {
        let prm = Arc::new(MockPrm::default());
        let generator = Arc::new(SimpleThoughtGenerator::default());
        
        let tot = TreeOfThoughtsBuilder::new(prm)
            .with_max_iterations(50)
            .with_max_depth(5)
            .build(generator);
        
        assert_eq!(tot.config().max_iterations, 50);
        assert_eq!(tot.config().max_depth, 5);
    }

    #[test]
    fn test_search_tree_leaves() {
        let mut tree = SearchTree::new("Test");
        
        // Root is the only leaf initially
        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 1);
        
        // Add children
        let step1 = ReasoningStep::new(1, "Step 1");
        let child1 = tree.add_child(NodeId(0), step1).unwrap();
        
        let step2 = ReasoningStep::new(2, "Step 2");
        let _child2 = tree.add_child(NodeId(0), step2).unwrap();
        
        // Now we have 2 leaves (the children), root is not a leaf
        let leaves = tree.leaves();
        assert_eq!(leaves.len(), 2);
        assert!(!leaves.contains(&NodeId(0)));
        assert!(leaves.contains(&child1));
    }

    #[tokio::test]
    async fn test_backpropagation() {
        let prm = Arc::new(MockPrm::default());
        let generator = Arc::new(SimpleThoughtGenerator::default());
        let config = TreeSearchConfig::default();
        
        let tot = TreeOfThoughts::new(prm, generator, config);
        
        // Create a simple tree
        let tree = Arc::new(RwLock::new(SearchTree::new("Test")));
        
        {
            let mut tree_write = tree.write().await;
            let step = ReasoningStep::new(1, "Step 1");
            tree_write.add_child(NodeId(0), step).unwrap();
        }
        
        // Backpropagate a reward
        tot.backpropagate(&tree, NodeId(1), 0.8).await.unwrap();
        
        // Check that stats were updated
        let tree_read = tree.read().await;
        let root = tree_read.get(NodeId(0)).unwrap();
        assert_eq!(root.stats.visits, 1);
        assert!((root.stats.total_reward - 0.8).abs() < 0.001);
    }
}
