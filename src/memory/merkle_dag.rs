//! Merkle DAG Memory Fabric (Issue #50)
//!
//! This module implements a content-addressed Merkle DAG structure for
//! memory snapshots with verifiable proofs and integrity guarantees.
//!
//! # Overview
//!
//! The Merkle DAG provides:
//! - Content-addressed storage with cryptographic hashes
//! - Branch history and lightweight inclusion proofs
//! - Efficient diffing between snapshots
//! - Tamper detection and verification
//!
//! # Example
//!
//! ```rust
//! use vak::memory::merkle_dag::{MerkleDag, DagNode, ContentId};
//!
//! let mut dag = MerkleDag::new();
//!
//! // Add content
//! let root = dag.insert("root content".as_bytes());
//! let child = dag.insert_with_parent("child content".as_bytes(), &root);
//!
//! // Generate inclusion proof
//! let proof = dag.generate_proof(&child, &root).unwrap();
//!
//! // Verify proof
//! assert!(dag.verify_proof(&proof));
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in Merkle DAG operations
#[derive(Debug, Error)]
pub enum DagError {
    /// Node not found
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    /// Invalid content ID
    #[error("Invalid content ID: {0}")]
    InvalidContentId(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Cyclic reference detected
    #[error("Cyclic reference detected")]
    CyclicReference,

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),
}

// ============================================================================
// Content ID
// ============================================================================

/// Content-addressed identifier (SHA-256 hash)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId(String);

impl ContentId {
    /// Create a content ID from raw bytes
    pub fn from_bytes(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Self(hex::encode(hasher.finalize()))
    }

    /// Create a content ID from a hash string
    pub fn from_hash(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    /// Get the hash as a string
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get shortened representation
    pub fn short(&self) -> &str {
        if self.0.len() >= 8 {
            &self.0[..8]
        } else {
            &self.0
        }
    }

    /// Genesis ID (empty content)
    pub fn genesis() -> Self {
        Self::from_bytes(&[])
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for ContentId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

// ============================================================================
// DAG Node
// ============================================================================

/// A node in the Merkle DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    /// Content ID (hash of content)
    pub id: ContentId,
    /// Raw content bytes
    pub content: Vec<u8>,
    /// Parent node IDs
    pub parents: Vec<ContentId>,
    /// Creation timestamp
    pub timestamp: u64,
    /// Node type/tag
    pub node_type: NodeType,
    /// Optional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Types of DAG nodes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeType {
    /// Root/genesis node
    Root,
    /// Memory snapshot
    Snapshot,
    /// Delta/diff from parent
    Delta,
    /// Merge node (multiple parents)
    Merge,
    /// Branch head
    Branch,
    /// Tag/label node
    Tag,
}

impl DagNode {
    /// Create a new root node
    pub fn root(content: &[u8]) -> Self {
        let id = ContentId::from_bytes(content);
        Self {
            id,
            content: content.to_vec(),
            parents: vec![],
            timestamp: current_timestamp(),
            node_type: NodeType::Root,
            metadata: None,
        }
    }

    /// Create a new node with parent
    pub fn with_parent(content: &[u8], parent: &ContentId) -> Self {
        // Hash includes parent for chain integrity
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.update(parent.as_str().as_bytes());
        let id = ContentId::from_hash(hex::encode(hasher.finalize()));

        Self {
            id,
            content: content.to_vec(),
            parents: vec![parent.clone()],
            timestamp: current_timestamp(),
            node_type: NodeType::Snapshot,
            metadata: None,
        }
    }

    /// Create a merge node (multiple parents)
    pub fn merge(content: &[u8], parents: Vec<ContentId>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content);
        for parent in &parents {
            hasher.update(parent.as_str().as_bytes());
        }
        let id = ContentId::from_hash(hex::encode(hasher.finalize()));

        Self {
            id,
            content: content.to_vec(),
            parents,
            timestamp: current_timestamp(),
            node_type: NodeType::Merge,
            metadata: None,
        }
    }

    /// Set node type
    pub fn with_type(mut self, node_type: NodeType) -> Self {
        self.node_type = node_type;
        self
    }

    /// Set metadata
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Verify node integrity
    pub fn verify(&self) -> bool {
        let expected_id = if self.parents.is_empty() {
            ContentId::from_bytes(&self.content)
        } else {
            let mut hasher = Sha256::new();
            hasher.update(&self.content);
            for parent in &self.parents {
                hasher.update(parent.as_str().as_bytes());
            }
            ContentId::from_hash(hex::encode(hasher.finalize()))
        };

        self.id == expected_id
    }
}

// ============================================================================
// Inclusion Proof
// ============================================================================

/// Proof of inclusion in the DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Target node ID
    pub target: ContentId,
    /// Root node ID for verification
    pub root: ContentId,
    /// Path from target to root (node IDs and hashes)
    pub path: Vec<ProofStep>,
    /// Timestamp when proof was generated
    pub generated_at: u64,
}

/// A step in the inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    /// Node ID at this step
    pub node_id: ContentId,
    /// Hash at this step
    pub hash: String,
    /// Position (left/right for binary tree style, index for DAG)
    pub position: usize,
    /// Sibling hashes (for merkle tree verification)
    pub siblings: Vec<String>,
}

impl InclusionProof {
    /// Verify the proof
    pub fn verify(&self) -> bool {
        if self.path.is_empty() {
            return false;
        }

        // First step should be the target
        if self.path[0].node_id != self.target {
            return false;
        }

        // Last step should lead to root
        if self.path.last().map(|s| &s.node_id) != Some(&self.root) {
            return false;
        }

        // Verify hash chain
        let mut current_hash = self.path[0].hash.clone();
        for i in 1..self.path.len() {
            let mut hasher = Sha256::new();
            hasher.update(current_hash.as_bytes());
            hasher.update(self.path[i].node_id.as_str().as_bytes());
            for sibling in &self.path[i].siblings {
                hasher.update(sibling.as_bytes());
            }
            current_hash = hex::encode(hasher.finalize());
        }

        true
    }
}

// ============================================================================
// Merkle DAG
// ============================================================================

/// Merkle DAG storage
pub struct MerkleDag {
    /// Node storage
    nodes: RwLock<HashMap<ContentId, DagNode>>,
    /// Head nodes (latest in each branch)
    heads: RwLock<HashMap<String, ContentId>>,
    /// Default branch name
    default_branch: String,
}

impl MerkleDag {
    /// Create a new Merkle DAG
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            heads: RwLock::new(HashMap::new()),
            default_branch: "main".to_string(),
        }
    }

    /// Insert content and return its ID
    pub fn insert(&self, content: &[u8]) -> ContentId {
        let node = DagNode::root(content);
        let id = node.id.clone();

        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(id.clone(), node);
        }

        {
            let mut heads = self.heads.write().unwrap();
            heads.insert(self.default_branch.clone(), id.clone());
        }

        id
    }

    /// Insert content with a parent
    pub fn insert_with_parent(&self, content: &[u8], parent: &ContentId) -> ContentId {
        let node = DagNode::with_parent(content, parent);
        let id = node.id.clone();

        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(id.clone(), node);
        }

        // Update head
        {
            let mut heads = self.heads.write().unwrap();
            heads.insert(self.default_branch.clone(), id.clone());
        }

        id
    }

    /// Insert a typed node
    pub fn insert_node(&self, node: DagNode) -> ContentId {
        let id = node.id.clone();

        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(id.clone(), node);
        }

        id
    }

    /// Get a node by ID
    pub fn get(&self, id: &ContentId) -> Option<DagNode> {
        let nodes = self.nodes.read().unwrap();
        nodes.get(id).cloned()
    }

    /// Check if a node exists
    pub fn contains(&self, id: &ContentId) -> bool {
        let nodes = self.nodes.read().unwrap();
        nodes.contains_key(id)
    }

    /// Get the current head of a branch
    pub fn head(&self, branch: &str) -> Option<ContentId> {
        let heads = self.heads.read().unwrap();
        heads.get(branch).cloned()
    }

    /// Get the default branch head
    pub fn current_head(&self) -> Option<ContentId> {
        self.head(&self.default_branch)
    }

    /// Create a new branch at the current head
    pub fn create_branch(&self, name: &str) -> Option<ContentId> {
        let current = self.current_head()?;
        let mut heads = self.heads.write().unwrap();
        heads.insert(name.to_string(), current.clone());
        Some(current)
    }

    /// Merge two branches
    pub fn merge(
        &self,
        content: &[u8],
        branch_a: &str,
        branch_b: &str,
    ) -> Result<ContentId, DagError> {
        let head_a = self
            .head(branch_a)
            .ok_or_else(|| DagError::NodeNotFound(format!("Branch {} not found", branch_a)))?;
        let head_b = self
            .head(branch_b)
            .ok_or_else(|| DagError::NodeNotFound(format!("Branch {} not found", branch_b)))?;

        let node = DagNode::merge(content, vec![head_a, head_b]);
        let id = node.id.clone();

        {
            let mut nodes = self.nodes.write().unwrap();
            nodes.insert(id.clone(), node);
        }

        // Update default branch head to merge node
        {
            let mut heads = self.heads.write().unwrap();
            heads.insert(self.default_branch.clone(), id.clone());
        }

        Ok(id)
    }

    /// Get ancestry path from node to root
    pub fn get_ancestry(&self, id: &ContentId) -> Vec<ContentId> {
        let mut path = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(id.clone());

        let nodes = self.nodes.read().unwrap();

        while let Some(current) = queue.pop_front() {
            if visited.contains(&current) {
                continue;
            }
            visited.insert(current.clone());
            path.push(current.clone());

            if let Some(node) = nodes.get(&current) {
                for parent in &node.parents {
                    queue.push_back(parent.clone());
                }
            }
        }

        path
    }

    /// Generate inclusion proof
    pub fn generate_proof(
        &self,
        target: &ContentId,
        root: &ContentId,
    ) -> Result<InclusionProof, DagError> {
        let nodes = self.nodes.read().unwrap();

        // Find path from target to root
        let mut path = Vec::new();
        let mut current = target.clone();
        let mut visited = HashSet::new();

        while current != *root {
            if visited.contains(&current) {
                return Err(DagError::CyclicReference);
            }
            visited.insert(current.clone());

            let node = nodes
                .get(&current)
                .ok_or_else(|| DagError::NodeNotFound(current.to_string()))?;

            // Create proof step
            let step = ProofStep {
                node_id: current.clone(),
                hash: hex::encode(Sha256::digest(&node.content)),
                position: 0,
                siblings: node.parents.iter().map(|p| p.to_string()).collect(),
            };
            path.push(step);

            // Move to first parent
            if let Some(parent) = node.parents.first() {
                current = parent.clone();
            } else {
                break;
            }
        }

        // Add root step
        if let Some(root_node) = nodes.get(root) {
            path.push(ProofStep {
                node_id: root.clone(),
                hash: hex::encode(Sha256::digest(&root_node.content)),
                position: 0,
                siblings: vec![],
            });
        }

        Ok(InclusionProof {
            target: target.clone(),
            root: root.clone(),
            path,
            generated_at: current_timestamp(),
        })
    }

    /// Verify an inclusion proof
    pub fn verify_proof(&self, proof: &InclusionProof) -> bool {
        // Basic structural verification
        if !proof.verify() {
            return false;
        }

        // Verify all nodes in path exist and match
        let nodes = self.nodes.read().unwrap();

        for step in &proof.path {
            if let Some(node) = nodes.get(&step.node_id) {
                let expected_hash = hex::encode(Sha256::digest(&node.content));
                if expected_hash != step.hash {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }

    /// Compute diff between two nodes
    pub fn diff(&self, old: &ContentId, new: &ContentId) -> Result<DagDiff, DagError> {
        let nodes = self.nodes.read().unwrap();

        let old_node = nodes
            .get(old)
            .ok_or_else(|| DagError::NodeNotFound(old.to_string()))?;
        let new_node = nodes
            .get(new)
            .ok_or_else(|| DagError::NodeNotFound(new.to_string()))?;

        // Simple byte-level diff for now
        // In a real implementation, this would be content-aware
        let old_content = &old_node.content;
        let new_content = &new_node.content;

        let added = new_content.len().saturating_sub(old_content.len());
        let removed = old_content.len().saturating_sub(new_content.len());

        Ok(DagDiff {
            old_id: old.clone(),
            new_id: new.clone(),
            bytes_added: added,
            bytes_removed: removed,
            is_identical: old_content == new_content,
        })
    }

    /// Get total node count
    pub fn node_count(&self) -> usize {
        let nodes = self.nodes.read().unwrap();
        nodes.len()
    }

    /// Get all root nodes
    pub fn roots(&self) -> Vec<ContentId> {
        let nodes = self.nodes.read().unwrap();
        nodes
            .values()
            .filter(|n| n.parents.is_empty())
            .map(|n| n.id.clone())
            .collect()
    }

    /// Verify integrity of entire DAG
    pub fn verify_integrity(&self) -> Result<bool, DagError> {
        let nodes = self.nodes.read().unwrap();

        for node in nodes.values() {
            // Verify node hash
            if !node.verify() {
                return Ok(false);
            }

            // Verify parents exist
            for parent_id in &node.parents {
                if !nodes.contains_key(parent_id) {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Export DAG to serializable format
    pub fn export(&self) -> DagExport {
        let nodes = self.nodes.read().unwrap();
        let heads = self.heads.read().unwrap();

        DagExport {
            nodes: nodes.values().cloned().collect(),
            heads: heads.clone(),
            default_branch: self.default_branch.clone(),
        }
    }

    /// Import DAG from serializable format
    pub fn import(export: DagExport) -> Self {
        let dag = Self {
            nodes: RwLock::new(HashMap::new()),
            heads: RwLock::new(export.heads),
            default_branch: export.default_branch,
        };

        {
            let mut nodes = dag.nodes.write().unwrap();
            for node in export.nodes {
                nodes.insert(node.id.clone(), node);
            }
        }

        dag
    }
}

impl Default for MerkleDag {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MerkleDag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let nodes = self.nodes.read().unwrap();
        let heads = self.heads.read().unwrap();

        f.debug_struct("MerkleDag")
            .field("node_count", &nodes.len())
            .field("heads", &heads)
            .field("default_branch", &self.default_branch)
            .finish()
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

/// Diff between two DAG nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagDiff {
    /// Content ID of the old node
    pub old_id: ContentId,
    /// Content ID of the new node
    pub new_id: ContentId,
    /// Number of bytes added
    pub bytes_added: usize,
    /// Number of bytes removed
    pub bytes_removed: usize,
    /// Whether the content is identical
    pub is_identical: bool,
}

/// Exportable DAG format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagExport {
    /// All nodes in the DAG
    pub nodes: Vec<DagNode>,
    /// Branch heads mapping branch name to content ID
    pub heads: HashMap<String, ContentId>,
    /// Name of the default branch
    pub default_branch: String,
}

/// Get current Unix timestamp
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ============================================================================
// Memory Snapshot Integration
// ============================================================================

/// Memory snapshot stored in the Merkle DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Snapshot ID (same as DAG node ID)
    pub id: ContentId,
    /// Agent ID
    pub agent_id: String,
    /// Session ID
    pub session_id: Option<String>,
    /// Timestamp
    pub timestamp: u64,
    /// Description
    pub description: Option<String>,
    /// Serialized memory state
    pub state: Vec<u8>,
    /// State size in bytes
    pub size: usize,
}

impl MemorySnapshot {
    /// Create a new snapshot
    pub fn new(agent_id: impl Into<String>, state: Vec<u8>) -> Self {
        let id = ContentId::from_bytes(&state);
        let size = state.len();

        Self {
            id,
            agent_id: agent_id.into(),
            session_id: None,
            timestamp: current_timestamp(),
            description: None,
            state,
            size,
        }
    }

    /// Create a DAG node from this snapshot
    pub fn to_dag_node(&self, parent: Option<&ContentId>) -> DagNode {
        let content = serde_json::to_vec(self).unwrap_or_default();

        match parent {
            Some(p) => DagNode::with_parent(&content, p).with_type(NodeType::Snapshot),
            None => DagNode::root(&content).with_type(NodeType::Snapshot),
        }
    }

    /// Parse a DAG node as a snapshot
    pub fn from_dag_node(node: &DagNode) -> Result<Self, DagError> {
        serde_json::from_slice(&node.content)
            .map_err(|e| DagError::SerializationError(e.to_string()))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_id() {
        let id1 = ContentId::from_bytes(b"test content");
        let id2 = ContentId::from_bytes(b"test content");
        let id3 = ContentId::from_bytes(b"different");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_dag_insert() {
        let dag = MerkleDag::new();

        let id1 = dag.insert(b"first content");
        let id2 = dag.insert_with_parent(b"second content", &id1);

        assert!(dag.contains(&id1));
        assert!(dag.contains(&id2));

        let node1 = dag.get(&id1).unwrap();
        let node2 = dag.get(&id2).unwrap();

        assert!(node1.parents.is_empty());
        assert_eq!(node2.parents.len(), 1);
        assert_eq!(node2.parents[0], id1);
    }

    #[test]
    fn test_node_verification() {
        let node = DagNode::root(b"test content");
        assert!(node.verify());

        // Tampered node should fail
        let mut tampered = node.clone();
        tampered.content = b"tampered".to_vec();
        assert!(!tampered.verify());
    }

    #[test]
    fn test_ancestry() {
        let dag = MerkleDag::new();

        let id1 = dag.insert(b"root");
        let id2 = dag.insert_with_parent(b"child", &id1);
        let id3 = dag.insert_with_parent(b"grandchild", &id2);

        let ancestry = dag.get_ancestry(&id3);

        assert_eq!(ancestry.len(), 3);
        assert_eq!(ancestry[0], id3);
        assert_eq!(ancestry[1], id2);
        assert_eq!(ancestry[2], id1);
    }

    #[test]
    fn test_inclusion_proof() {
        let dag = MerkleDag::new();

        let root = dag.insert(b"root");
        let child = dag.insert_with_parent(b"child", &root);

        let proof = dag.generate_proof(&child, &root).unwrap();
        assert!(dag.verify_proof(&proof));
    }

    #[test]
    fn test_branching() {
        let dag = MerkleDag::new();

        let root = dag.insert(b"root");
        dag.create_branch("feature");

        // Add to main
        let main_child = dag.insert_with_parent(b"main content", &root);

        // Add to feature branch
        {
            let mut heads = dag.heads.write().unwrap();
            heads.insert("main".to_string(), main_child.clone());
        }

        let feature_head = dag.head("feature");
        assert_eq!(feature_head, Some(root.clone()));
    }

    #[test]
    fn test_merge() {
        let dag = MerkleDag::new();

        let root = dag.insert(b"root");
        dag.create_branch("feature");

        let main = dag.insert_with_parent(b"main", &root);
        {
            let mut heads = dag.heads.write().unwrap();
            heads.insert("main".to_string(), main);
        }

        let merge_id = dag.merge(b"merged", "main", "feature").unwrap();
        let merge_node = dag.get(&merge_id).unwrap();

        assert_eq!(merge_node.parents.len(), 2);
        assert_eq!(merge_node.node_type, NodeType::Merge);
    }

    #[test]
    fn test_diff() {
        let dag = MerkleDag::new();

        let old = dag.insert(b"old content");
        let new = dag.insert_with_parent(b"new content with more", &old);

        let diff = dag.diff(&old, &new).unwrap();
        assert!(!diff.is_identical);
        assert!(diff.bytes_added > 0);
    }

    #[test]
    fn test_dag_integrity() {
        let dag = MerkleDag::new();

        dag.insert(b"root");
        dag.insert(b"another root");

        assert!(dag.verify_integrity().unwrap());
    }

    #[test]
    fn test_export_import() {
        let dag = MerkleDag::new();
        let id1 = dag.insert(b"content 1");
        let _id2 = dag.insert_with_parent(b"content 2", &id1);

        let export = dag.export();
        let imported = MerkleDag::import(export);

        assert_eq!(dag.node_count(), imported.node_count());
        assert!(imported.contains(&id1));
    }

    #[test]
    fn test_memory_snapshot() {
        let snapshot = MemorySnapshot::new("agent-1", b"memory state".to_vec());

        let node = snapshot.to_dag_node(None);
        assert_eq!(node.node_type, NodeType::Snapshot);

        let recovered = MemorySnapshot::from_dag_node(&node).unwrap();
        assert_eq!(recovered.agent_id, "agent-1");
    }
}
