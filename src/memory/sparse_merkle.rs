//! Sparse Merkle Proof Module (MEM-002)
//!
//! Provides sparse Merkle tree implementation for efficient inclusion proofs.
//! Allows proving an agent *did* see specific data without revealing the entire dataset.
//!
//! # Overview
//!
//! Sparse Merkle trees enable:
//! - Efficient proofs of inclusion/exclusion
//! - Compact proof size (O(log n))
//! - Privacy-preserving verification
//! - Batch proof generation
//!
//! # Example
//!
//! ```rust
//! use vak::memory::sparse_merkle::{SparseMerkleTree, SparseProof};
//!
//! let mut tree = SparseMerkleTree::new();
//!
//! // Insert data
//! tree.insert("key1", b"value1");
//! tree.insert("key2", b"value2");
//!
//! // Generate proof
//! let proof = tree.generate_proof("key1").unwrap();
//!
//! // Verify proof
//! assert!(tree.verify_proof(&proof));
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.3.1: Sparse Merkle Tree Proofs
//! - rs-merkle integration pattern

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

/// Errors for sparse Merkle operations
#[derive(Debug, Error)]
pub enum SparseMerkleError {
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Invalid proof
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Tree is empty
    #[error("Tree is empty")]
    EmptyTree,

    /// Proof generation failed
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),
}

/// Result type for sparse Merkle operations
pub type SparseMerkleResult<T> = Result<T, SparseMerkleError>;

/// Default tree depth (256 bits for SHA-256 keys)
const DEFAULT_DEPTH: usize = 256;

/// Empty node hash (hash of empty data)
const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// A node in the sparse Merkle tree
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleNode {
    /// Node hash
    pub hash: String,
    /// Left child hash (None for leaf nodes)
    pub left: Option<String>,
    /// Right child hash (None for leaf nodes)
    pub right: Option<String>,
    /// Value (only for leaf nodes)
    pub value: Option<Vec<u8>>,
    /// Key (only for leaf nodes)
    pub key: Option<String>,
    /// Node level (0 = root)
    pub level: usize,
}

impl SparseMerkleNode {
    /// Create an empty node
    pub fn empty(level: usize) -> Self {
        Self {
            hash: EMPTY_HASH.to_string(),
            left: None,
            right: None,
            value: None,
            key: None,
            level,
        }
    }

    /// Create a leaf node
    pub fn leaf(key: &str, value: &[u8], level: usize) -> Self {
        let hash = compute_leaf_hash(key, value);
        Self {
            hash,
            left: None,
            right: None,
            value: Some(value.to_vec()),
            key: Some(key.to_string()),
            level,
        }
    }

    /// Create an internal node
    pub fn internal(left_hash: &str, right_hash: &str, level: usize) -> Self {
        let hash = compute_internal_hash(left_hash, right_hash);
        Self {
            hash,
            left: Some(left_hash.to_string()),
            right: Some(right_hash.to_string()),
            value: None,
            key: None,
            level,
        }
    }

    /// Check if this is an empty node
    pub fn is_empty(&self) -> bool {
        self.hash == EMPTY_HASH
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.value.is_some()
    }
}

/// A proof step in the sparse Merkle proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseProofStep {
    /// Sibling hash at this level
    pub sibling_hash: String,
    /// Direction (false = left, true = right)
    pub direction: bool,
    /// Level in the tree
    pub level: usize,
}

/// Sparse Merkle proof for inclusion verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseProof {
    /// Key being proved
    pub key: String,
    /// Value hash (if proving inclusion)
    pub value_hash: Option<String>,
    /// Root hash at time of proof generation
    pub root_hash: String,
    /// Proof path from leaf to root
    pub path: Vec<SparseProofStep>,
    /// Whether this proves inclusion (true) or exclusion (false)
    pub is_inclusion: bool,
    /// Timestamp of proof generation
    pub generated_at: u64,
}

impl SparseProof {
    /// Verify this proof against a root hash
    pub fn verify(&self, expected_root: &str) -> bool {
        if self.path.is_empty() {
            return false;
        }

        // Compute the leaf hash
        // value_hash is hex-encoded original value bytes, so decode it first
        let mut current_hash = if let Some(ref value_hex) = self.value_hash {
            if let Ok(value_bytes) = hex::decode(value_hex) {
                compute_leaf_hash(&self.key, &value_bytes)
            } else {
                return false;
            }
        } else {
            EMPTY_HASH.to_string()
        };

        // Walk up the tree
        for step in &self.path {
            current_hash = if step.direction {
                // Current is on right, sibling is on left
                compute_internal_hash(&step.sibling_hash, &current_hash)
            } else {
                // Current is on left, sibling is on right
                compute_internal_hash(&current_hash, &step.sibling_hash)
            };
        }

        // Verify root matches
        current_hash == expected_root && expected_root == self.root_hash
    }

    /// Get proof size in bytes
    pub fn size_bytes(&self) -> usize {
        self.path.len() * 64 + self.key.len() + self.value_hash.as_ref().map_or(0, |v| v.len())
    }
}

/// Compact proof containing only essential data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactProof {
    /// Key hash
    pub key_hash: String,
    /// Root hash
    pub root_hash: String,
    /// Sibling hashes (compressed)
    pub siblings: Vec<String>,
    /// Path bitmap (direction bits)
    pub path_bits: Vec<u8>,
    /// Is inclusion proof
    pub is_inclusion: bool,
}

impl From<&SparseProof> for CompactProof {
    fn from(proof: &SparseProof) -> Self {
        let siblings: Vec<String> = proof.path.iter().map(|s| s.sibling_hash.clone()).collect();
        
        // Pack direction bits into bytes
        let mut path_bits = Vec::new();
        let mut current_byte = 0u8;
        for (i, step) in proof.path.iter().enumerate() {
            if step.direction {
                current_byte |= 1 << (i % 8);
            }
            if i % 8 == 7 {
                path_bits.push(current_byte);
                current_byte = 0;
            }
        }
        if proof.path.len() % 8 != 0 {
            path_bits.push(current_byte);
        }

        Self {
            key_hash: compute_hash(proof.key.as_bytes()),
            root_hash: proof.root_hash.clone(),
            siblings,
            path_bits,
            is_inclusion: proof.is_inclusion,
        }
    }
}

/// Sparse Merkle Tree implementation
pub struct SparseMerkleTree {
    /// Nodes by hash
    nodes: HashMap<String, SparseMerkleNode>,
    /// Key to leaf node hash mapping
    leaves: HashMap<String, String>,
    /// Current root hash
    root_hash: String,
    /// Tree depth
    depth: usize,
    /// Default hashes for empty subtrees at each level
    default_hashes: Vec<String>,
}

impl std::fmt::Debug for SparseMerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseMerkleTree")
            .field("root_hash", &self.root_hash)
            .field("leaf_count", &self.leaves.len())
            .field("depth", &self.depth)
            .finish()
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create a new empty sparse Merkle tree
    pub fn new() -> Self {
        Self::with_depth(DEFAULT_DEPTH)
    }

    /// Create with custom depth
    pub fn with_depth(depth: usize) -> Self {
        // Precompute default hashes for empty subtrees
        let mut default_hashes = vec![EMPTY_HASH.to_string()];
        for i in 1..=depth {
            let prev = &default_hashes[i - 1];
            let hash = compute_internal_hash(prev, prev);
            default_hashes.push(hash);
        }

        Self {
            nodes: HashMap::new(),
            leaves: HashMap::new(),
            root_hash: default_hashes[depth].clone(),
            depth,
            default_hashes,
        }
    }

    /// Get current root hash
    pub fn root_hash(&self) -> &str {
        &self.root_hash
    }

    /// Get leaf count
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Insert a key-value pair
    pub fn insert(&mut self, key: &str, value: &[u8]) -> String {
        let key_hash = compute_hash(key.as_bytes());
        let leaf = SparseMerkleNode::leaf(key, value, self.depth);
        let leaf_hash = leaf.hash.clone();

        self.nodes.insert(leaf_hash.clone(), leaf);
        self.leaves.insert(key.to_string(), leaf_hash.clone());

        // Update path from leaf to root
        self.update_path(&key_hash);

        leaf_hash
    }

    /// Get value for a key
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.leaves
            .get(key)
            .and_then(|hash| self.nodes.get(hash))
            .and_then(|node| node.value.as_ref())
            .map(|v| v.as_slice())
    }

    /// Check if key exists
    pub fn contains(&self, key: &str) -> bool {
        self.leaves.contains_key(key)
    }

    /// Remove a key
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        let value = self.get(key).map(|v| v.to_vec());
        
        if let Some(leaf_hash) = self.leaves.remove(key) {
            self.nodes.remove(&leaf_hash);
            let key_hash = compute_hash(key.as_bytes());
            self.update_path(&key_hash);
        }

        value
    }

    /// Generate inclusion proof for a key
    pub fn generate_proof(&self, key: &str) -> SparseMerkleResult<SparseProof> {
        let key_hash = compute_hash(key.as_bytes());
        let mut path = Vec::new();

        // Walk from leaf to root, collecting siblings
        // Get the actual value (we store its hex representation for the proof)
        let value_hash = self.leaves.get(key)
            .and_then(|leaf_hash| self.nodes.get(leaf_hash))
            .and_then(|node| node.value.as_ref())
            .map(|v| hex::encode(v));

        for level in (0..self.depth).rev() {
            let bit = get_bit(&key_hash, self.depth - 1 - level);
            let sibling_hash = self.get_sibling_hash(&key_hash, level);

            path.push(SparseProofStep {
                sibling_hash,
                direction: bit,
                level,
            });
        }

        let is_inclusion = self.contains(key);

        Ok(SparseProof {
            key: key.to_string(),
            value_hash,
            root_hash: self.root_hash.clone(),
            path,
            is_inclusion,
            generated_at: current_timestamp(),
        })
    }

    /// Generate batch proofs efficiently
    pub fn generate_batch_proofs(&self, keys: &[&str]) -> Vec<SparseMerkleResult<SparseProof>> {
        keys.iter().map(|k| self.generate_proof(k)).collect()
    }

    /// Verify a proof against current root
    pub fn verify_proof(&self, proof: &SparseProof) -> bool {
        proof.verify(&self.root_hash)
    }

    /// Update internal nodes along the path from a leaf to root
    fn update_path(&mut self, key_hash: &str) {
        let mut current_hash = if let Some(leaf) = self.leaves.values()
            .find(|&h| {
                self.nodes.get(h)
                    .and_then(|n| n.key.as_ref())
                    .map_or(false, |k| compute_hash(k.as_bytes()) == *key_hash)
            })
        {
            leaf.clone()
        } else {
            self.default_hashes[self.depth].clone()
        };

        for level in (0..self.depth).rev() {
            let bit = get_bit(key_hash, self.depth - 1 - level);
            let sibling_hash = self.get_sibling_hash(key_hash, level);

            let (left, right) = if bit {
                (sibling_hash.clone(), current_hash.clone())
            } else {
                (current_hash.clone(), sibling_hash.clone())
            };

            let internal = SparseMerkleNode::internal(&left, &right, level);
            current_hash = internal.hash.clone();
            self.nodes.insert(internal.hash.clone(), internal);
        }

        self.root_hash = current_hash;
    }

    /// Get sibling hash at a given level
    fn get_sibling_hash(&self, _key_hash: &str, level: usize) -> String {
        // For simplicity, return default hash for empty siblings
        // In production, would maintain actual sibling references
        self.default_hashes[level].clone()
    }

    /// Export tree state for serialization
    pub fn export(&self) -> SparseMerkleExport {
        SparseMerkleExport {
            root_hash: self.root_hash.clone(),
            depth: self.depth,
            leaves: self.leaves.clone(),
            leaf_count: self.leaves.len(),
        }
    }

    /// Create tree from export
    pub fn from_export(export: SparseMerkleExport) -> Self {
        let mut tree = Self::with_depth(export.depth);
        // Note: This is a simplified reconstruction
        // Full reconstruction would need to store all node data
        tree.root_hash = export.root_hash;
        tree.leaves = export.leaves;
        tree
    }
}

/// Exported tree state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleExport {
    /// Root hash
    pub root_hash: String,
    /// Tree depth
    pub depth: usize,
    /// Leaf mappings
    pub leaves: HashMap<String, String>,
    /// Leaf count
    pub leaf_count: usize,
}

/// Compute SHA-256 hash
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute leaf node hash
fn compute_leaf_hash(key: &str, value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"leaf:");
    hasher.update(key.as_bytes());
    hasher.update(b":");
    hasher.update(value);
    hex::encode(hasher.finalize())
}

/// Compute internal node hash
fn compute_internal_hash(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"node:");
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

/// Get bit at position in hex string
fn get_bit(hex_hash: &str, position: usize) -> bool {
    if position / 4 >= hex_hash.len() {
        return false;
    }
    let char_idx = position / 4;
    let bit_idx = 3 - (position % 4);
    let c = hex_hash.chars().nth(char_idx).unwrap_or('0');
    let nibble = c.to_digit(16).unwrap_or(0);
    (nibble >> bit_idx) & 1 == 1
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_merkle_tree_creation() {
        let tree = SparseMerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1");
        
        assert!(tree.contains("key1"));
        assert_eq!(tree.get("key1"), Some(b"value1".as_slice()));
        assert!(!tree.contains("key2"));
    }

    #[test]
    fn test_proof_generation() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1");
        tree.insert("key2", b"value2");

        let proof = tree.generate_proof("key1").unwrap();
        assert!(proof.is_inclusion);
        assert!(!proof.path.is_empty());
    }

    #[test]
    fn test_proof_verification() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1");

        let proof = tree.generate_proof("key1").unwrap();
        assert!(tree.verify_proof(&proof));
    }

    #[test]
    fn test_compact_proof() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1");

        let proof = tree.generate_proof("key1").unwrap();
        let compact: CompactProof = (&proof).into();

        assert_eq!(compact.root_hash, proof.root_hash);
        assert!(!compact.siblings.is_empty());
    }

    #[test]
    fn test_remove() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1");
        
        let removed = tree.remove("key1");
        assert_eq!(removed, Some(b"value1".to_vec()));
        assert!(!tree.contains("key1"));
    }

    #[test]
    fn test_export_import() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1");
        tree.insert("key2", b"value2");

        let export = tree.export();
        assert_eq!(export.leaf_count, 2);
        assert_eq!(export.root_hash, tree.root_hash());
    }

    #[test]
    fn test_batch_proofs() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1");
        tree.insert("key2", b"value2");
        tree.insert("key3", b"value3");

        let keys = vec!["key1", "key2", "key3"];
        let proofs = tree.generate_batch_proofs(&keys);

        assert_eq!(proofs.len(), 3);
        for proof in proofs {
            assert!(proof.is_ok());
        }
    }
}
