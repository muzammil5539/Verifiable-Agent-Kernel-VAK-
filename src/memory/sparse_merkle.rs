//! Sparse Merkle tree (MEM-002; finding V4 in `docs/architecture-v2.md`).
//!
//! A key-value map with a root hash that commits to every entry, and proofs
//! that a key holds a value (inclusion) or holds nothing (exclusion), each
//! checkable against the root alone.
//!
//! # Construction
//!
//! The standard sparse Merkle tree, as in Dahlberg, Pulls and Peeters (2016):
//!
//! - **Positions.** A key's leaf position is the first `depth` bits of
//!   SHA-256 of the key. Bit 0, the most significant, chooses the root's
//!   child.
//! - **Empty subtrees.** An empty subtree of height *h* has a precomputed
//!   hash: `E(0)` is SHA-256 of nothing, and `E(h+1) = node(E(h), E(h))`.
//!   Only non-empty nodes are stored.
//! - **Internal nodes.** Each one is derived from its two real children. The
//!   tree this replaced took every sibling to be empty, so its root
//!   committed only to the last key written (V4).
//! - **Leaves.** `SHA-256(0x00 ‖ len(key) ‖ key ‖ len(value) ‖ value)`, with
//!   lengths as 8-byte big-endian. Internal nodes are
//!   `SHA-256(0x01 ‖ left ‖ right)`, over the children's hex digests. The tags
//!   and the length prefixes separate the domains, so no leaf can pass for a
//!   node and no two entries share a preimage.
//!
//! With the default depth of 256 every key has its own position. A shallower
//! tree has fewer positions than keys. Two keys can then share one, and
//! [`SparseMerkleTree::insert`] refuses the second rather than overwrite the
//! first.
//!
//! # Example
//!
//! ```rust
//! use vak::memory::sparse_merkle::SparseMerkleTree;
//!
//! let mut tree = SparseMerkleTree::new();
//! tree.insert("key1", b"value1").unwrap();
//! tree.insert("key2", b"value2").unwrap();
//!
//! // Anyone holding the root can check a proof.
//! let root = tree.root_hash().to_string();
//! let proof = tree.generate_proof("key1").unwrap();
//! assert!(proof.is_inclusion);
//! assert!(proof.verify(&root));
//!
//! // And that a key is absent.
//! let absent = tree.generate_proof("key3").unwrap();
//! assert!(!absent.is_inclusion);
//! assert!(absent.verify(&root));
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

/// Errors for sparse Merkle operations
#[derive(Debug, Error)]
#[non_exhaustive]
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

    /// Two keys need the same leaf position, which a tree shallower than
    /// 256 levels can't avoid. The key already there keeps it.
    #[error("Key '{key}' needs the leaf position '{existing}' already holds")]
    KeyCollision {
        /// The key that was refused.
        key: String,
        /// The key holding the position.
        existing: String,
    },

    /// An export whose entries don't produce its root, or that can't be
    /// rebuilt.
    #[error("Export doesn't match its entries: {0}")]
    CorruptExport(String),
}

/// Result type for sparse Merkle operations
pub type SparseMerkleResult<T> = Result<T, SparseMerkleError>;

/// Default tree depth: every bit of a SHA-256 key hash.
const DEFAULT_DEPTH: usize = 256;

/// The deepest tree: positions come from a 256-bit hash.
const MAX_DEPTH: usize = 256;

/// The hash of an empty leaf position: SHA-256 of nothing.
const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Domain tag of a leaf hash.
const LEAF_TAG: u8 = 0x00;

/// Domain tag of an internal node hash.
const NODE_TAG: u8 = 0x01;

/// A node as a proof or export might describe it. The tree itself keeps
/// only hashes. The constructors hash as the tree does.
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

/// One step of a proof: the sibling of the node on the key's path at one
/// height, from the leaf up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseProofStep {
    /// Sibling hash at this level
    pub sibling_hash: String,
    /// Which side the path is on: `false` left, `true` right. Fixed by the
    /// key; [`SparseProof::verify`] checks it rather than trusting it.
    pub direction: bool,
    /// The level of the parent this step computes (0 = root).
    pub level: usize,
}

/// A proof that a key holds a value, or holds nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseProof {
    /// Key being proved
    pub key: String,
    /// For an inclusion proof, the value, hex-encoded. Despite the name, it
    /// is the value itself, not a hash of it: the leaf hash is recomputed
    /// from it.
    pub value_hash: Option<String>,
    /// Root hash at time of proof generation
    pub root_hash: String,
    /// One step per level, from the leaf up. Its length is the tree's depth.
    pub path: Vec<SparseProofStep>,
    /// Whether this proves inclusion (true) or exclusion (false)
    pub is_inclusion: bool,
    /// Timestamp of proof generation
    pub generated_at: u64,
}

impl SparseProof {
    /// Whether this proof holds against `expected_root`: walking up from the
    /// key's leaf (its value's, or the empty one) with these siblings yields
    /// `expected_root`, which is also the root the proof names.
    ///
    /// Everything the key fixes is checked, not trusted: the path's
    /// directions come from the key's hash, each step's level from its
    /// height, and an inclusion proof must carry a value and an exclusion
    /// proof none. A proof with no steps, more than 256, or a malformed
    /// sibling fails.
    pub fn verify(&self, expected_root: &str) -> bool {
        let depth = self.path.len();
        if depth == 0 || depth > MAX_DEPTH {
            return false;
        }
        if self.is_inclusion != self.value_hash.is_some() {
            return false;
        }

        let mut current_hash = match &self.value_hash {
            Some(value_hex) => match hex::decode(value_hex) {
                Ok(value) => compute_leaf_hash(&self.key, &value),
                Err(_) => return false,
            },
            None => EMPTY_HASH.to_string(),
        };

        let position = key_position(&self.key, depth);
        for (height, step) in self.path.iter().enumerate() {
            let bit = get_bit(&position, depth - 1 - height);
            if step.direction != bit
                || step.level != depth - 1 - height
                || !is_digest(&step.sibling_hash)
            {
                return false;
            }
            current_hash = if bit {
                compute_internal_hash(&step.sibling_hash, &current_hash)
            } else {
                compute_internal_hash(&current_hash, &step.sibling_hash)
            };
        }

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
        if !proof.path.len().is_multiple_of(8) {
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

/// A leaf position, or the prefix naming an internal node: the first bits
/// of a key's SHA-256, the rest zeroed.
type Position = [u8; 32];

/// Sparse Merkle Tree implementation
pub struct SparseMerkleTree {
    /// Every non-empty node's hash, by height (0 = leaf) and the position
    /// prefix naming it. An absent node is the empty subtree of its height.
    nodes: HashMap<(usize, Position), String>,
    /// Each key's value and leaf position.
    entries: HashMap<String, (Vec<u8>, Position)>,
    /// Which key holds each occupied leaf position.
    holders: HashMap<Position, String>,
    /// Current root hash
    root_hash: String,
    /// Tree depth
    depth: usize,
    /// The hash of an empty subtree of each height, 0 (a leaf) to `depth`.
    default_hashes: Vec<String>,
}

impl std::fmt::Debug for SparseMerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SparseMerkleTree")
            .field("root_hash", &self.root_hash)
            .field("leaf_count", &self.entries.len())
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
    /// An empty tree of depth 256, where every key has its own position.
    pub fn new() -> Self {
        Self::with_depth(DEFAULT_DEPTH)
    }

    /// An empty tree of `depth` levels, between 1 and 256; a depth outside
    /// that range is brought to the nearest end of it. A tree shallower than
    /// 256 has fewer leaf positions than possible keys, so
    /// [`SparseMerkleTree::insert`] can refuse a key whose position is
    /// taken.
    pub fn with_depth(depth: usize) -> Self {
        let depth = depth.clamp(1, MAX_DEPTH);
        let mut default_hashes = Vec::with_capacity(depth + 1);
        default_hashes.push(EMPTY_HASH.to_string());
        for height in 0..depth {
            let below = &default_hashes[height];
            let hash = compute_internal_hash(below, below);
            default_hashes.push(hash);
        }

        Self {
            nodes: HashMap::new(),
            entries: HashMap::new(),
            holders: HashMap::new(),
            root_hash: default_hashes[depth].clone(),
            depth,
            default_hashes,
        }
    }

    /// Get current root hash
    pub fn root_hash(&self) -> &str {
        &self.root_hash
    }

    /// The tree's depth.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Get leaf count
    pub fn leaf_count(&self) -> usize {
        self.entries.len()
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Sets `key` to `value`, replacing any value it had, and returns the
    /// new leaf's hash.
    ///
    /// # Errors
    ///
    /// [`SparseMerkleError::KeyCollision`] if another key holds this key's
    /// leaf position, which only a tree shallower than 256 levels allows.
    /// The tree is unchanged.
    pub fn insert(&mut self, key: &str, value: &[u8]) -> SparseMerkleResult<String> {
        let position = key_position(key, self.depth);
        if let Some(existing) = self.holders.get(&position) {
            if existing != key {
                return Err(SparseMerkleError::KeyCollision {
                    key: key.to_string(),
                    existing: existing.clone(),
                });
            }
        }

        let leaf_hash = compute_leaf_hash(key, value);
        self.entries
            .insert(key.to_string(), (value.to_vec(), position));
        self.holders.insert(position, key.to_string());
        self.nodes.insert((0, position), leaf_hash.clone());
        self.update_path(&position);
        Ok(leaf_hash)
    }

    /// Get value for a key
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.entries.get(key).map(|(value, _)| value.as_slice())
    }

    /// Check if key exists
    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    /// Removes `key`, returning its value. The root is then what it would
    /// be had the key never been inserted.
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        let (value, position) = self.entries.remove(key)?;
        self.holders.remove(&position);
        self.nodes.remove(&(0, position));
        self.update_path(&position);
        Some(value)
    }

    /// A proof for `key` against the current root: of inclusion if the key
    /// is present, of exclusion if its position is empty.
    ///
    /// # Errors
    ///
    /// [`SparseMerkleError::ProofGenerationFailed`] if the key is absent but
    /// another key holds its position (possible only below depth 256). The
    /// position isn't empty, so no exclusion proof can be made from it.
    pub fn generate_proof(&self, key: &str) -> SparseMerkleResult<SparseProof> {
        let position = key_position(key, self.depth);
        let value_hash = match (self.entries.get(key), self.holders.get(&position)) {
            (Some((value, _)), _) => Some(hex::encode(value)),
            (None, None) => None,
            (None, Some(existing)) => {
                return Err(SparseMerkleError::ProofGenerationFailed(format!(
                    "'{key}' is absent, but '{existing}' holds its position"
                )))
            }
        };

        let path = (0..self.depth)
            .map(|height| SparseProofStep {
                sibling_hash: self.sibling_hash(&position, height),
                direction: get_bit(&position, self.depth - 1 - height),
                level: self.depth - 1 - height,
            })
            .collect();

        Ok(SparseProof {
            key: key.to_string(),
            is_inclusion: value_hash.is_some(),
            value_hash,
            root_hash: self.root_hash.clone(),
            path,
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

    /// The hash of the node at `height` on the path to `position`, or of the
    /// empty subtree there.
    fn node_hash(&self, height: usize, prefix: &Position) -> &str {
        self.nodes
            .get(&(height, *prefix))
            .unwrap_or(&self.default_hashes[height])
    }

    /// The hash of the sibling, at `height`, of the node on the path to
    /// `position`.
    fn sibling_hash(&self, position: &Position, height: usize) -> String {
        let bit = self.depth - 1 - height;
        let sibling = prefix(&flip_bit(position, bit), self.depth - height);
        self.node_hash(height, &sibling).to_string()
    }

    /// Recomputes every node on the path from the leaf at `position` to the
    /// root, each from its two real children.
    fn update_path(&mut self, position: &Position) {
        let mut current = self.node_hash(0, position).to_string();
        for height in 0..self.depth {
            let sibling = self.sibling_hash(position, height);
            let parent = if get_bit(position, self.depth - 1 - height) {
                compute_internal_hash(&sibling, &current)
            } else {
                compute_internal_hash(&current, &sibling)
            };
            let key = (height + 1, prefix(position, self.depth - height - 1));
            if parent == self.default_hashes[height + 1] {
                self.nodes.remove(&key);
            } else {
                self.nodes.insert(key, parent.clone());
            }
            current = parent;
        }
        self.root_hash = current;
    }

    /// Export tree state for serialization
    pub fn export(&self) -> SparseMerkleExport {
        SparseMerkleExport {
            root_hash: self.root_hash.clone(),
            depth: self.depth,
            entries: self
                .entries
                .iter()
                .map(|(key, (value, _))| (key.clone(), value.clone()))
                .collect(),
            leaf_count: self.entries.len(),
        }
    }

    /// Rebuilds a tree from an export, and checks that its entries produce
    /// its root.
    ///
    /// # Errors
    ///
    /// [`SparseMerkleError::CorruptExport`] if the depth is out of range,
    /// the count is wrong, two entries share a position, or the rebuilt root
    /// isn't the exported one.
    pub fn from_export(export: SparseMerkleExport) -> SparseMerkleResult<Self> {
        if export.depth == 0 || export.depth > MAX_DEPTH {
            return Err(SparseMerkleError::CorruptExport(format!(
                "depth {} is outside 1 to {MAX_DEPTH}",
                export.depth
            )));
        }
        if export.leaf_count != export.entries.len() {
            return Err(SparseMerkleError::CorruptExport(format!(
                "it counts {} entries and holds {}",
                export.leaf_count,
                export.entries.len()
            )));
        }
        let mut tree = Self::with_depth(export.depth);
        for (key, value) in &export.entries {
            tree.insert(key, value)
                .map_err(|e| SparseMerkleError::CorruptExport(e.to_string()))?;
        }
        if tree.root_hash != export.root_hash {
            return Err(SparseMerkleError::CorruptExport(format!(
                "its entries produce the root {}, not {}",
                tree.root_hash, export.root_hash
            )));
        }
        Ok(tree)
    }
}

/// Exported tree state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseMerkleExport {
    /// Root hash
    pub root_hash: String,
    /// Tree depth
    pub depth: usize,
    /// Every key and its value.
    pub entries: BTreeMap<String, Vec<u8>>,
    /// Leaf count
    pub leaf_count: usize,
}

/// Compute SHA-256 hash
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// `SHA-256(0x00 ‖ len(key) ‖ key ‖ len(value) ‖ value)`.
fn compute_leaf_hash(key: &str, value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_TAG]);
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key.as_bytes());
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    hex::encode(hasher.finalize())
}

/// `SHA-256(0x01 ‖ left ‖ right)`, over the children's hex digests.
fn compute_internal_hash(left: &str, right: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update([NODE_TAG]);
    hasher.update(left.as_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

/// Whether `hash` is a digest as the tree writes one: 64 lowercase hex
/// digits.
fn is_digest(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The leaf position of `key` in a tree of `depth` levels.
fn key_position(key: &str, depth: usize) -> Position {
    let digest: Position = Sha256::digest(key.as_bytes()).into();
    prefix(&digest, depth)
}

/// `position` with every bit from `bits` on zeroed.
fn prefix(position: &Position, bits: usize) -> Position {
    let mut out = [0u8; 32];
    for (i, byte) in position.iter().enumerate() {
        let start = i * 8;
        if start + 8 <= bits {
            out[i] = *byte;
        } else if start < bits {
            out[i] = byte & (0xffu8 << (8 - (bits - start)));
        }
    }
    out
}

/// Bit `index` of `position`, most significant first.
fn get_bit(position: &Position, index: usize) -> bool {
    position
        .get(index / 8)
        .is_some_and(|byte| (byte >> (7 - index % 8)) & 1 == 1)
}

/// `position` with bit `index` flipped.
fn flip_bit(position: &Position, index: usize) -> Position {
    let mut out = *position;
    if let Some(byte) = out.get_mut(index / 8) {
        *byte ^= 1 << (7 - index % 8);
    }
    out
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

    /// The root of `entries` in a tree of `depth`, computed from scratch by
    /// recursion over the definition: a reference the tree must agree with.
    fn reference_root(entries: &[(&str, &[u8])], depth: usize) -> String {
        fn subtree(leaves: &[(Position, String)], height: usize, empty: &[String]) -> String {
            if leaves.is_empty() {
                return empty[height].clone();
            }
            if height == 0 {
                assert_eq!(leaves.len(), 1, "one leaf per position");
                return leaves[0].1.clone();
            }
            // The node at `height` splits on bit `depth - height`.
            let bit = empty.len() - 1 - height;
            let (right, left): (Vec<_>, Vec<_>) =
                leaves.iter().cloned().partition(|(p, _)| get_bit(p, bit));
            compute_internal_hash(
                &subtree(&left, height - 1, empty),
                &subtree(&right, height - 1, empty),
            )
        }
        // E(0) is SHA-256 of nothing; E(h+1) = node(E(h), E(h)).
        let mut empty = vec![compute_hash(b"")];
        for h in 0..depth {
            empty.push(compute_internal_hash(&empty[h], &empty[h]));
        }
        let leaves: Vec<(Position, String)> = entries
            .iter()
            .map(|(k, v)| (key_position(k, depth), compute_leaf_hash(k, v)))
            .collect();
        subtree(&leaves, depth, &empty)
    }

    fn tree_of(entries: &[(&str, &[u8])], depth: usize) -> SparseMerkleTree {
        let mut tree = SparseMerkleTree::with_depth(depth);
        for (k, v) in entries {
            tree.insert(k, v).unwrap();
        }
        tree
    }

    /// Two keys that share a position in a tree of `depth`.
    fn colliding_keys(depth: usize) -> (String, String) {
        let mut seen: HashMap<Position, String> = HashMap::new();
        for i in 0.. {
            let key = format!("k{i}");
            let position = key_position(&key, depth);
            if let Some(other) = seen.insert(position, key.clone()) {
                return (other, key);
            }
        }
        unreachable!("a shallow tree has few positions")
    }

    #[test]
    fn test_sparse_merkle_tree_creation() {
        let tree = SparseMerkleTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.leaf_count(), 0);
        assert_eq!(tree.root_hash(), reference_root(&[], 256));
    }

    #[test]
    fn test_insert_and_get() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1").unwrap();

        assert!(tree.contains("key1"));
        assert_eq!(tree.get("key1"), Some(b"value1".as_slice()));
        assert!(!tree.contains("key2"));
    }

    #[test]
    fn test_the_root_commits_to_every_entry() {
        // V4: siblings were always the empty subtree, so the root depended
        // only on the last key written, and earlier values could change
        // without changing it.
        let a = tree_of(&[("key1", b"value1"), ("key2", b"value2")], 256);
        let b = tree_of(&[("key1", b"forged"), ("key2", b"value2")], 256);
        assert_ne!(a.root_hash(), b.root_hash());

        for depth in [1, 7, 16, 256] {
            let entries: Vec<(String, Vec<u8>)> = (0..40)
                .map(|i| (format!("key{i}"), format!("v{i}").into_bytes()))
                .collect();
            let mut tree = SparseMerkleTree::with_depth(depth);
            let mut kept: Vec<(&str, &[u8])> = Vec::new();
            for (k, v) in &entries {
                if tree.insert(k, v).is_ok() {
                    kept.push((k, v));
                }
            }
            assert_eq!(
                tree.root_hash(),
                reference_root(&kept, depth),
                "depth {depth}"
            );
        }
    }

    #[test]
    fn test_root_is_independent_of_insertion_order() {
        let forward = tree_of(&[("a", b"1"), ("b", b"2"), ("c", b"3")], 256);
        let backward = tree_of(&[("c", b"3"), ("b", b"2"), ("a", b"1")], 256);
        assert_eq!(forward.root_hash(), backward.root_hash());
    }

    #[test]
    fn test_every_key_proves_against_the_final_root() {
        let keys: Vec<String> = (0..25).map(|i| format!("key{i}")).collect();
        let mut tree = SparseMerkleTree::with_depth(64);
        for k in &keys {
            tree.insert(k, k.as_bytes()).unwrap();
        }
        let root = tree.root_hash().to_string();
        for k in &keys {
            let proof = tree.generate_proof(k).unwrap();
            assert!(proof.is_inclusion);
            assert_eq!(proof.path.len(), 64);
            assert!(proof.verify(&root), "{k}");
        }
        let absent = tree.generate_proof("missing").unwrap();
        assert!(!absent.is_inclusion);
        assert!(absent.verify(&root));
    }

    #[test]
    fn test_tampered_proofs_fail() {
        let tree = tree_of(&[("key1", b"value1"), ("key2", b"value2")], 32);
        let root = tree.root_hash().to_string();
        let proof = tree.generate_proof("key1").unwrap();
        assert!(proof.verify(&root));

        let mut wrong_value = proof.clone();
        wrong_value.value_hash = Some(hex::encode(b"forged"));
        assert!(!wrong_value.verify(&root));

        let mut wrong_key = proof.clone();
        wrong_key.key = "key2".into();
        assert!(!wrong_key.verify(&root));

        let mut wrong_sibling = proof.clone();
        wrong_sibling.path[3].sibling_hash = EMPTY_HASH.replace('e', "f");
        assert!(!wrong_sibling.verify(&root));

        let mut flipped = proof.clone();
        flipped.path[0].direction = !flipped.path[0].direction;
        assert!(!flipped.verify(&root));

        let mut wrong_level = proof.clone();
        wrong_level.path[0].level += 1;
        assert!(!wrong_level.verify(&root));

        let mut truncated = proof.clone();
        truncated.path.pop();
        assert!(!truncated.verify(&root));

        let mut malformed = proof.clone();
        malformed.path[5].sibling_hash.push('0');
        assert!(!malformed.verify(&root));

        let mut no_value = proof.clone();
        no_value.value_hash = None;
        assert!(!no_value.verify(&root), "inclusion without a value");

        let mut empty = proof.clone();
        empty.path.clear();
        assert!(!empty.verify(&root));
        // Not even against a "root" that is the leaf itself.
        let leaf = compute_leaf_hash("key1", b"value1");
        empty.root_hash = leaf.clone();
        assert!(!empty.verify(&leaf), "a proof has at least one step");

        let mut other_root = proof.clone();
        other_root.root_hash = EMPTY_HASH.to_string();
        assert!(!other_root.verify(&root));
        assert!(!proof.verify(EMPTY_HASH));
    }

    #[test]
    fn test_a_present_key_cannot_be_proved_absent() {
        let tree = tree_of(&[("present", b"1"), ("other", b"2")], 256);
        let root = tree.root_hash().to_string();

        // The honest proof for an absent key, relabelled.
        let mut forged = tree.generate_proof("absent").unwrap();
        assert!(forged.verify(&root));
        forged.key = "present".into();
        assert!(
            !forged.verify(&root),
            "the path must be the key's own, not any empty position's"
        );

        // Claiming exclusion on the key's own path, with its real siblings.
        let mut claimed = tree.generate_proof("present").unwrap();
        claimed.is_inclusion = false;
        claimed.value_hash = None;
        assert!(!claimed.verify(&root));
        claimed.is_inclusion = true;
        assert!(!claimed.verify(&root));

        // A true proof of absence can't be relabelled as one of inclusion.
        let mut relabelled = tree.generate_proof("absent").unwrap();
        relabelled.is_inclusion = true;
        assert!(
            !relabelled.verify(&root),
            "an inclusion proof must carry a value"
        );
    }

    #[test]
    fn test_leaves_are_domain_separated() {
        // "leaf:" ‖ key ‖ ":" ‖ value used to collide across the separator.
        assert_ne!(
            compute_leaf_hash("a:b", b"c"),
            compute_leaf_hash("a", b"b:c")
        );
        assert_ne!(compute_leaf_hash("ab", b""), compute_leaf_hash("a", b"b"));
        // Without the key's length, "k" with eight zero bytes would hash as
        // the key "k" ‖ be(8) with an empty value.
        assert_ne!(
            compute_leaf_hash("k", &[0; 8]),
            compute_leaf_hash("k\0\0\0\0\0\0\0\u{8}", b"")
        );
        let (l, r) = (EMPTY_HASH, EMPTY_HASH);
        assert_ne!(
            compute_internal_hash(l, r),
            compute_leaf_hash(l, r.as_bytes())
        );
    }

    #[test]
    fn test_compact_proof() {
        let mut tree = SparseMerkleTree::with_depth(16);
        tree.insert("key1", b"value1").unwrap();

        let proof = tree.generate_proof("key1").unwrap();
        let compact: CompactProof = (&proof).into();

        assert_eq!(compact.root_hash, proof.root_hash);
        assert_eq!(compact.siblings.len(), 16);
        assert_eq!(compact.path_bits.len(), 2);
    }

    #[test]
    fn test_remove_restores_the_root() {
        let base = tree_of(&[("key1", b"value1")], 256);
        let mut tree = tree_of(&[("key1", b"value1"), ("key2", b"value2")], 256);

        assert_eq!(tree.remove("key2"), Some(b"value2".to_vec()));
        assert_eq!(tree.root_hash(), base.root_hash());
        assert!(!tree.contains("key2"));
        assert_eq!(tree.remove("key2"), None);

        assert_eq!(tree.remove("key1"), Some(b"value1".to_vec()));
        assert_eq!(tree.root_hash(), SparseMerkleTree::new().root_hash());
        assert!(tree.nodes.is_empty(), "an empty tree stores no nodes");
    }

    #[test]
    fn test_reinserting_a_key_replaces_its_value() {
        let mut tree = tree_of(&[("key1", b"old"), ("key2", b"x")], 256);
        tree.insert("key1", b"new").unwrap();
        assert_eq!(tree.get("key1"), Some(b"new".as_slice()));
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(
            tree.root_hash(),
            tree_of(&[("key1", b"new"), ("key2", b"x")], 256).root_hash()
        );
    }

    #[test]
    fn test_a_shared_position_is_refused_not_overwritten() {
        let (first, second) = colliding_keys(4);
        let mut tree = SparseMerkleTree::with_depth(4);
        tree.insert(&first, b"1").unwrap();
        let root = tree.root_hash().to_string();

        let refused = tree.insert(&second, b"2");
        assert!(matches!(
            refused,
            Err(SparseMerkleError::KeyCollision { .. })
        ));
        assert_eq!(tree.root_hash(), root, "the tree is unchanged");
        assert_eq!(tree.get(&first), Some(b"1".as_slice()));
        assert!(!tree.contains(&second));

        // Nor can the absent key be proved absent from an occupied position.
        assert!(tree.generate_proof(&second).is_err());
    }

    #[test]
    fn test_depth_is_kept_in_range() {
        assert_eq!(SparseMerkleTree::with_depth(0).depth(), 1);
        assert_eq!(SparseMerkleTree::with_depth(1000).depth(), 256);
        let mut tree = SparseMerkleTree::with_depth(1);
        tree.insert("only", b"1").unwrap();
        assert!(tree
            .generate_proof("only")
            .unwrap()
            .verify(tree.root_hash()));
    }

    #[test]
    fn test_export_import() {
        let tree = tree_of(&[("key1", b"value1"), ("key2", b"value2")], 16);

        let export = tree.export();
        assert_eq!(export.leaf_count, 2);
        assert_eq!(export.root_hash, tree.root_hash());

        let json = serde_json::to_string(&export).unwrap();
        let restored = SparseMerkleTree::from_export(serde_json::from_str(&json).unwrap()).unwrap();
        assert_eq!(restored.root_hash(), tree.root_hash());
        assert_eq!(restored.get("key1"), Some(b"value1".as_slice()));
        assert!(restored
            .generate_proof("key2")
            .unwrap()
            .verify(tree.root_hash()));
    }

    #[test]
    fn test_a_corrupt_export_is_refused() {
        let tree = tree_of(&[("key1", b"value1"), ("key2", b"value2")], 16);

        let mut changed = tree.export();
        changed.entries.insert("key1".into(), b"forged".to_vec());
        assert!(matches!(
            SparseMerkleTree::from_export(changed),
            Err(SparseMerkleError::CorruptExport(_))
        ));

        let mut miscounted = tree.export();
        miscounted.leaf_count = 3;
        assert!(SparseMerkleTree::from_export(miscounted).is_err());

        let mut too_deep = tree.export();
        too_deep.depth = 257;
        assert!(SparseMerkleTree::from_export(too_deep).is_err());

        let (first, second) = colliding_keys(4);
        let mut colliding = tree_of(&[(first.as_str(), b"1")], 4).export();
        colliding.entries.insert(second, b"2".to_vec());
        colliding.leaf_count = 2;
        assert!(SparseMerkleTree::from_export(colliding).is_err());
    }

    #[test]
    fn test_batch_proofs() {
        let tree = tree_of(
            &[
                ("key1", b"value1"),
                ("key2", b"value2"),
                ("key3", b"value3"),
            ],
            16,
        );

        let keys = vec!["key1", "key2", "key3"];
        let proofs = tree.generate_batch_proofs(&keys);

        assert_eq!(proofs.len(), 3);
        for proof in proofs {
            assert!(tree.verify_proof(&proof.unwrap()));
        }
    }

    #[test]
    fn test_bit_helpers() {
        let mut p = [0u8; 32];
        p[0] = 0b1010_0000;
        assert!(get_bit(&p, 0));
        assert!(!get_bit(&p, 1));
        assert!(get_bit(&p, 2));
        assert!(!get_bit(&p, 256), "past the end is zero");
        assert_eq!(prefix(&[0xff; 32], 3)[0], 0b1110_0000);
        assert_eq!(prefix(&[0xff; 32], 3)[1], 0);
        assert_eq!(prefix(&[0xff; 32], 256), [0xff; 32]);
        assert_eq!(flip_bit(&p, 0)[0], 0b0010_0000);
        assert!(is_digest(EMPTY_HASH));
        assert!(!is_digest(&EMPTY_HASH.to_uppercase()));
    }
}
