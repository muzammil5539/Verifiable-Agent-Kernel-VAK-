//! IPFS-Lite Content-Addressable Storage Backend (MEM-006)
//!
//! This module provides an IPFS-like content-addressable storage backend
//! for the memory system. It uses content hashing (CID-like) to store
//! and retrieve data, enabling verifiable and deduplicatable storage.
//!
//! # Overview
//!
//! The IPFS-Lite backend provides:
//! - Content-addressed storage using SHA-256 hashes
//! - Merkle DAG structure for linked data
//! - Block-based storage with configurable block sizes
//! - Pinning for persistent storage
//! - DAG traversal and verification
//!
//! # Example
//!
//! ```rust
//! use vak::memory::ipfs::{IpfsLiteStore, ContentId, IpfsConfig};
//!
//! let config = IpfsConfig::default();
//! let store = IpfsLiteStore::new(config);
//!
//! // Store content
//! let content = b"Hello, IPFS!";
//! let cid = store.put(content).unwrap();
//!
//! // Retrieve content
//! let retrieved = store.get(&cid).unwrap();
//! assert_eq!(retrieved, content);
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, RwLock};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during IPFS operations
#[derive(Debug, Error)]
pub enum IpfsError {
    /// Content not found
    #[error("Content not found: {0}")]
    NotFound(String),

    /// Invalid CID format
    #[error("Invalid CID format: {0}")]
    InvalidCid(String),

    /// Block too large
    #[error("Block too large: {0} bytes exceeds max {1}")]
    BlockTooLarge(usize, usize),

    /// DAG verification failed
    #[error("DAG verification failed: {0}")]
    DagVerificationFailed(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Storage full
    #[error("Storage full: {0} bytes used of {1} max")]
    StorageFull(usize, usize),

    /// Pin error
    #[error("Pin error: {0}")]
    PinError(String),

    /// Lock error
    #[error("Lock error: {0}")]
    LockError(String),
}

/// Result type for IPFS operations
pub type IpfsResult<T> = Result<T, IpfsError>;

// ============================================================================
// Content Identifier (CID)
// ============================================================================

/// Content Identifier (similar to IPFS CID v1)
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId {
    /// Hash of the content (SHA-256)
    pub hash: [u8; 32],
    /// Version (currently always 1)
    pub version: u8,
    /// Codec type
    pub codec: Codec,
}

/// Content codec types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[derive(Default)]
pub enum Codec {
    /// Raw binary data
    #[default]
    Raw,
    /// DAG-CBOR (structured data)
    DagCbor,
    /// DAG-JSON
    DagJson,
    /// Protobuf (for compatibility)
    Protobuf,
}


impl ContentId {
    /// Create a new CID from content
    pub fn from_content(content: &[u8], codec: Codec) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let hash: [u8; 32] = hasher.finalize().into();

        Self {
            hash,
            version: 1,
            codec,
        }
    }

    /// Create a CID from an existing hash
    pub fn from_hash(hash: [u8; 32], codec: Codec) -> Self {
        Self {
            hash,
            version: 1,
            codec,
        }
    }

    /// Parse a CID from a string (base58 or base32)
    pub fn from_string(s: &str) -> IpfsResult<Self> {
        // Simple hex parsing for now
        if s.len() != 64 {
            return Err(IpfsError::InvalidCid(format!(
                "Invalid CID length: {} (expected 64)",
                s.len()
            )));
        }

        let hash: [u8; 32] = hex::decode(s)
            .map_err(|e| IpfsError::InvalidCid(e.to_string()))?
            .try_into()
            .map_err(|_| IpfsError::InvalidCid("Invalid hash length".to_string()))?;

        Ok(Self {
            hash,
            version: 1,
            codec: Codec::Raw,
        })
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// Get the short form (first 8 chars)
    pub fn short(&self) -> String {
        hex::encode(&self.hash[..4])
    }
}

impl fmt::Debug for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CID({}...)", &self.to_hex()[..8])
    }
}

impl fmt::Display for ContentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ============================================================================
// Block Types
// ============================================================================

/// A block of data in the IPFS store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Content ID
    pub cid: ContentId,
    /// Raw data
    pub data: Vec<u8>,
    /// Size in bytes
    pub size: usize,
    /// Links to other blocks (for DAG)
    pub links: Vec<Link>,
}

/// A link to another block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Link {
    /// Name of the link (optional)
    pub name: Option<String>,
    /// Target CID
    pub cid: ContentId,
    /// Size of linked content
    pub size: usize,
}

impl Block {
    /// Create a new block from data
    pub fn new(data: Vec<u8>, codec: Codec) -> Self {
        let cid = ContentId::from_content(&data, codec);
        let size = data.len();

        Self {
            cid,
            data,
            size,
            links: Vec::new(),
        }
    }

    /// Add a link to another block
    pub fn with_link(mut self, name: Option<String>, cid: ContentId, size: usize) -> Self {
        self.links.push(Link { name, cid, size });
        self
    }

    /// Verify the block's integrity
    pub fn verify(&self) -> bool {
        let computed = ContentId::from_content(&self.data, self.cid.codec);
        computed == self.cid
    }
}

// ============================================================================
// DAG Node
// ============================================================================

/// A node in a Merkle DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    /// Content ID of this node
    pub cid: ContentId,
    /// Data at this node
    pub data: Vec<u8>,
    /// Child links
    pub children: Vec<DagLink>,
    /// Metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A link in the DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagLink {
    /// Name of this link
    pub name: String,
    /// Target CID
    pub target: ContentId,
    /// Whether this is a direct or indirect link
    pub is_direct: bool,
}

impl DagNode {
    /// Create a new DAG node
    pub fn new(data: Vec<u8>) -> Self {
        let cid = ContentId::from_content(&data, Codec::DagCbor);
        Self {
            cid,
            data,
            children: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    /// Add a child link
    pub fn with_child(mut self, name: impl Into<String>, target: ContentId) -> Self {
        self.children.push(DagLink {
            name: name.into(),
            target,
            is_direct: true,
        });
        // Recompute CID since structure changed
        self.recompute_cid();
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Recompute the CID after modifications
    fn recompute_cid(&mut self) {
        let serialized = serde_json::to_vec(&self).unwrap_or_default();
        self.cid = ContentId::from_content(&serialized, Codec::DagCbor);
    }

    /// Get all descendant CIDs
    pub fn descendants(&self) -> Vec<ContentId> {
        self.children.iter().map(|l| l.target.clone()).collect()
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the IPFS-Lite store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpfsConfig {
    /// Maximum block size in bytes
    pub max_block_size: usize,
    /// Maximum total storage in bytes
    pub max_storage: usize,
    /// Enable garbage collection
    pub gc_enabled: bool,
    /// GC threshold (trigger when storage exceeds this percentage)
    pub gc_threshold: f64,
    /// Default codec for new blocks
    pub default_codec: Codec,
}

impl Default for IpfsConfig {
    fn default() -> Self {
        Self {
            max_block_size: 1024 * 1024,    // 1MB
            max_storage: 100 * 1024 * 1024, // 100MB
            gc_enabled: true,
            gc_threshold: 0.9,
            default_codec: Codec::Raw,
        }
    }
}

impl IpfsConfig {
    /// Create a new configuration
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum block size
    pub fn with_max_block_size(mut self, size: usize) -> Self {
        self.max_block_size = size;
        self
    }

    /// Set maximum storage
    pub fn with_max_storage(mut self, size: usize) -> Self {
        self.max_storage = size;
        self
    }

    /// Enable or disable GC
    pub fn with_gc(mut self, enabled: bool) -> Self {
        self.gc_enabled = enabled;
        self
    }
}

// ============================================================================
// Store Statistics
// ============================================================================

/// Statistics about the IPFS store
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StoreStats {
    /// Total number of blocks
    pub block_count: usize,
    /// Total storage used in bytes
    pub storage_used: usize,
    /// Number of pinned blocks
    pub pinned_count: usize,
    /// Number of DAG roots
    pub dag_roots: usize,
}

// ============================================================================
// IPFS-Lite Store
// ============================================================================

/// In-memory IPFS-like content-addressable store
pub struct IpfsLiteStore {
    /// Configuration
    config: IpfsConfig,
    /// Block storage (CID -> Block)
    blocks: Arc<RwLock<HashMap<ContentId, Block>>>,
    /// Pinned CIDs (won't be garbage collected)
    pins: Arc<RwLock<HashSet<ContentId>>>,
    /// DAG roots
    roots: Arc<RwLock<HashSet<ContentId>>>,
}

impl IpfsLiteStore {
    /// Create a new IPFS-Lite store
    pub fn new(config: IpfsConfig) -> Self {
        Self {
            config,
            blocks: Arc::new(RwLock::new(HashMap::new())),
            pins: Arc::new(RwLock::new(HashSet::new())),
            roots: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Put raw content into the store
    pub fn put(&self, data: &[u8]) -> IpfsResult<ContentId> {
        self.put_with_codec(data, self.config.default_codec)
    }

    /// Put content with a specific codec
    pub fn put_with_codec(&self, data: &[u8], codec: Codec) -> IpfsResult<ContentId> {
        if data.len() > self.config.max_block_size {
            return Err(IpfsError::BlockTooLarge(
                data.len(),
                self.config.max_block_size,
            ));
        }

        let block = Block::new(data.to_vec(), codec);
        let cid = block.cid.clone();

        let mut blocks = self
            .blocks
            .write()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        // Check storage limits
        let current_size: usize = blocks.values().map(|b| b.size).sum();
        if current_size + data.len() > self.config.max_storage {
            if self.config.gc_enabled {
                drop(blocks);
                self.gc()?;
                blocks = self
                    .blocks
                    .write()
                    .map_err(|e| IpfsError::LockError(e.to_string()))?;
            } else {
                return Err(IpfsError::StorageFull(
                    current_size + data.len(),
                    self.config.max_storage,
                ));
            }
        }

        blocks.insert(cid.clone(), block);
        Ok(cid)
    }

    /// Get content by CID
    pub fn get(&self, cid: &ContentId) -> IpfsResult<Vec<u8>> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        blocks
            .get(cid)
            .map(|b| b.data.clone())
            .ok_or_else(|| IpfsError::NotFound(cid.to_hex()))
    }

    /// Get a block by CID
    pub fn get_block(&self, cid: &ContentId) -> IpfsResult<Block> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        blocks
            .get(cid)
            .cloned()
            .ok_or_else(|| IpfsError::NotFound(cid.to_hex()))
    }

    /// Check if content exists
    pub fn has(&self, cid: &ContentId) -> IpfsResult<bool> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        Ok(blocks.contains_key(cid))
    }

    /// Delete content (fails if pinned)
    pub fn delete(&self, cid: &ContentId) -> IpfsResult<()> {
        let pins = self
            .pins
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        if pins.contains(cid) {
            return Err(IpfsError::PinError(format!(
                "Cannot delete pinned content: {}",
                cid.short()
            )));
        }

        drop(pins);

        let mut blocks = self
            .blocks
            .write()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        blocks.remove(cid);
        Ok(())
    }

    /// Pin content to prevent garbage collection
    pub fn pin(&self, cid: &ContentId) -> IpfsResult<()> {
        // Verify content exists
        if !self.has(cid)? {
            return Err(IpfsError::NotFound(cid.to_hex()));
        }

        let mut pins = self
            .pins
            .write()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        pins.insert(cid.clone());
        Ok(())
    }

    /// Unpin content
    pub fn unpin(&self, cid: &ContentId) -> IpfsResult<()> {
        let mut pins = self
            .pins
            .write()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        pins.remove(cid);
        Ok(())
    }

    /// Check if content is pinned
    pub fn is_pinned(&self, cid: &ContentId) -> IpfsResult<bool> {
        let pins = self
            .pins
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        Ok(pins.contains(cid))
    }

    /// Put a DAG node
    pub fn put_dag(&self, node: &DagNode) -> IpfsResult<ContentId> {
        let serialized =
            serde_json::to_vec(node).map_err(|e| IpfsError::SerializationError(e.to_string()))?;

        let cid = self.put_with_codec(&serialized, Codec::DagCbor)?;

        // Mark as DAG root if it has no parents
        let mut roots = self
            .roots
            .write()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;
        roots.insert(cid.clone());

        // Remove children from roots (they're no longer roots)
        for child in &node.children {
            roots.remove(&child.target);
        }

        Ok(cid)
    }

    /// Get a DAG node
    pub fn get_dag(&self, cid: &ContentId) -> IpfsResult<DagNode> {
        let data = self.get(cid)?;
        serde_json::from_slice(&data).map_err(|e| IpfsError::SerializationError(e.to_string()))
    }

    /// Verify a block's integrity
    pub fn verify(&self, cid: &ContentId) -> IpfsResult<bool> {
        let block = self.get_block(cid)?;
        Ok(block.verify())
    }

    /// Verify an entire DAG recursively
    pub fn verify_dag(&self, root: &ContentId) -> IpfsResult<bool> {
        let block = self.get_block(root)?;
        if !block.verify() {
            return Ok(false);
        }

        for link in &block.links {
            if !self.verify_dag(&link.cid)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Get all CIDs in the store
    pub fn list_cids(&self) -> IpfsResult<Vec<ContentId>> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        Ok(blocks.keys().cloned().collect())
    }

    /// Get store statistics
    pub fn stats(&self) -> IpfsResult<StoreStats> {
        let blocks = self
            .blocks
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;
        let pins = self
            .pins
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;
        let roots = self
            .roots
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        Ok(StoreStats {
            block_count: blocks.len(),
            storage_used: blocks.values().map(|b| b.size).sum(),
            pinned_count: pins.len(),
            dag_roots: roots.len(),
        })
    }

    /// Run garbage collection
    pub fn gc(&self) -> IpfsResult<usize> {
        let pins = self
            .pins
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;
        let roots = self
            .roots
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        // Collect all reachable CIDs
        let mut reachable: HashSet<ContentId> = HashSet::new();
        reachable.extend(pins.iter().cloned());
        reachable.extend(roots.iter().cloned());

        // Traverse DAGs to find all reachable blocks
        let blocks_read = self
            .blocks
            .read()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        let mut to_visit: Vec<ContentId> = reachable.iter().cloned().collect();
        while let Some(cid) = to_visit.pop() {
            if let Some(block) = blocks_read.get(&cid) {
                for link in &block.links {
                    if reachable.insert(link.cid.clone()) {
                        to_visit.push(link.cid.clone());
                    }
                }
            }
        }

        drop(blocks_read);
        drop(pins);
        drop(roots);

        // Remove unreachable blocks
        let mut blocks = self
            .blocks
            .write()
            .map_err(|e| IpfsError::LockError(e.to_string()))?;

        let to_remove: Vec<ContentId> = blocks
            .keys()
            .filter(|cid| !reachable.contains(cid))
            .cloned()
            .collect();

        let removed_count = to_remove.len();
        for cid in to_remove {
            blocks.remove(&cid);
        }

        Ok(removed_count)
    }

    /// Get configuration
    pub fn config(&self) -> &IpfsConfig {
        &self.config
    }
}

impl Default for IpfsLiteStore {
    fn default() -> Self {
        Self::new(IpfsConfig::default())
    }
}

impl fmt::Debug for IpfsLiteStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IpfsLiteStore {{ config: {:?} }}", self.config)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_id_from_content() {
        let content = b"Hello, IPFS!";
        let cid = ContentId::from_content(content, Codec::Raw);

        assert_eq!(cid.version, 1);
        assert_eq!(cid.codec, Codec::Raw);
        assert_eq!(cid.hash.len(), 32);
    }

    #[test]
    fn test_content_id_deterministic() {
        let content = b"Same content";
        let cid1 = ContentId::from_content(content, Codec::Raw);
        let cid2 = ContentId::from_content(content, Codec::Raw);

        assert_eq!(cid1, cid2);
    }

    #[test]
    fn test_content_id_different_content() {
        let cid1 = ContentId::from_content(b"Content 1", Codec::Raw);
        let cid2 = ContentId::from_content(b"Content 2", Codec::Raw);

        assert_ne!(cid1, cid2);
    }

    #[test]
    fn test_content_id_from_string() {
        let cid = ContentId::from_content(b"test", Codec::Raw);
        let hex = cid.to_hex();
        let parsed = ContentId::from_string(&hex).unwrap();

        assert_eq!(cid.hash, parsed.hash);
    }

    #[test]
    fn test_block_creation() {
        let data = b"Block data".to_vec();
        let block = Block::new(data.clone(), Codec::Raw);

        assert_eq!(block.data, data);
        assert_eq!(block.size, data.len());
        assert!(block.links.is_empty());
    }

    #[test]
    fn test_block_verification() {
        let block = Block::new(b"Valid block".to_vec(), Codec::Raw);
        assert!(block.verify());
    }

    #[test]
    fn test_ipfs_config_default() {
        let config = IpfsConfig::default();
        assert_eq!(config.max_block_size, 1024 * 1024);
        assert!(config.gc_enabled);
    }

    #[test]
    fn test_store_put_get() {
        let store = IpfsLiteStore::new(IpfsConfig::default());
        let content = b"Test content";

        let cid = store.put(content).unwrap();
        let retrieved = store.get(&cid).unwrap();

        assert_eq!(retrieved, content);
    }

    #[test]
    fn test_store_has() {
        let store = IpfsLiteStore::new(IpfsConfig::default());
        let content = b"Test content";

        let cid = store.put(content).unwrap();
        assert!(store.has(&cid).unwrap());

        let fake_cid = ContentId::from_content(b"nonexistent", Codec::Raw);
        assert!(!store.has(&fake_cid).unwrap());
    }

    #[test]
    fn test_store_delete() {
        let store = IpfsLiteStore::new(IpfsConfig::default());
        let content = b"Test content";

        let cid = store.put(content).unwrap();
        assert!(store.has(&cid).unwrap());

        store.delete(&cid).unwrap();
        assert!(!store.has(&cid).unwrap());
    }

    #[test]
    fn test_store_pin() {
        let store = IpfsLiteStore::new(IpfsConfig::default());
        let content = b"Test content";

        let cid = store.put(content).unwrap();
        store.pin(&cid).unwrap();

        assert!(store.is_pinned(&cid).unwrap());

        // Cannot delete pinned content
        let result = store.delete(&cid);
        assert!(matches!(result, Err(IpfsError::PinError(_))));

        // Unpin and then delete
        store.unpin(&cid).unwrap();
        assert!(!store.is_pinned(&cid).unwrap());
        store.delete(&cid).unwrap();
    }

    #[test]
    fn test_store_block_too_large() {
        let config = IpfsConfig::default().with_max_block_size(100);
        let store = IpfsLiteStore::new(config);

        let large_content = vec![0u8; 200];
        let result = store.put(&large_content);

        assert!(matches!(result, Err(IpfsError::BlockTooLarge(200, 100))));
    }

    #[test]
    fn test_store_verify() {
        let store = IpfsLiteStore::new(IpfsConfig::default());
        let content = b"Test content";

        let cid = store.put(content).unwrap();
        assert!(store.verify(&cid).unwrap());
    }

    #[test]
    fn test_dag_node_creation() {
        let node =
            DagNode::new(b"Node data".to_vec()).with_metadata("type", serde_json::json!("test"));

        assert!(!node.data.is_empty());
        assert!(node.metadata.contains_key("type"));
    }

    #[test]
    fn test_dag_node_with_children() {
        let child_cid = ContentId::from_content(b"child", Codec::Raw);
        let node = DagNode::new(b"Parent".to_vec()).with_child("child1", child_cid.clone());

        assert_eq!(node.children.len(), 1);
        assert_eq!(node.children[0].target, child_cid);
    }

    #[test]
    fn test_store_dag_put_get() {
        let store = IpfsLiteStore::new(IpfsConfig::default());

        let node =
            DagNode::new(b"DAG node".to_vec()).with_metadata("version", serde_json::json!(1));

        let cid = store.put_dag(&node).unwrap();
        let retrieved = store.get_dag(&cid).unwrap();

        assert_eq!(retrieved.data, node.data);
    }

    #[test]
    fn test_store_stats() {
        let store = IpfsLiteStore::new(IpfsConfig::default());

        store.put(b"Content 1").unwrap();
        let cid2 = store.put(b"Content 2").unwrap();
        store.pin(&cid2).unwrap();

        let stats = store.stats().unwrap();
        assert_eq!(stats.block_count, 2);
        assert_eq!(stats.pinned_count, 1);
    }

    #[test]
    fn test_store_gc() {
        let store = IpfsLiteStore::new(IpfsConfig::default());

        // Put some content
        let cid1 = store.put(b"Content 1").unwrap();
        let cid2 = store.put(b"Content 2").unwrap();
        store.put(b"Content 3").unwrap();

        // Pin one, make another a root
        store.pin(&cid1).unwrap();
        {
            let mut roots = store.roots.write().unwrap();
            roots.insert(cid2.clone());
        }

        // Run GC
        let removed = store.gc().unwrap();

        // Content 3 should be removed (not pinned, not a root)
        assert_eq!(removed, 1);
        assert!(store.has(&cid1).unwrap());
        assert!(store.has(&cid2).unwrap());
    }

    #[test]
    fn test_list_cids() {
        let store = IpfsLiteStore::new(IpfsConfig::default());

        let cid1 = store.put(b"Content 1").unwrap();
        let cid2 = store.put(b"Content 2").unwrap();

        let cids = store.list_cids().unwrap();
        assert_eq!(cids.len(), 2);
        assert!(cids.contains(&cid1));
        assert!(cids.contains(&cid2));
    }

    #[test]
    fn test_content_id_short() {
        let cid = ContentId::from_content(b"test", Codec::Raw);
        let short = cid.short();

        // Short form should be 8 hex chars (4 bytes)
        assert_eq!(short.len(), 8);
    }
}
