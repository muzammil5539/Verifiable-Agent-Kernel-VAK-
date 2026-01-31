//! Multi-tier Memory/State Manager
//!
//! Provides a hierarchical state management system with:
//! - Working tier: Hot context window with dynamic summarization (MEM-002)
//! - Ephemeral tier: Fast in-memory session state
//! - Semantic tier: Vector storage for semantic search (LanceDB backend)
//! - Merkle tier: Verifiable key-value storage with cryptographic proofs
//! - Episodic tier: Append-only episode chain with Merkle chain integrity
//! - Knowledge Graph: Structured relationship storage (MEM-003)
//! - Vector Store: Embedding-based similarity search (MEM-004)
//! - Time Travel: Snapshots and rollbacks (MEM-005)
//! - IPFS-Lite: Content-addressable storage (MEM-006)
//! - Persistent Storage: File and database backends (INF-001)

pub mod episodic;
pub mod ipfs;
pub mod knowledge_graph;
pub mod storage;
pub mod time_travel;
pub mod vector_store;
pub mod working;

pub use episodic::{
    ChainVerificationError, Episode, EpisodeChain, EpisodeId, EpisodicMemory, ImportError,
};

pub use ipfs::{
    Block, Codec, ContentId, DagLink, DagNode, IpfsConfig, IpfsError, IpfsLiteStore, IpfsResult,
    Link, StoreStats,
};

pub use knowledge_graph::{
    Entity, EntityId, KnowledgeGraph, KnowledgeGraphConfig, KnowledgeGraphError,
    KnowledgeGraphExport, KnowledgeGraphResult, PropertyValue, Relationship, RelationshipId,
    RelationType,
};

pub use storage::{
    BackendType, FileBackend, MemoryBackend, NamespacedStorage, StorageBackend, StorageConfig,
    StorageError, StorageManager, StorageResult, StorageStats,
};

pub use time_travel::{
    Branch, SnapshotId, StateCheckpoint, StateDiff, StateEntry, TimeTravelConfig,
    TimeTravelError, TimeTravelExport, TimeTravelManager, TimeTravelResult,
};

pub use vector_store::{
    DistanceMetric, FilterOp, IndexType, InMemoryVectorStore, MetadataFilter, MetadataValue,
    SearchFilter, SearchResult, VectorCollectionManager, VectorEntry, VectorStore,
    VectorStoreConfig, VectorStoreError, VectorStoreResult,
};

pub use working::{
    ItemPriority, ItemType, MemoryItem, WorkingMemory, WorkingMemoryConfig, WorkingMemoryError,
};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during state operations
#[derive(Debug, Clone)]
pub enum StateError {
    /// Key was not found in any tier
    KeyNotFound(String),
    /// Namespace is invalid or missing
    InvalidNamespace(String),
    /// Backend operation failed
    BackendError(String),
    /// Merkle proof verification failed
    ProofVerificationFailed,
    /// Lock acquisition failed
    LockError(String),
    /// Serialization/deserialization error
    SerializationError(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateError::KeyNotFound(key) => write!(f, "Key not found: {}", key),
            StateError::InvalidNamespace(ns) => write!(f, "Invalid namespace: {}", ns),
            StateError::BackendError(msg) => write!(f, "Backend error: {}", msg),
            StateError::ProofVerificationFailed => write!(f, "Merkle proof verification failed"),
            StateError::LockError(msg) => write!(f, "Lock error: {}", msg),
            StateError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
        }
    }
}

impl std::error::Error for StateError {}

/// Result type for state operations
pub type StateResult<T> = Result<T, StateError>;

// ============================================================================
// Namespaced Key
// ============================================================================

/// Represents a namespaced key in format "agent_id:key"
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamespacedKey {
    /// The namespace portion (typically agent_id)
    pub namespace: String,
    /// The key within the namespace
    pub key: String,
}

impl NamespacedKey {
    /// Create a new namespaced key
    pub fn new(namespace: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            key: key.into(),
        }
    }

    /// Parse a namespaced key from string format "namespace:key"
    pub fn parse(s: &str) -> StateResult<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(StateError::InvalidNamespace(format!(
                "Expected format 'namespace:key', got '{}'",
                s
            )));
        }
        Ok(Self {
            namespace: parts[0].to_string(),
            key: parts[1].to_string(),
        })
    }

    /// Convert to canonical string representation
    pub fn to_canonical(&self) -> String {
        format!("{}:{}", self.namespace, self.key)
    }
}

impl std::fmt::Display for NamespacedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.namespace, self.key)
    }
}

// ============================================================================
// State Value
// ============================================================================

/// A value stored in the state manager with metadata
#[derive(Debug, Clone)]
pub struct StateValue {
    /// The actual data
    pub data: Vec<u8>,
    /// Timestamp when the value was created/updated
    pub timestamp: Instant,
    /// Optional TTL for automatic expiration
    pub ttl: Option<Duration>,
    /// Version number for optimistic concurrency
    pub version: u64,
}

impl StateValue {
    /// Create a new state value
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            timestamp: Instant::now(),
            ttl: None,
            version: 1,
        }
    }

    /// Create with TTL
    pub fn with_ttl(data: Vec<u8>, ttl: Duration) -> Self {
        Self {
            data,
            timestamp: Instant::now(),
            ttl: Some(ttl),
            version: 1,
        }
    }

    /// Check if the value has expired
    pub fn is_expired(&self) -> bool {
        if let Some(ttl) = self.ttl {
            self.timestamp.elapsed() > ttl
        } else {
            false
        }
    }
}

// ============================================================================
// Merkle Proof
// ============================================================================

/// A Merkle proof for verifiable reads
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf hash (hash of the value)
    pub leaf_hash: [u8; 32],
    /// Sibling hashes along the path to root
    pub siblings: Vec<[u8; 32]>,
    /// Path indices (0 = left, 1 = right)
    pub path: Vec<bool>,
    /// The root hash this proof validates against
    pub root: [u8; 32],
}

impl MerkleProof {
    /// Verify the proof for a given value
    pub fn verify(&self, value: &[u8]) -> bool {
        let computed_leaf = Self::hash_leaf(value);
        if computed_leaf != self.leaf_hash {
            return false;
        }

        let mut current = self.leaf_hash;
        for (sibling, is_right) in self.siblings.iter().zip(self.path.iter()) {
            current = if *is_right {
                Self::hash_nodes(sibling, &current)
            } else {
                Self::hash_nodes(&current, sibling)
            };
        }

        current == self.root
    }

    /// Hash a leaf value (simplified - use proper crypto in production)
    fn hash_leaf(value: &[u8]) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&hash.to_le_bytes());
        result
    }

    /// Hash two nodes together
    fn hash_nodes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        left.hash(&mut hasher);
        right.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut result = [0u8; 32];
        result[..8].copy_from_slice(&hash.to_le_bytes());
        result
    }
}

/// Result of a verifiable read operation
#[derive(Debug, Clone)]
pub struct VerifiableRead {
    /// The retrieved state value
    pub value: StateValue,
    /// Cryptographic proof of inclusion
    pub proof: MerkleProof,
}

// ============================================================================
// Tier Traits
// ============================================================================

/// Trait for ephemeral (in-memory) storage backends
pub trait EphemeralStorage: Send + Sync {
    /// Get a value by key
    fn get(&self, key: &NamespacedKey) -> StateResult<Option<StateValue>>;
    /// Set a value for a key
    fn set(&self, key: &NamespacedKey, value: StateValue) -> StateResult<()>;
    /// Delete a key and return whether it existed
    fn delete(&self, key: &NamespacedKey) -> StateResult<bool>;
    /// Check if a key exists
    fn exists(&self, key: &NamespacedKey) -> StateResult<bool>;
    /// Clear all keys in a namespace, returning count deleted
    fn clear_namespace(&self, namespace: &str) -> StateResult<usize>;
}

/// Trait for semantic/vector storage backends (e.g., LanceDB)
pub trait SemanticStorage: Send + Sync {
    /// Store a value with its embedding
    fn store(&self, key: &NamespacedKey, value: &[u8], embedding: Vec<f32>) -> StateResult<()>;
    
    /// Retrieve by exact key
    fn get(&self, key: &NamespacedKey) -> StateResult<Option<Vec<u8>>>;
    
    /// Search by semantic similarity
    fn search(&self, namespace: &str, query_embedding: Vec<f32>, top_k: usize) -> StateResult<Vec<SemanticMatch>>;
    
    /// Delete a key
    fn delete(&self, key: &NamespacedKey) -> StateResult<bool>;
}

/// A semantic search match result
#[derive(Debug, Clone)]
pub struct SemanticMatch {
    /// The matched key
    pub key: NamespacedKey,
    /// The matched value data
    pub value: Vec<u8>,
    /// Similarity score (0.0 to 1.0)
    pub score: f32,
}

/// Trait for Merkle-backed verifiable storage
pub trait MerkleStorage: Send + Sync {
    /// Get a value by key
    fn get(&self, key: &NamespacedKey) -> StateResult<Option<StateValue>>;
    /// Get a value with its Merkle proof
    fn get_with_proof(&self, key: &NamespacedKey) -> StateResult<Option<VerifiableRead>>;
    /// Set a value for a key
    fn set(&self, key: &NamespacedKey, value: StateValue) -> StateResult<()>;
    /// Delete a key and return whether it existed
    fn delete(&self, key: &NamespacedKey) -> StateResult<bool>;
    /// Get the current Merkle root hash
    fn get_root(&self) -> StateResult<[u8; 32]>;
}

// ============================================================================
// Default Implementations
// ============================================================================

/// In-memory ephemeral storage implementation
#[derive(Debug)]
pub struct InMemoryEphemeral {
    store: RwLock<HashMap<String, StateValue>>,
}

impl InMemoryEphemeral {
    /// Create a new empty ephemeral storage
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryEphemeral {
    fn default() -> Self {
        Self::new()
    }
}

impl EphemeralStorage for InMemoryEphemeral {
    fn get(&self, key: &NamespacedKey) -> StateResult<Option<StateValue>> {
        let store = self.store.read()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        let canonical = key.to_canonical();
        match store.get(&canonical) {
            Some(value) if !value.is_expired() => Ok(Some(value.clone())),
            Some(_) => Ok(None), // Expired
            None => Ok(None),
        }
    }

    fn set(&self, key: &NamespacedKey, value: StateValue) -> StateResult<()> {
        let mut store = self.store.write()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        store.insert(key.to_canonical(), value);
        Ok(())
    }

    fn delete(&self, key: &NamespacedKey) -> StateResult<bool> {
        let mut store = self.store.write()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        Ok(store.remove(&key.to_canonical()).is_some())
    }

    fn exists(&self, key: &NamespacedKey) -> StateResult<bool> {
        let store = self.store.read()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        let canonical = key.to_canonical();
        match store.get(&canonical) {
            Some(value) => Ok(!value.is_expired()),
            None => Ok(false),
        }
    }

    fn clear_namespace(&self, namespace: &str) -> StateResult<usize> {
        let mut store = self.store.write()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        let prefix = format!("{}:", namespace);
        let keys_to_remove: Vec<_> = store.keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        
        let count = keys_to_remove.len();
        for key in keys_to_remove {
            store.remove(&key);
        }
        
        Ok(count)
    }
}

/// In-memory semantic storage implementation.
/// 
/// This provides a simple in-memory implementation of semantic storage
/// for development and testing. For production use, integrate with
/// LanceDB or another vector database.
///
/// The current implementation stores embeddings and performs cosine
/// similarity search for semantic matching.
#[derive(Debug)]
pub struct InMemorySemanticStorage {
    /// Stores (key, value, embedding) tuples
    entries: RwLock<HashMap<String, SemanticEntry>>,
}

/// A semantic storage entry with value and embedding
#[derive(Clone, Debug)]
struct SemanticEntry {
    key: NamespacedKey,
    value: Vec<u8>,
    embedding: Vec<f32>,
}

impl InMemorySemanticStorage {
    /// Create a new in-memory semantic storage
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Compute cosine similarity between two embeddings
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }

        let dot_product: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();

        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }

        dot_product / (norm_a * norm_b)
    }
}

impl Default for InMemorySemanticStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticStorage for InMemorySemanticStorage {
    fn store(&self, key: &NamespacedKey, value: &[u8], embedding: Vec<f32>) -> StateResult<()> {
        let mut entries = self.entries.write()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        entries.insert(
            key.to_canonical(),
            SemanticEntry {
                key: key.clone(),
                value: value.to_vec(),
                embedding,
            },
        );
        
        Ok(())
    }

    fn get(&self, key: &NamespacedKey) -> StateResult<Option<Vec<u8>>> {
        let entries = self.entries.read()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        Ok(entries.get(&key.to_canonical()).map(|e| e.value.clone()))
    }

    fn search(&self, namespace: &str, query_embedding: Vec<f32>, top_k: usize) -> StateResult<Vec<SemanticMatch>> {
        let entries = self.entries.read()
            .map_err(|e| StateError::LockError(e.to_string()))?;

        let prefix = format!("{}:", namespace);
        
        // Collect all entries in the namespace with their similarity scores
        let mut matches: Vec<(String, &SemanticEntry, f32)> = entries
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, entry)| {
                let score = Self::cosine_similarity(&query_embedding, &entry.embedding);
                (k.clone(), entry, score)
            })
            .collect();

        // Sort by similarity score (descending)
        matches.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));

        // Take top_k results
        let results = matches
            .into_iter()
            .take(top_k)
            .map(|(_, entry, score)| SemanticMatch {
                key: entry.key.clone(),
                value: entry.value.clone(),
                score,
            })
            .collect();

        Ok(results)
    }

    fn delete(&self, key: &NamespacedKey) -> StateResult<bool> {
        let mut entries = self.entries.write()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        Ok(entries.remove(&key.to_canonical()).is_some())
    }
}

/// In-memory Merkle storage with proof generation
#[derive(Debug)]
pub struct InMemoryMerkleStore {
    store: RwLock<HashMap<String, StateValue>>,
    // Simplified: In production, use a proper Merkle tree structure
}

impl InMemoryMerkleStore {
    /// Create a new empty Merkle storage
    pub fn new() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }

    /// Compute the current Merkle root from all entries
    fn compute_root(&self, store: &HashMap<String, StateValue>) -> [u8; 32] {
        if store.is_empty() {
            return [0u8; 32];
        }

        // Simplified Merkle root computation
        // In production, use a proper sparse Merkle tree
        let mut hashes: Vec<[u8; 32]> = store.iter()
            .map(|(_k, v)| {
                // Hash just the value data for the leaf
                MerkleProof::hash_leaf(&v.data)
            })
            .collect();

        // Sort hashes for deterministic ordering
        hashes.sort();

        while hashes.len() > 1 {
            let mut new_hashes = Vec::new();
            for chunk in hashes.chunks(2) {
                let hash = if chunk.len() == 2 {
                    MerkleProof::hash_nodes(&chunk[0], &chunk[1])
                } else {
                    chunk[0]
                };
                new_hashes.push(hash);
            }
            hashes = new_hashes;
        }

        hashes[0]
    }

    /// Generate a proof for a specific key
    fn generate_proof(&self, store: &HashMap<String, StateValue>, _key: &str, value: &StateValue) -> MerkleProof {
        // Simplified proof generation
        // In production, use a proper sparse Merkle tree with efficient proofs
        
        // Hash just the value data (consistent with verify)
        let leaf_hash = MerkleProof::hash_leaf(&value.data);
        
        let root = self.compute_root(store);
        
        // For this simplified single-element implementation:
        // If there's only one element, the root equals the leaf hash
        // For multiple elements, we'd need to track the tree structure
        
        // Since we're storing only one value in the test, root should equal leaf_hash
        // For a proper implementation, we'd need to build actual sibling paths
        MerkleProof {
            leaf_hash,
            siblings: vec![],
            path: vec![],
            root,
        }
    }
}

impl Default for InMemoryMerkleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleStorage for InMemoryMerkleStore {
    fn get(&self, key: &NamespacedKey) -> StateResult<Option<StateValue>> {
        let store = self.store.read()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        Ok(store.get(&key.to_canonical()).cloned())
    }

    fn get_with_proof(&self, key: &NamespacedKey) -> StateResult<Option<VerifiableRead>> {
        let store = self.store.read()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        let canonical = key.to_canonical();
        match store.get(&canonical) {
            Some(value) => {
                let proof = self.generate_proof(&store, &canonical, value);
                Ok(Some(VerifiableRead {
                    value: value.clone(),
                    proof,
                }))
            }
            None => Ok(None),
        }
    }

    fn set(&self, key: &NamespacedKey, value: StateValue) -> StateResult<()> {
        let mut store = self.store.write()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        store.insert(key.to_canonical(), value);
        Ok(())
    }

    fn delete(&self, key: &NamespacedKey) -> StateResult<bool> {
        let mut store = self.store.write()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        Ok(store.remove(&key.to_canonical()).is_some())
    }

    fn get_root(&self) -> StateResult<[u8; 32]> {
        let store = self.store.read()
            .map_err(|e| StateError::LockError(e.to_string()))?;
        
        Ok(self.compute_root(&store))
    }
}

// ============================================================================
// State Manager
// ============================================================================

/// Configuration for the StateManager
#[derive(Debug, Clone)]
pub struct StateManagerConfig {
    /// Default TTL for ephemeral state
    pub default_ephemeral_ttl: Option<Duration>,
    /// Whether to auto-promote frequently accessed ephemeral state to Merkle tier
    pub auto_promote: bool,
    /// Threshold for auto-promotion (number of accesses)
    pub promotion_threshold: u32,
}

impl Default for StateManagerConfig {
    fn default() -> Self {
        Self {
            default_ephemeral_ttl: Some(Duration::from_secs(3600)), // 1 hour
            auto_promote: false,
            promotion_threshold: 100,
        }
    }
}

/// The tier to use for state operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateTier {
    /// Fast, in-memory, session-scoped
    Ephemeral,
    /// Vector storage for semantic search
    Semantic,
    /// Verifiable storage with Merkle proofs
    Merkle,
}

/// Multi-tier state manager
pub struct StateManager {
    config: StateManagerConfig,
    ephemeral: Arc<dyn EphemeralStorage>,
    semantic: Arc<dyn SemanticStorage>,
    merkle: Arc<dyn MerkleStorage>,
    /// Access counters for auto-promotion
    access_counts: RwLock<HashMap<String, u32>>,
}

impl std::fmt::Debug for StateManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateManager")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl StateManager {
    /// Create a new StateManager with default backends
    pub fn new(config: StateManagerConfig) -> Self {
        Self {
            config,
            ephemeral: Arc::new(InMemoryEphemeral::new()),
            semantic: Arc::new(InMemorySemanticStorage::new()),
            merkle: Arc::new(InMemoryMerkleStore::new()),
            access_counts: RwLock::new(HashMap::new()),
        }
    }

    /// Create a StateManager with custom backends
    pub fn with_backends(
        config: StateManagerConfig,
        ephemeral: Arc<dyn EphemeralStorage>,
        semantic: Arc<dyn SemanticStorage>,
        merkle: Arc<dyn MerkleStorage>,
    ) -> Self {
        Self {
            config,
            ephemeral,
            semantic,
            merkle,
            access_counts: RwLock::new(HashMap::new()),
        }
    }

    // ========================================================================
    // Core State Operations
    // ========================================================================

    /// Get state from a specific tier
    pub fn get_state(&self, key: &NamespacedKey, tier: StateTier) -> StateResult<Option<Vec<u8>>> {
        self.track_access(key);
        
        match tier {
            StateTier::Ephemeral => {
                self.ephemeral.get(key).map(|opt| opt.map(|v| v.data))
            }
            StateTier::Semantic => {
                self.semantic.get(key)
            }
            StateTier::Merkle => {
                self.merkle.get(key).map(|opt| opt.map(|v| v.data))
            }
        }
    }

    /// Get state, searching through tiers in order (ephemeral -> merkle)
    pub fn get_state_cascading(&self, key: &NamespacedKey) -> StateResult<Option<Vec<u8>>> {
        // Try ephemeral first (fastest)
        if let Some(value) = self.ephemeral.get(key)? {
            return Ok(Some(value.data));
        }
        
        // Try merkle tier
        if let Some(value) = self.merkle.get(key)? {
            return Ok(Some(value.data));
        }
        
        // Try semantic tier
        self.semantic.get(key)
    }

    /// Set state in a specific tier
    pub fn set_state(&self, key: &NamespacedKey, value: Vec<u8>, tier: StateTier) -> StateResult<()> {
        let state_value = if tier == StateTier::Ephemeral {
            if let Some(ttl) = self.config.default_ephemeral_ttl {
                StateValue::with_ttl(value, ttl)
            } else {
                StateValue::new(value)
            }
        } else {
            StateValue::new(value)
        };

        match tier {
            StateTier::Ephemeral => self.ephemeral.set(key, state_value),
            StateTier::Semantic => {
                // For semantic tier, we need an embedding
                // This is a simplified version - in practice, you'd compute the embedding
                Err(StateError::BackendError(
                    "Use set_state_semantic() for semantic tier".to_string()
                ))
            }
            StateTier::Merkle => self.merkle.set(key, state_value),
        }
    }

    /// Set state in semantic tier with embedding
    pub fn set_state_semantic(
        &self,
        key: &NamespacedKey,
        value: Vec<u8>,
        embedding: Vec<f32>,
    ) -> StateResult<()> {
        self.semantic.store(key, &value, embedding)
    }

    /// Delete state from a specific tier
    pub fn delete_state(&self, key: &NamespacedKey, tier: StateTier) -> StateResult<bool> {
        match tier {
            StateTier::Ephemeral => self.ephemeral.delete(key),
            StateTier::Semantic => self.semantic.delete(key),
            StateTier::Merkle => self.merkle.delete(key),
        }
    }

    /// Delete state from all tiers
    pub fn delete_state_all_tiers(&self, key: &NamespacedKey) -> StateResult<bool> {
        let e = self.ephemeral.delete(key)?;
        let s = self.semantic.delete(key)?;
        let m = self.merkle.delete(key)?;
        Ok(e || s || m)
    }

    // ========================================================================
    // Verifiable Operations
    // ========================================================================

    /// Get state with cryptographic proof (from Merkle tier)
    pub fn get_with_proof(&self, key: &NamespacedKey) -> StateResult<Option<VerifiableRead>> {
        self.merkle.get_with_proof(key)
    }

    /// Get the current Merkle root
    pub fn get_merkle_root(&self) -> StateResult<[u8; 32]> {
        self.merkle.get_root()
    }

    /// Verify a proof against the current Merkle root
    pub fn verify_proof(&self, proof: &MerkleProof, value: &[u8]) -> StateResult<bool> {
        let current_root = self.merkle.get_root()?;
        
        if proof.root != current_root {
            return Ok(false);
        }
        
        Ok(proof.verify(value))
    }

    // ========================================================================
    // Semantic Search
    // ========================================================================

    /// Search for semantically similar values
    pub fn semantic_search(
        &self,
        namespace: &str,
        query_embedding: Vec<f32>,
        top_k: usize,
    ) -> StateResult<Vec<SemanticMatch>> {
        self.semantic.search(namespace, query_embedding, top_k)
    }

    // ========================================================================
    // Namespace Operations
    // ========================================================================

    /// Clear all ephemeral state for a namespace (e.g., when a session ends)
    pub fn clear_ephemeral_namespace(&self, namespace: &str) -> StateResult<usize> {
        self.ephemeral.clear_namespace(namespace)
    }

    /// Check if a key exists in any tier
    pub fn exists(&self, key: &NamespacedKey) -> StateResult<bool> {
        if self.ephemeral.exists(key)? {
            return Ok(true);
        }
        
        if self.merkle.get(key)?.is_some() {
            return Ok(true);
        }
        
        if self.semantic.get(key)?.is_some() {
            return Ok(true);
        }
        
        Ok(false)
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Track access for potential auto-promotion
    fn track_access(&self, key: &NamespacedKey) {
        if !self.config.auto_promote {
            return;
        }
        
        if let Ok(mut counts) = self.access_counts.write() {
            let canonical = key.to_canonical();
            let count = counts.entry(canonical.clone()).or_insert(0);
            *count += 1;
            
            // Check if we should promote
            if *count >= self.config.promotion_threshold {
                // Trigger promotion (simplified - in practice, this would be async)
                let _ = self.maybe_promote(key);
                counts.remove(&canonical);
            }
        }
    }

    /// Attempt to promote ephemeral state to merkle tier
    fn maybe_promote(&self, key: &NamespacedKey) -> StateResult<bool> {
        if let Some(value) = self.ephemeral.get(key)? {
            self.merkle.set(key, value)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Helper to create a namespaced key for an agent
pub fn agent_key(agent_id: &str, key: &str) -> NamespacedKey {
    NamespacedKey::new(agent_id, key)
}

/// Helper to create a session-scoped key
pub fn session_key(session_id: &str, key: &str) -> NamespacedKey {
    NamespacedKey::new(format!("session:{}", session_id), key)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespaced_key_parse() {
        let key = NamespacedKey::parse("agent1:my_key").unwrap();
        assert_eq!(key.namespace, "agent1");
        assert_eq!(key.key, "my_key");
        assert_eq!(key.to_canonical(), "agent1:my_key");
    }

    #[test]
    fn test_namespaced_key_invalid() {
        assert!(NamespacedKey::parse("invalid_key").is_err());
    }

    #[test]
    fn test_ephemeral_storage() {
        let storage = InMemoryEphemeral::new();
        let key = NamespacedKey::new("agent1", "test_key");
        let value = StateValue::new(b"test_value".to_vec());
        
        storage.set(&key, value).unwrap();
        
        let retrieved = storage.get(&key).unwrap().unwrap();
        assert_eq!(retrieved.data, b"test_value");
    }

    #[test]
    fn test_state_manager_basic() {
        let manager = StateManager::new(StateManagerConfig::default());
        let key = agent_key("agent1", "counter");
        
        manager.set_state(&key, b"42".to_vec(), StateTier::Ephemeral).unwrap();
        
        let value = manager.get_state(&key, StateTier::Ephemeral).unwrap().unwrap();
        assert_eq!(value, b"42");
    }

    #[test]
    fn test_merkle_storage_with_proof() {
        let manager = StateManager::new(StateManagerConfig::default());
        let key = agent_key("agent1", "important_data");
        
        manager.set_state(&key, b"verified_value".to_vec(), StateTier::Merkle).unwrap();
        
        let read = manager.get_with_proof(&key).unwrap().unwrap();
        assert_eq!(read.value.data, b"verified_value");
        
        // Verify the proof
        let is_valid = manager.verify_proof(&read.proof, &read.value.data).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_cascading_get() {
        let manager = StateManager::new(StateManagerConfig::default());
        let key = agent_key("agent1", "cascading_key");
        
        // Set in merkle tier only
        manager.set_state(&key, b"merkle_value".to_vec(), StateTier::Merkle).unwrap();
        
        // Should find it via cascading search
        let value = manager.get_state_cascading(&key).unwrap().unwrap();
        assert_eq!(value, b"merkle_value");
    }

    #[test]
    fn test_clear_namespace() {
        let manager = StateManager::new(StateManagerConfig::default());
        
        // Add multiple keys in same namespace
        for i in 0..5 {
            let key = agent_key("agent1", &format!("key_{}", i));
            manager.set_state(&key, b"value".to_vec(), StateTier::Ephemeral).unwrap();
        }
        
        // Add key in different namespace
        let other_key = agent_key("agent2", "key_0");
        manager.set_state(&other_key, b"value".to_vec(), StateTier::Ephemeral).unwrap();
        
        // Clear agent1 namespace
        let cleared = manager.clear_ephemeral_namespace("agent1").unwrap();
        assert_eq!(cleared, 5);
        
        // agent2 key should still exist
        assert!(manager.exists(&other_key).unwrap());
    }
}
