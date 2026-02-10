//! Episodic Memory with Merkle Chain (MEM-001)
//!
//! This module provides an append-only episodic memory system that records
//! agent actions, observations, and thoughts with cryptographic integrity
//! guarantees through a Merkle chain structure.
//!
//! # Features
//! - **Append-only episode chain**: Each episode is cryptographically linked to its predecessor
//! - **Tamper detection**: Chain integrity can be verified at any time
//! - **Time-ordered storage**: Episodes are stored with UUID v7 for natural time ordering
//! - **Content search**: Simple text-based search across episode contents
//! - **Export/Import**: Persistent storage with verification on restore
//!
//! # Example
//! ```
//! use vak::memory::episodic::EpisodicMemory;
//!
//! let mut memory = EpisodicMemory::new();
//! let episode_id = memory.record_episode(
//!     "search".to_string(),
//!     "Found 10 results".to_string(),
//!     Some("User asked about weather".to_string()),
//! );
//!
//! let recent = memory.get_recent(5);
//! assert_eq!(recent.len(), 1);
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Error that occurs when verifying the integrity of an episode chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainVerificationError {
    /// The hash of an episode doesn't match its content
    HashMismatch {
        /// Index of the episode with the mismatched hash
        index: usize,
        /// The expected hash (stored in the episode)
        expected: [u8; 32],
        /// The actual hash (computed from content)
        actual: [u8; 32],
    },
    /// The prev_hash of an episode doesn't match the hash of the previous episode
    ChainBroken {
        /// Index of the episode where the chain is broken
        index: usize,
        /// The expected prev_hash (hash of the previous episode)
        expected: Option<[u8; 32]>,
        /// The actual prev_hash stored in the episode
        actual: Option<[u8; 32]>,
    },
    /// The first episode has a non-None prev_hash
    InvalidGenesisEpisode,
}

impl fmt::Display for ChainVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainVerificationError::HashMismatch {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Hash mismatch at episode {}: expected {}, got {}",
                    index,
                    hex::encode(expected),
                    hex::encode(actual)
                )
            }
            ChainVerificationError::ChainBroken {
                index,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "Chain broken at episode {}: expected prev_hash {:?}, got {:?}",
                    index,
                    expected.map(hex::encode),
                    actual.map(hex::encode)
                )
            }
            ChainVerificationError::InvalidGenesisEpisode => {
                write!(f, "Genesis episode has non-None prev_hash")
            }
        }
    }
}

impl std::error::Error for ChainVerificationError {}

/// Error that occurs when importing an episode chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The imported chain failed verification
    VerificationFailed(ChainVerificationError),
    /// The imported data is empty when it shouldn't be
    EmptyChain,
    /// Episodes are not in chronological order
    OutOfOrder {
        /// Index of the episode that is out of order
        index: usize,
    },
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ImportError::VerificationFailed(e) => write!(f, "Import verification failed: {}", e),
            ImportError::EmptyChain => write!(f, "Cannot import empty chain"),
            ImportError::OutOfOrder { index } => {
                write!(
                    f,
                    "Episode at index {} is out of chronological order",
                    index
                )
            }
        }
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ImportError::VerificationFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ChainVerificationError> for ImportError {
    fn from(error: ChainVerificationError) -> Self {
        ImportError::VerificationFailed(error)
    }
}

// ============================================================================
// Episode ID
// ============================================================================

/// A unique identifier for an episode, wrapping a UUID v7.
///
/// UUID v7 is time-ordered, meaning IDs generated later will sort after
/// IDs generated earlier, which is useful for maintaining chronological order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EpisodeId(Uuid);

impl EpisodeId {
    /// Create a new episode ID using UUID v7 (time-ordered).
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Create an episode ID from an existing UUID.
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID.
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Convert to bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }
}

impl Default for EpisodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for EpisodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for EpisodeId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl From<EpisodeId> for Uuid {
    fn from(id: EpisodeId) -> Self {
        id.0
    }
}

// ============================================================================
// Episode
// ============================================================================

/// A single episode in the agent's memory, representing an action-observation pair.
///
/// Each episode contains:
/// - What the agent did (action)
/// - What the agent observed (observation)
/// - Optional reasoning (thought)
/// - Extensible metadata
/// - Cryptographic hash for integrity verification
/// - Link to previous episode hash (Merkle chain)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    /// Unique identifier for this episode (UUID v7, time-ordered)
    pub id: EpisodeId,

    /// Timestamp when this episode was recorded
    pub timestamp: DateTime<Utc>,

    /// Description of what the agent did
    pub action: String,

    /// Description of what the agent observed
    pub observation: String,

    /// Optional reasoning or thought process
    pub thought: Option<String>,

    /// Extensible metadata for additional context
    pub metadata: HashMap<String, serde_json::Value>,

    /// SHA-256 hash of the episode content
    pub hash: [u8; 32],

    /// Hash of the previous episode (None for genesis episode)
    pub prev_hash: Option<[u8; 32]>,
}

impl Episode {
    /// Create a new episode with the given content.
    ///
    /// The hash is computed from the content, and prev_hash should be set
    /// by the chain when appending.
    pub fn new(
        action: String,
        observation: String,
        thought: Option<String>,
        prev_hash: Option<[u8; 32]>,
    ) -> Self {
        let id = EpisodeId::new();
        let timestamp = Utc::now();
        let metadata = HashMap::new();

        let hash = Self::compute_hash(
            &id,
            &timestamp,
            &action,
            &observation,
            &thought,
            &metadata,
            &prev_hash,
        );

        Self {
            id,
            timestamp,
            action,
            observation,
            thought,
            metadata,
            hash,
            prev_hash,
        }
    }

    /// Create a new episode with metadata.
    pub fn with_metadata(
        action: String,
        observation: String,
        thought: Option<String>,
        metadata: HashMap<String, serde_json::Value>,
        prev_hash: Option<[u8; 32]>,
    ) -> Self {
        let id = EpisodeId::new();
        let timestamp = Utc::now();

        let hash = Self::compute_hash(
            &id,
            &timestamp,
            &action,
            &observation,
            &thought,
            &metadata,
            &prev_hash,
        );

        Self {
            id,
            timestamp,
            action,
            observation,
            thought,
            metadata,
            hash,
            prev_hash,
        }
    }

    /// Compute the SHA-256 hash of an episode's content.
    ///
    /// The hash includes all content fields to ensure integrity:
    /// - Episode ID
    /// - Timestamp
    /// - Action
    /// - Observation
    /// - Thought
    /// - Metadata
    /// - Previous hash (for chain linkage)
    pub fn compute_hash(
        id: &EpisodeId,
        timestamp: &DateTime<Utc>,
        action: &str,
        observation: &str,
        thought: &Option<String>,
        metadata: &HashMap<String, serde_json::Value>,
        prev_hash: &Option<[u8; 32]>,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // Hash all content fields in a deterministic order
        hasher.update(id.as_bytes());
        hasher.update(timestamp.timestamp_millis().to_le_bytes());
        hasher.update(action.as_bytes());
        hasher.update(observation.as_bytes());

        if let Some(ref t) = thought {
            hasher.update(b"\x01"); // Marker for Some
            hasher.update(t.as_bytes());
        } else {
            hasher.update(b"\x00"); // Marker for None
        }

        // Sort metadata keys for deterministic hashing
        let mut keys: Vec<_> = metadata.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            if let Some(value) = metadata.get(key) {
                hasher.update(value.to_string().as_bytes());
            }
        }

        // Include previous hash in the chain
        if let Some(ref ph) = prev_hash {
            hasher.update(b"\x01");
            hasher.update(ph);
        } else {
            hasher.update(b"\x00");
        }

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    }

    /// Verify that the stored hash matches the computed hash from content.
    pub fn verify_hash(&self) -> bool {
        let computed = Self::compute_hash(
            &self.id,
            &self.timestamp,
            &self.action,
            &self.observation,
            &self.thought,
            &self.metadata,
            &self.prev_hash,
        );
        self.hash == computed
    }

    /// Check if this episode's content contains the given query string.
    ///
    /// Searches in action, observation, and thought fields (case-insensitive).
    pub fn contains(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();
        self.action.to_lowercase().contains(&query_lower)
            || self.observation.to_lowercase().contains(&query_lower)
            || self
                .thought
                .as_ref()
                .map(|t| t.to_lowercase().contains(&query_lower))
                .unwrap_or(false)
    }
}

// ============================================================================
// Episode Chain
// ============================================================================

/// An append-only chain of episodes with Merkle chain integrity.
///
/// Each episode's hash includes the previous episode's hash, creating a
/// tamper-evident chain similar to a blockchain structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EpisodeChain {
    /// The episodes in chronological order
    episodes: Vec<Episode>,

    /// Index for fast lookup by hash
    #[serde(skip)]
    hash_index: HashMap<[u8; 32], usize>,

    /// Index for fast lookup by ID
    #[serde(skip)]
    id_index: HashMap<EpisodeId, usize>,
}

impl EpisodeChain {
    /// Create a new empty episode chain.
    pub fn new() -> Self {
        Self {
            episodes: Vec::new(),
            hash_index: HashMap::new(),
            id_index: HashMap::new(),
        }
    }

    /// Append an episode to the chain with proper hash linkage.
    ///
    /// This method ensures that the episode's prev_hash is set to the
    /// hash of the last episode in the chain (or None for the first episode).
    pub fn append(&mut self, mut episode: Episode) {
        // Set the prev_hash to link to the previous episode
        episode.prev_hash = self.episodes.last().map(|e| e.hash);

        // Recompute the hash with the correct prev_hash
        episode.hash = Episode::compute_hash(
            &episode.id,
            &episode.timestamp,
            &episode.action,
            &episode.observation,
            &episode.thought,
            &episode.metadata,
            &episode.prev_hash,
        );

        let index = self.episodes.len();
        self.hash_index.insert(episode.hash, index);
        self.id_index.insert(episode.id, index);
        self.episodes.push(episode);
    }

    /// Verify the integrity of the entire chain.
    ///
    /// This checks:
    /// 1. Each episode's hash matches its content
    /// 2. Each episode's prev_hash matches the previous episode's hash
    /// 3. The first episode has prev_hash = None
    pub fn verify_chain(&self) -> Result<(), ChainVerificationError> {
        for (i, episode) in self.episodes.iter().enumerate() {
            // Verify the hash of this episode
            let computed_hash = Episode::compute_hash(
                &episode.id,
                &episode.timestamp,
                &episode.action,
                &episode.observation,
                &episode.thought,
                &episode.metadata,
                &episode.prev_hash,
            );

            if episode.hash != computed_hash {
                return Err(ChainVerificationError::HashMismatch {
                    index: i,
                    expected: episode.hash,
                    actual: computed_hash,
                });
            }

            // Verify the chain linkage
            if i == 0 {
                // First episode should have no prev_hash
                if episode.prev_hash.is_some() {
                    return Err(ChainVerificationError::InvalidGenesisEpisode);
                }
            } else {
                // Subsequent episodes should link to the previous episode
                let expected_prev_hash = Some(self.episodes[i - 1].hash);
                if episode.prev_hash != expected_prev_hash {
                    return Err(ChainVerificationError::ChainBroken {
                        index: i,
                        expected: expected_prev_hash,
                        actual: episode.prev_hash,
                    });
                }
            }
        }

        Ok(())
    }

    /// Get an episode by its hash.
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&Episode> {
        self.hash_index.get(hash).map(|&i| &self.episodes[i])
    }

    /// Get an episode by its ID.
    pub fn get_by_id(&self, id: &EpisodeId) -> Option<&Episode> {
        self.id_index.get(id).map(|&i| &self.episodes[i])
    }

    /// Get the number of episodes in the chain.
    pub fn len(&self) -> usize {
        self.episodes.len()
    }

    /// Check if the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.episodes.is_empty()
    }

    /// Get the latest hash in the chain (the root hash).
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.episodes.last().map(|e| e.hash)
    }

    /// Get all episodes as a slice.
    pub fn episodes(&self) -> &[Episode] {
        &self.episodes
    }

    /// Rebuild the indexes after deserialization.
    pub fn rebuild_indexes(&mut self) {
        self.hash_index.clear();
        self.id_index.clear();

        for (i, episode) in self.episodes.iter().enumerate() {
            self.hash_index.insert(episode.hash, i);
            self.id_index.insert(episode.id, i);
        }
    }
}

// ============================================================================
// Episodic Memory
// ============================================================================

/// The main interface for episodic memory management.
///
/// EpisodicMemory provides a high-level API for recording and querying
/// agent episodes, backed by a Merkle chain for integrity verification.
#[derive(Debug, Clone, Default)]
pub struct EpisodicMemory {
    /// The underlying episode chain
    chain: EpisodeChain,
}

impl EpisodicMemory {
    /// Create a new empty episodic memory.
    pub fn new() -> Self {
        Self {
            chain: EpisodeChain::new(),
        }
    }

    /// Record a new episode in memory.
    ///
    /// Returns the ID of the newly created episode.
    pub fn record_episode(
        &mut self,
        action: String,
        observation: String,
        thought: Option<String>,
    ) -> EpisodeId {
        let episode = Episode::new(action, observation, thought, None);
        let id = episode.id;
        self.chain.append(episode);
        id
    }

    /// Record a new episode with metadata.
    ///
    /// Returns the ID of the newly created episode.
    pub fn record_episode_with_metadata(
        &mut self,
        action: String,
        observation: String,
        thought: Option<String>,
        metadata: HashMap<String, serde_json::Value>,
    ) -> EpisodeId {
        let episode = Episode::with_metadata(action, observation, thought, metadata, None);
        let id = episode.id;
        self.chain.append(episode);
        id
    }

    /// Get the most recent episodes.
    ///
    /// Returns up to `count` episodes, starting from the most recent.
    pub fn get_recent(&self, count: usize) -> Vec<&Episode> {
        let episodes = self.chain.episodes();
        let start = episodes.len().saturating_sub(count);
        episodes[start..].iter().collect()
    }

    /// Get episodes within a time range.
    ///
    /// Returns all episodes with timestamps in [start, end].
    pub fn get_by_time_range(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> Vec<&Episode> {
        self.chain
            .episodes()
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect()
    }

    /// Search episodes by content.
    ///
    /// Returns all episodes containing the query string in their action,
    /// observation, or thought fields (case-insensitive).
    pub fn search_by_content(&self, query: &str) -> Vec<&Episode> {
        self.chain
            .episodes()
            .iter()
            .filter(|e| e.contains(query))
            .collect()
    }

    /// Get the root hash of the chain (latest episode's hash).
    ///
    /// This can be used to verify that the memory hasn't been tampered with.
    pub fn get_chain_root_hash(&self) -> Option<[u8; 32]> {
        self.chain.root_hash()
    }

    /// Get an episode by its ID.
    pub fn get_by_id(&self, id: &EpisodeId) -> Option<&Episode> {
        self.chain.get_by_id(id)
    }

    /// Get an episode by its hash.
    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Option<&Episode> {
        self.chain.get_by_hash(hash)
    }

    /// Verify the integrity of the entire episode chain.
    pub fn verify_chain(&self) -> Result<(), ChainVerificationError> {
        self.chain.verify_chain()
    }

    /// Get the total number of episodes.
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Check if the memory is empty.
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Export the chain for persistence.
    ///
    /// Returns a clone of all episodes that can be serialized.
    pub fn export_chain(&self) -> Vec<Episode> {
        self.chain.episodes().to_vec()
    }

    /// Import a chain from persisted data with verification.
    ///
    /// This will verify the chain integrity before accepting it.
    pub fn import_chain(episodes: Vec<Episode>) -> Result<Self, ImportError> {
        if episodes.is_empty() {
            return Err(ImportError::EmptyChain);
        }

        // Check chronological order
        for i in 1..episodes.len() {
            if episodes[i].timestamp < episodes[i - 1].timestamp {
                return Err(ImportError::OutOfOrder { index: i });
            }
        }

        let mut chain = EpisodeChain {
            episodes,
            hash_index: HashMap::new(),
            id_index: HashMap::new(),
        };

        // Rebuild indexes
        chain.rebuild_indexes();

        // Verify the chain integrity
        chain.verify_chain()?;

        Ok(Self { chain })
    }

    /// Get access to the underlying chain.
    pub fn chain(&self) -> &EpisodeChain {
        &self.chain
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_episode_id_creation() {
        let id1 = EpisodeId::new();
        let id2 = EpisodeId::new();

        // IDs should be unique
        assert_ne!(id1, id2);

        // Display should work
        let display = format!("{}", id1);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_episode_id_from_uuid() {
        let uuid = Uuid::now_v7();
        let id = EpisodeId::from_uuid(uuid);
        assert_eq!(*id.as_uuid(), uuid);
    }

    #[test]
    fn test_episode_creation() {
        let episode = Episode::new(
            "search".to_string(),
            "found results".to_string(),
            Some("thinking about query".to_string()),
            None,
        );

        assert!(!episode.action.is_empty());
        assert!(!episode.observation.is_empty());
        assert!(episode.thought.is_some());
        assert!(episode.prev_hash.is_none());
        assert!(episode.verify_hash());
    }

    #[test]
    fn test_episode_with_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("tool".to_string(), serde_json::json!("calculator"));
        metadata.insert("confidence".to_string(), serde_json::json!(0.95));

        let episode = Episode::with_metadata(
            "calculate".to_string(),
            "result: 42".to_string(),
            None,
            metadata.clone(),
            None,
        );

        assert_eq!(episode.metadata.len(), 2);
        assert!(episode.verify_hash());
    }

    #[test]
    fn test_episode_hash_verification() {
        let episode = Episode::new("action".to_string(), "observation".to_string(), None, None);

        assert!(episode.verify_hash());

        // Tamper with the episode
        let mut tampered = episode.clone();
        tampered.action = "tampered".to_string();
        assert!(!tampered.verify_hash());
    }

    #[test]
    fn test_episode_contains() {
        let episode = Episode::new(
            "searched for weather".to_string(),
            "found sunny forecast".to_string(),
            Some("User wants weather info".to_string()),
            None,
        );

        assert!(episode.contains("weather"));
        assert!(episode.contains("WEATHER")); // Case insensitive
        assert!(episode.contains("sunny"));
        assert!(episode.contains("User"));
        assert!(!episode.contains("nonexistent"));
    }

    #[test]
    fn test_episode_chain_new() {
        let chain = EpisodeChain::new();
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        assert!(chain.root_hash().is_none());
    }

    #[test]
    fn test_episode_chain_append() {
        let mut chain = EpisodeChain::new();

        let episode1 = Episode::new("action1".to_string(), "obs1".to_string(), None, None);
        chain.append(episode1);

        assert_eq!(chain.len(), 1);
        assert!(!chain.is_empty());
        assert!(chain.root_hash().is_some());

        // First episode should have no prev_hash
        assert!(chain.episodes()[0].prev_hash.is_none());

        let episode2 = Episode::new("action2".to_string(), "obs2".to_string(), None, None);
        chain.append(episode2);

        assert_eq!(chain.len(), 2);

        // Second episode should link to first
        assert_eq!(
            chain.episodes()[1].prev_hash,
            Some(chain.episodes()[0].hash)
        );
    }

    #[test]
    fn test_episode_chain_verify() {
        let mut chain = EpisodeChain::new();

        for i in 0..5 {
            let episode = Episode::new(format!("action{}", i), format!("obs{}", i), None, None);
            chain.append(episode);
        }

        // Chain should verify successfully
        assert!(chain.verify_chain().is_ok());
    }

    #[test]
    fn test_episode_chain_verify_tampered_hash() {
        let mut chain = EpisodeChain::new();

        let episode = Episode::new("action".to_string(), "obs".to_string(), None, None);
        chain.append(episode);

        // Tamper with the hash
        chain.episodes[0].hash[0] ^= 0xFF;

        let result = chain.verify_chain();
        assert!(matches!(
            result,
            Err(ChainVerificationError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_episode_chain_verify_broken_link() {
        let mut chain = EpisodeChain::new();

        for i in 0..3 {
            let episode = Episode::new(format!("action{}", i), format!("obs{}", i), None, None);
            chain.append(episode);
        }

        // Break the chain by modifying prev_hash
        chain.episodes[2].prev_hash = Some([0u8; 32]);

        let result = chain.verify_chain();
        assert!(matches!(
            result,
            Err(ChainVerificationError::HashMismatch { .. })
        ));
    }

    #[test]
    fn test_episode_chain_get_by_hash() {
        let mut chain = EpisodeChain::new();

        let episode = Episode::new("action".to_string(), "obs".to_string(), None, None);
        chain.append(episode);

        let hash = chain.episodes()[0].hash;
        let found = chain.get_by_hash(&hash);
        assert!(found.is_some());
        assert_eq!(found.unwrap().action, "action");

        let not_found = chain.get_by_hash(&[0u8; 32]);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_episode_chain_get_by_id() {
        let mut chain = EpisodeChain::new();

        let episode = Episode::new("action".to_string(), "obs".to_string(), None, None);
        let id = episode.id;
        chain.append(episode);

        let found = chain.get_by_id(&id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().action, "action");

        let fake_id = EpisodeId::new();
        let not_found = chain.get_by_id(&fake_id);
        assert!(not_found.is_none());
    }

    #[test]
    fn test_episodic_memory_new() {
        let memory = EpisodicMemory::new();
        assert!(memory.is_empty());
        assert_eq!(memory.len(), 0);
    }

    #[test]
    fn test_episodic_memory_record_episode() {
        let mut memory = EpisodicMemory::new();

        let id = memory.record_episode(
            "search".to_string(),
            "results".to_string(),
            Some("thinking".to_string()),
        );

        assert_eq!(memory.len(), 1);
        assert!(!memory.is_empty());

        let episode = memory.get_by_id(&id);
        assert!(episode.is_some());
        assert_eq!(episode.unwrap().action, "search");
    }

    #[test]
    fn test_episodic_memory_record_with_metadata() {
        let mut memory = EpisodicMemory::new();

        let mut metadata = HashMap::new();
        metadata.insert("key".to_string(), serde_json::json!("value"));

        let id = memory.record_episode_with_metadata(
            "action".to_string(),
            "obs".to_string(),
            None,
            metadata,
        );

        let episode = memory.get_by_id(&id).unwrap();
        assert!(episode.metadata.contains_key("key"));
    }

    #[test]
    fn test_episodic_memory_get_recent() {
        let mut memory = EpisodicMemory::new();

        for i in 0..10 {
            memory.record_episode(format!("action{}", i), format!("obs{}", i), None);
        }

        let recent = memory.get_recent(3);
        assert_eq!(recent.len(), 3);
        assert_eq!(recent[0].action, "action7");
        assert_eq!(recent[1].action, "action8");
        assert_eq!(recent[2].action, "action9");

        // Request more than available
        let all = memory.get_recent(100);
        assert_eq!(all.len(), 10);
    }

    #[test]
    fn test_episodic_memory_get_by_time_range() {
        let mut memory = EpisodicMemory::new();

        let now = Utc::now();
        let start = now - Duration::hours(1);
        let end = now + Duration::hours(1);

        memory.record_episode("action1".to_string(), "obs1".to_string(), None);
        memory.record_episode("action2".to_string(), "obs2".to_string(), None);

        let episodes = memory.get_by_time_range(start, end);
        assert_eq!(episodes.len(), 2);

        // Empty range
        let future_start = now + Duration::hours(10);
        let future_end = now + Duration::hours(11);
        let empty = memory.get_by_time_range(future_start, future_end);
        assert!(empty.is_empty());
    }

    #[test]
    fn test_episodic_memory_search_by_content() {
        let mut memory = EpisodicMemory::new();

        memory.record_episode(
            "search weather".to_string(),
            "sunny forecast".to_string(),
            None,
        );
        memory.record_episode(
            "calculate sum".to_string(),
            "result is 42".to_string(),
            Some("math operation".to_string()),
        );
        memory.record_episode("check weather".to_string(), "rainy today".to_string(), None);

        let weather_results = memory.search_by_content("weather");
        assert_eq!(weather_results.len(), 2);

        let math_results = memory.search_by_content("math");
        assert_eq!(math_results.len(), 1);
        assert_eq!(math_results[0].action, "calculate sum");

        let no_results = memory.search_by_content("nonexistent");
        assert!(no_results.is_empty());
    }

    #[test]
    fn test_episodic_memory_get_chain_root_hash() {
        let mut memory = EpisodicMemory::new();

        assert!(memory.get_chain_root_hash().is_none());

        memory.record_episode("action".to_string(), "obs".to_string(), None);
        let hash1 = memory.get_chain_root_hash();
        assert!(hash1.is_some());

        memory.record_episode("action2".to_string(), "obs2".to_string(), None);
        let hash2 = memory.get_chain_root_hash();
        assert!(hash2.is_some());
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_episodic_memory_verify_chain() {
        let mut memory = EpisodicMemory::new();

        for i in 0..5 {
            memory.record_episode(format!("action{}", i), format!("obs{}", i), None);
        }

        assert!(memory.verify_chain().is_ok());
    }

    #[test]
    fn test_episodic_memory_export_import() {
        let mut memory = EpisodicMemory::new();

        for i in 0..5 {
            memory.record_episode(
                format!("action{}", i),
                format!("obs{}", i),
                Some(format!("thought{}", i)),
            );
        }

        let exported = memory.export_chain();
        assert_eq!(exported.len(), 5);

        let imported = EpisodicMemory::import_chain(exported).unwrap();
        assert_eq!(imported.len(), 5);
        assert!(imported.verify_chain().is_ok());
        assert_eq!(imported.get_chain_root_hash(), memory.get_chain_root_hash());
    }

    #[test]
    fn test_episodic_memory_import_empty() {
        let result = EpisodicMemory::import_chain(vec![]);
        assert!(matches!(result, Err(ImportError::EmptyChain)));
    }

    #[test]
    fn test_episodic_memory_import_tampered() {
        let mut memory = EpisodicMemory::new();

        for i in 0..3 {
            memory.record_episode(format!("action{}", i), format!("obs{}", i), None);
        }

        let mut exported = memory.export_chain();

        // Tamper with an episode
        exported[1].action = "tampered".to_string();

        let result = EpisodicMemory::import_chain(exported);
        assert!(matches!(result, Err(ImportError::VerificationFailed(_))));
    }

    #[test]
    fn test_chain_verification_error_display() {
        let error = ChainVerificationError::HashMismatch {
            index: 5,
            expected: [0u8; 32],
            actual: [1u8; 32],
        };
        let display = format!("{}", error);
        assert!(display.contains("Hash mismatch"));
        assert!(display.contains("5"));

        let error2 = ChainVerificationError::ChainBroken {
            index: 3,
            expected: Some([0u8; 32]),
            actual: None,
        };
        let display2 = format!("{}", error2);
        assert!(display2.contains("Chain broken"));

        let error3 = ChainVerificationError::InvalidGenesisEpisode;
        let display3 = format!("{}", error3);
        assert!(display3.contains("Genesis"));
    }

    #[test]
    fn test_import_error_display() {
        let error = ImportError::EmptyChain;
        let display = format!("{}", error);
        assert!(display.contains("empty"));

        let error2 = ImportError::OutOfOrder { index: 5 };
        let display2 = format!("{}", error2);
        assert!(display2.contains("out of chronological order"));
        assert!(display2.contains("5"));
    }

    #[test]
    fn test_episode_id_hash() {
        use std::collections::HashSet;

        let id1 = EpisodeId::new();
        let id2 = EpisodeId::new();

        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        set.insert(id1); // Duplicate

        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_episode_chain_rebuild_indexes() {
        let mut chain = EpisodeChain::new();

        for i in 0..3 {
            let episode = Episode::new(format!("action{}", i), format!("obs{}", i), None, None);
            chain.append(episode);
        }

        let id = chain.episodes()[1].id;
        let hash = chain.episodes()[1].hash;

        // Clear and rebuild indexes
        chain.hash_index.clear();
        chain.id_index.clear();
        chain.rebuild_indexes();

        // Verify indexes work
        assert!(chain.get_by_id(&id).is_some());
        assert!(chain.get_by_hash(&hash).is_some());
    }

    #[test]
    fn test_deterministic_hashing() {
        let id = EpisodeId::new();
        let timestamp = Utc::now();
        let action = "test action";
        let observation = "test observation";
        let thought = Some("test thought".to_string());
        let metadata = HashMap::new();
        let prev_hash = None;

        let hash1 = Episode::compute_hash(
            &id,
            &timestamp,
            action,
            observation,
            &thought,
            &metadata,
            &prev_hash,
        );
        let hash2 = Episode::compute_hash(
            &id,
            &timestamp,
            action,
            observation,
            &thought,
            &metadata,
            &prev_hash,
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_metadata_ordering_deterministic() {
        let id = EpisodeId::new();
        let timestamp = Utc::now();
        let action = "test";
        let observation = "test";
        let thought = None;
        let prev_hash = None;

        let mut metadata1 = HashMap::new();
        metadata1.insert("z".to_string(), serde_json::json!(1));
        metadata1.insert("a".to_string(), serde_json::json!(2));
        metadata1.insert("m".to_string(), serde_json::json!(3));

        let mut metadata2 = HashMap::new();
        metadata2.insert("a".to_string(), serde_json::json!(2));
        metadata2.insert("m".to_string(), serde_json::json!(3));
        metadata2.insert("z".to_string(), serde_json::json!(1));

        let hash1 = Episode::compute_hash(
            &id,
            &timestamp,
            action,
            observation,
            &thought,
            &metadata1,
            &prev_hash,
        );
        let hash2 = Episode::compute_hash(
            &id,
            &timestamp,
            action,
            observation,
            &thought,
            &metadata2,
            &prev_hash,
        );

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_episodic_memory_get_by_hash() {
        let mut memory = EpisodicMemory::new();

        memory.record_episode("action".to_string(), "obs".to_string(), None);

        let hash = memory.get_chain_root_hash().unwrap();
        let episode = memory.get_by_hash(&hash);
        assert!(episode.is_some());
        assert_eq!(episode.unwrap().action, "action");
    }

    #[test]
    fn test_chain_access() {
        let mut memory = EpisodicMemory::new();
        memory.record_episode("action".to_string(), "obs".to_string(), None);

        let chain = memory.chain();
        assert_eq!(chain.len(), 1);
    }
}
