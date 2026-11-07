//! Time Travel & Rollbacks (MEM-005)
//!
//! This module implements time travel and rollback functionality for the
//! Verifiable Agent Kernel memory system. It enables agents to:
//! - Create snapshots of their state at any point
//! - Roll back to previous snapshots when errors occur
//! - Verify state integrity through cryptographic proofs
//! - Track state changes over time for debugging and auditing
//!
//! # Architecture
//!
//! The time travel system uses a Merkle DAG structure where:
//! - Each snapshot has a unique hash based on its content
//! - Snapshots reference their parent snapshot(s)
//! - State can be verified against any historical snapshot
//! - Rollbacks are O(1) operations (just change the current head)
//!
//! # Integrity
//!
//! A checkpoint's hash (version 2, [`StateCheckpoint::expected_hash`]) is
//! SHA-256 over a domain tag and every field, each length-prefixed: ID,
//! label, creation time, the parent's ID *and hash*, the state and the
//! metadata. A chain therefore commits to its whole history: change any
//! ancestor and every descendant's parent hash stops matching. Given a
//! trusted head hash ([`TimeTravelManager::get_chain_root`]), nothing below
//! it can change unnoticed. Without one, the hashes catch corruption, not
//! someone who rewrites a chain and recomputes it: there is no key.
//!
//! Version 1 hashed the fields unseparated (a renamed key or shifted
//! metadata kept the hash), left out the creation time, and chained parent
//! IDs rather than hashes. Exports made before version 2 don't verify.
//!
//! # Example
//! ```rust
//! use vak::memory::time_travel::{TimeTravelManager, StateCheckpoint};
//!
//! let mut ttm = TimeTravelManager::new("agent1");
//!
//! // Set some state
//! ttm.set("key1", b"value1".to_vec());
//!
//! // Create checkpoint of current state
//! let checkpoint1 = ttm.create_checkpoint("Initial state");
//!
//! // Modify state
//! ttm.set("key1", b"value2".to_vec());
//! let checkpoint2 = ttm.create_checkpoint("After first change");
//!
//! // Rollback to previous state
//! ttm.rollback_to(checkpoint1).unwrap();
//! assert_eq!(ttm.get("key1"), Some(b"value1".as_slice()));
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

/// Domain tag of the version 2 checkpoint hash.
const CHECKPOINT_HASH_TAG: &[u8] = b"vak-checkpoint-v2";

/// Feeds `bytes` to `hasher` behind their length, so no two fields run
/// together.
fn put(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

// Helper Functions

/// Compute SHA-256 hash of data
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// Error Types

/// Errors that can occur during time travel operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeTravelError {
    /// Snapshot not found
    SnapshotNotFound(SnapshotId),
    /// Cannot rollback - no snapshots available
    NoSnapshotsAvailable,
    /// Snapshot verification failed
    VerificationFailed {
        /// ID of the snapshot that failed verification
        snapshot_id: SnapshotId,
        /// Reason for the verification failure
        reason: String,
    },
    /// Branch not found
    BranchNotFound(String),
    /// Cannot merge - conflicts detected
    MergeConflict {
        /// Key where the conflict occurred
        key: String,
        /// First snapshot involved in the conflict
        snapshot_a: SnapshotId,
        /// Second snapshot involved in the conflict
        snapshot_b: SnapshotId,
    },
    /// Maximum history depth exceeded
    MaxHistoryExceeded(usize),
    /// Serialization error
    SerializationError(String),
}

impl std::fmt::Display for TimeTravelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeTravelError::SnapshotNotFound(id) => {
                write!(f, "Snapshot not found: {}", id)
            }
            TimeTravelError::NoSnapshotsAvailable => {
                write!(f, "No snapshots available for rollback")
            }
            TimeTravelError::VerificationFailed {
                snapshot_id,
                reason,
            } => {
                write!(
                    f,
                    "Snapshot {} verification failed: {}",
                    snapshot_id, reason
                )
            }
            TimeTravelError::BranchNotFound(name) => {
                write!(f, "Branch not found: {}", name)
            }
            TimeTravelError::MergeConflict {
                key,
                snapshot_a,
                snapshot_b,
            } => {
                write!(
                    f,
                    "Merge conflict on key '{}' between snapshots {} and {}",
                    key, snapshot_a, snapshot_b
                )
            }
            TimeTravelError::MaxHistoryExceeded(max) => {
                write!(f, "Maximum history depth exceeded: {}", max)
            }
            TimeTravelError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
        }
    }
}

impl std::error::Error for TimeTravelError {}

/// Result type for time travel operations
pub type TimeTravelResult<T> = Result<T, TimeTravelError>;

// Snapshot Types

/// Unique identifier for a snapshot
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotId(Uuid);

impl SnapshotId {
    /// Create a new random snapshot ID
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Create from a UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SnapshotId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SnapshotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a key-value state entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StateEntry {
    /// The key
    pub key: String,
    /// The value (serialized bytes)
    pub value: Vec<u8>,
    /// Hash of the value for integrity checking
    pub value_hash: [u8; 32],
}

impl StateEntry {
    /// Create a new state entry
    pub fn new(key: impl Into<String>, value: Vec<u8>) -> Self {
        let value_hash = compute_sha256(&value);
        Self {
            key: key.into(),
            value,
            value_hash,
        }
    }

    /// Verify the entry's hash
    pub fn verify(&self) -> bool {
        compute_sha256(&self.value) == self.value_hash
    }

    /// Whether the entry is intact and is the one for `key`.
    fn verify_as(&self, key: &str) -> bool {
        self.key == key && self.verify()
    }
}

/// A checkpoint capturing the state at a specific point in time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateCheckpoint {
    /// Unique identifier for this checkpoint
    pub id: SnapshotId,
    /// Human-readable label/description
    pub label: String,
    /// Parent checkpoint ID (None for the genesis checkpoint)
    pub parent_id: Option<SnapshotId>,
    /// When the checkpoint was created
    pub created_at: DateTime<Utc>,
    /// The state entries at this checkpoint
    pub state: HashMap<String, StateEntry>,
    /// Hash of the entire checkpoint, including the parent's hash
    pub hash: [u8; 32],
    /// The parent's hash when this checkpoint was made. `None` for a
    /// genesis checkpoint, and for one made by [`StateCheckpoint::new`]
    /// with a parent ID, which a chain doesn't accept.
    #[serde(default)]
    pub parent_hash: Option<[u8; 32]>,
    /// Optional metadata
    pub metadata: HashMap<String, String>,
}

impl StateCheckpoint {
    /// Create a new checkpoint
    pub fn new(
        label: impl Into<String>,
        parent_id: Option<SnapshotId>,
        state: Vec<(String, Vec<u8>)>,
    ) -> Self {
        let label = label.into();
        let state_map: HashMap<String, StateEntry> = state
            .into_iter()
            .map(|(k, v)| {
                let entry = StateEntry::new(&k, v);
                (k, entry)
            })
            .collect();

        let mut checkpoint = Self {
            id: SnapshotId::new(),
            label,
            parent_id,
            created_at: Utc::now(),
            state: state_map,
            hash: [0u8; 32],
            parent_hash: None,
            metadata: HashMap::new(),
        };
        checkpoint.compute_hash();
        checkpoint
    }

    /// A checkpoint whose parent is `parent`, committing to its hash.
    pub fn child_of(
        label: impl Into<String>,
        parent: &StateCheckpoint,
        state: Vec<(String, Vec<u8>)>,
    ) -> Self {
        let mut checkpoint = Self::new(label, Some(parent.id), state);
        checkpoint.parent_hash = Some(parent.hash);
        checkpoint.compute_hash();
        checkpoint
    }

    /// Add metadata to the checkpoint
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self.compute_hash();
        self
    }

    /// The version 2 hash of this checkpoint's contents: SHA-256 over a
    /// domain tag and every field, length-prefixed (see the module docs).
    pub fn expected_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        put(&mut hasher, CHECKPOINT_HASH_TAG);
        put(&mut hasher, self.id.0.as_bytes());
        put(&mut hasher, self.label.as_bytes());
        hasher.update(self.created_at.timestamp().to_be_bytes());
        hasher.update(self.created_at.timestamp_subsec_nanos().to_be_bytes());
        put(
            &mut hasher,
            self.parent_id
                .as_ref()
                .map(|p| p.0.as_bytes().as_slice())
                .unwrap_or_default(),
        );
        put(
            &mut hasher,
            self.parent_hash
                .as_ref()
                .map(|h| h.as_slice())
                .unwrap_or_default(),
        );

        let mut keys: Vec<_> = self.state.keys().collect();
        keys.sort();
        hasher.update((keys.len() as u64).to_be_bytes());
        for key in keys {
            put(&mut hasher, key.as_bytes());
            hasher.update(self.state[key].value_hash);
        }

        let mut meta_keys: Vec<_> = self.metadata.keys().collect();
        meta_keys.sort();
        hasher.update((meta_keys.len() as u64).to_be_bytes());
        for key in meta_keys {
            put(&mut hasher, key.as_bytes());
            put(&mut hasher, self.metadata[key].as_bytes());
        }

        hasher.finalize().into()
    }

    /// Compute the hash for this checkpoint
    fn compute_hash(&mut self) {
        self.hash = self.expected_hash();
    }

    /// Whether the checkpoint is intact: every entry matches its value and
    /// its key, and the hash matches the contents.
    pub fn verify(&self) -> bool {
        self.state.iter().all(|(key, entry)| entry.verify_as(key))
            && self.expected_hash() == self.hash
    }

    /// Get a state value by key
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.state.get(key).map(|e| e.value.as_slice())
    }

    /// Get all keys in this checkpoint
    pub fn keys(&self) -> Vec<&str> {
        self.state.keys().map(|s| s.as_str()).collect()
    }

    /// Get the number of state entries
    pub fn len(&self) -> usize {
        self.state.len()
    }

    /// Check if the checkpoint is empty
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }
}

/// Represents a diff between two checkpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDiff {
    /// Source checkpoint ID
    pub from_id: SnapshotId,
    /// Target checkpoint ID
    pub to_id: SnapshotId,
    /// Keys that were added
    pub added: Vec<String>,
    /// Keys that were removed
    pub removed: Vec<String>,
    /// Keys that were modified
    pub modified: Vec<String>,
}

impl StateDiff {
    /// Compute the diff between two checkpoints
    pub fn compute(from: &StateCheckpoint, to: &StateCheckpoint) -> Self {
        let from_keys: std::collections::HashSet<_> = from.state.keys().collect();
        let to_keys: std::collections::HashSet<_> = to.state.keys().collect();

        let added: Vec<String> = to_keys.difference(&from_keys).map(|&k| k.clone()).collect();

        let removed: Vec<String> = from_keys.difference(&to_keys).map(|&k| k.clone()).collect();

        let modified: Vec<String> = from_keys
            .intersection(&to_keys)
            .filter(|&&k| {
                from.state.get(k).map(|e| &e.value_hash) != to.state.get(k).map(|e| &e.value_hash)
            })
            .map(|&k| k.clone())
            .collect();

        Self {
            from_id: from.id,
            to_id: to.id,
            added,
            removed,
            modified,
        }
    }

    /// Check if there are any changes
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty() || !self.modified.is_empty()
    }
}

// Configuration

/// Configuration for the time travel manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeTravelConfig {
    /// Maximum number of snapshots to keep (0 = unlimited)
    pub max_snapshots: usize,
    /// Whether to automatically prune old snapshots
    pub auto_prune: bool,
    /// Keep snapshots newer than this duration (in seconds)
    pub retention_seconds: Option<u64>,
    /// Whether to verify snapshots on access
    pub verify_on_access: bool,
}

impl Default for TimeTravelConfig {
    fn default() -> Self {
        Self {
            max_snapshots: 100,
            auto_prune: true,
            retention_seconds: None,
            verify_on_access: true,
        }
    }
}

impl TimeTravelConfig {
    /// Create a config with unlimited history
    pub fn unlimited() -> Self {
        Self {
            max_snapshots: 0,
            auto_prune: false,
            ..Default::default()
        }
    }

    /// Set maximum snapshots
    pub fn with_max_snapshots(mut self, max: usize) -> Self {
        self.max_snapshots = max;
        self
    }

    /// Set retention period
    pub fn with_retention(mut self, seconds: u64) -> Self {
        self.retention_seconds = Some(seconds);
        self
    }
}

// Time Travel Manager

/// Named branch pointer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Branch {
    /// Branch name
    pub name: String,
    /// Current head snapshot ID
    pub head: SnapshotId,
    /// When the branch was created
    pub created_at: DateTime<Utc>,
}

/// The main time travel manager
pub struct TimeTravelManager {
    /// Namespace for this manager (typically agent ID)
    namespace: String,
    /// Configuration
    config: TimeTravelConfig,
    /// All snapshots indexed by ID
    snapshots: HashMap<SnapshotId, StateCheckpoint>,
    /// Current head snapshot ID
    head: Option<SnapshotId>,
    /// Named branches
    branches: HashMap<String, Branch>,
    /// Current working state (uncommitted changes)
    working_state: HashMap<String, Vec<u8>>,
}

impl TimeTravelManager {
    /// Create a new time travel manager
    pub fn new(namespace: impl Into<String>) -> Self {
        Self::with_config(namespace, TimeTravelConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(namespace: impl Into<String>, config: TimeTravelConfig) -> Self {
        Self {
            namespace: namespace.into(),
            config,
            snapshots: HashMap::new(),
            head: None,
            branches: HashMap::new(),
            working_state: HashMap::new(),
        }
    }

    /// Get the namespace
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get the current head snapshot ID
    pub fn head(&self) -> Option<SnapshotId> {
        self.head
    }

    /// Get the number of snapshots
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    // Working State Operations

    /// Set a value in the working state
    pub fn set(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.working_state.insert(key.into(), value);
    }

    /// Get a value from the working state
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.working_state.get(key).map(|v| v.as_slice())
    }

    /// Remove a value from the working state
    pub fn remove(&mut self, key: &str) -> Option<Vec<u8>> {
        self.working_state.remove(key)
    }

    /// Clear the working state
    pub fn clear_working_state(&mut self) {
        self.working_state.clear();
    }

    /// Get all keys in the working state
    pub fn working_keys(&self) -> Vec<&str> {
        self.working_state.keys().map(|s| s.as_str()).collect()
    }

    // Checkpoint Operations

    /// Create a checkpoint from the current working state
    pub fn create_checkpoint(&mut self, label: impl Into<String>) -> SnapshotId {
        let state: Vec<_> = self
            .working_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let checkpoint = self.next_checkpoint(label, state);
        let id = checkpoint.id;

        self.snapshots.insert(id, checkpoint);
        self.head = Some(id);

        // Auto-prune if configured
        if self.config.auto_prune && self.config.max_snapshots > 0 {
            self.prune_old_snapshots();
        }

        id
    }

    /// A checkpoint of `state` whose parent is the head, if there is one.
    fn next_checkpoint(
        &self,
        label: impl Into<String>,
        state: Vec<(String, Vec<u8>)>,
    ) -> StateCheckpoint {
        match self.head.and_then(|id| self.snapshots.get(&id)) {
            Some(parent) => StateCheckpoint::child_of(label, parent, state),
            None => StateCheckpoint::new(label, None, state),
        }
    }

    /// Create a checkpoint with explicit state
    pub fn create_checkpoint_with_state(
        &mut self,
        label: impl Into<String>,
        state: Vec<(String, Vec<u8>)>,
    ) -> SnapshotId {
        let checkpoint = self.next_checkpoint(label, state);
        let id = checkpoint.id;

        self.snapshots.insert(id, checkpoint);
        self.head = Some(id);

        // Update working state
        self.working_state.clear();
        if let Some(cp) = self.snapshots.get(&id) {
            for (k, v) in &cp.state {
                self.working_state.insert(k.clone(), v.value.clone());
            }
        }

        if self.config.auto_prune && self.config.max_snapshots > 0 {
            self.prune_old_snapshots();
        }

        id
    }

    /// Get a snapshot by ID
    pub fn get_snapshot(&self, id: SnapshotId) -> Option<&StateCheckpoint> {
        let snapshot = self.snapshots.get(&id)?;

        if self.config.verify_on_access && !snapshot.verify() {
            return None;
        }

        Some(snapshot)
    }

    /// Get the current snapshot
    pub fn current_snapshot(&self) -> Option<&StateCheckpoint> {
        self.head.and_then(|id| self.get_snapshot(id))
    }

    /// Rollback to a specific snapshot
    pub fn rollback_to(&mut self, id: SnapshotId) -> TimeTravelResult<()> {
        let snapshot = self
            .snapshots
            .get(&id)
            .ok_or(TimeTravelError::SnapshotNotFound(id))?;

        if self.config.verify_on_access && !snapshot.verify() {
            return Err(TimeTravelError::VerificationFailed {
                snapshot_id: id,
                reason: "Snapshot hash verification failed".to_string(),
            });
        }

        // Update working state from snapshot
        self.working_state.clear();
        for (k, v) in &snapshot.state {
            self.working_state.insert(k.clone(), v.value.clone());
        }

        self.head = Some(id);
        Ok(())
    }

    /// Rollback to the previous snapshot
    pub fn rollback(&mut self) -> TimeTravelResult<()> {
        let current_id = self.head.ok_or(TimeTravelError::NoSnapshotsAvailable)?;

        let current = self
            .snapshots
            .get(&current_id)
            .ok_or(TimeTravelError::SnapshotNotFound(current_id))?;

        let parent_id = current
            .parent_id
            .ok_or(TimeTravelError::NoSnapshotsAvailable)?;

        self.rollback_to(parent_id)
    }

    /// The chain from `id` back towards genesis, newest first, ending at
    /// a missing parent or genesis; and whether it stopped at a cycle, a
    /// parent link back into the chain. Every walk up the parents used to
    /// follow links unguarded, so an imported cycle looped for ever.
    fn ancestry(&self, id: Option<SnapshotId>) -> (Vec<&StateCheckpoint>, bool) {
        let mut chain = Vec::new();
        let mut seen = HashSet::new();
        let mut current = id;
        while let Some(id) = current {
            if !seen.insert(id) {
                return (chain, true);
            }
            match self.snapshots.get(&id) {
                Some(snapshot) => {
                    chain.push(snapshot);
                    current = snapshot.parent_id;
                }
                None => break,
            }
        }
        (chain, false)
    }

    /// Get the history chain from the current head
    pub fn get_history(&self) -> Vec<&StateCheckpoint> {
        self.ancestry(self.head).0
    }

    /// Get the history chain as snapshot IDs
    pub fn get_history_ids(&self) -> Vec<SnapshotId> {
        self.get_history().iter().map(|s| s.id).collect()
    }

    /// Compute the diff between two snapshots
    pub fn diff(&self, from_id: SnapshotId, to_id: SnapshotId) -> TimeTravelResult<StateDiff> {
        let from = self
            .snapshots
            .get(&from_id)
            .ok_or(TimeTravelError::SnapshotNotFound(from_id))?;

        let to = self
            .snapshots
            .get(&to_id)
            .ok_or(TimeTravelError::SnapshotNotFound(to_id))?;

        Ok(StateDiff::compute(from, to))
    }

    /// Compute the diff between working state and a snapshot
    pub fn diff_from_working(&self, snapshot_id: SnapshotId) -> TimeTravelResult<StateDiff> {
        let snapshot = self
            .snapshots
            .get(&snapshot_id)
            .ok_or(TimeTravelError::SnapshotNotFound(snapshot_id))?;

        // Create a temporary checkpoint from working state for comparison
        let working_checkpoint = StateCheckpoint::new(
            "working",
            None,
            self.working_state
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        );

        Ok(StateDiff::compute(snapshot, &working_checkpoint))
    }

    // Branch Operations

    /// Create a new branch at the current head
    pub fn create_branch(&mut self, name: impl Into<String>) -> TimeTravelResult<()> {
        let name = name.into();
        let head = self.head.ok_or(TimeTravelError::NoSnapshotsAvailable)?;

        self.branches.insert(
            name.clone(),
            Branch {
                name,
                head,
                created_at: Utc::now(),
            },
        );

        Ok(())
    }

    /// Switch to a different branch
    pub fn switch_branch(&mut self, name: &str) -> TimeTravelResult<()> {
        let branch = self
            .branches
            .get(name)
            .ok_or_else(|| TimeTravelError::BranchNotFound(name.to_string()))?
            .clone();

        self.rollback_to(branch.head)
    }

    /// Get all branch names
    pub fn list_branches(&self) -> Vec<&str> {
        self.branches.keys().map(|s| s.as_str()).collect()
    }

    /// Delete a branch
    pub fn delete_branch(&mut self, name: &str) -> TimeTravelResult<Branch> {
        self.branches
            .remove(name)
            .ok_or_else(|| TimeTravelError::BranchNotFound(name.to_string()))
    }

    // Verification & Integrity

    /// Verify the entire chain from head to genesis
    pub fn verify_chain(&self) -> TimeTravelResult<bool> {
        self.verify_chain_from(self.head)
    }

    /// Verifies the chain from `head` to genesis: every snapshot intact,
    /// each committing to its parent's hash, ending at a genesis snapshot.
    /// A head that isn't stored fails; no head is an empty, valid chain.
    fn verify_chain_from(&self, head: Option<SnapshotId>) -> TimeTravelResult<bool> {
        let (history, cycle) = self.ancestry(head);
        if let (Some(head), true) = (head, history.is_empty()) {
            return Err(TimeTravelError::SnapshotNotFound(head));
        }
        if cycle {
            if let Some(last) = history.last() {
                return Err(TimeTravelError::VerificationFailed {
                    snapshot_id: last.id,
                    reason: "Parent links form a cycle".to_string(),
                });
            }
        }

        for (i, snapshot) in history.iter().enumerate() {
            if !snapshot.verify() {
                return Err(TimeTravelError::VerificationFailed {
                    snapshot_id: snapshot.id,
                    reason: format!("Snapshot at position {} failed verification", i),
                });
            }

            // The parent's hash, not just its ID: a parent ID alone let any
            // ancestor change without its descendants noticing.
            if let Some(parent) = history.get(i + 1) {
                if snapshot.parent_hash != Some(parent.hash) {
                    return Err(TimeTravelError::VerificationFailed {
                        snapshot_id: snapshot.id,
                        reason: "Parent hash mismatch".to_string(),
                    });
                }
            }
        }

        // Verify genesis has no parent
        if let Some(genesis) = history.last() {
            if genesis.parent_id.is_some() {
                return Err(TimeTravelError::VerificationFailed {
                    snapshot_id: genesis.id,
                    reason: "Genesis snapshot has a parent".to_string(),
                });
            }
        }

        Ok(true)
    }

    /// Get the root hash of the current chain
    pub fn get_chain_root(&self) -> Option<[u8; 32]> {
        self.head
            .and_then(|id| self.snapshots.get(&id))
            .map(|s| s.hash)
    }

    // Maintenance

    /// Remove old snapshots based on configuration
    fn prune_old_snapshots(&mut self) {
        if self.config.max_snapshots == 0 {
            return;
        }

        // Keep the chains of the head and of every branch. Only branch heads
        // used to be kept, so a branch lost its history and stopped
        // verifying.
        let mut kept: HashSet<SnapshotId> =
            self.ancestry(self.head).0.iter().map(|s| s.id).collect();
        for branch in self.branches.values() {
            kept.extend(self.ancestry(Some(branch.head)).0.iter().map(|s| s.id));
        }

        // Keep snapshots that are in chain, branches, or within max_snapshots
        if self.snapshots.len() <= self.config.max_snapshots {
            return;
        }

        // Collect snapshots to remove (not in current chain or branches)
        let mut all_snapshots: Vec<_> = self.snapshots.values().collect();
        all_snapshots.sort_by_key(|a| a.created_at);

        let excess = self.snapshots.len() - self.config.max_snapshots;
        let mut to_remove = vec![];

        for snapshot in all_snapshots.iter().take(excess) {
            if !kept.contains(&snapshot.id) {
                to_remove.push(snapshot.id);
            }
        }

        for id in to_remove {
            self.snapshots.remove(&id);
        }
    }

    /// Export the entire time travel state
    pub fn export(&self) -> TimeTravelResult<TimeTravelExport> {
        let snapshots: Vec<_> = self.snapshots.values().cloned().collect();
        let branches: Vec<_> = self.branches.values().cloned().collect();

        Ok(TimeTravelExport {
            namespace: self.namespace.clone(),
            head: self.head,
            snapshots,
            branches,
            working_state: self.working_state.clone(),
        })
    }

    /// Imports exported state, verifying all of it: every snapshot, the
    /// head's chain and every branch's. It used to verify the head's chain
    /// only, so other snapshots and branches came in unchecked, and a head
    /// naming a missing snapshot passed as an empty chain.
    pub fn import(data: TimeTravelExport) -> TimeTravelResult<Self> {
        let mut manager = Self::new(data.namespace);

        for snapshot in data.snapshots {
            manager.snapshots.insert(snapshot.id, snapshot);
        }

        for branch in data.branches {
            manager.branches.insert(branch.name.clone(), branch);
        }

        manager.head = data.head;
        manager.working_state = data.working_state;

        if let Some(bad) = manager.snapshots.values().find(|s| !s.verify()) {
            return Err(TimeTravelError::VerificationFailed {
                snapshot_id: bad.id,
                reason: "Imported snapshot failed verification".to_string(),
            });
        }
        manager.verify_chain()?;
        for branch in manager.branches.values() {
            manager.verify_chain_from(Some(branch.head))?;
        }

        Ok(manager)
    }
}

impl std::fmt::Debug for TimeTravelManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TimeTravelManager")
            .field("namespace", &self.namespace)
            .field("snapshot_count", &self.snapshots.len())
            .field("head", &self.head)
            .field("branches", &self.branches.len())
            .field("working_state_keys", &self.working_state.len())
            .finish()
    }
}

/// Serializable export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeTravelExport {
    /// Namespace
    pub namespace: String,
    /// Current head
    pub head: Option<SnapshotId>,
    /// All snapshots
    pub snapshots: Vec<StateCheckpoint>,
    /// All branches
    pub branches: Vec<Branch>,
    /// Working state
    pub working_state: HashMap<String, Vec<u8>>,
}

// Full Checkout Capability (MEM-005 Enhancement)

/// A complete memory state checkout that can be used to recreate exact state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullCheckout {
    /// The snapshot ID this checkout is from
    pub snapshot_id: SnapshotId,
    /// The Merkle root hash
    pub merkle_root: String,
    /// Complete state data
    pub state_data: HashMap<String, Vec<u8>>,
    /// Metadata about the checkout
    pub metadata: CheckoutMetadata,
    /// Chain of hashes proving provenance
    pub provenance_chain: Vec<ProvenanceLink>,
}

/// Metadata about a checkout
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutMetadata {
    /// When the checkout was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Original snapshot timestamp
    pub snapshot_timestamp: chrono::DateTime<chrono::Utc>,
    /// Branch name if applicable
    pub branch: Option<String>,
    /// Description of state at this point
    pub description: Option<String>,
    /// Agent ID that created this state
    pub agent_id: Option<String>,
    /// Session ID for context
    pub session_id: Option<String>,
}

/// A link in the provenance chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceLink {
    /// Hash of this state
    pub state_hash: String,
    /// Hash of the previous state
    pub previous_hash: Option<String>,
    /// Action that led to this state
    pub action: String,
    /// Timestamp of the action
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Replay step for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStep {
    /// Step number
    pub step: u64,
    /// State hash at this step
    pub state_hash: String,
    /// Action taken
    pub action: ReplayAction,
    /// State changes
    pub changes: Vec<StateChange>,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Action taken during replay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplayAction {
    /// Memory write
    Write {
        /// Key being written to
        key: String,
        /// Size of the written value in bytes
        size: usize,
    },
    /// Memory read
    Read {
        /// Key being read
        key: String,
    },
    /// Memory delete
    Delete {
        /// Key being deleted
        key: String,
    },
    /// Tool execution
    ToolExec {
        /// Name of the tool being executed
        tool: String,
        /// Parameters passed to the tool
        params: serde_json::Value,
    },
    /// Policy evaluation
    PolicyEval {
        /// Action being evaluated
        action: String,
        /// Resource being accessed
        resource: String,
        /// Policy decision result
        decision: String,
    },
    /// LLM inference
    Inference {
        /// Model identifier used for inference
        model: String,
        /// Number of tokens consumed
        tokens: u64,
    },
    /// Custom action
    Custom {
        /// Type of the custom action
        action_type: String,
        /// Additional details about the action
        details: serde_json::Value,
    },
}

/// A change to state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// Key that changed
    pub key: String,
    /// Previous value hash (None if new)
    pub previous_hash: Option<String>,
    /// New value hash (None if deleted)
    pub new_hash: Option<String>,
}

// Checkout Types (MEM-005 Enhanced)

/// Options for checkout operations
#[derive(Debug, Clone, Default)]
pub struct CheckoutOptions {
    /// Whether to verify the snapshot before checkout
    pub verify_before_checkout: bool,
    /// Branch name to create from the checkout (optional)
    pub create_branch: Option<String>,
    /// Whether to preserve the current working state
    pub preserve_working_state: bool,
}

impl CheckoutOptions {
    /// Create new checkout options
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable verification before checkout
    pub fn with_verification(mut self) -> Self {
        self.verify_before_checkout = true;
        self
    }

    /// Create a branch from the checkout
    pub fn with_branch(mut self, name: impl Into<String>) -> Self {
        self.create_branch = Some(name.into());
        self
    }

    /// Preserve current working state
    pub fn preserve_state(mut self) -> Self {
        self.preserve_working_state = true;
        self
    }
}

/// Result of a checkout operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResult {
    /// The snapshot ID that was checked out
    pub snapshot_id: SnapshotId,
    /// The Merkle root hash
    pub merkle_root: [u8; 32],
    /// Number of entries restored
    pub entries_restored: usize,
    /// Summary of the restored state
    pub state_summary: CheckoutStateSummary,
}

/// Summary of checkout state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutStateSummary {
    /// Number of keys in the state
    pub key_count: usize,
    /// Total bytes of state data
    pub total_bytes: usize,
    /// List of keys in the state
    pub keys: Vec<String>,
    /// Hash of the state
    pub state_hash: String,
}

impl TimeTravelManager {
    // Checkout Operations (MEM-005 Enhanced)

    /// Checkout a snapshot by its Merkle root hash (MEM-005)
    ///
    /// This enables restoring exact memory state from a cryptographic hash,
    /// allowing for "time travel debugging" where you can reproduce the
    /// exact state of an agent at any point in history.
    ///
    /// # Arguments
    /// * `merkle_root` - The 32-byte hash of the snapshot to checkout
    /// * `options` - Optional checkout configuration
    ///
    /// # Returns
    /// * `Ok(CheckoutResult)` - The result of the checkout operation
    /// * `Err(TimeTravelError)` - If the snapshot wasn't found or verification failed
    ///
    /// # Example
    /// ```rust
    /// use vak::memory::time_travel::{TimeTravelManager, CheckoutOptions};
    ///
    /// let mut manager = TimeTravelManager::new("agent-1");
    /// manager.set("config", b"version=1".to_vec());
    /// let id = manager.create_checkpoint("Initial config");
    ///
    /// // Get the Merkle root
    /// let root = manager.get_chain_root().unwrap();
    ///
    /// // Later, checkout using the root hash
    /// let result = manager.checkout_by_hash(&root, None).unwrap();
    /// assert_eq!(result.merkle_root, root);
    /// ```
    pub fn checkout_by_hash(
        &mut self,
        merkle_root: &[u8; 32],
        options: Option<CheckoutOptions>,
    ) -> TimeTravelResult<CheckoutResult> {
        let options = options.unwrap_or_default();

        // Find the snapshot with this hash
        let snapshot_id = self
            .snapshots
            .iter()
            .find(|(_, s)| &s.hash == merkle_root)
            .map(|(id, _)| *id)
            .ok_or_else(|| TimeTravelError::SnapshotNotFound(SnapshotId::new()))?;

        self.checkout_by_id(snapshot_id, Some(options))
    }

    /// Checkout a snapshot by ID with full state restoration (MEM-005)
    pub fn checkout_by_id(
        &mut self,
        snapshot_id: SnapshotId,
        options: Option<CheckoutOptions>,
    ) -> TimeTravelResult<CheckoutResult> {
        let options = options.unwrap_or_default();

        // Get the snapshot
        let snapshot = self
            .snapshots
            .get(&snapshot_id)
            .ok_or(TimeTravelError::SnapshotNotFound(snapshot_id))?
            .clone();

        // Verify if requested, or if the manager verifies on every access:
        // checkout used to skip that, restoring a snapshot rollback_to
        // refuses.
        if (options.verify_before_checkout || self.config.verify_on_access) && !snapshot.verify() {
            return Err(TimeTravelError::VerificationFailed {
                snapshot_id,
                reason: "Snapshot integrity verification failed".to_string(),
            });
        }

        // Create branch if requested
        if let Some(branch_name) = &options.create_branch {
            self.branches.insert(
                branch_name.clone(),
                Branch {
                    name: branch_name.clone(),
                    head: snapshot_id,
                    created_at: Utc::now(),
                },
            );
        }

        // Calculate state summary before checkout
        let keys: Vec<String> = snapshot.state.keys().cloned().collect();
        let total_bytes: usize = snapshot.state.values().map(|v| v.value.len()).sum();
        let state_hash = hex::encode(snapshot.hash);

        // Restore working state
        if !options.preserve_working_state {
            self.working_state.clear();
        }

        for (key, entry) in &snapshot.state {
            self.working_state.insert(key.clone(), entry.value.clone());
        }

        // Update head
        self.head = Some(snapshot_id);

        Ok(CheckoutResult {
            snapshot_id,
            merkle_root: snapshot.hash,
            entries_restored: snapshot.state.len(),
            state_summary: CheckoutStateSummary {
                key_count: keys.len(),
                total_bytes,
                keys,
                state_hash,
            },
        })
    }

    /// Create a full checkout from a snapshot ID
    ///
    /// This captures the complete state that can be used to recreate
    /// an exact memory state in a new VAK instance.
    pub fn full_checkout(&self, snapshot_id: &SnapshotId) -> Option<FullCheckout> {
        // Find the snapshot
        let snapshot = self.snapshots.get(snapshot_id)?;

        // Build provenance chain by walking up the parent chain
        let mut provenance_chain = Vec::new();
        let mut current_id = Some(*snapshot_id);
        let mut chain_snapshots = Vec::new();

        // Collect all snapshots in the chain
        chain_snapshots.extend(self.ancestry(current_id.take()).0.into_iter().cloned());

        // Reverse to get genesis-first order
        chain_snapshots.reverse();

        // Build provenance chain
        for (i, s) in chain_snapshots.iter().enumerate() {
            provenance_chain.push(ProvenanceLink {
                state_hash: hex::encode(s.hash),
                previous_hash: if i > 0 {
                    Some(hex::encode(chain_snapshots[i - 1].hash))
                } else {
                    None
                },
                action: s
                    .metadata
                    .get("action")
                    .cloned()
                    .unwrap_or_else(|| "checkpoint".to_string()),
                timestamp: s.created_at,
            });
        }

        // Get the state data from the snapshot
        let state_data: HashMap<String, Vec<u8>> = snapshot
            .state
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect();

        Some(FullCheckout {
            snapshot_id: *snapshot_id,
            merkle_root: hex::encode(snapshot.hash),
            state_data,
            metadata: CheckoutMetadata {
                created_at: chrono::Utc::now(),
                snapshot_timestamp: snapshot.created_at,
                branch: self.get_current_branch_name(),
                description: snapshot.metadata.get("description").cloned(),
                agent_id: snapshot.metadata.get("agent_id").cloned(),
                session_id: snapshot.metadata.get("session_id").cloned(),
            },
            provenance_chain,
        })
    }

    /// Get the name of the current branch, if any
    fn get_current_branch_name(&self) -> Option<String> {
        self.head.and_then(|head_id| {
            self.branches
                .iter()
                .find(|(_, branch)| branch.head == head_id)
                .map(|(name, _)| name.clone())
        })
    }

    /// Restores the state in a checkout as a new checkpoint.
    ///
    /// This checks the checkout is consistent: its provenance links chain,
    /// genesis first, to its `merkle_root`. It can't check that
    /// `state_data` is the state that root committed to, because a checkout
    /// doesn't carry the rest of the snapshot (its label, parent and
    /// metadata), and a consistent checkout can be made up whole. So the
    /// restored state is only as trustworthy as the checkout's source; the
    /// new checkpoint records `restored_from` and `restored_unverified`
    /// in its metadata. (It used to say it verified the checkout, having
    /// compared two strings the checkout itself supplied.)
    pub fn restore_from_checkout(
        &mut self,
        checkout: &FullCheckout,
    ) -> Result<(), TimeTravelError> {
        let inconsistent = |reason: &str| TimeTravelError::VerificationFailed {
            snapshot_id: checkout.snapshot_id,
            reason: reason.to_string(),
        };
        for (i, link) in checkout.provenance_chain.iter().enumerate() {
            let expected = i
                .checked_sub(1)
                .map(|previous| checkout.provenance_chain[previous].state_hash.clone());
            if link.previous_hash != expected {
                return Err(inconsistent("Provenance links don't chain"));
            }
        }
        if checkout.provenance_chain.is_empty() {
            return Err(TimeTravelError::VerificationFailed {
                snapshot_id: checkout.snapshot_id,
                reason: "Empty provenance chain".to_string(),
            });
        }

        // Verify the last link in provenance chain matches the merkle root
        if let Some(last_link) = checkout.provenance_chain.last() {
            if last_link.state_hash != checkout.merkle_root {
                return Err(TimeTravelError::VerificationFailed {
                    snapshot_id: checkout.snapshot_id,
                    reason: "Provenance chain doesn't match merkle root".to_string(),
                });
            }
        }

        // Restore the state
        self.working_state = checkout.state_data.clone();

        // Create a new checkpoint for the restoration, saying what it is.
        let label = format!("Restored from {}", checkout.snapshot_id);
        let state = self
            .working_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let checkpoint = self
            .next_checkpoint(label, state)
            .with_metadata("restored_from", checkout.snapshot_id.to_string())
            .with_metadata(
                "restored_unverified",
                "state_data is not proven by the checkout",
            );
        let id = checkpoint.id;
        self.snapshots.insert(id, checkpoint);
        self.head = Some(id);
        if self.config.auto_prune && self.config.max_snapshots > 0 {
            self.prune_old_snapshots();
        }

        Ok(())
    }

    /// Generate replay steps between two snapshots
    ///
    /// Returns None if either snapshot is not found or if there's no valid path between them.
    pub fn generate_replay(&self, from: &SnapshotId, to: &SnapshotId) -> Option<Vec<ReplayStep>> {
        // Get both snapshots to verify they exist
        let _from_snapshot = self.snapshots.get(from)?;
        let _to_snapshot = self.snapshots.get(to)?;

        // Build the path from 'to' back to 'from' by following parent links
        let (ancestry, _) = self.ancestry(Some(*to));
        let mut path: Vec<StateCheckpoint> = Vec::new();
        for snapshot in ancestry {
            path.push(snapshot.clone());
            if snapshot.id == *from {
                break;
            }
        }

        // Verify we found the from snapshot
        if path.last().map(|s| s.id != *from).unwrap_or(true) {
            return None; // No path between snapshots
        }

        // Reverse to get from-first order
        path.reverse();

        // Generate replay steps
        let mut steps = Vec::new();

        for (i, snapshot) in path.iter().skip(1).enumerate() {
            let prev = &path[i];

            // Compute state changes
            let changes: Vec<StateChange> = {
                let mut changes = Vec::new();

                // Find added/modified keys
                for (key, entry) in &snapshot.state {
                    let new_hash = Some(hex::encode(entry.value_hash));
                    let previous_hash = prev.state.get(key).map(|e| hex::encode(e.value_hash));

                    if previous_hash != new_hash {
                        changes.push(StateChange {
                            key: key.clone(),
                            previous_hash,
                            new_hash,
                        });
                    }
                }

                // Find deleted keys
                for key in prev.state.keys() {
                    if !snapshot.state.contains_key(key) {
                        changes.push(StateChange {
                            key: key.clone(),
                            previous_hash: prev.state.get(key).map(|e| hex::encode(e.value_hash)),
                            new_hash: None,
                        });
                    }
                }

                changes
            };

            let action_type = snapshot
                .metadata
                .get("action")
                .cloned()
                .unwrap_or_else(|| "checkpoint".to_string());

            let replay_action = match action_type.as_str() {
                "write" => {
                    let key = snapshot
                        .metadata
                        .get("key")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    let size = snapshot.state.get(&key).map(|e| e.value.len()).unwrap_or(0);
                    ReplayAction::Write { key, size }
                }
                "delete" => {
                    let key = snapshot
                        .metadata
                        .get("key")
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    ReplayAction::Delete { key }
                }
                _ => ReplayAction::Custom {
                    action_type,
                    details: serde_json::json!(snapshot.metadata),
                },
            };

            steps.push(ReplayStep {
                step: (i + 1) as u64,
                state_hash: hex::encode(snapshot.hash),
                action: replay_action,
                changes,
                timestamp: snapshot.created_at,
            });
        }

        Some(steps)
    }

    /// Step forward one decision at a time (for debugging)
    pub fn step_forward(&mut self) -> Option<ReplayStep> {
        // Get current head
        let current_head = self.head?;
        let _current_snapshot = self.snapshots.get(&current_head)?;

        // Find any snapshot that has the current as its parent
        // (This is a simplified implementation - in production you'd want an index)
        let next_snapshot = self
            .snapshots
            .values()
            .find(|s| s.parent_id == Some(current_head))?
            .clone();

        // Apply the next state
        self.working_state.clear();
        for (key, entry) in &next_snapshot.state {
            self.working_state.insert(key.clone(), entry.value.clone());
        }
        self.head = Some(next_snapshot.id);

        let action_type = next_snapshot
            .metadata
            .get("action")
            .cloned()
            .unwrap_or_else(|| "checkpoint".to_string());

        Some(ReplayStep {
            step: 1,
            state_hash: hex::encode(next_snapshot.hash),
            action: ReplayAction::Custom {
                action_type,
                details: serde_json::json!(next_snapshot.metadata),
            },
            changes: vec![],
            timestamp: next_snapshot.created_at,
        })
    }
}

// Additional Tests

#[cfg(test)]
mod checkout_tests {
    use super::*;

    #[test]
    fn test_full_checkout() {
        let mut manager = TimeTravelManager::new("test-namespace");

        manager.set("key1", b"value1".to_vec());
        let snapshot_id = manager.create_checkpoint("Initial state");

        let checkout = manager.full_checkout(&snapshot_id).unwrap();

        assert_eq!(checkout.snapshot_id, snapshot_id);
        assert!(!checkout.provenance_chain.is_empty());
    }

    #[test]
    fn test_restore_from_checkout() {
        let mut manager = TimeTravelManager::new("test-namespace");

        manager.set("key1", b"value1".to_vec());
        let snapshot_id = manager.create_checkpoint("Initial state");

        let checkout = manager.full_checkout(&snapshot_id).unwrap();

        // Create a new manager and restore
        let mut new_manager = TimeTravelManager::new("test-namespace-2");
        new_manager.restore_from_checkout(&checkout).unwrap();

        assert_eq!(new_manager.get("key1"), Some(b"value1".as_slice()));
    }

    #[test]
    fn test_generate_replay() {
        let mut manager = TimeTravelManager::new("test-namespace");

        // Create some state changes
        let first_id = manager.create_checkpoint("Initial");

        manager.set("key1", b"value1".to_vec());
        let _mid_id = manager.create_checkpoint("After first change");

        manager.set("key2", b"value2".to_vec());
        let last_id = manager.create_checkpoint("After second change");

        let replay = manager.generate_replay(&first_id, &last_id);
        assert!(replay.is_some());

        let steps = replay.unwrap();
        assert_eq!(steps.len(), 2);
    }

    /// A manager with three checkpoints, a <- b <- c, the head at c.
    fn three() -> (TimeTravelManager, [SnapshotId; 3]) {
        let mut ttm = TimeTravelManager::with_config("agent", TimeTravelConfig::unlimited());
        ttm.set("k", b"1".to_vec());
        let a = ttm.create_checkpoint("a");
        ttm.set("k", b"2".to_vec());
        let b = ttm.create_checkpoint("b");
        ttm.set("other", b"x".to_vec());
        let c = ttm.create_checkpoint("c");
        (ttm, [a, b, c])
    }

    fn rehash(
        ttm: &mut TimeTravelManager,
        id: SnapshotId,
        edit: impl FnOnce(&mut StateCheckpoint),
    ) {
        let snapshot = ttm.snapshots.get_mut(&id).unwrap();
        edit(snapshot);
        snapshot.compute_hash();
    }

    #[test]
    fn test_a_renamed_key_or_shifted_metadata_changes_the_hash() {
        // Fields were hashed unseparated: label "ab" with key "c" hashed as
        // label "a" with key "bc", and metadata {a: bc} as {ab: c}.
        let original = StateCheckpoint::new("ab", None, vec![("c".into(), b"v".to_vec())])
            .with_metadata("a", "bc");
        let mut renamed = original.clone();
        renamed.label = "a".into();
        let entry = renamed.state.remove("c").unwrap();
        renamed.state.insert(
            "bc".into(),
            StateEntry {
                key: "bc".into(),
                ..entry
            },
        );
        assert!(!renamed.verify(), "a renamed key is detected");

        let mut shifted = original.clone();
        shifted.metadata = HashMap::from([("ab".to_string(), "c".to_string())]);
        assert!(!shifted.verify(), "shifted metadata is detected");

        let mut retimed = original.clone();
        retimed.created_at += chrono::Duration::seconds(1);
        assert!(!retimed.verify(), "the creation time is hashed");

        let mut mislabelled = original.clone();
        let entry = mislabelled.state.get_mut("c").unwrap();
        entry.key = "elsewhere".into();
        assert!(!mislabelled.verify(), "an entry must be its key's");
        assert!(original.verify());
        assert_ne!(original.hash, StateCheckpoint::new("ab", None, vec![]).hash);
    }

    #[test]
    fn test_a_rewritten_ancestor_breaks_the_chain() {
        // Checkpoints chained parent IDs, so an ancestor rewritten and
        // rehashed went unnoticed below an unchanged head.
        let (mut ttm, [a, b, c]) = three();
        let root = ttm.get_chain_root().unwrap();
        assert!(ttm.verify_chain().unwrap());
        assert_eq!(ttm.snapshots[&b].parent_hash, Some(ttm.snapshots[&a].hash));

        rehash(&mut ttm, a, |s| {
            s.state
                .insert("k".into(), StateEntry::new("k", b"forged".to_vec()));
        });
        assert!(
            ttm.snapshots[&a].verify(),
            "a rehashed snapshot is self-consistent"
        );
        let err = ttm.verify_chain().unwrap_err();
        assert!(
            matches!(&err, TimeTravelError::VerificationFailed { snapshot_id, reason }
                if *snapshot_id == b && reason.contains("Parent hash")),
            "{err:?}"
        );
        assert_eq!(ttm.get_chain_root(), Some(root), "the head didn't change");

        // Nor can the child be repointed at the rewritten parent: its parent
        // hash is part of its own hash.
        let rewritten = ttm.snapshots[&a].hash;
        ttm.snapshots.get_mut(&b).unwrap().parent_hash = Some(rewritten);
        assert!(!ttm.snapshots[&b].verify());
        assert!(ttm.verify_chain().is_err());

        // A checkpoint made with a parent ID but no parent hash is refused.
        let (mut ttm, [_, b, c2]) = three();
        let orphan = StateCheckpoint::new("loose", Some(b), vec![]);
        ttm.snapshots.insert(orphan.id, orphan.clone());
        ttm.head = Some(orphan.id);
        assert!(ttm.verify_chain().is_err());
        ttm.head = Some(c2);
        assert!(ttm.verify_chain().unwrap());
        let _ = c;
    }

    #[test]
    fn test_import_verifies_everything_and_ends_cycles() {
        let (mut ttm, [a, b, c]) = three();
        ttm.rollback_to(b).unwrap();
        ttm.create_branch("side").unwrap();
        ttm.rollback_to(c).unwrap();
        let good = ttm.export().unwrap();
        let back = TimeTravelManager::import(good.clone()).unwrap();
        assert_eq!(back.head(), Some(c));
        assert_eq!(back.snapshot_count(), 3);
        assert!(format!("{back:?}").contains("snapshot_count: 3"));

        // Only the head's chain was checked: a tampered snapshot off it, a
        // head naming nothing, and a branch naming nothing came in.
        let mut stray = good.clone();
        let mut loose = StateCheckpoint::new("off-chain", None, vec![]);
        loose.label = "tampered".into();
        stray.snapshots.push(loose);
        assert!(TimeTravelManager::import(stray).is_err());

        let mut headless = good.clone();
        headless.head = Some(SnapshotId::new());
        assert!(matches!(
            TimeTravelManager::import(headless),
            Err(TimeTravelError::SnapshotNotFound(_))
        ));
        let mut branchless = good.clone();
        branchless.branches[0].head = SnapshotId::new();
        assert!(TimeTravelManager::import(branchless).is_err());

        // A cycle of parent links used to loop for ever.
        let mut cyclic = good;
        for snapshot in &mut cyclic.snapshots {
            if snapshot.id == a {
                snapshot.parent_id = Some(c);
            }
        }
        let err = TimeTravelManager::import(cyclic).unwrap_err();
        assert!(
            matches!(err, TimeTravelError::VerificationFailed { .. }),
            "{err:?}"
        );

        let (mut looped, [a, _, c]) = three();
        looped.snapshots.get_mut(&a).unwrap().parent_id = Some(c);
        assert_eq!(looped.get_history().len(), 3);
        let err = looped.verify_chain().unwrap_err();
        assert!(format!("{err:?}").contains("cycle"), "{err:?}");
        assert!(looped.full_checkout(&c).is_some());
        assert!(looped.generate_replay(&SnapshotId::new(), &c).is_none());
    }

    #[test]
    fn test_checkout_verifies_when_the_manager_does() {
        // checkout_by_id skipped verify_on_access, restoring a snapshot
        // rollback_to refuses.
        let (mut ttm, [a, _, c]) = {
            let mut ttm = TimeTravelManager::new("agent");
            ttm.set("k", b"1".to_vec());
            let a = ttm.create_checkpoint("a");
            ttm.set("k", b"2".to_vec());
            let b = ttm.create_checkpoint("b");
            let c = ttm.create_checkpoint("c");
            (ttm, [a, b, c])
        };
        ttm.snapshots.get_mut(&a).unwrap().label = "tampered".into();
        assert!(ttm.rollback_to(a).is_err());
        assert!(ttm.get_snapshot(a).is_none());
        assert!(ttm.checkout_by_id(a, None).is_err());
        assert_eq!(ttm.head(), Some(c), "nothing restored");

        let mut lax = TimeTravelManager::with_config(
            "agent",
            TimeTravelConfig {
                verify_on_access: false,
                ..TimeTravelConfig::default()
            },
        );
        lax.set("k", b"1".to_vec());
        let id = lax.create_checkpoint("a");
        lax.snapshots.get_mut(&id).unwrap().label = "tampered".into();
        assert!(lax.checkout_by_id(id, None).is_ok(), "not asked to verify");
        assert!(lax
            .checkout_by_id(id, Some(CheckoutOptions::new().with_verification()))
            .is_err());
        let checked = lax
            .checkout_by_id(
                id,
                Some(CheckoutOptions::new().with_branch("b").preserve_state()),
            )
            .unwrap();
        assert_eq!(checked.entries_restored, 1);
        assert_eq!(lax.list_branches(), ["b"]);
        assert!(lax.checkout_by_hash(&[7u8; 32], None).is_err());
    }

    #[test]
    fn test_pruning_keeps_every_branch_history() {
        // Only branch heads were kept, so a branch lost its history and
        // stopped verifying.
        let mut ttm = TimeTravelManager::with_config(
            "agent",
            TimeTravelConfig::default().with_max_snapshots(3),
        );
        ttm.set("k", b"0".to_vec());
        ttm.create_checkpoint("base");
        ttm.set("k", b"1".to_vec());
        let side_a = ttm.create_checkpoint("side-1");
        ttm.set("k", b"2".to_vec());
        ttm.create_checkpoint("side-2");
        ttm.create_branch("side").unwrap();
        ttm.rollback_to(side_a).unwrap();
        ttm.rollback().unwrap();
        for i in 0..6 {
            ttm.set("k", format!("main-{i}").into_bytes());
            ttm.create_checkpoint(format!("main-{i}"));
        }
        ttm.switch_branch("side").unwrap();
        assert!(
            ttm.verify_chain().unwrap(),
            "the branch's history is intact"
        );
        assert_eq!(ttm.get_history().len(), 3);
        assert_eq!(ttm.get("k"), Some(&b"2"[..]));
        assert!(ttm.delete_branch("side").is_ok());
        assert!(ttm.delete_branch("side").is_err());
        assert!(ttm.switch_branch("side").is_err());
    }

    #[test]
    fn test_a_restored_checkout_is_consistent_and_says_unverified() {
        let (ttm, [_, _, c]) = three();
        let checkout = ttm.full_checkout(&c).unwrap();
        assert_eq!(checkout.provenance_chain.len(), 3);

        let mut target = TimeTravelManager::new("other");
        target.restore_from_checkout(&checkout).unwrap();
        let restored = target.current_snapshot().unwrap();
        assert_eq!(restored.metadata["restored_from"], c.to_string());
        assert!(restored.metadata.contains_key("restored_unverified"));
        assert_eq!(restored.get("k"), Some(&b"2"[..]));
        assert!(target.verify_chain().unwrap());

        // Links that don't chain, or a root that isn't the last link.
        let mut broken = checkout.clone();
        broken.provenance_chain[1].previous_hash = Some("00".repeat(32));
        assert!(target.restore_from_checkout(&broken).is_err());
        let mut rootless = checkout.clone();
        rootless.merkle_root = "ff".repeat(32);
        assert!(target.restore_from_checkout(&rootless).is_err());
        let mut empty = checkout;
        empty.provenance_chain.clear();
        assert!(target.restore_from_checkout(&empty).is_err());
    }

    #[test]
    fn test_history_diffs_and_working_state() {
        let (mut ttm, [a, b, c]) = three();
        assert_eq!(ttm.get_history_ids(), [c, b, a]);
        let diff = ttm.diff(a, c).unwrap();
        assert!(diff.has_changes());
        assert!(ttm.diff(a, SnapshotId::new()).is_err());
        ttm.set("new", b"n".to_vec());
        assert!(ttm.diff_from_working(c).unwrap().has_changes());
        assert!(ttm.diff_from_working(SnapshotId::new()).is_err());
        assert_eq!(ttm.remove("new"), Some(b"n".to_vec()));
        let mut keys = ttm.working_keys();
        keys.sort();
        assert_eq!(keys, ["k", "other"]);
        ttm.rollback().unwrap();
        assert_eq!(ttm.head(), Some(b));
        ttm.rollback().unwrap();
        assert!(matches!(
            ttm.rollback(),
            Err(TimeTravelError::NoSnapshotsAvailable)
        ));
        ttm.clear_working_state();
        assert!(ttm.working_keys().is_empty());
        let id = ttm.create_checkpoint_with_state("explicit", vec![("e".into(), b"1".to_vec())]);
        assert_eq!(ttm.get("e"), Some(&b"1"[..]));
        assert_eq!(ttm.snapshots[&id].parent_hash, Some(ttm.snapshots[&a].hash));
        assert!(ttm.verify_chain().unwrap());
        let snapshot = ttm.get_snapshot(id).unwrap();
        assert_eq!(
            (snapshot.len(), snapshot.is_empty(), snapshot.keys()),
            (1, false, vec!["e"])
        );
        assert_eq!(ttm.namespace(), "agent");

        let mut empty = TimeTravelManager::new("e");
        assert!(empty.rollback().is_err());
        assert!(empty.create_branch("x").is_err());
        assert!(empty.verify_chain().unwrap());
        assert!(empty.get_chain_root().is_none());
        assert!(TimeTravelConfig::default()
            .with_retention(60)
            .retention_seconds
            .is_some());
    }
}
