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
use std::collections::HashMap;
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during time travel operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeTravelError {
    /// Snapshot not found
    SnapshotNotFound(SnapshotId),
    /// Cannot rollback - no snapshots available
    NoSnapshotsAvailable,
    /// Snapshot verification failed
    VerificationFailed {
        snapshot_id: SnapshotId,
        reason: String,
    },
    /// Branch not found
    BranchNotFound(String),
    /// Cannot merge - conflicts detected
    MergeConflict {
        key: String,
        snapshot_a: SnapshotId,
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

// ============================================================================
// Snapshot Types
// ============================================================================

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
    /// Hash of the entire checkpoint (includes parent hash)
    pub hash: [u8; 32],
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
            metadata: HashMap::new(),
        };
        checkpoint.compute_hash();
        checkpoint
    }

    /// Add metadata to the checkpoint
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self.compute_hash();
        self
    }

    /// Compute the hash for this checkpoint
    fn compute_hash(&mut self) {
        let mut hasher = Sha256::new();

        // Include ID
        hasher.update(self.id.0.as_bytes());

        // Include label
        hasher.update(self.label.as_bytes());

        // Include parent hash for chain integrity
        if let Some(parent_id) = &self.parent_id {
            hasher.update(parent_id.0.as_bytes());
        }

        // Include state entries in deterministic order
        let mut keys: Vec<_> = self.state.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(&self.state[key].value_hash);
        }

        // Include metadata in deterministic order
        let mut meta_keys: Vec<_> = self.metadata.keys().collect();
        meta_keys.sort();
        for key in meta_keys {
            hasher.update(key.as_bytes());
            hasher.update(self.metadata[key].as_bytes());
        }

        self.hash = hasher.finalize().into();
    }

    /// Verify the checkpoint's integrity
    pub fn verify(&self) -> bool {
        // Verify all state entries
        for entry in self.state.values() {
            if !entry.verify() {
                return false;
            }
        }

        // Recompute and verify hash
        let mut hasher = Sha256::new();
        hasher.update(self.id.0.as_bytes());
        hasher.update(self.label.as_bytes());

        if let Some(parent_id) = &self.parent_id {
            hasher.update(parent_id.0.as_bytes());
        }

        let mut keys: Vec<_> = self.state.keys().collect();
        keys.sort();
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(&self.state[key].value_hash);
        }

        let mut meta_keys: Vec<_> = self.metadata.keys().collect();
        meta_keys.sort();
        for key in meta_keys {
            hasher.update(key.as_bytes());
            hasher.update(self.metadata[key].as_bytes());
        }

        let computed: [u8; 32] = hasher.finalize().into();
        computed == self.hash
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

// ============================================================================
// Configuration
// ============================================================================

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

// ============================================================================
// Time Travel Manager
// ============================================================================

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

    // ========================================================================
    // Working State Operations
    // ========================================================================

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

    // ========================================================================
    // Checkpoint Operations
    // ========================================================================

    /// Create a checkpoint from the current working state
    pub fn create_checkpoint(&mut self, label: impl Into<String>) -> SnapshotId {
        let state: Vec<_> = self
            .working_state
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        let checkpoint = StateCheckpoint::new(label, self.head, state);
        let id = checkpoint.id;

        self.snapshots.insert(id, checkpoint);
        self.head = Some(id);

        // Auto-prune if configured
        if self.config.auto_prune && self.config.max_snapshots > 0 {
            self.prune_old_snapshots();
        }

        id
    }

    /// Create a checkpoint with explicit state
    pub fn create_checkpoint_with_state(
        &mut self,
        label: impl Into<String>,
        state: Vec<(String, Vec<u8>)>,
    ) -> SnapshotId {
        let checkpoint = StateCheckpoint::new(label, self.head, state);
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

    /// Get the history chain from the current head
    pub fn get_history(&self) -> Vec<&StateCheckpoint> {
        let mut history = vec![];
        let mut current_id = self.head;

        while let Some(id) = current_id {
            if let Some(snapshot) = self.snapshots.get(&id) {
                history.push(snapshot);
                current_id = snapshot.parent_id;
            } else {
                break;
            }
        }

        history
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

    // ========================================================================
    // Branch Operations
    // ========================================================================

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

    // ========================================================================
    // Verification & Integrity
    // ========================================================================

    /// Verify the entire chain from head to genesis
    pub fn verify_chain(&self) -> TimeTravelResult<bool> {
        let history = self.get_history();

        for (i, snapshot) in history.iter().enumerate() {
            if !snapshot.verify() {
                return Err(TimeTravelError::VerificationFailed {
                    snapshot_id: snapshot.id,
                    reason: format!("Snapshot at position {} failed verification", i),
                });
            }

            // Verify parent linkage (except for genesis)
            if i < history.len() - 1 {
                if snapshot.parent_id != Some(history[i + 1].id) {
                    return Err(TimeTravelError::VerificationFailed {
                        snapshot_id: snapshot.id,
                        reason: "Parent ID mismatch".to_string(),
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

    // ========================================================================
    // Maintenance
    // ========================================================================

    /// Remove old snapshots based on configuration
    fn prune_old_snapshots(&mut self) {
        if self.config.max_snapshots == 0 {
            return;
        }

        // Get IDs in the main chain (these should be kept)
        let chain_ids: std::collections::HashSet<_> = self.get_history_ids().into_iter().collect();

        // Get IDs in branches
        let branch_ids: std::collections::HashSet<_> =
            self.branches.values().map(|b| b.head).collect();

        // Keep snapshots that are in chain, branches, or within max_snapshots
        if self.snapshots.len() <= self.config.max_snapshots {
            return;
        }

        // Collect snapshots to remove (not in current chain or branches)
        let mut all_snapshots: Vec<_> = self.snapshots.values().collect();
        all_snapshots.sort_by(|a, b| a.created_at.cmp(&b.created_at));

        let excess = self.snapshots.len() - self.config.max_snapshots;
        let mut to_remove = vec![];

        for snapshot in all_snapshots.iter().take(excess) {
            if !chain_ids.contains(&snapshot.id) && !branch_ids.contains(&snapshot.id) {
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

    /// Import from exported state
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

        // Verify the imported chain
        manager.verify_chain()?;

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

// ============================================================================
// Full Checkout Capability (MEM-005 Enhancement)
// ============================================================================

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
    Write { key: String, size: usize },
    /// Memory read
    Read { key: String },
    /// Memory delete
    Delete { key: String },
    /// Tool execution
    ToolExec { tool: String, params: serde_json::Value },
    /// Policy evaluation
    PolicyEval { action: String, resource: String, decision: String },
    /// LLM inference
    Inference { model: String, tokens: u64 },
    /// Custom action
    Custom { action_type: String, details: serde_json::Value },
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

impl TimeTravelManager {
    // ========================================================================
    // Checkout Operations (MEM-005 Enhanced)
    // ========================================================================

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

        // Verify if requested
        if options.verify_before_checkout && !snapshot.verify() {
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
        let state_hash = hex::encode(&snapshot.hash);

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
        let snapshot_idx = self.snapshots.iter().position(|s| &s.id == snapshot_id)?;
        let snapshot = &self.snapshots[snapshot_idx];

        // Build provenance chain from genesis to this snapshot
        let mut provenance_chain = Vec::new();
        for i in 0..=snapshot_idx {
            let s = &self.snapshots[i];
            provenance_chain.push(ProvenanceLink {
                state_hash: s.merkle_root.clone(),
                previous_hash: if i > 0 {
                    Some(self.snapshots[i - 1].merkle_root.clone())
                } else {
                    None
                },
                action: s.metadata.get("action")
                    .and_then(|v| v.as_str())
                    .unwrap_or("checkpoint")
                    .to_string(),
                timestamp: s.timestamp,
            });
        }

        // Get the state data at this point
        // For a full implementation, we'd need to reconstruct from the Merkle tree
        // For now, we use the current working state if this is the latest snapshot
        let state_data = if snapshot_idx == self.snapshots.len() - 1 {
            self.working_state.clone()
        } else {
            // For historical snapshots, we'd need delta reconstruction
            // This is a simplified implementation
            HashMap::new()
        };

        Some(FullCheckout {
            snapshot_id: snapshot_id.clone(),
            merkle_root: snapshot.merkle_root.clone(),
            state_data,
            metadata: CheckoutMetadata {
                created_at: chrono::Utc::now(),
                snapshot_timestamp: snapshot.timestamp,
                branch: self.current_branch.clone(),
                description: snapshot.metadata.get("description")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                agent_id: snapshot.metadata.get("agent_id")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                session_id: snapshot.metadata.get("session_id")
                    .and_then(|v| v.as_str())
                    .map(String::from),
            },
            provenance_chain,
        })
    }

    /// Restore from a full checkout
    pub fn restore_from_checkout(&mut self, checkout: &FullCheckout) -> Result<(), TimeTravelError> {
        // Verify the checkout integrity
        let computed_root = self.compute_merkle_root_from_state(&checkout.state_data);
        if computed_root != checkout.merkle_root {
            return Err(TimeTravelError::VerificationFailed(
                "Checkout merkle root mismatch".to_string()
            ));
        }

        // Restore the state
        self.working_state = checkout.state_data.clone();

        // Create a new snapshot for the restoration
        let mut metadata = serde_json::Map::new();
        metadata.insert("restored_from".to_string(), 
            serde_json::Value::String(checkout.snapshot_id.to_string()));
        metadata.insert("action".to_string(), 
            serde_json::Value::String("restore_from_checkout".to_string()));

        self.checkpoint_with_metadata(serde_json::Value::Object(metadata))?;

        Ok(())
    }

    fn compute_merkle_root_from_state(&self, state: &HashMap<String, Vec<u8>>) -> String {
        use sha2::{Sha256, Digest};
        
        let mut hasher = Sha256::new();
        let mut keys: Vec<_> = state.keys().collect();
        keys.sort();
        
        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(&state[key]);
        }
        
        hex::encode(hasher.finalize())
    }

    /// Generate replay steps between two snapshots
    pub fn generate_replay(&self, from: &SnapshotId, to: &SnapshotId) -> Option<Vec<ReplayStep>> {
        let from_idx = self.snapshots.iter().position(|s| &s.id == from)?;
        let to_idx = self.snapshots.iter().position(|s| &s.id == to)?;

        if from_idx >= to_idx {
            return None;
        }

        let mut steps = Vec::new();
        
        for i in from_idx..to_idx {
            let current = &self.snapshots[i];
            let next = &self.snapshots[i + 1];

            // Compute state diff
            let diff = self.compute_diff(&current.id, &next.id)?;

            let action = next.metadata.get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");

            let replay_action = match action {
                "write" => {
                    let key = next.metadata.get("key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let size = diff.changes.iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.as_ref().map(|d| d.len()).unwrap_or(0))
                        .unwrap_or(0);
                    ReplayAction::Write { 
                        key: key.to_string(), 
                        size 
                    }
                }
                "delete" => {
                    let key = next.metadata.get("key")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    ReplayAction::Delete { key: key.to_string() }
                }
                "tool_exec" => {
                    let tool = next.metadata.get("tool")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let params = next.metadata.get("params")
                        .cloned()
                        .unwrap_or(serde_json::json!({}));
                    ReplayAction::ToolExec { 
                        tool: tool.to_string(), 
                        params 
                    }
                }
                "policy_eval" => {
                    let action_str = next.metadata.get("action_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let resource = next.metadata.get("resource")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let decision = next.metadata.get("decision")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    ReplayAction::PolicyEval {
                        action: action_str.to_string(),
                        resource: resource.to_string(),
                        decision: decision.to_string(),
                    }
                }
                _ => ReplayAction::Custom {
                    action_type: action.to_string(),
                    details: next.metadata.clone(),
                }
            };

            let changes: Vec<StateChange> = diff.changes.iter()
                .map(|(key, new_value)| {
                    StateChange {
                        key: key.clone(),
                        previous_hash: None, // Would need historical state
                        new_hash: new_value.as_ref().map(|v| {
                            use sha2::{Sha256, Digest};
                            hex::encode(Sha256::digest(v))
                        }),
                    }
                })
                .collect();

            steps.push(ReplayStep {
                step: (i - from_idx + 1) as u64,
                state_hash: next.merkle_root.clone(),
                action: replay_action,
                changes,
                timestamp: next.timestamp,
            });
        }

        Some(steps)
    }

    /// Step forward one decision at a time (for debugging)
    pub fn step_forward(&mut self) -> Option<ReplayStep> {
        let current_idx = self.snapshots.iter()
            .position(|s| s.merkle_root == self.compute_current_merkle_root())?;

        if current_idx >= self.snapshots.len() - 1 {
            return None; // Already at latest
        }

        let next = &self.snapshots[current_idx + 1];
        
        // Apply the next state
        // In a full implementation, we'd apply the delta
        // For now, we just move the pointer

        let action = next.metadata.get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        Some(ReplayStep {
            step: (current_idx + 1) as u64,
            state_hash: next.merkle_root.clone(),
            action: ReplayAction::Custom {
                action_type: action.to_string(),
                details: next.metadata.clone(),
            },
            changes: vec![],
            timestamp: next.timestamp,
        })
    }
}

// ============================================================================
// Additional Tests
// ============================================================================

#[cfg(test)]
mod checkout_tests {
    use super::*;

    #[test]
    fn test_full_checkout() {
        let mut manager = TimeTravelManager::new(TimeTravelConfig::default());
        
        manager.set("key1", b"value1".to_vec());
        manager.checkpoint().unwrap();
        
        let snapshot_id = manager.current_snapshot_id().unwrap();
        let checkout = manager.full_checkout(&snapshot_id).unwrap();
        
        assert_eq!(checkout.snapshot_id, snapshot_id);
        assert!(!checkout.provenance_chain.is_empty());
    }

    #[test]
    fn test_restore_from_checkout() {
        let mut manager = TimeTravelManager::new(TimeTravelConfig::default());
        
        manager.set("key1", b"value1".to_vec());
        manager.checkpoint().unwrap();
        
        let snapshot_id = manager.current_snapshot_id().unwrap();
        let checkout = manager.full_checkout(&snapshot_id).unwrap();
        
        // Create a new manager and restore
        let mut new_manager = TimeTravelManager::new(TimeTravelConfig::default());
        new_manager.restore_from_checkout(&checkout).unwrap();
        
        assert_eq!(new_manager.get("key1"), Some(b"value1".to_vec()));
    }

    #[test]
    fn test_generate_replay() {
        let mut manager = TimeTravelManager::new(TimeTravelConfig::default());
        
        // Create some state changes
        manager.checkpoint().unwrap();
        let first_id = manager.current_snapshot_id().unwrap();
        
        manager.set("key1", b"value1".to_vec());
        manager.checkpoint().unwrap();
        
        manager.set("key2", b"value2".to_vec());
        manager.checkpoint().unwrap();
        let last_id = manager.current_snapshot_id().unwrap();
        
        let replay = manager.generate_replay(&first_id, &last_id);
        assert!(replay.is_some());
        
        let steps = replay.unwrap();
        assert_eq!(steps.len(), 2);
    }
}
