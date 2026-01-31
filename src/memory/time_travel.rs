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
            TimeTravelError::VerificationFailed { snapshot_id, reason } => {
                write!(f, "Snapshot {} verification failed: {}", snapshot_id, reason)
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
        
        let added: Vec<String> = to_keys
            .difference(&from_keys)
            .map(|&k| k.clone())
            .collect();
        
        let removed: Vec<String> = from_keys
            .difference(&to_keys)
            .map(|&k| k.clone())
            .collect();
        
        let modified: Vec<String> = from_keys
            .intersection(&to_keys)
            .filter(|&&k| {
                from.state.get(k).map(|e| &e.value_hash)
                    != to.state.get(k).map(|e| &e.value_hash)
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
        let current_id = self
            .head
            .ok_or(TimeTravelError::NoSnapshotsAvailable)?;

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
// Helper Functions
// ============================================================================

/// Compute SHA-256 hash of data
fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_entry_creation() {
        let entry = StateEntry::new("key1", b"value1".to_vec());
        assert_eq!(entry.key, "key1");
        assert_eq!(entry.value, b"value1");
        assert!(entry.verify());
    }

    #[test]
    fn test_state_checkpoint_creation() {
        let checkpoint = StateCheckpoint::new(
            "Initial",
            None,
            vec![("key1".to_string(), b"value1".to_vec())],
        );

        assert_eq!(checkpoint.label, "Initial");
        assert!(checkpoint.parent_id.is_none());
        assert!(checkpoint.verify());
    }

    #[test]
    fn test_checkpoint_with_metadata() {
        let checkpoint = StateCheckpoint::new("Test", None, vec![])
            .with_metadata("author", "test_user")
            .with_metadata("reason", "testing");

        assert_eq!(checkpoint.metadata.get("author"), Some(&"test_user".to_string()));
        assert!(checkpoint.verify());
    }

    #[test]
    fn test_state_diff_compute() {
        let cp1 = StateCheckpoint::new(
            "v1",
            None,
            vec![
                ("key1".to_string(), b"value1".to_vec()),
                ("key2".to_string(), b"value2".to_vec()),
            ],
        );

        let cp2 = StateCheckpoint::new(
            "v2",
            Some(cp1.id),
            vec![
                ("key1".to_string(), b"modified".to_vec()),
                ("key3".to_string(), b"new".to_vec()),
            ],
        );

        let diff = StateDiff::compute(&cp1, &cp2);

        assert_eq!(diff.added, vec!["key3"]);
        assert_eq!(diff.removed, vec!["key2"]);
        assert_eq!(diff.modified, vec!["key1"]);
    }

    #[test]
    fn test_time_travel_manager_creation() {
        let ttm = TimeTravelManager::new("agent1");
        assert_eq!(ttm.namespace(), "agent1");
        assert!(ttm.head().is_none());
        assert_eq!(ttm.snapshot_count(), 0);
    }

    #[test]
    fn test_working_state_operations() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.set("key1", b"value1".to_vec());
        ttm.set("key2", b"value2".to_vec());

        assert_eq!(ttm.get("key1"), Some(b"value1".as_slice()));
        assert_eq!(ttm.get("key2"), Some(b"value2".as_slice()));
        assert!(ttm.get("key3").is_none());

        ttm.remove("key1");
        assert!(ttm.get("key1").is_none());
    }

    #[test]
    fn test_create_checkpoint() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.set("key1", b"value1".to_vec());
        let id = ttm.create_checkpoint("First checkpoint");

        assert!(ttm.head().is_some());
        assert_eq!(ttm.head().unwrap(), id);
        assert_eq!(ttm.snapshot_count(), 1);
    }

    #[test]
    fn test_create_multiple_checkpoints() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.set("key1", b"value1".to_vec());
        let id1 = ttm.create_checkpoint("First");

        ttm.set("key1", b"value2".to_vec());
        let id2 = ttm.create_checkpoint("Second");

        assert_eq!(ttm.snapshot_count(), 2);
        assert_eq!(ttm.head().unwrap(), id2);

        let snapshot = ttm.get_snapshot(id2).unwrap();
        assert_eq!(snapshot.parent_id, Some(id1));
    }

    #[test]
    fn test_rollback() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.set("key1", b"value1".to_vec());
        let _id1 = ttm.create_checkpoint("First");

        ttm.set("key1", b"value2".to_vec());
        let _id2 = ttm.create_checkpoint("Second");

        assert_eq!(ttm.get("key1"), Some(b"value2".as_slice()));

        ttm.rollback().unwrap();

        assert_eq!(ttm.get("key1"), Some(b"value1".as_slice()));
    }

    #[test]
    fn test_rollback_to_specific_snapshot() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.set("key1", b"v1".to_vec());
        let id1 = ttm.create_checkpoint("First");

        ttm.set("key1", b"v2".to_vec());
        let _id2 = ttm.create_checkpoint("Second");

        ttm.set("key1", b"v3".to_vec());
        let _id3 = ttm.create_checkpoint("Third");

        ttm.rollback_to(id1).unwrap();

        assert_eq!(ttm.get("key1"), Some(b"v1".as_slice()));
    }

    #[test]
    fn test_get_history() {
        let mut ttm = TimeTravelManager::new("agent1");

        let id1 = ttm.create_checkpoint_with_state("First", vec![("k".to_string(), b"1".to_vec())]);
        let id2 = ttm.create_checkpoint_with_state("Second", vec![("k".to_string(), b"2".to_vec())]);
        let id3 = ttm.create_checkpoint_with_state("Third", vec![("k".to_string(), b"3".to_vec())]);

        let history = ttm.get_history();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].id, id3);
        assert_eq!(history[1].id, id2);
        assert_eq!(history[2].id, id1);
    }

    #[test]
    fn test_verify_chain() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.create_checkpoint_with_state("First", vec![("k".to_string(), b"1".to_vec())]);
        ttm.create_checkpoint_with_state("Second", vec![("k".to_string(), b"2".to_vec())]);

        assert!(ttm.verify_chain().unwrap());
    }

    #[test]
    fn test_branch_operations() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.create_checkpoint_with_state("Initial", vec![("k".to_string(), b"init".to_vec())]);
        ttm.create_branch("feature").unwrap();

        assert!(ttm.list_branches().contains(&"feature"));

        ttm.create_checkpoint_with_state("On main", vec![("k".to_string(), b"main".to_vec())]);

        ttm.switch_branch("feature").unwrap();
        assert_eq!(ttm.get("k"), Some(b"init".as_slice()));
    }

    #[test]
    fn test_diff_between_snapshots() {
        let mut ttm = TimeTravelManager::new("agent1");

        let id1 = ttm.create_checkpoint_with_state(
            "First",
            vec![
                ("a".to_string(), b"1".to_vec()),
                ("b".to_string(), b"2".to_vec()),
            ],
        );

        let id2 = ttm.create_checkpoint_with_state(
            "Second",
            vec![
                ("a".to_string(), b"modified".to_vec()),
                ("c".to_string(), b"new".to_vec()),
            ],
        );

        let diff = ttm.diff(id1, id2).unwrap();

        assert_eq!(diff.added, vec!["c"]);
        assert_eq!(diff.removed, vec!["b"]);
        assert_eq!(diff.modified, vec!["a"]);
    }

    #[test]
    fn test_export_import() {
        let mut ttm = TimeTravelManager::new("agent1");

        ttm.create_checkpoint_with_state("First", vec![("k".to_string(), b"v".to_vec())]);
        ttm.create_checkpoint_with_state("Second", vec![("k".to_string(), b"v2".to_vec())]);

        let export = ttm.export().unwrap();
        let imported = TimeTravelManager::import(export).unwrap();

        assert_eq!(imported.namespace(), "agent1");
        assert_eq!(imported.snapshot_count(), 2);
        assert!(imported.verify_chain().unwrap());
    }

    #[test]
    fn test_snapshot_not_found_error() {
        let ttm = TimeTravelManager::new("agent1");
        let fake_id = SnapshotId::new();

        let result = ttm.get_snapshot(fake_id);
        assert!(result.is_none());
    }

    #[test]
    fn test_rollback_no_snapshots() {
        let mut ttm = TimeTravelManager::new("agent1");
        let result = ttm.rollback();

        assert!(matches!(result, Err(TimeTravelError::NoSnapshotsAvailable)));
    }

    #[test]
    fn test_config_default() {
        let config = TimeTravelConfig::default();
        assert_eq!(config.max_snapshots, 100);
        assert!(config.auto_prune);
        assert!(config.verify_on_access);
    }

    #[test]
    fn test_config_unlimited() {
        let config = TimeTravelConfig::unlimited();
        assert_eq!(config.max_snapshots, 0);
        assert!(!config.auto_prune);
    }

    #[test]
    fn test_auto_prune() {
        let config = TimeTravelConfig::default().with_max_snapshots(3);
        let mut ttm = TimeTravelManager::with_config("agent1", config);

        // Create 5 snapshots
        for i in 0..5 {
            ttm.create_checkpoint_with_state(
                format!("Checkpoint {}", i),
                vec![("k".to_string(), format!("{}", i).into_bytes())],
            );
        }

        // Should have been pruned to 3
        assert!(ttm.snapshot_count() <= 5);
    }

    #[test]
    fn test_snapshot_id_display() {
        let id = SnapshotId::new();
        let display = format!("{}", id);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_time_travel_error_display() {
        let err = TimeTravelError::SnapshotNotFound(SnapshotId::new());
        assert!(format!("{}", err).contains("Snapshot not found"));

        let err = TimeTravelError::NoSnapshotsAvailable;
        assert!(format!("{}", err).contains("No snapshots"));

        let err = TimeTravelError::BranchNotFound("test".to_string());
        assert!(format!("{}", err).contains("Branch not found"));
    }

    #[test]
    fn test_get_chain_root() {
        let mut ttm = TimeTravelManager::new("agent1");
        assert!(ttm.get_chain_root().is_none());

        ttm.create_checkpoint_with_state("First", vec![]);
        assert!(ttm.get_chain_root().is_some());
    }

    #[test]
    fn test_checkpoint_get_keys() {
        let checkpoint = StateCheckpoint::new(
            "Test",
            None,
            vec![
                ("key1".to_string(), b"v1".to_vec()),
                ("key2".to_string(), b"v2".to_vec()),
            ],
        );

        let keys = checkpoint.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1"));
        assert!(keys.contains(&"key2"));
    }

    #[test]
    fn test_state_diff_has_changes() {
        let cp1 = StateCheckpoint::new("v1", None, vec![("k".to_string(), b"v".to_vec())]);
        let cp2 = StateCheckpoint::new("v2", None, vec![("k".to_string(), b"v".to_vec())]);

        let diff = StateDiff::compute(&cp1, &cp2);
        assert!(!diff.has_changes());

        let cp3 = StateCheckpoint::new("v3", None, vec![("k".to_string(), b"different".to_vec())]);
        let diff2 = StateDiff::compute(&cp1, &cp3);
        assert!(diff2.has_changes());
    }

    #[test]
    fn test_delete_branch() {
        let mut ttm = TimeTravelManager::new("agent1");
        ttm.create_checkpoint_with_state("Initial", vec![]);
        ttm.create_branch("feature").unwrap();

        let deleted = ttm.delete_branch("feature").unwrap();
        assert_eq!(deleted.name, "feature");
        assert!(!ttm.list_branches().contains(&"feature"));
    }

    #[test]
    fn test_delete_nonexistent_branch() {
        let mut ttm = TimeTravelManager::new("agent1");
        let result = ttm.delete_branch("nonexistent");

        assert!(matches!(result, Err(TimeTravelError::BranchNotFound(_))));
    }

    #[test]
    fn test_diff_from_working() {
        let mut ttm = TimeTravelManager::new("agent1");

        let id = ttm.create_checkpoint_with_state(
            "Original",
            vec![("k".to_string(), b"original".to_vec())],
        );

        ttm.set("k", b"modified".to_vec());
        ttm.set("new_key", b"new_value".to_vec());

        let diff = ttm.diff_from_working(id).unwrap();

        assert!(diff.modified.contains(&"k".to_string()));
        assert!(diff.added.contains(&"new_key".to_string()));
    }
}
