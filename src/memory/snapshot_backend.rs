//! Persistent Storage Backend for Memory Snapshots (Issue #11)
//!
//! This module provides persistent storage backends for state snapshots,
//! enabling the time travel system to persist checkpoints across restarts.
//!
//! # Overview
//!
//! The snapshot backend module provides:
//! - **SnapshotBackend trait**: Abstract interface for snapshot storage
//! - **InMemorySnapshotBackend**: In-memory storage for testing
//! - **FileSnapshotBackend**: File-based persistence with optional compression
//!
//! # Architecture
//!
//! Snapshots are stored with the following structure:
//! - Each agent has its own directory
//! - Snapshots are stored as JSON files (optionally gzip compressed)
//! - An index file tracks all snapshots for quick listing
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::memory::snapshot_backend::{
//!     FileSnapshotBackend, SnapshotBackend, SnapshotConfig,
//! };
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = SnapshotConfig::new(PathBuf::from("/tmp/snapshots"))
//!     .with_compression(true)
//!     .with_max_snapshots(100);
//!
//! let backend = FileSnapshotBackend::new(config).await?;
//!
//! // Save a snapshot
//! // backend.save_snapshot(&checkpoint).await?;
//!
//! // Load a snapshot
//! // let checkpoint = backend.load_snapshot(&id).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # File Format
//!
//! ## Snapshot File (JSON)
//! ```json
//! {
//!   "id": "01234567-89ab-cdef-0123-456789abcdef",
//!   "agent_id": "agent-1",
//!   "label": "Checkpoint after task completion",
//!   "parent_id": "fedcba98-7654-3210-fedc-ba9876543210",
//!   "created_at": "2026-02-01T12:00:00Z",
//!   "state": { ... },
//!   "hash": "...",
//!   "metadata": { ... }
//! }
//! ```
//!
//! ## Index File (JSON)
//! ```json
//! {
//!   "agent_id": "agent-1",
//!   "snapshots": [
//!     {
//!       "id": "...",
//!       "created_at": "...",
//!       "label": "..."
//!     }
//!   ],
//!   "updated_at": "..."
//! }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tokio::sync::RwLock;

use super::time_travel::{SnapshotId, StateCheckpoint};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during snapshot operations
#[derive(Debug, Error)]
pub enum SnapshotError {
    /// Snapshot not found
    #[error("Snapshot not found: {0}")]
    NotFound(SnapshotId),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// Corrupted data
    #[error("Corrupted data: {0}")]
    CorruptedData(String),

    /// Backend-specific error
    #[error("Backend error: {0}")]
    BackendError(String),
}

impl From<std::io::Error> for SnapshotError {
    fn from(err: std::io::Error) -> Self {
        SnapshotError::IoError(err.to_string())
    }
}

impl From<serde_json::Error> for SnapshotError {
    fn from(err: serde_json::Error) -> Self {
        SnapshotError::SerializationError(err.to_string())
    }
}

/// Result type for snapshot operations
pub type SnapshotResult<T> = Result<T, SnapshotError>;

// ============================================================================
// Snapshot Wrapper (includes agent_id for storage)
// ============================================================================

/// Wrapper for StateCheckpoint that includes agent_id for storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSnapshot {
    /// The agent ID this snapshot belongs to
    pub agent_id: String,
    /// The checkpoint data
    #[serde(flatten)]
    pub checkpoint: StateCheckpoint,
}

impl StoredSnapshot {
    /// Create a new stored snapshot
    pub fn new(agent_id: impl Into<String>, checkpoint: StateCheckpoint) -> Self {
        Self {
            agent_id: agent_id.into(),
            checkpoint,
        }
    }

    /// Get the snapshot ID
    pub fn id(&self) -> SnapshotId {
        self.checkpoint.id
    }
}

// ============================================================================
// Index Types
// ============================================================================

/// Summary of a snapshot for the index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotIndexEntry {
    /// Snapshot ID
    pub id: SnapshotId,
    /// When the snapshot was created
    pub created_at: DateTime<Utc>,
    /// Human-readable label
    pub label: String,
    /// Parent snapshot ID
    pub parent_id: Option<SnapshotId>,
}

impl From<&StateCheckpoint> for SnapshotIndexEntry {
    fn from(checkpoint: &StateCheckpoint) -> Self {
        Self {
            id: checkpoint.id,
            created_at: checkpoint.created_at,
            label: checkpoint.label.clone(),
            parent_id: checkpoint.parent_id,
        }
    }
}

/// Index file for an agent's snapshots
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotIndex {
    /// Agent ID
    pub agent_id: String,
    /// List of snapshots (newest first)
    pub snapshots: Vec<SnapshotIndexEntry>,
    /// When the index was last updated
    pub updated_at: DateTime<Utc>,
}

impl SnapshotIndex {
    /// Create a new empty index
    pub fn new(agent_id: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            snapshots: Vec::new(),
            updated_at: Utc::now(),
        }
    }

    /// Add a snapshot entry
    pub fn add(&mut self, entry: SnapshotIndexEntry) {
        // Insert at the beginning (newest first)
        self.snapshots.insert(0, entry);
        self.updated_at = Utc::now();
    }

    /// Remove a snapshot entry
    pub fn remove(&mut self, id: &SnapshotId) -> bool {
        let len_before = self.snapshots.len();
        self.snapshots.retain(|e| e.id != *id);
        if self.snapshots.len() != len_before {
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Get the latest snapshot ID
    pub fn latest(&self) -> Option<&SnapshotIndexEntry> {
        self.snapshots.first()
    }

    /// Get snapshot IDs, sorted by creation time (newest first)
    pub fn ids(&self) -> Vec<SnapshotId> {
        self.snapshots.iter().map(|e| e.id).collect()
    }

    /// Prune old snapshots, keeping only the newest `keep_count`
    pub fn prune(&mut self, keep_count: usize) -> Vec<SnapshotId> {
        if self.snapshots.len() <= keep_count {
            return Vec::new();
        }

        let pruned: Vec<SnapshotId> = self.snapshots.drain(keep_count..).map(|e| e.id).collect();

        if !pruned.is_empty() {
            self.updated_at = Utc::now();
        }

        pruned
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for snapshot backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Base path for file storage
    pub base_path: PathBuf,
    /// Whether to compress snapshots with gzip
    pub compression: bool,
    /// Maximum snapshots per agent (None = unlimited)
    pub max_snapshots_per_agent: Option<usize>,
    /// Compression level (0-9, default 6)
    pub compression_level: u32,
    /// Whether to sync writes to disk
    pub sync_writes: bool,
}

impl SnapshotConfig {
    /// Create a new configuration with the given base path
    pub fn new(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
            compression: false,
            max_snapshots_per_agent: None,
            compression_level: 6,
            sync_writes: true,
        }
    }

    /// Enable or disable compression
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Set the compression level (0-9)
    pub fn with_compression_level(mut self, level: u32) -> Self {
        self.compression_level = level.min(9);
        self
    }

    /// Set maximum snapshots per agent
    pub fn with_max_snapshots(mut self, max: usize) -> Self {
        self.max_snapshots_per_agent = Some(max);
        self
    }

    /// Enable or disable sync writes
    pub fn with_sync_writes(mut self, enabled: bool) -> Self {
        self.sync_writes = enabled;
        self
    }
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            base_path: PathBuf::from("./snapshots"),
            compression: false,
            max_snapshots_per_agent: None,
            compression_level: 6,
            sync_writes: true,
        }
    }
}

// ============================================================================
// Snapshot Backend Trait
// ============================================================================

/// Trait for snapshot storage backends
#[async_trait]
pub trait SnapshotBackend: Send + Sync {
    /// Save a snapshot to the backend
    async fn save_snapshot(
        &self,
        agent_id: &str,
        checkpoint: &StateCheckpoint,
    ) -> SnapshotResult<()>;

    /// Load a snapshot from the backend
    async fn load_snapshot(&self, id: &SnapshotId) -> SnapshotResult<StoredSnapshot>;

    /// List all snapshot IDs for an agent
    async fn list_snapshots(&self, agent_id: &str) -> SnapshotResult<Vec<SnapshotId>>;

    /// Delete a snapshot
    async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()>;

    /// Check if a snapshot exists
    async fn exists(&self, id: &SnapshotId) -> SnapshotResult<bool>;

    /// Get the latest snapshot for an agent
    async fn get_latest(&self, agent_id: &str) -> SnapshotResult<Option<StoredSnapshot>>;

    /// Prune old snapshots, keeping only the newest `keep_count`
    /// Returns the number of snapshots deleted
    async fn prune_old(&self, agent_id: &str, keep_count: usize) -> SnapshotResult<usize>;
}

// ============================================================================
// In-Memory Backend (for testing)
// ============================================================================

/// In-memory snapshot backend for testing
pub struct InMemorySnapshotBackend {
    /// Snapshots indexed by ID
    snapshots: Arc<RwLock<HashMap<SnapshotId, StoredSnapshot>>>,
    /// Index of snapshots per agent
    agent_snapshots: Arc<RwLock<HashMap<String, Vec<SnapshotId>>>>,
}

impl InMemorySnapshotBackend {
    /// Create a new in-memory backend
    pub fn new() -> Self {
        Self {
            snapshots: Arc::new(RwLock::new(HashMap::new())),
            agent_snapshots: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get the number of stored snapshots
    pub async fn len(&self) -> usize {
        self.snapshots.read().await.len()
    }

    /// Check if the backend is empty
    pub async fn is_empty(&self) -> bool {
        self.snapshots.read().await.is_empty()
    }

    /// Clear all snapshots
    pub async fn clear(&self) {
        self.snapshots.write().await.clear();
        self.agent_snapshots.write().await.clear();
    }
}

impl Default for InMemorySnapshotBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SnapshotBackend for InMemorySnapshotBackend {
    async fn save_snapshot(
        &self,
        agent_id: &str,
        checkpoint: &StateCheckpoint,
    ) -> SnapshotResult<()> {
        let stored = StoredSnapshot::new(agent_id, checkpoint.clone());
        let id = stored.id();

        // Store the snapshot
        self.snapshots.write().await.insert(id, stored);

        // Update the agent index
        let mut agent_snapshots = self.agent_snapshots.write().await;
        let ids = agent_snapshots
            .entry(agent_id.to_string())
            .or_insert_with(Vec::new);

        // Insert at the beginning (newest first)
        ids.insert(0, id);

        Ok(())
    }

    async fn load_snapshot(&self, id: &SnapshotId) -> SnapshotResult<StoredSnapshot> {
        self.snapshots
            .read()
            .await
            .get(id)
            .cloned()
            .ok_or(SnapshotError::NotFound(*id))
    }

    async fn list_snapshots(&self, agent_id: &str) -> SnapshotResult<Vec<SnapshotId>> {
        Ok(self
            .agent_snapshots
            .read()
            .await
            .get(agent_id)
            .cloned()
            .unwrap_or_default())
    }

    async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
        let mut snapshots = self.snapshots.write().await;

        if let Some(stored) = snapshots.remove(id) {
            // Remove from agent index
            let mut agent_snapshots = self.agent_snapshots.write().await;
            if let Some(ids) = agent_snapshots.get_mut(&stored.agent_id) {
                ids.retain(|i| i != id);
            }
            Ok(())
        } else {
            Err(SnapshotError::NotFound(*id))
        }
    }

    async fn exists(&self, id: &SnapshotId) -> SnapshotResult<bool> {
        Ok(self.snapshots.read().await.contains_key(id))
    }

    async fn get_latest(&self, agent_id: &str) -> SnapshotResult<Option<StoredSnapshot>> {
        let agent_snapshots = self.agent_snapshots.read().await;
        if let Some(ids) = agent_snapshots.get(agent_id) {
            if let Some(id) = ids.first() {
                let snapshots = self.snapshots.read().await;
                return Ok(snapshots.get(id).cloned());
            }
        }
        Ok(None)
    }

    async fn prune_old(&self, agent_id: &str, keep_count: usize) -> SnapshotResult<usize> {
        let mut agent_snapshots = self.agent_snapshots.write().await;
        let ids_to_delete = if let Some(ids) = agent_snapshots.get_mut(agent_id) {
            if ids.len() <= keep_count {
                return Ok(0);
            }
            ids.drain(keep_count..).collect::<Vec<_>>()
        } else {
            return Ok(0);
        };

        let deleted_count = ids_to_delete.len();
        let mut snapshots = self.snapshots.write().await;
        for id in ids_to_delete {
            snapshots.remove(&id);
        }

        Ok(deleted_count)
    }
}

// ============================================================================
// File-based Backend
// ============================================================================

/// File-based snapshot backend with optional gzip compression
pub struct FileSnapshotBackend {
    /// Configuration
    config: SnapshotConfig,
    /// In-memory index cache
    index_cache: Arc<RwLock<HashMap<String, SnapshotIndex>>>,
}

impl FileSnapshotBackend {
    /// Create a new file-based backend
    pub async fn new(config: SnapshotConfig) -> SnapshotResult<Self> {
        // Ensure the base directory exists
        fs::create_dir_all(&config.base_path).await?;

        let backend = Self {
            config,
            index_cache: Arc::new(RwLock::new(HashMap::new())),
        };

        Ok(backend)
    }

    /// Get the directory path for an agent
    fn agent_dir(&self, agent_id: &str) -> PathBuf {
        self.config.base_path.join(sanitize_filename(agent_id))
    }

    /// Get the path for a snapshot file
    fn snapshot_path(&self, agent_id: &str, id: &SnapshotId) -> PathBuf {
        let filename = if self.config.compression {
            format!("{}.json.gz", id)
        } else {
            format!("{}.json", id)
        };
        self.agent_dir(agent_id).join(filename)
    }

    /// Get the path for the index file
    fn index_path(&self, agent_id: &str) -> PathBuf {
        self.agent_dir(agent_id).join("index.json")
    }

    /// Load the index for an agent
    async fn load_index(&self, agent_id: &str) -> SnapshotResult<SnapshotIndex> {
        // Check cache first
        if let Some(index) = self.index_cache.read().await.get(agent_id) {
            return Ok(index.clone());
        }

        let index_path = self.index_path(agent_id);
        let index = if index_path.exists() {
            let content = fs::read_to_string(&index_path).await?;
            serde_json::from_str(&content)?
        } else {
            SnapshotIndex::new(agent_id)
        };

        // Cache the index
        self.index_cache
            .write()
            .await
            .insert(agent_id.to_string(), index.clone());

        Ok(index)
    }

    /// Save the index for an agent
    async fn save_index(&self, agent_id: &str, index: &SnapshotIndex) -> SnapshotResult<()> {
        let index_path = self.index_path(agent_id);
        let content = serde_json::to_string_pretty(index)?;
        fs::write(&index_path, content).await?;

        // Update cache
        self.index_cache
            .write()
            .await
            .insert(agent_id.to_string(), index.clone());

        Ok(())
    }

    /// Serialize a snapshot to bytes
    fn serialize_snapshot(&self, stored: &StoredSnapshot) -> SnapshotResult<Vec<u8>> {
        let json = serde_json::to_string_pretty(stored)?;

        if self.config.compression {
            let mut encoder =
                GzEncoder::new(Vec::new(), Compression::new(self.config.compression_level));
            encoder
                .write_all(json.as_bytes())
                .map_err(|e| SnapshotError::IoError(e.to_string()))?;
            encoder
                .finish()
                .map_err(|e| SnapshotError::IoError(e.to_string()))
        } else {
            Ok(json.into_bytes())
        }
    }

    /// Deserialize a snapshot from bytes
    fn deserialize_snapshot(
        &self,
        data: &[u8],
        compressed: bool,
    ) -> SnapshotResult<StoredSnapshot> {
        let json_str = if compressed {
            let mut decoder = GzDecoder::new(data);
            let mut decompressed = String::new();
            decoder.read_to_string(&mut decompressed).map_err(|e| {
                SnapshotError::CorruptedData(format!("Decompression failed: {}", e))
            })?;
            decompressed
        } else {
            String::from_utf8(data.to_vec())
                .map_err(|e| SnapshotError::CorruptedData(format!("Invalid UTF-8: {}", e)))?
        };

        serde_json::from_str(&json_str)
            .map_err(|e| SnapshotError::CorruptedData(format!("Invalid JSON: {}", e)))
    }

    /// Find the snapshot file for a given ID (checks both compressed and uncompressed)
    async fn find_snapshot_file(&self, id: &SnapshotId) -> SnapshotResult<(PathBuf, String, bool)> {
        // Search through all agent directories
        let mut entries = fs::read_dir(&self.config.base_path).await?;

        while let Some(entry) = entries.next_entry().await? {
            if entry.file_type().await?.is_dir() {
                let agent_id = entry.file_name().to_string_lossy().to_string();
                let agent_dir = entry.path();

                // Check for compressed file
                let compressed_path = agent_dir.join(format!("{}.json.gz", id));
                if compressed_path.exists() {
                    return Ok((compressed_path, agent_id, true));
                }

                // Check for uncompressed file
                let uncompressed_path = agent_dir.join(format!("{}.json", id));
                if uncompressed_path.exists() {
                    return Ok((uncompressed_path, agent_id, false));
                }
            }
        }

        Err(SnapshotError::NotFound(*id))
    }
}

#[async_trait]
impl SnapshotBackend for FileSnapshotBackend {
    async fn save_snapshot(
        &self,
        agent_id: &str,
        checkpoint: &StateCheckpoint,
    ) -> SnapshotResult<()> {
        // Ensure agent directory exists
        let agent_dir = self.agent_dir(agent_id);
        fs::create_dir_all(&agent_dir).await?;

        // Create the stored snapshot
        let stored = StoredSnapshot::new(agent_id, checkpoint.clone());

        // Serialize and write
        let data = self.serialize_snapshot(&stored)?;
        let path = self.snapshot_path(agent_id, &checkpoint.id);
        fs::write(&path, data).await?;

        // Update index
        let mut index = self.load_index(agent_id).await?;
        index.add(SnapshotIndexEntry::from(checkpoint));
        self.save_index(agent_id, &index).await?;

        // Auto-prune if configured
        if let Some(max) = self.config.max_snapshots_per_agent {
            self.prune_old(agent_id, max).await?;
        }

        Ok(())
    }

    async fn load_snapshot(&self, id: &SnapshotId) -> SnapshotResult<StoredSnapshot> {
        let (path, _agent_id, compressed) = self.find_snapshot_file(id).await?;
        let data = fs::read(&path).await?;
        self.deserialize_snapshot(&data, compressed)
    }

    async fn list_snapshots(&self, agent_id: &str) -> SnapshotResult<Vec<SnapshotId>> {
        let index = self.load_index(agent_id).await?;
        Ok(index.ids())
    }

    async fn delete_snapshot(&self, id: &SnapshotId) -> SnapshotResult<()> {
        let (path, agent_id, _compressed) = self.find_snapshot_file(id).await?;

        // Delete the file
        fs::remove_file(&path).await?;

        // Update index
        let mut index = self.load_index(&agent_id).await?;
        index.remove(id);
        self.save_index(&agent_id, &index).await?;

        Ok(())
    }

    async fn exists(&self, id: &SnapshotId) -> SnapshotResult<bool> {
        match self.find_snapshot_file(id).await {
            Ok(_) => Ok(true),
            Err(SnapshotError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    async fn get_latest(&self, agent_id: &str) -> SnapshotResult<Option<StoredSnapshot>> {
        let index = self.load_index(agent_id).await?;
        if let Some(entry) = index.latest() {
            let snapshot = self.load_snapshot(&entry.id).await?;
            Ok(Some(snapshot))
        } else {
            Ok(None)
        }
    }

    async fn prune_old(&self, agent_id: &str, keep_count: usize) -> SnapshotResult<usize> {
        let mut index = self.load_index(agent_id).await?;
        let pruned_ids = index.prune(keep_count);

        if pruned_ids.is_empty() {
            return Ok(0);
        }

        let count = pruned_ids.len();

        // Delete the files
        for id in &pruned_ids {
            let compressed_path = self.agent_dir(agent_id).join(format!("{}.json.gz", id));
            let uncompressed_path = self.agent_dir(agent_id).join(format!("{}.json", id));

            if compressed_path.exists() {
                let _ = fs::remove_file(&compressed_path).await;
            }
            if uncompressed_path.exists() {
                let _ = fs::remove_file(&uncompressed_path).await;
            }
        }

        // Save updated index
        self.save_index(agent_id, &index).await?;

        Ok(count)
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

/// Sanitize a string to be safe for use as a filename
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0' => '_',
            c => c,
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // Helper function to create a test checkpoint
    fn create_test_checkpoint(label: &str, parent: Option<SnapshotId>) -> StateCheckpoint {
        StateCheckpoint::new(
            label,
            parent,
            vec![
                ("key1".to_string(), b"value1".to_vec()),
                ("key2".to_string(), b"value2".to_vec()),
            ],
        )
    }

    // ========================================================================
    // In-Memory Backend Tests
    // ========================================================================

    #[tokio::test]
    async fn test_inmemory_save_and_load() {
        let backend = InMemorySnapshotBackend::new();
        let checkpoint = create_test_checkpoint("test", None);

        backend.save_snapshot("agent1", &checkpoint).await.unwrap();
        let loaded = backend.load_snapshot(&checkpoint.id).await.unwrap();

        assert_eq!(loaded.agent_id, "agent1");
        assert_eq!(loaded.checkpoint.id, checkpoint.id);
        assert_eq!(loaded.checkpoint.label, checkpoint.label);
    }

    #[tokio::test]
    async fn test_inmemory_list_snapshots() {
        let backend = InMemorySnapshotBackend::new();

        let cp1 = create_test_checkpoint("first", None);
        let cp2 = create_test_checkpoint("second", Some(cp1.id));
        let cp3 = create_test_checkpoint("third", Some(cp2.id));

        backend.save_snapshot("agent1", &cp1).await.unwrap();
        backend.save_snapshot("agent1", &cp2).await.unwrap();
        backend.save_snapshot("agent1", &cp3).await.unwrap();

        let ids = backend.list_snapshots("agent1").await.unwrap();
        assert_eq!(ids.len(), 3);

        // Should be newest first
        assert_eq!(ids[0], cp3.id);
        assert_eq!(ids[1], cp2.id);
        assert_eq!(ids[2], cp1.id);
    }

    #[tokio::test]
    async fn test_inmemory_delete_snapshot() {
        let backend = InMemorySnapshotBackend::new();
        let checkpoint = create_test_checkpoint("test", None);

        backend.save_snapshot("agent1", &checkpoint).await.unwrap();
        assert!(backend.exists(&checkpoint.id).await.unwrap());

        backend.delete_snapshot(&checkpoint.id).await.unwrap();
        assert!(!backend.exists(&checkpoint.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_inmemory_exists() {
        let backend = InMemorySnapshotBackend::new();
        let checkpoint = create_test_checkpoint("test", None);

        assert!(!backend.exists(&checkpoint.id).await.unwrap());

        backend.save_snapshot("agent1", &checkpoint).await.unwrap();
        assert!(backend.exists(&checkpoint.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_inmemory_get_latest() {
        let backend = InMemorySnapshotBackend::new();

        // No snapshots yet
        assert!(backend.get_latest("agent1").await.unwrap().is_none());

        let cp1 = create_test_checkpoint("first", None);
        backend.save_snapshot("agent1", &cp1).await.unwrap();

        let latest = backend.get_latest("agent1").await.unwrap().unwrap();
        assert_eq!(latest.checkpoint.id, cp1.id);

        let cp2 = create_test_checkpoint("second", Some(cp1.id));
        backend.save_snapshot("agent1", &cp2).await.unwrap();

        let latest = backend.get_latest("agent1").await.unwrap().unwrap();
        assert_eq!(latest.checkpoint.id, cp2.id);
    }

    #[tokio::test]
    async fn test_inmemory_prune_old() {
        let backend = InMemorySnapshotBackend::new();

        let cp1 = create_test_checkpoint("first", None);
        let cp2 = create_test_checkpoint("second", Some(cp1.id));
        let cp3 = create_test_checkpoint("third", Some(cp2.id));
        let cp4 = create_test_checkpoint("fourth", Some(cp3.id));
        let cp5 = create_test_checkpoint("fifth", Some(cp4.id));

        backend.save_snapshot("agent1", &cp1).await.unwrap();
        backend.save_snapshot("agent1", &cp2).await.unwrap();
        backend.save_snapshot("agent1", &cp3).await.unwrap();
        backend.save_snapshot("agent1", &cp4).await.unwrap();
        backend.save_snapshot("agent1", &cp5).await.unwrap();

        let deleted = backend.prune_old("agent1", 3).await.unwrap();
        assert_eq!(deleted, 2);

        let ids = backend.list_snapshots("agent1").await.unwrap();
        assert_eq!(ids.len(), 3);

        // Should have kept the newest 3
        assert!(ids.contains(&cp5.id));
        assert!(ids.contains(&cp4.id));
        assert!(ids.contains(&cp3.id));
        assert!(!ids.contains(&cp2.id));
        assert!(!ids.contains(&cp1.id));
    }

    #[tokio::test]
    async fn test_inmemory_multiple_agents() {
        let backend = InMemorySnapshotBackend::new();

        let cp1 = create_test_checkpoint("agent1-first", None);
        let cp2 = create_test_checkpoint("agent2-first", None);

        backend.save_snapshot("agent1", &cp1).await.unwrap();
        backend.save_snapshot("agent2", &cp2).await.unwrap();

        let agent1_ids = backend.list_snapshots("agent1").await.unwrap();
        let agent2_ids = backend.list_snapshots("agent2").await.unwrap();

        assert_eq!(agent1_ids.len(), 1);
        assert_eq!(agent2_ids.len(), 1);
        assert_eq!(agent1_ids[0], cp1.id);
        assert_eq!(agent2_ids[0], cp2.id);
    }

    #[tokio::test]
    async fn test_inmemory_not_found() {
        let backend = InMemorySnapshotBackend::new();
        let fake_id = SnapshotId::new();

        let result = backend.load_snapshot(&fake_id).await;
        assert!(matches!(result, Err(SnapshotError::NotFound(_))));

        let result = backend.delete_snapshot(&fake_id).await;
        assert!(matches!(result, Err(SnapshotError::NotFound(_))));
    }

    // ========================================================================
    // File Backend Tests
    // ========================================================================

    #[tokio::test]
    async fn test_file_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path());
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        let checkpoint = create_test_checkpoint("test", None);
        backend.save_snapshot("agent1", &checkpoint).await.unwrap();

        let loaded = backend.load_snapshot(&checkpoint.id).await.unwrap();
        assert_eq!(loaded.agent_id, "agent1");
        assert_eq!(loaded.checkpoint.id, checkpoint.id);
        assert_eq!(loaded.checkpoint.label, checkpoint.label);
    }

    #[tokio::test]
    async fn test_file_save_and_load_with_compression() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path()).with_compression(true);
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        let checkpoint = create_test_checkpoint("test", None);
        backend.save_snapshot("agent1", &checkpoint).await.unwrap();

        // Verify the file is compressed
        let expected_path = temp_dir
            .path()
            .join("agent1")
            .join(format!("{}.json.gz", checkpoint.id));
        assert!(expected_path.exists());

        let loaded = backend.load_snapshot(&checkpoint.id).await.unwrap();
        assert_eq!(loaded.checkpoint.id, checkpoint.id);
    }

    #[tokio::test]
    async fn test_file_list_snapshots() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path());
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        let cp1 = create_test_checkpoint("first", None);
        let cp2 = create_test_checkpoint("second", Some(cp1.id));

        backend.save_snapshot("agent1", &cp1).await.unwrap();
        backend.save_snapshot("agent1", &cp2).await.unwrap();

        let ids = backend.list_snapshots("agent1").await.unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], cp2.id); // Newest first
        assert_eq!(ids[1], cp1.id);
    }

    #[tokio::test]
    async fn test_file_delete_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path());
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        let checkpoint = create_test_checkpoint("test", None);
        backend.save_snapshot("agent1", &checkpoint).await.unwrap();

        assert!(backend.exists(&checkpoint.id).await.unwrap());

        backend.delete_snapshot(&checkpoint.id).await.unwrap();
        assert!(!backend.exists(&checkpoint.id).await.unwrap());
    }

    #[tokio::test]
    async fn test_file_prune_old() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path());
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        let cp1 = create_test_checkpoint("first", None);
        let cp2 = create_test_checkpoint("second", Some(cp1.id));
        let cp3 = create_test_checkpoint("third", Some(cp2.id));

        backend.save_snapshot("agent1", &cp1).await.unwrap();
        backend.save_snapshot("agent1", &cp2).await.unwrap();
        backend.save_snapshot("agent1", &cp3).await.unwrap();

        let deleted = backend.prune_old("agent1", 2).await.unwrap();
        assert_eq!(deleted, 1);

        let ids = backend.list_snapshots("agent1").await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&cp3.id));
        assert!(ids.contains(&cp2.id));
    }

    #[tokio::test]
    async fn test_file_auto_prune() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path()).with_max_snapshots(2);
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        let cp1 = create_test_checkpoint("first", None);
        let cp2 = create_test_checkpoint("second", Some(cp1.id));
        let cp3 = create_test_checkpoint("third", Some(cp2.id));

        backend.save_snapshot("agent1", &cp1).await.unwrap();
        backend.save_snapshot("agent1", &cp2).await.unwrap();
        backend.save_snapshot("agent1", &cp3).await.unwrap();

        let ids = backend.list_snapshots("agent1").await.unwrap();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&cp3.id));
        assert!(ids.contains(&cp2.id));
    }

    #[tokio::test]
    async fn test_file_get_latest() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path());
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        assert!(backend.get_latest("agent1").await.unwrap().is_none());

        let cp1 = create_test_checkpoint("first", None);
        backend.save_snapshot("agent1", &cp1).await.unwrap();

        let latest = backend.get_latest("agent1").await.unwrap().unwrap();
        assert_eq!(latest.checkpoint.id, cp1.id);

        let cp2 = create_test_checkpoint("second", Some(cp1.id));
        backend.save_snapshot("agent1", &cp2).await.unwrap();

        let latest = backend.get_latest("agent1").await.unwrap().unwrap();
        assert_eq!(latest.checkpoint.id, cp2.id);
    }

    #[tokio::test]
    async fn test_file_persistence_across_instances() {
        let temp_dir = TempDir::new().unwrap();
        let checkpoint = create_test_checkpoint("test", None);
        let id = checkpoint.id;

        // Save with first instance
        {
            let config = SnapshotConfig::new(temp_dir.path());
            let backend = FileSnapshotBackend::new(config).await.unwrap();
            backend.save_snapshot("agent1", &checkpoint).await.unwrap();
        }

        // Load with second instance
        {
            let config = SnapshotConfig::new(temp_dir.path());
            let backend = FileSnapshotBackend::new(config).await.unwrap();
            let loaded = backend.load_snapshot(&id).await.unwrap();
            assert_eq!(loaded.checkpoint.id, id);
            assert_eq!(loaded.checkpoint.label, "test");
        }
    }

    #[tokio::test]
    async fn test_file_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let config = SnapshotConfig::new(temp_dir.path());
        let backend = FileSnapshotBackend::new(config).await.unwrap();

        let fake_id = SnapshotId::new();
        let result = backend.load_snapshot(&fake_id).await;
        assert!(matches!(result, Err(SnapshotError::NotFound(_))));
    }

    // ========================================================================
    // Snapshot Index Tests
    // ========================================================================

    #[test]
    fn test_index_add_and_remove() {
        let mut index = SnapshotIndex::new("agent1");

        let cp1 = create_test_checkpoint("first", None);
        let cp2 = create_test_checkpoint("second", Some(cp1.id));

        index.add(SnapshotIndexEntry::from(&cp1));
        index.add(SnapshotIndexEntry::from(&cp2));

        assert_eq!(index.snapshots.len(), 2);
        assert_eq!(index.latest().unwrap().id, cp2.id);

        index.remove(&cp1.id);
        assert_eq!(index.snapshots.len(), 1);
    }

    #[test]
    fn test_index_prune() {
        let mut index = SnapshotIndex::new("agent1");

        let mut checkpoints: Vec<StateCheckpoint> = Vec::new();
        for i in 0..5 {
            let parent = if i > 0 {
                Some(checkpoints[i - 1].id)
            } else {
                None
            };
            let cp = create_test_checkpoint(&format!("cp{}", i), parent);
            index.add(SnapshotIndexEntry::from(&cp));
            checkpoints.push(cp);
        }

        let pruned = index.prune(3);
        assert_eq!(pruned.len(), 2);
        assert_eq!(index.snapshots.len(), 3);
    }

    // ========================================================================
    // Stored Snapshot Tests
    // ========================================================================

    #[test]
    fn test_stored_snapshot_serialization() {
        let checkpoint = create_test_checkpoint("test", None);
        let stored = StoredSnapshot::new("agent1", checkpoint.clone());

        let json = serde_json::to_string(&stored).unwrap();
        let deserialized: StoredSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.agent_id, "agent1");
        assert_eq!(deserialized.checkpoint.id, checkpoint.id);
        assert_eq!(deserialized.checkpoint.label, checkpoint.label);
    }

    // ========================================================================
    // Config Tests
    // ========================================================================

    #[test]
    fn test_config_defaults() {
        let config = SnapshotConfig::default();
        assert_eq!(config.base_path, PathBuf::from("./snapshots"));
        assert!(!config.compression);
        assert!(config.max_snapshots_per_agent.is_none());
    }

    #[test]
    fn test_config_builder() {
        let config = SnapshotConfig::new("/tmp/test")
            .with_compression(true)
            .with_compression_level(9)
            .with_max_snapshots(50);

        assert_eq!(config.base_path, PathBuf::from("/tmp/test"));
        assert!(config.compression);
        assert_eq!(config.compression_level, 9);
        assert_eq!(config.max_snapshots_per_agent, Some(50));
    }

    // ========================================================================
    // Utility Function Tests
    // ========================================================================

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("agent1"), "agent1");
        assert_eq!(sanitize_filename("agent/1"), "agent_1");
        assert_eq!(sanitize_filename("agent:1"), "agent_1");
        assert_eq!(sanitize_filename("agent*1?test"), "agent_1_test");
    }

    // ========================================================================
    // Error Tests
    // ========================================================================

    #[test]
    fn test_error_display() {
        let id = SnapshotId::new();

        let err = SnapshotError::NotFound(id);
        assert!(err.to_string().contains("not found"));

        let err = SnapshotError::SerializationError("test error".to_string());
        assert!(err.to_string().contains("Serialization"));

        let err = SnapshotError::IoError("disk full".to_string());
        assert!(err.to_string().contains("IO"));

        let err = SnapshotError::CorruptedData("invalid checksum".to_string());
        assert!(err.to_string().contains("Corrupted"));

        let err = SnapshotError::BackendError("connection failed".to_string());
        assert!(err.to_string().contains("Backend"));
    }
}
