//! Cryptographic Audit Logging Module
//!
//! Provides tamper-evident, hash-chained audit logging for agent actions.
//! Supports pluggable backends for persistent storage (Issue #3).
//!
//! # Features
//! - Hash-chained audit entries for tamper detection
//! - Pluggable storage backends (memory, file, database)
//! - Optional ed25519 signing for non-repudiation (Issue #51)
//! - Chain verification and integrity checks
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::audit::{AuditLogger, AuditDecision, AuditBackend, FileAuditBackend};
//!
//! // Create with file-based persistence
//! let backend = FileAuditBackend::new("/var/log/vak/audit").unwrap();
//! let mut logger = AuditLogger::with_backend(Box::new(backend)).unwrap();
//!
//! logger.log("agent-1", "read", "/data/file.txt", AuditDecision::Allowed);
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Audit Entry Types
// ============================================================================

/// Represents a single audit log entry with cryptographic chaining
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this entry
    pub id: u64,
    /// Unix timestamp when the entry was created
    pub timestamp: u64,
    /// ID of the agent that performed the action
    pub agent_id: String,
    /// The action that was performed
    pub action: String,
    /// The resource that was accessed
    pub resource: String,
    /// The decision outcome
    pub decision: AuditDecision,
    /// SHA-256 hash of this entry
    pub hash: String,
    /// Hash of the previous entry (chain linkage)
    pub prev_hash: String,
    /// Optional ed25519 signature for non-repudiation (Issue #51)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Optional metadata for extensibility
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Decision outcome for an audited action
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuditDecision {
    /// Action was allowed
    Allowed,
    /// Action was denied
    Denied,
    /// An error occurred during evaluation
    Error(String),
}

impl std::fmt::Display for AuditDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditDecision::Allowed => write!(f, "ALLOWED"),
            AuditDecision::Denied => write!(f, "DENIED"),
            AuditDecision::Error(msg) => write!(f, "ERROR: {}", msg),
        }
    }
}

// ============================================================================
// Audit Backend Trait (Issue #3)
// ============================================================================

/// Trait for audit storage backends
///
/// Allows pluggable persistence for audit logs:
/// - Memory (default, for testing)
/// - File (append-only log files)
/// - Database (PostgreSQL/SQLite for queries)
/// - S3/Cloud (for archival)
pub trait AuditBackend: Send + Sync + std::fmt::Debug {
    /// Append an entry to the audit log
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditError>;

    /// Load all entries from storage (for chain verification)
    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditError>;

    /// Get the last entry (for chain continuation)
    fn get_last(&self) -> Result<Option<AuditEntry>, AuditError>;

    /// Get entry count
    fn count(&self) -> Result<u64, AuditError>;

    /// Flush buffered entries to storage
    fn flush(&mut self) -> Result<(), AuditError>;

    /// Get entries by agent ID
    fn get_by_agent(&self, agent_id: &str) -> Result<Vec<AuditEntry>, AuditError>;

    /// Get entries in a time range
    fn get_by_time_range(&self, start: u64, end: u64) -> Result<Vec<AuditEntry>, AuditError>;
}

/// Errors that can occur in audit operations
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Backend not available
    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    /// Chain verification failed
    #[error("Chain verification failed: {0}")]
    ChainVerificationFailed(String),
}

// ============================================================================
// Memory Backend (Default)
// ============================================================================

/// In-memory audit backend (for testing and development)
#[derive(Debug, Default)]
pub struct MemoryAuditBackend {
    entries: Vec<AuditEntry>,
}

impl MemoryAuditBackend {
    /// Create a new memory backend
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl AuditBackend for MemoryAuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        self.entries.push(entry.clone());
        Ok(())
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditError> {
        Ok(self.entries.clone())
    }

    fn get_last(&self) -> Result<Option<AuditEntry>, AuditError> {
        Ok(self.entries.last().cloned())
    }

    fn count(&self) -> Result<u64, AuditError> {
        Ok(self.entries.len() as u64)
    }

    fn flush(&mut self) -> Result<(), AuditError> {
        Ok(()) // No-op for memory
    }

    fn get_by_agent(&self, agent_id: &str) -> Result<Vec<AuditEntry>, AuditError> {
        Ok(self
            .entries
            .iter()
            .filter(|e| e.agent_id == agent_id)
            .cloned()
            .collect())
    }

    fn get_by_time_range(&self, start: u64, end: u64) -> Result<Vec<AuditEntry>, AuditError> {
        Ok(self
            .entries
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect())
    }
}

// ============================================================================
// File Backend (Issue #3 - Persistent Storage)
// ============================================================================

/// File-based audit backend with append-only storage
///
/// Stores audit entries as JSONL (JSON Lines) for efficient appending
/// and streaming reads. Supports log rotation via file naming.
#[derive(Debug)]
pub struct FileAuditBackend {
    /// Directory for audit log files
    log_dir: PathBuf,
    /// Current log file path
    current_file: PathBuf,
    /// File handle for appending
    file_handle: Option<File>,
    /// Cached entry count
    entry_count: u64,
}

impl FileAuditBackend {
    /// Create a new file-based audit backend
    ///
    /// # Arguments
    /// * `log_dir` - Directory to store audit log files
    ///
    /// # Returns
    /// * New backend instance or error if directory cannot be created
    pub fn new(log_dir: impl AsRef<Path>) -> Result<Self, AuditError> {
        let log_dir = log_dir.as_ref().to_path_buf();

        // Create directory if needed
        if !log_dir.exists() {
            fs::create_dir_all(&log_dir)?;
        }

        let current_file = log_dir.join("audit.jsonl");

        // Count existing entries
        let entry_count = if current_file.exists() {
            let file = File::open(&current_file)?;
            BufReader::new(file).lines().count() as u64
        } else {
            0
        };

        Ok(Self {
            log_dir,
            current_file,
            file_handle: None,
            entry_count,
        })
    }

    /// Get or create the file handle
    fn get_file_handle(&mut self) -> Result<&mut File, AuditError> {
        if self.file_handle.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.current_file)?;
            self.file_handle = Some(file);
        }
        Ok(self.file_handle.as_mut().unwrap())
    }

    /// Rotate log file (create new file with timestamp)
    pub fn rotate(&mut self) -> Result<PathBuf, AuditError> {
        // Close current file
        self.file_handle = None;

        // Rename current file with timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let rotated_name = format!("audit_{}.jsonl", timestamp);
        let rotated_path = self.log_dir.join(&rotated_name);

        if self.current_file.exists() {
            fs::rename(&self.current_file, &rotated_path)?;
        }

        // Reset counter
        self.entry_count = 0;

        Ok(rotated_path)
    }
}

impl AuditBackend for FileAuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        let json = serde_json::to_string(entry)
            .map_err(|e| AuditError::SerializationError(e.to_string()))?;

        let file = self.get_file_handle()?;
        writeln!(file, "{}", json)?;

        self.entry_count += 1;
        Ok(())
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditError> {
        if !self.current_file.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.current_file)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            entries.push(entry);
        }

        Ok(entries)
    }

    fn get_last(&self) -> Result<Option<AuditEntry>, AuditError> {
        if !self.current_file.exists() {
            return Ok(None);
        }

        let file = File::open(&self.current_file)?;
        let reader = BufReader::new(file);
        let mut last_entry = None;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            last_entry = Some(entry);
        }

        Ok(last_entry)
    }

    fn count(&self) -> Result<u64, AuditError> {
        Ok(self.entry_count)
    }

    fn flush(&mut self) -> Result<(), AuditError> {
        if let Some(ref mut file) = self.file_handle {
            file.sync_all()?;
        }
        Ok(())
    }

    fn get_by_agent(&self, agent_id: &str) -> Result<Vec<AuditEntry>, AuditError> {
        let all = self.load_all()?;
        Ok(all.into_iter().filter(|e| e.agent_id == agent_id).collect())
    }

    fn get_by_time_range(&self, start: u64, end: u64) -> Result<Vec<AuditEntry>, AuditError> {
        let all = self.load_all()?;
        Ok(all
            .into_iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .collect())
    }
}

// ============================================================================
// Audit Logger with Pluggable Backend
// ============================================================================

/// Cryptographic audit logger with hash-chained entries
///
/// Now supports pluggable storage backends (Issue #3) for persistent
/// audit trails that survive restarts.
pub struct AuditLogger {
    /// Storage backend for audit entries
    backend: Box<dyn AuditBackend>,
    /// In-memory cache for fast access
    entries: Vec<AuditEntry>,
    /// Next entry ID
    next_id: u64,
    /// Chain is verified
    chain_verified: bool,
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger")
            .field("entry_count", &self.entries.len())
            .field("next_id", &self.next_id)
            .field("chain_verified", &self.chain_verified)
            .finish()
    }
}

impl AuditLogger {
    /// Creates a new audit logger with in-memory backend (default)
    pub fn new() -> Self {
        Self {
            backend: Box::new(MemoryAuditBackend::new()),
            entries: Vec::new(),
            next_id: 1,
            chain_verified: true,
        }
    }

    /// Creates a new audit logger with a custom backend (Issue #3)
    ///
    /// # Arguments
    /// * `backend` - The storage backend to use
    ///
    /// # Example
    /// ```rust,ignore
    /// let backend = FileAuditBackend::new("/var/log/vak/audit").unwrap();
    /// let logger = AuditLogger::with_backend(Box::new(backend));
    /// ```
    pub fn with_backend(backend: Box<dyn AuditBackend>) -> Result<Self, AuditError> {
        // Load existing entries from backend
        let entries = backend.load_all()?;
        let next_id = entries.last().map(|e| e.id + 1).unwrap_or(1);

        let mut logger = Self {
            backend,
            entries,
            next_id,
            chain_verified: false,
        };

        // Verify chain integrity on startup
        if let Err(e) = logger.verify_chain() {
            tracing::error!("Audit chain verification failed on startup: {:?}", e);
            return Err(AuditError::ChainVerificationFailed(format!("{:?}", e)));
        }

        logger.chain_verified = true;
        Ok(logger)
    }

    /// Logs an action with cryptographic hash chaining
    pub fn log(
        &mut self,
        agent_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        decision: AuditDecision,
    ) -> &AuditEntry {
        self.log_with_metadata(agent_id, action, resource, decision, None)
    }

    /// Logs an action with additional metadata
    pub fn log_with_metadata(
        &mut self,
        agent_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        decision: AuditDecision,
        metadata: Option<serde_json::Value>,
    ) -> &AuditEntry {
        let agent_id = agent_id.into();
        let action = action.into();
        let resource = resource.into();

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let prev_hash = self
            .entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64)); // Genesis hash

        let hash = Self::compute_hash_static(
            self.next_id,
            timestamp,
            &agent_id,
            &action,
            &resource,
            &decision,
            &prev_hash,
        );

        let entry = AuditEntry {
            id: self.next_id,
            timestamp,
            agent_id,
            action,
            resource,
            decision,
            hash,
            prev_hash,
            signature: None, // TODO: Add signing support (Issue #51)
            metadata,
        };

        // Persist to backend
        if let Err(e) = self.backend.append(&entry) {
            tracing::error!("Failed to persist audit entry: {:?}", e);
        }

        self.entries.push(entry);
        self.next_id += 1;

        self.entries.last().unwrap()
    }

    /// Static hash computation function (for use before self is available)
    fn compute_hash_static(
        id: u64,
        timestamp: u64,
        agent_id: &str,
        action: &str,
        resource: &str,
        decision: &AuditDecision,
        prev_hash: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(id.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(agent_id.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(resource.as_bytes());
        hasher.update(decision.to_string().as_bytes());
        hasher.update(prev_hash.as_bytes());

        let result = hasher.finalize();
        hex::encode(result)
    }

    /// Flush pending entries to the backend
    pub fn flush(&mut self) -> Result<(), AuditError> {
        self.backend.flush()
    }

    /// Get entries for a specific agent
    pub fn get_entries_by_agent(&self, agent_id: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.agent_id == agent_id)
            .collect()
    }

    /// Verifies the integrity of the entire audit chain
    pub fn verify_chain(&self) -> Result<(), AuditVerificationError> {
        if self.entries.is_empty() {
            return Ok(());
        }

        let genesis_hash = "0".repeat(64);

        for (i, entry) in self.entries.iter().enumerate() {
            // Verify prev_hash linkage
            let expected_prev = if i == 0 {
                &genesis_hash
            } else {
                &self.entries[i - 1].hash
            };

            if entry.prev_hash != *expected_prev {
                return Err(AuditVerificationError::BrokenChain {
                    entry_id: entry.id,
                    expected: expected_prev.clone(),
                    found: entry.prev_hash.clone(),
                });
            }

            // Verify entry hash
            let computed_hash = Self::compute_hash_static(
                entry.id,
                entry.timestamp,
                &entry.agent_id,
                &entry.action,
                &entry.resource,
                &entry.decision,
                &entry.prev_hash,
            );

            if entry.hash != computed_hash {
                return Err(AuditVerificationError::InvalidHash {
                    entry_id: entry.id,
                    expected: computed_hash,
                    found: entry.hash.clone(),
                });
            }
        }

        Ok(())
    }

    /// Exports audit log for compliance reporting
    pub fn export(&self) -> AuditReport {
        let total_entries = self.entries.len();
        let allowed_count = self
            .entries
            .iter()
            .filter(|e| e.decision == AuditDecision::Allowed)
            .count();
        let denied_count = self
            .entries
            .iter()
            .filter(|e| e.decision == AuditDecision::Denied)
            .count();
        let error_count = self
            .entries
            .iter()
            .filter(|e| matches!(e.decision, AuditDecision::Error(_)))
            .count();

        let chain_valid = self.verify_chain().is_ok();

        let first_timestamp = self.entries.first().map(|e| e.timestamp);
        let last_timestamp = self.entries.last().map(|e| e.timestamp);

        AuditReport {
            total_entries,
            allowed_count,
            denied_count,
            error_count,
            chain_valid,
            first_timestamp,
            last_timestamp,
            entries: self.entries.clone(),
        }
    }

    /// Returns all entries (read-only)
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get a specific entry by ID
    pub fn get_entry(&self, id: u64) -> Option<&AuditEntry> {
        self.entries.iter().find(|e| e.id == id)
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Error types for audit chain verification
#[derive(Debug)]
pub enum AuditVerificationError {
    /// Chain linkage is broken (prev_hash mismatch)
    BrokenChain {
        /// ID of the entry with broken chain
        entry_id: u64,
        /// Expected previous hash
        expected: String,
        /// Actual previous hash found
        found: String,
    },
    /// Entry hash does not match computed hash
    InvalidHash {
        /// ID of the entry with invalid hash
        entry_id: u64,
        /// Expected hash
        expected: String,
        /// Actual hash found
        found: String,
    },
}

impl std::fmt::Display for AuditVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BrokenChain {
                entry_id,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Broken chain at entry {}: expected prev_hash {}, found {}",
                    entry_id, expected, found
                )
            }
            Self::InvalidHash {
                entry_id,
                expected,
                found,
            } => {
                write!(
                    f,
                    "Invalid hash at entry {}: expected {}, found {}",
                    entry_id, expected, found
                )
            }
        }
    }
}

impl std::error::Error for AuditVerificationError {}

/// Compliance report generated from audit log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    /// Total number of audit entries
    pub total_entries: usize,
    /// Number of allowed actions
    pub allowed_count: usize,
    /// Number of denied actions
    pub denied_count: usize,
    /// Number of actions that resulted in errors
    pub error_count: usize,
    /// Whether the hash chain is valid
    pub chain_valid: bool,
    /// Timestamp of first entry (if any)
    pub first_timestamp: Option<u64>,
    /// Timestamp of last entry (if any)
    pub last_timestamp: Option<u64>,
    /// All audit entries
    pub entries: Vec<AuditEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_log_creates_entry() {
        let mut logger = AuditLogger::new();
        logger.log("agent-1", "read", "/data/file.txt", AuditDecision::Allowed);

        assert_eq!(logger.entries().len(), 1);
        assert_eq!(logger.entries()[0].agent_id, "agent-1");
    }

    #[test]
    fn test_hash_chain_integrity() {
        let mut logger = AuditLogger::new();
        logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/data/b.txt", AuditDecision::Denied);
        logger.log("agent-1", "delete", "/data/c.txt", AuditDecision::Allowed);

        assert!(logger.verify_chain().is_ok());

        // Verify chain linkage
        assert_eq!(logger.entries()[1].prev_hash, logger.entries()[0].hash);
        assert_eq!(logger.entries()[2].prev_hash, logger.entries()[1].hash);
    }

    #[test]
    fn test_export_report() {
        let mut logger = AuditLogger::new();
        logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/data/b.txt", AuditDecision::Denied);

        let report = logger.export();

        assert_eq!(report.total_entries, 2);
        assert_eq!(report.allowed_count, 1);
        assert_eq!(report.denied_count, 1);
        assert!(report.chain_valid);
    }

    #[test]
    fn test_memory_backend() {
        let mut backend = MemoryAuditBackend::new();
        
        let entry = AuditEntry {
            id: 1,
            timestamp: 1234567890,
            agent_id: "agent-1".to_string(),
            action: "read".to_string(),
            resource: "/test".to_string(),
            decision: AuditDecision::Allowed,
            hash: "abc123".to_string(),
            prev_hash: "0".repeat(64),
            signature: None,
            metadata: None,
        };

        backend.append(&entry).unwrap();
        assert_eq!(backend.count().unwrap(), 1);

        let loaded = backend.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].agent_id, "agent-1");
    }

    #[test]
    fn test_file_backend() {
        let temp_dir = tempdir().unwrap();
        let mut backend = FileAuditBackend::new(temp_dir.path()).unwrap();

        let entry = AuditEntry {
            id: 1,
            timestamp: 1234567890,
            agent_id: "agent-file-1".to_string(),
            action: "write".to_string(),
            resource: "/tmp/test".to_string(),
            decision: AuditDecision::Denied,
            hash: "def456".to_string(),
            prev_hash: "0".repeat(64),
            signature: None,
            metadata: Some(serde_json::json!({"key": "value"})),
        };

        backend.append(&entry).unwrap();
        backend.flush().unwrap();

        // Reload and verify
        let loaded = backend.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].agent_id, "agent-file-1");
        assert!(loaded[0].metadata.is_some());
    }

    #[test]
    fn test_file_backend_persistence() {
        let temp_dir = tempdir().unwrap();
        let log_path = temp_dir.path().to_path_buf();

        // Write entries with first backend instance
        {
            let mut backend = FileAuditBackend::new(&log_path).unwrap();
            for i in 1..=5 {
                let entry = AuditEntry {
                    id: i,
                    timestamp: 1234567890 + i,
                    agent_id: format!("agent-{}", i),
                    action: "test".to_string(),
                    resource: "/test".to_string(),
                    decision: AuditDecision::Allowed,
                    hash: format!("hash-{}", i),
                    prev_hash: if i == 1 {
                        "0".repeat(64)
                    } else {
                        format!("hash-{}", i - 1)
                    },
                    signature: None,
                    metadata: None,
                };
                backend.append(&entry).unwrap();
            }
            backend.flush().unwrap();
        }

        // Read with new backend instance (simulating restart)
        {
            let backend = FileAuditBackend::new(&log_path).unwrap();
            let loaded = backend.load_all().unwrap();
            assert_eq!(loaded.len(), 5);
            assert_eq!(backend.count().unwrap(), 5);
        }
    }

    #[test]
    fn test_logger_with_file_backend() {
        let temp_dir = tempdir().unwrap();
        let backend = FileAuditBackend::new(temp_dir.path()).unwrap();
        let mut logger = AuditLogger::with_backend(Box::new(backend)).unwrap();

        logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/data/b.txt", AuditDecision::Denied);
        logger.flush().unwrap();

        assert_eq!(logger.entries().len(), 2);
        assert!(logger.verify_chain().is_ok());
    }

    #[test]
    fn test_entries_by_agent() {
        let mut logger = AuditLogger::new();
        logger.log("agent-1", "read", "/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/b.txt", AuditDecision::Allowed);
        logger.log("agent-1", "delete", "/c.txt", AuditDecision::Denied);

        let agent1_entries = logger.get_entries_by_agent("agent-1");
        assert_eq!(agent1_entries.len(), 2);
    }

    #[test]
    fn test_log_with_metadata() {
        let mut logger = AuditLogger::new();
        let metadata = serde_json::json!({
            "ip_address": "192.168.1.1",
            "request_id": "req-123"
        });

        logger.log_with_metadata(
            "agent-1",
            "api_call",
            "/api/v1/users",
            AuditDecision::Allowed,
            Some(metadata.clone()),
        );

        let entry = &logger.entries()[0];
        assert!(entry.metadata.is_some());
        assert_eq!(entry.metadata.as_ref().unwrap()["ip_address"], "192.168.1.1");
    }
}
