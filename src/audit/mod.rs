//! Cryptographic Audit Logging Module
//!
//! Provides tamper-evident, hash-chained audit logging for agent actions.
//! Supports pluggable backends for persistent storage (Issue #3).
//!
//! # Features
//! - Hash-chained audit entries for tamper detection
//! - Pluggable storage backends (memory, file, database)
//! - Ed25519 signing for non-repudiation (Issue #51)
//! - Chain verification and integrity checks
//! - SQLite backend for queryable storage (Issue #4)
//! - S3 backend for cloud archival
//! - Multi-region S3 replication for disaster recovery
//! - Real-time streaming for live monitoring
//! - Flight recorder for shadow mode (#43)
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

pub mod flight_recorder;
pub mod graphql;
pub mod multi_region;
pub mod otel;
pub mod replay;
pub mod s3_backend;
pub mod streaming;

// New modules
pub mod backend;
pub mod error;
pub mod file;
pub mod logger;
pub mod memory;
pub mod signing;
pub mod sqlite;
pub mod types;

// Re-export core types
pub use backend::AuditBackend;
pub use error::{AuditError, AuditVerificationError};
pub use file::FileAuditBackend;
pub use logger::AuditLogger;
pub use memory::MemoryAuditBackend;
pub use signing::AuditSigner;
pub use sqlite::SqliteAuditBackend;
pub use types::{AuditDecision, AuditEntry, AuditReport};

// Re-export GraphQL/Query API types (OBS-004)
pub use graphql::{
    AuditLogEntry as GqlAuditLogEntry, AuditQueryEngine, AuditStats as GqlAuditStats,
    ChainVerificationResult as GqlChainVerificationResult, PolicyDecisionEntry,
    PolicyDecisionResult, QueryError, QueryRequest, QueryResponse, QueryResult, SortOrder,
};

// Re-export cryptographic replay types (OBS-002)
pub use replay::{
    ActiveReplay, LogMetadata, ReplayConfig, ReplayError, ReplayReport, ReplayResult,
    ReplaySession, ReplayStep, ReplayVerifier, ReplayedResult, StepComparison,
};

// Re-export OpenTelemetry tracing types (OBS-001)
pub use otel::{
    traced_operation, AttributeValue, OtlpExporter, Span as OtelSpan,
    SpanContext as OtelSpanContext, SpanEvent, SpanKind, SpanLink, SpanStatus, TraceContext,
    TracerStats, TracingConfig, TracingError, TracingResult, VakTracer,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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

    /// Iterate over all entries (streaming)
    fn for_each_entry(
        &self,
        f: &mut dyn FnMut(&AuditEntry) -> Result<(), AuditError>,
    ) -> Result<(), AuditError>;

    /// Get entry by ID
    fn get_entry(&self, id: u64) -> Result<Option<AuditEntry>, AuditError>;
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

    fn for_each_entry(
        &self,
        f: &mut dyn FnMut(&AuditEntry) -> Result<(), AuditError>,
    ) -> Result<(), AuditError> {
        for entry in &self.entries {
            f(entry)?;
        }
        Ok(())
    }

    fn get_entry(&self, id: u64) -> Result<Option<AuditEntry>, AuditError> {
        Ok(self.entries.iter().find(|e| e.id == id).cloned())
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
        self.file_handle
            .as_mut()
            .ok_or_else(|| AuditError::BackendNotAvailable("File handle failed to initialize".to_string()))
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

    fn for_each_entry(
        &self,
        f: &mut dyn FnMut(&AuditEntry) -> Result<(), AuditError>,
    ) -> Result<(), AuditError> {
        if !self.current_file.exists() {
            return Ok(());
        }

        let file = File::open(&self.current_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            f(&entry)?;
        }
        Ok(())
    }

    fn get_entry(&self, id: u64) -> Result<Option<AuditEntry>, AuditError> {
        if !self.current_file.exists() {
            return Ok(None);
        }

        let file = File::open(&self.current_file)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            // Optimization: check ID string before parsing? Maybe unsafe if format changes.
            // Just parse for correctness.
            let entry: AuditEntry = serde_json::from_str(&line)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            if entry.id == id {
                return Ok(Some(entry));
            }
        }
        Ok(None)
    }
}

// ============================================================================
// SQLite Backend (Issue #4 - Queryable Persistent Storage)
// ============================================================================

/// SQLite-based audit backend with full queryability
///
/// Provides persistent, queryable storage for audit logs with:
/// - ACID transactions
/// - Efficient queries by agent, time range, action, decision
/// - Automatic schema migrations
/// - Index optimization for common queries
#[derive(Debug)]
pub struct SqliteAuditBackend {
    /// SQLite connection (wrapped in Mutex for thread safety)
    conn: Mutex<Connection>,
    /// Cached entry count
    entry_count: u64,
}

impl SqliteAuditBackend {
    /// SQL schema for audit_logs table
    const SCHEMA: &'static str = r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            decision TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            prev_hash TEXT NOT NULL,
            signature TEXT,
            metadata TEXT
        );
        
        CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_logs(agent_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
        CREATE INDEX IF NOT EXISTS idx_audit_hash ON audit_logs(hash);
    "#;

    /// Create a new SQLite backend at the given path
    ///
    /// # Arguments
    /// * `db_path` - Path to the SQLite database file
    ///
    /// # Returns
    /// * New backend instance or error if database cannot be opened
    pub fn new(db_path: impl AsRef<Path>) -> Result<Self, AuditError> {
        let db_path = db_path.as_ref();

        // Create parent directory if needed
        if let Some(parent) = db_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(db_path)
            .map_err(|e| AuditError::BackendNotAvailable(format!("SQLite: {}", e)))?;

        // Initialize schema
        conn.execute_batch(Self::SCHEMA)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Schema init: {}", e)))?;

        // Get entry count
        let entry_count: u64 = conn
            .query_row("SELECT COUNT(*) FROM audit_logs", [], |row| row.get(0))
            .map_err(|e| AuditError::BackendNotAvailable(format!("Count query: {}", e)))?;

        Ok(Self {
            conn: Mutex::new(conn),
            entry_count,
        })
    }

    /// Create an in-memory SQLite backend (for testing)
    pub fn in_memory() -> Result<Self, AuditError> {
        let conn = Connection::open_in_memory()
            .map_err(|e| AuditError::BackendNotAvailable(format!("SQLite in-memory: {}", e)))?;

        conn.execute_batch(Self::SCHEMA)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Schema init: {}", e)))?;

        Ok(Self {
            conn: Mutex::new(conn),
            entry_count: 0,
        })
    }

    /// Get entries by action type
    pub fn get_by_action(&self, action: &str) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs WHERE action = ? ORDER BY id")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let entries = stmt
            .query_map(params![action], Self::row_to_entry)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Row mapping: {}", e)))?;

        Ok(entries)
    }

    /// Get entries by decision type
    pub fn get_by_decision(&self, decision: &AuditDecision) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let decision_str = decision.to_string();
        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs WHERE decision = ? ORDER BY id")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let entries = stmt
            .query_map(params![decision_str], Self::row_to_entry)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Row mapping: {}", e)))?;

        Ok(entries)
    }

    /// Helper to convert a database row to an AuditEntry
    fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
        let decision_str: String = row.get(5)?;
        let decision = match decision_str.as_str() {
            "ALLOWED" => AuditDecision::Allowed,
            "DENIED" => AuditDecision::Denied,
            s if s.starts_with("ERROR: ") => AuditDecision::Error(s[7..].to_string()),
            _ => AuditDecision::Error(format!("Unknown decision: {}", decision_str)),
        };

        let metadata_str: Option<String> = row.get(9)?;
        let metadata = metadata_str.and_then(|s| serde_json::from_str(&s).ok());

        Ok(AuditEntry {
            id: row.get(0)?,
            timestamp: row.get(1)?,
            agent_id: row.get(2)?,
            action: row.get(3)?,
            resource: row.get(4)?,
            decision,
            hash: row.get(6)?,
            prev_hash: row.get(7)?,
            signature: row.get(8)?,
            metadata,
        })
    }
}

impl AuditBackend for SqliteAuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let metadata_str = entry
            .metadata
            .as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_default());

        conn.execute(
            "INSERT INTO audit_logs (id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                entry.id,
                entry.timestamp,
                entry.agent_id,
                entry.action,
                entry.resource,
                entry.decision.to_string(),
                entry.hash,
                entry.prev_hash,
                entry.signature,
                metadata_str,
            ],
        ).map_err(|e| AuditError::BackendNotAvailable(format!("Insert: {}", e)))?;

        self.entry_count += 1;
        Ok(())
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs ORDER BY id")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let entries = stmt
            .query_map([], Self::row_to_entry)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Row mapping: {}", e)))?;

        Ok(entries)
    }

    fn get_last(&self) -> Result<Option<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs ORDER BY id DESC LIMIT 1")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let mut rows = stmt
            .query([])
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?;

        match rows
            .next()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Row fetch: {}", e)))?
        {
            Some(row) => Ok(Some(Self::row_to_entry(row).map_err(|e| {
                AuditError::BackendNotAvailable(format!("Row mapping: {}", e))
            })?)),
            None => Ok(None),
        }
    }

    fn count(&self) -> Result<u64, AuditError> {
        Ok(self.entry_count)
    }

    fn flush(&mut self) -> Result<(), AuditError> {
        // SQLite auto-commits, but we can force a checkpoint for WAL mode
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Checkpoint: {}", e)))?;

        Ok(())
    }

    fn get_by_agent(&self, agent_id: &str) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs WHERE agent_id = ? ORDER BY id")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let entries = stmt
            .query_map(params![agent_id], Self::row_to_entry)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Row mapping: {}", e)))?;

        Ok(entries)
    }

    fn get_by_time_range(&self, start: u64, end: u64) -> Result<Vec<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs WHERE timestamp >= ? AND timestamp <= ? ORDER BY id")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let entries = stmt
            .query_map(params![start, end], Self::row_to_entry)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Row mapping: {}", e)))?;

        Ok(entries)
    }

    fn for_each_entry(
        &self,
        f: &mut dyn FnMut(&AuditEntry) -> Result<(), AuditError>,
    ) -> Result<(), AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs ORDER BY id")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let rows = stmt
            .query_map([], Self::row_to_entry)
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?;

        for row in rows {
            let entry = row.map_err(|e| AuditError::BackendNotAvailable(format!("Row mapping: {}", e)))?;
            f(&entry)?;
        }
        Ok(())
    }

    fn get_entry(&self, id: u64) -> Result<Option<AuditEntry>, AuditError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut stmt = conn
            .prepare("SELECT id, timestamp, agent_id, action, resource, decision, hash, prev_hash, signature, metadata FROM audit_logs WHERE id = ?")
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query prepare: {}", e)))?;

        let mut rows = stmt
            .query(params![id])
            .map_err(|e| AuditError::BackendNotAvailable(format!("Query: {}", e)))?;

        match rows.next().map_err(|e| AuditError::BackendNotAvailable(format!("Row fetch: {}", e)))? {
            Some(row) => Ok(Some(Self::row_to_entry(row).map_err(|e| AuditError::BackendNotAvailable(format!("Row mapping: {}", e)))?)),
            None => Ok(None),
        }
    }
}

// ============================================================================
// Ed25519 Signing Support (Issue #51 - Non-repudiation)
// ============================================================================

/// Signing key manager for audit entry signatures
///
/// Provides ed25519 signing for audit entries to ensure non-repudiation.
/// Each kernel instance can have its own signing key.
#[derive(Debug)]
pub struct AuditSigner {
    /// Ed25519 signing key
    signing_key: SigningKey,
    /// Public key for verification (hex-encoded for storage)
    pub public_key_hex: String,
}

impl AuditSigner {
    /// Create a new signer with a freshly generated key pair
    pub fn new() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());

        Self {
            signing_key,
            public_key_hex,
        }
    }

    /// Create a signer from a hex-encoded private key
    pub fn from_key_bytes(key_bytes: &[u8; 32]) -> Result<Self, AuditError> {
        let signing_key = SigningKey::from_bytes(key_bytes);
        let public_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(public_key.as_bytes());

        Ok(Self {
            signing_key,
            public_key_hex,
        })
    }

    /// Export the private key bytes for secure storage
    pub fn export_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Sign an audit entry hash
    pub fn sign(&self, entry_hash: &str) -> String {
        let signature = self.signing_key.sign(entry_hash.as_bytes());
        hex::encode(signature.to_bytes())
    }

    /// Verify a signature against an entry hash
    pub fn verify(&self, entry_hash: &str, signature_hex: &str) -> Result<bool, AuditError> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| AuditError::SerializationError(format!("Invalid signature hex: {}", e)))?;

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuditError::SerializationError("Signature wrong length".to_string()))?;

        let signature = Signature::from_bytes(&sig_array);

        Ok(self
            .signing_key
            .verifying_key()
            .verify(entry_hash.as_bytes(), &signature)
            .is_ok())
    }

    /// Verify a signature using a public key
    pub fn verify_with_public_key(
        public_key_hex: &str,
        entry_hash: &str,
        signature_hex: &str,
    ) -> Result<bool, AuditError> {
        let pk_bytes = hex::decode(public_key_hex).map_err(|e| {
            AuditError::SerializationError(format!("Invalid public key hex: {}", e))
        })?;

        let pk_array: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| AuditError::SerializationError("Public key wrong length".to_string()))?;

        let verifying_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|e| AuditError::SerializationError(format!("Invalid public key: {}", e)))?;

        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| AuditError::SerializationError(format!("Invalid signature hex: {}", e)))?;

        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| AuditError::SerializationError("Signature wrong length".to_string()))?;

        let signature = Signature::from_bytes(&sig_array);

        Ok(verifying_key
            .verify(entry_hash.as_bytes(), &signature)
            .is_ok())
    }
}

impl Default for AuditSigner {
    fn default() -> Self {
        Self::new()
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
    /// Cache of the last entry for chaining
    last_entry_cache: Option<AuditEntry>,
    /// Next entry ID
    next_id: u64,
    /// Chain is verified
    chain_verified: bool,
    /// Optional signer for ed25519 signatures (Issue #51)
    signer: Option<AuditSigner>,
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger")
            .field("next_id", &self.next_id)
            .field("chain_verified", &self.chain_verified)
            .field("signing_enabled", &self.signer.is_some())
            .finish()
    }
}

impl AuditLogger {
    /// Creates a new audit logger with in-memory backend (default)
    pub fn new() -> Self {
        Self {
            backend: Box::new(MemoryAuditBackend::new()),
            last_entry_cache: None,
            next_id: 1,
            chain_verified: true,
            signer: None,
        }
    }

    /// Creates a new audit logger with signing enabled (Issue #51)
    pub fn new_with_signing() -> Self {
        Self {
            backend: Box::new(MemoryAuditBackend::new()),
            last_entry_cache: None,
            next_id: 1,
            chain_verified: true,
            signer: Some(AuditSigner::new()),
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
        let mut logger = Self {
            backend,
            last_entry_cache: None,
            next_id: 1,
            chain_verified: false,
            signer: None,
        };

        // Verify chain integrity on startup and get last entry
        match logger.verify_chain() {
            Ok(last_entry) => {
                logger.next_id = last_entry.as_ref().map(|e| e.id + 1).unwrap_or(1);
                logger.last_entry_cache = last_entry;
            }
            Err(e) => {
                tracing::error!("Audit chain verification failed on startup: {:?}", e);
                return Err(AuditError::ChainVerificationFailed(format!("{:?}", e)));
            }
        }

        logger.chain_verified = true;
        Ok(logger)
    }

    /// Creates a new audit logger with backend and signing enabled (Issue #51)
    pub fn with_backend_and_signing(backend: Box<dyn AuditBackend>) -> Result<Self, AuditError> {
        let mut logger = Self::with_backend(backend)?;
        logger.signer = Some(AuditSigner::new());
        Ok(logger)
    }

    /// Creates a new audit logger with backend and a specific signer (Issue #51)
    pub fn with_backend_and_signer(
        backend: Box<dyn AuditBackend>,
        signer: AuditSigner,
    ) -> Result<Self, AuditError> {
        let mut logger = Self::with_backend(backend)?;
        logger.signer = Some(signer);
        Ok(logger)
    }

    /// Enable signing with a new key pair
    pub fn enable_signing(&mut self) {
        self.signer = Some(AuditSigner::new());
    }

    /// Enable signing with a specific signer
    pub fn set_signer(&mut self, signer: AuditSigner) {
        self.signer = Some(signer);
    }

    /// Get the public key if signing is enabled
    pub fn public_key(&self) -> Option<&str> {
        self.signer.as_ref().map(|s| s.public_key_hex.as_str())
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
            .last_entry_cache
            .as_ref()
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
            hash: hash.clone(),
            prev_hash,
            signature: self.signer.as_ref().map(|s| s.sign(&hash)), // Sign if signer is available (Issue #51)
            metadata,
        };

        // Persist to backend
        if let Err(e) = self.backend.append(&entry) {
            tracing::error!("Failed to persist audit entry: {:?}", e);
        }

        self.last_entry_cache = Some(entry);
        self.next_id += 1;

        // SAFETY: We just set last_entry_cache to Some(entry)
        #[allow(clippy::unwrap_used)]
        self.last_entry_cache.as_ref().unwrap()
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
    pub fn get_entries_by_agent(&self, agent_id: &str) -> Result<Vec<AuditEntry>, AuditError> {
        self.backend.get_by_agent(agent_id)
    }

    /// Verifies the integrity of the entire audit chain and returns the last entry
    pub fn verify_chain(&self) -> Result<Option<AuditEntry>, AuditVerificationError> {
        let mut prev_hash = "0".repeat(64);
        let mut last_entry: Option<AuditEntry> = None;

        let mut verify_fn = |entry: &AuditEntry| -> Result<(), AuditError> {
            if entry.prev_hash != prev_hash {
                return Err(AuditError::ChainVerificationFailed(format!(
                    "Broken chain at entry {}: expected prev_hash {}, found {}",
                    entry.id, prev_hash, entry.prev_hash
                )));
            }

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
                return Err(AuditError::ChainVerificationFailed(format!(
                    "Invalid hash at entry {}: expected {}, found {}",
                    entry.id, computed_hash, entry.hash
                )));
            }

            prev_hash = entry.hash.clone();
            last_entry = Some(entry.clone());
            Ok(())
        };

        self.backend
            .for_each_entry(&mut verify_fn)
            .map_err(|e| match e {
                AuditError::ChainVerificationFailed(msg) => {
                    AuditVerificationError::BrokenChain {
                        entry_id: 0,
                        expected: String::new(),
                        found: msg,
                    }
                }
                e => AuditVerificationError::BrokenChain {
                    entry_id: 0,
                    expected: String::new(),
                    found: format!("Backend error: {:?}", e),
                },
            })?;

        Ok(last_entry)
    }

    /// Verify all signatures in the chain (Issue #51)
    ///
    /// Requires the public key that was used for signing
    pub fn verify_signatures(&self, public_key_hex: &str) -> Result<(), AuditVerificationError> {
        let mut verify_fn = |entry: &AuditEntry| -> Result<(), AuditError> {
            if let Some(ref signature) = entry.signature {
                match AuditSigner::verify_with_public_key(public_key_hex, &entry.hash, signature) {
                    Ok(true) => Ok(()),
                    Ok(false) => Err(AuditError::ChainVerificationFailed(format!(
                        "Signature verification failed for entry {}",
                        entry.id
                    ))),
                    Err(e) => Err(AuditError::ChainVerificationFailed(format!(
                        "Signature verification error for entry {}: {:?}",
                        entry.id, e
                    ))),
                }
            } else {
                Ok(())
            }
        };

        self.backend
            .for_each_entry(&mut verify_fn)
            .map_err(|e| match e {
                AuditError::ChainVerificationFailed(msg) => {
                    AuditVerificationError::InvalidSignature {
                        entry_id: 0,
                        reason: msg,
                    }
                }
                e => AuditVerificationError::InvalidSignature {
                    entry_id: 0,
                    reason: format!("Backend error: {:?}", e),
                },
            })
    }

    /// Verify both chain integrity and signatures
    pub fn verify_all(&self, public_key_hex: Option<&str>) -> Result<(), AuditVerificationError> {
        self.verify_chain()?;
        if let Some(pk) = public_key_hex {
            self.verify_signatures(pk)?;
        }
        Ok(())
    }

    /// Exports audit log for compliance reporting
    pub fn export(&self) -> Result<AuditReport, AuditError> {
        let entries = self.backend.load_all()?;
        let total_entries = entries.len();
        let allowed_count = entries
            .iter()
            .filter(|e| e.decision == AuditDecision::Allowed)
            .count();
        let denied_count = entries
            .iter()
            .filter(|e| e.decision == AuditDecision::Denied)
            .count();
        let error_count = entries
            .iter()
            .filter(|e| matches!(e.decision, AuditDecision::Error(_)))
            .count();

        let chain_valid = self.verify_chain().is_ok();

        let first_timestamp = entries.first().map(|e| e.timestamp);
        let last_timestamp = entries.last().map(|e| e.timestamp);

        Ok(AuditReport {
            total_entries,
            allowed_count,
            denied_count,
            error_count,
            chain_valid,
            first_timestamp,
            last_timestamp,
            entries,
        })
    }

    /// Returns all entries
    /// Warning: This loads all entries into memory.
    pub fn load_all_entries(&self) -> Result<Vec<AuditEntry>, AuditError> {
        self.backend.load_all()
    }

    /// Get a specific entry by ID
    pub fn get_entry(&self, id: u64) -> Result<Option<AuditEntry>, AuditError> {
        self.backend.get_entry(id)
    }

    /// Get the last entry
    pub fn last_entry(&self) -> Option<&AuditEntry> {
        self.last_entry_cache.as_ref()
    }

    /// Get total entry count
    pub fn count(&self) -> Result<u64, AuditError> {
        self.backend.count()
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
    /// Signature verification failed (Issue #51)
    InvalidSignature {
        /// ID of the entry with invalid signature
        entry_id: u64,
        /// Reason for failure
        reason: String,
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
            Self::InvalidSignature { entry_id, reason } => {
                write!(f, "Invalid signature at entry {}: {}", entry_id, reason)
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

        assert_eq!(logger.count().unwrap(), 1);
        assert_eq!(
            logger.load_all_entries().unwrap()[0].agent_id,
            "agent-1"
        );
    }

    #[test]
    fn test_hash_chain_integrity() {
        let mut logger = AuditLogger::new();
        logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/data/b.txt", AuditDecision::Denied);
        logger.log("agent-1", "delete", "/data/c.txt", AuditDecision::Allowed);

        assert!(logger.verify_chain().is_ok());

        // Verify chain linkage
        let entries = logger.load_all_entries().unwrap();
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(entries[2].prev_hash, entries[1].hash);
    }

    #[test]
    fn test_export_report() {
        let mut logger = AuditLogger::new();
        logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/data/b.txt", AuditDecision::Denied);

        let report = logger.export().unwrap();

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

        assert_eq!(logger.count().unwrap(), 2);
        assert!(logger.verify_chain().is_ok());
    }

    #[test]
    fn test_entries_by_agent() {
        let mut logger = AuditLogger::new();
        logger.log("agent-1", "read", "/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/b.txt", AuditDecision::Allowed);
        logger.log("agent-1", "delete", "/c.txt", AuditDecision::Denied);

        let agent1_entries = logger.get_entries_by_agent("agent-1").unwrap();
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

        let entries = logger.load_all_entries().unwrap();
        let entry = &entries[0];
        assert!(entry.metadata.is_some());
        assert_eq!(
            entry.metadata.as_ref().unwrap()["ip_address"],
            "192.168.1.1"
        );
    }

    // ========================================================================
    // SQLite Backend Tests (Issue #4)
    // ========================================================================

    #[test]
    fn test_sqlite_backend_in_memory() {
        let mut backend = SqliteAuditBackend::in_memory().unwrap();

        let entry = AuditEntry {
            id: 1,
            timestamp: 1234567890,
            agent_id: "agent-sql-1".to_string(),
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
        assert_eq!(loaded[0].agent_id, "agent-sql-1");
    }

    #[test]
    fn test_sqlite_backend_persistence() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("audit.db");

        // Write entries
        {
            let mut backend = SqliteAuditBackend::new(&db_path).unwrap();
            for i in 1..=5 {
                let entry = AuditEntry {
                    id: i,
                    timestamp: 1234567890 + i,
                    agent_id: format!("agent-{}", i),
                    action: "test".to_string(),
                    resource: "/test".to_string(),
                    decision: if i % 2 == 0 {
                        AuditDecision::Denied
                    } else {
                        AuditDecision::Allowed
                    },
                    hash: format!("hash-{}", i),
                    prev_hash: if i == 1 {
                        "0".repeat(64)
                    } else {
                        format!("hash-{}", i - 1)
                    },
                    signature: None,
                    metadata: Some(serde_json::json!({"index": i})),
                };
                backend.append(&entry).unwrap();
            }
            backend.flush().unwrap();
        }

        // Read with new instance
        {
            let backend = SqliteAuditBackend::new(&db_path).unwrap();
            let loaded = backend.load_all().unwrap();
            assert_eq!(loaded.len(), 5);
            assert_eq!(backend.count().unwrap(), 5);

            // Test filtering
            let by_agent = backend.get_by_agent("agent-3").unwrap();
            assert_eq!(by_agent.len(), 1);

            let denied = backend.get_by_decision(&AuditDecision::Denied).unwrap();
            assert_eq!(denied.len(), 2); // entries 2 and 4
        }
    }

    #[test]
    fn test_sqlite_backend_queries() {
        let mut backend = SqliteAuditBackend::in_memory().unwrap();

        // Add various entries
        for i in 1..=10 {
            let entry = AuditEntry {
                id: i,
                timestamp: 1000 + i,
                agent_id: if i <= 5 { "agent-a" } else { "agent-b" }.to_string(),
                action: if i % 3 == 0 { "write" } else { "read" }.to_string(),
                resource: format!("/file-{}", i),
                decision: AuditDecision::Allowed,
                hash: format!("h{}", i),
                prev_hash: if i == 1 {
                    "0".repeat(64)
                } else {
                    format!("h{}", i - 1)
                },
                signature: None,
                metadata: None,
            };
            backend.append(&entry).unwrap();
        }

        // Test get_by_agent
        assert_eq!(backend.get_by_agent("agent-a").unwrap().len(), 5);
        assert_eq!(backend.get_by_agent("agent-b").unwrap().len(), 5);

        // Test get_by_action
        assert_eq!(backend.get_by_action("write").unwrap().len(), 3); // entries 3, 6, 9

        // Test get_by_time_range
        assert_eq!(backend.get_by_time_range(1003, 1007).unwrap().len(), 5);

        // Test get_last
        let last = backend.get_last().unwrap().unwrap();
        assert_eq!(last.id, 10);
    }

    // ========================================================================
    // Ed25519 Signing Tests (Issue #51)
    // ========================================================================

    #[test]
    fn test_signer_creation() {
        let signer = AuditSigner::new();
        assert!(!signer.public_key_hex.is_empty());
        assert_eq!(signer.public_key_hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_signer_sign_and_verify() {
        let signer = AuditSigner::new();
        let hash = "abc123def456";

        let signature = signer.sign(hash);
        assert!(!signature.is_empty());
        assert_eq!(signature.len(), 128); // 64 bytes = 128 hex chars

        // Verify with the same signer
        assert!(signer.verify(hash, &signature).unwrap());

        // Verify fails with different message
        assert!(!signer.verify("different_hash", &signature).unwrap());
    }

    #[test]
    fn test_signer_key_export_import() {
        let signer1 = AuditSigner::new();
        let key_bytes = signer1.export_key_bytes();

        let signer2 = AuditSigner::from_key_bytes(&key_bytes).unwrap();

        // Both should have same public key
        assert_eq!(signer1.public_key_hex, signer2.public_key_hex);

        // Sign with signer1, verify with signer2
        let hash = "test_hash";
        let signature = signer1.sign(hash);
        assert!(signer2.verify(hash, &signature).unwrap());
    }

    #[test]
    fn test_verify_with_public_key() {
        let signer = AuditSigner::new();
        let hash = "some_audit_hash";
        let signature = signer.sign(hash);

        // Verify using static method with public key
        let result =
            AuditSigner::verify_with_public_key(&signer.public_key_hex, hash, &signature).unwrap();
        assert!(result);
    }

    #[test]
    fn test_logger_with_signing() {
        let mut logger = AuditLogger::new_with_signing();

        logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/data/b.txt", AuditDecision::Denied);

        // All entries should have signatures
        for entry in logger.load_all_entries().unwrap() {
            assert!(entry.signature.is_some());
        }

        // Verify signatures
        let pk = logger.public_key().unwrap().to_string();
        assert!(logger.verify_signatures(&pk).is_ok());
    }

    #[test]
    fn test_logger_verify_all() {
        let mut logger = AuditLogger::new_with_signing();

        logger.log("agent-1", "action1", "/res1", AuditDecision::Allowed);
        logger.log("agent-1", "action2", "/res2", AuditDecision::Denied);
        logger.log("agent-2", "action3", "/res3", AuditDecision::Allowed);

        let pk = logger.public_key().unwrap().to_string();

        // Verify both chain and signatures
        assert!(logger.verify_all(Some(&pk)).is_ok());

        // Also verify with just chain
        assert!(logger.verify_all(None).is_ok());
    }

    #[test]
    fn test_sqlite_backend_with_signatures() {
        let mut backend = SqliteAuditBackend::in_memory().unwrap();
        let signer = AuditSigner::new();

        let hash = "test_hash_123";
        let signature = signer.sign(hash);

        let entry = AuditEntry {
            id: 1,
            timestamp: 1234567890,
            agent_id: "agent-1".to_string(),
            action: "read".to_string(),
            resource: "/test".to_string(),
            decision: AuditDecision::Allowed,
            hash: hash.to_string(),
            prev_hash: "0".repeat(64),
            signature: Some(signature.clone()),
            metadata: None,
        };

        backend.append(&entry).unwrap();

        let loaded = backend.load_all().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].signature, Some(signature));

        // Verify signature from loaded entry
        let result = AuditSigner::verify_with_public_key(
            &signer.public_key_hex,
            &loaded[0].hash,
            loaded[0].signature.as_ref().unwrap(),
        )
        .unwrap();
        assert!(result);
    }
}
