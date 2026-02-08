use std::fs;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};

use crate::audit::backend::AuditBackend;
use crate::audit::error::AuditError;
use crate::audit::types::{AuditDecision, AuditEntry};

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
}

#[cfg(test)]
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::audit::signing::AuditSigner;

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
