use crate::audit::error::AuditError;
use crate::audit::types::AuditEntry;

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
