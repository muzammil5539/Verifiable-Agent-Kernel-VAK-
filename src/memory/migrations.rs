//! Database Migration System (Issue #4 Extended)
//!
//! Provides migration scripts for persistent data including:
//! - Policies table and schema
//! - Agent sessions table
//! - Memory snapshots table
//!
//! # Migration Versioning
//!
//! Each migration has a version number and can be applied/rolled back.
//! The system tracks applied migrations in a `schema_migrations` table.
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::memory::migrations::{MigrationRunner, Migration};
//! use rusqlite::Connection;
//!
//! let conn = Connection::open("vak.db").unwrap();
//! let runner = MigrationRunner::new(&conn).unwrap();
//! runner.run_all().unwrap();
//! ```

use rusqlite::{params, Connection};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during migrations
#[derive(Debug, Error)]
pub enum MigrationError {
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Migration already applied
    #[error("Migration {0} already applied")]
    AlreadyApplied(u32),

    /// Migration not found
    #[error("Migration {0} not found")]
    NotFound(u32),

    /// Migration failed
    #[error("Migration {0} failed: {1}")]
    MigrationFailed(u32, String),

    /// Rollback failed
    #[error("Rollback of migration {0} failed: {1}")]
    RollbackFailed(u32, String),

    /// Schema version mismatch
    #[error("Schema version mismatch: expected {expected}, found {found}")]
    VersionMismatch {
        /// Expected schema version
        expected: u32,
        /// Actual schema version found
        found: u32,
    },
}

impl From<rusqlite::Error> for MigrationError {
    fn from(e: rusqlite::Error) -> Self {
        MigrationError::DatabaseError(e.to_string())
    }
}

// ============================================================================
// Migration Types
// ============================================================================

/// A database migration
#[derive(Debug, Clone)]
pub struct Migration {
    /// Migration version number
    pub version: u32,
    /// Migration name
    pub name: String,
    /// SQL to apply the migration
    pub up_sql: String,
    /// SQL to rollback the migration
    pub down_sql: String,
    /// Description of what this migration does
    pub description: String,
}

impl Migration {
    /// Create a new migration
    pub fn new(
        version: u32,
        name: impl Into<String>,
        up_sql: impl Into<String>,
        down_sql: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            version,
            name: name.into(),
            up_sql: up_sql.into(),
            down_sql: down_sql.into(),
            description: description.into(),
        }
    }
}

/// Status of a migration
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationStatus {
    /// Migration has not been applied
    Pending,
    /// Migration has been applied
    Applied,
    /// Migration failed
    Failed(String),
}

/// Record of an applied migration
#[derive(Debug, Clone)]
pub struct MigrationRecord {
    /// Migration version
    pub version: u32,
    /// Migration name
    pub name: String,
    /// Timestamp when applied (Unix timestamp)
    pub applied_at: i64,
    /// Checksum of the migration SQL
    pub checksum: String,
}

// ============================================================================
// Migration Registry
// ============================================================================

/// Get all available migrations
pub fn get_all_migrations() -> Vec<Migration> {
    vec![
        // Migration 001: Schema migrations table
        Migration::new(
            1,
            "create_schema_migrations",
            r#"
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at INTEGER NOT NULL,
                    checksum TEXT NOT NULL
                );
            "#,
            r#"
                DROP TABLE IF EXISTS schema_migrations;
            "#,
            "Create schema migrations tracking table",
        ),
        // Migration 002: Policies table
        Migration::new(
            2,
            "create_policies_table",
            r#"
                CREATE TABLE IF NOT EXISTS policies (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    effect TEXT NOT NULL CHECK (effect IN ('allow', 'deny')),
                    resource_pattern TEXT NOT NULL,
                    action_pattern TEXT NOT NULL,
                    conditions TEXT,  -- JSON-encoded conditions
                    priority INTEGER DEFAULT 0,
                    description TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    version INTEGER DEFAULT 1
                );
                
                CREATE INDEX IF NOT EXISTS idx_policies_effect ON policies(effect);
                CREATE INDEX IF NOT EXISTS idx_policies_resource ON policies(resource_pattern);
                CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
                CREATE INDEX IF NOT EXISTS idx_policies_priority ON policies(priority DESC);
            "#,
            r#"
                DROP INDEX IF EXISTS idx_policies_priority;
                DROP INDEX IF EXISTS idx_policies_enabled;
                DROP INDEX IF EXISTS idx_policies_resource;
                DROP INDEX IF EXISTS idx_policies_effect;
                DROP TABLE IF EXISTS policies;
            "#,
            "Create policies table with ABAC support",
        ),
        // Migration 003: Agent sessions table
        Migration::new(
            3,
            "create_agent_sessions_table",
            r#"
                CREATE TABLE IF NOT EXISTS agent_sessions (
                    session_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    agent_type TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'terminated')),
                    created_at INTEGER NOT NULL,
                    last_activity INTEGER NOT NULL,
                    terminated_at INTEGER,
                    metadata TEXT,  -- JSON-encoded metadata
                    parent_session_id TEXT,
                    FOREIGN KEY (parent_session_id) REFERENCES agent_sessions(session_id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_sessions_agent_id ON agent_sessions(agent_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_status ON agent_sessions(status);
                CREATE INDEX IF NOT EXISTS idx_sessions_created ON agent_sessions(created_at);
                CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON agent_sessions(last_activity);
            "#,
            r#"
                DROP INDEX IF EXISTS idx_sessions_last_activity;
                DROP INDEX IF EXISTS idx_sessions_created;
                DROP INDEX IF EXISTS idx_sessions_status;
                DROP INDEX IF EXISTS idx_sessions_agent_id;
                DROP TABLE IF EXISTS agent_sessions;
            "#,
            "Create agent sessions table for tracking agent lifecycle",
        ),
        // Migration 004: Memory snapshots table
        Migration::new(
            4,
            "create_memory_snapshots_table",
            r#"
                CREATE TABLE IF NOT EXISTS memory_snapshots (
                    snapshot_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    session_id TEXT,
                    parent_snapshot_id TEXT,
                    merkle_root TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    description TEXT,
                    data BLOB NOT NULL,  -- Compressed/serialized state
                    data_size INTEGER NOT NULL,
                    metadata TEXT,  -- JSON-encoded metadata
                    FOREIGN KEY (session_id) REFERENCES agent_sessions(session_id),
                    FOREIGN KEY (parent_snapshot_id) REFERENCES memory_snapshots(snapshot_id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_snapshots_agent ON memory_snapshots(agent_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_snapshots_session ON memory_snapshots(session_id);
                CREATE INDEX IF NOT EXISTS idx_snapshots_merkle ON memory_snapshots(merkle_root);
                CREATE INDEX IF NOT EXISTS idx_snapshots_parent ON memory_snapshots(parent_snapshot_id);
            "#,
            r#"
                DROP INDEX IF EXISTS idx_snapshots_parent;
                DROP INDEX IF EXISTS idx_snapshots_merkle;
                DROP INDEX IF EXISTS idx_snapshots_session;
                DROP INDEX IF EXISTS idx_snapshots_agent;
                DROP TABLE IF EXISTS memory_snapshots;
            "#,
            "Create memory snapshots table with Merkle DAG support",
        ),
        // Migration 005: Policy audit log extension
        Migration::new(
            5,
            "extend_audit_logs_for_policies",
            r#"
                -- Add policy-specific columns to audit_logs if they don't exist
                -- Note: SQLite doesn't support IF NOT EXISTS for ALTER TABLE ADD COLUMN
                -- so we use a workaround with a new table
                
                CREATE TABLE IF NOT EXISTS policy_evaluations (
                    id INTEGER PRIMARY KEY,
                    audit_entry_id INTEGER,
                    policy_id TEXT NOT NULL,
                    policy_version INTEGER,
                    evaluation_time_ms INTEGER NOT NULL,
                    conditions_checked INTEGER NOT NULL,
                    matched BOOLEAN NOT NULL,
                    cached BOOLEAN DEFAULT 0,
                    rate_limited BOOLEAN DEFAULT 0,
                    context TEXT,  -- JSON-encoded evaluation context
                    FOREIGN KEY (audit_entry_id) REFERENCES audit_logs(id)
                );
                
                CREATE INDEX IF NOT EXISTS idx_policy_eval_policy ON policy_evaluations(policy_id);
                CREATE INDEX IF NOT EXISTS idx_policy_eval_audit ON policy_evaluations(audit_entry_id);
            "#,
            r#"
                DROP INDEX IF EXISTS idx_policy_eval_audit;
                DROP INDEX IF EXISTS idx_policy_eval_policy;
                DROP TABLE IF EXISTS policy_evaluations;
            "#,
            "Add policy evaluation tracking table",
        ),
        // Migration 006: Working memory cache table
        Migration::new(
            6,
            "create_working_memory_cache",
            r#"
                CREATE TABLE IF NOT EXISTS working_memory_cache (
                    cache_key TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    token_count INTEGER NOT NULL,
                    importance_score REAL DEFAULT 0.5,
                    created_at INTEGER NOT NULL,
                    accessed_at INTEGER NOT NULL,
                    access_count INTEGER DEFAULT 1,
                    expires_at INTEGER,
                    metadata TEXT
                );
                
                CREATE INDEX IF NOT EXISTS idx_wm_cache_agent ON working_memory_cache(agent_id);
                CREATE INDEX IF NOT EXISTS idx_wm_cache_expires ON working_memory_cache(expires_at);
                CREATE INDEX IF NOT EXISTS idx_wm_cache_importance ON working_memory_cache(importance_score DESC);
            "#,
            r#"
                DROP INDEX IF EXISTS idx_wm_cache_importance;
                DROP INDEX IF EXISTS idx_wm_cache_expires;
                DROP INDEX IF EXISTS idx_wm_cache_agent;
                DROP TABLE IF EXISTS working_memory_cache;
            "#,
            "Create working memory cache table",
        ),
        // Migration 007: Skill registry table
        Migration::new(
            7,
            "create_skill_registry_table",
            r#"
                CREATE TABLE IF NOT EXISTS skill_registry (
                    skill_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    description TEXT,
                    wasm_hash TEXT NOT NULL,  -- SHA-256 hash of WASM binary
                    signature TEXT,  -- Ed25519 signature
                    signer_public_key TEXT,
                    manifest TEXT NOT NULL,  -- JSON-encoded manifest
                    enabled BOOLEAN DEFAULT 1,
                    registered_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    execution_count INTEGER DEFAULT 0,
                    last_executed_at INTEGER
                );
                
                CREATE INDEX IF NOT EXISTS idx_skills_name ON skill_registry(name);
                CREATE INDEX IF NOT EXISTS idx_skills_enabled ON skill_registry(enabled);
                CREATE INDEX IF NOT EXISTS idx_skills_hash ON skill_registry(wasm_hash);
            "#,
            r#"
                DROP INDEX IF EXISTS idx_skills_hash;
                DROP INDEX IF EXISTS idx_skills_enabled;
                DROP INDEX IF EXISTS idx_skills_name;
                DROP TABLE IF EXISTS skill_registry;
            "#,
            "Create skill registry table for WASM skill tracking",
        ),
        // Migration 008: Flight recorder events table
        Migration::new(
            8,
            "create_flight_recorder_table",
            r#"
                CREATE TABLE IF NOT EXISTS flight_recorder_events (
                    event_id INTEGER PRIMARY KEY,
                    trace_id TEXT NOT NULL,
                    span_id TEXT,
                    parent_span_id TEXT,
                    timestamp INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    agent_id TEXT NOT NULL,
                    session_id TEXT,
                    action TEXT,
                    resource TEXT,
                    input TEXT,  -- JSON-encoded input (may be redacted)
                    output TEXT,  -- JSON-encoded output (may be redacted)
                    decision TEXT,
                    duration_ms INTEGER,
                    error TEXT,
                    metadata TEXT,
                    shadow_mode BOOLEAN DEFAULT 0
                );
                
                CREATE INDEX IF NOT EXISTS idx_flight_trace ON flight_recorder_events(trace_id);
                CREATE INDEX IF NOT EXISTS idx_flight_timestamp ON flight_recorder_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_flight_agent ON flight_recorder_events(agent_id);
                CREATE INDEX IF NOT EXISTS idx_flight_session ON flight_recorder_events(session_id);
                CREATE INDEX IF NOT EXISTS idx_flight_shadow ON flight_recorder_events(shadow_mode);
            "#,
            r#"
                DROP INDEX IF EXISTS idx_flight_shadow;
                DROP INDEX IF EXISTS idx_flight_session;
                DROP INDEX IF EXISTS idx_flight_agent;
                DROP INDEX IF EXISTS idx_flight_timestamp;
                DROP INDEX IF EXISTS idx_flight_trace;
                DROP TABLE IF EXISTS flight_recorder_events;
            "#,
            "Create flight recorder events table for shadow mode",
        ),
    ]
}

// ============================================================================
// Migration Runner
// ============================================================================

/// Runs database migrations
pub struct MigrationRunner<'a> {
    conn: &'a Connection,
    migrations: Vec<Migration>,
}

impl<'a> MigrationRunner<'a> {
    /// Create a new migration runner
    pub fn new(conn: &'a Connection) -> Result<Self, MigrationError> {
        let migrations = get_all_migrations();

        // Ensure schema_migrations table exists (bootstrap)
        conn.execute_batch(
            r#"
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at INTEGER NOT NULL,
                    checksum TEXT NOT NULL
                );
            "#,
        )?;

        Ok(Self { conn, migrations })
    }

    /// Get the current schema version
    pub fn current_version(&self) -> Result<u32, MigrationError> {
        let result: Option<u32> = self
            .conn
            .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .ok()
            .flatten();

        Ok(result.unwrap_or(0))
    }

    /// Get pending migrations
    pub fn pending(&self) -> Result<Vec<&Migration>, MigrationError> {
        let applied = self.get_applied_versions()?;
        Ok(self
            .migrations
            .iter()
            .filter(|m| !applied.contains(&m.version))
            .collect())
    }

    /// Get applied migration versions
    fn get_applied_versions(&self) -> Result<Vec<u32>, MigrationError> {
        let mut stmt = self
            .conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")?;

        let versions = stmt
            .query_map([], |row| row.get(0))?
            .collect::<Result<Vec<u32>, _>>()?;

        Ok(versions)
    }

    /// Run all pending migrations
    pub fn run_all(&self) -> Result<Vec<u32>, MigrationError> {
        let pending = self.pending()?;
        let mut applied = Vec::new();

        for migration in pending {
            self.run_one(migration.version)?;
            applied.push(migration.version);
        }

        Ok(applied)
    }

    /// Run a specific migration
    pub fn run_one(&self, version: u32) -> Result<(), MigrationError> {
        let migration = self
            .migrations
            .iter()
            .find(|m| m.version == version)
            .ok_or(MigrationError::NotFound(version))?;

        // Check if already applied
        let applied = self.get_applied_versions()?;
        if applied.contains(&version) {
            return Err(MigrationError::AlreadyApplied(version));
        }

        // Calculate checksum
        let checksum = calculate_checksum(&migration.up_sql);

        // Run migration
        tracing::info!(
            "Running migration {}: {} - {}",
            version,
            migration.name,
            migration.description
        );

        self.conn
            .execute_batch(&migration.up_sql)
            .map_err(|e| MigrationError::MigrationFailed(version, e.to_string()))?;

        // Record migration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.conn.execute(
            "INSERT INTO schema_migrations (version, name, applied_at, checksum) VALUES (?1, ?2, ?3, ?4)",
            params![version, migration.name, now, checksum],
        )?;

        tracing::info!("Migration {} completed successfully", version);
        Ok(())
    }

    /// Rollback a specific migration
    pub fn rollback(&self, version: u32) -> Result<(), MigrationError> {
        let migration = self
            .migrations
            .iter()
            .find(|m| m.version == version)
            .ok_or(MigrationError::NotFound(version))?;

        // Check if applied
        let applied = self.get_applied_versions()?;
        if !applied.contains(&version) {
            return Err(MigrationError::NotFound(version));
        }

        tracing::info!("Rolling back migration {}: {}", version, migration.name);

        // Run rollback
        self.conn
            .execute_batch(&migration.down_sql)
            .map_err(|e| MigrationError::RollbackFailed(version, e.to_string()))?;

        // Remove from migrations table
        self.conn.execute(
            "DELETE FROM schema_migrations WHERE version = ?1",
            params![version],
        )?;

        tracing::info!("Rollback of migration {} completed", version);
        Ok(())
    }

    /// Rollback all migrations to a specific version
    pub fn rollback_to(&self, target_version: u32) -> Result<Vec<u32>, MigrationError> {
        let applied = self.get_applied_versions()?;
        let mut rolled_back = Vec::new();

        // Rollback in reverse order
        for version in applied.into_iter().rev() {
            if version > target_version {
                self.rollback(version)?;
                rolled_back.push(version);
            }
        }

        Ok(rolled_back)
    }

    /// Get migration status
    pub fn status(&self) -> Result<Vec<(Migration, MigrationStatus)>, MigrationError> {
        let applied = self.get_applied_versions()?;

        Ok(self
            .migrations
            .iter()
            .map(|m| {
                let status = if applied.contains(&m.version) {
                    MigrationStatus::Applied
                } else {
                    MigrationStatus::Pending
                };
                (m.clone(), status)
            })
            .collect())
    }
}

/// Calculate SHA-256 checksum of SQL content
fn calculate_checksum(sql: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    hex::encode(hasher.finalize())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use tempfile::tempdir;

    fn setup_test_db() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn test_migration_runner_creation() {
        let conn = setup_test_db();
        let runner = MigrationRunner::new(&conn).unwrap();
        assert!(runner.current_version().unwrap() == 0);
    }

    #[test]
    fn test_run_all_migrations() {
        let conn = setup_test_db();
        let runner = MigrationRunner::new(&conn).unwrap();

        let applied = runner.run_all().unwrap();
        assert!(!applied.is_empty());

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table'")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"policies".to_string()));
        assert!(tables.contains(&"agent_sessions".to_string()));
        assert!(tables.contains(&"memory_snapshots".to_string()));
    }

    #[test]
    fn test_migration_status() {
        let conn = setup_test_db();
        let runner = MigrationRunner::new(&conn).unwrap();

        // Initially all pending
        let status = runner.status().unwrap();
        assert!(status.iter().all(|(_, s)| *s == MigrationStatus::Pending));

        // Run migrations
        runner.run_all().unwrap();

        // Now all applied
        let status = runner.status().unwrap();
        assert!(status.iter().all(|(_, s)| *s == MigrationStatus::Applied));
    }

    #[test]
    fn test_rollback_migration() {
        let conn = setup_test_db();
        let runner = MigrationRunner::new(&conn).unwrap();

        // Run all migrations
        runner.run_all().unwrap();

        // Rollback last migration
        let current = runner.current_version().unwrap();
        runner.rollback(current).unwrap();

        // Version should be decremented
        let new_version = runner.current_version().unwrap();
        assert!(new_version < current);
    }

    #[test]
    fn test_idempotent_migration() {
        let conn = setup_test_db();
        let runner = MigrationRunner::new(&conn).unwrap();

        // Run once
        runner.run_all().unwrap();

        // Running again should return empty (no pending)
        let applied = runner.run_all().unwrap();
        assert!(applied.is_empty());
    }

    #[test]
    fn test_pending_migrations() {
        let conn = setup_test_db();
        let runner = MigrationRunner::new(&conn).unwrap();

        let pending = runner.pending().unwrap();
        let total_migrations = get_all_migrations().len();

        // Initially all migrations are pending (minus bootstrap)
        assert_eq!(pending.len(), total_migrations);
    }
}
