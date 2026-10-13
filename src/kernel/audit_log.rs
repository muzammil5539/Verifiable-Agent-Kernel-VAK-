//! The kernel's audit log port, and its memory, file and SQLite adapters.
//!
//! The Record stages of [`Kernel::execute`](super::Kernel::execute) append
//! through [`AuditLog`]. An append links the entry to the log's tail (the
//! per-entry hash chain) and adds it as a leaf of an RFC 9162 Merkle tree
//! ([`crate::audit::transparency`]), so any entry can later be proven to a
//! third party. The kernel signs tree heads; the log only stores.
//!
//! The contract that makes "record before acting" hold: **`append` returns
//! `Ok` only once the entry is stored**. If it returns `Err`, the kernel does
//! not run the tool. See `docs/adr/0003`.
//!
//! This is the kernel's only audit path (`docs/adr/0007`). The durable
//! adapters, [`FileAuditLog`] and [`SqliteAuditLog`], verify everything they
//! hold when they open and refuse a log that doesn't verify.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use rusqlite::{params, Connection};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;

use super::types::AuditEntry;
use crate::audit::transparency::{
    leaf_hash, ConsistencyProof, Digest, InclusionProof, MerkleLog, TransparencyError, TreeHead,
};

/// Errors from an [`AuditLog`].
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum AuditLogError {
    /// Reading or writing the backing store failed.
    #[error("audit log I/O error: {0}")]
    Io(String),

    /// The stored log does not verify, so it can't be extended.
    #[error("audit log is corrupt at entry {line}: {reason}")]
    Corrupt {
        /// 1-based entry number (the line, in a JSONL file) where
        /// verification failed.
        line: usize,
        /// What was wrong.
        reason: String,
    },

    /// The store isn't a VAK audit log, or is one in a format this version
    /// can't read.
    #[error("not a usable VAK audit log: {0}")]
    Format(String),

    /// A proof was requested for an index or size the log doesn't have.
    #[error(transparent)]
    Proof(#[from] TransparencyError),
}

/// The Merkle leaf hash of an audit entry: `leaf_hash(entry.hash)`, over the
/// entry's hex hash string as bytes.
#[must_use]
pub fn entry_leaf_hash(entry: &AuditEntry) -> Digest {
    leaf_hash(entry.hash.as_bytes())
}

/// Append-only, provable storage for audit entries.
///
/// Implementations must:
///
/// - link each appended entry to the current tail with
///   [`AuditEntry::with_previous`] before storing it;
/// - return `Ok` from [`AuditLog::append`] only once the entry is stored, and
///   `Err` otherwise (the kernel then refuses to run the tool);
/// - assign leaf indices densely from zero, in append order;
/// - keep storage and the tree in step even if the caller stops waiting for
///   an `append` (drops its future) part-way through.
#[async_trait]
pub trait AuditLog: Send + Sync + fmt::Debug {
    /// Links `entry` to the tail, stores it, and returns its leaf index.
    async fn append(&self, entry: AuditEntry) -> Result<u64, AuditLogError>;

    /// The current size and Merkle root.
    async fn tree_head(&self) -> TreeHead;

    /// Proof that leaf `leaf_index` is in the tree of the first `tree_size`
    /// leaves.
    async fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, AuditLogError>;

    /// Proof that the tree of `old_size` leaves is a prefix of the tree of
    /// `new_size` leaves.
    async fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, AuditLogError>;

    /// Every stored entry, in order.
    async fn entries(&self) -> Vec<AuditEntry>;

    /// A short name identifying this log in logs.
    fn name(&self) -> &str;
}

/// Entries plus the Merkle tree over them, kept in step.
#[derive(Debug, Default)]
struct Trail {
    entries: Vec<AuditEntry>,
    tree: MerkleLog,
}

impl Trail {
    /// Links `entry` to the current tail.
    fn link(&self, entry: AuditEntry) -> AuditEntry {
        match self.entries.last() {
            Some(prev) => entry.with_previous(prev.hash.clone()),
            None => entry,
        }
    }

    /// Adds an already-linked entry and returns its leaf index.
    fn push(&mut self, linked: AuditEntry) -> u64 {
        let index = self.tree.append_leaf_hash(entry_leaf_hash(&linked));
        self.entries.push(linked);
        index
    }

    /// Adds an entry read back from storage, after checking that it matches
    /// its own hash and links to the tail. `line` is its 1-based position,
    /// for the error.
    fn push_verified(&mut self, entry: AuditEntry, line: usize) -> Result<u64, AuditLogError> {
        let expected_prev = self.entries.last().map(|p| p.hash.as_str());
        if entry.previous_hash.as_deref() != expected_prev || !entry.verify_integrity() {
            return Err(AuditLogError::Corrupt {
                line,
                reason: "entry does not match its hash or its predecessor".to_string(),
            });
        }
        Ok(self.push(entry))
    }
}

/// The error an append returns once a durable log has stopped accepting them.
fn refused(path: &Path, reason: &str) -> AuditLogError {
    AuditLogError::Io(format!(
        "{} refused after an earlier failed write ({reason}); reopen it to recover",
        path.display()
    ))
}

/// Runs a durable log's append on its own task, so it finishes even if the
/// caller stops waiting. Otherwise a write could land in storage after the
/// caller's future was dropped, without its leaf joining the tree, and the
/// next append would link to the wrong predecessor.
async fn run_to_completion<F>(append: F) -> Result<u64, AuditLogError>
where
    F: std::future::Future<Output = Result<u64, AuditLogError>> + Send + 'static,
{
    tokio::spawn(append)
        .await
        .map_err(|e| AuditLogError::Io(format!("audit append task failed: {e}")))?
}

/// An [`AuditLog`] in memory. Lives as long as the process; the default when
/// `audit.log_path` is not set.
#[derive(Debug, Default)]
pub struct MemoryAuditLog {
    trail: RwLock<Trail>,
}

impl MemoryAuditLog {
    /// Creates an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AuditLog for MemoryAuditLog {
    async fn append(&self, entry: AuditEntry) -> Result<u64, AuditLogError> {
        // One write lock across link-and-push, so concurrent appends can't
        // both claim the same predecessor. Nothing awaits in between, so a
        // dropped call can't leave half an append behind.
        let mut trail = self.trail.write().await;
        let linked = trail.link(entry);
        Ok(trail.push(linked))
    }

    async fn tree_head(&self) -> TreeHead {
        self.trail.read().await.tree.tree_head()
    }

    async fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, AuditLogError> {
        Ok(self
            .trail
            .read()
            .await
            .tree
            .inclusion_proof(leaf_index, tree_size)?)
    }

    async fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, AuditLogError> {
        Ok(self
            .trail
            .read()
            .await
            .tree
            .consistency_proof(old_size, new_size)?)
    }

    async fn entries(&self) -> Vec<AuditEntry> {
        self.trail.read().await.entries.clone()
    }

    fn name(&self) -> &str {
        "memory"
    }
}

/// An [`AuditLog`] in an append-only JSONL file, one entry per line.
///
/// - Each append is written and `sync_data`'d before `append` returns.
/// - Opening reads every line, verifies the hash chain, and rebuilds the
///   Merkle tree. A file that doesn't verify is refused rather than repaired,
///   including a torn last line left by a crash mid-write: an operator
///   decides what to do with it, not the kernel.
/// - After a failed write the file may end in a partial line, so the log
///   refuses every further append until it is reopened (which then reports
///   the damage).
pub struct FileAuditLog {
    path: PathBuf,
    inner: Arc<RwLock<FileInner>>,
}

struct FileInner {
    file: tokio::fs::File,
    trail: Trail,
    /// Set after a failed write; the log refuses appends from then on.
    failed: Option<String>,
}

impl fmt::Debug for FileAuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAuditLog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl FileAuditLog {
    /// Opens the log at `path`, creating it (and its parent directories) if
    /// it doesn't exist, and verifying it if it does.
    ///
    /// # Errors
    ///
    /// [`AuditLogError::Io`] if the file can't be read or opened, and
    /// [`AuditLogError::Corrupt`] if an entry doesn't parse, the hash chain
    /// is broken, or the last line is incomplete.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, AuditLogError> {
        let path = path.as_ref().to_path_buf();
        let io = |e: std::io::Error| AuditLogError::Io(format!("{}: {e}", path.display()));

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await.map_err(io)?;
        }

        let existing = match tokio::fs::read_to_string(&path).await {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(io(e)),
        };
        let trail = Self::replay(&existing)?;

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .map_err(io)?;

        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(FileInner {
                file,
                trail,
                failed: None,
            })),
        })
    }

    /// The file this log writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Rebuilds the trail from the file's contents, verifying as it goes.
    fn replay(text: &str) -> Result<Trail, AuditLogError> {
        let mut trail = Trail::default();
        if text.is_empty() {
            return Ok(trail);
        }
        let line_count = text.lines().count();
        if !text.ends_with('\n') {
            return Err(AuditLogError::Corrupt {
                line: line_count,
                reason: "incomplete last line (interrupted write)".to_string(),
            });
        }
        for (i, line) in text.lines().enumerate() {
            let entry: AuditEntry =
                serde_json::from_str(line).map_err(|e| AuditLogError::Corrupt {
                    line: i + 1,
                    reason: format!("unparseable entry: {e}"),
                })?;
            trail.push_verified(entry, i + 1)?;
        }
        Ok(trail)
    }
}

#[async_trait]
impl AuditLog for FileAuditLog {
    async fn append(&self, entry: AuditEntry) -> Result<u64, AuditLogError> {
        let inner = Arc::clone(&self.inner);
        let path = self.path.clone();
        run_to_completion(async move {
            let mut inner = inner.write().await;
            if let Some(reason) = &inner.failed {
                return Err(refused(&path, reason));
            }

            let linked = inner.trail.link(entry);
            let mut line =
                serde_json::to_string(&linked).map_err(|e| AuditLogError::Io(e.to_string()))?;
            line.push('\n');

            let written = async {
                inner.file.write_all(line.as_bytes()).await?;
                inner.file.flush().await?;
                inner.file.sync_data().await
            }
            .await;

            match written {
                // Only a stored entry becomes a leaf.
                Ok(()) => Ok(inner.trail.push(linked)),
                Err(e) => {
                    let reason = e.to_string();
                    tracing::error!(
                        path = %path.display(),
                        error = %reason,
                        "Audit log write failed; refusing further appends"
                    );
                    inner.failed = Some(reason.clone());
                    Err(AuditLogError::Io(format!("{}: {reason}", path.display())))
                }
            }
        })
        .await
    }

    async fn tree_head(&self) -> TreeHead {
        self.inner.read().await.trail.tree.tree_head()
    }

    async fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, AuditLogError> {
        Ok(self
            .inner
            .read()
            .await
            .trail
            .tree
            .inclusion_proof(leaf_index, tree_size)?)
    }

    async fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, AuditLogError> {
        Ok(self
            .inner
            .read()
            .await
            .trail
            .tree
            .consistency_proof(old_size, new_size)?)
    }

    async fn entries(&self) -> Vec<AuditEntry> {
        self.inner.read().await.trail.entries.clone()
    }

    fn name(&self) -> &str {
        "file"
    }
}

/// `PRAGMA application_id` of a VAK audit database: `"VAKL"` in ASCII.
const SQLITE_APPLICATION_ID: i32 = 0x5641_4B4C;

/// `PRAGMA user_version` of the schema [`SqliteAuditLog`] writes.
const SQLITE_SCHEMA_VERSION: i32 = 1;

const SQLITE_SCHEMA: &str = "
    CREATE TABLE vak_audit_log (
        leaf_index INTEGER PRIMARY KEY,
        entry_hash TEXT NOT NULL,
        entry TEXT NOT NULL
    ) STRICT;
";

/// An [`AuditLog`] in a SQLite database, one row per entry.
///
/// - Each append is a single autocommit `INSERT`, with the database in WAL
///   mode and `synchronous = FULL`, so `append` returns `Ok` only once the row
///   is durable. A crash mid-append rolls the row back, so unlike the JSONL
///   file the log reopens cleanly, without the entry (whose tool the kernel
///   never ran, since the append never returned `Ok`).
/// - A row holds the entry as the same JSON [`FileAuditLog`] writes, so it can
///   be queried with SQLite's `json_extract`.
/// - Opening reads every row in leaf order, checks that leaf indices are
///   dense from zero, verifies the hash chain, and rebuilds the Merkle tree.
///   A database that doesn't verify is refused, and so is one VAK didn't
///   create (checked by `PRAGMA application_id`).
/// - After a failed write the log refuses further appends until it is
///   reopened, since it can no longer be sure what the database holds.
///
/// One kernel should write to a database at a time. A second writer is
/// detected rather than coordinated: its insert collides on the leaf index,
/// and that log refuses appends from then on.
pub struct SqliteAuditLog {
    path: PathBuf,
    inner: Arc<RwLock<SqliteInner>>,
}

struct SqliteInner {
    /// Used only on the blocking pool, one append at a time.
    conn: Arc<Mutex<Connection>>,
    trail: Trail,
    /// Set after a failed write; the log refuses appends from then on.
    failed: Option<String>,
}

impl fmt::Debug for SqliteAuditLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteAuditLog")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SqliteAuditLog {
    /// Opens the database at `path`, creating it (and its parent
    /// directories) if it doesn't exist, and verifying it if it does.
    ///
    /// # Errors
    ///
    /// [`AuditLogError::Io`] if the database can't be opened or read,
    /// [`AuditLogError::Format`] if it isn't a VAK audit log or has an
    /// unsupported schema version, and [`AuditLogError::Corrupt`] if a row is
    /// missing, an entry doesn't parse, or the hash chain is broken.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, AuditLogError> {
        let path = path.as_ref().to_path_buf();
        let at = path.clone();
        let (conn, trail) = tokio::task::spawn_blocking(move || Self::open_blocking(&at))
            .await
            .map_err(|e| AuditLogError::Io(format!("{}: {e}", path.display())))??;
        Ok(Self {
            path,
            inner: Arc::new(RwLock::new(SqliteInner {
                conn: Arc::new(Mutex::new(conn)),
                trail,
                failed: None,
            })),
        })
    }

    /// The database this log writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open_blocking(path: &Path) -> Result<(Connection, Trail), AuditLogError> {
        let sql = |e: rusqlite::Error| AuditLogError::Io(format!("{}: {e}", path.display()));

        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)
                .map_err(|e| AuditLogError::Io(format!("{}: {e}", path.display())))?;
        }
        let conn = Connection::open(path).map_err(sql)?;

        // WAL lets readers (an operator's `sqlite3`) work alongside the
        // kernel; FULL makes each commit durable before `execute` returns.
        let _mode: String = conn
            .pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get(0))
            .map_err(sql)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .map_err(sql)?;

        Self::check_schema(&conn, path)?;
        let trail = Self::replay(&conn).map_err(|e| match e {
            ReplayError::Sql(e) => sql(e),
            ReplayError::Log(e) => e,
        })?;
        Ok((conn, trail))
    }

    /// Accepts a VAK audit database of the current schema version, creates
    /// the schema in an empty database, and refuses anything else.
    fn check_schema(conn: &Connection, path: &Path) -> Result<(), AuditLogError> {
        let sql = |e: rusqlite::Error| AuditLogError::Io(format!("{}: {e}", path.display()));
        let pragma = |name: &str| -> Result<i32, AuditLogError> {
            conn.query_row(&format!("PRAGMA {name}"), [], |row| row.get(0))
                .map_err(sql)
        };

        match (pragma("application_id")?, pragma("user_version")?) {
            (SQLITE_APPLICATION_ID, SQLITE_SCHEMA_VERSION) => Ok(()),
            (SQLITE_APPLICATION_ID, version) => Err(AuditLogError::Format(format!(
                "{} has schema version {version}; this version of VAK reads {SQLITE_SCHEMA_VERSION}",
                path.display()
            ))),
            (0, 0) => {
                let objects: i64 = conn
                    .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
                    .map_err(sql)?;
                if objects != 0 {
                    return Err(AuditLogError::Format(format!(
                        "{} is a SQLite database VAK didn't create",
                        path.display()
                    )));
                }
                conn.execute_batch(&format!(
                    "BEGIN IMMEDIATE;
                     {SQLITE_SCHEMA}
                     PRAGMA application_id = {SQLITE_APPLICATION_ID};
                     PRAGMA user_version = {SQLITE_SCHEMA_VERSION};
                     COMMIT;"
                ))
                .map_err(sql)
            }
            (application_id, _) => Err(AuditLogError::Format(format!(
                "{} has application_id {application_id:#x}, not VAK's",
                path.display()
            ))),
        }
    }

    /// Rebuilds the trail from the rows, verifying as it goes.
    fn replay(conn: &Connection) -> Result<Trail, ReplayError> {
        let mut trail = Trail::default();
        let mut statement = conn.prepare(
            "SELECT leaf_index, entry_hash, entry FROM vak_audit_log ORDER BY leaf_index",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let position = trail.entries.len();
            let line = position + 1;
            let corrupt =
                |reason: String| ReplayError::Log(AuditLogError::Corrupt { line, reason });

            let leaf_index: i64 = row.get(0)?;
            if i64::try_from(position).ok() != Some(leaf_index) {
                return Err(corrupt(format!(
                    "expected leaf {position}, found leaf {leaf_index}: entries are missing"
                )));
            }
            let entry_hash: String = row.get(1)?;
            let json: String = row.get(2)?;
            let entry: AuditEntry = serde_json::from_str(&json)
                .map_err(|e| corrupt(format!("unparseable entry: {e}")))?;
            if entry.hash != entry_hash {
                return Err(corrupt(
                    "the entry_hash column doesn't match the entry".to_string(),
                ));
            }
            trail.push_verified(entry, line).map_err(ReplayError::Log)?;
        }
        Ok(trail)
    }
}

/// Why replaying a SQLite log failed: the database, or what it held.
enum ReplayError {
    Sql(rusqlite::Error),
    Log(AuditLogError),
}

impl From<rusqlite::Error> for ReplayError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}

#[async_trait]
impl AuditLog for SqliteAuditLog {
    async fn append(&self, entry: AuditEntry) -> Result<u64, AuditLogError> {
        let inner = Arc::clone(&self.inner);
        let path = self.path.clone();
        run_to_completion(async move {
            let mut inner = inner.write().await;
            if let Some(reason) = &inner.failed {
                return Err(refused(&path, reason));
            }

            let linked = inner.trail.link(entry);
            let json =
                serde_json::to_string(&linked).map_err(|e| AuditLogError::Io(e.to_string()))?;
            let hash = linked.hash.clone();
            let position = inner.trail.entries.len();
            let conn = Arc::clone(&inner.conn);

            let written = tokio::task::spawn_blocking(move || -> Result<(), String> {
                let conn = conn
                    .lock()
                    .map_err(|_| "connection lock poisoned".to_string())?;
                let leaf_index = i64::try_from(position).map_err(|e| e.to_string())?;
                conn.execute(
                    "INSERT INTO vak_audit_log (leaf_index, entry_hash, entry) VALUES (?1, ?2, ?3)",
                    params![leaf_index, hash, json],
                )
                .map(|_| ())
                .map_err(|e| e.to_string())
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|written| written);

            match written {
                // Only a stored entry becomes a leaf.
                Ok(()) => Ok(inner.trail.push(linked)),
                Err(reason) => {
                    tracing::error!(
                        path = %path.display(),
                        error = %reason,
                        "Audit log write failed; refusing further appends"
                    );
                    inner.failed = Some(reason.clone());
                    Err(AuditLogError::Io(format!("{}: {reason}", path.display())))
                }
            }
        })
        .await
    }

    async fn tree_head(&self) -> TreeHead {
        self.inner.read().await.trail.tree.tree_head()
    }

    async fn inclusion_proof(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, AuditLogError> {
        Ok(self
            .inner
            .read()
            .await
            .trail
            .tree
            .inclusion_proof(leaf_index, tree_size)?)
    }

    async fn consistency_proof(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, AuditLogError> {
        Ok(self
            .inner
            .read()
            .await
            .trail
            .tree
            .consistency_proof(old_size, new_size)?)
    }

    async fn entries(&self) -> Vec<AuditEntry> {
        self.inner.read().await.trail.entries.clone()
    }

    fn name(&self) -> &str {
        "sqlite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::transparency::{verify_consistency, verify_inclusion};
    use crate::kernel::types::{AgentId, PolicyDecision, SessionId};
    use futures::FutureExt;

    fn entry(action: &str) -> AuditEntry {
        AuditEntry::new(
            AgentId::new(),
            SessionId::new(),
            action,
            PolicyDecision::Allow {
                reason: "test".to_string(),
                constraints: None,
            },
        )
    }

    fn hashes(entries: &[AuditEntry]) -> Vec<&str> {
        entries.iter().map(|e| e.hash.as_str()).collect()
    }

    async fn exercise(log: &dyn AuditLog) {
        assert_eq!(log.append(entry("a")).await.unwrap(), 0);
        let first = log.tree_head().await;
        assert_eq!(log.append(entry("b")).await.unwrap(), 1);
        assert_eq!(log.append(entry("c")).await.unwrap(), 2);
        let head = log.tree_head().await;
        assert_eq!(head.size, 3);

        let entries = log.entries().await;
        AuditEntry::verify_chain(&entries).unwrap();
        for (i, e) in entries.iter().enumerate() {
            let proof = log.inclusion_proof(i as u64, head.size).await.unwrap();
            verify_inclusion(&entry_leaf_hash(e), &proof, &head.root).unwrap();
        }
        let consistency = log.consistency_proof(first.size, head.size).await.unwrap();
        verify_consistency(&consistency, &first.root, &head.root).unwrap();
        assert!(matches!(
            log.inclusion_proof(3, 3).await,
            Err(AuditLogError::Proof(_))
        ));
    }

    #[tokio::test]
    async fn test_memory_log() {
        exercise(&MemoryAuditLog::new()).await;
    }

    #[tokio::test]
    async fn test_file_log_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("audit.jsonl");

        let log = FileAuditLog::open(&path).await.unwrap();
        exercise(&log).await;
        let head = log.tree_head().await;
        let entries = log.entries().await;
        drop(log);

        // Reopening rebuilds the same tree, and appends continue the chain.
        let reopened = FileAuditLog::open(&path).await.unwrap();
        assert_eq!(reopened.tree_head().await, head);
        assert_eq!(reopened.entries().await.len(), entries.len());
        assert_eq!(reopened.append(entry("d")).await.unwrap(), 3);
        AuditEntry::verify_chain(&reopened.entries().await).unwrap();
        let later = reopened.tree_head().await;
        let consistency = reopened
            .consistency_proof(head.size, later.size)
            .await
            .unwrap();
        verify_consistency(&consistency, &head.root, &later.root).unwrap();
    }

    #[tokio::test]
    async fn test_file_log_refuses_tampered_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let log = FileAuditLog::open(&path).await.unwrap();
            log.append(entry("transfer")).await.unwrap();
            log.append(entry("echo")).await.unwrap();
        }

        // Rewrite a field without fixing the hash.
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replacen("transfer", "nothing!", 1)).unwrap();
        assert!(matches!(
            FileAuditLog::open(&path).await,
            Err(AuditLogError::Corrupt { line: 1, .. })
        ));

        // Drop the first line: the second no longer links to anything.
        let second = text.lines().nth(1).unwrap().to_string() + "\n";
        std::fs::write(&path, second).unwrap();
        assert!(matches!(
            FileAuditLog::open(&path).await,
            Err(AuditLogError::Corrupt { line: 1, .. })
        ));
    }

    #[tokio::test]
    async fn test_file_log_refuses_torn_last_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let log = FileAuditLog::open(&path).await.unwrap();
            log.append(entry("a")).await.unwrap();
        }
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"audit_id\":");
        std::fs::write(&path, text).unwrap();
        assert!(matches!(
            FileAuditLog::open(&path).await,
            Err(AuditLogError::Corrupt { line: 2, .. })
        ));
    }

    #[tokio::test]
    async fn test_file_log_open_fails_on_unusable_path() {
        let dir = tempfile::tempdir().unwrap();
        // A directory where the file should be.
        assert!(matches!(
            FileAuditLog::open(dir.path()).await,
            Err(AuditLogError::Io(_))
        ));
    }

    #[tokio::test]
    async fn test_sqlite_log_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("audit.db");

        let log = SqliteAuditLog::open(&path).await.unwrap();
        exercise(&log).await;
        let head = log.tree_head().await;
        let entries = log.entries().await;
        drop(log);

        let reopened = SqliteAuditLog::open(&path).await.unwrap();
        assert_eq!(reopened.tree_head().await, head);
        assert_eq!(hashes(&reopened.entries().await), hashes(&entries));
        assert_eq!(reopened.append(entry("d")).await.unwrap(), 3);
        AuditEntry::verify_chain(&reopened.entries().await).unwrap();
        let later = reopened.tree_head().await;
        let consistency = reopened
            .consistency_proof(head.size, later.size)
            .await
            .unwrap();
        verify_consistency(&consistency, &head.root, &later.root).unwrap();
    }

    /// Writes two entries ("transfer", then "echo") and returns the database.
    async fn sqlite_with_two_entries(dir: &Path) -> PathBuf {
        let path = dir.join("audit.db");
        let log = SqliteAuditLog::open(&path).await.unwrap();
        log.append(entry("transfer")).await.unwrap();
        log.append(entry("echo")).await.unwrap();
        path
    }

    async fn sqlite_open_error(path: &Path) -> AuditLogError {
        SqliteAuditLog::open(path).await.unwrap_err()
    }

    #[tokio::test]
    async fn test_sqlite_log_refuses_tampered_rows() {
        let cases: [(&str, &str, usize); 4] = [
            (
                "a rewritten field",
                "UPDATE vak_audit_log SET entry = replace(entry, 'transfer', 'nothing!') WHERE leaf_index = 0",
                1,
            ),
            (
                "a deleted first row",
                "DELETE FROM vak_audit_log WHERE leaf_index = 0",
                1,
            ),
            (
                "rows swapped",
                "UPDATE vak_audit_log SET leaf_index = 1 - leaf_index + 10; \
                 UPDATE vak_audit_log SET leaf_index = leaf_index - 10",
                1,
            ),
            (
                "an index column that disagrees with the entry",
                "UPDATE vak_audit_log SET entry_hash = 'ff' WHERE leaf_index = 1",
                2,
            ),
        ];
        for (case, tamper, at) in cases {
            let dir = tempfile::tempdir().unwrap();
            let path = sqlite_with_two_entries(dir.path()).await;
            Connection::open(&path)
                .unwrap()
                .execute_batch(tamper)
                .unwrap();
            let error = sqlite_open_error(&path).await;
            assert!(
                matches!(error, AuditLogError::Corrupt { line, .. } if line == at),
                "{case}: {error:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_sqlite_log_refuses_databases_it_did_not_create() {
        let dir = tempfile::tempdir().unwrap();

        let foreign = dir.path().join("foreign.db");
        Connection::open(&foreign)
            .unwrap()
            .execute_batch("CREATE TABLE notes (body TEXT)")
            .unwrap();
        assert!(matches!(
            sqlite_open_error(&foreign).await,
            AuditLogError::Format(_)
        ));

        let other_app = dir.path().join("other-app.db");
        Connection::open(&other_app)
            .unwrap()
            .execute_batch("PRAGMA application_id = 42")
            .unwrap();
        assert!(matches!(
            sqlite_open_error(&other_app).await,
            AuditLogError::Format(_)
        ));

        let newer = sqlite_with_two_entries(dir.path()).await;
        Connection::open(&newer)
            .unwrap()
            .execute_batch("PRAGMA user_version = 2")
            .unwrap();
        assert!(matches!(
            sqlite_open_error(&newer).await,
            AuditLogError::Format(_)
        ));

        let text = dir.path().join("audit.jsonl");
        std::fs::write(&text, "{\"not\": \"a database\"}\n".repeat(200)).unwrap();
        assert!(matches!(
            sqlite_open_error(&text).await,
            AuditLogError::Io(_)
        ));
    }

    #[tokio::test]
    async fn test_sqlite_log_detects_a_second_writer_and_stops() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let first = SqliteAuditLog::open(&path).await.unwrap();
        let second = SqliteAuditLog::open(&path).await.unwrap();

        assert_eq!(second.append(entry("theirs")).await.unwrap(), 0);
        // Leaf 0 is taken: the first log's view of the database is stale.
        assert!(matches!(
            first.append(entry("ours")).await,
            Err(AuditLogError::Io(_))
        ));
        assert_eq!(first.tree_head().await.size, 0, "a failed write is no leaf");
        let refused = first.append(entry("again")).await.unwrap_err();
        assert!(refused.to_string().contains("reopen"), "{refused}");

        // Reopening shows what the database really holds.
        let reopened = SqliteAuditLog::open(&path).await.unwrap();
        assert_eq!(
            hashes(&reopened.entries().await),
            hashes(&second.entries().await)
        );
    }

    /// A caller that stops waiting for an append must not leave storage and
    /// the tree out of step.
    async fn survives_a_dropped_append<L, F, Fut>(path: &Path, open: F)
    where
        L: AuditLog,
        F: Fn(PathBuf) -> Fut,
        Fut: std::future::Future<Output = Result<L, AuditLogError>>,
    {
        let log = open(path.to_path_buf()).await.unwrap();
        // Polled once, then dropped mid-write.
        assert!(log.append(entry("abandoned")).now_or_never().is_none());
        assert_eq!(log.append(entry("next")).await.unwrap(), 1);
        let entries = log.entries().await;
        AuditEntry::verify_chain(&entries).unwrap();
        drop(log);

        let reopened = open(path.to_path_buf()).await.unwrap();
        assert_eq!(hashes(&reopened.entries().await), hashes(&entries));
    }

    #[tokio::test]
    async fn test_durable_logs_survive_a_dropped_append() {
        let dir = tempfile::tempdir().unwrap();
        survives_a_dropped_append(&dir.path().join("audit.jsonl"), FileAuditLog::open).await;
        survives_a_dropped_append(&dir.path().join("audit.db"), SqliteAuditLog::open).await;
    }
}
