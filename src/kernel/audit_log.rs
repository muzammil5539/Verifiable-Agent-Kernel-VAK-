//! The kernel's audit log port, and its memory and file adapters.
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

use std::fmt;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
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
    #[error("audit log is corrupt at line {line}: {reason}")]
    Corrupt {
        /// 1-based line (entry) number where verification failed.
        line: usize,
        /// What was wrong.
        reason: String,
    },

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
/// - assign leaf indices densely from zero, in append order.
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
        // both claim the same predecessor.
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
    inner: RwLock<FileInner>,
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
            inner: RwLock::new(FileInner {
                file,
                trail,
                failed: None,
            }),
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
            let expected_prev = trail.entries.last().map(|p| p.hash.as_str());
            if entry.previous_hash.as_deref() != expected_prev || !entry.verify_integrity() {
                return Err(AuditLogError::Corrupt {
                    line: i + 1,
                    reason: "entry does not match its hash or its predecessor".to_string(),
                });
            }
            trail.push(entry);
        }
        Ok(trail)
    }
}

#[async_trait]
impl AuditLog for FileAuditLog {
    async fn append(&self, entry: AuditEntry) -> Result<u64, AuditLogError> {
        let mut inner = self.inner.write().await;
        if let Some(reason) = &inner.failed {
            return Err(AuditLogError::Io(format!(
                "{} refused after an earlier failed write ({reason}); reopen it to recover",
                self.path.display()
            )));
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
                    path = %self.path.display(),
                    error = %reason,
                    "Audit log write failed; refusing further appends"
                );
                inner.failed = Some(reason.clone());
                Err(AuditLogError::Io(format!(
                    "{}: {reason}",
                    self.path.display()
                )))
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::transparency::{verify_consistency, verify_inclusion};
    use crate::kernel::types::{AgentId, PolicyDecision, SessionId};

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
}
