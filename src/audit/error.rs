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
