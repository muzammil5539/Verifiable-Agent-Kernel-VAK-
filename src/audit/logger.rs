use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::audit::backend::AuditBackend;
use crate::audit::error::{AuditError, AuditVerificationError};
use crate::audit::memory::MemoryAuditBackend;
use crate::audit::signing::AuditSigner;
use crate::audit::types::{AuditDecision, AuditEntry, AuditReport};

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
    /// Optional signer for ed25519 signatures (Issue #51)
    signer: Option<AuditSigner>,
}

impl std::fmt::Debug for AuditLogger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLogger")
            .field("entry_count", &self.entries.len())
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
            entries: Vec::new(),
            next_id: 1,
            chain_verified: true,
            signer: None,
        }
    }

    /// Creates a new audit logger with signing enabled (Issue #51)
    pub fn new_with_signing() -> Self {
        Self {
            backend: Box::new(MemoryAuditBackend::new()),
            entries: Vec::new(),
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
        // Load existing entries from backend
        let entries = backend.load_all()?;
        let next_id = entries.last().map(|e| e.id + 1).unwrap_or(1);

        let mut logger = Self {
            backend,
            entries,
            next_id,
            chain_verified: false,
            signer: None,
        };

        // Verify chain integrity on startup
        if let Err(e) = logger.verify_chain() {
            tracing::error!("Audit chain verification failed on startup: {:?}", e);
            return Err(AuditError::ChainVerificationFailed(format!("{:?}", e)));
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
            hash: hash.clone(),
            prev_hash,
            signature: self.signer.as_ref().map(|s| s.sign(&hash)), // Sign if signer is available (Issue #51)
            metadata,
        };

        // Persist to backend
        if let Err(e) = self.backend.append(&entry) {
            tracing::error!("Failed to persist audit entry: {:?}", e);
        }

        self.entries.push(entry);
        self.next_id += 1;

        // self.entries.last() should never be None here
        self.entries.last().expect("Entry pushed but not found")
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

    /// Verify all signatures in the chain (Issue #51)
    ///
    /// Requires the public key that was used for signing
    pub fn verify_signatures(&self, public_key_hex: &str) -> Result<(), AuditVerificationError> {
        for entry in &self.entries {
            if let Some(ref signature) = entry.signature {
                match AuditSigner::verify_with_public_key(public_key_hex, &entry.hash, signature) {
                    Ok(true) => continue,
                    Ok(false) => {
                        return Err(AuditVerificationError::InvalidSignature {
                            entry_id: entry.id,
                            reason: "Signature verification failed".to_string(),
                        });
                    }
                    Err(e) => {
                        return Err(AuditVerificationError::InvalidSignature {
                            entry_id: entry.id,
                            reason: format!("Signature verification error: {:?}", e),
                        });
                    }
                }
            }
        }
        Ok(())
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

#[cfg(test)]
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::audit::file::FileAuditBackend;

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
        assert_eq!(
            entry.metadata.as_ref().unwrap()["ip_address"],
            "192.168.1.1"
        );
    }

    #[test]
    fn test_logger_with_signing() {
        let mut logger = AuditLogger::new_with_signing();

        logger.log("agent-1", "read", "/data/a.txt", AuditDecision::Allowed);
        logger.log("agent-2", "write", "/data/b.txt", AuditDecision::Denied);

        // All entries should have signatures
        for entry in logger.entries() {
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
}
