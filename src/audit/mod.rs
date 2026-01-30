//! Cryptographic Audit Logging Module
//! 
//! Provides tamper-evident, hash-chained audit logging for agent actions.

use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a single audit log entry with cryptographic chaining
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: u64,
    pub timestamp: u64,
    pub agent_id: String,
    pub action: String,
    pub resource: String,
    pub decision: AuditDecision,
    pub hash: String,
    pub prev_hash: String,
}

/// Decision outcome for an audited action
#[derive(Debug, Clone, PartialEq)]
pub enum AuditDecision {
    Allowed,
    Denied,
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

/// Cryptographic audit logger with hash-chained entries
pub struct AuditLogger {
    entries: Vec<AuditEntry>,
    next_id: u64,
}

impl AuditLogger {
    /// Creates a new audit logger with genesis hash
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 1,
        }
    }

    /// Logs an action with cryptographic hash chaining
    pub fn log(
        &mut self,
        agent_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        decision: AuditDecision,
    ) -> &AuditEntry {
        let agent_id = agent_id.into();
        let action = action.into();
        let resource = resource.into();
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let prev_hash = self.entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64)); // Genesis hash

        let hash = self.compute_hash(
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
        };

        self.entries.push(entry);
        self.next_id += 1;

        self.entries.last().unwrap()
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
            let computed_hash = self.compute_hash(
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
        let allowed_count = self.entries.iter()
            .filter(|e| e.decision == AuditDecision::Allowed)
            .count();
        let denied_count = self.entries.iter()
            .filter(|e| e.decision == AuditDecision::Denied)
            .count();
        let error_count = self.entries.iter()
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

    /// Computes SHA-256 hash for an entry
    fn compute_hash(
        &self,
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
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

/// Error types for audit chain verification
#[derive(Debug)]
pub enum AuditVerificationError {
    BrokenChain {
        entry_id: u64,
        expected: String,
        found: String,
    },
    InvalidHash {
        entry_id: u64,
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for AuditVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BrokenChain { entry_id, expected, found } => {
                write!(f, "Broken chain at entry {}: expected prev_hash {}, found {}", 
                    entry_id, expected, found)
            }
            Self::InvalidHash { entry_id, expected, found } => {
                write!(f, "Invalid hash at entry {}: expected {}, found {}", 
                    entry_id, expected, found)
            }
        }
    }
}

impl std::error::Error for AuditVerificationError {}

/// Compliance report generated from audit log
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub total_entries: usize,
    pub allowed_count: usize,
    pub denied_count: usize,
    pub error_count: usize,
    pub chain_valid: bool,
    pub first_timestamp: Option<u64>,
    pub last_timestamp: Option<u64>,
    pub entries: Vec<AuditEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
