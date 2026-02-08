use crate::audit::backend::AuditBackend;
use crate::audit::error::AuditError;
use crate::audit::types::AuditEntry;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::AuditDecision;

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
}
