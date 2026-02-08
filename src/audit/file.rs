use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::audit::backend::AuditBackend;
use crate::audit::error::AuditError;
use crate::audit::types::AuditEntry;

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
        Ok(self.file_handle.as_mut().unwrap())
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use crate::audit::types::AuditDecision;

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
}
