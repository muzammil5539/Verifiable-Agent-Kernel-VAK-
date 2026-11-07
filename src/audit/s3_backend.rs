//! S3 Backend for Cloud Audit Log Archival
//!
//! **Uploads are not implemented.** The backend buffers entries in memory
//! and builds the objects it would write, but it can't sign a request (AWS
//! Signature V4), so it sends nothing. Every flush fails, saying so, and
//! keeps the entries buffered (finding K12). It used to report each upload
//! as done and drop the entries.
//!
//! An [`AuditLogger`](crate::audit::AuditLogger) rotating into this backend
//! therefore keeps the entries it couldn't archive, rather than losing them.
//!
//! What works:
//! - buffering, with a local cache that answers queries;
//! - batching thresholds (`maybe_flush`);
//! - object keys, JSONL and gzip bodies, storage-class and encryption
//!   headers: the request a signer would send.
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::audit::s3_backend::{S3AuditBackend, S3Config};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let config = S3Config::new("my-audit-bucket", "us-east-1");
//! let backend = S3AuditBackend::new(config).await?;
//! # Ok(())
//! # }
//! ```

use crate::audit::{AuditBackend, AuditEntry, AuditError};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Configuration

/// Configuration for S3 audit backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3Config {
    /// S3 bucket name
    pub bucket: String,
    /// AWS region
    pub region: String,
    /// Object key prefix (e.g., "audit-logs/")
    pub key_prefix: String,
    /// Access key ID (optional, uses IAM role if not set)
    pub access_key_id: Option<String>,
    /// Secret access key (optional, uses IAM role if not set)
    pub secret_access_key: Option<String>,
    /// Custom endpoint URL (for S3-compatible storage)
    pub endpoint_url: Option<String>,
    /// Enable gzip compression
    pub compression: bool,
    /// Batch size before uploading
    pub batch_size: usize,
    /// Maximum time to wait before flushing (seconds)
    pub flush_interval_secs: u64,
    /// Storage class (STANDARD, STANDARD_IA, GLACIER, etc.)
    pub storage_class: String,
    /// Enable server-side encryption
    pub server_side_encryption: bool,
    /// KMS key ID for encryption (optional)
    pub kms_key_id: Option<String>,
}

impl S3Config {
    /// Create a new S3 configuration
    pub fn new(bucket: impl Into<String>, region: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            key_prefix: "audit-logs/".to_string(),
            access_key_id: None,
            secret_access_key: None,
            endpoint_url: None,
            compression: true,
            batch_size: 1000,
            flush_interval_secs: 300,
            storage_class: "STANDARD".to_string(),
            server_side_encryption: true,
            kms_key_id: None,
        }
    }

    /// Set object key prefix
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Set AWS credentials
    pub fn with_credentials(
        mut self,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        self.access_key_id = Some(access_key_id.into());
        self.secret_access_key = Some(secret_access_key.into());
        self
    }

    /// Set custom endpoint (for MinIO, LocalStack, etc.)
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint_url = Some(endpoint.into());
        self
    }

    /// Set batch size
    pub fn with_batch_size(mut self, size: usize) -> Self {
        self.batch_size = size;
        self
    }

    /// Set storage class
    pub fn with_storage_class(mut self, class: impl Into<String>) -> Self {
        self.storage_class = class.into();
        self
    }

    /// Set KMS key for encryption
    pub fn with_kms_key(mut self, key_id: impl Into<String>) -> Self {
        self.kms_key_id = Some(key_id.into());
        self.server_side_encryption = true;
        self
    }

    /// Disable compression
    pub fn without_compression(mut self) -> Self {
        self.compression = false;
        self
    }
}

// S3 Audit Backend

/// S3-based audit backend for cloud archival
///
/// Buffers entries for upload to S3. Uploads aren't implemented, so every
/// flush fails and keeps the buffer; see the module docs.
pub struct S3AuditBackend {
    config: S3Config,
    /// Buffered entries waiting to be uploaded
    buffer: Mutex<VecDeque<AuditEntry>>,
    /// HTTP client for S3 API calls
    client: reqwest::Client,
    /// Last flush timestamp
    last_flush: RwLock<SystemTime>,
    /// Upload counter for unique object names
    upload_counter: std::sync::atomic::AtomicU64,
    /// Local cache of recent entries
    local_cache: RwLock<Vec<AuditEntry>>,
    /// Maximum local cache size
    max_cache_size: usize,
}

impl S3AuditBackend {
    /// Create a new S3 audit backend
    pub async fn new(config: S3Config) -> Result<Self, AuditError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AuditError::BackendNotAvailable(format!("HTTP client error: {}", e)))?;

        Ok(Self {
            config,
            buffer: Mutex::new(VecDeque::new()),
            client,
            last_flush: RwLock::new(SystemTime::now()),
            upload_counter: std::sync::atomic::AtomicU64::new(0),
            local_cache: RwLock::new(Vec::new()),
            max_cache_size: 10000,
        })
    }

    /// Generate S3 object key for current batch
    fn generate_object_key(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let counter = self
            .upload_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let date = chrono::Utc::now().format("%Y/%m/%d");
        let extension = if self.config.compression {
            "jsonl.gz"
        } else {
            "jsonl"
        };

        format!(
            "{}{}/audit_{}_{}.{}",
            self.config.key_prefix, date, timestamp, counter, extension
        )
    }

    /// Compress entries to gzip format
    fn compress_entries(&self, entries: &[AuditEntry]) -> Result<Vec<u8>, AuditError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());

        for entry in entries {
            let json = serde_json::to_string(entry)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            writeln!(encoder, "{}", json).map_err(AuditError::IoError)?;
        }

        encoder.finish().map_err(AuditError::IoError)
    }

    /// Serialize entries to JSONL format
    fn serialize_entries(&self, entries: &[AuditEntry]) -> Result<Vec<u8>, AuditError> {
        let mut output = Vec::new();

        for entry in entries {
            let json = serde_json::to_string(entry)
                .map_err(|e| AuditError::SerializationError(e.to_string()))?;
            writeln!(output, "{}", json).map_err(AuditError::IoError)?;
        }

        Ok(output)
    }

    /// Upload batch to S3. Always an error for now: see the module docs.
    async fn upload_batch(&self, entries: &[AuditEntry]) -> Result<String, AuditError> {
        if entries.is_empty() {
            return Ok(String::new());
        }

        let object_key = self.generate_object_key();

        let body = if self.config.compression {
            self.compress_entries(entries)?
        } else {
            self.serialize_entries(entries)?
        };

        // Build S3 PUT URL
        let url = if let Some(ref endpoint) = self.config.endpoint_url {
            format!("{}/{}/{}", endpoint, self.config.bucket, object_key)
        } else {
            format!(
                "https://{}.s3.{}.amazonaws.com/{}",
                self.config.bucket, self.config.region, object_key
            )
        };

        // Build request
        let mut request = self
            .client
            .put(&url)
            .body(body)
            .header("Content-Type", "application/x-ndjson");

        // Add storage class
        request = request.header("x-amz-storage-class", &self.config.storage_class);

        // Add encryption headers
        if self.config.server_side_encryption {
            request = if let Some(ref kms_key) = self.config.kms_key_id {
                request
                    .header("x-amz-server-side-encryption", "aws:kms")
                    .header("x-amz-server-side-encryption-aws-kms-key-id", kms_key)
            } else {
                request.header("x-amz-server-side-encryption", "AES256")
            };
        }

        // The request is complete but for its signature. Without AWS
        // Signature V4, S3 would refuse it, so it isn't sent. This used to
        // log "upload simulated" and report the entries as stored.
        drop(request);
        Err(not_uploaded(
            entries.len(),
            &format!("s3://{}/{object_key}", self.config.bucket),
        ))
    }

    /// Check if flush is needed based on buffer size or time
    fn should_flush(&self) -> bool {
        // Check buffer size
        let buffer_size = self.buffer.lock().map(|b| b.len()).unwrap_or(0);
        if buffer_size >= self.config.batch_size {
            return true;
        }

        // Check time since last flush
        let last_flush = self.last_flush.read().ok().map(|t| *t);
        if let Some(last) = last_flush {
            let elapsed = SystemTime::now().duration_since(last).unwrap_or_default();
            if elapsed.as_secs() >= self.config.flush_interval_secs {
                return true;
            }
        }

        false
    }

    /// Flush buffer to S3 if needed.
    ///
    /// # Errors
    ///
    /// As [`S3AuditBackend::flush_async`], whenever a flush is due.
    pub async fn maybe_flush(&self) -> Result<Option<String>, AuditError> {
        if !self.should_flush() {
            return Ok(None);
        }

        self.flush_async().await.map(Some)
    }

    /// Uploads the buffered entries, and empties the buffer only if they
    /// were stored. With nothing buffered, `Ok("")`.
    ///
    /// # Errors
    ///
    /// [`AuditError::BackendNotAvailable`] for any buffered entries: uploads
    /// aren't implemented. The entries stay buffered.
    pub async fn flush_async(&self) -> Result<String, AuditError> {
        let entries: Vec<AuditEntry> = {
            let buffer = self
                .buffer
                .lock()
                .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;
            buffer.iter().cloned().collect()
        };

        if entries.is_empty() {
            return Ok(String::new());
        }

        // Update last flush time
        {
            let mut last_flush = self
                .last_flush
                .write()
                .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;
            *last_flush = SystemTime::now();
        }

        let key = self.upload_batch(&entries).await?;
        // Stored: drop exactly what was uploaded. Entries appended meanwhile
        // stay.
        if let Ok(mut buffer) = self.buffer.lock() {
            let stored = entries.len().min(buffer.len());
            buffer.drain(..stored);
        }
        Ok(key)
    }

    /// Add entry to local cache
    fn add_to_cache(&self, entry: &AuditEntry) {
        if let Ok(mut cache) = self.local_cache.write() {
            cache.push(entry.clone());

            // Trim cache if too large
            if cache.len() > self.max_cache_size {
                let drain_count = cache.len() - self.max_cache_size;
                cache.drain(0..drain_count);
            }
        }
    }
}

impl std::fmt::Debug for S3AuditBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3AuditBackend")
            .field("bucket", &self.config.bucket)
            .field("region", &self.config.region)
            .field("prefix", &self.config.key_prefix)
            .field("batch_size", &self.config.batch_size)
            .field("compression", &self.config.compression)
            .finish()
    }
}

impl AuditBackend for S3AuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditError> {
        // Add to buffer
        {
            let mut buffer = self
                .buffer
                .lock()
                .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;
            buffer.push_back(entry.clone());
        }

        // Add to local cache for queries
        self.add_to_cache(entry);

        // Note: In async context, call maybe_flush() separately
        // For sync interface, we just buffer
        Ok(())
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditError> {
        // Since append() adds to both buffer and cache, just use cache
        // to avoid duplicating entries
        let cache = self
            .local_cache
            .read()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        let mut entries = cache.clone();
        entries.sort_by_key(|e| e.id);
        Ok(entries)
    }

    fn get_last(&self) -> Result<Option<AuditEntry>, AuditError> {
        // Check buffer first
        if let Ok(buffer) = self.buffer.lock() {
            if let Some(entry) = buffer.back() {
                return Ok(Some(entry.clone()));
            }
        }

        // Fall back to cache
        let cache = self
            .local_cache
            .read()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        Ok(cache.last().cloned())
    }

    fn count(&self) -> Result<u64, AuditError> {
        // Buffer and cache can have overlapping entries, so use cache as the source of truth
        // since append() adds to both. Buffer entries are always in cache too.
        let cache_count = self.local_cache.read().map(|c| c.len()).unwrap_or(0);

        Ok(cache_count as u64)
    }

    /// Fails while anything is buffered: buffered entries aren't stored.
    /// This used to return `Ok` without uploading, so a caller (such as
    /// `AuditLogger` rotation) took the entries for archived.
    fn flush(&mut self) -> Result<(), AuditError> {
        let pending = self
            .buffer
            .lock()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?
            .len();
        if pending == 0 {
            return Ok(());
        }
        Err(not_uploaded(
            pending,
            &format!("s3://{}", self.config.bucket),
        ))
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

    fn for_each_entry(
        &self,
        f: &mut dyn FnMut(&AuditEntry) -> Result<(), AuditError>,
    ) -> Result<(), AuditError> {
        let cache = self
            .local_cache
            .read()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        for entry in cache.iter() {
            f(entry)?;
        }
        Ok(())
    }

    fn get_entry(&self, id: u64) -> Result<Option<AuditEntry>, AuditError> {
        let cache = self
            .local_cache
            .read()
            .map_err(|e| AuditError::BackendNotAvailable(format!("Lock error: {}", e)))?;

        Ok(cache.iter().find(|e| e.id == id).cloned())
    }
}

/// The error for entries this backend can't upload.
pub(crate) fn not_uploaded(count: usize, destination: &str) -> AuditError {
    AuditError::BackendNotAvailable(format!(
        "S3 uploads aren't implemented (requests can't be signed with AWS Signature V4), so \
         {count} entries for {destination} were not stored; they stay buffered"
    ))
}

// S3 Object Listing (for archive queries)

/// Represents an archived audit log object in S3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedAuditObject {
    /// S3 object key
    pub key: String,
    /// Object size in bytes
    pub size: u64,
    /// Last modified timestamp
    pub last_modified: u64,
    /// Storage class
    pub storage_class: String,
    /// Whether object is compressed
    pub compressed: bool,
}

/// Query parameters for listing archived objects
#[derive(Debug, Clone, Default)]
pub struct ArchiveQuery {
    /// Start date (inclusive)
    pub start_date: Option<chrono::NaiveDate>,
    /// End date (inclusive)
    pub end_date: Option<chrono::NaiveDate>,
    /// Maximum results to return
    pub max_results: Option<usize>,
}

impl ArchiveQuery {
    /// Create a query for a date range
    pub fn date_range(start: chrono::NaiveDate, end: chrono::NaiveDate) -> Self {
        Self {
            start_date: Some(start),
            end_date: Some(end),
            max_results: None,
        }
    }

    /// Set maximum results
    pub fn with_max_results(mut self, max: usize) -> Self {
        self.max_results = Some(max);
        self
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditDecision, AuditLogger, RotationConfig};

    fn create_test_entry(id: u64, agent_id: &str) -> AuditEntry {
        AuditEntry {
            id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            agent_id: agent_id.to_string(),
            action: "test_action".to_string(),
            resource: "/test/resource".to_string(),
            decision: AuditDecision::Allowed,
            hash: format!("hash_{}", id),
            prev_hash: format!("prev_hash_{}", id.saturating_sub(1)),
            signature: None,
            metadata: None,
        }
    }

    #[test]
    fn test_s3_config_builder() {
        let config = S3Config::new("my-bucket", "us-west-2")
            .with_prefix("logs/audit/")
            .with_batch_size(500)
            .with_storage_class("STANDARD_IA")
            .with_kms_key("arn:aws:kms:us-west-2:123456789012:key/my-key");

        assert_eq!(config.bucket, "my-bucket");
        assert_eq!(config.region, "us-west-2");
        assert_eq!(config.key_prefix, "logs/audit/");
        assert_eq!(config.batch_size, 500);
        assert_eq!(config.storage_class, "STANDARD_IA");
        assert!(config.kms_key_id.is_some());
        assert!(config.server_side_encryption);
    }

    #[test]
    fn test_object_key_generation() {
        let config = S3Config::new("test-bucket", "us-east-1").with_prefix("audit/");

        let backend = tokio_test::block_on(S3AuditBackend::new(config)).unwrap();

        let key1 = backend.generate_object_key();
        let key2 = backend.generate_object_key();

        // Keys should be unique
        assert_ne!(key1, key2);

        // Keys should have proper prefix and extension
        assert!(key1.starts_with("audit/"));
        assert!(key1.ends_with(".jsonl.gz"));
    }

    #[test]
    fn test_entry_serialization() {
        let config = S3Config::new("test-bucket", "us-east-1").without_compression();

        let backend = tokio_test::block_on(S3AuditBackend::new(config)).unwrap();

        let entries = vec![
            create_test_entry(1, "agent-1"),
            create_test_entry(2, "agent-2"),
        ];

        let serialized = backend.serialize_entries(&entries).unwrap();
        let content = String::from_utf8(serialized).unwrap();

        // Should be JSONL format
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Each line should be valid JSON
        for line in lines {
            let _: AuditEntry = serde_json::from_str(line).unwrap();
        }
    }

    #[test]
    fn test_entry_compression() {
        let config = S3Config::new("test-bucket", "us-east-1");

        let backend = tokio_test::block_on(S3AuditBackend::new(config)).unwrap();

        let entries = vec![
            create_test_entry(1, "agent-1"),
            create_test_entry(2, "agent-2"),
            create_test_entry(3, "agent-3"),
        ];

        let uncompressed = backend.serialize_entries(&entries).unwrap();
        let compressed = backend.compress_entries(&entries).unwrap();

        // Compressed should be smaller
        assert!(compressed.len() < uncompressed.len());
    }

    #[test]
    fn test_buffer_and_cache() {
        let config = S3Config::new("test-bucket", "us-east-1").with_batch_size(100);

        let mut backend = tokio_test::block_on(S3AuditBackend::new(config)).unwrap();

        // Add entries
        for i in 0..10 {
            let entry = create_test_entry(i, "agent-test");
            backend.append(&entry).unwrap();
        }

        // Should be in buffer
        assert_eq!(backend.count().unwrap(), 10);

        // Query should return entries from cache
        let all = backend.load_all().unwrap();
        assert_eq!(all.len(), 10);

        // Query by agent should work
        let agent_entries = backend.get_by_agent("agent-test").unwrap();
        assert_eq!(agent_entries.len(), 10);
    }

    #[test]
    fn test_should_flush_by_size() {
        let config = S3Config::new("test-bucket", "us-east-1").with_batch_size(5);

        let mut backend = tokio_test::block_on(S3AuditBackend::new(config)).unwrap();

        // Add less than batch size
        for i in 0..4 {
            backend.append(&create_test_entry(i, "agent")).unwrap();
        }
        assert!(!backend.should_flush());

        // Add to reach batch size
        backend.append(&create_test_entry(4, "agent")).unwrap();
        assert!(backend.should_flush());
    }

    fn buffered(entries: u64) -> S3AuditBackend {
        let mut backend = tokio_test::block_on(S3AuditBackend::new(
            S3Config::new("test-bucket", "us-east-1").with_batch_size(2),
        ))
        .unwrap();
        for i in 0..entries {
            backend.append(&create_test_entry(i, "agent")).unwrap();
        }
        backend
    }

    #[test]
    fn test_a_flush_fails_and_keeps_the_entries() {
        // Uploads were simulated: the entries were drained and reported
        // stored, though nothing was sent.
        let backend = buffered(3);
        let err = tokio_test::block_on(backend.flush_async()).unwrap_err();
        assert!(err.to_string().contains("not stored"), "{err}");
        assert!(err.to_string().contains("3 entries"), "{err}");
        assert_eq!(
            backend.buffer.lock().unwrap().len(),
            3,
            "nothing was dropped"
        );
        assert!(
            tokio_test::block_on(backend.maybe_flush()).is_err(),
            "a due flush fails too"
        );
        assert_eq!(backend.get_last().unwrap().unwrap().id, 2);

        let empty = buffered(0);
        assert_eq!(tokio_test::block_on(empty.flush_async()).unwrap(), "");
        assert_eq!(
            tokio_test::block_on(empty.maybe_flush()).unwrap(),
            None,
            "nothing due"
        );
        assert!(format!("{empty:?}").contains("test-bucket"));
    }

    #[test]
    fn test_a_sync_flush_fails_while_anything_is_buffered() {
        let mut backend = buffered(1);
        assert!(backend.flush().is_err());
        assert!(buffered(0).flush().is_ok());
    }

    #[test]
    fn test_rotating_into_s3_keeps_what_it_could_not_archive() {
        // The failure that mattered: rotation appends to its archive, then
        // flushes, and evicts only if the flush succeeds. A flush that
        // claimed success evicted entries that were never stored anywhere.
        let mut logger = AuditLogger::new();
        logger.set_rotation(RotationConfig::with_archival(5, Box::new(buffered(0))));
        for i in 0..12 {
            logger
                .log(format!("agent-{i}"), "read", "/r", AuditDecision::Allowed)
                .unwrap();
        }
        assert_eq!(logger.count().unwrap(), 12, "nothing lost");
        assert_eq!(logger.rotated_count(), 0);
        logger.verify_chain().unwrap();
    }

    #[test]
    fn test_queries_answer_from_the_cache() {
        let backend = buffered(4);
        assert_eq!(backend.get_entry(2).unwrap().unwrap().id, 2);
        assert!(backend.get_entry(99).unwrap().is_none());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(backend.get_by_time_range(0, now + 1).unwrap().len(), 4);
        assert!(backend.get_by_time_range(0, 1).unwrap().is_empty());
        let mut seen = 0;
        backend
            .for_each_entry(&mut |_| {
                seen += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(seen, 4);

        let query = ArchiveQuery::date_range(
            chrono::NaiveDate::from_ymd_opt(2026, 1, 1).unwrap(),
            chrono::NaiveDate::from_ymd_opt(2026, 1, 31).unwrap(),
        )
        .with_max_results(10);
        assert_eq!(query.max_results, Some(10));
    }

    #[test]
    fn test_an_endpoint_and_credentials_configure_the_backend() {
        let config = S3Config::new("b", "eu-west-1")
            .with_endpoint("http://localhost:9000")
            .with_credentials("AKIA", "secret")
            .without_compression();
        assert_eq!(
            config.endpoint_url.as_deref(),
            Some("http://localhost:9000")
        );
        assert!(config.access_key_id.is_some() && !config.compression);
        let backend = tokio_test::block_on(S3AuditBackend::new(config)).unwrap();
        assert!(backend.generate_object_key().ends_with(".jsonl"));
    }
}
