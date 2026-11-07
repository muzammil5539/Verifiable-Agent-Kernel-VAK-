//! Content-Addressable Storage Backend (MEM-003)
//!
//! Provides a content-addressable blob store where data is stored and
//! retrieved using its cryptographic hash (Content ID). This enables:
//! - Deduplication of identical content
//! - Tamper-evident storage
//! - Efficient verification of data integrity
//!
//! # Architecture
//!
//! Data is stored using its SHA-256 hash as the key:
//! 1. Compute hash of content
//! 2. Store content with hash as key
//! 3. Return Content ID (CID) for retrieval
//!
//! # Example
//!
//! ```rust
//! use vak::memory::content_addressable::{ContentAddressableStore, CASConfig};
//!
//! let store = ContentAddressableStore::new(CASConfig::default()).unwrap();
//!
//! // Store content
//! let cid = store.put(b"Hello, World!").unwrap();
//!
//! // Retrieve by CID
//! let data = store.get(&cid).unwrap();
//! assert_eq!(data, b"Hello, World!");
//!
//! // Same content always produces same CID
//! let cid2 = store.put(b"Hello, World!").unwrap();
//! assert_eq!(cid, cid2);
//! ```
//!
//! # Stored blobs
//!
//! A blob is stored raw or gzipped. Reading takes whichever decoding
//! matches its CID, so a reopened file store, which has lost the in-memory
//! metadata saying which it is, still reads its blobs. Decompression is
//! capped, at the content's recorded size when known. Blobs are written to
//! a temporary file and renamed into place, and `put` rewrites a blob that
//! doesn't match its CID instead of deduplicating against it.
//!
//! Metadata and statistics live in memory: a reopened file store serves
//! its blobs, but lists and counts only what it has stored since.
//!
//! # References
//!
//! - Blue Ocean MVP Section 4.1: Immutable Memory Log
//! - Gap Analysis Section 2.3.2: Content-Addressable Knowledge Graph

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, info, warn};

// Error Types

/// Errors that can occur during CAS operations
#[derive(Debug, Error)]
pub enum CASError {
    /// Content not found
    #[error("Content not found for CID: {0}")]
    NotFound(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Hash mismatch (data corruption)
    #[error("Hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// Expected hash
        expected: String,
        /// Actual hash
        actual: String,
    },

    /// Storage full
    #[error("Storage capacity exceeded: {0}")]
    StorageFull(String),

    /// Invalid CID format
    #[error("Invalid CID format: {0}")]
    InvalidCid(String),

    /// Lock error
    #[error("Lock error: {0}")]
    LockError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for CAS operations
pub type CASResult<T> = Result<T, CASError>;

// Content ID

/// Content Identifier - a hash-based address for content
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentId {
    /// The hash algorithm used (currently always SHA-256)
    pub algorithm: HashAlgorithm,
    /// The hash bytes
    pub hash: Vec<u8>,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum HashAlgorithm {
    /// SHA-256 (default)
    #[default]
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
}

impl ContentId {
    /// Create a new ContentId from raw hash bytes
    pub fn new(algorithm: HashAlgorithm, hash: Vec<u8>) -> Self {
        Self { algorithm, hash }
    }

    /// Create a ContentId by hashing data
    pub fn from_data(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        Self {
            algorithm: HashAlgorithm::Sha256,
            hash,
        }
    }

    /// Convert to hex string representation
    pub fn to_hex(&self) -> String {
        hex::encode(&self.hash)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> CASResult<Self> {
        let hash = hex::decode(s).map_err(|e| CASError::InvalidCid(e.to_string()))?;
        Ok(Self {
            algorithm: HashAlgorithm::Sha256,
            hash,
        })
    }

    /// Get the short representation (first 8 chars)
    pub fn short(&self) -> String {
        self.to_hex().chars().take(8).collect()
    }

    /// Verify that data matches this CID
    pub fn verify(&self, data: &[u8]) -> bool {
        let computed = ContentId::from_data(data);
        self.hash == computed.hash
    }
}

impl std::fmt::Display for ContentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "cid:{}", self.to_hex())
    }
}

// Configuration

/// Configuration for Content-Addressable Storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CASConfig {
    /// Storage backend type
    pub backend: CASBackendType,
    /// Base path for file-based storage
    pub base_path: Option<PathBuf>,
    /// Maximum storage size in bytes (0 = unlimited)
    pub max_size: u64,
    /// Enable compression for large blobs
    pub compression: bool,
    /// Compression threshold in bytes
    pub compression_threshold: usize,
    /// Verify content on read
    pub verify_on_read: bool,
    /// Sharding depth for file storage (0-4)
    pub shard_depth: u8,
    /// In-memory cache size
    pub cache_size: usize,
}

/// Backend types for CAS
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CASBackendType {
    /// In-memory (non-persistent)
    Memory,
    /// File-based with sharding
    File,
}

impl Default for CASConfig {
    fn default() -> Self {
        Self {
            backend: CASBackendType::Memory,
            base_path: None,
            max_size: 0, // Unlimited
            compression: true,
            compression_threshold: 1024, // Compress blobs > 1KB
            verify_on_read: true,
            shard_depth: 2,   // 2 levels of sharding
            cache_size: 1000, // Cache 1000 items
        }
    }
}

impl CASConfig {
    /// Create file-based configuration
    pub fn file_based(path: impl Into<PathBuf>) -> Self {
        Self {
            backend: CASBackendType::File,
            base_path: Some(path.into()),
            ..Default::default()
        }
    }

    /// Create memory-based configuration
    pub fn memory() -> Self {
        Self {
            backend: CASBackendType::Memory,
            ..Default::default()
        }
    }

    /// Set maximum storage size
    pub fn with_max_size(mut self, size: u64) -> Self {
        self.max_size = size;
        self
    }

    /// Enable/disable compression
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Set cache size
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }
}

// Content Metadata

/// Metadata about stored content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Content ID
    pub cid: ContentId,
    /// Original size in bytes
    pub size: u64,
    /// Stored size (after compression)
    pub stored_size: u64,
    /// Whether content is compressed
    pub compressed: bool,
    /// Creation timestamp
    pub created_at: u64,
    /// Content type hint (optional)
    pub content_type: Option<String>,
    /// Custom tags
    pub tags: HashMap<String, String>,
}

impl ContentMetadata {
    /// Create new metadata for content
    pub fn new(cid: ContentId, size: u64) -> Self {
        Self {
            cid,
            size,
            stored_size: size,
            compressed: false,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            content_type: None,
            tags: HashMap::new(),
        }
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }

    /// Set content type
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }
}

// Storage Statistics

/// Statistics about the CAS
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CASStats {
    /// Total number of stored items
    pub item_count: u64,
    /// Total size of all content (uncompressed)
    pub total_size: u64,
    /// Total stored size (after compression)
    pub stored_size: u64,
    /// Number of cache hits
    pub cache_hits: u64,
    /// Number of cache misses
    pub cache_misses: u64,
    /// Number of deduplicated stores
    pub deduplications: u64,
    /// Compression ratio (stored/original)
    pub compression_ratio: f64,
}

impl CASStats {
    /// Calculate compression ratio
    pub fn calculate_compression_ratio(&mut self) {
        if self.total_size > 0 {
            self.compression_ratio = self.stored_size as f64 / self.total_size as f64;
        }
    }
}

// Content-Addressable Store Implementation

/// Content-Addressable Storage backend
pub struct ContentAddressableStore {
    /// Configuration
    config: CASConfig,
    /// In-memory storage (for Memory backend or cache)
    memory: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Metadata storage
    metadata: Arc<RwLock<HashMap<String, ContentMetadata>>>,
    /// Statistics
    stats: Arc<RwLock<CASStats>>,
}

impl std::fmt::Debug for ContentAddressableStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentAddressableStore")
            .field("config", &self.config)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl ContentAddressableStore {
    /// Create a new Content-Addressable Store
    pub fn new(config: CASConfig) -> CASResult<Self> {
        // Create directory for file-based storage
        if config.backend == CASBackendType::File {
            if let Some(ref path) = config.base_path {
                fs::create_dir_all(path)?;
                info!(path = %path.display(), "Initialized CAS file storage");
            } else {
                return Err(CASError::ConfigError(
                    "File backend requires base_path".to_string(),
                ));
            }
        }

        Ok(Self {
            config,
            memory: Arc::new(RwLock::new(HashMap::new())),
            metadata: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(CASStats::default())),
        })
    }

    /// Store content and return its CID
    pub fn put(&self, data: &[u8]) -> CASResult<ContentId> {
        let cid = ContentId::from_data(data);
        let hex_key = cid.to_hex();

        // Check if already exists (deduplication). A file at the CID's path
        // that doesn't hold this content (partly written, corrupted, or
        // replaced) is rewritten: deduplicating against it used to leave
        // the content unreadable for good.
        if self.exists(&cid)? {
            if self.holds(&cid) {
                debug!(cid = %cid.short(), "Content already exists, deduplicated");
                if let Ok(mut stats) = self.stats.write() {
                    stats.deduplications += 1;
                }
                return Ok(cid);
            }
            warn!(cid = %cid.short(), "Stored blob doesn't match its CID; rewriting it");
        }

        // Check storage limits
        if self.config.max_size > 0 {
            let stats = self
                .stats
                .read()
                .map_err(|e| CASError::LockError(e.to_string()))?;
            if stats.stored_size + data.len() as u64 > self.config.max_size {
                return Err(CASError::StorageFull(format!(
                    "Would exceed max size of {} bytes",
                    self.config.max_size
                )));
            }
        }

        // Optionally compress
        let (stored_data, compressed) =
            if self.config.compression && data.len() > self.config.compression_threshold {
                match Self::compress(data) {
                    Ok(compressed_data) if compressed_data.len() < data.len() => {
                        (compressed_data, true)
                    }
                    _ => (data.to_vec(), false),
                }
            } else {
                (data.to_vec(), false)
            };

        let stored_size = stored_data.len() as u64;

        // Store based on backend type
        match self.config.backend {
            CASBackendType::Memory => {
                let mut mem = self
                    .memory
                    .write()
                    .map_err(|e| CASError::LockError(e.to_string()))?;
                mem.insert(hex_key.clone(), stored_data);
            }
            CASBackendType::File => {
                let path = self.get_file_path(&hex_key)?;
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                // Written aside and renamed into place, so a crash leaves no
                // partial blob under the CID.
                let partial = path.with_extension("blob.partial");
                let mut file = File::create(&partial)?;
                file.write_all(&stored_data)?;
                file.sync_all()?;
                drop(file);
                fs::rename(&partial, &path)?;
                // A cached copy of what was there before is stale.
                if let Ok(mut mem) = self.memory.write() {
                    mem.remove(&hex_key);
                }
            }
        }

        // Store metadata
        let mut meta = ContentMetadata::new(cid.clone(), data.len() as u64);
        meta.stored_size = stored_size;
        meta.compressed = compressed;

        let mut meta_store = self
            .metadata
            .write()
            .map_err(|e| CASError::LockError(e.to_string()))?;
        let replaced = meta_store.insert(hex_key, meta);
        drop(meta_store);

        // Update stats; a rewritten blob replaces its old entry's counts.
        if let Ok(mut stats) = self.stats.write() {
            if let Some(old) = replaced {
                stats.item_count = stats.item_count.saturating_sub(1);
                stats.total_size = stats.total_size.saturating_sub(old.size);
                stats.stored_size = stats.stored_size.saturating_sub(old.stored_size);
            }
            stats.item_count += 1;
            stats.total_size += data.len() as u64;
            stats.stored_size += stored_size;
            stats.calculate_compression_ratio();
        }

        debug!(cid = %cid.short(), size = data.len(), compressed, "Stored content");
        Ok(cid)
    }

    /// Retrieve content by CID
    pub fn get(&self, cid: &ContentId) -> CASResult<Vec<u8>> {
        let hex_key = cid.to_hex();

        // Try memory/cache first
        let stored_data = match self.config.backend {
            CASBackendType::Memory => {
                let mem = self
                    .memory
                    .read()
                    .map_err(|e| CASError::LockError(e.to_string()))?;
                mem.get(&hex_key)
                    .cloned()
                    .ok_or_else(|| CASError::NotFound(cid.to_hex()))?
            }
            CASBackendType::File => {
                // Check memory cache
                {
                    let mem = self
                        .memory
                        .read()
                        .map_err(|e| CASError::LockError(e.to_string()))?;
                    if let Some(data) = mem.get(&hex_key) {
                        if let Ok(mut stats) = self.stats.write() {
                            stats.cache_hits += 1;
                        }
                        return self.maybe_decompress_and_verify(cid, data.clone());
                    }
                }

                if let Ok(mut stats) = self.stats.write() {
                    stats.cache_misses += 1;
                }

                let path = self.get_file_path(&hex_key)?;
                let mut file = File::open(&path).map_err(|_| CASError::NotFound(cid.to_hex()))?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;

                // Add to cache
                if let Ok(mut mem) = self.memory.write() {
                    if mem.len() < self.config.cache_size {
                        mem.insert(hex_key.clone(), data.clone());
                    }
                }

                data
            }
        };

        self.maybe_decompress_and_verify(cid, stored_data)
    }

    /// Check if content exists
    pub fn exists(&self, cid: &ContentId) -> CASResult<bool> {
        let hex_key = cid.to_hex();

        match self.config.backend {
            CASBackendType::Memory => {
                let mem = self
                    .memory
                    .read()
                    .map_err(|e| CASError::LockError(e.to_string()))?;
                Ok(mem.contains_key(&hex_key))
            }
            CASBackendType::File => {
                let path = self.get_file_path(&hex_key)?;
                Ok(path.exists())
            }
        }
    }

    /// Delete content by CID
    pub fn delete(&self, cid: &ContentId) -> CASResult<()> {
        let hex_key = cid.to_hex();

        // Get metadata for stats update
        let meta = {
            let meta_store = self
                .metadata
                .read()
                .map_err(|e| CASError::LockError(e.to_string()))?;
            meta_store.get(&hex_key).cloned()
        };

        match self.config.backend {
            CASBackendType::Memory => {
                let mut mem = self
                    .memory
                    .write()
                    .map_err(|e| CASError::LockError(e.to_string()))?;
                mem.remove(&hex_key);
            }
            CASBackendType::File => {
                let path = self.get_file_path(&hex_key)?;
                if path.exists() {
                    fs::remove_file(&path)?;
                }
                // Remove from cache
                if let Ok(mut mem) = self.memory.write() {
                    mem.remove(&hex_key);
                }
            }
        }

        // Remove metadata
        if let Ok(mut meta_store) = self.metadata.write() {
            meta_store.remove(&hex_key);
        }

        // Update stats
        if let Some(meta) = meta {
            if let Ok(mut stats) = self.stats.write() {
                stats.item_count = stats.item_count.saturating_sub(1);
                stats.total_size = stats.total_size.saturating_sub(meta.size);
                stats.stored_size = stats.stored_size.saturating_sub(meta.stored_size);
                stats.calculate_compression_ratio();
            }
        }

        debug!(cid = %cid.short(), "Deleted content");
        Ok(())
    }

    /// Get metadata for content
    pub fn get_metadata(&self, cid: &ContentId) -> CASResult<ContentMetadata> {
        let hex_key = cid.to_hex();
        let meta_store = self
            .metadata
            .read()
            .map_err(|e| CASError::LockError(e.to_string()))?;
        meta_store
            .get(&hex_key)
            .cloned()
            .ok_or_else(|| CASError::NotFound(cid.to_hex()))
    }

    /// Get storage statistics
    pub fn stats(&self) -> CASResult<CASStats> {
        let stats = self
            .stats
            .read()
            .map_err(|e| CASError::LockError(e.to_string()))?;
        Ok(stats.clone())
    }

    /// List all stored CIDs
    pub fn list(&self) -> CASResult<Vec<ContentId>> {
        let meta_store = self
            .metadata
            .read()
            .map_err(|e| CASError::LockError(e.to_string()))?;
        let cids: Vec<ContentId> = meta_store.values().map(|m| m.cid.clone()).collect();
        Ok(cids)
    }

    /// Store content with associated metadata
    pub fn put_with_metadata(
        &self,
        data: &[u8],
        content_type: Option<&str>,
        tags: HashMap<String, String>,
    ) -> CASResult<ContentId> {
        let cid = self.put(data)?;
        let hex_key = cid.to_hex();

        // Update metadata
        if let Ok(mut meta_store) = self.metadata.write() {
            if let Some(meta) = meta_store.get_mut(&hex_key) {
                meta.content_type = content_type.map(String::from);
                meta.tags = tags;
            }
        }

        Ok(cid)
    }

    // Helper Methods

    /// Get file path for a given key using sharding
    fn get_file_path(&self, hex_key: &str) -> CASResult<PathBuf> {
        let base =
            self.config.base_path.as_ref().ok_or_else(|| {
                CASError::ConfigError("File backend requires base_path".to_string())
            })?;
        let mut path = base.clone();

        // Shard based on first N characters
        let depth = self.config.shard_depth.min(4) as usize;
        for i in 0..depth {
            if i * 2 < hex_key.len() {
                path.push(&hex_key[i * 2..i * 2 + 2]);
            }
        }

        path.push(format!("{}.blob", hex_key));
        Ok(path)
    }

    /// Compress data using flate2
    fn compress(data: &[u8]) -> CASResult<Vec<u8>> {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data)?;
        Ok(encoder.finish()?)
    }

    /// Decompresses gzip data, refusing more than `limit` bytes of
    /// output. It used to decompress without limit, so a small blob could
    /// expand without bound.
    fn decompress(data: &[u8], limit: u64) -> CASResult<Vec<u8>> {
        use flate2::read::GzDecoder;

        let mut decompressed = Vec::new();
        GzDecoder::new(data)
            .take(limit.saturating_add(1))
            .read_to_end(&mut decompressed)?;
        if decompressed.len() as u64 > limit {
            return Err(CASError::StorageFull(format!(
                "a blob decompresses to more than {limit} bytes"
            )));
        }
        Ok(decompressed)
    }

    /// The most a blob of `stored_len` bytes may decompress to: the
    /// content's recorded size if known, otherwise DEFLATE's largest
    /// expansion (about 1032:1), and never more than `max_size` if set.
    fn decompression_limit(&self, known_size: Option<u64>, stored_len: usize) -> u64 {
        let limit = known_size.unwrap_or_else(|| (stored_len as u64).saturating_mul(1032));
        match self.config.max_size {
            0 => limit,
            max => limit.min(max),
        }
    }

    /// Whether the blob stored under `cid` holds its content.
    fn holds(&self, cid: &ContentId) -> bool {
        let stored = match self.config.backend {
            CASBackendType::Memory => self
                .memory
                .read()
                .ok()
                .and_then(|mem| mem.get(&cid.to_hex()).cloned()),
            CASBackendType::File => self
                .get_file_path(&cid.to_hex())
                .ok()
                .and_then(|path| fs::read(path).ok()),
        };
        stored.is_some_and(|stored| self.decode(cid, stored).is_ok_and(|data| cid.verify(&data)))
    }

    /// The content a stored blob holds: whichever of its raw bytes and its
    /// decompression matches the CID, trying the recorded encoding first.
    /// With neither matching, an error under `verify_on_read`, otherwise the
    /// recorded encoding's bytes.
    fn decode(&self, cid: &ContentId, stored_data: Vec<u8>) -> CASResult<Vec<u8>> {
        let (compressed, known_size) = {
            let meta_store = self
                .metadata
                .read()
                .map_err(|e| CASError::LockError(e.to_string()))?;
            match meta_store.get(&cid.to_hex()) {
                Some(m) => (Some(m.compressed), Some(m.size)),
                None => (None, None),
            }
        };
        if compressed != Some(true) && cid.verify(&stored_data) {
            return Ok(stored_data);
        }
        let limit = self.decompression_limit(known_size, stored_data.len());
        let decompressed = if stored_data.starts_with(&[0x1f, 0x8b]) {
            Self::decompress(&stored_data, limit).ok()
        } else {
            None
        };
        if let Some(data) = decompressed.as_ref().filter(|data| cid.verify(data)) {
            return Ok(data.clone());
        }
        if compressed == Some(true) && cid.verify(&stored_data) {
            return Ok(stored_data);
        }
        if self.config.verify_on_read {
            let actual = ContentId::from_data(decompressed.as_deref().unwrap_or(&stored_data));
            return Err(CASError::HashMismatch {
                expected: cid.to_hex(),
                actual: actual.to_hex(),
            });
        }
        // Unverified reads keep the recorded encoding, as before.
        match (compressed, decompressed) {
            (Some(true), Some(data)) => Ok(data),
            _ => Ok(stored_data),
        }
    }

    /// Decompress if needed and verify hash
    fn maybe_decompress_and_verify(
        &self,
        cid: &ContentId,
        stored_data: Vec<u8>,
    ) -> CASResult<Vec<u8>> {
        self.decode(cid, stored_data)
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_id_creation() {
        let data = b"Hello, World!";
        let cid1 = ContentId::from_data(data);
        let cid2 = ContentId::from_data(data);

        assert_eq!(cid1, cid2);
        assert_eq!(cid1.hash.len(), 32); // SHA-256
    }

    #[test]
    fn test_content_id_hex() {
        let cid = ContentId::from_data(b"test");
        let hex = cid.to_hex();
        let parsed = ContentId::from_hex(&hex).unwrap();

        assert_eq!(cid, parsed);
    }

    #[test]
    fn test_memory_store() {
        let store = ContentAddressableStore::new(CASConfig::memory()).unwrap();

        let data = b"Test content for CAS";
        let cid = store.put(data).unwrap();

        assert!(store.exists(&cid).unwrap());

        let retrieved = store.get(&cid).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn test_deduplication() {
        let store = ContentAddressableStore::new(CASConfig::memory()).unwrap();

        let data = b"Duplicate content";
        let cid1 = store.put(data).unwrap();
        let cid2 = store.put(data).unwrap();

        assert_eq!(cid1, cid2);

        let stats = store.stats().unwrap();
        assert_eq!(stats.deduplications, 1);
    }

    #[test]
    fn test_delete() {
        let store = ContentAddressableStore::new(CASConfig::memory()).unwrap();

        let data = b"Content to delete";
        let cid = store.put(data).unwrap();

        assert!(store.exists(&cid).unwrap());

        store.delete(&cid).unwrap();

        assert!(!store.exists(&cid).unwrap());
    }

    #[test]
    fn test_verification() {
        let cid = ContentId::from_data(b"Original");
        assert!(cid.verify(b"Original"));
        assert!(!cid.verify(b"Modified"));
    }

    fn file_store(dir: &std::path::Path) -> ContentAddressableStore {
        ContentAddressableStore::new(CASConfig::file_based(dir)).unwrap()
    }

    /// Compressible content over the compression threshold.
    fn big() -> Vec<u8> {
        b"abcdefgh".repeat(512)
    }

    #[test]
    fn test_a_reopened_store_reads_compressed_blobs() {
        // Whether a blob was compressed was known only from in-memory
        // metadata, so a reopened store returned gzip bytes, a mismatch.
        let dir = tempfile::tempdir().unwrap();
        let cid = file_store(dir.path()).put(&big()).unwrap();
        let small = file_store(dir.path()).put(b"tiny").unwrap();
        let reopened = file_store(dir.path());
        assert_eq!(reopened.get(&cid).unwrap(), big());
        assert_eq!(reopened.get(&small).unwrap(), b"tiny");
        assert!(
            reopened.list().unwrap().is_empty(),
            "metadata isn't persisted"
        );
        assert!(reopened.get_metadata(&cid).is_err());
    }

    #[test]
    fn test_put_repairs_a_blob_that_does_not_match() {
        // put deduplicated against whatever file was at the CID's path, so
        // a corrupt or partial blob was never rewritten.
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        let cid = store.put(b"original content").unwrap();
        let path = store.get_file_path(&cid.to_hex()).unwrap();
        for damage in [&b"tampered"[..], &b"orig"[..], &b"\x1f\x8bnot gzip"[..]] {
            std::fs::write(&path, damage).unwrap();
            let reopened = file_store(dir.path());
            assert!(matches!(
                reopened.get(&cid),
                Err(CASError::HashMismatch { .. })
            ));
            assert_eq!(reopened.put(b"original content").unwrap(), cid);
            assert_eq!(reopened.get(&cid).unwrap(), b"original content");
            assert_eq!(reopened.stats().unwrap().deduplications, 0);
        }
        // The same store repairs it too, without counting it twice.
        std::fs::write(&path, b"tampered").unwrap();
        assert_eq!(store.put(b"original content").unwrap(), cid);
        let stats = store.stats().unwrap();
        assert_eq!((stats.item_count, stats.total_size), (1, 16));

        // A good blob is deduplicated, not rewritten.
        assert_eq!(store.put(b"original content").unwrap(), cid);
        assert_eq!(store.stats().unwrap().deduplications, 1);
        assert_eq!(store.stats().unwrap().item_count, 1);
        let blobs: Vec<_> = walk(dir.path());
        assert!(blobs.iter().all(|p| !p.ends_with(".partial")), "{blobs:?}");

        // In memory, a stored entry can't be damaged from outside; a cached
        // copy of a rewritten blob isn't served.
        let cached = file_store(dir.path());
        assert_eq!(cached.get(&cid).unwrap(), b"original content");
        std::fs::write(&path, b"tampered").unwrap();
        cached.put(b"original content").unwrap();
        assert_eq!(cached.get(&cid).unwrap(), b"original content");
    }

    fn walk(dir: &std::path::Path) -> Vec<String> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walk(&path));
            } else {
                found.push(path.display().to_string());
            }
        }
        found
    }

    #[test]
    fn test_decompression_is_capped() {
        // Decompression had no limit: a small blob could expand without
        // bound.
        let bomb = ContentAddressableStore::compress(&vec![0u8; 1 << 20]).unwrap();
        assert!(bomb.len() < 4096);
        assert_eq!(
            ContentAddressableStore::decompress(&bomb, 1 << 20)
                .unwrap()
                .len(),
            1 << 20
        );
        assert!(ContentAddressableStore::decompress(&bomb, (1 << 20) - 1).is_err());

        let store = ContentAddressableStore::new(CASConfig::memory()).unwrap();
        assert_eq!(store.decompression_limit(Some(10), 5), 10);
        assert_eq!(store.decompression_limit(None, 5), 5 * 1032);
        let capped = ContentAddressableStore::new(CASConfig::memory().with_max_size(100)).unwrap();
        assert_eq!(capped.decompression_limit(None, 5), 100);

        // A blob swapped for a bomb fails at its recorded size.
        let dir = tempfile::tempdir().unwrap();
        let files = file_store(dir.path());
        let cid = files.put(b"short").unwrap();
        std::fs::write(files.get_file_path(&cid.to_hex()).unwrap(), &bomb).unwrap();
        assert!(files.get(&cid).is_err());
    }

    #[test]
    fn test_unverified_reads_keep_the_recorded_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let config = CASConfig {
            verify_on_read: false,
            ..CASConfig::file_based(dir.path())
        };
        let store = ContentAddressableStore::new(config).unwrap();
        let cid = store.put(&big()).unwrap();
        assert!(store.get_metadata(&cid).unwrap().compressed);
        assert_eq!(store.get(&cid).unwrap(), big());
        let path = store.get_file_path(&cid.to_hex()).unwrap();
        std::fs::write(&path, ContentAddressableStore::compress(b"other").unwrap()).unwrap();
        assert_eq!(store.get(&cid).unwrap(), big(), "the cached copy");
        store.memory.write().unwrap().clear();
        assert_eq!(
            store.get(&cid).unwrap(),
            b"other",
            "unverified: the recorded encoding, decompressed"
        );
        let fresh = ContentAddressableStore::new(CASConfig {
            verify_on_read: false,
            ..CASConfig::file_based(dir.path())
        })
        .unwrap();
        assert!(fresh.get(&cid).is_ok(), "unverified, as configured");
    }

    #[test]
    fn test_store_operations() {
        let dir = tempfile::tempdir().unwrap();
        let store = file_store(dir.path());
        let cid = store
            .put_with_metadata(
                &big(),
                Some("text/plain"),
                HashMap::from([("k".to_string(), "v".to_string())]),
            )
            .unwrap();
        let meta = store.get_metadata(&cid).unwrap();
        assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
        assert!(meta.compressed && meta.stored_size < meta.size);
        assert_eq!(store.list().unwrap(), std::slice::from_ref(&cid));
        let stats = store.stats().unwrap();
        assert!(stats.compression_ratio < 1.0);
        assert_eq!(store.get(&cid).unwrap(), big());
        assert!(store.stats().unwrap().cache_hits + store.stats().unwrap().cache_misses > 0);
        store.delete(&cid).unwrap();
        assert!(!store.exists(&cid).unwrap());
        assert!(matches!(store.get(&cid), Err(CASError::NotFound(_))));
        assert_eq!(store.stats().unwrap().item_count, 0);

        let full = ContentAddressableStore::new(CASConfig::memory().with_max_size(4)).unwrap();
        assert!(matches!(
            full.put(b"too big"),
            Err(CASError::StorageFull(_))
        ));
        assert!(ContentAddressableStore::new(CASConfig {
            backend: CASBackendType::File,
            base_path: None,
            ..CASConfig::default()
        })
        .is_err());
        assert!(ContentId::from_hex("zz").is_err());
        let id = ContentId::from_data(b"x");
        assert_eq!(id.short().len(), 8);
        assert!(id.to_string().contains(&id.short()));
        assert!(!id.verify(b"y"));
        let memory = ContentAddressableStore::new(
            CASConfig::memory()
                .with_compression(false)
                .with_cache_size(1),
        )
        .unwrap();
        let plain = memory.put(&big()).unwrap();
        assert!(!memory.get_metadata(&plain).unwrap().compressed);
        assert!(format!("{memory:?}").contains("ContentAddressableStore"));
    }
}
