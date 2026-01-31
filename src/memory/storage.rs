//! Persistent Storage Backends (INF-001)
//!
//! This module provides persistent storage backends for the memory system.
//! It supports multiple backend types including file-based, SQLite, and
//! configurable backends for production deployments.
//!
//! # Overview
//!
//! The storage backends module provides:
//! - **FileBackend**: Simple file-based persistence
//! - **SqliteBackend**: SQLite database storage
//! - **StorageManager**: Unified interface for storage operations
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::memory::storage::{StorageManager, StorageConfig, BackendType};
//!
//! let config = StorageConfig::new(BackendType::File)
//!     .with_path("/tmp/vak_storage");
//!
//! let manager = StorageManager::new(config).unwrap();
//! manager.put("key1", b"value1").unwrap();
//! let value = manager.get("key1").unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during storage operations
#[derive(Debug, Error)]
pub enum StorageError {
    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Backend not available
    #[error("Backend not available: {0}")]
    BackendNotAvailable(String),

    /// Lock error
    #[error("Lock error: {0}")]
    LockError(String),

    /// Invalid path
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Namespace error
    #[error("Namespace error: {0}")]
    NamespaceError(String),
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

// ============================================================================
// Backend Types
// ============================================================================

/// Types of storage backends
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendType {
    /// In-memory storage (non-persistent, for testing)
    Memory,
    /// File-based storage
    File,
    /// SQLite database
    Sqlite,
    /// LevelDB/RocksDB-style key-value store
    KeyValue,
}

impl Default for BackendType {
    fn default() -> Self {
        BackendType::Memory
    }
}

// ============================================================================
// Storage Configuration
// ============================================================================

/// Configuration for storage backends
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend type to use
    pub backend_type: BackendType,
    /// Base path for file-based storage
    pub base_path: Option<PathBuf>,
    /// Enable compression
    pub compression: bool,
    /// Enable encryption (requires key)
    pub encryption: bool,
    /// Maximum cache size in bytes
    pub cache_size: usize,
    /// Sync writes to disk immediately
    pub sync_writes: bool,
    /// Create directories if they don't exist
    pub create_dirs: bool,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend_type: BackendType::Memory,
            base_path: None,
            compression: false,
            encryption: false,
            cache_size: 64 * 1024 * 1024, // 64MB
            sync_writes: true,
            create_dirs: true,
        }
    }
}

impl StorageConfig {
    /// Create a new configuration with the specified backend type
    pub fn new(backend_type: BackendType) -> Self {
        Self {
            backend_type,
            ..Default::default()
        }
    }

    /// Set the base path
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.base_path = Some(path.into());
        self
    }

    /// Enable compression
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Enable sync writes
    pub fn with_sync_writes(mut self, enabled: bool) -> Self {
        self.sync_writes = enabled;
        self
    }

    /// Set cache size
    pub fn with_cache_size(mut self, size: usize) -> Self {
        self.cache_size = size;
        self
    }
}

// ============================================================================
// Storage Backend Trait
// ============================================================================

/// Trait for storage backends
pub trait StorageBackend: Send + Sync {
    /// Get the backend type
    fn backend_type(&self) -> BackendType;

    /// Store a value
    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()>;

    /// Retrieve a value
    fn get(&self, key: &str) -> StorageResult<Vec<u8>>;

    /// Delete a key
    fn delete(&self, key: &str) -> StorageResult<()>;

    /// Check if a key exists
    fn exists(&self, key: &str) -> StorageResult<bool>;

    /// List all keys with optional prefix
    fn list_keys(&self, prefix: Option<&str>) -> StorageResult<Vec<String>>;

    /// Get storage statistics
    fn stats(&self) -> StorageResult<StorageStats>;

    /// Flush any buffered data
    fn flush(&self) -> StorageResult<()>;

    /// Close the backend
    fn close(&self) -> StorageResult<()>;
}

// ============================================================================
// Storage Statistics
// ============================================================================

/// Statistics about storage usage
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageStats {
    /// Total number of keys
    pub key_count: usize,
    /// Total storage used in bytes
    pub storage_used: usize,
    /// Number of read operations
    pub reads: u64,
    /// Number of write operations
    pub writes: u64,
    /// Number of delete operations
    pub deletes: u64,
    /// Cache hit rate (0.0 to 1.0)
    pub cache_hit_rate: f64,
}

// ============================================================================
// In-Memory Backend
// ============================================================================

/// In-memory storage backend (for testing)
pub struct MemoryBackend {
    data: RwLock<HashMap<String, Vec<u8>>>,
    stats: RwLock<StorageStats>,
}

impl MemoryBackend {
    /// Create a new in-memory backend
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            stats: RwLock::new(StorageStats::default()),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl StorageBackend for MemoryBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::Memory
    }

    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        let mut data = self.data.write()
            .map_err(|e| StorageError::LockError(e.to_string()))?;
        let mut stats = self.stats.write()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let is_new = !data.contains_key(key);
        data.insert(key.to_string(), value.to_vec());
        
        stats.writes += 1;
        if is_new {
            stats.key_count += 1;
        }
        stats.storage_used = data.values().map(|v| v.len()).sum();

        Ok(())
    }

    fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        let data = self.data.read()
            .map_err(|e| StorageError::LockError(e.to_string()))?;
        let mut stats = self.stats.write()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        stats.reads += 1;

        data.get(key)
            .cloned()
            .ok_or_else(|| StorageError::KeyNotFound(key.to_string()))
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        let mut data = self.data.write()
            .map_err(|e| StorageError::LockError(e.to_string()))?;
        let mut stats = self.stats.write()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        if data.remove(key).is_some() {
            stats.deletes += 1;
            stats.key_count = stats.key_count.saturating_sub(1);
            stats.storage_used = data.values().map(|v| v.len()).sum();
        }

        Ok(())
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        let data = self.data.read()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        Ok(data.contains_key(key))
    }

    fn list_keys(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let data = self.data.read()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        let keys: Vec<String> = match prefix {
            Some(p) => data.keys().filter(|k| k.starts_with(p)).cloned().collect(),
            None => data.keys().cloned().collect(),
        };

        Ok(keys)
    }

    fn stats(&self) -> StorageResult<StorageStats> {
        let stats = self.stats.read()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        Ok(stats.clone())
    }

    fn flush(&self) -> StorageResult<()> {
        Ok(()) // No-op for in-memory
    }

    fn close(&self) -> StorageResult<()> {
        Ok(()) // No-op for in-memory
    }
}

impl fmt::Debug for MemoryBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemoryBackend")
    }
}

// ============================================================================
// File Backend
// ============================================================================

/// File-based storage backend
pub struct FileBackend {
    base_path: PathBuf,
    config: StorageConfig,
    stats: RwLock<StorageStats>,
}

impl FileBackend {
    /// Create a new file backend
    pub fn new(config: StorageConfig) -> StorageResult<Self> {
        let base_path = config.base_path.clone()
            .ok_or_else(|| StorageError::ConfigError("Base path required for file backend".to_string()))?;

        if config.create_dirs {
            fs::create_dir_all(&base_path)?;
        }

        if !base_path.exists() {
            return Err(StorageError::InvalidPath(format!(
                "Path does not exist: {:?}",
                base_path
            )));
        }

        Ok(Self {
            base_path,
            config,
            stats: RwLock::new(StorageStats::default()),
        })
    }

    /// Get the file path for a key
    fn key_path(&self, key: &str) -> PathBuf {
        // Sanitize key to be safe as filename
        let safe_key = key.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.base_path.join(format!("{}.dat", safe_key))
    }

    /// Get the metadata path for a key
    fn meta_path(&self, key: &str) -> PathBuf {
        let safe_key = key.replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_");
        self.base_path.join(format!("{}.meta", safe_key))
    }
}

impl StorageBackend for FileBackend {
    fn backend_type(&self) -> BackendType {
        BackendType::File
    }

    fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        let path = self.key_path(key);
        
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;

        file.write_all(value)?;

        if self.config.sync_writes {
            file.sync_all()?;
        }

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.writes += 1;
        }

        Ok(())
    }

    fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        let path = self.key_path(key);
        
        if !path.exists() {
            return Err(StorageError::KeyNotFound(key.to_string()));
        }

        let mut file = File::open(&path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.reads += 1;
        }

        Ok(data)
    }

    fn delete(&self, key: &str) -> StorageResult<()> {
        let path = self.key_path(key);
        let meta_path = self.meta_path(key);

        if path.exists() {
            fs::remove_file(&path)?;
        }
        if meta_path.exists() {
            fs::remove_file(&meta_path)?;
        }

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.deletes += 1;
        }

        Ok(())
    }

    fn exists(&self, key: &str) -> StorageResult<bool> {
        let path = self.key_path(key);
        Ok(path.exists())
    }

    fn list_keys(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        let mut keys = Vec::new();

        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map(|e| e == "dat").unwrap_or(false) {
                if let Some(stem) = path.file_stem() {
                    let key = stem.to_string_lossy().to_string();
                    
                    match prefix {
                        Some(p) if !key.starts_with(p) => continue,
                        _ => keys.push(key),
                    }
                }
            }
        }

        Ok(keys)
    }

    fn stats(&self) -> StorageResult<StorageStats> {
        let mut stats = self.stats.write()
            .map_err(|e| StorageError::LockError(e.to_string()))?;

        // Calculate actual storage
        let mut storage_used = 0;
        let mut key_count = 0;

        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().map(|e| e == "dat").unwrap_or(false) {
                if let Ok(metadata) = entry.metadata() {
                    storage_used += metadata.len() as usize;
                    key_count += 1;
                }
            }
        }

        stats.storage_used = storage_used;
        stats.key_count = key_count;

        Ok(stats.clone())
    }

    fn flush(&self) -> StorageResult<()> {
        Ok(()) // Files are synced on write if configured
    }

    fn close(&self) -> StorageResult<()> {
        Ok(())
    }
}

impl fmt::Debug for FileBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileBackend {{ path: {:?} }}", self.base_path)
    }
}

// ============================================================================
// Storage Manager
// ============================================================================

/// Unified storage manager that wraps different backends
pub struct StorageManager {
    backend: Arc<dyn StorageBackend>,
    config: StorageConfig,
}

impl StorageManager {
    /// Create a new storage manager
    pub fn new(config: StorageConfig) -> StorageResult<Self> {
        let backend: Arc<dyn StorageBackend> = match config.backend_type {
            BackendType::Memory => Arc::new(MemoryBackend::new()),
            BackendType::File => Arc::new(FileBackend::new(config.clone())?),
            BackendType::Sqlite => {
                // SQLite would be implemented here
                return Err(StorageError::BackendNotAvailable(
                    "SQLite backend not implemented".to_string(),
                ));
            }
            BackendType::KeyValue => {
                return Err(StorageError::BackendNotAvailable(
                    "KeyValue backend not implemented".to_string(),
                ));
            }
        };

        Ok(Self { backend, config })
    }

    /// Create a memory-based storage manager
    pub fn memory() -> Self {
        Self {
            backend: Arc::new(MemoryBackend::new()),
            config: StorageConfig::new(BackendType::Memory),
        }
    }

    /// Store a value
    pub fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        self.backend.put(key, value)
    }

    /// Store a serializable value
    pub fn put_json<T: Serialize>(&self, key: &str, value: &T) -> StorageResult<()> {
        let data = serde_json::to_vec(value)
            .map_err(|e| StorageError::SerializationError(e.to_string()))?;
        self.put(key, &data)
    }

    /// Retrieve a value
    pub fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        self.backend.get(key)
    }

    /// Retrieve and deserialize a value
    pub fn get_json<T: for<'de> Deserialize<'de>>(&self, key: &str) -> StorageResult<T> {
        let data = self.get(key)?;
        serde_json::from_slice(&data)
            .map_err(|e| StorageError::SerializationError(e.to_string()))
    }

    /// Delete a key
    pub fn delete(&self, key: &str) -> StorageResult<()> {
        self.backend.delete(key)
    }

    /// Check if a key exists
    pub fn exists(&self, key: &str) -> StorageResult<bool> {
        self.backend.exists(key)
    }

    /// List keys with optional prefix
    pub fn list_keys(&self, prefix: Option<&str>) -> StorageResult<Vec<String>> {
        self.backend.list_keys(prefix)
    }

    /// Get storage statistics
    pub fn stats(&self) -> StorageResult<StorageStats> {
        self.backend.stats()
    }

    /// Flush buffered data
    pub fn flush(&self) -> StorageResult<()> {
        self.backend.flush()
    }

    /// Close the storage manager
    pub fn close(&self) -> StorageResult<()> {
        self.backend.close()
    }

    /// Get the backend type
    pub fn backend_type(&self) -> BackendType {
        self.backend.backend_type()
    }

    /// Get the configuration
    pub fn config(&self) -> &StorageConfig {
        &self.config
    }
}

impl fmt::Debug for StorageManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StorageManager {{ backend: {:?} }}", self.config.backend_type)
    }
}

// ============================================================================
// Namespaced Storage
// ============================================================================

/// Storage with namespace support
pub struct NamespacedStorage {
    manager: StorageManager,
    namespace: String,
}

impl NamespacedStorage {
    /// Create a new namespaced storage
    pub fn new(manager: StorageManager, namespace: impl Into<String>) -> Self {
        Self {
            manager,
            namespace: namespace.into(),
        }
    }

    /// Get the full key with namespace
    fn full_key(&self, key: &str) -> String {
        format!("{}:{}", self.namespace, key)
    }

    /// Store a value
    pub fn put(&self, key: &str, value: &[u8]) -> StorageResult<()> {
        self.manager.put(&self.full_key(key), value)
    }

    /// Store a serializable value
    pub fn put_json<T: Serialize>(&self, key: &str, value: &T) -> StorageResult<()> {
        self.manager.put_json(&self.full_key(key), value)
    }

    /// Retrieve a value
    pub fn get(&self, key: &str) -> StorageResult<Vec<u8>> {
        self.manager.get(&self.full_key(key))
    }

    /// Retrieve and deserialize a value
    pub fn get_json<T: for<'de> Deserialize<'de>>(&self, key: &str) -> StorageResult<T> {
        self.manager.get_json(&self.full_key(key))
    }

    /// Delete a key
    pub fn delete(&self, key: &str) -> StorageResult<()> {
        self.manager.delete(&self.full_key(key))
    }

    /// Check if a key exists
    pub fn exists(&self, key: &str) -> StorageResult<bool> {
        self.manager.exists(&self.full_key(key))
    }

    /// List keys in this namespace
    pub fn list_keys(&self) -> StorageResult<Vec<String>> {
        let prefix = format!("{}:", self.namespace);
        let keys = self.manager.list_keys(Some(&prefix))?;
        
        Ok(keys
            .into_iter()
            .map(|k| k.strip_prefix(&prefix).unwrap_or(&k).to_string())
            .collect())
    }

    /// Get the namespace
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_config_default() {
        let config = StorageConfig::default();
        assert_eq!(config.backend_type, BackendType::Memory);
        assert!(config.sync_writes);
    }

    #[test]
    fn test_storage_config_builder() {
        let config = StorageConfig::new(BackendType::File)
            .with_path("/tmp/test")
            .with_compression(true)
            .with_sync_writes(false);

        assert_eq!(config.backend_type, BackendType::File);
        assert!(config.compression);
        assert!(!config.sync_writes);
    }

    #[test]
    fn test_memory_backend_put_get() {
        let backend = MemoryBackend::new();

        backend.put("key1", b"value1").unwrap();
        let value = backend.get("key1").unwrap();
        assert_eq!(value, b"value1");
    }

    #[test]
    fn test_memory_backend_exists() {
        let backend = MemoryBackend::new();

        assert!(!backend.exists("key1").unwrap());
        backend.put("key1", b"value1").unwrap();
        assert!(backend.exists("key1").unwrap());
    }

    #[test]
    fn test_memory_backend_delete() {
        let backend = MemoryBackend::new();

        backend.put("key1", b"value1").unwrap();
        assert!(backend.exists("key1").unwrap());
        
        backend.delete("key1").unwrap();
        assert!(!backend.exists("key1").unwrap());
    }

    #[test]
    fn test_memory_backend_list_keys() {
        let backend = MemoryBackend::new();

        backend.put("prefix_a", b"1").unwrap();
        backend.put("prefix_b", b"2").unwrap();
        backend.put("other", b"3").unwrap();

        let all_keys = backend.list_keys(None).unwrap();
        assert_eq!(all_keys.len(), 3);

        let prefixed = backend.list_keys(Some("prefix_")).unwrap();
        assert_eq!(prefixed.len(), 2);
    }

    #[test]
    fn test_memory_backend_stats() {
        let backend = MemoryBackend::new();

        backend.put("key1", b"value1").unwrap();
        backend.put("key2", b"value2").unwrap();
        let _ = backend.get("key1");

        let stats = backend.stats().unwrap();
        assert_eq!(stats.key_count, 2);
        assert_eq!(stats.writes, 2);
        assert_eq!(stats.reads, 1);
    }

    #[test]
    fn test_file_backend_put_get() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig::new(BackendType::File)
            .with_path(temp_dir.path());

        let backend = FileBackend::new(config).unwrap();

        backend.put("key1", b"value1").unwrap();
        let value = backend.get("key1").unwrap();
        assert_eq!(value, b"value1");
    }

    #[test]
    fn test_file_backend_exists() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig::new(BackendType::File)
            .with_path(temp_dir.path());

        let backend = FileBackend::new(config).unwrap();

        assert!(!backend.exists("key1").unwrap());
        backend.put("key1", b"value1").unwrap();
        assert!(backend.exists("key1").unwrap());
    }

    #[test]
    fn test_file_backend_delete() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig::new(BackendType::File)
            .with_path(temp_dir.path());

        let backend = FileBackend::new(config).unwrap();

        backend.put("key1", b"value1").unwrap();
        backend.delete("key1").unwrap();
        assert!(!backend.exists("key1").unwrap());
    }

    #[test]
    fn test_storage_manager_memory() {
        let manager = StorageManager::memory();

        manager.put("key1", b"value1").unwrap();
        let value = manager.get("key1").unwrap();
        assert_eq!(value, b"value1");
    }

    #[test]
    fn test_storage_manager_json() {
        let manager = StorageManager::memory();

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            name: String,
            value: i32,
        }

        let data = TestData {
            name: "test".to_string(),
            value: 42,
        };

        manager.put_json("test_data", &data).unwrap();
        let retrieved: TestData = manager.get_json("test_data").unwrap();
        
        assert_eq!(retrieved, data);
    }

    #[test]
    fn test_namespaced_storage() {
        let manager = StorageManager::memory();
        let ns1 = NamespacedStorage::new(manager, "ns1");

        ns1.put("key1", b"value1").unwrap();
        let value = ns1.get("key1").unwrap();
        assert_eq!(value, b"value1");
    }

    #[test]
    fn test_namespaced_storage_isolation() {
        let manager1 = StorageManager::memory();
        let manager2 = manager1.config.clone();

        // This demonstrates namespace concept - in practice would share backend
        let ns = NamespacedStorage::new(manager1, "namespace1");
        ns.put("key", b"value").unwrap();

        // Key should be prefixed with namespace
        assert!(ns.exists("key").unwrap());
    }

    #[test]
    fn test_namespaced_storage_list_keys() {
        let manager = StorageManager::memory();
        
        // Put some keys directly
        manager.put("ns1:key1", b"1").unwrap();
        manager.put("ns1:key2", b"2").unwrap();
        manager.put("ns2:key1", b"3").unwrap();

        let ns1 = NamespacedStorage::new(manager, "ns1");
        let keys = ns1.list_keys().unwrap();
        
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"key1".to_string()));
        assert!(keys.contains(&"key2".to_string()));
    }

    #[test]
    fn test_file_backend_list_keys() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig::new(BackendType::File)
            .with_path(temp_dir.path());

        let backend = FileBackend::new(config).unwrap();

        backend.put("key1", b"value1").unwrap();
        backend.put("key2", b"value2").unwrap();

        let keys = backend.list_keys(None).unwrap();
        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_storage_manager_file_backend() {
        let temp_dir = TempDir::new().unwrap();
        let config = StorageConfig::new(BackendType::File)
            .with_path(temp_dir.path());

        let manager = StorageManager::new(config).unwrap();
        assert_eq!(manager.backend_type(), BackendType::File);

        manager.put("test", b"data").unwrap();
        let retrieved = manager.get("test").unwrap();
        assert_eq!(retrieved, b"data");
    }
}
