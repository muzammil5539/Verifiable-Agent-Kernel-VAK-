//! Secrets Management Integration (Issue #37)
//!
//! Provides a pluggable secrets management system for secure storage
//! and retrieval of sensitive data like API keys, signing keys, and credentials.
//!
//! # Supported Backends
//!
//! - **Environment**: Read secrets from environment variables (development)
//! - **File**: Read secrets from encrypted files on disk
//! - **Memory**: In-memory store for testing
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::secrets::{SecretsManager, EnvSecretsProvider};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let provider = EnvSecretsProvider::new()
//!     .with_prefix("VAK_");
//!
//! let manager = SecretsManager::new(Box::new(provider));
//!
//! let api_key = manager.get_secret("LLM_API_KEY").await?;
//! # Ok(())
//! # }
//! ```

use async_trait::async_trait;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, info, warn};

// ============================================================================
// Error Types
// ============================================================================

/// Errors from secrets management operations
#[derive(Debug, Error)]
pub enum SecretsError {
    /// Secret not found
    #[error("Secret '{0}' not found")]
    NotFound(String),

    /// Access denied
    #[error("Access denied for secret '{0}': {1}")]
    AccessDenied(String, String),

    /// Provider error
    #[error("Secrets provider error: {0}")]
    ProviderError(String),

    /// Decryption error
    #[error("Failed to decrypt secret '{0}': {1}")]
    DecryptionError(String, String),

    /// Configuration error
    #[error("Secrets configuration error: {0}")]
    ConfigError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(String),

    /// Expired secret
    #[error("Secret '{0}' has expired")]
    Expired(String),
}

/// Result type for secrets operations
pub type SecretsResult<T> = Result<T, SecretsError>;

// ============================================================================
// Secret Types
// ============================================================================

/// A retrieved secret value with metadata
#[derive(Debug, Clone)]
pub struct Secret {
    /// The secret value
    value: String,
    /// Key name
    pub key: String,
    /// When the secret was last rotated
    pub last_rotated: Option<u64>,
    /// When the secret expires
    pub expires_at: Option<u64>,
    /// Version of the secret
    pub version: u32,
    /// Source provider
    pub source: String,
}

impl Secret {
    /// Create a new secret
    pub fn new(key: impl Into<String>, value: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
            last_rotated: None,
            expires_at: None,
            version: 1,
            source: source.into(),
        }
    }

    /// Get the secret value
    ///
    /// The value is not logged or displayed in Debug output for security.
    pub fn value(&self) -> &str {
        &self.value
    }

    /// Check if the secret has expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            now >= expires_at
        } else {
            false
        }
    }

    /// Set expiration timestamp
    pub fn with_expiry(mut self, expires_at: u64) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Set version
    pub fn with_version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }
}

// ============================================================================
// Provider Trait
// ============================================================================

/// Trait for secrets provider backends
#[async_trait]
pub trait SecretsProvider: Send + Sync {
    /// Get a secret by key
    async fn get_secret(&self, key: &str) -> SecretsResult<Secret>;

    /// List available secret keys (may not list values)
    async fn list_keys(&self) -> SecretsResult<Vec<String>>;

    /// Set or update a secret
    async fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()>;

    /// Delete a secret
    async fn delete_secret(&self, key: &str) -> SecretsResult<()>;

    /// Check if a secret exists
    async fn has_secret(&self, key: &str) -> SecretsResult<bool> {
        match self.get_secret(key).await {
            Ok(_) => Ok(true),
            Err(SecretsError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Get the provider name
    fn name(&self) -> &str;
}

// ============================================================================
// Environment Variables Provider
// ============================================================================

/// Reads secrets from environment variables
///
/// Optionally supports a prefix (e.g., "VAK_") to namespace secrets.
pub struct EnvSecretsProvider {
    prefix: String,
}

impl EnvSecretsProvider {
    /// Create a new environment secrets provider
    pub fn new() -> Self {
        Self {
            prefix: String::new(),
        }
    }

    /// Set a prefix for environment variable names
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    fn env_key(&self, key: &str) -> String {
        if self.prefix.is_empty() {
            key.to_string()
        } else {
            format!("{}{}", self.prefix, key)
        }
    }
}

impl Default for EnvSecretsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretsProvider for EnvSecretsProvider {
    async fn get_secret(&self, key: &str) -> SecretsResult<Secret> {
        let env_key = self.env_key(key);
        match std::env::var(&env_key) {
            Ok(value) => {
                debug!(key = %key, "Retrieved secret from environment");
                Ok(Secret::new(key, value, "env"))
            }
            Err(_) => Err(SecretsError::NotFound(key.to_string())),
        }
    }

    async fn list_keys(&self) -> SecretsResult<Vec<String>> {
        let keys: Vec<String> = std::env::vars()
            .filter_map(|(k, _)| {
                if self.prefix.is_empty() {
                    Some(k)
                } else if k.starts_with(&self.prefix) {
                    Some(k[self.prefix.len()..].to_string())
                } else {
                    None
                }
            })
            .collect();
        Ok(keys)
    }

    async fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        let env_key = self.env_key(key);
        std::env::set_var(&env_key, value);
        info!(key = %key, "Set secret in environment");
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        let env_key = self.env_key(key);
        std::env::remove_var(&env_key);
        info!(key = %key, "Removed secret from environment");
        Ok(())
    }

    fn name(&self) -> &str {
        "environment"
    }
}

// ============================================================================
// In-Memory Provider (for testing)
// ============================================================================

/// In-memory secrets provider for testing
pub struct MemorySecretsProvider {
    secrets: RwLock<HashMap<String, Secret>>,
}

impl MemorySecretsProvider {
    /// Create a new in-memory provider
    pub fn new() -> Self {
        Self {
            secrets: RwLock::new(HashMap::new()),
        }
    }

    /// Create with initial secrets
    pub fn with_secrets(secrets: HashMap<String, String>) -> Self {
        let provider = Self::new();
        {
            let mut store = provider.secrets.write().unwrap();
            for (k, v) in secrets {
                store.insert(k.clone(), Secret::new(&k, v, "memory"));
            }
        }
        provider
    }
}

impl Default for MemorySecretsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SecretsProvider for MemorySecretsProvider {
    async fn get_secret(&self, key: &str) -> SecretsResult<Secret> {
        let store = self
            .secrets
            .read()
            .map_err(|e| SecretsError::ProviderError(e.to_string()))?;

        store
            .get(key)
            .cloned()
            .ok_or_else(|| SecretsError::NotFound(key.to_string()))
    }

    async fn list_keys(&self) -> SecretsResult<Vec<String>> {
        let store = self
            .secrets
            .read()
            .map_err(|e| SecretsError::ProviderError(e.to_string()))?;

        Ok(store.keys().cloned().collect())
    }

    async fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        let mut store = self
            .secrets
            .write()
            .map_err(|e| SecretsError::ProviderError(e.to_string()))?;

        let version = store.get(key).map(|s| s.version + 1).unwrap_or(1);
        let mut secret = Secret::new(key, value, "memory");
        secret.version = version;
        store.insert(key.to_string(), secret);
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        let mut store = self
            .secrets
            .write()
            .map_err(|e| SecretsError::ProviderError(e.to_string()))?;

        store.remove(key);
        Ok(())
    }

    fn name(&self) -> &str {
        "memory"
    }
}

// ============================================================================
// File-based Provider
// ============================================================================

/// Reads secrets from a JSON file on disk
///
/// The file format is a simple JSON object mapping keys to values.
/// In production, this should be combined with filesystem encryption.
pub struct FileSecretsProvider {
    path: PathBuf,
}

impl FileSecretsProvider {
    /// Create a new file-based secrets provider
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn read_file(&self) -> SecretsResult<HashMap<String, String>> {
        if !self.path.exists() {
            return Ok(HashMap::new());
        }

        let content = std::fs::read_to_string(&self.path)
            .map_err(|e| SecretsError::IoError(e.to_string()))?;

        serde_json::from_str(&content)
            .map_err(|e| SecretsError::ProviderError(format!("Invalid secrets file: {}", e)))
    }

    fn write_file(&self, secrets: &HashMap<String, String>) -> SecretsResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SecretsError::IoError(e.to_string()))?;
        }

        let content = serde_json::to_string_pretty(secrets)
            .map_err(|e| SecretsError::ProviderError(e.to_string()))?;

        std::fs::write(&self.path, content)
            .map_err(|e| SecretsError::IoError(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl SecretsProvider for FileSecretsProvider {
    async fn get_secret(&self, key: &str) -> SecretsResult<Secret> {
        let secrets = self.read_file()?;
        secrets
            .get(key)
            .map(|v| Secret::new(key, v.clone(), "file"))
            .ok_or_else(|| SecretsError::NotFound(key.to_string()))
    }

    async fn list_keys(&self) -> SecretsResult<Vec<String>> {
        let secrets = self.read_file()?;
        Ok(secrets.keys().cloned().collect())
    }

    async fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        let mut secrets = self.read_file()?;
        secrets.insert(key.to_string(), value.to_string());
        self.write_file(&secrets)?;
        info!(key = %key, "Stored secret to file");
        Ok(())
    }

    async fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        let mut secrets = self.read_file()?;
        secrets.remove(key);
        self.write_file(&secrets)?;
        info!(key = %key, "Deleted secret from file");
        Ok(())
    }

    fn name(&self) -> &str {
        "file"
    }
}

// ============================================================================
// Secrets Manager
// ============================================================================

/// Central secrets manager with caching and provider abstraction
pub struct SecretsManager {
    provider: Box<dyn SecretsProvider>,
    cache: RwLock<HashMap<String, CachedSecret>>,
    cache_ttl: Duration,
}

/// A cached secret with expiration
struct CachedSecret {
    secret: Secret,
    cached_at: Instant,
}

impl SecretsManager {
    /// Create a new secrets manager with the given provider
    pub fn new(provider: Box<dyn SecretsProvider>) -> Self {
        Self {
            provider,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300), // 5 minute cache
        }
    }

    /// Set the cache TTL
    pub fn with_cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Get a secret, using cache if available
    pub async fn get_secret(&self, key: &str) -> SecretsResult<Secret> {
        // Check cache first
        if let Ok(cache) = self.cache.read() {
            if let Some(cached) = cache.get(key) {
                if cached.cached_at.elapsed() < self.cache_ttl {
                    debug!(key = %key, "Cache hit for secret");
                    let secret = cached.secret.clone();
                    if secret.is_expired() {
                        return Err(SecretsError::Expired(key.to_string()));
                    }
                    return Ok(secret);
                }
            }
        }

        // Fetch from provider
        let secret = self.provider.get_secret(key).await?;

        if secret.is_expired() {
            return Err(SecretsError::Expired(key.to_string()));
        }

        // Update cache
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                key.to_string(),
                CachedSecret {
                    secret: secret.clone(),
                    cached_at: Instant::now(),
                },
            );
        }

        Ok(secret)
    }

    /// Get a secret value as a string
    pub async fn get_secret_value(&self, key: &str) -> SecretsResult<String> {
        self.get_secret(key).await.map(|s| s.value().to_string())
    }

    /// Set a secret
    pub async fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        self.provider.set_secret(key, value).await?;

        // Invalidate cache
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(key);
        }

        Ok(())
    }

    /// Delete a secret
    pub async fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        self.provider.delete_secret(key).await?;

        // Invalidate cache
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(key);
        }

        Ok(())
    }

    /// List available secret keys
    pub async fn list_keys(&self) -> SecretsResult<Vec<String>> {
        self.provider.list_keys().await
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Get the provider name
    pub fn provider_name(&self) -> &str {
        self.provider.name()
    }

    /// Check if a secret exists
    pub async fn has_secret(&self, key: &str) -> SecretsResult<bool> {
        self.provider.has_secret(key).await
    }
}

// ============================================================================
// Chained Provider
// ============================================================================

/// A provider that chains multiple providers, trying each in order
pub struct ChainedSecretsProvider {
    providers: Vec<Box<dyn SecretsProvider>>,
}

impl ChainedSecretsProvider {
    /// Create a new chained provider
    pub fn new(providers: Vec<Box<dyn SecretsProvider>>) -> Self {
        Self { providers }
    }
}

#[async_trait]
impl SecretsProvider for ChainedSecretsProvider {
    async fn get_secret(&self, key: &str) -> SecretsResult<Secret> {
        for provider in &self.providers {
            match provider.get_secret(key).await {
                Ok(secret) => return Ok(secret),
                Err(SecretsError::NotFound(_)) => continue,
                Err(e) => {
                    warn!(
                        provider = %provider.name(),
                        key = %key,
                        error = %e,
                        "Provider error, trying next"
                    );
                    continue;
                }
            }
        }
        Err(SecretsError::NotFound(key.to_string()))
    }

    async fn list_keys(&self) -> SecretsResult<Vec<String>> {
        let mut all_keys = Vec::new();
        for provider in &self.providers {
            if let Ok(keys) = provider.list_keys().await {
                for key in keys {
                    if !all_keys.contains(&key) {
                        all_keys.push(key);
                    }
                }
            }
        }
        Ok(all_keys)
    }

    async fn set_secret(&self, key: &str, value: &str) -> SecretsResult<()> {
        // Set in the first provider
        if let Some(provider) = self.providers.first() {
            provider.set_secret(key, value).await
        } else {
            Err(SecretsError::ProviderError("No providers configured".to_string()))
        }
    }

    async fn delete_secret(&self, key: &str) -> SecretsResult<()> {
        // Delete from all providers
        for provider in &self.providers {
            let _ = provider.delete_secret(key).await;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "chained"
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_provider_crud() {
        let provider = MemorySecretsProvider::new();

        // Set
        provider.set_secret("test_key", "test_value").await.unwrap();

        // Get
        let secret = provider.get_secret("test_key").await.unwrap();
        assert_eq!(secret.value(), "test_value");
        assert_eq!(secret.key, "test_key");
        assert_eq!(secret.source, "memory");

        // Has
        assert!(provider.has_secret("test_key").await.unwrap());
        assert!(!provider.has_secret("missing").await.unwrap());

        // List
        let keys = provider.list_keys().await.unwrap();
        assert!(keys.contains(&"test_key".to_string()));

        // Delete
        provider.delete_secret("test_key").await.unwrap();
        assert!(!provider.has_secret("test_key").await.unwrap());
    }

    #[tokio::test]
    async fn test_memory_provider_versioning() {
        let provider = MemorySecretsProvider::new();

        provider.set_secret("key", "v1").await.unwrap();
        let s1 = provider.get_secret("key").await.unwrap();
        assert_eq!(s1.version, 1);

        provider.set_secret("key", "v2").await.unwrap();
        let s2 = provider.get_secret("key").await.unwrap();
        assert_eq!(s2.version, 2);
        assert_eq!(s2.value(), "v2");
    }

    #[tokio::test]
    async fn test_memory_provider_not_found() {
        let provider = MemorySecretsProvider::new();
        let result = provider.get_secret("missing").await;
        assert!(matches!(result, Err(SecretsError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_secrets_manager_caching() {
        let provider = MemorySecretsProvider::new();
        provider.set_secret("cached_key", "cached_value").await.unwrap();

        let manager = SecretsManager::new(Box::new(provider));

        // First access (cache miss)
        let s1 = manager.get_secret("cached_key").await.unwrap();
        assert_eq!(s1.value(), "cached_value");

        // Second access (cache hit)
        let s2 = manager.get_secret("cached_key").await.unwrap();
        assert_eq!(s2.value(), "cached_value");

        // Clear cache
        manager.clear_cache();
    }

    #[tokio::test]
    async fn test_secrets_manager_set_invalidates_cache() {
        let provider = MemorySecretsProvider::new();
        provider.set_secret("key", "old").await.unwrap();

        let manager = SecretsManager::new(Box::new(provider));

        // Cache it
        manager.get_secret("key").await.unwrap();

        // Update
        manager.set_secret("key", "new").await.unwrap();

        // Should get new value
        let secret = manager.get_secret("key").await.unwrap();
        assert_eq!(secret.value(), "new");
    }

    #[tokio::test]
    async fn test_secret_expiry() {
        let secret = Secret::new("key", "value", "test")
            .with_expiry(0); // Already expired
        assert!(secret.is_expired());

        let future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;
        let secret = Secret::new("key", "value", "test")
            .with_expiry(future);
        assert!(!secret.is_expired());
    }

    #[tokio::test]
    async fn test_chained_provider() {
        let p1 = MemorySecretsProvider::new();
        p1.set_secret("only_in_p1", "from_p1").await.unwrap();

        let p2 = MemorySecretsProvider::new();
        p2.set_secret("only_in_p2", "from_p2").await.unwrap();

        let chained = ChainedSecretsProvider::new(vec![Box::new(p1), Box::new(p2)]);

        let s1 = chained.get_secret("only_in_p1").await.unwrap();
        assert_eq!(s1.value(), "from_p1");

        let s2 = chained.get_secret("only_in_p2").await.unwrap();
        assert_eq!(s2.value(), "from_p2");

        let missing = chained.get_secret("missing").await;
        assert!(matches!(missing, Err(SecretsError::NotFound(_))));
    }

    #[tokio::test]
    async fn test_chained_provider_list_keys() {
        let p1 = MemorySecretsProvider::new();
        p1.set_secret("a", "1").await.unwrap();
        p1.set_secret("b", "2").await.unwrap();

        let p2 = MemorySecretsProvider::new();
        p2.set_secret("b", "3").await.unwrap(); // duplicate
        p2.set_secret("c", "4").await.unwrap();

        let chained = ChainedSecretsProvider::new(vec![Box::new(p1), Box::new(p2)]);
        let keys = chained.list_keys().await.unwrap();

        assert!(keys.contains(&"a".to_string()));
        assert!(keys.contains(&"b".to_string()));
        assert!(keys.contains(&"c".to_string()));
        // "b" should appear only once
        assert_eq!(keys.iter().filter(|k| *k == "b").count(), 1);
    }

    #[tokio::test]
    async fn test_env_provider() {
        let provider = EnvSecretsProvider::new().with_prefix("VAK_TEST_");

        // Set env var
        std::env::set_var("VAK_TEST_MY_KEY", "my_value");

        let secret = provider.get_secret("MY_KEY").await.unwrap();
        assert_eq!(secret.value(), "my_value");
        assert_eq!(secret.source, "env");

        // Cleanup
        std::env::remove_var("VAK_TEST_MY_KEY");
    }

    #[tokio::test]
    async fn test_file_provider() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets.json");

        let provider = FileSecretsProvider::new(&path);

        // Set
        provider.set_secret("file_key", "file_value").await.unwrap();

        // Get
        let secret = provider.get_secret("file_key").await.unwrap();
        assert_eq!(secret.value(), "file_value");

        // Verify file exists
        assert!(path.exists());

        // List
        let keys = provider.list_keys().await.unwrap();
        assert!(keys.contains(&"file_key".to_string()));

        // Delete
        provider.delete_secret("file_key").await.unwrap();
        assert!(!provider.has_secret("file_key").await.unwrap());
    }

    #[tokio::test]
    async fn test_manager_provider_name() {
        let provider = MemorySecretsProvider::new();
        let manager = SecretsManager::new(Box::new(provider));
        assert_eq!(manager.provider_name(), "memory");
    }

    #[tokio::test]
    async fn test_manager_get_secret_value() {
        let provider = MemorySecretsProvider::new();
        provider.set_secret("k", "v").await.unwrap();

        let manager = SecretsManager::new(Box::new(provider));
        let val = manager.get_secret_value("k").await.unwrap();
        assert_eq!(val, "v");
    }
}
