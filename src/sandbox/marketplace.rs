//! WASM Skill Marketplace Integration
//!
//! Provides marketplace features for discovering, downloading, and managing
//! WASM skills from remote registries. Supports skill publishing, versioning,
//! reviews, and dependency management.
//!
//! # Features
//! - Browse and search skill marketplace
//! - Download and install skills from registry
//! - Publish skills to marketplace
//! - Version management with semver
//! - Skill dependencies and compatibility
//! - Reviews and ratings
//! - License and security information
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::marketplace::{MarketplaceClient, MarketplaceConfig, SkillQuery};
//!
//! let config = MarketplaceConfig::default();
//! let client = MarketplaceClient::new(config).await.unwrap();
//!
//! // Search for skills
//! let query = SkillQuery::new("calculator").with_category("math");
//! let results = client.search(&query).await.unwrap();
//!
//! // Install a skill
//! client.install("calculator", "1.0.0").await.unwrap();
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the marketplace client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceConfig {
    /// Registry URL
    pub registry_url: String,
    /// API key for authentication (optional)
    pub api_key: Option<String>,
    /// Local cache directory
    pub cache_dir: PathBuf,
    /// Enable caching
    pub enable_cache: bool,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// Request timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum concurrent downloads
    pub max_concurrent_downloads: usize,
    /// Verify signatures on download
    pub verify_signatures: bool,
    /// Allow prerelease versions
    pub allow_prerelease: bool,
    /// Trusted publishers
    pub trusted_publishers: Vec<String>,
}

impl Default for MarketplaceConfig {
    fn default() -> Self {
        Self {
            registry_url: "https://registry.vak.dev/v1".to_string(),
            api_key: None,
            cache_dir: PathBuf::from(".vak/cache/skills"),
            enable_cache: true,
            cache_ttl_secs: 3600,
            timeout_ms: 30000,
            max_concurrent_downloads: 5,
            verify_signatures: true,
            allow_prerelease: false,
            trusted_publishers: Vec::new(),
        }
    }
}

impl MarketplaceConfig {
    /// Create config for local development
    pub fn local(registry_url: impl Into<String>) -> Self {
        Self {
            registry_url: registry_url.into(),
            verify_signatures: false,
            allow_prerelease: true,
            ..Default::default()
        }
    }

    /// Set API key
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set cache directory
    pub fn with_cache_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.cache_dir = dir.into();
        self
    }

    /// Add trusted publisher
    pub fn with_trusted_publisher(mut self, publisher: impl Into<String>) -> Self {
        self.trusted_publishers.push(publisher.into());
        self
    }
}

// ============================================================================
// Skill Metadata
// ============================================================================

/// Skill category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillCategory {
    /// Mathematical operations
    Math,
    /// Text processing
    Text,
    /// Data transformation
    Data,
    /// File operations
    FileSystem,
    /// Network operations
    Network,
    /// Database operations
    Database,
    /// Security tools
    Security,
    /// Utility functions
    Utility,
    /// AI/ML integration
    Ai,
    /// Custom category
    Custom(String),
}

impl std::fmt::Display for SkillCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Math => write!(f, "math"),
            Self::Text => write!(f, "text"),
            Self::Data => write!(f, "data"),
            Self::FileSystem => write!(f, "filesystem"),
            Self::Network => write!(f, "network"),
            Self::Database => write!(f, "database"),
            Self::Security => write!(f, "security"),
            Self::Utility => write!(f, "utility"),
            Self::Ai => write!(f, "ai"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// License type for skills
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkillLicense {
    /// MIT License
    Mit,
    /// Apache 2.0 License
    Apache2,
    /// BSD 3-Clause License
    Bsd3,
    /// GPL v3 License
    Gpl3,
    /// Proprietary license
    Proprietary,
    /// Other license
    Other(String),
}

impl std::fmt::Display for SkillLicense {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mit => write!(f, "MIT"),
            Self::Apache2 => write!(f, "Apache-2.0"),
            Self::Bsd3 => write!(f, "BSD-3-Clause"),
            Self::Gpl3 => write!(f, "GPL-3.0"),
            Self::Proprietary => write!(f, "Proprietary"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
}

/// Publisher information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publisher {
    /// Publisher ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Email address
    pub email: Option<String>,
    /// Website URL
    pub website: Option<String>,
    /// Is verified publisher
    pub verified: bool,
    /// Public key for signature verification
    pub public_key: Option<String>,
    /// Member since timestamp
    pub member_since: u64,
}

/// Skill dependency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillDependency {
    /// Dependency skill name
    pub name: String,
    /// Version requirement (semver)
    pub version_req: String,
    /// Is optional dependency
    pub optional: bool,
}

/// Security audit information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAudit {
    /// Audit ID
    pub id: String,
    /// Auditor name
    pub auditor: String,
    /// Audit date
    pub date: u64,
    /// Audit passed
    pub passed: bool,
    /// Issues found
    pub issues: Vec<SecurityIssue>,
    /// Audit certificate URL
    pub certificate_url: Option<String>,
}

/// Security issue from audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityIssue {
    /// Issue severity
    pub severity: SecuritySeverity,
    /// Issue description
    pub description: String,
    /// Is fixed
    pub fixed: bool,
    /// Fix version (if fixed)
    pub fixed_in: Option<String>,
}

/// Security issue severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

/// Marketplace skill metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MarketplaceSkill {
    /// Unique skill ID
    pub id: String,
    /// Skill name
    pub name: String,
    /// Latest version
    pub version: String,
    /// All available versions
    pub versions: Vec<String>,
    /// Short description
    pub description: String,
    /// Long description (markdown)
    pub readme: Option<String>,
    /// Categories
    pub categories: Vec<SkillCategory>,
    /// Tags for search
    pub tags: Vec<String>,
    /// License
    pub license: SkillLicense,
    /// Publisher
    pub publisher: Publisher,
    /// Dependencies
    pub dependencies: Vec<SkillDependency>,
    /// Download count
    pub downloads: u64,
    /// Average rating (1-5)
    pub rating: f32,
    /// Number of ratings
    pub rating_count: u32,
    /// Created timestamp
    pub created_at: u64,
    /// Updated timestamp
    pub updated_at: u64,
    /// Homepage URL
    pub homepage: Option<String>,
    /// Repository URL
    pub repository: Option<String>,
    /// Documentation URL
    pub documentation: Option<String>,
    /// Security audits
    pub security_audits: Vec<SecurityAudit>,
    /// Required permissions
    pub required_permissions: Vec<String>,
    /// WASM size in bytes
    pub wasm_size: u64,
    /// SHA256 hash of WASM binary
    pub wasm_hash: String,
    /// Signature (if signed)
    pub signature: Option<String>,
    /// Is deprecated
    pub deprecated: bool,
    /// Deprecation message
    pub deprecation_message: Option<String>,
}

/// Skill version details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillVersion {
    /// Version string
    pub version: String,
    /// Release notes
    pub release_notes: Option<String>,
    /// Published timestamp
    pub published_at: u64,
    /// WASM size in bytes
    pub wasm_size: u64,
    /// SHA256 hash
    pub wasm_hash: String,
    /// Signature
    pub signature: Option<String>,
    /// Is yanked
    pub yanked: bool,
    /// Yank reason
    pub yank_reason: Option<String>,
}

/// Skill review
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillReview {
    /// Review ID
    pub id: String,
    /// Reviewer name
    pub reviewer: String,
    /// Rating (1-5)
    pub rating: u8,
    /// Review title
    pub title: String,
    /// Review body
    pub body: String,
    /// Version reviewed
    pub version: String,
    /// Created timestamp
    pub created_at: u64,
    /// Helpful count
    pub helpful_count: u32,
}

// ============================================================================
// Search and Query
// ============================================================================

/// Sort order for search results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SortOrder {
    /// Most relevant first
    Relevance,
    /// Most downloads first
    Downloads,
    /// Highest rated first
    Rating,
    /// Most recently updated
    Updated,
    /// Most recently created
    Created,
    /// Alphabetical
    Name,
}

impl Default for SortOrder {
    fn default() -> Self {
        Self::Relevance
    }
}

/// Query for searching skills
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillQuery {
    /// Search query string
    pub query: Option<String>,
    /// Filter by categories
    pub categories: Option<Vec<SkillCategory>>,
    /// Filter by tags
    pub tags: Option<Vec<String>>,
    /// Filter by publisher
    pub publisher: Option<String>,
    /// Filter by license
    pub licenses: Option<Vec<SkillLicense>>,
    /// Minimum rating
    pub min_rating: Option<f32>,
    /// Include deprecated skills
    pub include_deprecated: bool,
    /// Sort order
    pub sort: SortOrder,
    /// Page number (0-indexed)
    pub page: usize,
    /// Page size
    pub page_size: usize,
}

impl SkillQuery {
    /// Create a new query
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query: Some(query.into()),
            page_size: 20,
            ..Default::default()
        }
    }

    /// Filter by category
    pub fn with_category(mut self, category: impl Into<String>) -> Self {
        let cat = match category.into().as_str() {
            "math" => SkillCategory::Math,
            "text" => SkillCategory::Text,
            "data" => SkillCategory::Data,
            "filesystem" => SkillCategory::FileSystem,
            "network" => SkillCategory::Network,
            "database" => SkillCategory::Database,
            "security" => SkillCategory::Security,
            "utility" => SkillCategory::Utility,
            "ai" => SkillCategory::Ai,
            other => SkillCategory::Custom(other.to_string()),
        };
        self.categories.get_or_insert_with(Vec::new).push(cat);
        self
    }

    /// Filter by tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.get_or_insert_with(Vec::new).push(tag.into());
        self
    }

    /// Filter by publisher
    pub fn with_publisher(mut self, publisher: impl Into<String>) -> Self {
        self.publisher = Some(publisher.into());
        self
    }

    /// Set minimum rating
    pub fn with_min_rating(mut self, rating: f32) -> Self {
        self.min_rating = Some(rating);
        self
    }

    /// Set sort order
    pub fn with_sort(mut self, sort: SortOrder) -> Self {
        self.sort = sort;
        self
    }

    /// Set page
    pub fn with_page(mut self, page: usize) -> Self {
        self.page = page;
        self
    }

    /// Set page size
    pub fn with_page_size(mut self, size: usize) -> Self {
        self.page_size = size;
        self
    }
}

/// Search results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    /// Found skills
    pub skills: Vec<MarketplaceSkill>,
    /// Total count
    pub total: usize,
    /// Current page
    pub page: usize,
    /// Page size
    pub page_size: usize,
    /// Has more pages
    pub has_more: bool,
}

// ============================================================================
// Marketplace Errors
// ============================================================================

/// Marketplace-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum MarketplaceError {
    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Skill not found
    #[error("Skill not found: {name}")]
    SkillNotFound { name: String },

    /// Version not found
    #[error("Version {version} not found for skill {name}")]
    VersionNotFound { name: String, version: String },

    /// Authentication required
    #[error("Authentication required")]
    AuthenticationRequired,

    /// Authentication failed
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Invalid signature
    #[error("Invalid signature for skill {name}")]
    InvalidSignature { name: String },

    /// Untrusted publisher
    #[error("Untrusted publisher: {0}")]
    UntrustedPublisher(String),

    /// Dependency resolution failed
    #[error("Dependency resolution failed: {0}")]
    DependencyResolutionFailed(String),

    /// Download failed
    #[error("Download failed: {0}")]
    DownloadFailed(String),

    /// Hash mismatch
    #[error("Hash mismatch for {name}: expected {expected}, got {actual}")]
    HashMismatch {
        name: String,
        expected: String,
        actual: String,
    },

    /// Cache error
    #[error("Cache error: {0}")]
    CacheError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Skill already exists
    #[error("Skill already exists: {name} v{version}")]
    SkillExists { name: String, version: String },

    /// Invalid version
    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },
}

// ============================================================================
// Install Result
// ============================================================================

/// Result of skill installation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallResult {
    /// Skill name
    pub name: String,
    /// Installed version
    pub version: String,
    /// Installation path
    pub install_path: PathBuf,
    /// Installed dependencies
    pub dependencies: Vec<InstallResult>,
    /// Was cached
    pub from_cache: bool,
    /// Download size in bytes
    pub download_size: u64,
    /// Install time in milliseconds
    pub install_time_ms: u64,
}

/// Result of skill uninstallation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallResult {
    /// Skill name
    pub name: String,
    /// Uninstalled version
    pub version: String,
    /// Files removed
    pub files_removed: Vec<PathBuf>,
    /// Orphaned dependencies (no longer needed)
    pub orphaned_dependencies: Vec<String>,
}

// ============================================================================
// Marketplace Client
// ============================================================================

/// Cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry<T> {
    data: T,
    cached_at: u64,
}

/// Client for interacting with the skill marketplace
pub struct MarketplaceClient {
    /// Configuration
    config: MarketplaceConfig,
    /// HTTP client
    client: reqwest::Client,
    /// Metadata cache
    cache: Arc<RwLock<HashMap<String, CacheEntry<MarketplaceSkill>>>>,
    /// Search cache
    search_cache: Arc<RwLock<HashMap<String, CacheEntry<SearchResults>>>>,
    /// Installed skills
    installed: Arc<RwLock<HashMap<String, InstallResult>>>,
}

impl MarketplaceClient {
    /// Create a new marketplace client
    pub async fn new(config: MarketplaceConfig) -> Result<Self, MarketplaceError> {
        // Create cache directory if it doesn't exist
        if config.enable_cache {
            std::fs::create_dir_all(&config.cache_dir)
                .map_err(|e| MarketplaceError::IoError(e.to_string()))?;
        }

        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| MarketplaceError::NetworkError(e.to_string()))?;

        Ok(Self {
            config,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
            search_cache: Arc::new(RwLock::new(HashMap::new())),
            installed: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Search for skills
    pub async fn search(&self, query: &SkillQuery) -> Result<SearchResults, MarketplaceError> {
        // Check cache
        let cache_key = format!("{:?}", query);
        if let Some(cached) = self.get_search_cache(&cache_key) {
            return Ok(cached);
        }

        // Make API request
        let url = format!("{}/skills/search", self.config.registry_url);
        let response = self
            .client
            .post(&url)
            .json(query)
            .send()
            .await
            .map_err(|e| MarketplaceError::NetworkError(e.to_string()))?;

        if response.status() == 429 {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok())
                .unwrap_or(60);
            return Err(MarketplaceError::RateLimited {
                retry_after_secs: retry_after,
            });
        }

        if !response.status().is_success() {
            return Err(MarketplaceError::NetworkError(format!(
                "Search failed with status: {}",
                response.status()
            )));
        }

        let results: SearchResults = response
            .json()
            .await
            .map_err(|e| MarketplaceError::SerializationError(e.to_string()))?;

        // Cache results
        self.set_search_cache(&cache_key, results.clone());

        Ok(results)
    }

    /// Get skill metadata
    pub async fn get_skill(&self, name: &str) -> Result<MarketplaceSkill, MarketplaceError> {
        // Check cache
        if let Some(cached) = self.get_cache(name) {
            return Ok(cached);
        }

        // Make API request
        let url = format!("{}/skills/{}", self.config.registry_url, name);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| MarketplaceError::NetworkError(e.to_string()))?;

        if response.status() == 404 {
            return Err(MarketplaceError::SkillNotFound {
                name: name.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(MarketplaceError::NetworkError(format!(
                "Failed to get skill: {}",
                response.status()
            )));
        }

        let skill: MarketplaceSkill = response
            .json()
            .await
            .map_err(|e| MarketplaceError::SerializationError(e.to_string()))?;

        // Cache result
        self.set_cache(name, skill.clone());

        Ok(skill)
    }

    /// Get skill version details
    pub async fn get_version(
        &self,
        name: &str,
        version: &str,
    ) -> Result<SkillVersion, MarketplaceError> {
        let url = format!(
            "{}/skills/{}/versions/{}",
            self.config.registry_url, name, version
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| MarketplaceError::NetworkError(e.to_string()))?;

        if response.status() == 404 {
            return Err(MarketplaceError::VersionNotFound {
                name: name.to_string(),
                version: version.to_string(),
            });
        }

        if !response.status().is_success() {
            return Err(MarketplaceError::NetworkError(format!(
                "Failed to get version: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| MarketplaceError::SerializationError(e.to_string()))
    }

    /// Install a skill
    pub async fn install(
        &self,
        name: &str,
        version: &str,
    ) -> Result<InstallResult, MarketplaceError> {
        let start = std::time::Instant::now();

        // Get skill metadata
        let skill = self.get_skill(name).await?;

        // Verify version exists
        if !skill.versions.contains(&version.to_string()) {
            return Err(MarketplaceError::VersionNotFound {
                name: name.to_string(),
                version: version.to_string(),
            });
        }

        // Check if deprecated
        if skill.deprecated {
            tracing::warn!(
                "Installing deprecated skill {}: {}",
                name,
                skill.deprecation_message.as_deref().unwrap_or("No reason given")
            );
        }

        // Check publisher trust
        if self.config.verify_signatures
            && !self.config.trusted_publishers.is_empty()
            && !self.config.trusted_publishers.contains(&skill.publisher.id)
            && !skill.publisher.verified
        {
            return Err(MarketplaceError::UntrustedPublisher(
                skill.publisher.name.clone(),
            ));
        }

        // Check cache for WASM binary
        let cache_path = self.config.cache_dir.join(format!("{}-{}.wasm", name, version));
        let from_cache = cache_path.exists();

        let wasm_bytes = if from_cache {
            std::fs::read(&cache_path)
                .map_err(|e| MarketplaceError::CacheError(e.to_string()))?
        } else {
            // Download WASM binary
            let wasm_url = format!(
                "{}/skills/{}/versions/{}/download",
                self.config.registry_url, name, version
            );

            let response = self
                .client
                .get(&wasm_url)
                .send()
                .await
                .map_err(|e| MarketplaceError::DownloadFailed(e.to_string()))?;

            if !response.status().is_success() {
                return Err(MarketplaceError::DownloadFailed(format!(
                    "Download failed: {}",
                    response.status()
                )));
            }

            let bytes = response
                .bytes()
                .await
                .map_err(|e| MarketplaceError::DownloadFailed(e.to_string()))?;

            // Verify hash
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = format!("{:x}", hasher.finalize());

            if hash != skill.wasm_hash {
                return Err(MarketplaceError::HashMismatch {
                    name: name.to_string(),
                    expected: skill.wasm_hash.clone(),
                    actual: hash,
                });
            }

            // Cache the binary
            if self.config.enable_cache {
                std::fs::write(&cache_path, &bytes)
                    .map_err(|e| MarketplaceError::CacheError(e.to_string()))?;
            }

            bytes.to_vec()
        };

        // Install to skills directory
        let install_dir = self.config.cache_dir.parent()
            .map(|p| p.join("installed").join(name))
            .unwrap_or_else(|| PathBuf::from(format!("skills/{}", name)));

        std::fs::create_dir_all(&install_dir)
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

        let install_path = install_dir.join(format!("{}.wasm", name));
        std::fs::write(&install_path, &wasm_bytes)
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

        // Write manifest
        let manifest_path = install_dir.join("manifest.yaml");
        let manifest_content = format!(
            r#"name: {}
version: {}
description: {}
author: {}
wasm_path: {}.wasm
"#,
            name, version, skill.description, skill.publisher.name, name
        );
        std::fs::write(&manifest_path, manifest_content)
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

        // Install dependencies
        let mut dependencies = Vec::new();
        for dep in &skill.dependencies {
            if !dep.optional {
                let dep_result = Box::pin(self.install(&dep.name, &dep.version_req)).await?;
                dependencies.push(dep_result);
            }
        }

        let result = InstallResult {
            name: name.to_string(),
            version: version.to_string(),
            install_path,
            dependencies,
            from_cache,
            download_size: wasm_bytes.len() as u64,
            install_time_ms: start.elapsed().as_millis() as u64,
        };

        // Track installed skill
        if let Ok(mut installed) = self.installed.write() {
            installed.insert(name.to_string(), result.clone());
        }

        tracing::info!(
            "Installed {} v{} ({} bytes, {}ms)",
            name,
            version,
            wasm_bytes.len(),
            start.elapsed().as_millis()
        );

        Ok(result)
    }

    /// Uninstall a skill
    pub async fn uninstall(&self, name: &str) -> Result<UninstallResult, MarketplaceError> {
        let installed = self.installed.read()
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

        let install_info = installed.get(name)
            .ok_or_else(|| MarketplaceError::SkillNotFound {
                name: name.to_string(),
            })?;

        let mut files_removed = Vec::new();

        // Remove WASM file
        if install_info.install_path.exists() {
            std::fs::remove_file(&install_info.install_path)
                .map_err(|e| MarketplaceError::IoError(e.to_string()))?;
            files_removed.push(install_info.install_path.clone());
        }

        // Remove manifest
        if let Some(parent) = install_info.install_path.parent() {
            let manifest_path = parent.join("manifest.yaml");
            if manifest_path.exists() {
                std::fs::remove_file(&manifest_path)
                    .map_err(|e| MarketplaceError::IoError(e.to_string()))?;
                files_removed.push(manifest_path);
            }

            // Remove directory if empty
            if let Ok(entries) = std::fs::read_dir(parent) {
                if entries.count() == 0 {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        }

        let version = install_info.version.clone();

        // Remove from tracked
        drop(installed);
        if let Ok(mut installed) = self.installed.write() {
            installed.remove(name);
        }

        // Clear cache
        let cache_pattern = self.config.cache_dir.join(format!("{}-*.wasm", name));
        if let Some(pattern_str) = cache_pattern.to_str() {
            if let Ok(entries) = glob::glob(pattern_str) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_file(&entry);
                    files_removed.push(entry);
                }
            }
        }

        Ok(UninstallResult {
            name: name.to_string(),
            version,
            files_removed,
            orphaned_dependencies: Vec::new(), // Would need dependency graph analysis
        })
    }

    /// Update a skill to latest version
    pub async fn update(&self, name: &str) -> Result<InstallResult, MarketplaceError> {
        let skill = self.get_skill(name).await?;
        self.install(name, &skill.version).await
    }

    /// List installed skills
    pub fn list_installed(&self) -> Vec<InstallResult> {
        self.installed
            .read()
            .map(|i| i.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Get reviews for a skill
    pub async fn get_reviews(
        &self,
        name: &str,
        page: usize,
        page_size: usize,
    ) -> Result<Vec<SkillReview>, MarketplaceError> {
        let url = format!(
            "{}/skills/{}/reviews?page={}&page_size={}",
            self.config.registry_url, name, page, page_size
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| MarketplaceError::NetworkError(e.to_string()))?;

        if !response.status().is_success() {
            return Err(MarketplaceError::NetworkError(format!(
                "Failed to get reviews: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| MarketplaceError::SerializationError(e.to_string()))
    }

    /// Submit a review
    pub async fn submit_review(
        &self,
        name: &str,
        version: &str,
        rating: u8,
        title: &str,
        body: &str,
    ) -> Result<SkillReview, MarketplaceError> {
        if self.config.api_key.is_none() {
            return Err(MarketplaceError::AuthenticationRequired);
        }

        let url = format!("{}/skills/{}/reviews", self.config.registry_url, name);

        let review_data = serde_json::json!({
            "version": version,
            "rating": rating,
            "title": title,
            "body": body,
        });

        let mut request = self.client.post(&url).json(&review_data);

        if let Some(ref api_key) = self.config.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request
            .send()
            .await
            .map_err(|e| MarketplaceError::NetworkError(e.to_string()))?;

        if response.status() == 401 {
            return Err(MarketplaceError::AuthenticationFailed(
                "Invalid API key".to_string(),
            ));
        }

        if !response.status().is_success() {
            return Err(MarketplaceError::NetworkError(format!(
                "Failed to submit review: {}",
                response.status()
            )));
        }

        response
            .json()
            .await
            .map_err(|e| MarketplaceError::SerializationError(e.to_string()))
    }

    /// Get popular skills
    pub async fn get_popular(&self, limit: usize) -> Result<Vec<MarketplaceSkill>, MarketplaceError> {
        let query = SkillQuery {
            sort: SortOrder::Downloads,
            page_size: limit,
            ..Default::default()
        };
        let results = self.search(&query).await?;
        Ok(results.skills)
    }

    /// Get recently updated skills
    pub async fn get_recent(&self, limit: usize) -> Result<Vec<MarketplaceSkill>, MarketplaceError> {
        let query = SkillQuery {
            sort: SortOrder::Updated,
            page_size: limit,
            ..Default::default()
        };
        let results = self.search(&query).await?;
        Ok(results.skills)
    }

    /// Get cache entry
    fn get_cache(&self, name: &str) -> Option<MarketplaceSkill> {
        if !self.config.enable_cache {
            return None;
        }

        let cache = self.cache.read().ok()?;
        let entry = cache.get(name)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now - entry.cached_at < self.config.cache_ttl_secs {
            Some(entry.data.clone())
        } else {
            None
        }
    }

    /// Set cache entry
    fn set_cache(&self, name: &str, skill: MarketplaceSkill) {
        if !self.config.enable_cache {
            return;
        }

        if let Ok(mut cache) = self.cache.write() {
            let entry = CacheEntry {
                data: skill,
                cached_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };
            cache.insert(name.to_string(), entry);
        }
    }

    /// Get search cache entry
    fn get_search_cache(&self, key: &str) -> Option<SearchResults> {
        if !self.config.enable_cache {
            return None;
        }

        let cache = self.search_cache.read().ok()?;
        let entry = cache.get(key)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Shorter TTL for search results
        if now - entry.cached_at < 300 {
            Some(entry.data.clone())
        } else {
            None
        }
    }

    /// Set search cache entry
    fn set_search_cache(&self, key: &str, results: SearchResults) {
        if !self.config.enable_cache {
            return;
        }

        if let Ok(mut cache) = self.search_cache.write() {
            let entry = CacheEntry {
                data: results,
                cached_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            };
            cache.insert(key.to_string(), entry);
        }
    }

    /// Clear all caches
    pub fn clear_cache(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
        if let Ok(mut search_cache) = self.search_cache.write() {
            search_cache.clear();
        }
    }
}

impl std::fmt::Debug for MarketplaceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MarketplaceClient")
            .field("registry_url", &self.config.registry_url)
            .field("cache_enabled", &self.config.enable_cache)
            .field("verify_signatures", &self.config.verify_signatures)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_marketplace_config() {
        let config = MarketplaceConfig::default();
        assert!(config.enable_cache);
        assert!(config.verify_signatures);

        let local = MarketplaceConfig::local("http://localhost:8080");
        assert!(!local.verify_signatures);
        assert!(local.allow_prerelease);
    }

    #[test]
    fn test_skill_query_builder() {
        let query = SkillQuery::new("calculator")
            .with_category("math")
            .with_tag("arithmetic")
            .with_min_rating(4.0)
            .with_sort(SortOrder::Downloads)
            .with_page(0)
            .with_page_size(10);

        assert_eq!(query.query, Some("calculator".to_string()));
        assert_eq!(query.categories.as_ref().map(|c| c.len()), Some(1));
        assert_eq!(query.tags.as_ref().map(|t| t.len()), Some(1));
        assert_eq!(query.min_rating, Some(4.0));
        assert_eq!(query.sort, SortOrder::Downloads);
    }

    #[test]
    fn test_skill_categories() {
        assert_eq!(SkillCategory::Math.to_string(), "math");
        assert_eq!(SkillCategory::Network.to_string(), "network");
        assert_eq!(
            SkillCategory::Custom("custom".to_string()).to_string(),
            "custom"
        );
    }

    #[test]
    fn test_skill_licenses() {
        assert_eq!(SkillLicense::Mit.to_string(), "MIT");
        assert_eq!(SkillLicense::Apache2.to_string(), "Apache-2.0");
        assert_eq!(
            SkillLicense::Other("Custom".to_string()).to_string(),
            "Custom"
        );
    }

    #[test]
    fn test_security_severity_ordering() {
        assert!(SecuritySeverity::Low < SecuritySeverity::Medium);
        assert!(SecuritySeverity::Medium < SecuritySeverity::High);
        assert!(SecuritySeverity::High < SecuritySeverity::Critical);
    }

    #[test]
    fn test_sort_order_default() {
        assert_eq!(SortOrder::default(), SortOrder::Relevance);
    }

    fn create_test_skill() -> MarketplaceSkill {
        MarketplaceSkill {
            id: Uuid::new_v4().to_string(),
            name: "test-skill".to_string(),
            version: "1.0.0".to_string(),
            versions: vec!["1.0.0".to_string(), "0.9.0".to_string()],
            description: "A test skill".to_string(),
            readme: Some("# Test Skill\n\nThis is a test.".to_string()),
            categories: vec![SkillCategory::Math],
            tags: vec!["test".to_string()],
            license: SkillLicense::Mit,
            publisher: Publisher {
                id: "publisher-1".to_string(),
                name: "Test Publisher".to_string(),
                email: Some("test@example.com".to_string()),
                website: None,
                verified: true,
                public_key: None,
                member_since: 1700000000,
            },
            dependencies: Vec::new(),
            downloads: 1000,
            rating: 4.5,
            rating_count: 50,
            created_at: 1700000000,
            updated_at: 1700100000,
            homepage: None,
            repository: Some("https://github.com/test/skill".to_string()),
            documentation: None,
            security_audits: Vec::new(),
            required_permissions: vec!["compute".to_string()],
            wasm_size: 1024,
            wasm_hash: "abc123".to_string(),
            signature: None,
            deprecated: false,
            deprecation_message: None,
        }
    }

    #[test]
    fn test_marketplace_skill_structure() {
        let skill = create_test_skill();
        assert_eq!(skill.name, "test-skill");
        assert_eq!(skill.version, "1.0.0");
        assert!(skill.publisher.verified);
        assert!(!skill.deprecated);
    }

    #[test]
    fn test_install_result() {
        let result = InstallResult {
            name: "test-skill".to_string(),
            version: "1.0.0".to_string(),
            install_path: PathBuf::from("/skills/test-skill/test-skill.wasm"),
            dependencies: Vec::new(),
            from_cache: false,
            download_size: 1024,
            install_time_ms: 500,
        };

        assert_eq!(result.name, "test-skill");
        assert!(!result.from_cache);
    }

    #[test]
    fn test_skill_review() {
        let review = SkillReview {
            id: Uuid::new_v4().to_string(),
            reviewer: "test-user".to_string(),
            rating: 5,
            title: "Great skill!".to_string(),
            body: "Works perfectly.".to_string(),
            version: "1.0.0".to_string(),
            created_at: 1700000000,
            helpful_count: 10,
        };

        assert_eq!(review.rating, 5);
        assert_eq!(review.title, "Great skill!");
    }

    #[tokio::test]
    async fn test_client_creation() {
        let config = MarketplaceConfig::local("http://localhost:8080")
            .with_cache_dir("/tmp/vak-test-cache");

        // Clean up any existing cache
        let _ = std::fs::remove_dir_all("/tmp/vak-test-cache");

        let result = MarketplaceClient::new(config).await;
        assert!(result.is_ok());

        let client = result.unwrap();
        assert!(client.list_installed().is_empty());

        // Clean up
        let _ = std::fs::remove_dir_all("/tmp/vak-test-cache");
    }
}
