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
//! # Trust
//!
//! The registry is not trusted. Every name and version, the caller's or a
//! dependency's the registry lists, is checked before it reaches a URL or
//! a path; every binary, downloaded or cached, must match its version's
//! SHA-256; downloads are capped; dependency chains end. Signatures are
//! not verified here: with `verify_signatures` (the default), `install`
//! refuses with [`MarketplaceError::SignatureUnverifiable`]. The kernel's
//! skill registry verifies signed skills when it loads them (docs/adr/0005),
//! and the manifest `install` writes is unsigned, so a strict registry
//! refuses it.
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::marketplace::{MarketplaceClient, MarketplaceConfig, SkillQuery};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Unverified installs; MarketplaceConfig::default() refuses them.
//! let config = MarketplaceConfig::local("https://registry.example/v1");
//! let client = MarketplaceClient::new(config).await?;
//!
//! // Search for skills
//! let query = SkillQuery::new("calculator").with_category("math");
//! let results = client.search(&query).await?;
//!
//! // Install a skill
//! client.install("calculator", "1.0.0").await?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Configuration

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
    /// Verify signatures on download. Not implemented, so with this on
    /// `install` refuses every skill ([`MarketplaceError::SignatureUnverifiable`]).
    /// It used to install them unverified.
    pub verify_signatures: bool,
    /// Allow prerelease versions (`1.0.0-beta`). Without it `install`
    /// refuses them; the setting used to be ignored.
    pub allow_prerelease: bool,
    /// Trusted publisher IDs. If any are listed, `install` refuses a skill
    /// from anyone else, whatever the registry says about the publisher.
    pub trusted_publishers: Vec<String>,
    /// The largest skill binary `install` downloads, in bytes.
    #[serde(default = "default_max_download_bytes")]
    pub max_download_bytes: usize,
}

fn default_max_download_bytes() -> usize {
    64 * 1024 * 1024
}

/// How deep `install` follows dependencies before giving up.
pub const MAX_DEPENDENCY_DEPTH: usize = 16;

/// The longest skill name or version accepted.
const MAX_COMPONENT_LEN: usize = 128;

/// Whether `value` may be used as a skill name or version: 1 to 128 ASCII
/// letters, digits, `.`, `-`, `_` or `+`, starting with a letter or digit.
/// Nothing else can reach a URL or a path: no `/`, no `..` component, no
/// query string.
fn is_safe_component(value: &str) -> bool {
    value.len() <= MAX_COMPONENT_LEN
        && value
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// Refuses a skill name that isn't [`is_safe_component`]. Names come from
/// callers and from the registry's dependency lists; one with `/` or `..`
/// used to reach outside the cache and install directories.
fn check_name(name: &str) -> Result<(), MarketplaceError> {
    if is_safe_component(name) {
        Ok(())
    } else {
        Err(MarketplaceError::InvalidName(format!(
            "{name:?}: a skill name is 1-{MAX_COMPONENT_LEN} letters, digits, '.', '-', '_' or '+', starting with a letter or digit"
        )))
    }
}

/// Refuses a version that isn't [`is_safe_component`]. A dependency's
/// `version_req` is used as an exact version: ranges aren't resolved.
fn check_version(version: &str) -> Result<(), MarketplaceError> {
    if is_safe_component(version) {
        Ok(())
    } else {
        Err(MarketplaceError::InvalidVersion(format!(
            "{version:?}: a version is 1-{MAX_COMPONENT_LEN} letters, digits, '.', '-', '_' or '+', starting with a letter or digit (ranges aren't resolved)"
        )))
    }
}

/// Whether a semver version is a prerelease: a `-` before any `+` build
/// metadata.
fn is_prerelease(version: &str) -> bool {
    version
        .split('+')
        .next()
        .is_some_and(|core| core.contains('-'))
}

/// Seconds since the epoch.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
            max_download_bytes: default_max_download_bytes(),
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

// Skill Metadata

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

// Search and Query

/// Sort order for search results
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SortOrder {
    /// Most relevant first
    #[default]
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

// Marketplace Errors

/// Marketplace-related errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum MarketplaceError {
    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Skill not found
    #[error("Skill not found: {name}")]
    SkillNotFound {
        /// Name of the skill that was not found
        name: String,
    },

    /// Version not found
    #[error("Version {version} not found for skill {name}")]
    VersionNotFound {
        /// Name of the skill
        name: String,
        /// Version that was not found
        version: String,
    },

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
    InvalidSignature {
        /// Name of the skill with the invalid signature
        name: String,
    },

    /// `verify_signatures` is on, and the marketplace can't verify a
    /// signature, so it installs nothing.
    #[error(
        "can't verify the signature of {name}: marketplace downloads aren't \
         signature-checked; the kernel's skill registry verifies signed skills \
         when it loads them (docs/adr/0005). Set verify_signatures: false to \
         install unverified."
    )]
    SignatureUnverifiable {
        /// Name of the skill that wasn't installed
        name: String,
    },

    /// A skill name that can't be used in a URL or a path
    #[error("Invalid skill name: {0}")]
    InvalidName(String),

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
        /// Name of the skill with the hash mismatch
        name: String,
        /// Expected hash value
        expected: String,
        /// Actual hash value that was computed
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
    SkillExists {
        /// Name of the existing skill
        name: String,
        /// Version of the existing skill
        version: String,
    },

    /// Invalid version
    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    /// Rate limited
    #[error("Rate limited, retry after {retry_after_secs} seconds")]
    RateLimited {
        /// Number of seconds to wait before retrying
        retry_after_secs: u64,
    },
}

// Install Result

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

// Marketplace Client

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

    /// A request to the registry, with the API key if one is configured. It
    /// used to be sent only with reviews.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let request = self.client.request(method, url);
        match &self.config.api_key {
            Some(key) => request.bearer_auth(key),
            None => request,
        }
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
            .request(reqwest::Method::POST, &url)
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
        check_name(name)?;
        // Check cache
        if let Some(cached) = self.get_cache(name) {
            return Ok(cached);
        }

        // Make API request
        let url = format!("{}/skills/{}", self.config.registry_url, name);
        let response = self
            .request(reqwest::Method::GET, &url)
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
        check_name(name)?;
        check_version(version)?;
        let url = format!(
            "{}/skills/{}/versions/{}",
            self.config.registry_url, name, version
        );

        let response = self
            .request(reqwest::Method::GET, &url)
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

    /// Installs a skill version and, first, its non-optional dependencies.
    ///
    /// Refuses, before writing anything:
    /// - with `verify_signatures`, everything ([`MarketplaceError::SignatureUnverifiable`]);
    /// - a name or version that can't be used in a path or URL;
    /// - a version the skill doesn't list, a yanked one, or a prerelease
    ///   without `allow_prerelease`;
    /// - with `trusted_publishers`, a publisher not on the list;
    /// - a binary, downloaded or cached, that doesn't match its version's
    ///   SHA-256, or a download over `max_download_bytes`;
    /// - a dependency cycle, or dependencies over [`MAX_DEPENDENCY_DEPTH`] deep.
    ///
    /// The manifest written is the registry's [`SkillManifest`](super::registry::SkillManifest),
    /// unsigned, with no permissions and schemas that accept any JSON.
    pub async fn install(
        &self,
        name: &str,
        version: &str,
    ) -> Result<InstallResult, MarketplaceError> {
        self.install_in(name, version, &mut Vec::new()).await
    }

    /// [`install`](Self::install), inside the dependency chain `chain`
    /// (outermost first).
    async fn install_in(
        &self,
        name: &str,
        version: &str,
        chain: &mut Vec<String>,
    ) -> Result<InstallResult, MarketplaceError> {
        let start = std::time::Instant::now();
        check_name(name)?;
        check_version(version)?;
        if self.config.verify_signatures {
            return Err(MarketplaceError::SignatureUnverifiable {
                name: name.to_string(),
            });
        }
        if chain.iter().any(|outer| outer == name) {
            return Err(MarketplaceError::DependencyResolutionFailed(format!(
                "dependency cycle: {} -> {name}",
                chain.join(" -> ")
            )));
        }
        if chain.len() >= MAX_DEPENDENCY_DEPTH {
            return Err(MarketplaceError::DependencyResolutionFailed(format!(
                "dependencies nest more than {MAX_DEPENDENCY_DEPTH} deep at {name}"
            )));
        }
        if is_prerelease(version) && !self.config.allow_prerelease {
            return Err(MarketplaceError::InvalidVersion(format!(
                "{name} {version} is a prerelease, and allow_prerelease is off"
            )));
        }

        // Get skill metadata
        let skill = self.get_skill(name).await?;

        // Verify version exists
        if !skill.versions.iter().any(|v| v == version) {
            return Err(MarketplaceError::VersionNotFound {
                name: name.to_string(),
                version: version.to_string(),
            });
        }
        // The version's own record has its hash. The skill's `wasm_hash` is
        // the latest version's, so any other version used to fail its check.
        let release = self.get_version(name, version).await?;
        if release.yanked {
            return Err(MarketplaceError::InvalidVersion(format!(
                "{name} {version} was yanked: {}",
                release.yank_reason.as_deref().unwrap_or("no reason given")
            )));
        }

        // Check if deprecated
        if skill.deprecated {
            tracing::warn!(
                "Installing deprecated skill {}: {}",
                name,
                skill
                    .deprecation_message
                    .as_deref()
                    .unwrap_or("No reason given")
            );
        }

        // Check publisher trust: the configured list decides. It used to
        // apply only with verify_signatures, and the registry's own
        // `verified` flag overrode it.
        if !self.config.trusted_publishers.is_empty()
            && !self.config.trusted_publishers.contains(&skill.publisher.id)
        {
            return Err(MarketplaceError::UntrustedPublisher(
                skill.publisher.name.clone(),
            ));
        }

        // The binary, from the cache or the registry, checked either way. A
        // cached binary used to be trusted unchecked.
        let cache_path = self
            .config
            .cache_dir
            .join(format!("{}-{}.wasm", name, version));
        let from_cache = cache_path.exists();
        let wasm_bytes = if from_cache {
            std::fs::read(&cache_path).map_err(|e| MarketplaceError::CacheError(e.to_string()))?
        } else {
            self.download(name, version).await?
        };
        let hash = hex::encode(Sha256::digest(&wasm_bytes));
        if !hash.eq_ignore_ascii_case(&release.wasm_hash) {
            return Err(MarketplaceError::HashMismatch {
                name: name.to_string(),
                expected: release.wasm_hash.clone(),
                actual: hash,
            });
        }
        if !from_cache && self.config.enable_cache {
            std::fs::write(&cache_path, &wasm_bytes)
                .map_err(|e| MarketplaceError::CacheError(e.to_string()))?;
        }

        // Dependencies first, so a failing one leaves this skill uninstalled.
        chain.push(name.to_string());
        let mut dependencies = Vec::new();
        for dep in skill.dependencies.iter().filter(|dep| !dep.optional) {
            let installed = Box::pin(self.install_in(&dep.name, &dep.version_req, chain)).await;
            match installed {
                Ok(result) => dependencies.push(result),
                Err(e) => {
                    chain.pop();
                    return Err(e);
                }
            }
        }
        chain.pop();

        // Install to skills directory
        let install_dir = self
            .config
            .cache_dir
            .parent()
            .map(|p| p.join("installed").join(name))
            .unwrap_or_else(|| PathBuf::from(format!("skills/{}", name)));

        std::fs::create_dir_all(&install_dir)
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

        let install_path = install_dir.join(format!("{}.wasm", name));
        std::fs::write(&install_path, &wasm_bytes)
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

        // The manifest is serialized, not formatted: the description is the
        // registry's, and a newline in it used to add manifest keys, such
        // as permissions.
        let manifest = super::registry::SkillManifest {
            name: name.to_string(),
            version: version.to_string(),
            description: skill.description.clone(),
            author: Some(skill.publisher.name.clone()),
            permissions: super::registry::SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from(format!("{name}.wasm")),
            signed_by: None,
            signature: None,
        };
        let manifest_content = serde_yaml::to_string(&manifest)
            .map_err(|e| MarketplaceError::SerializationError(e.to_string()))?;
        std::fs::write(install_dir.join("manifest.yaml"), manifest_content)
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

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

    /// Downloads a version's binary, refusing one over `max_download_bytes`.
    async fn download(&self, name: &str, version: &str) -> Result<Vec<u8>, MarketplaceError> {
        let wasm_url = format!(
            "{}/skills/{}/versions/{}/download",
            self.config.registry_url, name, version
        );
        let mut response = self
            .request(reqwest::Method::GET, &wasm_url)
            .send()
            .await
            .map_err(|e| MarketplaceError::DownloadFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(MarketplaceError::DownloadFailed(format!(
                "Download failed: {}",
                response.status()
            )));
        }

        // The whole body used to be read into memory, however large.
        let limit = self.config.max_download_bytes;
        let too_large = || {
            MarketplaceError::DownloadFailed(format!(
                "{name} {version} is larger than the {limit}-byte limit"
            ))
        };
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(too_large());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| MarketplaceError::DownloadFailed(e.to_string()))?
        {
            if bytes.len().saturating_add(chunk.len()) > limit {
                return Err(too_large());
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Uninstall a skill
    pub async fn uninstall(&self, name: &str) -> Result<UninstallResult, MarketplaceError> {
        let installed = self
            .installed
            .read()
            .map_err(|e| MarketplaceError::IoError(e.to_string()))?;

        let install_info = installed
            .get(name)
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

        // Clear this version's cached binary. A glob of `{name}-*.wasm`
        // used to delete other skills' too: `calc-*` matches `calc-extra`.
        let cached = self
            .config
            .cache_dir
            .join(format!("{}-{}.wasm", name, version));
        if cached.exists() && std::fs::remove_file(&cached).is_ok() {
            files_removed.push(cached);
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
        check_name(name)?;
        let url = format!(
            "{}/skills/{}/reviews?page={}&page_size={}",
            self.config.registry_url, name, page, page_size
        );

        let response = self
            .request(reqwest::Method::GET, &url)
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
        check_name(name)?;

        let url = format!("{}/skills/{}/reviews", self.config.registry_url, name);

        let review_data = serde_json::json!({
            "version": version,
            "rating": rating,
            "title": title,
            "body": body,
        });

        let response = self
            .request(reqwest::Method::POST, &url)
            .json(&review_data)
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
    pub async fn get_popular(
        &self,
        limit: usize,
    ) -> Result<Vec<MarketplaceSkill>, MarketplaceError> {
        let query = SkillQuery {
            sort: SortOrder::Downloads,
            page_size: limit,
            ..Default::default()
        };
        let results = self.search(&query).await?;
        Ok(results.skills)
    }

    /// Get recently updated skills
    pub async fn get_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<MarketplaceSkill>, MarketplaceError> {
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

        // The age saturates: a clock that moved back used to underflow, a
        // panic in debug builds.
        if now_secs().saturating_sub(entry.cached_at) < self.config.cache_ttl_secs {
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
                cached_at: now_secs(),
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

        // Shorter TTL for search results
        if now_secs().saturating_sub(entry.cached_at) < 300 {
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
                cached_at: now_secs(),
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

// Tests

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
        let config =
            MarketplaceConfig::local("http://localhost:8080").with_cache_dir("/tmp/vak-test-cache");

        // Clean up any existing cache
        let _ = std::fs::remove_dir_all("/tmp/vak-test-cache");

        let result = MarketplaceClient::new(config).await;
        assert!(result.is_ok());

        let client = result.unwrap();
        assert!(client.list_installed().is_empty());

        // Clean up
        let _ = std::fs::remove_dir_all("/tmp/vak-test-cache");
    }

    use std::sync::Mutex;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One canned response.
    #[derive(Clone)]
    struct Route {
        status: u16,
        body: Vec<u8>,
        headers: Vec<(&'static str, String)>,
        /// Leave out Content-Length; the body ends when the connection does.
        no_length: bool,
    }

    fn ok(body: impl Into<Vec<u8>>) -> Route {
        status(200, body)
    }

    fn status(status: u16, body: impl Into<Vec<u8>>) -> Route {
        Route {
            status,
            body: body.into(),
            headers: Vec::new(),
            no_length: false,
        }
    }

    /// A registry on localhost. Each `"METHOD /path"` answers with its
    /// route, anything else with 404, and every request is recorded as
    /// `"METHOD /path"`, plus ` [authorization]` when one was sent.
    struct Registry {
        url: String,
        requests: Arc<Mutex<Vec<String>>>,
        routes: Arc<Mutex<HashMap<String, Route>>>,
    }

    impl Registry {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/v1", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let routes = Arc::new(Mutex::new(HashMap::<String, Route>::new()));
            let (log, table) = (requests.clone(), routes.clone());
            tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let (log, table) = (log.clone(), table.clone());
                    tokio::spawn(async move {
                        let request = read_request(&mut socket).await;
                        let mut first = request.lines().next().unwrap_or("").split_whitespace();
                        let method = first.next().unwrap_or("").to_string();
                        let target = first.next().unwrap_or("");
                        let path = target.strip_prefix("/v1").unwrap_or(target).to_string();
                        let auth = request.lines().find_map(|l| {
                            l.to_ascii_lowercase()
                                .starts_with("authorization:")
                                .then(|| l["authorization:".len()..].trim().to_string())
                        });
                        let key = format!("{method} {path}");
                        log.lock().unwrap().push(match auth {
                            Some(auth) => format!("{key} [{auth}]"),
                            None => key.clone(),
                        });
                        let route = table
                            .lock()
                            .unwrap()
                            .get(&key)
                            .cloned()
                            .unwrap_or_else(|| status(404, "{}"));
                        let mut head =
                            format!("HTTP/1.1 {} Stub\r\nConnection: close\r\n", route.status);
                        if !route.no_length {
                            head += &format!("Content-Length: {}\r\n", route.body.len());
                        }
                        for (name, value) in &route.headers {
                            head += &format!("{name}: {value}\r\n");
                        }
                        head += "\r\n";
                        let _ = socket.write_all(head.as_bytes()).await;
                        let _ = socket.write_all(&route.body).await;
                        let _ = socket.shutdown().await;
                    });
                }
            });
            Self {
                url,
                requests,
                routes,
            }
        }

        fn route(&self, key: &str, route: Route) {
            self.routes.lock().unwrap().insert(key.to_string(), route);
        }

        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }

        /// Publishes `version` of `skill` with `wasm` as its binary.
        fn publish(&self, skill: &MarketplaceSkill, version: &str, wasm: &[u8]) {
            let name = &skill.name;
            self.route(
                &format!("GET /skills/{name}"),
                ok(serde_json::to_vec(skill).unwrap()),
            );
            self.route(
                &format!("GET /skills/{name}/versions/{version}"),
                ok(serde_json::to_vec(&release(version, wasm)).unwrap()),
            );
            self.route(
                &format!("GET /skills/{name}/versions/{version}/download"),
                ok(wasm.to_vec()),
            );
        }
    }

    /// Reads a request's headers and the body Content-Length announces.
    async fn read_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = socket.read(&mut chunk).await.unwrap_or(0);
            request.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&request).to_string();
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    return text;
                }
            }
            if n == 0 {
                return String::from_utf8_lossy(&request).to_string();
            }
        }
    }

    fn release(version: &str, wasm: &[u8]) -> SkillVersion {
        SkillVersion {
            version: version.to_string(),
            release_notes: None,
            published_at: 1_700_000_000,
            wasm_size: wasm.len() as u64,
            wasm_hash: hex::encode(Sha256::digest(wasm)),
            signature: None,
            yanked: false,
            yank_reason: None,
        }
    }

    fn skill(name: &str, versions: &[&str]) -> MarketplaceSkill {
        MarketplaceSkill {
            name: name.to_string(),
            version: versions.last().unwrap().to_string(),
            versions: versions.iter().map(|v| v.to_string()).collect(),
            wasm_hash: "the latest version's".to_string(),
            ..create_test_skill()
        }
    }

    fn dependency(name: &str, version: &str, optional: bool) -> SkillDependency {
        SkillDependency {
            name: name.to_string(),
            version_req: version.to_string(),
            optional,
        }
    }

    /// A client for `registry` with installs allowed (no signature
    /// checks), caching under a fresh directory.
    async fn connect(
        registry: &Registry,
        configure: impl FnOnce(MarketplaceConfig) -> MarketplaceConfig,
    ) -> (MarketplaceClient, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let config = configure(
            MarketplaceConfig::local(registry.url.clone()).with_cache_dir(dir.path().join("cache")),
        );
        (MarketplaceClient::new(config).await.unwrap(), dir)
    }

    #[tokio::test]
    async fn test_install_verifies_the_version_and_writes_a_registry_manifest() {
        let registry = Registry::start().await;
        let mut calc = skill("calc", &["1.0.0", "1.1.0"]);
        calc.dependencies = vec![
            dependency("mathlib", "2.0.0", false),
            dependency("never-fetched", "9.9.9", true),
        ];
        registry.publish(&calc, "1.0.0", b"\0asm calc 1.0.0");
        registry.publish(&skill("mathlib", &["2.0.0"]), "2.0.0", b"\0asm mathlib");
        let (client, dir) = connect(&registry, |c| c).await;

        // 1.0.0 isn't the latest: its hash is in its own record. Checking
        // the skill's wasm_hash, the latest's, refused every other version.
        let installed = client.install("calc", "1.0.0").await.unwrap();
        assert!(!installed.from_cache);
        assert_eq!(installed.download_size, 15);
        assert_eq!(
            installed.dependencies.len(),
            1,
            "the optional one is skipped"
        );
        assert_eq!(installed.dependencies[0].name, "mathlib");
        assert_eq!(
            std::fs::read(&installed.install_path).unwrap(),
            b"\0asm calc 1.0.0"
        );
        assert!(!registry
            .requests()
            .iter()
            .any(|r| r.contains("never-fetched")));

        // The manifest is one the skill registry loads: unsigned, with no
        // permissions.
        let manifest_path = installed.install_path.with_file_name("manifest.yaml");
        let manifest = super::super::registry::SkillManifest::from_file(&manifest_path).unwrap();
        assert_eq!(
            (manifest.name.as_str(), manifest.version.as_str()),
            ("calc", "1.0.0")
        );
        assert_eq!(manifest.wasm_path, installed.install_path);
        assert!(!manifest.permissions.network && manifest.signature.is_none());

        let mut names: Vec<_> = client
            .list_installed()
            .into_iter()
            .map(|r| r.name)
            .collect();
        names.sort();
        assert_eq!(names, ["calc", "mathlib"]);

        // From the cache the second time, checked all the same.
        let downloads = |r: &Registry| {
            r.requests()
                .iter()
                .filter(|r| r.ends_with("/download"))
                .count()
        };
        let before = downloads(&registry);
        assert!(client.install("calc", "1.0.0").await.unwrap().from_cache);
        assert_eq!(downloads(&registry), before);
        let cached = dir.path().join("cache").join("calc-1.0.0.wasm");
        std::fs::write(&cached, b"\0asm tampered").unwrap();
        let err = client.install("calc", "1.0.0").await.unwrap_err();
        assert!(
            matches!(err, MarketplaceError::HashMismatch { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn test_a_hostile_registry_cannot_write_outside_its_directories() {
        // Names and versions went straight into paths and URLs, including
        // the dependencies the registry lists.
        let registry = Registry::start().await;
        let mut calc = skill("calc", &["1.0.0"]);
        calc.dependencies = vec![dependency("../../escape", "1.0.0", false)];
        registry.publish(&calc, "1.0.0", b"\0asm calc");
        let mut versioned = skill("versioned", &["1.0.0"]);
        versioned.dependencies = vec![dependency("mathlib", "../../../x", false)];
        registry.publish(&versioned, "1.0.0", b"\0asm v");
        let (client, dir) = connect(&registry, |c| c).await;

        let err = client.install("calc", "1.0.0").await.unwrap_err();
        assert!(matches!(err, MarketplaceError::InvalidName(_)), "{err}");
        assert!(!dir.path().join("escape").exists());
        assert!(
            !dir.path().join("installed").join("calc").exists(),
            "nothing written"
        );
        let err = client.install("versioned", "1.0.0").await.unwrap_err();
        assert!(matches!(err, MarketplaceError::InvalidVersion(_)), "{err}");

        let before = registry.requests().len();
        for name in ["../calc", "calc/x", "", ".hidden", "a?b", &"a".repeat(129)] {
            assert!(
                matches!(
                    client.install(name, "1.0.0").await,
                    Err(MarketplaceError::InvalidName(_))
                ),
                "{name:?}"
            );
            assert!(client.get_skill(name).await.is_err());
            assert!(client.get_reviews(name, 0, 10).await.is_err());
        }
        for version in ["1.0.0/../x", "^1.0", "", "1 0"] {
            assert!(matches!(
                client.install("calc", version).await,
                Err(MarketplaceError::InvalidVersion(_))
            ));
            assert!(client.get_version("calc", version).await.is_err());
        }
        assert_eq!(
            registry.requests().len(),
            before,
            "refused before any request"
        );
        assert!(
            client.install("calc", "1.0.0+build.5").await.is_err(),
            "valid but unlisted"
        );
    }

    #[tokio::test]
    async fn test_a_download_must_match_its_hash_and_size_limit() {
        let registry = Registry::start().await;
        let calc = skill("calc", &["1.0.0"]);
        registry.publish(&calc, "1.0.0", b"\0asm calc");
        registry.route(
            "GET /skills/calc/versions/1.0.0/download",
            ok(b"\0asm swapped".to_vec()),
        );
        let (client, dir) = connect(&registry, |c| c).await;
        let err = client.install("calc", "1.0.0").await.unwrap_err();
        assert!(
            matches!(err, MarketplaceError::HashMismatch { .. }),
            "{err}"
        );
        assert!(
            !dir.path().join("cache").join("calc-1.0.0.wasm").exists(),
            "not cached"
        );
        assert!(client.list_installed().is_empty());

        // The whole body used to be read, however large: refused by its
        // Content-Length, or while it streams when it has none.
        let big = vec![7u8; 64];
        registry.publish(&calc, "1.0.0", &big);
        let (small, _dir) = connect(&registry, |c| MarketplaceConfig {
            max_download_bytes: 16,
            ..c
        })
        .await;
        let err = small.install("calc", "1.0.0").await.unwrap_err();
        assert!(err.to_string().contains("16-byte limit"), "{err}");
        registry.route(
            "GET /skills/calc/versions/1.0.0/download",
            Route {
                no_length: true,
                ..ok(big.clone())
            },
        );
        let err = small.install("calc", "1.0.0").await.unwrap_err();
        assert!(err.to_string().contains("16-byte limit"), "{err}");

        registry.route(
            "GET /skills/calc/versions/1.0.0/download",
            status(500, "{}"),
        );
        let err = small.install("calc", "1.0.0").await.unwrap_err();
        assert!(matches!(err, MarketplaceError::DownloadFailed(_)), "{err}");
    }

    #[tokio::test]
    async fn test_refused_versions() {
        let registry = Registry::start().await;
        let calc = skill("calc", &["1.0.0", "2.0.0-beta.1"]);
        registry.publish(&calc, "1.0.0", b"\0asm 1");
        registry.publish(&calc, "2.0.0-beta.1", b"\0asm beta");
        let (client, _dir) = connect(&registry, |c| MarketplaceConfig {
            allow_prerelease: false,
            ..c
        })
        .await;
        // allow_prerelease was never read.
        let err = client.install("calc", "2.0.0-beta.1").await.unwrap_err();
        assert!(err.to_string().contains("prerelease"), "{err}");
        let (prerelease, _dir) = connect(&registry, |c| c).await;
        prerelease.install("calc", "2.0.0-beta.1").await.unwrap();

        // A yanked version, and one the skill doesn't list.
        let mut yanked = release("1.0.0", b"\0asm 1");
        yanked.yanked = true;
        yanked.yank_reason = Some("CVE-2026-0001".into());
        registry.route(
            "GET /skills/calc/versions/1.0.0",
            ok(serde_json::to_vec(&yanked).unwrap()),
        );
        let err = client.install("calc", "1.0.0").await.unwrap_err();
        assert!(err.to_string().contains("yanked: CVE-2026-0001"), "{err}");
        assert!(matches!(
            client.install("calc", "3.0.0").await,
            Err(MarketplaceError::VersionNotFound { .. })
        ));
        assert!(is_prerelease("1.0.0-rc.1+build") && !is_prerelease("1.0.0+build-5"));
    }

    #[tokio::test]
    async fn test_dependency_chains_end() {
        // A dependency cycle used to recurse for ever.
        let registry = Registry::start().await;
        let mut a = skill("loop-a", &["1.0.0"]);
        a.dependencies = vec![dependency("loop-b", "1.0.0", false)];
        let mut b = skill("loop-b", &["1.0.0"]);
        b.dependencies = vec![dependency("loop-a", "1.0.0", false)];
        registry.publish(&a, "1.0.0", b"\0asm a");
        registry.publish(&b, "1.0.0", b"\0asm b");
        let (client, dir) = connect(&registry, |c| c).await;
        let err = client.install("loop-a", "1.0.0").await.unwrap_err();
        assert!(
            err.to_string()
                .contains("cycle: loop-a -> loop-b -> loop-a"),
            "{err}"
        );
        assert!(!dir.path().join("installed").join("loop-a").exists());

        // A chain deeper than the limit, without a cycle.
        for depth in 0..=MAX_DEPENDENCY_DEPTH {
            let mut link = skill(&format!("link-{depth}"), &["1.0.0"]);
            link.dependencies = vec![dependency(&format!("link-{}", depth + 1), "1.0.0", false)];
            registry.publish(&link, "1.0.0", format!("\0asm {depth}").as_bytes());
        }
        let err = client.install("link-0", "1.0.0").await.unwrap_err();
        assert!(err.to_string().contains("more than 16 deep"), "{err}");
    }

    #[tokio::test]
    async fn test_signatures_and_publishers_fail_closed() {
        // verify_signatures, the default, used to install unverified.
        let registry = Registry::start().await;
        let calc = skill("calc", &["1.0.0"]);
        registry.publish(&calc, "1.0.0", b"\0asm calc");
        let (strict, _dir) = connect(&registry, |c| MarketplaceConfig {
            verify_signatures: true,
            ..c
        })
        .await;
        let err = strict.install("calc", "1.0.0").await.unwrap_err();
        assert!(matches!(
            err,
            MarketplaceError::SignatureUnverifiable { .. }
        ));
        assert!(err.to_string().contains("docs/adr/0005"), "{err}");
        assert!(registry.requests().is_empty(), "refused before any request");
        assert!(MarketplaceConfig::default().verify_signatures);

        // The trusted list decides; the registry's own `verified` flag used
        // to override it.
        let (listed, _dir) = connect(&registry, |c| c.with_trusted_publisher("acme")).await;
        let err = listed.install("calc", "1.0.0").await.unwrap_err();
        assert!(
            matches!(err, MarketplaceError::UntrustedPublisher(_)),
            "{err}"
        );
        let mut by_acme = calc.clone();
        by_acme.publisher.id = "acme".into();
        registry.publish(&by_acme, "1.0.0", b"\0asm calc");
        listed.clear_cache();
        listed.install("calc", "1.0.0").await.unwrap();
    }

    #[tokio::test]
    async fn test_the_manifest_cannot_be_injected() {
        // The manifest was formatted, so a newline in the registry's
        // description added keys.
        let registry = Registry::start().await;
        let mut calc = skill("calc", &["1.0.0"]);
        calc.description = "adds\npermissions:\n  network: true\nwasm_path: /bin/sh".into();
        registry.publish(&calc, "1.0.0", b"\0asm calc");
        let (client, _dir) = connect(&registry, |c| c).await;
        let installed = client.install("calc", "1.0.0").await.unwrap();
        let manifest_path = installed.install_path.with_file_name("manifest.yaml");
        let manifest = super::super::registry::SkillManifest::from_file(&manifest_path).unwrap();
        assert_eq!(manifest.description, calc.description);
        assert!(!manifest.permissions.network);
        assert_eq!(manifest.wasm_path, installed.install_path);
    }

    #[tokio::test]
    async fn test_uninstall_removes_only_that_skill() {
        // Its cache glob `calc-*.wasm` also matched calc-extra's binaries.
        let registry = Registry::start().await;
        registry.publish(&skill("calc", &["1.0.0"]), "1.0.0", b"\0asm calc");
        registry.publish(&skill("calc-extra", &["1.0.0"]), "1.0.0", b"\0asm extra");
        let (client, dir) = connect(&registry, |c| c).await;
        let calc = client.install("calc", "1.0.0").await.unwrap();
        let extra = client.install("calc-extra", "1.0.0").await.unwrap();

        let removed = client.uninstall("calc").await.unwrap();
        assert_eq!(removed.version, "1.0.0");
        assert_eq!(
            removed.files_removed.len(),
            3,
            "{:?}",
            removed.files_removed
        );
        assert!(!calc.install_path.exists());
        assert!(
            !calc.install_path.parent().unwrap().exists(),
            "empty directory removed"
        );
        assert!(extra.install_path.exists());
        assert!(dir
            .path()
            .join("cache")
            .join("calc-extra-1.0.0.wasm")
            .exists());
        assert!(matches!(
            client.uninstall("calc").await,
            Err(MarketplaceError::SkillNotFound { .. })
        ));
        assert_eq!(client.list_installed().len(), 1);
    }

    #[tokio::test]
    async fn test_queries_and_the_api_key() {
        // The API key was sent only with reviews.
        let registry = Registry::start().await;
        let mut calc = skill("calc", &["1.0.0", "1.1.0"]);
        calc.version = "1.1.0".into();
        registry.publish(&calc, "1.1.0", b"\0asm 1.1");
        let results = SearchResults {
            skills: vec![calc.clone()],
            total: 1,
            page: 0,
            page_size: 20,
            has_more: false,
        };
        registry.route(
            "POST /skills/search",
            ok(serde_json::to_vec(&results).unwrap()),
        );
        let review = SkillReview {
            id: "r1".into(),
            reviewer: "ann".into(),
            rating: 5,
            title: "good".into(),
            body: "works".into(),
            version: "1.1.0".into(),
            created_at: 1,
            helpful_count: 0,
        };
        registry.route(
            "GET /skills/calc/reviews?page=0&page_size=10",
            ok(serde_json::to_vec(&vec![review.clone()]).unwrap()),
        );
        registry.route(
            "POST /skills/calc/reviews",
            ok(serde_json::to_vec(&review).unwrap()),
        );
        let (client, _dir) = connect(&registry, |c| c.with_api_key("k-123")).await;

        let found = client.search(&SkillQuery::new("calc")).await.unwrap();
        assert_eq!(found.skills[0].name, "calc");
        client.search(&SkillQuery::new("calc")).await.unwrap();
        assert_eq!(client.get_popular(5).await.unwrap().len(), 1);
        assert_eq!(client.get_recent(5).await.unwrap().len(), 1);
        assert_eq!(client.get_reviews("calc", 0, 10).await.unwrap()[0].id, "r1");
        assert_eq!(
            client
                .submit_review("calc", "1.1.0", 5, "good", "works")
                .await
                .unwrap()
                .title,
            "good"
        );
        assert_eq!(
            client.update("calc").await.unwrap().version,
            "1.1.0",
            "the latest"
        );
        let get = client.get_skill("calc").await.unwrap();
        assert_eq!(get.version, "1.1.0");
        assert_eq!(
            client.get_version("calc", "1.1.0").await.unwrap().version,
            "1.1.0"
        );

        let requests = registry.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("POST /skills/search"))
                .count(),
            3,
            "the repeated search came from the cache: {requests:?}"
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("GET /skills/calc "))
                .count(),
            1,
            "so did the skill: {requests:?}"
        );
        assert!(
            requests.iter().all(|r| r.ends_with("[Bearer k-123]")),
            "{requests:?}"
        );
        assert!(format!("{client:?}").contains(&registry.url));
    }

    #[tokio::test]
    async fn test_registry_errors() {
        let registry = Registry::start().await;
        registry.route(
            "POST /skills/search",
            Route {
                headers: vec![("Retry-After", "7".into())],
                ..status(429, "{}")
            },
        );
        registry.route("GET /skills/broken", status(500, "{}"));
        registry.route("GET /skills/garbled", ok("not json"));
        registry.route("GET /skills/calc/versions/9.0.0", status(500, "{}"));
        registry.route(
            "GET /skills/calc/reviews?page=0&page_size=1",
            status(503, "{}"),
        );
        registry.route("POST /skills/calc/reviews", status(401, "{}"));
        let (client, _dir) = connect(&registry, |c| MarketplaceConfig {
            enable_cache: false,
            ..c
        })
        .await;

        assert!(matches!(
            client.search(&SkillQuery::new("x")).await,
            Err(MarketplaceError::RateLimited {
                retry_after_secs: 7
            })
        ));
        registry.route("POST /skills/search", status(502, "{}"));
        assert!(matches!(
            client.search(&SkillQuery::new("y")).await,
            Err(MarketplaceError::NetworkError(_))
        ));
        registry.route("POST /skills/search", ok("[]"));
        assert!(matches!(
            client.search(&SkillQuery::new("z")).await,
            Err(MarketplaceError::SerializationError(_))
        ));
        assert!(matches!(
            client.get_skill("missing").await,
            Err(MarketplaceError::SkillNotFound { .. })
        ));
        assert!(matches!(
            client.get_skill("broken").await,
            Err(MarketplaceError::NetworkError(_))
        ));
        assert!(matches!(
            client.get_skill("garbled").await,
            Err(MarketplaceError::SerializationError(_))
        ));
        assert!(matches!(
            client.get_version("calc", "8.0.0").await,
            Err(MarketplaceError::VersionNotFound { .. })
        ));
        assert!(matches!(
            client.get_version("calc", "9.0.0").await,
            Err(MarketplaceError::NetworkError(_))
        ));
        assert!(client.get_reviews("calc", 0, 1).await.is_err());
        assert!(matches!(
            client.submit_review("calc", "1.0.0", 5, "t", "b").await,
            Err(MarketplaceError::AuthenticationRequired)
        ));
        let (keyed, _dir) = connect(&registry, |c| c.with_api_key("bad")).await;
        assert!(matches!(
            keyed.submit_review("calc", "1.0.0", 5, "t", "b").await,
            Err(MarketplaceError::AuthenticationFailed(_))
        ));
        registry.route("POST /skills/calc/reviews", status(500, "{}"));
        assert!(matches!(
            keyed.submit_review("calc", "1.0.0", 5, "t", "b").await,
            Err(MarketplaceError::NetworkError(_))
        ));

        // Nothing listening.
        let (offline, _dir) = connect(&registry, |c| MarketplaceConfig {
            registry_url: "http://127.0.0.1:9".into(),
            ..c
        })
        .await;
        assert!(matches!(
            offline.get_skill("calc").await,
            Err(MarketplaceError::NetworkError(_))
        ));
    }

    #[test]
    fn test_a_clock_moving_back_does_not_panic_the_cache() {
        // The age was `now - cached_at` on u64.
        let client = tokio_test::block_on(MarketplaceClient::new(
            MarketplaceConfig::local("http://127.0.0.1:9")
                .with_cache_dir(tempfile::tempdir().unwrap().path().join("c")),
        ))
        .unwrap();
        let future = now_secs() + 3600;
        client.cache.write().unwrap().insert(
            "calc".into(),
            CacheEntry {
                data: skill("calc", &["1.0.0"]),
                cached_at: future,
            },
        );
        client.search_cache.write().unwrap().insert(
            "q".into(),
            CacheEntry {
                data: SearchResults {
                    skills: vec![],
                    total: 0,
                    page: 0,
                    page_size: 0,
                    has_more: false,
                },
                cached_at: future,
            },
        );
        assert!(client.get_cache("calc").is_some());
        assert!(client.get_search_cache("q").is_some());
        client.clear_cache();
        assert!(client.get_cache("calc").is_none());
    }

    #[test]
    fn test_names_versions_and_display() {
        for valid in [
            "calc",
            "crypto-hasher",
            "json_validator",
            "v2.0",
            "a+b",
            "1.0.0-beta.1+build",
        ] {
            assert!(is_safe_component(valid), "{valid}");
        }
        for invalid in [
            "", "-x", ".x", "_x", "a/b", "a\\b", "..", "a b", "a?b", "a#b", "é",
        ] {
            assert!(!is_safe_component(invalid), "{invalid:?}");
        }
        for (category, text) in [
            (SkillCategory::Text, "text"),
            (SkillCategory::Data, "data"),
            (SkillCategory::FileSystem, "filesystem"),
            (SkillCategory::Database, "database"),
            (SkillCategory::Security, "security"),
            (SkillCategory::Utility, "utility"),
            (SkillCategory::Ai, "ai"),
        ] {
            assert_eq!(category.to_string(), text);
            assert_eq!(
                SkillQuery::new("q").with_category(text).categories.unwrap()[0],
                category
            );
        }
        for (license, text) in [
            (SkillLicense::Bsd3, "BSD-3-Clause"),
            (SkillLicense::Gpl3, "GPL-3.0"),
            (SkillLicense::Proprietary, "Proprietary"),
        ] {
            assert_eq!(license.to_string(), text);
        }
        let query = SkillQuery::new("q")
            .with_publisher("acme")
            .with_category("weird");
        assert_eq!(query.publisher.as_deref(), Some("acme"));
        assert_eq!(
            query.categories.unwrap()[0],
            SkillCategory::Custom("weird".into())
        );
        let config: MarketplaceConfig =
            serde_json::from_value(serde_json::to_value(MarketplaceConfig::default()).unwrap())
                .unwrap();
        assert_eq!(config.max_download_bytes, 64 * 1024 * 1024);
        let mut old = serde_json::to_value(MarketplaceConfig::default()).unwrap();
        old.as_object_mut().unwrap().remove("max_download_bytes");
        let old: MarketplaceConfig = serde_json::from_value(old).unwrap();
        assert_eq!(
            old.max_download_bytes,
            64 * 1024 * 1024,
            "older configs get the default"
        );
    }
}
