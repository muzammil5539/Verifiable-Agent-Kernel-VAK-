//! Skill Registry for managing WASM skill manifests and permissions
//!
//! This module provides a registry for loading, managing, and validating
//! WASM skills and their associated permissions. Skills are defined via
//! YAML manifest files that specify metadata, permissions, and schemas.
//!
//! # Features
//! - Skill manifest loading and validation
//! - Permission-based access control
//! - Cryptographic signature verification (SBX-002)
//!
//! # Example
//!
//! ```no_run
//! use std::path::PathBuf;
//! use vak::sandbox::registry::SkillRegistry;
//!
//! let mut registry = SkillRegistry::new(PathBuf::from("./skills"));
//! let skill_ids = registry.load_all_skills().unwrap();
//!
//! for skill in registry.list_skills() {
//!     println!("Loaded skill: {} v{}", skill.name, skill.version);
//! }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

/// Unique identifier for a loaded skill
///
/// Generated when a skill is loaded into the registry.
/// Implements common traits for use in collections and display.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SkillId(Uuid);

impl SkillId {
    /// Create a new random SkillId
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a SkillId from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the underlying UUID
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for SkillId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SkillId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for SkillId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SkillId({})", self.0)
    }
}

/// Permissions granted to a skill during execution
///
/// Defines resource limits and access permissions for a skill.
/// These are enforced by the WASM sandbox during execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SkillPermissions {
    /// Whether the skill can make network requests
    #[serde(default)]
    pub network: bool,

    /// Allowed filesystem paths (glob patterns)
    #[serde(default)]
    pub filesystem: Vec<String>,

    /// Allowed environment variable patterns
    #[serde(default)]
    pub env_vars: Vec<String>,

    /// Maximum memory limit in megabytes
    #[serde(default = "default_max_memory_mb")]
    pub max_memory_mb: u32,

    /// Maximum execution time in milliseconds
    #[serde(default = "default_max_execution_ms")]
    pub max_execution_ms: u64,
}

fn default_max_memory_mb() -> u32 {
    64
}

fn default_max_execution_ms() -> u64 {
    5000
}

impl Default for SkillPermissions {
    fn default() -> Self {
        Self {
            network: false,
            filesystem: Vec::new(),
            env_vars: Vec::new(),
            max_memory_mb: default_max_memory_mb(),
            max_execution_ms: default_max_execution_ms(),
        }
    }
}

/// Manifest describing a skill and its requirements
///
/// The manifest is typically loaded from a YAML file and contains
/// all metadata needed to load and execute a skill safely.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillManifest {
    /// Unique name identifier for the skill
    pub name: String,

    /// Semantic version string (e.g., "1.0.0")
    pub version: String,

    /// Human-readable description of what the skill does
    pub description: String,

    /// Optional author information
    #[serde(default)]
    pub author: Option<String>,

    /// Permissions required by this skill
    #[serde(default)]
    pub permissions: SkillPermissions,

    /// JSON Schema for validating input to the skill
    pub input_schema: serde_json::Value,

    /// JSON Schema for validating output from the skill
    pub output_schema: serde_json::Value,

    /// Path to the WASM binary (relative to manifest or absolute)
    pub wasm_path: PathBuf,

    /// Optional cryptographic signature for skill verification (SBX-002)
    #[serde(default)]
    pub signature: Option<String>,
}

impl SkillManifest {
    /// Load a manifest from a YAML file
    ///
    /// # Arguments
    /// * `path` - Path to the YAML manifest file
    ///
    /// # Returns
    /// * The parsed manifest or a RegistryError
    pub fn from_file(path: &Path) -> Result<Self, RegistryError> {
        let content = std::fs::read_to_string(path).map_err(|e| RegistryError::IoError {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;

        let mut manifest: SkillManifest =
            serde_yaml::from_str(&content).map_err(|e| RegistryError::ParseError {
                path: path.to_path_buf(),
                message: e.to_string(),
            })?;

        // Resolve relative wasm_path to be relative to the manifest file
        if manifest.wasm_path.is_relative() {
            if let Some(parent) = path.parent() {
                manifest.wasm_path = parent.join(&manifest.wasm_path);
            }
        }

        Ok(manifest)
    }

    /// Validate that the manifest has all required fields
    pub fn validate(&self) -> Result<(), RegistryError> {
        if self.name.is_empty() {
            return Err(RegistryError::ValidationError {
                field: "name".to_string(),
                message: "Skill name cannot be empty".to_string(),
            });
        }

        if self.version.is_empty() {
            return Err(RegistryError::ValidationError {
                field: "version".to_string(),
                message: "Skill version cannot be empty".to_string(),
            });
        }

        Ok(())
    }
}

/// Errors that can occur during registry operations
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// IO error while reading files
    #[error("IO error reading {path}: {message}")]
    IoError {
        /// Path that caused the error
        path: PathBuf,
        /// Error description
        message: String,
    },

    /// Error parsing manifest YAML
    #[error("Parse error in {path}: {message}")]
    ParseError {
        /// Path to the file with parse error
        path: PathBuf,
        /// Parse error description
        message: String,
    },

    /// Manifest validation error
    #[error("Validation error for field '{field}': {message}")]
    ValidationError {
        /// Field that failed validation
        field: String,
        /// Validation error message
        message: String,
    },

    /// Skill with the same name already loaded
    #[error("Skill '{name}' is already loaded with ID {existing_id}")]
    DuplicateSkill {
        /// Name of the duplicate skill
        name: String,
        /// ID of the existing skill
        existing_id: SkillId,
    },

    /// Skill not found in registry
    #[error("Skill with ID {0} not found")]
    SkillNotFound(SkillId),

    /// Skills directory does not exist
    #[error("Skills directory does not exist: {0}")]
    DirectoryNotFound(PathBuf),
}

/// Errors that can occur during permission validation
#[derive(Debug, thiserror::Error)]
pub enum PermissionError {
    /// Network access not allowed
    #[error("Network access not permitted for skill {skill_id}")]
    NetworkNotAllowed {
        /// ID of the skill
        skill_id: SkillId,
    },

    /// Filesystem path not allowed
    #[error("Filesystem access to '{path}' not permitted for skill {skill_id}")]
    FilesystemPathNotAllowed {
        /// ID of the skill
        skill_id: SkillId,
        /// Requested path
        path: String,
    },

    /// Environment variable access not allowed
    #[error("Environment variable '{var}' not permitted for skill {skill_id}")]
    EnvVarNotAllowed {
        /// ID of the skill
        skill_id: SkillId,
        /// Requested environment variable
        var: String,
    },

    /// Memory limit exceeded
    #[error("Requested memory {requested_mb}MB exceeds limit {limit_mb}MB for skill {skill_id}")]
    MemoryLimitExceeded {
        /// ID of the skill
        skill_id: SkillId,
        /// Requested memory in MB
        requested_mb: u32,
        /// Allowed limit in MB
        limit_mb: u32,
    },

    /// Execution time limit exceeded
    #[error(
        "Requested execution time {requested_ms}ms exceeds limit {limit_ms}ms for skill {skill_id}"
    )]
    ExecutionTimeLimitExceeded {
        /// ID of the skill
        skill_id: SkillId,
        /// Requested execution time in ms
        requested_ms: u64,
        /// Allowed limit in ms
        limit_ms: u64,
    },

    /// Skill not found in registry
    #[error("Skill with ID {0} not found")]
    SkillNotFound(SkillId),
}

// ============================================================================
// Signature Verification (SBX-002)
// ============================================================================

/// Errors that can occur during signature verification
#[derive(Debug, Clone, thiserror::Error)]
pub enum SignatureError {
    /// No signature found when one was required
    #[error("Signature required but not found for skill '{skill_name}'")]
    SignatureRequired {
        /// Name of the skill missing a signature
        skill_name: String,
    },

    /// Signature format is invalid
    #[error("Invalid signature format: {message}")]
    InvalidFormat {
        /// Description of the format error
        message: String,
    },

    /// Signature verification failed
    #[error("Signature verification failed for skill '{skill_name}': computed={computed}, expected={expected}")]
    VerificationFailed {
        /// Name of the skill that failed verification
        skill_name: String,
        /// The computed signature
        computed: String,
        /// The expected signature from the manifest
        expected: String,
    },

    /// Public key not found in trusted keys
    #[error("Public key '{key_id}' is not in the trusted key set")]
    UntrustedKey {
        /// The key ID that was not found
        key_id: String,
    },

    /// WASM binary not found or unreadable
    #[error("WASM binary not found at {path}: {message}")]
    WasmNotFound {
        /// Path to the WASM binary
        path: PathBuf,
        /// Error message
        message: String,
    },
}

/// Configuration for signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureConfig {
    /// Whether signature verification is required
    pub require_signatures: bool,

    /// Trusted public key IDs (SHA-256 of the key)
    pub trusted_keys: Vec<String>,

    /// Whether to allow unsigned skills in development mode
    pub allow_unsigned_in_dev: bool,
}

impl Default for SignatureConfig {
    fn default() -> Self {
        Self {
            require_signatures: true,
            trusted_keys: Vec::new(),
            allow_unsigned_in_dev: false,
        }
    }
}

impl SignatureConfig {
    /// Create a new config requiring signatures
    pub fn strict() -> Self {
        Self {
            require_signatures: true,
            trusted_keys: Vec::new(),
            allow_unsigned_in_dev: false,
        }
    }

    /// Create a permissive configuration intended for development
    /// where unsigned skills are explicitly allowed.
    pub fn permissive_dev() -> Self {
        Self {
            require_signatures: false,
            trusted_keys: Vec::new(),
            allow_unsigned_in_dev: true,
        }
    }

    /// Add a trusted key
    pub fn with_trusted_key(mut self, key: impl Into<String>) -> Self {
        self.trusted_keys.push(key.into());
        self
    }

    /// Toggle allowance for unsigned skills in development scenarios.
    pub fn with_allow_unsigned_in_dev(mut self, allow: bool) -> Self {
        self.allow_unsigned_in_dev = allow;
        self
    }
}

/// Signature verification result
#[derive(Debug, Clone)]
pub struct SignatureVerificationResult {
    /// Whether verification passed
    pub valid: bool,

    /// The computed signature hash
    pub computed_signature: String,

    /// The expected signature (from manifest)
    pub expected_signature: Option<String>,

    /// Key ID that was used (if applicable)
    pub key_id: Option<String>,

    /// Additional details about the verification
    pub details: String,
}

impl SignatureVerificationResult {
    /// Create a successful verification result
    pub fn success(computed: impl Into<String>, expected: impl Into<String>) -> Self {
        Self {
            valid: true,
            computed_signature: computed.into(),
            expected_signature: Some(expected.into()),
            key_id: None,
            details: "Signature verification successful".to_string(),
        }
    }

    /// Create a failed verification result
    pub fn failure(
        computed: impl Into<String>,
        expected: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            valid: false,
            computed_signature: computed.into(),
            expected_signature: Some(expected.into()),
            key_id: None,
            details: details.into(),
        }
    }

    /// Create a result for unsigned skill (allowed)
    pub fn unsigned_allowed() -> Self {
        Self {
            valid: true,
            computed_signature: String::new(),
            expected_signature: None,
            key_id: None,
            details: "No signature present, unsigned skills allowed".to_string(),
        }
    }
}

/// Skill signature verifier
///
/// Verifies that skill manifests and WASM binaries have valid cryptographic
/// signatures from trusted sources. This provides integrity verification
/// and supply chain security for loaded skills.
#[derive(Debug)]
pub struct SkillSignatureVerifier {
    config: SignatureConfig,
}

impl SkillSignatureVerifier {
    /// Create a new signature verifier with the given configuration
    pub fn new(config: SignatureConfig) -> Self {
        Self { config }
    }

    /// Create a verifier with default (permissive) configuration
    pub fn permissive() -> Self {
        Self::new(SignatureConfig::permissive_dev())
    }

    /// Create a verifier with strict configuration
    pub fn strict() -> Self {
        Self::new(SignatureConfig::strict())
    }

    /// Verify a skill manifest and its WASM binary
    pub fn verify_skill(
        &self,
        manifest: &SkillManifest,
    ) -> Result<SignatureVerificationResult, SignatureError> {
        // If no signature and signatures are not required, allow
        if manifest.signature.is_none() {
            if self.config.require_signatures && !self.config.allow_unsigned_in_dev {
                return Err(SignatureError::SignatureRequired {
                    skill_name: manifest.name.clone(),
                });
            }
            return Ok(SignatureVerificationResult::unsigned_allowed());
        }

        let signature = manifest.signature.as_ref().unwrap();

        // Compute the expected signature
        let computed = self.compute_signature(manifest)?;

        // Verify the signature matches
        if computed != *signature {
            return Ok(SignatureVerificationResult::failure(
                &computed,
                signature,
                "Computed signature does not match manifest signature",
            ));
        }

        Ok(SignatureVerificationResult::success(&computed, signature))
    }

    /// Compute the signature for a manifest
    ///
    /// The signature is computed as:
    /// SHA256(name || version || description || permissions_json || wasm_sha256)
    pub fn compute_signature(&self, manifest: &SkillManifest) -> Result<String, SignatureError> {
        let mut hasher = Sha256::new();

        // Include manifest metadata
        hasher.update(manifest.name.as_bytes());
        hasher.update(b"|");
        hasher.update(manifest.version.as_bytes());
        hasher.update(b"|");
        hasher.update(manifest.description.as_bytes());
        hasher.update(b"|");

        // Include permissions as JSON
        let permissions_json = serde_json::to_string(&manifest.permissions).map_err(|e| {
            SignatureError::InvalidFormat {
                message: format!("Failed to serialize permissions: {}", e),
            }
        })?;
        hasher.update(permissions_json.as_bytes());
        hasher.update(b"|");

        // Include WASM binary hash if the file exists
        if manifest.wasm_path.exists() {
            let wasm_bytes =
                std::fs::read(&manifest.wasm_path).map_err(|e| SignatureError::WasmNotFound {
                    path: manifest.wasm_path.clone(),
                    message: e.to_string(),
                })?;

            let wasm_hash = Sha256::digest(&wasm_bytes);
            hasher.update(wasm_hash);
        } else {
            // For manifests without WASM yet, use the path
            hasher.update(manifest.wasm_path.to_string_lossy().as_bytes());
        }

        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    /// Sign a manifest (returns the signature to be added to the manifest)
    pub fn sign_manifest(&self, manifest: &SkillManifest) -> Result<String, SignatureError> {
        self.compute_signature(manifest)
    }

    /// Check if a key is trusted
    pub fn is_key_trusted(&self, key_id: &str) -> bool {
        self.config.trusted_keys.contains(&key_id.to_string())
    }

    /// Get the configuration
    pub fn config(&self) -> &SignatureConfig {
        &self.config
    }
}

impl Default for SkillSignatureVerifier {
    fn default() -> Self {
        Self::strict()
    }
}

/// Registry for managing loaded skills
///
/// The registry maintains a collection of loaded skill manifests,
/// indexed by both SkillId and skill name for efficient lookup.
#[derive(Debug)]
pub struct SkillRegistry {
    /// Directory containing skill manifests
    skills_directory: PathBuf,

    /// Map from SkillId to manifest
    skills: HashMap<SkillId, SkillManifest>,

    /// Map from skill name to SkillId for name-based lookup
    name_index: HashMap<String, SkillId>,

    /// Optional signature verifier for SBX-002
    signature_verifier: Option<SkillSignatureVerifier>,
}

impl SkillRegistry {
    /// Create a new skill registry with the given skills directory
    ///
    /// # Arguments
    /// * `skills_directory` - Path to the directory containing skill manifests
    ///
    /// # Example
    /// ```no_run
    /// use std::path::PathBuf;
    /// use vak::sandbox::registry::SkillRegistry;
    ///
    /// let registry = SkillRegistry::new(PathBuf::from("./skills"));
    /// ```
    pub fn new(skills_directory: PathBuf) -> Self {
        Self::new_with_signature_config(skills_directory, SignatureConfig::default())
    }

    /// Create a new registry with an explicit signature configuration
    pub fn new_with_signature_config(
        skills_directory: PathBuf,
        signature_config: SignatureConfig,
    ) -> Self {
        Self {
            skills_directory,
            skills: HashMap::new(),
            name_index: HashMap::new(),
            signature_verifier: Some(SkillSignatureVerifier::new(signature_config)),
        }
    }

    /// Create a registry that explicitly allows unsigned skills (development only)
    pub fn new_permissive_dev(skills_directory: PathBuf) -> Self {
        Self::new_with_signature_config(skills_directory, SignatureConfig::permissive_dev())
    }

    /// Create a new registry with signature verification enabled
    pub fn with_signature_verification(
        skills_directory: PathBuf,
        verifier: SkillSignatureVerifier,
    ) -> Self {
        Self {
            skills_directory,
            skills: HashMap::new(),
            name_index: HashMap::new(),
            signature_verifier: Some(verifier),
        }
    }

    /// Enable signature verification
    pub fn set_signature_verifier(&mut self, verifier: SkillSignatureVerifier) {
        self.signature_verifier = Some(verifier);
    }

    /// Disable signature verification
    pub fn disable_signature_verification(&mut self) {
        self.signature_verifier = None;
    }

    /// Check if signature verification is enabled
    pub fn signature_verification_enabled(&self) -> bool {
        self.signature_verifier.is_some()
    }

    /// Verify a skill's signature (returns error if verification is required and fails)
    pub fn verify_skill_signature(
        &self,
        manifest: &SkillManifest,
    ) -> Result<Option<SignatureVerificationResult>, SignatureError> {
        match &self.signature_verifier {
            Some(verifier) => Ok(Some(verifier.verify_skill(manifest)?)),
            None => Ok(None),
        }
    }

    /// Load a skill from a manifest file
    ///
    /// # Arguments
    /// * `manifest_path` - Path to the YAML manifest file
    ///
    /// # Returns
    /// * The SkillId of the loaded skill, or an error
    ///
    /// # Errors
    /// * `RegistryError::IoError` - If the file cannot be read
    /// * `RegistryError::ParseError` - If the YAML is invalid
    /// * `RegistryError::ValidationError` - If the manifest is invalid
    /// * `RegistryError::DuplicateSkill` - If a skill with the same name is already loaded
    pub fn load_skill(&mut self, manifest_path: &Path) -> Result<SkillId, RegistryError> {
        let manifest = SkillManifest::from_file(manifest_path)?;
        manifest.validate()?;

        // Verify signature if enabled
        if let Some(verifier) = &self.signature_verifier {
            let result =
                verifier
                    .verify_skill(&manifest)
                    .map_err(|e| RegistryError::ValidationError {
                        field: "signature".to_string(),
                        message: e.to_string(),
                    })?;

            if !result.valid {
                return Err(RegistryError::ValidationError {
                    field: "signature".to_string(),
                    message: result.details,
                });
            }

            if result.expected_signature.is_none() {
                warn!(
                    skill = %manifest.name,
                    "Loaded unsigned skill (explicitly allowed by configuration)"
                );
            } else {
                info!(
                    skill = %manifest.name,
                    computed = %result.computed_signature,
                    "Skill signature verified"
                );
            }
        }

        // Check for duplicate
        if let Some(&existing_id) = self.name_index.get(&manifest.name) {
            return Err(RegistryError::DuplicateSkill {
                name: manifest.name,
                existing_id,
            });
        }

        let id = SkillId::new();
        self.name_index.insert(manifest.name.clone(), id);
        self.skills.insert(id, manifest);

        Ok(id)
    }

    /// Load all skill manifests from the skills directory
    ///
    /// Searches for files with .yaml or .yml extension in the skills directory
    /// and its subdirectories.
    ///
    /// # Returns
    /// * A vector of SkillIds for successfully loaded skills
    ///
    /// # Errors
    /// * `RegistryError::DirectoryNotFound` - If the skills directory doesn't exist
    pub fn load_all_skills(&mut self) -> Result<Vec<SkillId>, RegistryError> {
        if !self.skills_directory.exists() {
            return Err(RegistryError::DirectoryNotFound(
                self.skills_directory.clone(),
            ));
        }

        let mut loaded_ids = Vec::new();

        // Search for .yaml and .yml files
        for extension in &["yaml", "yml"] {
            let pattern = format!("{}/**/*.{}", self.skills_directory.display(), extension);

            if let Ok(entries) = glob::glob(&pattern) {
                for entry in entries.flatten() {
                    // Skip non-manifest files (e.g., test files, config files)
                    if entry.file_name().is_some_and(|n| {
                        let name = n.to_string_lossy();
                        name.starts_with('_') || name.contains("test")
                    }) {
                        continue;
                    }

                    match self.load_skill(&entry) {
                        Ok(id) => {
                            tracing::info!("Loaded skill from {}", entry.display());
                            loaded_ids.push(id);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load skill from {}: {}", entry.display(), e);
                        }
                    }
                }
            }
        }

        Ok(loaded_ids)
    }

    /// Get a skill manifest by its ID
    ///
    /// # Arguments
    /// * `id` - The SkillId to look up
    ///
    /// # Returns
    /// * A reference to the manifest, or None if not found
    pub fn get_skill(&self, id: &SkillId) -> Option<&SkillManifest> {
        self.skills.get(id)
    }

    /// Get a skill manifest by its name
    ///
    /// # Arguments
    /// * `name` - The skill name to look up
    ///
    /// # Returns
    /// * A reference to the manifest, or None if not found
    pub fn get_skill_by_name(&self, name: &str) -> Option<&SkillManifest> {
        self.name_index.get(name).and_then(|id| self.skills.get(id))
    }

    /// Get the SkillId for a skill by name
    ///
    /// # Arguments
    /// * `name` - The skill name to look up
    ///
    /// # Returns
    /// * The SkillId, or None if not found
    pub fn get_skill_id_by_name(&self, name: &str) -> Option<SkillId> {
        self.name_index.get(name).copied()
    }

    /// List all loaded skills
    ///
    /// # Returns
    /// * A vector of references to all loaded skill manifests
    pub fn list_skills(&self) -> Vec<&SkillManifest> {
        self.skills.values().collect()
    }

    /// Get the number of loaded skills
    pub fn skill_count(&self) -> usize {
        self.skills.len()
    }

    /// Validate that requested permissions are allowed for a skill
    ///
    /// Compares the requested permissions against the skill's declared permissions
    /// and returns an error if any requested permission exceeds what's allowed.
    ///
    /// # Arguments
    /// * `skill_id` - The ID of the skill to check
    /// * `requested` - The permissions being requested
    ///
    /// # Returns
    /// * Ok(()) if all permissions are allowed
    /// * Err(PermissionError) if any permission is denied
    pub fn validate_permissions(
        &self,
        skill_id: &SkillId,
        requested: &SkillPermissions,
    ) -> Result<(), PermissionError> {
        let manifest = self
            .skills
            .get(skill_id)
            .ok_or(PermissionError::SkillNotFound(*skill_id))?;

        let allowed = &manifest.permissions;

        // Check network permission
        if requested.network && !allowed.network {
            return Err(PermissionError::NetworkNotAllowed {
                skill_id: *skill_id,
            });
        }

        // Check filesystem permissions
        Self::check_glob_permissions(&requested.filesystem, &allowed.filesystem, |path| {
            PermissionError::FilesystemPathNotAllowed {
                skill_id: *skill_id,
                path: path.to_string(),
            }
        })?;

        // Check env var permissions
        Self::check_glob_permissions(&requested.env_vars, &allowed.env_vars, |var| {
            PermissionError::EnvVarNotAllowed {
                skill_id: *skill_id,
                var: var.to_string(),
            }
        })?;

        // Check memory limit
        if requested.max_memory_mb > allowed.max_memory_mb {
            return Err(PermissionError::MemoryLimitExceeded {
                skill_id: *skill_id,
                requested_mb: requested.max_memory_mb,
                limit_mb: allowed.max_memory_mb,
            });
        }

        // Check execution time limit
        if requested.max_execution_ms > allowed.max_execution_ms {
            return Err(PermissionError::ExecutionTimeLimitExceeded {
                skill_id: *skill_id,
                requested_ms: requested.max_execution_ms,
                limit_ms: allowed.max_execution_ms,
            });
        }

        Ok(())
    }

    /// Helper to validate permissions using glob patterns
    fn check_glob_permissions<F>(
        requested_items: &[String],
        allowed_patterns: &[String],
        error_constructor: F,
    ) -> Result<(), PermissionError>
    where
        F: Fn(&str) -> PermissionError,
    {
        for requested in requested_items {
            let mut is_allowed = false;
            for pattern_str in allowed_patterns {
                if let Ok(pattern) = glob::Pattern::new(pattern_str) {
                    if pattern.matches(requested) {
                        is_allowed = true;
                        break;
                    }
                }
                // Also allow exact matches
                if pattern_str == requested {
                    is_allowed = true;
                    break;
                }
            }

            if !is_allowed {
                return Err(error_constructor(requested));
            }
        }
        Ok(())
    }

    /// Unload a skill from the registry
    ///
    /// # Arguments
    /// * `id` - The SkillId of the skill to unload
    ///
    /// # Returns
    /// * true if the skill was found and removed, false otherwise
    pub fn unload_skill(&mut self, id: &SkillId) -> bool {
        if let Some(manifest) = self.skills.remove(id) {
            self.name_index.remove(&manifest.name);
            true
        } else {
            false
        }
    }

    /// Clear all loaded skills from the registry
    pub fn clear(&mut self) {
        self.skills.clear();
        self.name_index.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn create_test_manifest(dir: &Path, name: &str, content: &str) -> PathBuf {
        let path = dir.join(format!("{}.yaml", name));
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        path
    }

    fn permissive_registry(dir: &Path) -> SkillRegistry {
        SkillRegistry::new_permissive_dev(dir.to_path_buf())
    }

    fn sample_manifest_yaml() -> &'static str {
        r#"
name: calculator
version: "1.0.0"
description: "Basic arithmetic operations"
author: "VAK Team"
permissions:
  network: false
  filesystem: []
  env_vars: []
  max_memory_mb: 64
  max_execution_ms: 5000
input_schema:
  type: object
  properties:
    operation:
      type: string
      enum: [add, subtract, multiply, divide]
    a:
      type: number
    b:
      type: number
  required: [operation, a, b]
output_schema:
  type: object
  properties:
    result:
      type: number
wasm_path: "./calculator.wasm"
"#
    }

    fn sample_manifest_with_permissions() -> &'static str {
        r#"
name: file_processor
version: "2.0.0"
description: "File processing skill"
permissions:
  network: true
  filesystem:
    - "/tmp/*"
    - "/data/**"
  env_vars:
    - "HOME"
    - "API_*"
  max_memory_mb: 128
  max_execution_ms: 10000
input_schema:
  type: object
output_schema:
  type: object
wasm_path: "./file_processor.wasm"
"#
    }

    #[test]
    fn test_skill_id_creation() {
        let id1 = SkillId::new();
        let id2 = SkillId::new();

        // IDs should be unique
        assert_ne!(id1, id2);

        // Display and Debug should work
        let display = format!("{}", id1);
        let debug = format!("{:?}", id1);
        assert!(!display.is_empty());
        assert!(debug.starts_with("SkillId("));
    }

    #[test]
    fn test_skill_id_from_uuid() {
        let uuid = Uuid::new_v4();
        let id = SkillId::from_uuid(uuid);
        assert_eq!(*id.as_uuid(), uuid);
    }

    #[test]
    fn test_skill_id_hash_and_eq() {
        use std::collections::HashSet;

        let id1 = SkillId::new();
        let id2 = id1; // Copy

        assert_eq!(id1, id2);

        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_skill_permissions_default() {
        let perms = SkillPermissions::default();
        assert!(!perms.network);
        assert!(perms.filesystem.is_empty());
        assert!(perms.env_vars.is_empty());
        assert_eq!(perms.max_memory_mb, 64);
        assert_eq!(perms.max_execution_ms, 5000);
    }

    #[test]
    fn test_manifest_from_yaml() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "test_skill", sample_manifest_yaml());

        let manifest = SkillManifest::from_file(&path).unwrap();

        assert_eq!(manifest.name, "calculator");
        assert_eq!(manifest.version, "1.0.0");
        assert_eq!(manifest.description, "Basic arithmetic operations");
        assert_eq!(manifest.author, Some("VAK Team".to_string()));
        assert!(!manifest.permissions.network);
        assert_eq!(manifest.permissions.max_memory_mb, 64);
        assert!(manifest.signature.is_none());
    }

    #[test]
    fn test_manifest_wasm_path_resolution() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "test_skill", sample_manifest_yaml());

        let manifest = SkillManifest::from_file(&path).unwrap();

        // wasm_path should be resolved relative to the manifest
        assert!(manifest.wasm_path.starts_with(temp_dir.path()));
        assert!(manifest.wasm_path.ends_with("calculator.wasm"));
    }

    #[test]
    fn test_manifest_validation() {
        let temp_dir = TempDir::new().unwrap();

        // Empty name should fail
        let empty_name = r#"
name: ""
version: "1.0.0"
description: "Test"
input_schema: {}
output_schema: {}
wasm_path: "./test.wasm"
"#;
        let path = create_test_manifest(temp_dir.path(), "empty_name", empty_name);
        let manifest = SkillManifest::from_file(&path).unwrap();
        assert!(matches!(
            manifest.validate(),
            Err(RegistryError::ValidationError { field, .. }) if field == "name"
        ));

        // Empty version should fail
        let empty_version = r#"
name: "test"
version: ""
description: "Test"
input_schema: {}
output_schema: {}
wasm_path: "./test.wasm"
"#;
        let path = create_test_manifest(temp_dir.path(), "empty_version", empty_version);
        let manifest = SkillManifest::from_file(&path).unwrap();
        assert!(matches!(
            manifest.validate(),
            Err(RegistryError::ValidationError { field, .. }) if field == "version"
        ));
    }

    #[test]
    fn test_manifest_parse_error() {
        let temp_dir = TempDir::new().unwrap();
        let invalid_yaml = "not: valid: yaml: [[";
        let path = create_test_manifest(temp_dir.path(), "invalid", invalid_yaml);

        let result = SkillManifest::from_file(&path);
        assert!(matches!(result, Err(RegistryError::ParseError { .. })));
    }

    #[test]
    fn test_registry_new() {
        let registry = SkillRegistry::new(PathBuf::from("./skills"));
        assert_eq!(registry.skill_count(), 0);
        assert!(registry.list_skills().is_empty());
    }

    #[test]
    fn test_registry_load_skill() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        assert_eq!(registry.skill_count(), 1);

        let skill = registry.get_skill(&id).unwrap();
        assert_eq!(skill.name, "calculator");
    }

    #[test]
    fn test_registry_rejects_unsigned_when_strict() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
        let result = registry.load_skill(&path);

        assert!(matches!(
            result,
            Err(RegistryError::ValidationError { field, .. }) if field == "signature"
        ));
    }

    #[test]
    fn test_registry_get_skill_by_name() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        registry.load_skill(&path).unwrap();

        let skill = registry.get_skill_by_name("calculator").unwrap();
        assert_eq!(skill.version, "1.0.0");

        assert!(registry.get_skill_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_registry_duplicate_skill() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        let first_id = registry.load_skill(&path).unwrap();

        // Create another manifest with the same name
        let path2 = create_test_manifest(temp_dir.path(), "calculator2", sample_manifest_yaml());
        let result = registry.load_skill(&path2);

        assert!(matches!(
            result,
            Err(RegistryError::DuplicateSkill { existing_id, .. }) if existing_id == first_id
        ));
    }

    #[test]
    fn test_registry_load_all_skills() {
        let temp_dir = TempDir::new().unwrap();

        // Create multiple manifests
        create_test_manifest(temp_dir.path(), "skill1", sample_manifest_yaml());
        create_test_manifest(
            temp_dir.path(),
            "skill2",
            &sample_manifest_yaml().replace("calculator", "skill2"),
        );

        // Also test .yml extension
        let yml_content = sample_manifest_yaml().replace("calculator", "skill3");
        let yml_path = temp_dir.path().join("skill3.yml");
        std::fs::write(&yml_path, yml_content).unwrap();

        let mut registry = permissive_registry(temp_dir.path());
        let ids = registry.load_all_skills().unwrap();

        // Should load calculator, skill2, and skill3
        assert_eq!(ids.len(), 3);
        assert_eq!(registry.skill_count(), 3);
    }

    #[test]
    fn test_registry_load_all_skills_directory_not_found() {
        let mut registry = SkillRegistry::new(PathBuf::from("/nonexistent/path"));
        let result = registry.load_all_skills();
        assert!(matches!(result, Err(RegistryError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_registry_unload_skill() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        assert_eq!(registry.skill_count(), 1);
        assert!(registry.unload_skill(&id));
        assert_eq!(registry.skill_count(), 0);
        assert!(registry.get_skill(&id).is_none());
        assert!(registry.get_skill_by_name("calculator").is_none());

        // Unloading again should return false
        assert!(!registry.unload_skill(&id));
    }

    #[test]
    fn test_registry_clear() {
        let temp_dir = TempDir::new().unwrap();
        create_test_manifest(temp_dir.path(), "skill1", sample_manifest_yaml());
        create_test_manifest(
            temp_dir.path(),
            "skill2",
            &sample_manifest_yaml().replace("calculator", "skill2"),
        );

        let mut registry = permissive_registry(temp_dir.path());
        registry.load_all_skills().unwrap();

        assert_eq!(registry.skill_count(), 2);
        registry.clear();
        assert_eq!(registry.skill_count(), 0);
    }

    #[test]
    fn test_validate_permissions_network_denied() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            network: true, // Requesting network, but calculator doesn't allow it
            ..Default::default()
        };

        let result = registry.validate_permissions(&id, &requested);
        assert!(matches!(
            result,
            Err(PermissionError::NetworkNotAllowed { .. })
        ));
    }

    #[test]
    fn test_validate_permissions_network_allowed() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(
            temp_dir.path(),
            "file_processor",
            sample_manifest_with_permissions(),
        );

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            network: true,
            ..Default::default()
        };

        assert!(registry.validate_permissions(&id, &requested).is_ok());
    }

    #[test]
    fn test_validate_permissions_memory_exceeded() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            max_memory_mb: 256, // Exceeds the 64MB limit
            ..Default::default()
        };

        let result = registry.validate_permissions(&id, &requested);
        assert!(matches!(
            result,
            Err(PermissionError::MemoryLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_validate_permissions_execution_time_exceeded() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            max_execution_ms: 60000, // Exceeds the 5000ms limit
            ..Default::default()
        };

        let result = registry.validate_permissions(&id, &requested);
        assert!(matches!(
            result,
            Err(PermissionError::ExecutionTimeLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_validate_permissions_filesystem_allowed() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(
            temp_dir.path(),
            "file_processor",
            sample_manifest_with_permissions(),
        );

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            filesystem: vec!["/tmp/test.txt".to_string()],
            ..Default::default()
        };

        // /tmp/* should match /tmp/test.txt
        assert!(registry.validate_permissions(&id, &requested).is_ok());
    }

    #[test]
    fn test_validate_permissions_filesystem_denied() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(
            temp_dir.path(),
            "file_processor",
            sample_manifest_with_permissions(),
        );

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            filesystem: vec!["/etc/passwd".to_string()], // Not in allowed paths
            ..Default::default()
        };

        let result = registry.validate_permissions(&id, &requested);
        assert!(matches!(
            result,
            Err(PermissionError::FilesystemPathNotAllowed { .. })
        ));
    }

    #[test]
    fn test_validate_permissions_env_var_allowed() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(
            temp_dir.path(),
            "file_processor",
            sample_manifest_with_permissions(),
        );

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            env_vars: vec!["HOME".to_string(), "API_KEY".to_string()],
            ..Default::default()
        };

        // HOME is explicitly allowed, API_* should match API_KEY
        assert!(registry.validate_permissions(&id, &requested).is_ok());
    }

    #[test]
    fn test_validate_permissions_env_var_denied() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(
            temp_dir.path(),
            "file_processor",
            sample_manifest_with_permissions(),
        );

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        let requested = SkillPermissions {
            env_vars: vec!["SECRET_KEY".to_string()], // Not in allowed patterns
            ..Default::default()
        };

        let result = registry.validate_permissions(&id, &requested);
        assert!(matches!(
            result,
            Err(PermissionError::EnvVarNotAllowed { .. })
        ));
    }

    #[test]
    fn test_validate_permissions_skill_not_found() {
        let temp_dir = TempDir::new().unwrap();
        let registry = SkillRegistry::new(temp_dir.path().to_path_buf());

        let nonexistent_id = SkillId::new();
        let requested = SkillPermissions::default();

        let result = registry.validate_permissions(&nonexistent_id, &requested);
        assert!(matches!(result, Err(PermissionError::SkillNotFound(_))));
    }

    #[test]
    fn test_validate_permissions_all_allowed() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(
            temp_dir.path(),
            "file_processor",
            sample_manifest_with_permissions(),
        );

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        // Request permissions within the allowed limits
        let requested = SkillPermissions {
            network: true,
            filesystem: vec![
                "/tmp/file.txt".to_string(),
                "/data/subdir/file.csv".to_string(),
            ],
            env_vars: vec!["HOME".to_string(), "API_TOKEN".to_string()],
            max_memory_mb: 128,
            max_execution_ms: 10000,
        };

        assert!(registry.validate_permissions(&id, &requested).is_ok());
    }

    #[test]
    fn test_list_skills() {
        let temp_dir = TempDir::new().unwrap();
        create_test_manifest(temp_dir.path(), "skill1", sample_manifest_yaml());
        create_test_manifest(
            temp_dir.path(),
            "skill2",
            &sample_manifest_yaml().replace("calculator", "skill2"),
        );

        let mut registry = permissive_registry(temp_dir.path());
        registry.load_all_skills().unwrap();

        let skills = registry.list_skills();
        assert_eq!(skills.len(), 2);

        let names: Vec<&str> = skills.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"calculator"));
        assert!(names.contains(&"skill2"));
    }

    #[test]
    fn test_get_skill_id_by_name() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = permissive_registry(temp_dir.path());
        let id = registry.load_skill(&path).unwrap();

        assert_eq!(registry.get_skill_id_by_name("calculator"), Some(id));
        assert_eq!(registry.get_skill_id_by_name("nonexistent"), None);
    }

    #[test]
    fn test_skill_manifest_serialization() {
        let permissions = SkillPermissions {
            network: true,
            filesystem: vec!["/tmp/*".to_string()],
            env_vars: vec!["HOME".to_string()],
            max_memory_mb: 128,
            max_execution_ms: 10000,
        };

        let manifest = SkillManifest {
            name: "test_skill".to_string(),
            version: "1.0.0".to_string(),
            description: "A test skill".to_string(),
            author: Some("Test Author".to_string()),
            permissions,
            input_schema: serde_json::json!({ "type": "object" }),
            output_schema: serde_json::json!({ "type": "object" }),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        // Test serialization to YAML
        let yaml = serde_yaml::to_string(&manifest).unwrap();
        assert!(yaml.contains("name: test_skill"));
        assert!(yaml.contains("version: 1.0.0"));

        // Test deserialization from YAML
        let deserialized: SkillManifest = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(deserialized.name, manifest.name);
        assert_eq!(deserialized.version, manifest.version);
    }

    // =========================================================================
    // Signature Verification Tests (SBX-002)
    // =========================================================================

    #[test]
    fn test_signature_config_default() {
        let config = SignatureConfig::default();
        assert!(config.require_signatures);
        assert!(config.trusted_keys.is_empty());
        assert!(!config.allow_unsigned_in_dev);
    }

    #[test]
    fn test_signature_config_strict() {
        let config = SignatureConfig::strict();
        assert!(config.require_signatures);
        assert!(config.trusted_keys.is_empty());
        assert!(!config.allow_unsigned_in_dev);
    }

    #[test]
    fn test_signature_config_builder() {
        let config = SignatureConfig::strict()
            .with_trusted_key("key1")
            .with_trusted_key("key2");
        assert!(config.trusted_keys.contains(&"key1".to_string()));
        assert!(config.trusted_keys.contains(&"key2".to_string()));
        assert_eq!(config.trusted_keys.len(), 2);
    }

    #[test]
    fn test_signature_config_permissive_dev() {
        let config = SignatureConfig::permissive_dev();
        assert!(!config.require_signatures);
        assert!(config.trusted_keys.is_empty());
        assert!(config.allow_unsigned_in_dev);
    }

    #[test]
    fn test_signature_verifier_permissive_unsigned() {
        let verifier = SkillSignatureVerifier::permissive();

        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        let result = verifier.verify_skill(&manifest).unwrap();
        assert!(result.valid);
        assert!(result.expected_signature.is_none());
    }

    #[test]
    fn test_signature_verifier_strict_requires_signature() {
        let verifier = SkillSignatureVerifier::strict();

        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        let result = verifier.verify_skill(&manifest);
        assert!(matches!(
            result,
            Err(SignatureError::SignatureRequired { .. })
        ));
    }

    #[test]
    fn test_signature_computation_deterministic() {
        let verifier = SkillSignatureVerifier::permissive();

        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        let sig1 = verifier.compute_signature(&manifest).unwrap();
        let sig2 = verifier.compute_signature(&manifest).unwrap();

        assert_eq!(sig1, sig2);
        assert!(!sig1.is_empty());
    }

    #[test]
    fn test_signature_changes_with_content() {
        let verifier = SkillSignatureVerifier::permissive();

        let manifest1 = SkillManifest {
            name: "test1".to_string(),
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        let manifest2 = SkillManifest {
            name: "test2".to_string(), // Different name
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        let sig1 = verifier.compute_signature(&manifest1).unwrap();
        let sig2 = verifier.compute_signature(&manifest2).unwrap();

        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_signature_verification_valid() {
        let verifier = SkillSignatureVerifier::permissive();

        let mut manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        // Sign the manifest
        let signature = verifier.sign_manifest(&manifest).unwrap();
        manifest.signature = Some(signature.clone());

        // Verify
        let result = verifier.verify_skill(&manifest).unwrap();
        assert!(result.valid);
        assert_eq!(result.expected_signature, Some(signature));
    }

    #[test]
    fn test_signature_verification_tampered() {
        let verifier = SkillSignatureVerifier::permissive();

        let mut manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        // Sign the manifest
        let signature = verifier.sign_manifest(&manifest).unwrap();
        manifest.signature = Some(signature);

        // Tamper with the manifest
        manifest.description = "Tampered description".to_string();

        // Verify should fail
        let result = verifier.verify_skill(&manifest).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_signature_verification_result_display() {
        let result = SignatureVerificationResult::success("abc123", "abc123");
        assert!(result.valid);
        assert_eq!(result.computed_signature, "abc123");

        let result = SignatureVerificationResult::failure("abc", "def", "Mismatch");
        assert!(!result.valid);
        assert!(result.details.contains("Mismatch"));

        let result = SignatureVerificationResult::unsigned_allowed();
        assert!(result.valid);
        assert!(result.expected_signature.is_none());
    }

    #[test]
    fn test_signature_error_display() {
        let err = SignatureError::SignatureRequired {
            skill_name: "test".to_string(),
        };
        assert!(err.to_string().contains("Signature required"));

        let err = SignatureError::InvalidFormat {
            message: "bad format".to_string(),
        };
        assert!(err.to_string().contains("Invalid signature format"));

        let err = SignatureError::VerificationFailed {
            skill_name: "test".to_string(),
            computed: "abc".to_string(),
            expected: "def".to_string(),
        };
        assert!(err.to_string().contains("verification failed"));
    }

    #[test]
    fn test_registry_with_signature_verification() {
        let temp_dir = TempDir::new().unwrap();
        let verifier = SkillSignatureVerifier::permissive();

        let mut registry =
            SkillRegistry::with_signature_verification(temp_dir.path().to_path_buf(), verifier);

        assert!(registry.signature_verification_enabled());

        registry.disable_signature_verification();
        assert!(!registry.signature_verification_enabled());
    }

    #[test]
    fn test_registry_verify_skill_signature() {
        let temp_dir = TempDir::new().unwrap();
        let verifier = SkillSignatureVerifier::permissive();

        let registry =
            SkillRegistry::with_signature_verification(temp_dir.path().to_path_buf(), verifier);

        let manifest = SkillManifest {
            name: "test".to_string(),
            version: "1.0.0".to_string(),
            description: "Test skill".to_string(),
            author: None,
            permissions: SkillPermissions::default(),
            input_schema: serde_json::json!({}),
            output_schema: serde_json::json!({}),
            wasm_path: PathBuf::from("./test.wasm"),
            signature: None,
        };

        let result = registry.verify_skill_signature(&manifest).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().valid);
    }

    #[test]
    fn test_is_key_trusted() {
        let config = SignatureConfig::default().with_trusted_key("trusted_key_123");
        let verifier = SkillSignatureVerifier::new(config);

        assert!(verifier.is_key_trusted("trusted_key_123"));
        assert!(!verifier.is_key_trusted("untrusted_key"));
    }
}
