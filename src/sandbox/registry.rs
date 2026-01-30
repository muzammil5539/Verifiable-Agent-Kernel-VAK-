//! Skill Registry for managing WASM skill manifests and permissions
//!
//! This module provides a registry for loading, managing, and validating
//! WASM skills and their associated permissions. Skills are defined via
//! YAML manifest files that specify metadata, permissions, and schemas.
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
use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
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
        Self {
            skills_directory,
            skills: HashMap::new(),
            name_index: HashMap::new(),
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
            let pattern = format!(
                "{}/**/*.{}",
                self.skills_directory.display(),
                extension
            );

            if let Ok(entries) = glob::glob(&pattern) {
                for entry in entries.flatten() {
                    // Skip non-manifest files (e.g., test files, config files)
                    if entry.file_name().map_or(false, |n| {
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
        self.name_index
            .get(name)
            .and_then(|id| self.skills.get(id))
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

        // Check filesystem permissions using glob pattern matching
        for requested_path in &requested.filesystem {
            let mut path_allowed = false;
            for allowed_pattern in &allowed.filesystem {
                if let Ok(pattern) = glob::Pattern::new(allowed_pattern) {
                    if pattern.matches(requested_path) {
                        path_allowed = true;
                        break;
                    }
                }
                // Also allow exact matches
                if allowed_pattern == requested_path {
                    path_allowed = true;
                    break;
                }
            }
            if !path_allowed && !allowed.filesystem.is_empty() {
                return Err(PermissionError::FilesystemPathNotAllowed {
                    skill_id: *skill_id,
                    path: requested_path.clone(),
                });
            }
            if !path_allowed && allowed.filesystem.is_empty() && !requested.filesystem.is_empty() {
                return Err(PermissionError::FilesystemPathNotAllowed {
                    skill_id: *skill_id,
                    path: requested_path.clone(),
                });
            }
        }

        // Check env var permissions using glob pattern matching
        for requested_var in &requested.env_vars {
            let mut var_allowed = false;
            for allowed_pattern in &allowed.env_vars {
                if let Ok(pattern) = glob::Pattern::new(allowed_pattern) {
                    if pattern.matches(requested_var) {
                        var_allowed = true;
                        break;
                    }
                }
                // Also allow exact matches
                if allowed_pattern == requested_var {
                    var_allowed = true;
                    break;
                }
            }
            if !var_allowed && !allowed.env_vars.is_empty() {
                return Err(PermissionError::EnvVarNotAllowed {
                    skill_id: *skill_id,
                    var: requested_var.clone(),
                });
            }
            if !var_allowed && allowed.env_vars.is_empty() && !requested.env_vars.is_empty() {
                return Err(PermissionError::EnvVarNotAllowed {
                    skill_id: *skill_id,
                    var: requested_var.clone(),
                });
            }
        }

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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
        let id = registry.load_skill(&path).unwrap();

        assert_eq!(registry.skill_count(), 1);

        let skill = registry.get_skill(&id).unwrap();
        assert_eq!(skill.name, "calculator");
    }

    #[test]
    fn test_registry_get_skill_by_name() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
        registry.load_skill(&path).unwrap();

        let skill = registry.get_skill_by_name("calculator").unwrap();
        assert_eq!(skill.version, "1.0.0");

        assert!(registry.get_skill_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_registry_duplicate_skill() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
        registry.load_all_skills().unwrap();

        assert_eq!(registry.skill_count(), 2);
        registry.clear();
        assert_eq!(registry.skill_count(), 0);
    }

    #[test]
    fn test_validate_permissions_network_denied() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_manifest(temp_dir.path(), "calculator", sample_manifest_yaml());

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
        let id = registry.load_skill(&path).unwrap();

        // Request permissions within the allowed limits
        let requested = SkillPermissions {
            network: true,
            filesystem: vec!["/tmp/file.txt".to_string(), "/data/subdir/file.csv".to_string()],
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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

        let mut registry = SkillRegistry::new(temp_dir.path().to_path_buf());
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
}
