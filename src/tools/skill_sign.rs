//! VAK Skill Signing CLI Tool
//!
//! Command-line utility for signing WASM skills with Ed25519 keys.
//!
//! # Usage
//!
//! ```bash
//! # Generate a new signing keypair
//! vak-skill-sign keygen --output ./keys/
//!
//! # Sign a skill
//! vak-skill-sign sign --skill ./skills/calculator.wasm --key ./keys/signing.key
//!
//! # Verify a signed skill
//! vak-skill-sign verify --skill ./skills/calculator.wasm --pubkey ./keys/signing.pub
//!
//! # Show skill metadata
//! vak-skill-sign info --skill ./skills/calculator.wasm
//! ```
//!
//! # Key Format
//!
//! - Private key: Base64-encoded Ed25519 private key (64 bytes)
//! - Public key: Base64-encoded Ed25519 public key (32 bytes)
//!
//! # Signature Format
//!
//! Signatures are stored in the skill manifest alongside the WASM binary:
//! ```yaml
//! signature:
//!   algorithm: ed25519
//!   signature: <base64-encoded signature>
//!   public_key: <base64-encoded public key>
//!   timestamp: <ISO 8601 timestamp>
//!   signer_id: <optional signer identifier>
//! ```

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey, PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during skill signing operations
#[derive(Debug, Error)]
pub enum SigningError {
    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Key generation error
    #[error("Key generation error: {0}")]
    KeyGenerationError(String),

    /// Key loading error
    #[error("Failed to load key: {0}")]
    KeyLoadError(String),

    /// Signing error
    #[error("Signing error: {0}")]
    SigningFailed(String),

    /// Verification error
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKeyFormat(String),

    /// Manifest error
    #[error("Manifest error: {0}")]
    ManifestError(String),

    /// WASM error
    #[error("WASM error: {0}")]
    WasmError(String),
}

// ============================================================================
// Signature Types
// ============================================================================

/// Signature information stored in skill manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSignature {
    /// Signature algorithm (always "ed25519" for now)
    pub algorithm: String,
    /// Base64-encoded signature
    pub signature: String,
    /// Base64-encoded public key
    pub public_key: String,
    /// Signing timestamp (ISO 8601)
    pub timestamp: String,
    /// Optional signer identifier
    pub signer_id: Option<String>,
    /// SHA-256 hash of the signed content
    pub content_hash: String,
}

/// Complete signed skill manifest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSkillManifest {
    /// Skill name
    pub name: String,
    /// Skill version
    pub version: String,
    /// Skill description
    pub description: Option<String>,
    /// WASM binary path (relative to manifest)
    pub wasm_path: String,
    /// SHA-256 hash of WASM binary
    pub wasm_hash: String,
    /// Signature information
    pub signature: Option<SkillSignature>,
    /// Required permissions
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Entry point function name
    #[serde(default = "default_entry_point")]
    pub entry_point: String,
    /// Additional metadata
    #[serde(default)]
    pub metadata: serde_json::Value,
}

fn default_entry_point() -> String {
    "execute".to_string()
}

// ============================================================================
// Key Management
// ============================================================================

/// Ed25519 keypair for signing
pub struct SigningKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl SigningKeypair {
    /// Generate a new random keypair
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load keypair from private key bytes
    pub fn from_private_key_bytes(bytes: &[u8]) -> Result<Self, SigningError> {
        if bytes.len() != SECRET_KEY_LENGTH {
            return Err(SigningError::InvalidKeyFormat(format!(
                "Private key must be {} bytes, got {}",
                SECRET_KEY_LENGTH,
                bytes.len()
            )));
        }

        let signing_key = SigningKey::from_bytes(bytes.try_into().map_err(|_| {
            SigningError::InvalidKeyFormat("Invalid private key bytes".to_string())
        })?);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Load keypair from Base64-encoded private key
    pub fn from_base64_private_key(encoded: &str) -> Result<Self, SigningError> {
        let bytes = BASE64
            .decode(encoded.trim())
            .map_err(|e| SigningError::InvalidKeyFormat(format!("Invalid Base64: {}", e)))?;
        Self::from_private_key_bytes(&bytes)
    }

    /// Load keypair from file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, SigningError> {
        let content = fs::read_to_string(path)?;
        Self::from_base64_private_key(&content)
    }

    /// Export private key as Base64
    pub fn private_key_base64(&self) -> String {
        BASE64.encode(self.signing_key.to_bytes())
    }

    /// Export public key as Base64
    pub fn public_key_base64(&self) -> String {
        BASE64.encode(self.verifying_key.to_bytes())
    }

    /// Save keypair to files
    pub fn save_to_files(
        &self,
        private_key_path: impl AsRef<Path>,
        public_key_path: impl AsRef<Path>,
    ) -> Result<(), SigningError> {
        // Ensure parent directories exist
        if let Some(parent) = private_key_path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = public_key_path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }

        // Write private key
        let mut priv_file = File::create(private_key_path)?;
        writeln!(priv_file, "{}", self.private_key_base64())?;

        // Write public key
        let mut pub_file = File::create(public_key_path)?;
        writeln!(pub_file, "{}", self.public_key_base64())?;

        Ok(())
    }

    /// Sign content
    pub fn sign(&self, content: &[u8]) -> Signature {
        self.signing_key.sign(content)
    }

    /// Verify signature
    pub fn verify(&self, content: &[u8], signature: &Signature) -> bool {
        self.verifying_key.verify(content, signature).is_ok()
    }
}

/// Load public key from Base64 string
pub fn load_public_key(encoded: &str) -> Result<VerifyingKey, SigningError> {
    let bytes = BASE64
        .decode(encoded.trim())
        .map_err(|e| SigningError::InvalidKeyFormat(format!("Invalid Base64: {}", e)))?;

    if bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(SigningError::InvalidKeyFormat(format!(
            "Public key must be {} bytes, got {}",
            PUBLIC_KEY_LENGTH,
            bytes.len()
        )));
    }

    VerifyingKey::from_bytes(bytes.as_slice().try_into().map_err(|_| {
        SigningError::InvalidKeyFormat("Invalid public key bytes".to_string())
    })?)
    .map_err(|e| SigningError::InvalidKeyFormat(format!("Invalid public key: {}", e)))
}

/// Load public key from file
pub fn load_public_key_from_file(path: impl AsRef<Path>) -> Result<VerifyingKey, SigningError> {
    let content = fs::read_to_string(path)?;
    load_public_key(&content)
}

// ============================================================================
// Skill Signing
// ============================================================================

/// Sign a WASM skill
pub struct SkillSigner {
    keypair: SigningKeypair,
    signer_id: Option<String>,
}

impl SkillSigner {
    /// Create a new skill signer
    pub fn new(keypair: SigningKeypair) -> Self {
        Self {
            keypair,
            signer_id: None,
        }
    }

    /// Set signer identifier
    pub fn with_signer_id(mut self, signer_id: impl Into<String>) -> Self {
        self.signer_id = Some(signer_id.into());
        self
    }

    /// Compute SHA-256 hash of content
    fn compute_hash(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hex::encode(hasher.finalize())
    }

    /// Create signable content from manifest and WASM
    fn create_signable_content(manifest: &SignedSkillManifest, wasm_hash: &str) -> Vec<u8> {
        // Create canonical content to sign:
        // name + version + wasm_hash
        format!("{}:{}:{}", manifest.name, manifest.version, wasm_hash).into_bytes()
    }

    /// Sign a skill's WASM binary and manifest
    pub fn sign_skill(
        &self,
        wasm_path: impl AsRef<Path>,
        manifest_path: impl AsRef<Path>,
    ) -> Result<SignedSkillManifest, SigningError> {
        // Read WASM binary
        let wasm_bytes = fs::read(&wasm_path)?;
        let wasm_hash = Self::compute_hash(&wasm_bytes);

        // Read existing manifest
        let manifest_content = fs::read_to_string(&manifest_path)?;
        let mut manifest: SignedSkillManifest = serde_yaml::from_str(&manifest_content)
            .map_err(|e| SigningError::ManifestError(format!("Failed to parse manifest: {}", e)))?;

        // Update WASM hash
        manifest.wasm_hash = wasm_hash.clone();

        // Create content to sign
        let signable_content = Self::create_signable_content(&manifest, &wasm_hash);

        // Sign
        let signature = self.keypair.sign(&signable_content);

        // Create signature info
        let sig_info = SkillSignature {
            algorithm: "ed25519".to_string(),
            signature: BASE64.encode(signature.to_bytes()),
            public_key: self.keypair.public_key_base64(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            signer_id: self.signer_id.clone(),
            content_hash: Self::compute_hash(&signable_content),
        };

        manifest.signature = Some(sig_info);

        Ok(manifest)
    }

    /// Sign and save manifest
    pub fn sign_and_save(
        &self,
        wasm_path: impl AsRef<Path>,
        manifest_path: impl AsRef<Path>,
    ) -> Result<PathBuf, SigningError> {
        let signed_manifest = self.sign_skill(&wasm_path, &manifest_path)?;

        // Write signed manifest
        let yaml = serde_yaml::to_string(&signed_manifest)
            .map_err(|e| SigningError::ManifestError(format!("Failed to serialize manifest: {}", e)))?;

        let signed_path = manifest_path
            .as_ref()
            .with_extension("signed.yaml");
        
        fs::write(&signed_path, yaml)?;

        Ok(signed_path)
    }
}

// ============================================================================
// Skill Verification
// ============================================================================

/// Verify a signed skill
pub struct SkillVerifier;

impl SkillVerifier {
    /// Verify a signed skill
    pub fn verify(
        manifest_path: impl AsRef<Path>,
        wasm_path: impl AsRef<Path>,
        public_key: Option<&VerifyingKey>,
    ) -> Result<VerificationResult, SigningError> {
        // Read manifest
        let manifest_content = fs::read_to_string(&manifest_path)?;
        let manifest: SignedSkillManifest = serde_yaml::from_str(&manifest_content)
            .map_err(|e| SigningError::ManifestError(format!("Failed to parse manifest: {}", e)))?;

        // Check for signature
        let sig_info = match &manifest.signature {
            Some(sig) => sig,
            None => {
                return Ok(VerificationResult {
                    valid: false,
                    reason: "Skill is not signed".to_string(),
                    signer_id: None,
                    signed_at: None,
                });
            }
        };

        // Verify algorithm
        if sig_info.algorithm != "ed25519" {
            return Ok(VerificationResult {
                valid: false,
                reason: format!("Unsupported signature algorithm: {}", sig_info.algorithm),
                signer_id: sig_info.signer_id.clone(),
                signed_at: Some(sig_info.timestamp.clone()),
            });
        }

        // Read WASM and compute hash
        let wasm_bytes = fs::read(&wasm_path)?;
        let wasm_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&wasm_bytes);
            hex::encode(hasher.finalize())
        };

        // Verify WASM hash matches
        if wasm_hash != manifest.wasm_hash {
            return Ok(VerificationResult {
                valid: false,
                reason: "WASM hash mismatch - binary has been modified".to_string(),
                signer_id: sig_info.signer_id.clone(),
                signed_at: Some(sig_info.timestamp.clone()),
            });
        }

        // Load public key (from manifest or provided)
        let verifying_key = match public_key {
            Some(key) => key.clone(),
            None => load_public_key(&sig_info.public_key)?,
        };

        // Decode signature
        let signature_bytes = BASE64
            .decode(&sig_info.signature)
            .map_err(|_e| SigningError::InvalidSignature)?;

        let signature = Signature::from_bytes(signature_bytes.as_slice().try_into().map_err(
            |_| SigningError::InvalidSignature,
        )?);

        // Create signable content
        let signable_content = format!(
            "{}:{}:{}",
            manifest.name, manifest.version, wasm_hash
        )
        .into_bytes();

        // Verify signature
        match verifying_key.verify(&signable_content, &signature) {
            Ok(_) => Ok(VerificationResult {
                valid: true,
                reason: "Signature is valid".to_string(),
                signer_id: sig_info.signer_id.clone(),
                signed_at: Some(sig_info.timestamp.clone()),
            }),
            Err(_) => Ok(VerificationResult {
                valid: false,
                reason: "Signature verification failed".to_string(),
                signer_id: sig_info.signer_id.clone(),
                signed_at: Some(sig_info.timestamp.clone()),
            }),
        }
    }
}

/// Result of skill verification
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether the signature is valid
    pub valid: bool,
    /// Reason for the result
    pub reason: String,
    /// Signer identifier (if present)
    pub signer_id: Option<String>,
    /// When the skill was signed (if present)
    pub signed_at: Option<String>,
}

// ============================================================================
// CLI Commands
// ============================================================================

/// Generate a new signing keypair
pub fn cmd_keygen(output_dir: impl AsRef<Path>) -> Result<(), SigningError> {
    let output_dir = output_dir.as_ref();
    fs::create_dir_all(output_dir)?;

    let keypair = SigningKeypair::generate();

    let private_key_path = output_dir.join("signing.key");
    let public_key_path = output_dir.join("signing.pub");

    keypair.save_to_files(&private_key_path, &public_key_path)?;

    println!("Generated new signing keypair:");
    println!("  Private key: {}", private_key_path.display());
    println!("  Public key:  {}", public_key_path.display());
    println!();
    println!("Public key (Base64):");
    println!("  {}", keypair.public_key_base64());
    println!();
    println!("⚠️  Keep the private key secure and never share it!");

    Ok(())
}

/// Sign a skill
pub fn cmd_sign(
    skill_dir: impl AsRef<Path>,
    key_path: impl AsRef<Path>,
    signer_id: Option<&str>,
) -> Result<PathBuf, SigningError> {
    let skill_dir = skill_dir.as_ref();

    // Find WASM and manifest files
    let wasm_path = find_wasm_file(skill_dir)?;
    let manifest_path = skill_dir.join("skill.yaml");

    if !manifest_path.exists() {
        return Err(SigningError::ManifestError(format!(
            "Manifest not found at {}",
            manifest_path.display()
        )));
    }

    // Load signing key
    let keypair = SigningKeypair::from_file(&key_path)?;

    // Create signer
    let mut signer = SkillSigner::new(keypair);
    if let Some(id) = signer_id {
        signer = signer.with_signer_id(id);
    }

    // Sign and save
    let output_path = signer.sign_and_save(&wasm_path, &manifest_path)?;

    println!("✅ Skill signed successfully!");
    println!("   Signed manifest: {}", output_path.display());

    Ok(output_path)
}

/// Verify a signed skill
pub fn cmd_verify(
    skill_dir: impl AsRef<Path>,
    public_key_path: Option<impl AsRef<Path>>,
) -> Result<VerificationResult, SigningError> {
    let skill_dir = skill_dir.as_ref();

    // Find files
    let wasm_path = find_wasm_file(skill_dir)?;
    let manifest_path = if skill_dir.join("skill.signed.yaml").exists() {
        skill_dir.join("skill.signed.yaml")
    } else {
        skill_dir.join("skill.yaml")
    };

    // Load public key if provided
    let public_key = match public_key_path {
        Some(path) => Some(load_public_key_from_file(path)?),
        None => None,
    };

    // Verify
    let result = SkillVerifier::verify(&manifest_path, &wasm_path, public_key.as_ref())?;

    if result.valid {
        println!("✅ Signature is valid");
    } else {
        println!("❌ Signature verification failed: {}", result.reason);
    }

    if let Some(ref signer) = result.signer_id {
        println!("   Signer: {}", signer);
    }
    if let Some(ref timestamp) = result.signed_at {
        println!("   Signed at: {}", timestamp);
    }

    Ok(result)
}

/// Show skill information
pub fn cmd_info(skill_dir: impl AsRef<Path>) -> Result<(), SigningError> {
    let skill_dir = skill_dir.as_ref();

    // Find manifest
    let manifest_path = if skill_dir.join("skill.signed.yaml").exists() {
        skill_dir.join("skill.signed.yaml")
    } else {
        skill_dir.join("skill.yaml")
    };

    // Read manifest
    let manifest_content = fs::read_to_string(&manifest_path)?;
    let manifest: SignedSkillManifest = serde_yaml::from_str(&manifest_content)
        .map_err(|e| SigningError::ManifestError(format!("Failed to parse manifest: {}", e)))?;

    // Find WASM
    let wasm_path = find_wasm_file(skill_dir)?;
    let wasm_size = fs::metadata(&wasm_path)?.len();

    println!("Skill Information");
    println!("=================");
    println!("Name:        {}", manifest.name);
    println!("Version:     {}", manifest.version);
    if let Some(ref desc) = manifest.description {
        println!("Description: {}", desc);
    }
    println!("WASM Path:   {}", wasm_path.display());
    println!("WASM Size:   {} bytes", wasm_size);
    println!("WASM Hash:   {}", manifest.wasm_hash);
    println!("Entry Point: {}", manifest.entry_point);

    if !manifest.permissions.is_empty() {
        println!("Permissions:");
        for perm in &manifest.permissions {
            println!("  - {}", perm);
        }
    }

    if let Some(ref sig) = manifest.signature {
        println!();
        println!("Signature");
        println!("---------");
        println!("Algorithm:   {}", sig.algorithm);
        println!("Signed at:   {}", sig.timestamp);
        if let Some(ref signer) = sig.signer_id {
            println!("Signer ID:   {}", signer);
        }
        println!("Public Key:  {}...", &sig.public_key[..20]);
    } else {
        println!();
        println!("⚠️  This skill is NOT signed");
    }

    Ok(())
}

/// Find WASM file in skill directory
fn find_wasm_file(skill_dir: &Path) -> Result<PathBuf, SigningError> {
    // Check target/wasm32-unknown-unknown/release first
    let release_path = skill_dir
        .join("target")
        .join("wasm32-unknown-unknown")
        .join("release");
    
    if release_path.exists() {
        for entry in fs::read_dir(&release_path)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "wasm").unwrap_or(false) {
                return Ok(path);
            }
        }
    }

    // Check skill.wasm in root
    let root_wasm = skill_dir.join("skill.wasm");
    if root_wasm.exists() {
        return Ok(root_wasm);
    }

    // Check any .wasm file
    for entry in fs::read_dir(skill_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().map(|e| e == "wasm").unwrap_or(false) {
            return Ok(path);
        }
    }

    Err(SigningError::WasmError(format!(
        "No WASM file found in {}",
        skill_dir.display()
    )))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_keypair_generation() {
        let keypair = SigningKeypair::generate();
        
        // Keys should be proper length when Base64 decoded
        let private_decoded = BASE64.decode(keypair.private_key_base64()).unwrap();
        let public_decoded = BASE64.decode(keypair.public_key_base64()).unwrap();
        
        assert_eq!(private_decoded.len(), SECRET_KEY_LENGTH);
        assert_eq!(public_decoded.len(), PUBLIC_KEY_LENGTH);
    }

    #[test]
    fn test_keypair_save_load() {
        let dir = tempdir().unwrap();
        let priv_path = dir.path().join("test.key");
        let pub_path = dir.path().join("test.pub");

        let original = SigningKeypair::generate();
        original.save_to_files(&priv_path, &pub_path).unwrap();

        let loaded = SigningKeypair::from_file(&priv_path).unwrap();

        assert_eq!(original.public_key_base64(), loaded.public_key_base64());
    }

    #[test]
    fn test_sign_verify() {
        let keypair = SigningKeypair::generate();
        let content = b"test content to sign";

        let signature = keypair.sign(content);
        assert!(keypair.verify(content, &signature));

        // Tampered content should fail
        let tampered = b"tampered content";
        assert!(!keypair.verify(tampered, &signature));
    }

    #[test]
    fn test_public_key_loading() {
        let keypair = SigningKeypair::generate();
        let pub_base64 = keypair.public_key_base64();

        let loaded_key = load_public_key(&pub_base64).unwrap();
        
        // Verify loaded key works
        let content = b"test";
        let signature = keypair.sign(content);
        assert!(loaded_key.verify(content, &signature).is_ok());
    }

    #[test]
    fn test_compute_hash() {
        let content = b"test content";
        let hash = SkillSigner::compute_hash(content);
        
        // Should be hex-encoded SHA-256 (64 chars)
        assert_eq!(hash.len(), 64);
        
        // Same content should produce same hash
        let hash2 = SkillSigner::compute_hash(content);
        assert_eq!(hash, hash2);
        
        // Different content should produce different hash
        let hash3 = SkillSigner::compute_hash(b"different");
        assert_ne!(hash, hash3);
    }
}
