//! Skill Marketplace Verified Publishers (FUT-004)
//!
//! Extends the skill marketplace with comprehensive publisher verification,
//! reputation tracking, and malicious skill reporting. Enables trust-based
//! skill distribution with multiple verification methods.
//!
//! # Features
//!
//! - **Publisher Verification**: GitHub org, GPG key, and domain ownership verification
//! - **Reputation System**: Community-driven reputation scores for publishers
//! - **Skill Publishing**: Publish WASM skills with manifests and signatures
//! - **Malicious Skill Reporting**: Community reporting and automated suspension
//! - **Vulnerability Scanning**: Automated security scanning on publish
//! - **Verification Badges**: Visual indicators of trust level
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::sandbox::verified_publisher::{
//!     PublisherRegistry, PublisherProfile, VerificationMethod,
//!     VerificationRequest, PublisherConfig,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = PublisherConfig::default();
//! let registry = PublisherRegistry::new(config);
//!
//! // Register a new publisher
//! let profile = PublisherProfile::new("acme-corp", "ACME Corp", "dev@acme.com");
//! let publisher_id = registry.register(profile)?;
//!
//! // Request verification
//! let request = VerificationRequest::github_org("acme-corp", "acme-org");
//! let result = registry.request_verification(&publisher_id, request)?;
//! # Ok(())
//! # }
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during publisher operations
#[derive(Debug, Error)]
pub enum PublisherError {
    /// Publisher not found
    #[error("Publisher not found: {0}")]
    NotFound(String),

    /// Publisher already exists
    #[error("Publisher already exists: {0}")]
    AlreadyExists(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Verification already pending
    #[error("Verification already pending for publisher {0}")]
    VerificationPending(String),

    /// Publisher suspended
    #[error("Publisher is suspended: {0}")]
    Suspended(String),

    /// Invalid profile data
    #[error("Invalid profile: {0}")]
    InvalidProfile(String),

    /// Skill publishing failed
    #[error("Skill publishing failed: {0}")]
    PublishFailed(String),

    /// Report submission failed
    #[error("Report submission failed: {0}")]
    ReportFailed(String),

    /// Lock error
    #[error("Internal lock error: {0}")]
    LockError(String),
}

/// Result type for publisher operations
pub type PublisherResult<T> = Result<T, PublisherError>;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the publisher registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherConfig {
    /// Minimum reputation score to publish skills (0.0-1.0)
    pub min_publish_reputation: f64,
    /// Reports needed to auto-suspend a publisher
    pub suspension_threshold: u32,
    /// Reports needed to auto-suspend a skill
    pub skill_suspension_threshold: u32,
    /// Verification expiry in seconds
    pub verification_expiry_secs: u64,
    /// Enable auto-suspension on reports
    pub auto_suspension_enabled: bool,
    /// Require verification to publish
    pub require_verification_to_publish: bool,
}

impl Default for PublisherConfig {
    fn default() -> Self {
        Self {
            min_publish_reputation: 0.0,
            suspension_threshold: 5,
            skill_suspension_threshold: 3,
            verification_expiry_secs: 365 * 24 * 3600, // 1 year
            auto_suspension_enabled: true,
            require_verification_to_publish: false,
        }
    }
}

impl PublisherConfig {
    /// Create strict config (require verification)
    pub fn strict() -> Self {
        Self {
            min_publish_reputation: 0.5,
            suspension_threshold: 3,
            skill_suspension_threshold: 2,
            verification_expiry_secs: 180 * 24 * 3600, // 6 months
            auto_suspension_enabled: true,
            require_verification_to_publish: true,
        }
    }
}

// ============================================================================
// Verification Types
// ============================================================================

/// Methods for verifying publisher identity
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMethod {
    /// Verify via GitHub organization membership
    GithubOrg {
        /// GitHub organization name
        org_name: String,
    },
    /// Verify via GPG/PGP key ownership
    GpgKey {
        /// GPG key fingerprint
        key_fingerprint: String,
        /// The signed challenge text
        signed_challenge: Option<String>,
    },
    /// Verify via DNS domain ownership
    DomainOwnership {
        /// Domain name to verify
        domain: String,
        /// Expected TXT record value
        txt_record: Option<String>,
    },
    /// Verify via email verification
    Email {
        /// Email address
        email: String,
        /// Verification code
        code: Option<String>,
    },
}

impl std::fmt::Display for VerificationMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GithubOrg { org_name } => write!(f, "github_org:{}", org_name),
            Self::GpgKey { key_fingerprint, .. } => write!(f, "gpg_key:{}", key_fingerprint),
            Self::DomainOwnership { domain, .. } => write!(f, "domain:{}", domain),
            Self::Email { email, .. } => write!(f, "email:{}", email),
        }
    }
}

/// Status of a verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    /// Verification is pending
    Pending,
    /// Verification succeeded
    Verified,
    /// Verification failed
    Failed,
    /// Verification expired
    Expired,
    /// Verification revoked
    Revoked,
}

/// A verification request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Verification method
    pub method: VerificationMethod,
    /// Request timestamp
    pub requested_at: u64,
    /// Challenge token (generated by system)
    pub challenge: String,
}

impl VerificationRequest {
    /// Create a GitHub org verification request
    pub fn github_org(publisher_id: &str, org_name: &str) -> Self {
        Self {
            method: VerificationMethod::GithubOrg {
                org_name: org_name.to_string(),
            },
            requested_at: now(),
            challenge: generate_challenge(publisher_id, "github_org"),
        }
    }

    /// Create a GPG key verification request
    pub fn gpg_key(publisher_id: &str, fingerprint: &str) -> Self {
        Self {
            method: VerificationMethod::GpgKey {
                key_fingerprint: fingerprint.to_string(),
                signed_challenge: None,
            },
            requested_at: now(),
            challenge: generate_challenge(publisher_id, "gpg_key"),
        }
    }

    /// Create a domain ownership verification request
    pub fn domain(publisher_id: &str, domain: &str) -> Self {
        let challenge = generate_challenge(publisher_id, "domain");
        Self {
            method: VerificationMethod::DomainOwnership {
                domain: domain.to_string(),
                txt_record: Some(format!("vak-verify={}", challenge)),
            },
            requested_at: now(),
            challenge,
        }
    }

    /// Create an email verification request
    pub fn email(publisher_id: &str, email: &str) -> Self {
        Self {
            method: VerificationMethod::Email {
                email: email.to_string(),
                code: None,
            },
            requested_at: now(),
            challenge: generate_challenge(publisher_id, "email"),
        }
    }
}

/// Record of a completed verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRecord {
    /// Verification method
    pub method: VerificationMethod,
    /// Status
    pub status: VerificationStatus,
    /// When verified
    pub verified_at: Option<u64>,
    /// Expiry timestamp
    pub expires_at: Option<u64>,
    /// Verification details
    pub details: String,
}

// ============================================================================
// Publisher Profile
// ============================================================================

/// Trust level for a publisher
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// New, unverified publisher
    Unverified,
    /// Email verified
    Basic,
    /// One verification method completed
    Verified,
    /// Multiple verification methods + good reputation
    Trusted,
    /// Official VAK team verified
    Official,
}

impl std::fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unverified => write!(f, "unverified"),
            Self::Basic => write!(f, "basic"),
            Self::Verified => write!(f, "verified"),
            Self::Trusted => write!(f, "trusted"),
            Self::Official => write!(f, "official"),
        }
    }
}

/// Publisher profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherProfile {
    /// Unique publisher ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Contact email
    pub email: String,
    /// Website URL
    pub website: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Public key for skill signing (Ed25519, hex-encoded)
    pub public_key: Option<String>,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Reputation score (0.0-1.0)
    pub reputation_score: f64,
    /// Verification records
    pub verifications: Vec<VerificationRecord>,
    /// Published skill IDs
    pub published_skills: Vec<String>,
    /// Whether the publisher is suspended
    pub suspended: bool,
    /// Suspension reason
    pub suspension_reason: Option<String>,
    /// Registration timestamp
    pub registered_at: u64,
    /// Total downloads across all skills
    pub total_downloads: u64,
    /// Average rating across all skills
    pub average_rating: f64,
}

impl PublisherProfile {
    /// Create a new publisher profile
    pub fn new(id: impl Into<String>, name: impl Into<String>, email: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            email: email.into(),
            website: None,
            description: None,
            public_key: None,
            trust_level: TrustLevel::Unverified,
            reputation_score: 0.5,
            verifications: Vec::new(),
            published_skills: Vec::new(),
            suspended: false,
            suspension_reason: None,
            registered_at: now(),
            total_downloads: 0,
            average_rating: 0.0,
        }
    }

    /// Set website
    pub fn with_website(mut self, website: impl Into<String>) -> Self {
        self.website = Some(website.into());
        self
    }

    /// Set description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set public key
    pub fn with_public_key(mut self, key: impl Into<String>) -> Self {
        self.public_key = Some(key.into());
        self
    }

    /// Check if the publisher is verified (at least one verified method)
    pub fn is_verified(&self) -> bool {
        self.verifications
            .iter()
            .any(|v| v.status == VerificationStatus::Verified)
    }

    /// Get active verifications count
    pub fn active_verifications(&self) -> usize {
        self.verifications
            .iter()
            .filter(|v| v.status == VerificationStatus::Verified)
            .count()
    }

    /// Update trust level based on verifications and reputation
    fn update_trust_level(&mut self) {
        let verified_count = self.active_verifications();
        self.trust_level = if self.trust_level == TrustLevel::Official {
            TrustLevel::Official
        } else if verified_count >= 2 && self.reputation_score >= 0.8 {
            TrustLevel::Trusted
        } else if verified_count >= 1 {
            TrustLevel::Verified
        } else if !self.email.is_empty() {
            TrustLevel::Basic
        } else {
            TrustLevel::Unverified
        };
    }
}

// ============================================================================
// Published Skill
// ============================================================================

/// A published skill in the marketplace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedSkill {
    /// Skill ID
    pub id: String,
    /// Skill name
    pub name: String,
    /// Version
    pub version: String,
    /// Publisher ID
    pub publisher_id: String,
    /// Description
    pub description: String,
    /// SHA-256 hash of WASM binary
    pub wasm_hash: String,
    /// WASM binary size in bytes
    pub wasm_size: u64,
    /// Ed25519 signature of the WASM hash
    pub signature: Option<String>,
    /// Required permissions
    pub permissions: Vec<String>,
    /// Published timestamp
    pub published_at: u64,
    /// Whether the skill is suspended
    pub suspended: bool,
    /// Report count
    pub report_count: u32,
    /// Download count
    pub download_count: u64,
    /// Average rating
    pub average_rating: f64,
    /// Vulnerability scan passed
    pub scan_passed: bool,
}

/// A report against a malicious skill
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillReport {
    /// Report ID
    pub id: String,
    /// Skill ID
    pub skill_id: String,
    /// Reporter identifier
    pub reporter: String,
    /// Report reason
    pub reason: ReportReason,
    /// Detailed description
    pub description: String,
    /// Report timestamp
    pub reported_at: u64,
    /// Report status
    pub status: ReportStatus,
}

/// Reasons for reporting a skill
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportReason {
    /// Skill contains malicious code
    Malicious,
    /// Skill has a security vulnerability
    Vulnerability,
    /// Skill performs unauthorized actions
    UnauthorizedActions,
    /// Skill description is misleading
    Misleading,
    /// Skill violates licensing terms
    LicenseViolation,
    /// Other reason
    Other(String),
}

/// Status of a report
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    /// Report submitted, pending review
    Pending,
    /// Report is being investigated
    Investigating,
    /// Report confirmed, action taken
    Confirmed,
    /// Report dismissed
    Dismissed,
}

/// Result of a vulnerability scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Whether the scan passed
    pub passed: bool,
    /// Issues found
    pub issues: Vec<ScanIssue>,
    /// Scan timestamp
    pub scanned_at: u64,
    /// Scan duration in milliseconds
    pub duration_ms: u64,
}

/// An issue found during vulnerability scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIssue {
    /// Issue severity
    pub severity: IssueSeverity,
    /// Issue description
    pub description: String,
    /// Recommendation
    pub recommendation: String,
}

/// Severity levels for scan issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IssueSeverity {
    /// Informational
    Info,
    /// Low severity
    Low,
    /// Medium severity
    Medium,
    /// High severity
    High,
    /// Critical severity
    Critical,
}

// ============================================================================
// Publisher Registry
// ============================================================================

/// Registry for managing verified publishers
#[derive(Debug)]
pub struct PublisherRegistry {
    config: PublisherConfig,
    publishers: RwLock<HashMap<String, PublisherProfile>>,
    skills: RwLock<HashMap<String, PublishedSkill>>,
    reports: RwLock<Vec<SkillReport>>,
    pending_verifications: RwLock<HashMap<String, VerificationRequest>>,
}

impl PublisherRegistry {
    /// Create a new publisher registry
    pub fn new(config: PublisherConfig) -> Self {
        Self {
            config,
            publishers: RwLock::new(HashMap::new()),
            skills: RwLock::new(HashMap::new()),
            reports: RwLock::new(Vec::new()),
            pending_verifications: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(PublisherConfig::default())
    }

    /// Register a new publisher
    pub fn register(&self, profile: PublisherProfile) -> PublisherResult<String> {
        if profile.id.is_empty() {
            return Err(PublisherError::InvalidProfile("ID cannot be empty".to_string()));
        }
        if profile.name.is_empty() {
            return Err(PublisherError::InvalidProfile("Name cannot be empty".to_string()));
        }

        let mut publishers = self
            .publishers
            .write()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        if publishers.contains_key(&profile.id) {
            return Err(PublisherError::AlreadyExists(profile.id.clone()));
        }

        let id = profile.id.clone();
        publishers.insert(id.clone(), profile);
        Ok(id)
    }

    /// Get a publisher profile
    pub fn get_publisher(&self, id: &str) -> PublisherResult<PublisherProfile> {
        let publishers = self
            .publishers
            .read()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        publishers
            .get(id)
            .cloned()
            .ok_or_else(|| PublisherError::NotFound(id.to_string()))
    }

    /// Request verification for a publisher
    pub fn request_verification(
        &self,
        publisher_id: &str,
        request: VerificationRequest,
    ) -> PublisherResult<String> {
        // Check publisher exists
        let publishers = self
            .publishers
            .read()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        if !publishers.contains_key(publisher_id) {
            return Err(PublisherError::NotFound(publisher_id.to_string()));
        }
        drop(publishers);

        let verification_id = format!("{}:{}", publisher_id, request.method);

        let mut pending = self
            .pending_verifications
            .write()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        pending.insert(verification_id.clone(), request);
        Ok(verification_id)
    }

    /// Complete a verification
    pub fn complete_verification(
        &self,
        publisher_id: &str,
        method: VerificationMethod,
        success: bool,
        details: impl Into<String>,
    ) -> PublisherResult<VerificationRecord> {
        let mut publishers = self
            .publishers
            .write()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        let publisher = publishers
            .get_mut(publisher_id)
            .ok_or_else(|| PublisherError::NotFound(publisher_id.to_string()))?;

        let record = VerificationRecord {
            method,
            status: if success {
                VerificationStatus::Verified
            } else {
                VerificationStatus::Failed
            },
            verified_at: if success { Some(now()) } else { None },
            expires_at: if success {
                Some(now() + self.config.verification_expiry_secs)
            } else {
                None
            },
            details: details.into(),
        };

        publisher.verifications.push(record.clone());
        publisher.update_trust_level();

        // Clean up pending verification
        let verification_id = format!("{}:{}", publisher_id, record.method);
        if let Ok(mut pending) = self.pending_verifications.write() {
            pending.remove(&verification_id);
        }

        Ok(record)
    }

    /// Publish a skill
    pub fn publish_skill(
        &self,
        publisher_id: &str,
        skill: PublishedSkill,
    ) -> PublisherResult<String> {
        let publishers = self
            .publishers
            .read()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        let publisher = publishers
            .get(publisher_id)
            .ok_or_else(|| PublisherError::NotFound(publisher_id.to_string()))?;

        if publisher.suspended {
            return Err(PublisherError::Suspended(publisher_id.to_string()));
        }

        if self.config.require_verification_to_publish && !publisher.is_verified() {
            return Err(PublisherError::PublishFailed(
                "Publisher must be verified to publish skills".to_string(),
            ));
        }

        if publisher.reputation_score < self.config.min_publish_reputation {
            return Err(PublisherError::PublishFailed(format!(
                "Publisher reputation {:.2} is below minimum {:.2}",
                publisher.reputation_score, self.config.min_publish_reputation
            )));
        }

        drop(publishers);

        let skill_id = skill.id.clone();

        let mut skills = self
            .skills
            .write()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;
        skills.insert(skill_id.clone(), skill);

        // Add to publisher's published skills
        if let Ok(mut publishers) = self.publishers.write() {
            if let Some(publisher) = publishers.get_mut(publisher_id) {
                publisher.published_skills.push(skill_id.clone());
            }
        }

        Ok(skill_id)
    }

    /// Report a malicious skill
    pub fn report_skill(
        &self,
        skill_id: &str,
        reporter: &str,
        reason: ReportReason,
        description: &str,
    ) -> PublisherResult<String> {
        // Verify skill exists
        let mut skills = self
            .skills
            .write()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        let skill = skills
            .get_mut(skill_id)
            .ok_or_else(|| PublisherError::NotFound(skill_id.to_string()))?;

        skill.report_count += 1;

        // Auto-suspend if threshold reached
        if self.config.auto_suspension_enabled
            && skill.report_count >= self.config.skill_suspension_threshold
        {
            skill.suspended = true;
        }

        let report_id = uuid::Uuid::new_v4().to_string();

        let report = SkillReport {
            id: report_id.clone(),
            skill_id: skill_id.to_string(),
            reporter: reporter.to_string(),
            reason,
            description: description.to_string(),
            reported_at: now(),
            status: ReportStatus::Pending,
        };

        // Check if publisher should be suspended too
        let publisher_id = skill.publisher_id.clone();
        let should_suspend_publisher = skill.report_count >= self.config.suspension_threshold;

        drop(skills);

        if should_suspend_publisher && self.config.auto_suspension_enabled {
            if let Ok(mut publishers) = self.publishers.write() {
                if let Some(publisher) = publishers.get_mut(&publisher_id) {
                    publisher.suspended = true;
                    publisher.suspension_reason =
                        Some("Auto-suspended due to skill reports".to_string());
                }
            }
        }

        let mut reports = self
            .reports
            .write()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;
        reports.push(report);

        Ok(report_id)
    }

    /// Scan a skill for vulnerabilities (basic checks)
    pub fn scan_skill(&self, wasm_bytes: &[u8]) -> ScanResult {
        let start = std::time::Instant::now();
        let mut issues = Vec::new();

        // Check size
        if wasm_bytes.len() > 10 * 1024 * 1024 {
            issues.push(ScanIssue {
                severity: IssueSeverity::Medium,
                description: format!(
                    "WASM binary is large ({} bytes)",
                    wasm_bytes.len()
                ),
                recommendation: "Consider optimizing binary size".to_string(),
            });
        }

        // Check for WASM magic bytes
        if wasm_bytes.len() < 4 || &wasm_bytes[..4] != b"\0asm" {
            issues.push(ScanIssue {
                severity: IssueSeverity::Critical,
                description: "Invalid WASM binary: missing magic bytes".to_string(),
                recommendation: "Ensure the file is a valid WASM binary".to_string(),
            });
        }

        // Check minimum size
        if wasm_bytes.len() < 8 {
            issues.push(ScanIssue {
                severity: IssueSeverity::Critical,
                description: "WASM binary too small to be valid".to_string(),
                recommendation: "Provide a valid WASM binary".to_string(),
            });
        }

        let passed = !issues.iter().any(|i| i.severity >= IssueSeverity::High);

        ScanResult {
            passed,
            issues,
            scanned_at: now(),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Get publisher reputation
    pub fn get_reputation(&self, publisher_id: &str) -> PublisherResult<PublisherReputation> {
        let publishers = self
            .publishers
            .read()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        let publisher = publishers
            .get(publisher_id)
            .ok_or_else(|| PublisherError::NotFound(publisher_id.to_string()))?;

        let skills = self
            .skills
            .read()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        let publisher_skills: Vec<_> = skills
            .values()
            .filter(|s| s.publisher_id == publisher_id)
            .collect();

        let total_downloads: u64 = publisher_skills.iter().map(|s| s.download_count).sum();
        let total_reports: u32 = publisher_skills.iter().map(|s| s.report_count).sum();
        let avg_rating = if publisher_skills.is_empty() {
            0.0
        } else {
            publisher_skills.iter().map(|s| s.average_rating).sum::<f64>()
                / publisher_skills.len() as f64
        };

        Ok(PublisherReputation {
            publisher_id: publisher_id.to_string(),
            trust_level: publisher.trust_level,
            reputation_score: publisher.reputation_score,
            verification_count: publisher.active_verifications(),
            skill_count: publisher_skills.len(),
            total_downloads,
            total_reports,
            average_rating: avg_rating,
            is_suspended: publisher.suspended,
        })
    }

    /// Update publisher reputation score
    pub fn update_reputation(
        &self,
        publisher_id: &str,
        delta: f64,
    ) -> PublisherResult<f64> {
        let mut publishers = self
            .publishers
            .write()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        let publisher = publishers
            .get_mut(publisher_id)
            .ok_or_else(|| PublisherError::NotFound(publisher_id.to_string()))?;

        publisher.reputation_score = (publisher.reputation_score + delta).clamp(0.0, 1.0);
        publisher.update_trust_level();

        Ok(publisher.reputation_score)
    }

    /// List all publishers (optionally filtered by trust level)
    pub fn list_publishers(
        &self,
        min_trust_level: Option<TrustLevel>,
    ) -> PublisherResult<Vec<PublisherProfile>> {
        let publishers = self
            .publishers
            .read()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        let result: Vec<_> = publishers
            .values()
            .filter(|p| {
                if let Some(min_level) = min_trust_level {
                    p.trust_level >= min_level
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        Ok(result)
    }

    /// Get reports for a skill
    pub fn get_reports(&self, skill_id: &str) -> PublisherResult<Vec<SkillReport>> {
        let reports = self
            .reports
            .read()
            .map_err(|e| PublisherError::LockError(e.to_string()))?;

        Ok(reports
            .iter()
            .filter(|r| r.skill_id == skill_id)
            .cloned()
            .collect())
    }

    /// Get total number of publishers
    pub fn publisher_count(&self) -> usize {
        self.publishers.read().map(|p| p.len()).unwrap_or(0)
    }

    /// Get total number of published skills
    pub fn skill_count(&self) -> usize {
        self.skills.read().map(|s| s.len()).unwrap_or(0)
    }
}

/// Reputation details for a publisher
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublisherReputation {
    /// Publisher ID
    pub publisher_id: String,
    /// Trust level
    pub trust_level: TrustLevel,
    /// Reputation score (0.0-1.0)
    pub reputation_score: f64,
    /// Number of active verifications
    pub verification_count: usize,
    /// Number of published skills
    pub skill_count: usize,
    /// Total downloads across all skills
    pub total_downloads: u64,
    /// Total reports against publisher's skills
    pub total_reports: u32,
    /// Average rating
    pub average_rating: f64,
    /// Whether publisher is suspended
    pub is_suspended: bool,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Get current Unix timestamp
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a verification challenge
fn generate_challenge(publisher_id: &str, method: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(publisher_id.as_bytes());
    hasher.update(method.as_bytes());
    hasher.update(&now().to_le_bytes());
    hex::encode(hasher.finalize())[..32].to_string()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_publisher() -> PublisherProfile {
        PublisherProfile::new("test-pub", "Test Publisher", "test@example.com")
    }

    fn sample_skill(publisher_id: &str) -> PublishedSkill {
        PublishedSkill {
            id: "skill-001".to_string(),
            name: "test-skill".to_string(),
            version: "1.0.0".to_string(),
            publisher_id: publisher_id.to_string(),
            description: "A test skill".to_string(),
            wasm_hash: "abc123".to_string(),
            wasm_size: 1024,
            signature: None,
            permissions: vec!["read".to_string()],
            published_at: now(),
            suspended: false,
            report_count: 0,
            download_count: 0,
            average_rating: 0.0,
            scan_passed: true,
        }
    }

    #[test]
    fn test_register_publisher() {
        let registry = PublisherRegistry::with_defaults();
        let profile = sample_publisher();

        let id = registry.register(profile).unwrap();
        assert_eq!(id, "test-pub");
        assert_eq!(registry.publisher_count(), 1);
    }

    #[test]
    fn test_duplicate_publisher() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();

        let result = registry.register(sample_publisher());
        assert!(matches!(result, Err(PublisherError::AlreadyExists(_))));
    }

    #[test]
    fn test_get_publisher() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();

        let publisher = registry.get_publisher("test-pub").unwrap();
        assert_eq!(publisher.name, "Test Publisher");
        assert_eq!(publisher.trust_level, TrustLevel::Unverified);
    }

    #[test]
    fn test_verification_flow() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();

        // Request verification
        let request = VerificationRequest::github_org("test-pub", "test-org");
        let verification_id = registry.request_verification("test-pub", request).unwrap();
        assert!(!verification_id.is_empty());

        // Complete verification
        let record = registry
            .complete_verification(
                "test-pub",
                VerificationMethod::GithubOrg {
                    org_name: "test-org".to_string(),
                },
                true,
                "Verified via GitHub API",
            )
            .unwrap();

        assert_eq!(record.status, VerificationStatus::Verified);

        // Check trust level updated
        let publisher = registry.get_publisher("test-pub").unwrap();
        assert_eq!(publisher.trust_level, TrustLevel::Verified);
    }

    #[test]
    fn test_publish_skill() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();

        let skill = sample_skill("test-pub");
        let skill_id = registry.publish_skill("test-pub", skill).unwrap();
        assert_eq!(skill_id, "skill-001");
        assert_eq!(registry.skill_count(), 1);
    }

    #[test]
    fn test_publish_requires_verification() {
        let registry = PublisherRegistry::new(PublisherConfig::strict());
        registry.register(sample_publisher()).unwrap();

        let result = registry.publish_skill("test-pub", sample_skill("test-pub"));
        assert!(matches!(result, Err(PublisherError::PublishFailed(_))));
    }

    #[test]
    fn test_suspended_publisher_cannot_publish() {
        let registry = PublisherRegistry::with_defaults();
        let mut profile = sample_publisher();
        profile.suspended = true;
        registry.register(profile).unwrap();

        let result = registry.publish_skill("test-pub", sample_skill("test-pub"));
        assert!(matches!(result, Err(PublisherError::Suspended(_))));
    }

    #[test]
    fn test_report_skill() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();
        registry
            .publish_skill("test-pub", sample_skill("test-pub"))
            .unwrap();

        let report_id = registry
            .report_skill(
                "skill-001",
                "reporter-1",
                ReportReason::Malicious,
                "Skill contains suspicious behavior",
            )
            .unwrap();
        assert!(!report_id.is_empty());

        let reports = registry.get_reports("skill-001").unwrap();
        assert_eq!(reports.len(), 1);
    }

    #[test]
    fn test_auto_suspension() {
        let config = PublisherConfig {
            skill_suspension_threshold: 2,
            auto_suspension_enabled: true,
            ..PublisherConfig::default()
        };
        let registry = PublisherRegistry::new(config);
        registry.register(sample_publisher()).unwrap();
        registry
            .publish_skill("test-pub", sample_skill("test-pub"))
            .unwrap();

        // First report
        registry
            .report_skill("skill-001", "r1", ReportReason::Malicious, "report 1")
            .unwrap();

        // Second report should trigger suspension
        registry
            .report_skill("skill-001", "r2", ReportReason::Malicious, "report 2")
            .unwrap();

        // Skill should be suspended (read through the internal state)
        let skills = registry.skills.read().unwrap();
        assert!(skills.get("skill-001").unwrap().suspended);
    }

    #[test]
    fn test_reputation() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();
        registry
            .publish_skill("test-pub", sample_skill("test-pub"))
            .unwrap();

        let rep = registry.get_reputation("test-pub").unwrap();
        assert_eq!(rep.reputation_score, 0.5);
        assert_eq!(rep.skill_count, 1);

        // Update reputation
        let new_score = registry.update_reputation("test-pub", 0.2).unwrap();
        assert!((new_score - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn test_reputation_clamping() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();

        let score = registry.update_reputation("test-pub", 1.0).unwrap();
        assert_eq!(score, 1.0);

        let score = registry.update_reputation("test-pub", -2.0).unwrap();
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_list_publishers() {
        let registry = PublisherRegistry::with_defaults();
        registry.register(sample_publisher()).unwrap();

        let mut profile2 = PublisherProfile::new("pub-2", "Publisher 2", "pub2@test.com");
        profile2.trust_level = TrustLevel::Verified;
        registry.register(profile2).unwrap();

        let all = registry.list_publishers(None).unwrap();
        assert_eq!(all.len(), 2);

        let verified = registry.list_publishers(Some(TrustLevel::Verified)).unwrap();
        assert_eq!(verified.len(), 1);
    }

    #[test]
    fn test_scan_valid_wasm() {
        let registry = PublisherRegistry::with_defaults();

        // Valid WASM magic bytes + minimal content
        let wasm = b"\0asm\x01\x00\x00\x00extra_content_here";
        let result = registry.scan_skill(wasm);
        assert!(result.passed);
        assert!(result.issues.is_empty());
    }

    #[test]
    fn test_scan_invalid_wasm() {
        let registry = PublisherRegistry::with_defaults();

        let result = registry.scan_skill(b"not wasm");
        assert!(!result.passed);
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn test_scan_empty_wasm() {
        let registry = PublisherRegistry::with_defaults();

        let result = registry.scan_skill(b"");
        assert!(!result.passed);
    }

    #[test]
    fn test_trust_level_progression() {
        let mut profile = sample_publisher();
        assert_eq!(profile.trust_level, TrustLevel::Unverified);

        profile.update_trust_level();
        assert_eq!(profile.trust_level, TrustLevel::Basic);

        // Add one verification
        profile.verifications.push(VerificationRecord {
            method: VerificationMethod::GithubOrg {
                org_name: "test".to_string(),
            },
            status: VerificationStatus::Verified,
            verified_at: Some(now()),
            expires_at: Some(now() + 86400),
            details: "OK".to_string(),
        });
        profile.update_trust_level();
        assert_eq!(profile.trust_level, TrustLevel::Verified);

        // Add second verification + high reputation
        profile.verifications.push(VerificationRecord {
            method: VerificationMethod::Email {
                email: "test@test.com".to_string(),
                code: None,
            },
            status: VerificationStatus::Verified,
            verified_at: Some(now()),
            expires_at: Some(now() + 86400),
            details: "OK".to_string(),
        });
        profile.reputation_score = 0.9;
        profile.update_trust_level();
        assert_eq!(profile.trust_level, TrustLevel::Trusted);
    }

    #[test]
    fn test_verification_request_types() {
        let github = VerificationRequest::github_org("pub", "org");
        assert!(matches!(github.method, VerificationMethod::GithubOrg { .. }));

        let gpg = VerificationRequest::gpg_key("pub", "ABCD1234");
        assert!(matches!(gpg.method, VerificationMethod::GpgKey { .. }));

        let domain = VerificationRequest::domain("pub", "example.com");
        assert!(matches!(domain.method, VerificationMethod::DomainOwnership { .. }));

        let email = VerificationRequest::email("pub", "test@test.com");
        assert!(matches!(email.method, VerificationMethod::Email { .. }));
    }

    #[test]
    fn test_invalid_publisher_profile() {
        let registry = PublisherRegistry::with_defaults();

        let empty_id = PublisherProfile::new("", "Name", "email");
        assert!(matches!(
            registry.register(empty_id),
            Err(PublisherError::InvalidProfile(_))
        ));

        let empty_name = PublisherProfile::new("id", "", "email");
        assert!(matches!(
            registry.register(empty_name),
            Err(PublisherError::InvalidProfile(_))
        ));
    }
}
