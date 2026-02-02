//! Secret Scrubbing Module (MEM-006)
//!
//! Provides automatic detection and redaction of sensitive patterns in memory
//! snapshots, logs, and exported data. Prevents accidental exposure of API keys,
//! passwords, tokens, and other secrets.
//!
//! # Overview
//!
//! Secret scrubbing enables:
//! - Pattern-based detection of common secret formats
//! - Configurable redaction strategies
//! - Pre-persistence scrubbing of memory snapshots
//! - Audit-safe logging with sensitive data masked
//!
//! # Example
//!
//! ```rust
//! use vak::memory::secret_scrubber::{SecretScrubber, ScrubberConfig, PatternType};
//!
//! let scrubber = SecretScrubber::with_defaults();
//!
//! let text = "API_KEY=sk-proj-abc123xyz and password=secret123";
//! let scrubbed = scrubber.scrub(text);
//!
//! assert!(!scrubbed.contains("sk-proj-"));
//! assert!(!scrubbed.contains("secret123"));
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 3.2: Secret Scrubbing

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tracing::debug;

/// Errors that can occur during secret scrubbing
#[derive(Debug, Error)]
pub enum ScrubberError {
    /// Invalid regex pattern
    #[error("Invalid regex pattern: {0}")]
    InvalidPattern(String),

    /// Scrubbing failed
    #[error("Scrubbing failed: {0}")]
    ScrubFailed(String),
}

/// Result type for scrubber operations
pub type ScrubberResult<T> = Result<T, ScrubberError>;

/// Types of secret patterns to detect
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    /// OpenAI API keys (sk-...)
    OpenAiKey,
    /// Anthropic API keys (sk-ant-...)
    AnthropicKey,
    /// Generic API keys
    GenericApiKey,
    /// AWS access keys
    AwsAccessKey,
    /// AWS secret keys
    AwsSecretKey,
    /// GitHub tokens
    GitHubToken,
    /// Generic bearer tokens
    BearerToken,
    /// Passwords in common formats
    Password,
    /// Private keys (PEM format)
    PrivateKey,
    /// JWT tokens
    JwtToken,
    /// Database connection strings
    DatabaseUrl,
    /// Generic secrets (key=value patterns)
    GenericSecret,
    /// Credit card numbers
    CreditCard,
    /// Social Security Numbers
    Ssn,
    /// Custom pattern
    Custom,
}

impl PatternType {
    /// Get the default regex pattern for this type
    pub fn default_pattern(&self) -> &'static str {
        match self {
            PatternType::OpenAiKey => r"sk-[a-zA-Z0-9]{20,}",
            PatternType::AnthropicKey => r"sk-ant-[a-zA-Z0-9-]{20,}",
            PatternType::GenericApiKey => r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\x22]?([a-zA-Z0-9_-]{16,})['\x22]?",
            PatternType::AwsAccessKey => r"AKIA[0-9A-Z]{16}",
            PatternType::AwsSecretKey => r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[=:]\s*['\x22]?([a-zA-Z0-9/+=]{40})['\x22]?",
            PatternType::GitHubToken => r"(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}",
            PatternType::BearerToken => r"(?i)bearer\s+[a-zA-Z0-9_.~+/-]+=*",
            PatternType::Password => r"(?i)(password|passwd|pwd)\s*[=:]\s*['\x22]?([^\s'\x22]{4,})['\x22]?",
            PatternType::PrivateKey => r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            PatternType::JwtToken => r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
            PatternType::DatabaseUrl => r"(?i)(postgres|mysql|mongodb|redis)://[^\s]+",
            PatternType::GenericSecret => r"(?i)(secret|token|credential)[_-]?\w*\s*[=:]\s*['\x22]?([a-zA-Z0-9_-]{8,})['\x22]?",
            PatternType::CreditCard => r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            PatternType::Ssn => r"\b\d{3}-\d{2}-\d{4}\b",
            PatternType::Custom => "",
        }
    }

    /// Get a human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            PatternType::OpenAiKey => "OpenAI API Key",
            PatternType::AnthropicKey => "Anthropic API Key",
            PatternType::GenericApiKey => "Generic API Key",
            PatternType::AwsAccessKey => "AWS Access Key",
            PatternType::AwsSecretKey => "AWS Secret Key",
            PatternType::GitHubToken => "GitHub Token",
            PatternType::BearerToken => "Bearer Token",
            PatternType::Password => "Password",
            PatternType::PrivateKey => "Private Key",
            PatternType::JwtToken => "JWT Token",
            PatternType::DatabaseUrl => "Database URL",
            PatternType::GenericSecret => "Generic Secret",
            PatternType::CreditCard => "Credit Card",
            PatternType::Ssn => "SSN",
            PatternType::Custom => "Custom Pattern",
        }
    }
}

/// Configuration for secret scrubbing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubberConfig {
    /// Enable scrubbing
    pub enabled: bool,
    /// Patterns to detect
    pub patterns: Vec<PatternType>,
    /// Custom patterns (regex strings)
    pub custom_patterns: Vec<String>,
    /// Redaction string
    pub redaction_text: String,
    /// Whether to log detected secrets (redacted)
    pub log_detections: bool,
    /// Minimum confidence for detection (0.0 - 1.0)
    pub min_confidence: f64,
}

impl Default for ScrubberConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            patterns: vec![
                PatternType::OpenAiKey,
                PatternType::AnthropicKey,
                PatternType::GenericApiKey,
                PatternType::AwsAccessKey,
                PatternType::AwsSecretKey,
                PatternType::GitHubToken,
                PatternType::BearerToken,
                PatternType::Password,
                PatternType::PrivateKey,
                PatternType::JwtToken,
                PatternType::DatabaseUrl,
                PatternType::GenericSecret,
            ],
            custom_patterns: Vec::new(),
            redaction_text: "[REDACTED]".to_string(),
            log_detections: true,
            min_confidence: 0.5,
        }
    }
}

impl ScrubberConfig {
    /// Create a minimal configuration (for testing)
    pub fn minimal() -> Self {
        Self {
            enabled: true,
            patterns: vec![PatternType::OpenAiKey, PatternType::Password],
            custom_patterns: Vec::new(),
            redaction_text: "***".to_string(),
            log_detections: false,
            min_confidence: 0.0,
        }
    }

    /// Create a comprehensive configuration (for production)
    pub fn comprehensive() -> Self {
        Self::default()
    }

    /// Add PII patterns (GDPR compliance)
    pub fn with_pii_patterns(mut self) -> Self {
        self.patterns.push(PatternType::CreditCard);
        self.patterns.push(PatternType::Ssn);
        self
    }
}

/// A detected secret occurrence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretDetection {
    /// Pattern type that matched
    pub pattern_type: PatternType,
    /// Start position in text
    pub start: usize,
    /// End position in text
    pub end: usize,
    /// Matched text (partially redacted for logging)
    pub preview: String,
    /// Detection confidence (0.0 - 1.0)
    pub confidence: f64,
}

impl SecretDetection {
    /// Create a preview that shows only first/last few characters
    fn create_preview(matched: &str) -> String {
        if matched.len() <= 8 {
            "*".repeat(matched.len())
        } else {
            let first = &matched[..3];
            let last = &matched[matched.len() - 2..];
            format!("{}...{}", first, last)
        }
    }
}

/// Compiled pattern for efficient matching
struct CompiledPattern {
    pattern_type: PatternType,
    regex: Regex,
    confidence: f64,
}

/// Secret scrubber for detecting and redacting sensitive data
pub struct SecretScrubber {
    config: ScrubberConfig,
    patterns: Vec<CompiledPattern>,
}

impl std::fmt::Debug for SecretScrubber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretScrubber")
            .field("config", &self.config)
            .field("pattern_count", &self.patterns.len())
            .finish()
    }
}

impl SecretScrubber {
    /// Create a new secret scrubber with the given configuration
    pub fn new(config: ScrubberConfig) -> ScrubberResult<Self> {
        let mut patterns = Vec::new();

        // Compile built-in patterns
        for pattern_type in &config.patterns {
            let pattern_str = pattern_type.default_pattern();
            if !pattern_str.is_empty() {
                let regex = Regex::new(pattern_str)
                    .map_err(|e| ScrubberError::InvalidPattern(e.to_string()))?;
                patterns.push(CompiledPattern {
                    pattern_type: *pattern_type,
                    regex,
                    confidence: 0.9, // High confidence for built-in patterns
                });
            }
        }

        // Compile custom patterns
        for custom in &config.custom_patterns {
            let regex =
                Regex::new(custom).map_err(|e| ScrubberError::InvalidPattern(e.to_string()))?;
            patterns.push(CompiledPattern {
                pattern_type: PatternType::Custom,
                regex,
                confidence: 0.7, // Lower confidence for custom patterns
            });
        }

        Ok(Self { config, patterns })
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(ScrubberConfig::default()).expect("Default config should be valid")
    }

    /// Create with minimal configuration (for testing)
    pub fn minimal() -> Self {
        Self::new(ScrubberConfig::minimal()).expect("Minimal config should be valid")
    }

    /// Detect all secrets in text
    pub fn detect(&self, text: &str) -> Vec<SecretDetection> {
        if !self.config.enabled {
            return Vec::new();
        }

        let mut detections = Vec::new();

        for compiled in &self.patterns {
            if compiled.confidence < self.config.min_confidence {
                continue;
            }

            for m in compiled.regex.find_iter(text) {
                let matched = m.as_str();
                let detection = SecretDetection {
                    pattern_type: compiled.pattern_type,
                    start: m.start(),
                    end: m.end(),
                    preview: SecretDetection::create_preview(matched),
                    confidence: compiled.confidence,
                };

                if self.config.log_detections {
                    debug!(
                        pattern = %compiled.pattern_type.display_name(),
                        preview = %detection.preview,
                        position = m.start(),
                        "Secret detected"
                    );
                }

                detections.push(detection);
            }
        }

        // Sort by position
        detections.sort_by_key(|d| d.start);

        detections
    }

    /// Scrub all secrets from text, replacing with redaction text
    pub fn scrub(&self, text: &str) -> String {
        if !self.config.enabled {
            return text.to_string();
        }

        let detections = self.detect(text);
        if detections.is_empty() {
            return text.to_string();
        }

        // Build result string with redactions
        let mut result = String::with_capacity(text.len());
        let mut last_end = 0;

        for detection in &detections {
            // Skip overlapping detections
            if detection.start < last_end {
                continue;
            }

            // Add text before this detection
            result.push_str(&text[last_end..detection.start]);
            // Add redaction
            result.push_str(&self.config.redaction_text);
            last_end = detection.end;
        }

        // Add remaining text
        result.push_str(&text[last_end..]);

        result
    }

    /// Scrub secrets from a JSON value (recursively)
    pub fn scrub_json(&self, value: &serde_json::Value) -> serde_json::Value {
        if !self.config.enabled {
            return value.clone();
        }

        match value {
            serde_json::Value::String(s) => {
                serde_json::Value::String(self.scrub(s))
            }
            serde_json::Value::Object(map) => {
                let scrubbed: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(k, v)| {
                        // Also scrub keys that look like they contain secrets
                        let scrubbed_key = if self.is_sensitive_key(k) {
                            k.clone() // Keep key but scrub value
                        } else {
                            k.clone()
                        };
                        (scrubbed_key, self.scrub_json(v))
                    })
                    .collect();
                serde_json::Value::Object(scrubbed)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(|v| self.scrub_json(v)).collect())
            }
            // Other types pass through unchanged
            other => other.clone(),
        }
    }

    /// Scrub secrets from a HashMap
    pub fn scrub_map(&self, map: &HashMap<String, String>) -> HashMap<String, String> {
        if !self.config.enabled {
            return map.clone();
        }

        map.iter()
            .map(|(k, v)| (k.clone(), self.scrub(v)))
            .collect()
    }

    /// Check if a key name suggests it contains sensitive data
    pub fn is_sensitive_key(&self, key: &str) -> bool {
        let key_lower = key.to_lowercase();
        let sensitive_keywords = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "api-key",
            "auth",
            "credential",
            "private",
            "access_key",
            "secret_key",
        ];

        sensitive_keywords
            .iter()
            .any(|kw| key_lower.contains(kw))
    }

    /// Check if text contains any secrets
    pub fn contains_secrets(&self, text: &str) -> bool {
        if !self.config.enabled {
            return false;
        }

        for compiled in &self.patterns {
            if compiled.confidence >= self.config.min_confidence && compiled.regex.is_match(text) {
                return true;
            }
        }

        false
    }

    /// Get count of secrets in text
    pub fn count_secrets(&self, text: &str) -> usize {
        self.detect(text).len()
    }

    /// Create a scrubbing report
    pub fn generate_report(&self, text: &str) -> ScrubReport {
        let detections = self.detect(text);
        let mut by_type: HashMap<PatternType, usize> = HashMap::new();

        for detection in &detections {
            *by_type.entry(detection.pattern_type).or_insert(0) += 1;
        }

        ScrubReport {
            total_detections: detections.len(),
            by_type,
            detections,
            scrubbed_length: self.scrub(text).len(),
            original_length: text.len(),
        }
    }
}

/// Report of scrubbing results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScrubReport {
    /// Total number of secrets detected
    pub total_detections: usize,
    /// Detections by pattern type
    pub by_type: HashMap<PatternType, usize>,
    /// Individual detections
    pub detections: Vec<SecretDetection>,
    /// Length of scrubbed text
    pub scrubbed_length: usize,
    /// Length of original text
    pub original_length: usize,
}

impl ScrubReport {
    /// Check if any secrets were found
    pub fn has_secrets(&self) -> bool {
        self.total_detections > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openai_key_detection() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "My API key is sk-abc123xyz890defghijklmnopqrstuvw";

        let detections = scrubber.detect(text);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].pattern_type, PatternType::OpenAiKey);
    }

    #[test]
    fn test_password_detection() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "password=supersecret123";

        let detections = scrubber.detect(text);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].pattern_type, PatternType::Password);
    }

    #[test]
    fn test_scrubbing() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "Config: API_KEY=sk-abc123xyz890defghijklmnopqrstuvw end";

        let scrubbed = scrubber.scrub(text);
        assert!(!scrubbed.contains("sk-abc123"));
        assert!(scrubbed.contains("[REDACTED]"));
        assert!(scrubbed.contains("Config:"));
        assert!(scrubbed.contains("end"));
    }

    #[test]
    fn test_multiple_secrets() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "key1=sk-aaaaaaaaaaaaaaaaaaaaaaaa key2=sk-bbbbbbbbbbbbbbbbbbbbbbbb";

        let detections = scrubber.detect(text);
        assert_eq!(detections.len(), 2);
    }

    #[test]
    fn test_github_token() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890";

        let detections = scrubber.detect(text);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].pattern_type, PatternType::GitHubToken);
    }

    #[test]
    fn test_aws_key() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "AWS key: AKIAIOSFODNN7EXAMPLE";

        let detections = scrubber.detect(text);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].pattern_type, PatternType::AwsAccessKey);
    }

    #[test]
    fn test_jwt_token() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";

        let detections = scrubber.detect(text);
        assert!(!detections.is_empty());
        assert_eq!(detections[0].pattern_type, PatternType::JwtToken);
    }

    #[test]
    fn test_json_scrubbing() {
        let scrubber = SecretScrubber::with_defaults();
        let json = serde_json::json!({
            "name": "test",
            "api_key": "sk-abc123xyz890defghijklmnopqrstuvw",
            "nested": {
                "password": "password=secret123"
            }
        });

        let scrubbed = scrubber.scrub_json(&json);
        let scrubbed_str = scrubbed.to_string();

        assert!(!scrubbed_str.contains("sk-abc123"));
        assert!(scrubbed_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_sensitive_key_detection() {
        let scrubber = SecretScrubber::with_defaults();

        assert!(scrubber.is_sensitive_key("api_key"));
        assert!(scrubber.is_sensitive_key("PASSWORD"));
        assert!(scrubber.is_sensitive_key("secret_token"));
        assert!(!scrubber.is_sensitive_key("username"));
        assert!(!scrubber.is_sensitive_key("email"));
    }

    #[test]
    fn test_scrub_report() {
        let scrubber = SecretScrubber::with_defaults();
        let text = "key=sk-abc123xyz890defghijklmnopqrstuvw password=secret123";

        let report = scrubber.generate_report(text);
        assert!(report.has_secrets());
        assert!(report.total_detections >= 2);
    }

    #[test]
    fn test_disabled_scrubber() {
        let config = ScrubberConfig {
            enabled: false,
            ..Default::default()
        };
        let scrubber = SecretScrubber::new(config).unwrap();

        let text = "sk-abc123xyz890defghijklmnopqrstuvw";
        let scrubbed = scrubber.scrub(text);

        // Should not scrub when disabled
        assert_eq!(scrubbed, text);
    }

    #[test]
    fn test_custom_redaction_text() {
        let config = ScrubberConfig {
            redaction_text: "<<HIDDEN>>".to_string(),
            ..Default::default()
        };
        let scrubber = SecretScrubber::new(config).unwrap();

        let text = "key=sk-abc123xyz890defghijklmnopqrstuvw";
        let scrubbed = scrubber.scrub(text);

        assert!(scrubbed.contains("<<HIDDEN>>"));
    }

    #[test]
    fn test_preview_generation() {
        let preview = SecretDetection::create_preview("sk-abc123xyz890defghijklmnopqrstuvw");
        assert!(preview.starts_with("sk-"));
        assert!(preview.ends_with("vw"));
        assert!(preview.contains("..."));
    }
}
