//! Formal Verification Gateway (NSR-002)
//!
//! This module provides formal verification capabilities for agent actions.
//! It supports a simple constraint DSL for common verification tasks and
//! optionally integrates with Z3 SMT solver for complex constraint solving.
//!
//! # Features
//! - **Constraint DSL**: Simple YAML-based constraint definitions
//! - **Safety verification**: Verify actions don't violate safety constraints
//! - **Counterexample generation**: Get concrete counterexamples when verification fails
//! - **Batch verification**: Verify multiple constraints efficiently
//! - **Optional Z3 integration**: Use Z3 SMT solver for complex SAT problems (requires `z3-solver` feature)
//!
//! # Example
//!
//! ```
//! use vak::reasoner::{ConstraintVerifier, Constraint, ConstraintKind, FormalVerifier};
//! use std::collections::HashMap;
//!
//! // Create a verifier
//! let verifier = ConstraintVerifier::new();
//!
//! // Define a constraint: amount must be less than 1000
//! let constraint = Constraint::new("max_refund", ConstraintKind::LessThan {
//!     field: "amount".to_string(),
//!     value: 1000.into(),
//! });
//!
//! // Create context with field values
//! let mut context = HashMap::new();
//! context.insert("amount".to_string(), 500.into());
//!
//! // Verify the constraint
//! let result = verifier.verify(&constraint, &context).unwrap();
//! assert!(result.is_satisfied());
//! ```

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during formal verification
#[derive(Debug, Error)]
pub enum VerificationError {
    /// Constraint definition is invalid
    #[error("Invalid constraint: {0}")]
    InvalidConstraint(String),

    /// Missing required field in context
    #[error("Missing field in context: {0}")]
    MissingField(String),

    /// Type mismatch during constraint evaluation
    #[error("Type mismatch for field '{field}': expected {expected}, got {actual}")]
    TypeMismatch {
        /// Field name
        field: String,
        /// Expected type
        expected: String,
        /// Actual type
        actual: String,
    },

    /// Solver error (used with Z3 feature)
    #[error("Solver error: {0}")]
    SolverError(String),

    /// Failed to parse constraint file
    #[error("Failed to parse constraint file '{path}': {message}")]
    ParseError {
        /// File path
        path: String,
        /// Error message
        message: String,
    },

    /// I/O error reading constraint file
    #[error("I/O error reading '{path}': {message}")]
    IoError {
        /// File path
        path: String,
        /// Error message
        message: String,
    },

    /// Verification timeout
    #[error("Verification timed out after {0} ms")]
    Timeout(u64),

    /// Unknown constraint kind
    #[error("Unknown constraint kind: {0}")]
    UnknownConstraintKind(String),

    /// Invalid regex pattern
    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
}

// ============================================================================
// Value Types
// ============================================================================

/// A value that can be used in constraints
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConstraintValue {
    /// Integer value
    Integer(i64),
    /// Floating point value
    Float(f64),
    /// String value
    String(String),
    /// Boolean value
    Boolean(bool),
    /// List of values
    List(Vec<ConstraintValue>),
}

impl ConstraintValue {
    /// Get as integer if possible
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            ConstraintValue::Integer(i) => Some(*i),
            ConstraintValue::Float(f) => Some(*f as i64),
            _ => None,
        }
    }

    /// Get as float if possible
    pub fn as_float(&self) -> Option<f64> {
        match self {
            ConstraintValue::Integer(i) => Some(*i as f64),
            ConstraintValue::Float(f) => Some(*f),
            _ => None,
        }
    }

    /// Get as string if possible
    pub fn as_string(&self) -> Option<&str> {
        match self {
            ConstraintValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as boolean if possible
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            ConstraintValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    /// Get as list if possible
    pub fn as_list(&self) -> Option<&[ConstraintValue]> {
        match self {
            ConstraintValue::List(l) => Some(l),
            _ => None,
        }
    }

    /// Get the type name for error messages
    pub fn type_name(&self) -> &'static str {
        match self {
            ConstraintValue::Integer(_) => "integer",
            ConstraintValue::Float(_) => "float",
            ConstraintValue::String(_) => "string",
            ConstraintValue::Boolean(_) => "boolean",
            ConstraintValue::List(_) => "list",
        }
    }
}

impl From<i64> for ConstraintValue {
    fn from(v: i64) -> Self {
        ConstraintValue::Integer(v)
    }
}

impl From<i32> for ConstraintValue {
    fn from(v: i32) -> Self {
        ConstraintValue::Integer(v as i64)
    }
}

impl From<f64> for ConstraintValue {
    fn from(v: f64) -> Self {
        ConstraintValue::Float(v)
    }
}

impl From<String> for ConstraintValue {
    fn from(v: String) -> Self {
        ConstraintValue::String(v)
    }
}

impl From<&str> for ConstraintValue {
    fn from(v: &str) -> Self {
        ConstraintValue::String(v.to_string())
    }
}

impl From<bool> for ConstraintValue {
    fn from(v: bool) -> Self {
        ConstraintValue::Boolean(v)
    }
}

impl<T: Into<ConstraintValue>> From<Vec<T>> for ConstraintValue {
    fn from(v: Vec<T>) -> Self {
        ConstraintValue::List(v.into_iter().map(Into::into).collect())
    }
}

impl fmt::Display for ConstraintValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstraintValue::Integer(i) => write!(f, "{}", i),
            ConstraintValue::Float(fl) => write!(f, "{}", fl),
            ConstraintValue::String(s) => write!(f, "\"{}\"", s),
            ConstraintValue::Boolean(b) => write!(f, "{}", b),
            ConstraintValue::List(l) => {
                write!(f, "[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", v)?;
                }
                write!(f, "]")
            }
        }
    }
}

// ============================================================================
// Constraint Types
// ============================================================================

/// Kind of constraint to verify
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConstraintKind {
    /// Field must equal a value
    Equals {
        /// Field name to check
        field: String,
        /// Expected value
        value: ConstraintValue,
    },

    /// Field must not equal a value
    NotEquals {
        /// Field name to check
        field: String,
        /// Value that must not match
        value: ConstraintValue,
    },

    /// Field must be less than a value
    LessThan {
        /// Field name to check
        field: String,
        /// Upper bound (exclusive)
        value: ConstraintValue,
    },

    /// Field must be less than or equal to a value
    LessThanOrEqual {
        /// Field name to check
        field: String,
        /// Upper bound (inclusive)
        value: ConstraintValue,
    },

    /// Field must be greater than a value
    GreaterThan {
        /// Field name to check
        field: String,
        /// Lower bound (exclusive)
        value: ConstraintValue,
    },

    /// Field must be greater than or equal to a value
    GreaterThanOrEqual {
        /// Field name to check
        field: String,
        /// Lower bound (inclusive)
        value: ConstraintValue,
    },

    /// Field must be in a set of allowed values
    In {
        /// Field name to check
        field: String,
        /// Allowed values
        values: Vec<ConstraintValue>,
    },

    /// Field must not be in a set of forbidden values
    NotIn {
        /// Field name to check
        field: String,
        /// Forbidden values
        values: Vec<ConstraintValue>,
    },

    /// Resource pattern must not be accessed (FORBIDDEN constraint)
    Forbidden {
        /// Resource patterns that are forbidden (glob-style)
        resources: Vec<String>,
    },

    /// Field must contain a substring (for strings)
    Contains {
        /// Field name to check
        field: String,
        /// Substring that must be present
        value: String,
    },

    /// Field must match a regex pattern
    Matches {
        /// Field name to check
        field: String,
        /// Regex pattern
        pattern: String,
    },

    /// Field must be between two values (inclusive)
    Between {
        /// Field name to check
        field: String,
        /// Lower bound (inclusive)
        min: ConstraintValue,
        /// Upper bound (inclusive)
        max: ConstraintValue,
    },

    /// All sub-constraints must be satisfied (AND)
    And {
        /// Sub-constraints
        constraints: Vec<Constraint>,
    },

    /// At least one sub-constraint must be satisfied (OR)
    Or {
        /// Sub-constraints
        constraints: Vec<Constraint>,
    },

    /// Sub-constraint must not be satisfied (NOT)
    Not {
        /// Sub-constraint to negate
        constraint: Box<Constraint>,
    },

    /// If condition is true, then consequence must be true (IMPLIES)
    Implies {
        /// Condition constraint
        condition: Box<Constraint>,
        /// Consequence constraint
        consequence: Box<Constraint>,
    },
}

/// A constraint to verify
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraint {
    /// Unique name for the constraint
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: Option<String>,

    /// The constraint kind with parameters
    #[serde(flatten)]
    pub kind: ConstraintKind,

    /// Priority (higher = more important)
    #[serde(default = "default_priority")]
    pub priority: u32,

    /// Whether this constraint is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_priority() -> u32 {
    100
}

fn default_enabled() -> bool {
    true
}

impl Constraint {
    /// Create a new constraint
    pub fn new(name: impl Into<String>, kind: ConstraintKind) -> Self {
        Self {
            name: name.into(),
            description: None,
            kind,
            priority: default_priority(),
            enabled: true,
        }
    }

    /// Add a description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }

    /// Enable or disable the constraint
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if let Some(ref desc) = self.description {
            write!(f, " ({})", desc)?;
        }
        Ok(())
    }
}

// ============================================================================
// Verification Results
// ============================================================================

/// Result of a verification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// Constraint is satisfied
    Satisfied,
    /// Constraint is violated
    Violated,
    /// Could not determine (unknown)
    Unknown,
}

impl VerificationStatus {
    /// Check if satisfied
    pub fn is_satisfied(&self) -> bool {
        matches!(self, VerificationStatus::Satisfied)
    }

    /// Check if violated
    pub fn is_violated(&self) -> bool {
        matches!(self, VerificationStatus::Violated)
    }
}

/// A counterexample showing why a constraint was violated
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Counterexample {
    /// Field values that caused the violation
    pub values: HashMap<String, ConstraintValue>,
    /// Human-readable explanation
    pub explanation: String,
}

impl Counterexample {
    /// Create a new counterexample
    pub fn new(values: HashMap<String, ConstraintValue>, explanation: impl Into<String>) -> Self {
        Self {
            values,
            explanation: explanation.into(),
        }
    }
}

impl fmt::Display for Counterexample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.explanation, self.values)
    }
}

/// Complete result of verifying a constraint
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Name of the constraint that was verified
    pub constraint_name: String,
    /// Status of the verification
    pub status: VerificationStatus,
    /// Counterexample if violated
    pub counterexample: Option<Counterexample>,
    /// Time taken to verify (in microseconds)
    pub verification_time_us: u64,
}

impl VerificationResult {
    /// Create a satisfied result
    pub fn satisfied(constraint_name: impl Into<String>, time_us: u64) -> Self {
        Self {
            constraint_name: constraint_name.into(),
            status: VerificationStatus::Satisfied,
            counterexample: None,
            verification_time_us: time_us,
        }
    }

    /// Create a violated result with counterexample
    pub fn violated(
        constraint_name: impl Into<String>,
        counterexample: Counterexample,
        time_us: u64,
    ) -> Self {
        Self {
            constraint_name: constraint_name.into(),
            status: VerificationStatus::Violated,
            counterexample: Some(counterexample),
            verification_time_us: time_us,
        }
    }

    /// Create an unknown result
    pub fn unknown(constraint_name: impl Into<String>, time_us: u64) -> Self {
        Self {
            constraint_name: constraint_name.into(),
            status: VerificationStatus::Unknown,
            counterexample: None,
            verification_time_us: time_us,
        }
    }

    /// Check if satisfied
    pub fn is_satisfied(&self) -> bool {
        self.status.is_satisfied()
    }

    /// Check if violated
    pub fn is_violated(&self) -> bool {
        self.status.is_violated()
    }
}

impl fmt::Display for VerificationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:?}", self.constraint_name, self.status)?;
        if let Some(ref ce) = self.counterexample {
            write!(f, " - {}", ce)?;
        }
        Ok(())
    }
}

/// Result of verifying multiple constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationResult {
    /// Results for each constraint
    pub results: Vec<VerificationResult>,
    /// Total time taken (in microseconds)
    pub total_time_us: u64,
}

impl BatchVerificationResult {
    /// Create a new batch result
    pub fn new(results: Vec<VerificationResult>, total_time_us: u64) -> Self {
        Self {
            results,
            total_time_us,
        }
    }

    /// Check if all constraints are satisfied
    pub fn all_satisfied(&self) -> bool {
        self.results.iter().all(|r| r.is_satisfied())
    }

    /// Get all violated constraints
    pub fn violated(&self) -> Vec<&VerificationResult> {
        self.results.iter().filter(|r| r.is_violated()).collect()
    }

    /// Get count of satisfied constraints
    pub fn satisfied_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_satisfied()).count()
    }

    /// Get count of violated constraints
    pub fn violated_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_violated()).count()
    }
}

// ============================================================================
// Constraint File
// ============================================================================

/// A file containing multiple constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintFile {
    /// Version of the constraint file format
    #[serde(default = "default_version")]
    pub version: String,
    /// Description of the constraint set
    #[serde(default)]
    pub description: Option<String>,
    /// List of constraints
    pub constraints: Vec<Constraint>,
}

fn default_version() -> String {
    "1.0".to_string()
}

impl ConstraintFile {
    /// Create a new constraint file
    pub fn new(constraints: Vec<Constraint>) -> Self {
        Self {
            version: default_version(),
            description: None,
            constraints,
        }
    }

    /// Load from a YAML file
    pub fn from_file(path: &Path) -> Result<Self, VerificationError> {
        let content = std::fs::read_to_string(path).map_err(|e| VerificationError::IoError {
            path: path.display().to_string(),
            message: e.to_string(),
        })?;

        Self::from_yaml(&content, path.display().to_string())
    }

    /// Parse from YAML string
    pub fn from_yaml(content: &str, path: String) -> Result<Self, VerificationError> {
        serde_yaml::from_str(content).map_err(|e| VerificationError::ParseError {
            path,
            message: e.to_string(),
        })
    }

    /// Get enabled constraints sorted by priority (highest first)
    pub fn enabled_constraints(&self) -> Vec<&Constraint> {
        let mut constraints: Vec<_> = self.constraints.iter().filter(|c| c.enabled).collect();
        constraints.sort_by(|a, b| b.priority.cmp(&a.priority));
        constraints
    }
}

// ============================================================================
// Formal Verifier Trait
// ============================================================================

/// Trait for formal verification implementations
pub trait FormalVerifier: Send + Sync {
    /// Verify a single constraint against a context
    fn verify(
        &self,
        constraint: &Constraint,
        context: &HashMap<String, ConstraintValue>,
    ) -> Result<VerificationResult, VerificationError>;

    /// Verify multiple constraints against a context
    fn verify_all(
        &self,
        constraints: &[Constraint],
        context: &HashMap<String, ConstraintValue>,
    ) -> Result<BatchVerificationResult, VerificationError>;

    /// Check if a resource path is forbidden
    fn check_forbidden(&self, resource: &str, forbidden_patterns: &[String]) -> bool;

    /// Validate that a constraint definition is valid
    fn validate_constraint(&self, constraint: &Constraint) -> Result<(), VerificationError>;
}

// ============================================================================
// Constraint Verifier Configuration
// ============================================================================

/// Configuration for the constraint verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    /// Timeout for verification (in milliseconds)
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,
}

fn default_timeout_ms() -> u64 {
    5000
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout_ms(),
            verbose: false,
        }
    }
}

// ============================================================================
// Constraint Verifier Implementation
// ============================================================================

/// Pure Rust constraint verifier
///
/// This verifier implements the constraint DSL without requiring external
/// dependencies like Z3. It handles common constraint types efficiently
/// and provides detailed counterexamples when constraints are violated.
#[derive(Debug, Clone)]
pub struct ConstraintVerifier {
    /// Configuration for the verifier
    config: VerifierConfig,
}

impl ConstraintVerifier {
    /// Create a new constraint verifier with default configuration
    pub fn new() -> Self {
        Self {
            config: VerifierConfig::default(),
        }
    }

    /// Create a new constraint verifier with custom configuration
    pub fn with_config(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Get the current configuration
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }

    /// Verify a numeric comparison constraint
    fn verify_numeric_constraint(
        &self,
        field: &str,
        context: &HashMap<String, ConstraintValue>,
        constraint_name: &str,
        check_fn: impl FnOnce(f64) -> bool,
        violation_msg: impl FnOnce(f64) -> String,
        start_time: std::time::Instant,
    ) -> Result<VerificationResult, VerificationError> {
        let value = context
            .get(field)
            .ok_or_else(|| VerificationError::MissingField(field.to_string()))?;

        let num_value = value
            .as_float()
            .ok_or_else(|| VerificationError::TypeMismatch {
                field: field.to_string(),
                expected: "numeric".to_string(),
                actual: value.type_name().to_string(),
            })?;

        let elapsed_us = start_time.elapsed().as_micros() as u64;

        if check_fn(num_value) {
            Ok(VerificationResult::satisfied(constraint_name, elapsed_us))
        } else {
            let mut values = HashMap::new();
            values.insert(field.to_string(), value.clone());
            let ce = Counterexample::new(values, violation_msg(num_value));
            Ok(VerificationResult::violated(
                constraint_name,
                ce,
                elapsed_us,
            ))
        }
    }

    /// Verify an equality constraint
    fn verify_equality(
        &self,
        field: &str,
        expected: &ConstraintValue,
        context: &HashMap<String, ConstraintValue>,
        constraint_name: &str,
        should_equal: bool,
        start_time: std::time::Instant,
    ) -> Result<VerificationResult, VerificationError> {
        let value = context
            .get(field)
            .ok_or_else(|| VerificationError::MissingField(field.to_string()))?;

        let elapsed_us = start_time.elapsed().as_micros() as u64;

        let is_equal = value == expected;
        let satisfied = if should_equal { is_equal } else { !is_equal };

        if satisfied {
            Ok(VerificationResult::satisfied(constraint_name, elapsed_us))
        } else {
            let mut values = HashMap::new();
            values.insert(field.to_string(), value.clone());
            let explanation = if should_equal {
                format!("expected {} = {}, got {}", field, expected, value)
            } else {
                format!("expected {} != {}, but it equals", field, expected)
            };
            let ce = Counterexample::new(values, explanation);
            Ok(VerificationResult::violated(
                constraint_name,
                ce,
                elapsed_us,
            ))
        }
    }

    /// Verify an In/NotIn constraint
    fn verify_membership(
        &self,
        field: &str,
        allowed_values: &[ConstraintValue],
        context: &HashMap<String, ConstraintValue>,
        constraint_name: &str,
        should_be_member: bool,
        start_time: std::time::Instant,
    ) -> Result<VerificationResult, VerificationError> {
        let value = context
            .get(field)
            .ok_or_else(|| VerificationError::MissingField(field.to_string()))?;

        let elapsed_us = start_time.elapsed().as_micros() as u64;

        let is_member = allowed_values.contains(value);
        let satisfied = if should_be_member {
            is_member
        } else {
            !is_member
        };

        if satisfied {
            Ok(VerificationResult::satisfied(constraint_name, elapsed_us))
        } else {
            let mut values = HashMap::new();
            values.insert(field.to_string(), value.clone());
            let explanation = if should_be_member {
                format!(
                    "{} = {} is not in the allowed set {:?}",
                    field, value, allowed_values
                )
            } else {
                format!(
                    "{} = {} is in the forbidden set {:?}",
                    field, value, allowed_values
                )
            };
            let ce = Counterexample::new(values, explanation);
            Ok(VerificationResult::violated(
                constraint_name,
                ce,
                elapsed_us,
            ))
        }
    }

    /// Verify a Forbidden resource constraint
    fn verify_forbidden(
        &self,
        resources: &[String],
        context: &HashMap<String, ConstraintValue>,
        constraint_name: &str,
        start_time: std::time::Instant,
    ) -> Result<VerificationResult, VerificationError> {
        // Check if "resource" field exists in context
        let resource = context.get("resource").and_then(|v| v.as_string());

        let elapsed_us = start_time.elapsed().as_micros() as u64;

        if let Some(res) = resource {
            if self.check_forbidden(res, resources) {
                let mut values = HashMap::new();
                values.insert("resource".to_string(), res.into());
                let ce = Counterexample::new(
                    values,
                    format!("resource '{}' matches forbidden pattern", res),
                );
                return Ok(VerificationResult::violated(
                    constraint_name,
                    ce,
                    elapsed_us,
                ));
            }
        }

        Ok(VerificationResult::satisfied(constraint_name, elapsed_us))
    }

    /// Verify a Contains constraint for strings
    fn verify_contains(
        &self,
        field: &str,
        substring: &str,
        context: &HashMap<String, ConstraintValue>,
        constraint_name: &str,
        start_time: std::time::Instant,
    ) -> Result<VerificationResult, VerificationError> {
        let value = context
            .get(field)
            .ok_or_else(|| VerificationError::MissingField(field.to_string()))?;

        let str_value = value
            .as_string()
            .ok_or_else(|| VerificationError::TypeMismatch {
                field: field.to_string(),
                expected: "string".to_string(),
                actual: value.type_name().to_string(),
            })?;

        let elapsed_us = start_time.elapsed().as_micros() as u64;

        if str_value.contains(substring) {
            Ok(VerificationResult::satisfied(constraint_name, elapsed_us))
        } else {
            let mut values = HashMap::new();
            values.insert(field.to_string(), value.clone());
            let ce = Counterexample::new(
                values,
                format!("'{}' does not contain '{}'", str_value, substring),
            );
            Ok(VerificationResult::violated(
                constraint_name,
                ce,
                elapsed_us,
            ))
        }
    }

    /// Verify a Between constraint
    fn verify_between(
        &self,
        field: &str,
        min: &ConstraintValue,
        max: &ConstraintValue,
        context: &HashMap<String, ConstraintValue>,
        constraint_name: &str,
        start_time: std::time::Instant,
    ) -> Result<VerificationResult, VerificationError> {
        let value = context
            .get(field)
            .ok_or_else(|| VerificationError::MissingField(field.to_string()))?;

        let num_value = value
            .as_float()
            .ok_or_else(|| VerificationError::TypeMismatch {
                field: field.to_string(),
                expected: "numeric".to_string(),
                actual: value.type_name().to_string(),
            })?;

        let min_val = min.as_float().ok_or_else(|| {
            VerificationError::InvalidConstraint("min must be numeric".to_string())
        })?;
        let max_val = max.as_float().ok_or_else(|| {
            VerificationError::InvalidConstraint("max must be numeric".to_string())
        })?;

        let elapsed_us = start_time.elapsed().as_micros() as u64;

        if num_value >= min_val && num_value <= max_val {
            Ok(VerificationResult::satisfied(constraint_name, elapsed_us))
        } else {
            let mut values = HashMap::new();
            values.insert(field.to_string(), value.clone());
            let ce = Counterexample::new(
                values,
                format!(
                    "{} = {} is not between {} and {}",
                    field, num_value, min_val, max_val
                ),
            );
            Ok(VerificationResult::violated(
                constraint_name,
                ce,
                elapsed_us,
            ))
        }
    }

    /// Verify a Matches constraint (regex)
    fn verify_matches(
        &self,
        field: &str,
        pattern: &str,
        context: &HashMap<String, ConstraintValue>,
        constraint_name: &str,
        start_time: std::time::Instant,
    ) -> Result<VerificationResult, VerificationError> {
        let value = context
            .get(field)
            .ok_or_else(|| VerificationError::MissingField(field.to_string()))?;

        let str_value = value
            .as_string()
            .ok_or_else(|| VerificationError::TypeMismatch {
                field: field.to_string(),
                expected: "string".to_string(),
                actual: value.type_name().to_string(),
            })?;

        let regex = Regex::new(pattern)
            .map_err(|e| VerificationError::InvalidRegex(format!("{}: {}", pattern, e)))?;

        let elapsed_us = start_time.elapsed().as_micros() as u64;

        if regex.is_match(str_value) {
            Ok(VerificationResult::satisfied(constraint_name, elapsed_us))
        } else {
            let mut values = HashMap::new();
            values.insert(field.to_string(), value.clone());
            let ce = Counterexample::new(
                values,
                format!("'{}' does not match pattern '{}'", str_value, pattern),
            );
            Ok(VerificationResult::violated(
                constraint_name,
                ce,
                elapsed_us,
            ))
        }
    }
}

impl Default for ConstraintVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl FormalVerifier for ConstraintVerifier {
    fn verify(
        &self,
        constraint: &Constraint,
        context: &HashMap<String, ConstraintValue>,
    ) -> Result<VerificationResult, VerificationError> {
        if !constraint.enabled {
            return Ok(VerificationResult::satisfied(&constraint.name, 0));
        }

        let start_time = std::time::Instant::now();

        match &constraint.kind {
            ConstraintKind::Equals { field, value } => {
                self.verify_equality(field, value, context, &constraint.name, true, start_time)
            }
            ConstraintKind::NotEquals { field, value } => {
                self.verify_equality(field, value, context, &constraint.name, false, start_time)
            }
            ConstraintKind::LessThan { field, value } => {
                let bound = value.as_float().ok_or_else(|| {
                    VerificationError::InvalidConstraint("bound must be numeric".to_string())
                })?;
                self.verify_numeric_constraint(
                    field,
                    context,
                    &constraint.name,
                    |v| v < bound,
                    |v| format!("{} = {} is not less than {}", field, v, bound),
                    start_time,
                )
            }
            ConstraintKind::LessThanOrEqual { field, value } => {
                let bound = value.as_float().ok_or_else(|| {
                    VerificationError::InvalidConstraint("bound must be numeric".to_string())
                })?;
                self.verify_numeric_constraint(
                    field,
                    context,
                    &constraint.name,
                    |v| v <= bound,
                    |v| format!("{} = {} is not less than or equal to {}", field, v, bound),
                    start_time,
                )
            }
            ConstraintKind::GreaterThan { field, value } => {
                let bound = value.as_float().ok_or_else(|| {
                    VerificationError::InvalidConstraint("bound must be numeric".to_string())
                })?;
                self.verify_numeric_constraint(
                    field,
                    context,
                    &constraint.name,
                    |v| v > bound,
                    |v| format!("{} = {} is not greater than {}", field, v, bound),
                    start_time,
                )
            }
            ConstraintKind::GreaterThanOrEqual { field, value } => {
                let bound = value.as_float().ok_or_else(|| {
                    VerificationError::InvalidConstraint("bound must be numeric".to_string())
                })?;
                self.verify_numeric_constraint(
                    field,
                    context,
                    &constraint.name,
                    |v| v >= bound,
                    |v| {
                        format!(
                            "{} = {} is not greater than or equal to {}",
                            field, v, bound
                        )
                    },
                    start_time,
                )
            }
            ConstraintKind::In { field, values } => {
                self.verify_membership(field, values, context, &constraint.name, true, start_time)
            }
            ConstraintKind::NotIn { field, values } => {
                self.verify_membership(field, values, context, &constraint.name, false, start_time)
            }
            ConstraintKind::Forbidden { resources } => {
                self.verify_forbidden(resources, context, &constraint.name, start_time)
            }
            ConstraintKind::Contains { field, value } => {
                self.verify_contains(field, value, context, &constraint.name, start_time)
            }
            ConstraintKind::Matches { field, pattern } => {
                self.verify_matches(field, pattern, context, &constraint.name, start_time)
            }
            ConstraintKind::Between { field, min, max } => {
                self.verify_between(field, min, max, context, &constraint.name, start_time)
            }
            ConstraintKind::And { constraints } => {
                // All must be satisfied
                for inner in constraints {
                    let result = self.verify(inner, context)?;
                    if result.is_violated() {
                        return Ok(VerificationResult {
                            constraint_name: constraint.name.clone(),
                            ..result
                        });
                    }
                }
                let elapsed_us = start_time.elapsed().as_micros() as u64;
                Ok(VerificationResult::satisfied(&constraint.name, elapsed_us))
            }
            ConstraintKind::Or { constraints } => {
                // At least one must be satisfied
                let mut last_violation = None;
                for inner in constraints {
                    let result = self.verify(inner, context)?;
                    if result.is_satisfied() {
                        let elapsed_us = start_time.elapsed().as_micros() as u64;
                        return Ok(VerificationResult::satisfied(&constraint.name, elapsed_us));
                    }
                    last_violation = Some(result);
                }
                // None satisfied, return the last violation
                if let Some(violation) = last_violation {
                    Ok(VerificationResult {
                        constraint_name: constraint.name.clone(),
                        ..violation
                    })
                } else {
                    let elapsed_us = start_time.elapsed().as_micros() as u64;
                    Ok(VerificationResult::satisfied(&constraint.name, elapsed_us))
                }
            }
            ConstraintKind::Not { constraint: inner } => {
                let result = self.verify(inner, context)?;
                let elapsed_us = start_time.elapsed().as_micros() as u64;
                if result.is_satisfied() {
                    let ce = Counterexample::new(
                        HashMap::new(),
                        format!(
                            "Negation failed: inner constraint '{}' was satisfied",
                            inner.name
                        ),
                    );
                    Ok(VerificationResult::violated(
                        &constraint.name,
                        ce,
                        elapsed_us,
                    ))
                } else {
                    Ok(VerificationResult::satisfied(&constraint.name, elapsed_us))
                }
            }
            ConstraintKind::Implies {
                condition,
                consequence,
            } => {
                let cond_result = self.verify(condition, context)?;
                if cond_result.is_violated() {
                    // If condition is false, implication is satisfied
                    let elapsed_us = start_time.elapsed().as_micros() as u64;
                    Ok(VerificationResult::satisfied(&constraint.name, elapsed_us))
                } else {
                    // Condition is true, check consequence
                    let cons_result = self.verify(consequence, context)?;
                    if cons_result.is_satisfied() {
                        let elapsed_us = start_time.elapsed().as_micros() as u64;
                        Ok(VerificationResult::satisfied(&constraint.name, elapsed_us))
                    } else {
                        Ok(VerificationResult {
                            constraint_name: constraint.name.clone(),
                            ..cons_result
                        })
                    }
                }
            }
        }
    }

    fn verify_all(
        &self,
        constraints: &[Constraint],
        context: &HashMap<String, ConstraintValue>,
    ) -> Result<BatchVerificationResult, VerificationError> {
        let start_time = std::time::Instant::now();
        let mut results = Vec::with_capacity(constraints.len());

        for constraint in constraints {
            results.push(self.verify(constraint, context)?);
        }

        let total_time_us = start_time.elapsed().as_micros() as u64;
        Ok(BatchVerificationResult::new(results, total_time_us))
    }

    fn check_forbidden(&self, resource: &str, forbidden_patterns: &[String]) -> bool {
        for pattern in forbidden_patterns {
            // Support glob-style patterns
            if pattern.contains('*') {
                // Convert glob to regex
                let regex_pattern = pattern.replace('.', "\\.").replace('*', ".*");
                if let Ok(re) = Regex::new(&format!("^{}$", regex_pattern)) {
                    if re.is_match(resource) {
                        return true;
                    }
                }
            } else if resource == pattern || resource.starts_with(&format!("{}/", pattern)) {
                return true;
            }
        }
        false
    }

    fn validate_constraint(&self, constraint: &Constraint) -> Result<(), VerificationError> {
        match &constraint.kind {
            ConstraintKind::LessThan { value, .. }
            | ConstraintKind::LessThanOrEqual { value, .. }
            | ConstraintKind::GreaterThan { value, .. }
            | ConstraintKind::GreaterThanOrEqual { value, .. } => {
                if value.as_float().is_none() {
                    return Err(VerificationError::InvalidConstraint(
                        "Comparison constraints require numeric values".to_string(),
                    ));
                }
            }
            ConstraintKind::Between { min, max, .. } => {
                if min.as_float().is_none() || max.as_float().is_none() {
                    return Err(VerificationError::InvalidConstraint(
                        "Between constraint requires numeric min and max".to_string(),
                    ));
                }
            }
            ConstraintKind::Matches { pattern, .. } => {
                Regex::new(pattern).map_err(|e| {
                    VerificationError::InvalidConstraint(format!("Invalid regex pattern: {}", e))
                })?;
            }
            ConstraintKind::And { constraints } | ConstraintKind::Or { constraints } => {
                for c in constraints {
                    self.validate_constraint(c)?;
                }
            }
            ConstraintKind::Not { constraint } => {
                self.validate_constraint(constraint)?;
            }
            ConstraintKind::Implies {
                condition,
                consequence,
            } => {
                self.validate_constraint(condition)?;
                self.validate_constraint(consequence)?;
            }
            _ => {}
        }
        Ok(())
    }
}

// ============================================================================
// Backward Compatibility Alias
// ============================================================================

/// Alias for `ConstraintVerifier` for backward compatibility
///
/// Note: For Z3-based verification, enable the `z3-solver` feature.
pub type Z3Verifier = ConstraintVerifier;

/// Alias for `VerifierConfig` for backward compatibility
pub type Z3Config = VerifierConfig;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_verifier() -> ConstraintVerifier {
        ConstraintVerifier::new()
    }

    #[test]
    fn test_constraint_value_creation() {
        let int_val: ConstraintValue = 42.into();
        assert_eq!(int_val.as_integer(), Some(42));

        let float_val: ConstraintValue = 3.14.into();
        assert!(float_val.as_float().is_some());

        let str_val: ConstraintValue = "hello".into();
        assert_eq!(str_val.as_string(), Some("hello"));

        let bool_val: ConstraintValue = true.into();
        assert_eq!(bool_val.as_boolean(), Some(true));
    }

    #[test]
    fn test_constraint_value_display() {
        assert_eq!(format!("{}", ConstraintValue::Integer(42)), "42");
        assert_eq!(
            format!("{}", ConstraintValue::String("test".into())),
            "\"test\""
        );
        assert_eq!(format!("{}", ConstraintValue::Boolean(true)), "true");
    }

    #[test]
    fn test_less_than_constraint_satisfied() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "max_amount",
            ConstraintKind::LessThan {
                field: "amount".to_string(),
                value: 1000.into(),
            },
        );

        let mut context = HashMap::new();
        context.insert("amount".to_string(), 500.into());

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());
    }

    #[test]
    fn test_less_than_constraint_violated() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "max_amount",
            ConstraintKind::LessThan {
                field: "amount".to_string(),
                value: 1000.into(),
            },
        );

        let mut context = HashMap::new();
        context.insert("amount".to_string(), 1500.into());

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
        assert!(result.counterexample.is_some());
    }

    #[test]
    fn test_equals_constraint_satisfied() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "status_check",
            ConstraintKind::Equals {
                field: "status".to_string(),
                value: "active".into(),
            },
        );

        let mut context = HashMap::new();
        context.insert("status".to_string(), "active".into());

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());
    }

    #[test]
    fn test_not_equals_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "not_deleted",
            ConstraintKind::NotEquals {
                field: "status".to_string(),
                value: "deleted".into(),
            },
        );

        let mut context = HashMap::new();
        context.insert("status".to_string(), "active".into());

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());
    }

    #[test]
    fn test_in_constraint_satisfied() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "valid_role",
            ConstraintKind::In {
                field: "role".to_string(),
                values: vec!["admin".into(), "user".into(), "guest".into()],
            },
        );

        let mut context = HashMap::new();
        context.insert("role".to_string(), "user".into());

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());
    }

    #[test]
    fn test_in_constraint_violated() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "valid_role",
            ConstraintKind::In {
                field: "role".to_string(),
                values: vec!["admin".into(), "user".into()],
            },
        );

        let mut context = HashMap::new();
        context.insert("role".to_string(), "hacker".into());

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_not_in_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "forbidden_action",
            ConstraintKind::NotIn {
                field: "action".to_string(),
                values: vec!["delete".into(), "destroy".into()],
            },
        );

        let mut context = HashMap::new();
        context.insert("action".to_string(), "read".into());

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());
    }

    #[test]
    fn test_forbidden_resource_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "no_secrets",
            ConstraintKind::Forbidden {
                resources: vec!["*.env".to_string(), "secrets/*".to_string()],
            },
        );

        // Safe resource
        let mut context = HashMap::new();
        context.insert("resource".to_string(), "config.json".into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        // Forbidden resource
        context.insert("resource".to_string(), "secrets/api_key".into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_between_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "valid_range",
            ConstraintKind::Between {
                field: "score".to_string(),
                min: 0.into(),
                max: 100.into(),
            },
        );

        // Within range
        let mut context = HashMap::new();
        context.insert("score".to_string(), 75.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        // Outside range
        context.insert("score".to_string(), 150.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_contains_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "has_domain",
            ConstraintKind::Contains {
                field: "email".to_string(),
                value: "@company.com".to_string(),
            },
        );

        let mut context = HashMap::new();
        context.insert("email".to_string(), "user@company.com".into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        context.insert("email".to_string(), "user@other.com".into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_and_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "combined",
            ConstraintKind::And {
                constraints: vec![
                    Constraint::new(
                        "min_amount",
                        ConstraintKind::GreaterThan {
                            field: "amount".to_string(),
                            value: 0.into(),
                        },
                    ),
                    Constraint::new(
                        "max_amount",
                        ConstraintKind::LessThan {
                            field: "amount".to_string(),
                            value: 1000.into(),
                        },
                    ),
                ],
            },
        );

        let mut context = HashMap::new();
        context.insert("amount".to_string(), 500.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        context.insert("amount".to_string(), 1500.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_or_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "any_valid",
            ConstraintKind::Or {
                constraints: vec![
                    Constraint::new(
                        "is_admin",
                        ConstraintKind::Equals {
                            field: "role".to_string(),
                            value: "admin".into(),
                        },
                    ),
                    Constraint::new(
                        "is_owner",
                        ConstraintKind::Equals {
                            field: "is_owner".to_string(),
                            value: true.into(),
                        },
                    ),
                ],
            },
        );

        let mut context = HashMap::new();
        context.insert("role".to_string(), "user".into());
        context.insert("is_owner".to_string(), true.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());
    }

    #[test]
    fn test_not_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "not_zero",
            ConstraintKind::Not {
                constraint: Box::new(Constraint::new(
                    "is_zero",
                    ConstraintKind::Equals {
                        field: "count".to_string(),
                        value: 0.into(),
                    },
                )),
            },
        );

        let mut context = HashMap::new();
        context.insert("count".to_string(), 5.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        context.insert("count".to_string(), 0.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_implies_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "admin_implies_verified",
            ConstraintKind::Implies {
                condition: Box::new(Constraint::new(
                    "is_admin",
                    ConstraintKind::Equals {
                        field: "role".to_string(),
                        value: "admin".into(),
                    },
                )),
                consequence: Box::new(Constraint::new(
                    "is_verified",
                    ConstraintKind::Equals {
                        field: "verified".to_string(),
                        value: true.into(),
                    },
                )),
            },
        );

        // Admin and verified - satisfied
        let mut context = HashMap::new();
        context.insert("role".to_string(), "admin".into());
        context.insert("verified".to_string(), true.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        // Not admin - satisfied (implication is vacuously true)
        context.insert("role".to_string(), "user".into());
        context.insert("verified".to_string(), false.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        // Admin but not verified - violated
        context.insert("role".to_string(), "admin".into());
        context.insert("verified".to_string(), false.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_disabled_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "disabled",
            ConstraintKind::Equals {
                field: "value".to_string(),
                value: "impossible".into(),
            },
        )
        .with_enabled(false);

        let context = HashMap::new();
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied()); // Disabled constraints are always satisfied
    }

    #[test]
    fn test_missing_field_error() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "check",
            ConstraintKind::Equals {
                field: "missing".to_string(),
                value: "value".into(),
            },
        );

        let context = HashMap::new();
        let result = verifier.verify(&constraint, &context);
        assert!(matches!(result, Err(VerificationError::MissingField(_))));
    }

    #[test]
    fn test_type_mismatch_error() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "numeric_check",
            ConstraintKind::LessThan {
                field: "value".to_string(),
                value: 100.into(),
            },
        );

        let mut context = HashMap::new();
        context.insert("value".to_string(), "not a number".into());

        let result = verifier.verify(&constraint, &context);
        assert!(matches!(
            result,
            Err(VerificationError::TypeMismatch { .. })
        ));
    }

    #[test]
    fn test_batch_verification() {
        let verifier = create_verifier();
        let constraints = vec![
            Constraint::new(
                "min_check",
                ConstraintKind::GreaterThan {
                    field: "amount".to_string(),
                    value: 0.into(),
                },
            ),
            Constraint::new(
                "max_check",
                ConstraintKind::LessThan {
                    field: "amount".to_string(),
                    value: 1000.into(),
                },
            ),
        ];

        let mut context = HashMap::new();
        context.insert("amount".to_string(), 500.into());

        let result = verifier.verify_all(&constraints, &context).unwrap();
        assert!(result.all_satisfied());
        assert_eq!(result.satisfied_count(), 2);
        assert_eq!(result.violated_count(), 0);
    }

    #[test]
    fn test_batch_verification_with_violations() {
        let verifier = create_verifier();
        let constraints = vec![
            Constraint::new(
                "min_check",
                ConstraintKind::GreaterThan {
                    field: "amount".to_string(),
                    value: 0.into(),
                },
            ),
            Constraint::new(
                "max_check",
                ConstraintKind::LessThan {
                    field: "amount".to_string(),
                    value: 100.into(),
                },
            ),
        ];

        let mut context = HashMap::new();
        context.insert("amount".to_string(), 500.into());

        let result = verifier.verify_all(&constraints, &context).unwrap();
        assert!(!result.all_satisfied());
        assert_eq!(result.satisfied_count(), 1);
        assert_eq!(result.violated_count(), 1);
    }

    #[test]
    fn test_check_forbidden_patterns() {
        let verifier = create_verifier();

        // Exact match
        assert!(verifier.check_forbidden("secrets/api_key", &["secrets/*".to_string()]));

        // Glob match
        assert!(verifier.check_forbidden("config.env", &["*.env".to_string()]));

        // No match
        assert!(!verifier.check_forbidden(
            "config.json",
            &["*.env".to_string(), "secrets/*".to_string()]
        ));

        // Directory prefix match
        assert!(verifier.check_forbidden("credentials/db", &["credentials".to_string()]));
    }

    #[test]
    fn test_validate_constraint() {
        let verifier = create_verifier();

        // Valid constraint
        let valid = Constraint::new(
            "valid",
            ConstraintKind::LessThan {
                field: "x".to_string(),
                value: 100.into(),
            },
        );
        assert!(verifier.validate_constraint(&valid).is_ok());

        // Invalid regex
        let invalid_regex = Constraint::new(
            "invalid",
            ConstraintKind::Matches {
                field: "x".to_string(),
                pattern: "[invalid".to_string(),
            },
        );
        assert!(verifier.validate_constraint(&invalid_regex).is_err());
    }

    #[test]
    fn test_constraint_serialization() {
        let constraint = Constraint::new(
            "test",
            ConstraintKind::LessThan {
                field: "amount".to_string(),
                value: 1000.into(),
            },
        )
        .with_description("Test constraint")
        .with_priority(200);

        let json = serde_json::to_string(&constraint).unwrap();
        let parsed: Constraint = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.priority, 200);
    }

    #[test]
    fn test_verification_result_display() {
        let result = VerificationResult::satisfied("test", 100);
        let display = format!("{}", result);
        assert!(display.contains("test"));
        assert!(display.contains("Satisfied"));
    }

    #[test]
    fn test_verifier_config_default() {
        let config = VerifierConfig::default();
        assert_eq!(config.timeout_ms, 5000);
        assert!(!config.verbose);
    }

    #[test]
    fn test_greater_than_or_equal() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "min_age",
            ConstraintKind::GreaterThanOrEqual {
                field: "age".to_string(),
                value: 18.into(),
            },
        );

        let mut context = HashMap::new();
        context.insert("age".to_string(), 18.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        context.insert("age".to_string(), 17.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_less_than_or_equal() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "max_score",
            ConstraintKind::LessThanOrEqual {
                field: "score".to_string(),
                value: 100.into(),
            },
        );

        let mut context = HashMap::new();
        context.insert("score".to_string(), 100.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        context.insert("score".to_string(), 101.into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_matches_constraint() {
        let verifier = create_verifier();
        let constraint = Constraint::new(
            "valid_email",
            ConstraintKind::Matches {
                field: "email".to_string(),
                pattern: r"^[\w.+-]+@[\w.-]+\.\w+$".to_string(),
            },
        );

        let mut context = HashMap::new();
        context.insert("email".to_string(), "user@example.com".into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());

        context.insert("email".to_string(), "not-an-email".into());
        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_violated());
    }

    #[test]
    fn test_constraint_file_parsing() {
        let yaml = r#"
version: "1.0"
description: "Test constraints"
constraints:
  - name: max_amount
    type: LESS_THAN
    field: amount
    value: 1000
    priority: 100
    enabled: true
"#;
        let file = ConstraintFile::from_yaml(yaml, "test.yaml".to_string()).unwrap();
        assert_eq!(file.version, "1.0");
        assert_eq!(file.constraints.len(), 1);
        assert_eq!(file.constraints[0].name, "max_amount");
    }

    #[test]
    fn test_enabled_constraints_sorted() {
        let file = ConstraintFile {
            version: "1.0".to_string(),
            description: None,
            constraints: vec![
                Constraint::new(
                    "low",
                    ConstraintKind::Equals {
                        field: "a".to_string(),
                        value: 1.into(),
                    },
                )
                .with_priority(10),
                Constraint::new(
                    "high",
                    ConstraintKind::Equals {
                        field: "b".to_string(),
                        value: 2.into(),
                    },
                )
                .with_priority(100),
                Constraint::new(
                    "disabled",
                    ConstraintKind::Equals {
                        field: "c".to_string(),
                        value: 3.into(),
                    },
                )
                .with_enabled(false),
            ],
        };

        let enabled = file.enabled_constraints();
        assert_eq!(enabled.len(), 2);
        assert_eq!(enabled[0].name, "high"); // Higher priority first
        assert_eq!(enabled[1].name, "low");
    }
}
