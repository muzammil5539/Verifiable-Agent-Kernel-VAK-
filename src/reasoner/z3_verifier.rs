//! Z3 SMT Solver Integration (Issue #12)
//!
//! This module provides formal verification capabilities using the Z3 SMT solver.
//! It translates constraint DSL to SMT-LIB2 and provides proof generation.
//!
//! # Features
//!
//! - Constraint translation to SMT-LIB2 format
//! - SAT/UNSAT solving for constraint verification
//! - Counterexample generation
//! - Proof explanations
//! - Integration with policy verification
//!
//! # Example
//!
//! ```rust,no_run
//! use std::collections::HashMap;
//! use vak::reasoner::z3_verifier::{Z3FormalVerifier, Z3Config};
//! use vak::reasoner::{Constraint, ConstraintKind, FormalVerifier};
//!
//! let config = Z3Config::default();
//! let verifier = Z3FormalVerifier::new(config);
//!
//! let constraint = Constraint::new("max_amount", ConstraintKind::LessThan {
//!     field: "amount".to_string(),
//!     value: 1000.into(),
//! });
//!
//! let mut context = HashMap::new();
//! context.insert("amount".to_string(), 500.into());
//!
//! let result = verifier.verify(&constraint, &context);
//! assert!(result.unwrap().is_satisfied());
//! ```

use crate::reasoner::verifier::{
    BatchVerificationResult, Constraint, ConstraintKind, ConstraintValue, Counterexample,
    FormalVerifier, VerificationError, VerificationResult,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors specific to Z3 integration
#[derive(Debug, Error)]
pub enum Z3Error {
    /// Z3 not found or not installed
    #[error("Z3 solver not found. Install with: apt install z3")]
    Z3NotFound,

    /// Z3 execution failed
    #[error("Z3 execution failed: {0}")]
    ExecutionFailed(String),

    /// Translation error
    #[error("Failed to translate constraint to SMT-LIB2: {0}")]
    TranslationError(String),

    /// Timeout
    #[error("Z3 solving timed out after {0}ms")]
    Timeout(u64),

    /// Parse error
    #[error("Failed to parse Z3 output: {0}")]
    ParseError(String),

    /// Unsupported constraint
    #[error("Unsupported constraint type for Z3: {0}")]
    UnsupportedConstraint(String),

    /// Invalid Z3 executable path
    #[error("Invalid Z3 executable path: {0}")]
    InvalidPath(String),
}

impl From<Z3Error> for VerificationError {
    fn from(e: Z3Error) -> Self {
        VerificationError::SolverError(e.to_string())
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for Z3 verifier
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Z3Config {
    /// Path to Z3 binary
    pub z3_path: String,
    /// Timeout in milliseconds
    pub timeout_ms: u64,
    /// Enable proof generation
    pub generate_proofs: bool,
    /// Enable model generation (counterexamples)
    pub generate_models: bool,
    /// Enable unsat cores
    pub unsat_cores: bool,
    /// Verbosity level
    pub verbosity: u8,
}

impl Default for Z3Config {
    fn default() -> Self {
        Self {
            z3_path: "z3".to_string(),
            timeout_ms: 5000,
            generate_proofs: true,
            generate_models: true,
            unsat_cores: true,
            verbosity: 0,
        }
    }
}

impl Z3Config {
    /// Set timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Set Z3 binary path
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.z3_path = path.into();
        self
    }

    /// Disable proof generation
    pub fn without_proofs(mut self) -> Self {
        self.generate_proofs = false;
        self
    }
}

// ============================================================================
// SMT-LIB2 Builder
// ============================================================================

/// Builder for SMT-LIB2 formulas.
///
/// The builder assembles raw SMT-LIB text and does no escaping. Pass names
/// through [`smt_symbol`] and string values through [`smt_string`] first;
/// [`Z3FormalVerifier`] does.
#[derive(Debug, Default)]
pub struct SmtLibBuilder {
    declarations: Vec<String>,
    assertions: Vec<String>,
    options: Vec<String>,
}

impl SmtLibBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Add solver option
    pub fn option(&mut self, opt: impl Into<String>) -> &mut Self {
        self.options.push(format!("(set-option {})", opt.into()));
        self
    }

    /// Declare an integer variable
    pub fn declare_int(&mut self, name: &str) -> &mut Self {
        self.declarations
            .push(format!("(declare-const {} Int)", name));
        self
    }

    /// Declare a real/float variable
    pub fn declare_real(&mut self, name: &str) -> &mut Self {
        self.declarations
            .push(format!("(declare-const {} Real)", name));
        self
    }

    /// Declare a boolean variable
    pub fn declare_bool(&mut self, name: &str) -> &mut Self {
        self.declarations
            .push(format!("(declare-const {} Bool)", name));
        self
    }

    /// Declare a string variable
    pub fn declare_string(&mut self, name: &str) -> &mut Self {
        self.declarations
            .push(format!("(declare-const {} String)", name));
        self
    }

    /// Add an assertion
    pub fn assert(&mut self, assertion: impl Into<String>) -> &mut Self {
        self.assertions
            .push(format!("(assert {})", assertion.into()));
        self
    }

    /// Add equality assertion
    pub fn assert_eq(&mut self, var: &str, value: &str) -> &mut Self {
        self.assert(format!("(= {} {})", var, value))
    }

    /// Add less-than assertion
    pub fn assert_lt(&mut self, var: &str, value: &str) -> &mut Self {
        self.assert(format!("(< {} {})", var, value))
    }

    /// Add greater-than assertion
    pub fn assert_gt(&mut self, var: &str, value: &str) -> &mut Self {
        self.assert(format!("(> {} {})", var, value))
    }

    /// Add less-than-or-equal assertion
    pub fn assert_le(&mut self, var: &str, value: &str) -> &mut Self {
        self.assert(format!("(<= {} {})", var, value))
    }

    /// Add greater-than-or-equal assertion
    pub fn assert_ge(&mut self, var: &str, value: &str) -> &mut Self {
        self.assert(format!("(>= {} {})", var, value))
    }

    /// Add NOT assertion
    pub fn assert_not(&mut self, assertion: impl Into<String>) -> &mut Self {
        self.assert(format!("(not {})", assertion.into()))
    }

    /// Add AND assertion
    pub fn assert_and(&mut self, assertions: &[&str]) -> &mut Self {
        let and_expr = format!("(and {})", assertions.join(" "));
        self.assert(and_expr)
    }

    /// Add OR assertion
    pub fn assert_or(&mut self, assertions: &[&str]) -> &mut Self {
        let or_expr = format!("(or {})", assertions.join(" "));
        self.assert(or_expr)
    }

    /// Add implication assertion
    pub fn assert_implies(&mut self, antecedent: &str, consequent: &str) -> &mut Self {
        self.assert(format!("(=> {} {})", antecedent, consequent))
    }

    /// Build the complete SMT-LIB2 script
    pub fn build(&self, check_sat: bool, get_model: bool) -> String {
        let mut script = String::new();

        // Add options
        for opt in &self.options {
            script.push_str(opt);
            script.push('\n');
        }

        // Set logic (use QF_LIA for linear integer arithmetic)
        script.push_str("(set-logic QF_LIRA)\n");

        // Add declarations
        for decl in &self.declarations {
            script.push_str(decl);
            script.push('\n');
        }

        // Add assertions
        for assertion in &self.assertions {
            script.push_str(assertion);
            script.push('\n');
        }

        // Check satisfiability
        if check_sat {
            script.push_str("(check-sat)\n");
        }

        // Get model if sat
        if get_model {
            script.push_str("(get-model)\n");
        }

        script
    }
}

// ============================================================================
// SMT-LIB2 quoting
// ============================================================================

/// SMT-LIB and theory names a field must not shadow. Fields are restricted to
/// `[A-Za-z_][A-Za-z0-9_]*`, so dotted theory functions (`str.len`, …) can't
/// collide; these are the undotted ones.
const RESERVED_SYMBOLS: &[&str] = &[
    "true", "false", "and", "or", "not", "xor", "ite", "distinct", "let", "forall", "exists",
    "match", "par", "as", "abs", "div", "mod", "to_real", "to_int", "is_int",
];

/// Validates a field name for use as an SMT-LIB symbol.
///
/// Only plain identifiers are accepted. Anything else, including names that
/// would need quoting, is rejected rather than escaped: a field name that
/// could change the structure of the script must never reach the solver.
pub fn smt_symbol(name: &str) -> Result<String, Z3Error> {
    let mut chars = name.chars();
    let valid_start = chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
    let valid_rest = chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid_start || !valid_rest || RESERVED_SYMBOLS.contains(&name) {
        return Err(Z3Error::TranslationError(format!(
            "field name {name:?} is not a plain identifier ([A-Za-z_][A-Za-z0-9_]*) or is reserved"
        )));
    }
    Ok(name.to_string())
}

/// Encodes a string as an SMT-LIB 2.6 string literal.
///
/// Printable ASCII passes through, except `"`, which is doubled as the
/// standard requires. Every other character, including `\`, is written as a
/// `\u{…}` escape, so the literal cannot end early and no escape sequence in
/// the input is reinterpreted.
pub fn smt_string(value: &str) -> Result<String, Z3Error> {
    // The SMT-LIB string theory's alphabet ends at U+2FFFF.
    const MAX_CODE_POINT: u32 = 0x2FFFF;

    let mut literal = String::with_capacity(value.len() + 2);
    literal.push('"');
    for c in value.chars() {
        match c {
            '"' => literal.push_str("\"\""),
            ' '..='~' if c != '\\' => literal.push(c),
            _ if (c as u32) <= MAX_CODE_POINT => {
                literal.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
            _ => {
                return Err(Z3Error::TranslationError(format!(
                    "character U+{:X} is outside the SMT-LIB string alphabet",
                    c as u32
                )))
            }
        }
    }
    literal.push('"');
    Ok(literal)
}

// ============================================================================
// Z3 Formal Verifier
// ============================================================================

/// Z3-based formal verifier
pub struct Z3FormalVerifier {
    config: Z3Config,
}

impl Z3FormalVerifier {
    /// Create a new Z3 verifier
    pub fn new(config: Z3Config) -> Self {
        Self { config }
    }

    /// Validates the Z3 executable path to prevent arbitrary command execution.
    fn validate_z3_path(path_str: &str) -> Result<(), Z3Error> {
        // Normalize backslashes to forward slashes for cross-platform checking
        let normalized_path_str = path_str.replace('\\', "/");
        let path = std::path::Path::new(&normalized_path_str);

        // Check for directory traversal
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(Z3Error::InvalidPath(
                "Path contains directory traversal (..)".to_string(),
            ));
        }

        // Verify the file name is strictly 'z3' or 'z3.exe'
        let file_name = path.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            Z3Error::InvalidPath("Path does not have a valid filename".to_string())
        })?;

        if file_name != "z3" && file_name != "z3.exe" {
            return Err(Z3Error::InvalidPath(format!(
                "Executable must be named 'z3' or 'z3.exe', found '{}'",
                file_name
            )));
        }

        Ok(())
    }

    /// Check if Z3 is available
    pub fn is_available(&self) -> bool {
        if Self::validate_z3_path(&self.config.z3_path).is_err() {
            return false;
        }

        Command::new(&self.config.z3_path)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Translate a constraint value to an SMT-LIB2 term.
    ///
    /// Values used to be spliced in with `format!`, so a string containing
    /// `"` could close the literal and inject arbitrary assertions, negative
    /// numbers came out as `-5` (not an SMT-LIB numeral), and a list was
    /// silently replaced by its first element.
    fn translate_value(value: &ConstraintValue) -> Result<String, Z3Error> {
        match value {
            ConstraintValue::Integer(i) if *i < 0 => Ok(format!("(- {})", i.unsigned_abs())),
            ConstraintValue::Integer(i) => Ok(i.to_string()),
            ConstraintValue::Float(f) if !f.is_finite() => Err(Z3Error::TranslationError(format!(
                "non-finite number {f} has no SMT-LIB representation"
            ))),
            ConstraintValue::Float(f) if *f < 0.0 => Ok(format!("(- {})", -f)),
            ConstraintValue::Float(f) => Ok(f.to_string()),
            ConstraintValue::String(s) => smt_string(s),
            ConstraintValue::Boolean(b) => Ok(b.to_string()),
            ConstraintValue::List(_) => Err(Z3Error::UnsupportedConstraint(
                "list values have no sound encoding here; use In/NotIn".to_string(),
            )),
        }
    }

    /// Translate a constraint to SMT-LIB2
    fn translate_constraint(
        &self,
        constraint: &Constraint,
        context: &HashMap<String, ConstraintValue>,
        builder: &mut SmtLibBuilder,
    ) -> Result<String, Z3Error> {
        // Declare context variables
        for (name, value) in context {
            let symbol = smt_symbol(name)?;
            let smt_value = Self::translate_value(value)?;
            match value {
                ConstraintValue::Integer(_) => builder.declare_int(&symbol),
                ConstraintValue::Float(_) => builder.declare_real(&symbol),
                ConstraintValue::Boolean(_) => builder.declare_bool(&symbol),
                ConstraintValue::String(_) => builder.declare_string(&symbol),
                ConstraintValue::List(_) => {
                    return Err(Z3Error::UnsupportedConstraint(
                        "list values have no sound encoding here".to_string(),
                    ))
                }
            };

            // Assert the context value
            builder.assert_eq(&symbol, &smt_value);
        }

        let value = Self::translate_value;

        // Translate constraint kind
        let assertion = match &constraint.kind {
            ConstraintKind::Equals { field, value: v } => {
                format!("(= {} {})", smt_symbol(field)?, value(v)?)
            }
            ConstraintKind::NotEquals { field, value: v } => {
                format!("(not (= {} {}))", smt_symbol(field)?, value(v)?)
            }
            ConstraintKind::LessThan { field, value: v } => {
                format!("(< {} {})", smt_symbol(field)?, value(v)?)
            }
            ConstraintKind::LessThanOrEqual { field, value: v } => {
                format!("(<= {} {})", smt_symbol(field)?, value(v)?)
            }
            ConstraintKind::GreaterThan { field, value: v } => {
                format!("(> {} {})", smt_symbol(field)?, value(v)?)
            }
            ConstraintKind::GreaterThanOrEqual { field, value: v } => {
                format!("(>= {} {})", smt_symbol(field)?, value(v)?)
            }
            ConstraintKind::In { field, values } => {
                let field = smt_symbol(field)?;
                let or_clauses = values
                    .iter()
                    .map(|v| Ok(format!("(= {} {})", field, value(v)?)))
                    .collect::<Result<Vec<_>, Z3Error>>()?;
                // `(or)` with no arguments is false: membership in nothing.
                format!("(or {})", or_clauses.join(" "))
            }
            ConstraintKind::NotIn { field, values } => {
                let field = smt_symbol(field)?;
                let and_clauses = values
                    .iter()
                    .map(|v| Ok(format!("(not (= {} {}))", field, value(v)?)))
                    .collect::<Result<Vec<_>, Z3Error>>()?;
                format!("(and {})", and_clauses.join(" "))
            }
            ConstraintKind::Contains { field, value: v } => {
                format!("(str.contains {} {})", smt_symbol(field)?, smt_string(v)?)
            }
            ConstraintKind::Matches { .. } => {
                // `str.to.re` matches its argument *literally*, so the old
                // translation turned every regex into a string equality.
                // SMT-LIB regexes are built from combinators, not PCRE syntax;
                // until there is a translator, refuse rather than answer wrong.
                return Err(Z3Error::UnsupportedConstraint(
                    "Matches: regex patterns are not translated to SMT-LIB".to_string(),
                ));
            }
            ConstraintKind::Between { field, min, max } => {
                let field = smt_symbol(field)?;
                format!(
                    "(and (>= {} {}) (<= {} {}))",
                    field,
                    value(min)?,
                    field,
                    value(max)?
                )
            }
            ConstraintKind::Forbidden { .. } => {
                // This used to translate to `true`, so `verify` reported every
                // Forbidden constraint as satisfied whatever the resource.
                // Forbidden resources are checked by `check_forbidden`.
                return Err(Z3Error::UnsupportedConstraint(
                    "Forbidden: use check_forbidden, not verify".to_string(),
                ));
            }
            ConstraintKind::And { constraints } => {
                let mut sub_assertions = Vec::new();
                for c in constraints {
                    let sub = self.translate_constraint(c, context, builder)?;
                    sub_assertions.push(sub);
                }
                format!("(and {})", sub_assertions.join(" "))
            }
            ConstraintKind::Or { constraints } => {
                let mut sub_assertions = Vec::new();
                for c in constraints {
                    let sub = self.translate_constraint(c, context, builder)?;
                    sub_assertions.push(sub);
                }
                format!("(or {})", sub_assertions.join(" "))
            }
            ConstraintKind::Not { constraint } => {
                let sub = self.translate_constraint(constraint, context, builder)?;
                format!("(not {})", sub)
            }
            ConstraintKind::Implies {
                condition,
                consequence,
            } => {
                let cond = self.translate_constraint(condition, context, builder)?;
                let cons = self.translate_constraint(consequence, context, builder)?;
                format!("(=> {} {})", cond, cons)
            }
        };

        Ok(assertion)
    }

    /// Run Z3 solver on SMT-LIB2 script
    fn run_z3(&self, script: &str) -> Result<Z3Output, Z3Error> {
        Self::validate_z3_path(&self.config.z3_path)?;

        use std::io::Write;

        // Create temp file
        let mut temp_file = tempfile::NamedTempFile::new()
            .map_err(|e| Z3Error::ExecutionFailed(format!("Failed to create temp file: {}", e)))?;

        temp_file
            .write_all(script.as_bytes())
            .map_err(|e| Z3Error::ExecutionFailed(format!("Failed to write script: {}", e)))?;

        let temp_path = temp_file.path().to_string_lossy().to_string();

        // Run Z3
        let output = Command::new(&self.config.z3_path)
            .arg("-smt2")
            .arg(&temp_path)
            .arg(format!("-T:{}", self.config.timeout_ms / 1000))
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    Z3Error::Z3NotFound
                } else {
                    Z3Error::ExecutionFailed(e.to_string())
                }
            })?;

        if !output.status.success() && !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("timeout") {
                return Err(Z3Error::Timeout(self.config.timeout_ms));
            }
        }

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        // Parse output
        let satisfiable = stdout.contains("sat") && !stdout.contains("unsat");
        let unsatisfiable = stdout.contains("unsat");

        let model = if satisfiable && stdout.contains("(model") {
            Some(self.parse_model(&stdout)?)
        } else {
            None
        };

        Ok(Z3Output {
            satisfiable,
            unsatisfiable,
            model,
            raw_output: stdout,
        })
    }

    /// Parse Z3 model output
    fn parse_model(&self, output: &str) -> Result<HashMap<String, ConstraintValue>, Z3Error> {
        let mut model = HashMap::new();

        // Simple parser for (define-fun name () Type value)
        for line in output.lines() {
            let line = line.trim();
            if line.starts_with("(define-fun") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 5 {
                    let name = parts[1].to_string();
                    let value_str = parts
                        .last()
                        .ok_or_else(|| {
                            Z3Error::ParseError("Missing value in model line".to_string())
                        })?
                        .trim_end_matches(')');

                    let value = if let Ok(i) = value_str.parse::<i64>() {
                        ConstraintValue::Integer(i)
                    } else if let Ok(f) = value_str.parse::<f64>() {
                        ConstraintValue::Float(f)
                    } else if value_str == "true" {
                        ConstraintValue::Boolean(true)
                    } else if value_str == "false" {
                        ConstraintValue::Boolean(false)
                    } else {
                        ConstraintValue::String(value_str.trim_matches('"').to_string())
                    };

                    model.insert(name, value);
                }
            }
        }

        Ok(model)
    }

    /// Generate human-readable explanation
    fn generate_explanation(
        &self,
        constraint: &Constraint,
        output: &Z3Output,
        context: &HashMap<String, ConstraintValue>,
    ) -> String {
        if output.satisfiable {
            format!(
                "Constraint '{}' is satisfied. Context values satisfy all conditions.",
                constraint.name
            )
        } else if output.unsatisfiable {
            let mut explanation = format!(
                "Constraint '{}' is NOT satisfied. The following conditions were violated:\n",
                constraint.name
            );

            // Add context info
            for (key, value) in context {
                explanation.push_str(&format!("  - {} = {:?}\n", key, value));
            }

            if let Some(ref model) = output.model {
                explanation.push_str("\nCounterexample:\n");
                for (key, value) in model {
                    explanation.push_str(&format!("  - {} = {:?}\n", key, value));
                }
            }

            explanation
        } else {
            format!(
                "Constraint '{}' verification result is unknown (solver returned neither sat nor unsat)",
                constraint.name
            )
        }
    }
}

/// Z3 solver output
#[derive(Debug)]
pub struct Z3Output {
    /// Whether the formula is satisfiable
    pub satisfiable: bool,
    /// Whether the formula is unsatisfiable
    pub unsatisfiable: bool,
    /// Model (counterexample) if satisfiable and model generation is enabled
    pub model: Option<HashMap<String, ConstraintValue>>,
    /// Raw text output from the Z3 process
    pub raw_output: String,
}

impl FormalVerifier for Z3FormalVerifier {
    fn verify(
        &self,
        constraint: &Constraint,
        context: &HashMap<String, ConstraintValue>,
    ) -> Result<VerificationResult, VerificationError> {
        use std::time::Instant;
        let start = Instant::now();

        let mut builder = SmtLibBuilder::new();

        // Translate constraint
        let assertion = self.translate_constraint(constraint, context, &mut builder)?;

        // We want to verify that the constraint holds
        // So we assert the constraint and check if it's satisfiable
        builder.assert(assertion);

        // Build and run
        let script = builder.build(true, self.config.generate_models);
        let output = self.run_z3(&script)?;

        // Generate explanation
        let explanation = self.generate_explanation(constraint, &output, context);

        let time_us = start.elapsed().as_micros() as u64;

        // Determine status and build result
        if output.satisfiable {
            Ok(VerificationResult::satisfied(
                constraint.name.clone(),
                time_us,
            ))
        } else if output.unsatisfiable {
            let counterexample = output
                .model
                .map(|model| Counterexample::new(model, explanation.clone()))
                .unwrap_or_else(|| Counterexample::new(HashMap::new(), explanation));
            Ok(VerificationResult::violated(
                constraint.name.clone(),
                counterexample,
                time_us,
            ))
        } else {
            Ok(VerificationResult::unknown(
                constraint.name.clone(),
                time_us,
            ))
        }
    }

    fn verify_all(
        &self,
        constraints: &[Constraint],
        context: &HashMap<String, ConstraintValue>,
    ) -> Result<BatchVerificationResult, VerificationError> {
        use std::time::Instant;
        let start = Instant::now();

        let mut results = Vec::new();
        for constraint in constraints {
            results.push(self.verify(constraint, context)?);
        }

        let total_time_us = start.elapsed().as_micros() as u64;

        Ok(BatchVerificationResult::new(results, total_time_us))
    }

    fn check_forbidden(&self, resource: &str, forbidden_patterns: &[String]) -> bool {
        for pattern in forbidden_patterns {
            if resource.contains(pattern) || pattern == "*" {
                return true;
            }
            // Support basic glob patterns
            if pattern.ends_with("/*") {
                let prefix = &pattern[..pattern.len() - 2];
                if resource.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }

    fn validate_constraint(&self, constraint: &Constraint) -> Result<(), VerificationError> {
        // Basic validation
        if constraint.name.is_empty() {
            return Err(VerificationError::InvalidConstraint(
                "Constraint name cannot be empty".to_string(),
            ));
        }

        // Validate constraint kind
        match &constraint.kind {
            ConstraintKind::LessThan { field, .. }
            | ConstraintKind::LessThanOrEqual { field, .. }
            | ConstraintKind::GreaterThan { field, .. }
            | ConstraintKind::GreaterThanOrEqual { field, .. }
            | ConstraintKind::Equals { field, .. }
            | ConstraintKind::NotEquals { field, .. }
            | ConstraintKind::Contains { field, .. }
            | ConstraintKind::Matches { field, .. }
            | ConstraintKind::Between { field, .. }
            | ConstraintKind::In { field, .. }
            | ConstraintKind::NotIn { field, .. } => {
                if field.is_empty() {
                    return Err(VerificationError::InvalidConstraint(format!(
                        "Constraint '{}': field name cannot be empty",
                        constraint.name
                    )));
                }
            }
            ConstraintKind::And { constraints } | ConstraintKind::Or { constraints } => {
                if constraints.is_empty() {
                    return Err(VerificationError::InvalidConstraint(format!(
                        "Constraint '{}': compound constraint cannot be empty",
                        constraint.name
                    )));
                }
                for c in constraints {
                    self.validate_constraint(c)?;
                }
            }
            ConstraintKind::Not { constraint: inner } => {
                self.validate_constraint(inner)?;
            }
            ConstraintKind::Implies {
                condition,
                consequence,
            } => {
                self.validate_constraint(condition)?;
                self.validate_constraint(consequence)?;
            }
            ConstraintKind::Forbidden { resources } => {
                if resources.is_empty() {
                    return Err(VerificationError::InvalidConstraint(format!(
                        "Constraint '{}': forbidden resources list cannot be empty",
                        constraint.name
                    )));
                }
            }
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_verifier() -> Z3FormalVerifier {
        Z3FormalVerifier::new(Z3Config::default())
    }

    #[test]
    fn test_smt_lib_builder() {
        let mut builder = SmtLibBuilder::new();
        builder.declare_int("x");
        builder.declare_int("y");
        builder.assert_lt("x", "10");
        builder.assert_gt("y", "0");

        let script = builder.build(true, false);

        assert!(script.contains("(declare-const x Int)"));
        assert!(script.contains("(declare-const y Int)"));
        assert!(script.contains("(assert (< x 10))"));
        assert!(script.contains("(check-sat)"));
    }

    #[test]
    fn test_value_translation() {
        let t = |v: ConstraintValue| Z3FormalVerifier::translate_value(&v).unwrap();
        assert_eq!(t(ConstraintValue::Integer(42)), "42");
        assert_eq!(t(ConstraintValue::Float(2.5)), "2.5");
        assert_eq!(t(ConstraintValue::Boolean(true)), "true");
        assert_eq!(t(ConstraintValue::String("hello".to_string())), "\"hello\"");
    }

    #[test]
    fn test_negative_numbers_use_smtlib_negation() {
        let t = |v: ConstraintValue| Z3FormalVerifier::translate_value(&v).unwrap();
        assert_eq!(t(ConstraintValue::Integer(-5)), "(- 5)");
        assert_eq!(
            t(ConstraintValue::Integer(i64::MIN)),
            "(- 9223372036854775808)"
        );
        assert_eq!(t(ConstraintValue::Float(-2.5)), "(- 2.5)");
        assert!(Z3FormalVerifier::translate_value(&ConstraintValue::Float(f64::NAN)).is_err());
        assert!(Z3FormalVerifier::translate_value(&ConstraintValue::Float(f64::INFINITY)).is_err());
    }

    #[test]
    fn test_string_values_cannot_escape_their_literal() {
        let payload = "x\") (assert false) (check-sat";
        let literal = smt_string(payload).unwrap();
        assert_eq!(literal, "\"x\"\") (assert false) (check-sat\"");

        // Backslashes and non-ASCII become \u{..} escapes, so an escape
        // sequence in the input is never reinterpreted by the solver.
        assert_eq!(smt_string("a\\u{41}").unwrap(), "\"a\\u{5c}u{41}\"");
        assert_eq!(smt_string("é\n").unwrap(), "\"\\u{e9}\\u{a}\"");

        // A value inside a constraint is quoted the same way.
        let verifier = create_test_verifier();
        let mut builder = SmtLibBuilder::new();
        let constraint = Constraint::new(
            "c",
            ConstraintKind::Contains {
                field: "path".to_string(),
                value: payload.to_string(),
            },
        );
        let assertion = verifier
            .translate_constraint(&constraint, &HashMap::new(), &mut builder)
            .unwrap();
        assert_eq!(
            assertion,
            "(str.contains path \"x\"\") (assert false) (check-sat\")"
        );
    }

    #[test]
    fn test_field_names_must_be_plain_identifiers() {
        assert_eq!(smt_symbol("amount").unwrap(), "amount");
        assert_eq!(smt_symbol("_tmp2").unwrap(), "_tmp2");
        for bad in [
            "",
            "2fast",
            "a b",
            "x) (assert false",
            "|quoted|",
            "str.len",
            "true",
            "and",
        ] {
            assert!(smt_symbol(bad).is_err(), "{bad:?} should be rejected");
        }

        let verifier = create_test_verifier();
        let mut builder = SmtLibBuilder::new();
        let constraint = Constraint::new(
            "c",
            ConstraintKind::LessThan {
                field: "x 0) (assert true".to_string(),
                value: ConstraintValue::Integer(1),
            },
        );
        assert!(verifier
            .translate_constraint(&constraint, &HashMap::new(), &mut builder)
            .is_err());

        // Context keys are checked too.
        let mut context = HashMap::new();
        context.insert("a) (assert false".to_string(), ConstraintValue::Integer(1));
        let ok = Constraint::new(
            "c",
            ConstraintKind::LessThan {
                field: "a".to_string(),
                value: ConstraintValue::Integer(1),
            },
        );
        assert!(verifier
            .translate_constraint(&ok, &context, &mut builder)
            .is_err());
    }

    #[test]
    fn test_untranslatable_constraints_fail_closed() {
        let verifier = create_test_verifier();
        let mut builder = SmtLibBuilder::new();
        let context = HashMap::new();
        for kind in [
            ConstraintKind::Matches {
                field: "path".to_string(),
                pattern: "^/etc/.*".to_string(),
            },
            ConstraintKind::Forbidden {
                resources: vec!["/etc/shadow".to_string()],
            },
        ] {
            let constraint = Constraint::new("c", kind);
            assert!(matches!(
                verifier.translate_constraint(&constraint, &context, &mut builder),
                Err(Z3Error::UnsupportedConstraint(_))
            ));
        }

        let mut lists = HashMap::new();
        lists.insert(
            "xs".to_string(),
            ConstraintValue::List(vec![ConstraintValue::Integer(1)]),
        );
        let constraint = Constraint::new(
            "c",
            ConstraintKind::GreaterThan {
                field: "xs".to_string(),
                value: ConstraintValue::Integer(0),
            },
        );
        assert!(verifier
            .translate_constraint(&constraint, &lists, &mut builder)
            .is_err());
    }

    #[test]
    fn test_validate_z3_path() {
        // Valid paths
        assert!(Z3FormalVerifier::validate_z3_path("z3").is_ok());
        assert!(Z3FormalVerifier::validate_z3_path("z3.exe").is_ok());
        assert!(Z3FormalVerifier::validate_z3_path("/usr/bin/z3").is_ok());
        assert!(Z3FormalVerifier::validate_z3_path("C:\\Program Files\\z3\\bin\\z3.exe").is_ok());
        assert!(Z3FormalVerifier::validate_z3_path("./z3").is_ok());

        // Invalid paths - wrong executable name
        assert!(Z3FormalVerifier::validate_z3_path("rm").is_err());
        assert!(Z3FormalVerifier::validate_z3_path("/usr/bin/python").is_err());
        assert!(Z3FormalVerifier::validate_z3_path("z3_malicious.exe").is_err());
        assert!(Z3FormalVerifier::validate_z3_path("z3.sh").is_err());

        // Invalid paths - directory traversal
        assert!(Z3FormalVerifier::validate_z3_path("../z3").is_err());
        assert!(Z3FormalVerifier::validate_z3_path("/usr/bin/../z3").is_err());
        assert!(Z3FormalVerifier::validate_z3_path("C:\\z3\\..\\z3.exe").is_err());
    }

    #[test]
    fn test_constraint_translation() {
        let verifier = create_test_verifier();
        let mut builder = SmtLibBuilder::new();
        let context = HashMap::new();

        let constraint = Constraint::new(
            "test",
            ConstraintKind::LessThan {
                field: "amount".to_string(),
                value: ConstraintValue::Integer(1000),
            },
        );

        let result = verifier.translate_constraint(&constraint, &context, &mut builder);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "(< amount 1000)");
    }

    #[test]
    fn test_and_constraint() {
        let verifier = create_test_verifier();
        let mut builder = SmtLibBuilder::new();
        let context = HashMap::new();

        let constraint = Constraint::new(
            "combined",
            ConstraintKind::And {
                constraints: vec![
                    Constraint::new(
                        "min",
                        ConstraintKind::GreaterThan {
                            field: "x".to_string(),
                            value: ConstraintValue::Integer(0),
                        },
                    ),
                    Constraint::new(
                        "max",
                        ConstraintKind::LessThan {
                            field: "x".to_string(),
                            value: ConstraintValue::Integer(100),
                        },
                    ),
                ],
            },
        );

        let result = verifier.translate_constraint(&constraint, &context, &mut builder);
        assert!(result.is_ok());
        let assertion = result.unwrap();
        assert!(assertion.contains("and"));
        assert!(assertion.contains("(> x 0)"));
        assert!(assertion.contains("(< x 100)"));
    }

    // Integration tests (require Z3 to be installed)
    #[tokio::test]
    #[ignore = "Requires Z3 installation"]
    async fn test_z3_simple_verification() {
        let verifier = create_test_verifier();

        if !verifier.is_available() {
            println!("Z3 not available, skipping test");
            return;
        }

        let constraint = Constraint::new(
            "amount_check",
            ConstraintKind::LessThan {
                field: "amount".to_string(),
                value: ConstraintValue::Integer(1000),
            },
        );

        let mut context = HashMap::new();
        context.insert("amount".to_string(), ConstraintValue::Integer(500));

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(result.is_satisfied());
    }

    #[tokio::test]
    #[ignore = "Requires Z3 installation"]
    async fn test_z3_failing_constraint() {
        let verifier = create_test_verifier();

        if !verifier.is_available() {
            println!("Z3 not available, skipping test");
            return;
        }

        let constraint = Constraint::new(
            "amount_check",
            ConstraintKind::LessThan {
                field: "amount".to_string(),
                value: ConstraintValue::Integer(1000),
            },
        );

        let mut context = HashMap::new();
        context.insert("amount".to_string(), ConstraintValue::Integer(1500));

        let result = verifier.verify(&constraint, &context).unwrap();
        assert!(!result.is_satisfied());
    }
}
