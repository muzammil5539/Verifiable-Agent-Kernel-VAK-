//! Constrained Decoding Bridge (NSR-005)
//!
//! Provides grammar-based constraints for LLM output to eliminate parse errors.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use regex::Regex;

#[derive(Debug, Error)]
pub enum ConstraintError {
    #[error("Grammar violation: {0}")]
    GrammarViolation(String),
    #[error("Schema validation failed: {0}")]
    SchemaValidation(String),
    #[error("Datalog syntax error: {0}")]
    DatalogSyntax(String),
    #[error("Pattern match failed: {0}")]
    PatternMismatch(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type ConstraintResult<T> = Result<T, ConstraintError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GrammarType {
    JsonSchema,
    Datalog,
    Regex,
    Enum,
    FreeText,
    Composite,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarRule {
    pub name: String,
    pub rule_type: GrammarType,
    pub definition: serde_json::Value,
    pub required: bool,
    pub error_message: Option<String>,
}

impl GrammarRule {
    pub fn json_schema(name: impl Into<String>, schema: serde_json::Value) -> Self {
        Self { name: name.into(), rule_type: GrammarType::JsonSchema, definition: schema, required: true, error_message: None }
    }

    pub fn datalog(name: impl Into<String>) -> Self {
        Self { name: name.into(), rule_type: GrammarType::Datalog, definition: serde_json::json!({}), required: true, error_message: None }
    }

    pub fn regex(name: impl Into<String>, pattern: impl Into<String>) -> Self {
        Self { name: name.into(), rule_type: GrammarType::Regex, definition: serde_json::json!({ "pattern": pattern.into() }), required: true, error_message: None }
    }

    pub fn enum_values(name: impl Into<String>, values: Vec<String>) -> Self {
        Self { name: name.into(), rule_type: GrammarType::Enum, definition: serde_json::json!({ "values": values }), required: true, error_message: None }
    }

    pub fn optional(mut self) -> Self { self.required = false; self }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputGrammar {
    pub name: String,
    pub rules: Vec<GrammarRule>,
    pub allow_additional: bool,
    pub attempt_repair: bool,
}

impl OutputGrammar {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into(), rules: Vec::new(), allow_additional: false, attempt_repair: true }
    }

    pub fn json_schema(name: impl Into<String>, schema: serde_json::Value) -> Self {
        let mut g = Self::new(name);
        g.rules.push(GrammarRule::json_schema("schema", schema));
        g
    }

    pub fn datalog(name: impl Into<String>) -> Self {
        let mut g = Self::new(name);
        g.rules.push(GrammarRule::datalog("datalog"));
        g
    }

    pub fn with_rule(mut self, rule: GrammarRule) -> Self { self.rules.push(rule); self }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub parsed_value: Option<serde_json::Value>,
    pub errors: Vec<ValidationError>,
    pub suggestions: Vec<RepairSuggestion>,
    pub confidence: f64,
}

impl ValidationResult {
    pub fn success(value: serde_json::Value) -> Self {
        Self { valid: true, parsed_value: Some(value), errors: Vec::new(), suggestions: Vec::new(), confidence: 1.0 }
    }

    pub fn failure(errors: Vec<ValidationError>) -> Self {
        Self { valid: false, parsed_value: None, errors, suggestions: Vec::new(), confidence: 0.0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub rule_name: String,
    pub message: String,
    pub location: Option<String>,
    pub severity: ErrorSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity { Info, Warning, Error, Critical }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairSuggestion {
    pub repair_type: RepairType,
    pub description: String,
    pub suggested_fix: Option<String>,
    pub confidence: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RepairType { AddField, RemoveField, ChangeType, FixSyntax, WrapStructure, ExtractSubstring }

pub struct ConstrainedDecoder {
    grammar: OutputGrammar,
    compiled_patterns: HashMap<String, Regex>,
}

impl ConstrainedDecoder {
    pub fn new(grammar: OutputGrammar) -> ConstraintResult<Self> {
        let mut compiled_patterns = HashMap::new();
        for rule in &grammar.rules {
            if matches!(rule.rule_type, GrammarType::Regex) {
                if let Some(pattern) = rule.definition.get("pattern").and_then(|p| p.as_str()) {
                    let regex = Regex::new(pattern).map_err(|e| ConstraintError::InvalidConfig(format!("Invalid regex: {}", e)))?;
                    compiled_patterns.insert(rule.name.clone(), regex);
                }
            }
        }
        Ok(Self { grammar, compiled_patterns })
    }

    pub fn validate(&self, output: &str) -> ValidationResult {
        let mut errors = Vec::new();
        let mut parsed_value = None;
        let mut confidence: f64 = 1.0;

        for rule in &self.grammar.rules {
            match self.validate_rule(rule, output) {
                Ok(value) => { if parsed_value.is_none() { parsed_value = value; } }
                Err(err) => {
                    let severity = if rule.required { confidence -= 0.2; ErrorSeverity::Error } else { confidence -= 0.05; ErrorSeverity::Warning };
                    errors.push(ValidationError { rule_name: rule.name.clone(), message: rule.error_message.clone().unwrap_or_else(|| err.to_string()), location: None, severity });
                }
            }
        }

        let valid = errors.iter().all(|e| e.severity != ErrorSeverity::Error && e.severity != ErrorSeverity::Critical);
        let mut result = ValidationResult { valid, parsed_value, errors, suggestions: Vec::new(), confidence: confidence.max(0.0) };
        if !valid && self.grammar.attempt_repair { result.suggestions = self.generate_suggestions(output); }
        result
    }

    fn validate_rule(&self, rule: &GrammarRule, output: &str) -> ConstraintResult<Option<serde_json::Value>> {
        match &rule.rule_type {
            GrammarType::JsonSchema => self.validate_json_schema(rule, output),
            GrammarType::Datalog => self.validate_datalog(output),
            GrammarType::Regex => self.validate_regex(rule, output),
            GrammarType::Enum => self.validate_enum(rule, output),
            GrammarType::FreeText => Ok(Some(serde_json::Value::String(output.to_string()))),
            GrammarType::Composite => Ok(None),
        }
    }

    fn validate_json_schema(&self, rule: &GrammarRule, output: &str) -> ConstraintResult<Option<serde_json::Value>> {
        let value: serde_json::Value = serde_json::from_str(output).map_err(|e| ConstraintError::SchemaValidation(format!("Invalid JSON: {}", e)))?;
        let schema = &rule.definition;

        if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
            let actual_type = match &value {
                serde_json::Value::Object(_) => "object",
                serde_json::Value::Array(_) => "array",
                serde_json::Value::String(_) => "string",
                serde_json::Value::Number(_) => "number",
                serde_json::Value::Bool(_) => "boolean",
                serde_json::Value::Null => "null",
            };
            if actual_type != expected_type {
                return Err(ConstraintError::SchemaValidation(format!("Expected '{}', got '{}'", expected_type, actual_type)));
            }
        }

        if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
            if let serde_json::Value::Object(obj) = &value {
                for req in required {
                    if let Some(prop) = req.as_str() {
                        if !obj.contains_key(prop) {
                            return Err(ConstraintError::SchemaValidation(format!("Missing required property: {}", prop)));
                        }
                    }
                }
            }
        }
        Ok(Some(value))
    }

    fn validate_datalog(&self, output: &str) -> ConstraintResult<Option<serde_json::Value>> {
        let fact_pattern = Regex::new(r"^[A-Z][a-zA-Z0-9_]*\([^)]*\)\.?$").unwrap();
        let rule_pattern = Regex::new(r"^[A-Z][a-zA-Z0-9_]*\([^)]*\)\s*:-\s*.+\.$").unwrap();
        let lines: Vec<&str> = output.trim().lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
        let mut facts = Vec::new();
        for line in lines {
            if fact_pattern.is_match(line) || rule_pattern.is_match(line) {
                facts.push(serde_json::Value::String(line.to_string()));
            } else {
                return Err(ConstraintError::DatalogSyntax(format!("Invalid Datalog: {}", line)));
            }
        }
        if facts.is_empty() { return Err(ConstraintError::DatalogSyntax("No valid Datalog facts".to_string())); }
        Ok(Some(serde_json::Value::Array(facts)))
    }

    fn validate_regex(&self, rule: &GrammarRule, output: &str) -> ConstraintResult<Option<serde_json::Value>> {
        let regex = self.compiled_patterns.get(&rule.name).ok_or_else(|| ConstraintError::InvalidConfig("Pattern not compiled".to_string()))?;
        if regex.is_match(output) { Ok(Some(serde_json::Value::String(output.to_string()))) }
        else { Err(ConstraintError::PatternMismatch(format!("Doesn't match pattern for '{}'", rule.name))) }
    }

    fn validate_enum(&self, rule: &GrammarRule, output: &str) -> ConstraintResult<Option<serde_json::Value>> {
        let values = rule.definition.get("values").and_then(|v| v.as_array()).ok_or_else(|| ConstraintError::InvalidConfig("Enum values not specified".to_string()))?;
        let trimmed = output.trim();
        for value in values {
            if value.as_str() == Some(trimmed) { return Ok(Some(serde_json::Value::String(trimmed.to_string()))); }
        }
        Err(ConstraintError::GrammarViolation(format!("'{}' not in enum", trimmed)))
    }

    fn generate_suggestions(&self, output: &str) -> Vec<RepairSuggestion> {
        let mut suggestions = Vec::new();
        let trimmed = output.trim();
        
        if (trimmed.starts_with('{') || trimmed.starts_with('[')) && serde_json::from_str::<serde_json::Value>(trimmed).is_err() {
            suggestions.push(RepairSuggestion { repair_type: RepairType::FixSyntax, description: "JSON has syntax errors".to_string(), suggested_fix: Some("Check quotes, commas, brackets".to_string()), confidence: 0.8 });
        }
        
        if let Some(start) = trimmed.find('{') {
            if let Some(end) = trimmed.rfind('}') {
                if end > start {
                    let potential = &trimmed[start..=end];
                    if serde_json::from_str::<serde_json::Value>(potential).is_ok() {
                        suggestions.push(RepairSuggestion { repair_type: RepairType::ExtractSubstring, description: "JSON embedded in text".to_string(), suggested_fix: Some(format!("Extract: {}", potential)), confidence: 0.9 });
                    }
                }
            }
        }
        suggestions
    }

    pub fn repair(&self, output: &str) -> Option<String> {
        let trimmed = output.trim();
        if let Some(start) = trimmed.find('{') {
            if let Some(end) = trimmed.rfind('}') {
                if end > start {
                    let potential = &trimmed[start..=end];
                    if serde_json::from_str::<serde_json::Value>(potential).is_ok() {
                        return Some(potential.to_string());
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_validation() {
        let grammar = OutputGrammar::json_schema("test", serde_json::json!({"type": "object", "required": ["action"]}));
        let decoder = ConstrainedDecoder::new(grammar).unwrap();
        assert!(decoder.validate(r#"{"action": "read"}"#).valid);
        assert!(!decoder.validate(r#"{}"#).valid);
    }

    #[test]
    fn test_datalog_validation() {
        let grammar = OutputGrammar::datalog("test");
        let decoder = ConstrainedDecoder::new(grammar).unwrap();
        assert!(decoder.validate("FileAccess(agent, \"/file\").").valid);
        assert!(!decoder.validate("invalid syntax").valid);
    }

    #[test]
    fn test_enum_validation() {
        let grammar = OutputGrammar::new("test").with_rule(GrammarRule::enum_values("status", vec!["ok".to_string(), "error".to_string()]));
        let decoder = ConstrainedDecoder::new(grammar).unwrap();
        assert!(decoder.validate("ok").valid);
        assert!(!decoder.validate("unknown").valid);
    }
}
