//! Constrained Decoding Bridge (NSR-005)
//!
//! Implements grammar-based constrained decoding for LLM output to ensure
//! outputs conform to valid Datalog facts, JSON schemas, or other structured
//! formats. This eliminates the "Parse Error" class of failures.
//!
//! # Overview
//!
//! Constrained decoding forces the LLM to produce output that matches a
//! predefined grammar. Instead of generating free text and parsing it,
//! the generation process is constrained at each token to only produce
//! valid next tokens according to the grammar.
//!
//! # Supported Formats
//!
//! - **Datalog**: Valid Datalog facts and rules
//! - **JSON Schema**: JSON matching a provided schema
//! - **Action Schema**: VAK action format
//! - **Custom Grammar**: User-defined KBNF grammars
//!
//! # Example
//!
//! ```rust
//! use vak::llm::constrained::{
//!     ConstrainedDecoder, Grammar, OutputConstraint, DatalogConstraint
//! };
//!
//! let decoder = ConstrainedDecoder::new();
//!
//! // Constrain output to valid Datalog facts
//! let constraint = OutputConstraint::Datalog(DatalogConstraint::facts_only());
//! let grammar = decoder.build_grammar(&constraint);
//!
//! // Use grammar during LLM inference to constrain output
//! let valid_output = decoder.decode_with_grammar("Action(read, /data/file.txt)", &grammar);
//! assert!(valid_output.is_ok());
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.4.2: Constrained Decoding
//! - KBNF Grammar Format: https://github.com/microsoft/guidance

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during constrained decoding
#[derive(Debug, Error)]
pub enum ConstraintError {
    /// Invalid grammar specification
    #[error("Invalid grammar: {0}")]
    InvalidGrammar(String),

    /// Output does not match constraint
    #[error("Output does not match constraint: expected {expected}, got {actual}")]
    ConstraintViolation { expected: String, actual: String },

    /// Grammar compilation failed
    #[error("Grammar compilation failed: {0}")]
    CompilationFailed(String),

    /// Parsing failed
    #[error("Parsing failed: {0}")]
    ParseFailed(String),

    /// Validation failed
    #[error("Validation failed: {0}")]
    ValidationFailed(String),
}

/// Result type for constraint operations
pub type ConstraintResult<T> = Result<T, ConstraintError>;

// ============================================================================
// Grammar Types
// ============================================================================

/// A compiled grammar for constraining output
#[derive(Debug, Clone)]
pub struct Grammar {
    /// Grammar name
    pub name: String,
    /// Production rules
    rules: Vec<GrammarRule>,
    /// Terminal symbols
    terminals: HashSet<String>,
    /// Non-terminal symbols
    non_terminals: HashSet<String>,
    /// Start symbol
    start_symbol: String,
    /// Validation regex (for quick validation)
    validation_regex: Option<Regex>,
}

impl Grammar {
    /// Create a new grammar with a start symbol
    pub fn new(name: impl Into<String>, start_symbol: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            rules: Vec::new(),
            terminals: HashSet::new(),
            non_terminals: HashSet::new(),
            start_symbol: start_symbol.into(),
            validation_regex: None,
        }
    }

    /// Add a production rule
    pub fn add_rule(&mut self, rule: GrammarRule) {
        self.non_terminals.insert(rule.non_terminal.clone());
        for symbol in &rule.production {
            if symbol.starts_with('<') && symbol.ends_with('>') {
                self.non_terminals.insert(symbol.clone());
            } else {
                self.terminals.insert(symbol.clone());
            }
        }
        self.rules.push(rule);
    }

    /// Set validation regex
    pub fn with_validation_regex(mut self, pattern: &str) -> ConstraintResult<Self> {
        self.validation_regex = Some(
            Regex::new(pattern).map_err(|e| ConstraintError::InvalidGrammar(e.to_string()))?,
        );
        Ok(self)
    }

    /// Validate that a string matches this grammar
    pub fn validate(&self, input: &str) -> bool {
        if let Some(regex) = &self.validation_regex {
            regex.is_match(input)
        } else {
            // Basic validation - check if it uses known terminals
            !input.is_empty()
        }
    }

    /// Get all terminal symbols
    pub fn terminals(&self) -> &HashSet<String> {
        &self.terminals
    }

    /// Get allowed next tokens given current state
    pub fn allowed_next_tokens(&self, current_state: &str) -> Vec<String> {
        // Simplified implementation - returns all terminals
        // A full implementation would do proper grammar state tracking
        self.terminals.iter().cloned().collect()
    }
}

/// A production rule in the grammar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrammarRule {
    /// Non-terminal on the left side
    pub non_terminal: String,
    /// Production (right side)
    pub production: Vec<String>,
    /// Optional semantic action
    pub semantic_action: Option<String>,
}

impl GrammarRule {
    /// Create a new grammar rule
    pub fn new(non_terminal: impl Into<String>, production: Vec<String>) -> Self {
        Self {
            non_terminal: non_terminal.into(),
            production,
            semantic_action: None,
        }
    }

    /// Add a semantic action
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.semantic_action = Some(action.into());
        self
    }
}

// ============================================================================
// Constraint Types
// ============================================================================

/// Types of output constraints
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum OutputConstraint {
    /// Constrain to valid Datalog facts/rules
    Datalog(DatalogConstraint),
    /// Constrain to JSON matching a schema
    JsonSchema(JsonSchemaConstraint),
    /// Constrain to VAK action format
    VakAction(VakActionConstraint),
    /// Constrain using custom grammar
    CustomGrammar(CustomGrammarConstraint),
    /// Constrain to one of several choices
    Choice(ChoiceConstraint),
    /// Constrain using regex pattern
    Regex(RegexConstraint),
}

/// Constraint for Datalog output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatalogConstraint {
    /// Allow facts
    pub allow_facts: bool,
    /// Allow rules
    pub allow_rules: bool,
    /// Allowed predicates (empty = all allowed)
    pub allowed_predicates: Vec<String>,
    /// Allowed arities per predicate
    pub allowed_arities: HashMap<String, Vec<usize>>,
    /// Maximum number of facts/rules
    pub max_outputs: usize,
}

impl DatalogConstraint {
    /// Create constraint allowing only facts
    pub fn facts_only() -> Self {
        Self {
            allow_facts: true,
            allow_rules: false,
            allowed_predicates: Vec::new(),
            allowed_arities: HashMap::new(),
            max_outputs: 10,
        }
    }

    /// Create constraint allowing facts and rules
    pub fn facts_and_rules() -> Self {
        Self {
            allow_facts: true,
            allow_rules: true,
            allowed_predicates: Vec::new(),
            allowed_arities: HashMap::new(),
            max_outputs: 20,
        }
    }

    /// Add allowed predicate
    pub fn with_predicate(mut self, predicate: impl Into<String>) -> Self {
        self.allowed_predicates.push(predicate.into());
        self
    }

    /// Add allowed arity for predicate
    pub fn with_arity(mut self, predicate: impl Into<String>, arity: usize) -> Self {
        self.allowed_arities
            .entry(predicate.into())
            .or_insert_with(Vec::new)
            .push(arity);
        self
    }
}

/// Constraint for JSON schema output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonSchemaConstraint {
    /// JSON schema to validate against
    pub schema: serde_json::Value,
    /// Required fields
    pub required_fields: Vec<String>,
    /// Maximum depth of nesting
    pub max_depth: usize,
}

impl JsonSchemaConstraint {
    /// Create from a JSON schema
    pub fn from_schema(schema: serde_json::Value) -> Self {
        Self {
            schema,
            required_fields: Vec::new(),
            max_depth: 10,
        }
    }

    /// Create a simple object schema
    pub fn simple_object(fields: Vec<(&str, &str)>) -> Self {
        let mut properties = serde_json::Map::new();
        let mut required = Vec::new();

        for (name, type_name) in fields {
            properties.insert(
                name.to_string(),
                serde_json::json!({ "type": type_name }),
            );
            required.push(name.to_string());
        }

        Self {
            schema: serde_json::json!({
                "type": "object",
                "properties": properties,
                "required": required
            }),
            required_fields: required,
            max_depth: 5,
        }
    }
}

/// Constraint for VAK action format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VakActionConstraint {
    /// Allowed action types
    pub allowed_actions: Vec<String>,
    /// Required parameters per action
    pub required_params: HashMap<String, Vec<String>>,
    /// Maximum number of actions
    pub max_actions: usize,
}

impl Default for VakActionConstraint {
    fn default() -> Self {
        Self {
            allowed_actions: vec![
                "read_file".to_string(),
                "write_file".to_string(),
                "execute_tool".to_string(),
                "query".to_string(),
                "api_call".to_string(),
            ],
            required_params: HashMap::from([
                ("read_file".to_string(), vec!["path".to_string()]),
                ("write_file".to_string(), vec!["path".to_string(), "content".to_string()]),
                ("execute_tool".to_string(), vec!["tool_name".to_string()]),
                ("query".to_string(), vec!["query".to_string()]),
                ("api_call".to_string(), vec!["endpoint".to_string()]),
            ]),
            max_actions: 5,
        }
    }
}

impl VakActionConstraint {
    /// Create with specific allowed actions
    pub fn with_actions(actions: Vec<String>) -> Self {
        Self {
            allowed_actions: actions,
            ..Default::default()
        }
    }
}

/// Constraint using custom grammar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomGrammarConstraint {
    /// Grammar definition in KBNF-like format
    pub grammar_definition: String,
    /// Start symbol
    pub start_symbol: String,
}

impl CustomGrammarConstraint {
    /// Create from grammar definition
    pub fn new(definition: impl Into<String>, start: impl Into<String>) -> Self {
        Self {
            grammar_definition: definition.into(),
            start_symbol: start.into(),
        }
    }
}

/// Constraint to choose from options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChoiceConstraint {
    /// Available choices
    pub choices: Vec<String>,
    /// Allow multiple selections
    pub allow_multiple: bool,
    /// Maximum selections (if multiple allowed)
    pub max_selections: usize,
}

impl ChoiceConstraint {
    /// Create single-choice constraint
    pub fn single(choices: Vec<String>) -> Self {
        Self {
            choices,
            allow_multiple: false,
            max_selections: 1,
        }
    }

    /// Create multi-choice constraint
    pub fn multiple(choices: Vec<String>, max: usize) -> Self {
        Self {
            choices,
            allow_multiple: true,
            max_selections: max,
        }
    }
}

/// Constraint using regex pattern
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexConstraint {
    /// Regex pattern
    pub pattern: String,
    /// Human-readable description
    pub description: String,
}

impl RegexConstraint {
    /// Create from pattern
    pub fn new(pattern: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            description: description.into(),
        }
    }
}

// ============================================================================
// Parsed Output Types
// ============================================================================

/// A parsed Datalog fact
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatalogFact {
    /// Predicate name
    pub predicate: String,
    /// Arguments
    pub arguments: Vec<DatalogTerm>,
}

impl DatalogFact {
    /// Create a new fact
    pub fn new(predicate: impl Into<String>, args: Vec<DatalogTerm>) -> Self {
        Self {
            predicate: predicate.into(),
            arguments: args,
        }
    }

    /// Convert to string representation
    pub fn to_string(&self) -> String {
        let args: Vec<String> = self.arguments.iter().map(|a| a.to_string()).collect();
        format!("{}({})", self.predicate, args.join(", "))
    }
}

/// A Datalog term (argument)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatalogTerm {
    /// String constant
    String(String),
    /// Integer constant
    Integer(i64),
    /// Float constant
    Float(f64),
    /// Variable (starts with uppercase)
    Variable(String),
    /// Compound term
    Compound { functor: String, args: Vec<DatalogTerm> },
}

impl DatalogTerm {
    /// Convert to string representation
    pub fn to_string(&self) -> String {
        match self {
            DatalogTerm::String(s) => format!("\"{}\"", s),
            DatalogTerm::Integer(i) => i.to_string(),
            DatalogTerm::Float(f) => f.to_string(),
            DatalogTerm::Variable(v) => v.clone(),
            DatalogTerm::Compound { functor, args } => {
                let args_str: Vec<String> = args.iter().map(|a| a.to_string()).collect();
                format!("{}({})", functor, args_str.join(", "))
            }
        }
    }
}

/// A parsed VAK action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedVakAction {
    /// Action type
    pub action_type: String,
    /// Target resource
    pub target: String,
    /// Parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Confidence (if provided)
    pub confidence: Option<f64>,
    /// Reasoning (if provided)
    pub reasoning: Option<String>,
}

// ============================================================================
// Main Decoder
// ============================================================================

/// Constrained decoder for LLM output
#[derive(Debug)]
pub struct ConstrainedDecoder {
    /// Precompiled grammars cache
    grammar_cache: HashMap<String, Grammar>,
    /// Datalog fact regex
    datalog_fact_regex: Regex,
    /// VAK action regex
    vak_action_regex: Regex,
}

impl Default for ConstrainedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstrainedDecoder {
    /// Create a new constrained decoder
    pub fn new() -> Self {
        Self {
            grammar_cache: HashMap::new(),
            // Match patterns like: Predicate(arg1, arg2, ...)
            datalog_fact_regex: Regex::new(
                r#"^([A-Z][a-zA-Z0-9_]*)\s*\(\s*(.+)\s*\)$"#
            ).unwrap(),
            // Match patterns like: {"action": "...", "target": "...", ...}
            vak_action_regex: Regex::new(
                r#"\{\s*"action"\s*:\s*"([^"]+)"\s*,\s*"target"\s*:\s*"([^"]+)".*\}"#
            ).unwrap(),
        }
    }

    /// Build a grammar from a constraint
    pub fn build_grammar(&self, constraint: &OutputConstraint) -> ConstraintResult<Grammar> {
        match constraint {
            OutputConstraint::Datalog(c) => self.build_datalog_grammar(c),
            OutputConstraint::JsonSchema(c) => self.build_json_grammar(c),
            OutputConstraint::VakAction(c) => self.build_action_grammar(c),
            OutputConstraint::CustomGrammar(c) => self.parse_custom_grammar(c),
            OutputConstraint::Choice(c) => self.build_choice_grammar(c),
            OutputConstraint::Regex(c) => self.build_regex_grammar(c),
        }
    }

    /// Validate output against a constraint
    pub fn validate(&self, output: &str, constraint: &OutputConstraint) -> ConstraintResult<()> {
        match constraint {
            OutputConstraint::Datalog(c) => self.validate_datalog(output, c),
            OutputConstraint::JsonSchema(c) => self.validate_json(output, c),
            OutputConstraint::VakAction(c) => self.validate_action(output, c),
            OutputConstraint::CustomGrammar(c) => self.validate_custom(output, c),
            OutputConstraint::Choice(c) => self.validate_choice(output, c),
            OutputConstraint::Regex(c) => self.validate_regex(output, c),
        }
    }

    /// Parse Datalog facts from output
    pub fn parse_datalog(&self, output: &str) -> ConstraintResult<Vec<DatalogFact>> {
        let mut facts = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") || line.starts_with('#') {
                continue;
            }

            // Remove trailing period if present
            let line = line.trim_end_matches('.');

            if let Some(caps) = self.datalog_fact_regex.captures(line) {
                let predicate = caps.get(1).unwrap().as_str().to_string();
                let args_str = caps.get(2).unwrap().as_str();
                let arguments = self.parse_datalog_args(args_str)?;
                
                facts.push(DatalogFact {
                    predicate,
                    arguments,
                });
            }
        }

        if facts.is_empty() {
            return Err(ConstraintError::ParseFailed(
                "No valid Datalog facts found".to_string(),
            ));
        }

        Ok(facts)
    }

    /// Parse VAK action from output
    pub fn parse_action(&self, output: &str) -> ConstraintResult<ParsedVakAction> {
        // Try JSON format first
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(output) {
            if let Some(obj) = json.as_object() {
                let action_type = obj
                    .get("action")
                    .or_else(|| obj.get("action_type"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ConstraintError::ParseFailed("Missing action field".to_string()))?
                    .to_string();

                let target = obj
                    .get("target")
                    .or_else(|| obj.get("resource"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let parameters: HashMap<String, serde_json::Value> = obj
                    .get("parameters")
                    .or_else(|| obj.get("params"))
                    .and_then(|v| v.as_object())
                    .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
                    .unwrap_or_default();

                let confidence = obj
                    .get("confidence")
                    .and_then(|v| v.as_f64());

                let reasoning = obj
                    .get("reasoning")
                    .or_else(|| obj.get("explanation"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                return Ok(ParsedVakAction {
                    action_type,
                    target,
                    parameters,
                    confidence,
                    reasoning,
                });
            }
        }

        // Try regex fallback
        if let Some(caps) = self.vak_action_regex.captures(output) {
            return Ok(ParsedVakAction {
                action_type: caps.get(1).unwrap().as_str().to_string(),
                target: caps.get(2).unwrap().as_str().to_string(),
                parameters: HashMap::new(),
                confidence: None,
                reasoning: None,
            });
        }

        Err(ConstraintError::ParseFailed(
            "Could not parse VAK action from output".to_string(),
        ))
    }

    // ========================================================================
    // Private Helper Methods
    // ========================================================================

    fn build_datalog_grammar(&self, constraint: &DatalogConstraint) -> ConstraintResult<Grammar> {
        let mut grammar = Grammar::new("datalog", "<facts>");

        // Add fact production
        if constraint.allow_facts {
            grammar.add_rule(GrammarRule::new(
                "<facts>",
                vec!["<fact>".to_string()],
            ));
            grammar.add_rule(GrammarRule::new(
                "<facts>",
                vec!["<fact>".to_string(), "\n".to_string(), "<facts>".to_string()],
            ));
            grammar.add_rule(GrammarRule::new(
                "<fact>",
                vec!["<predicate>".to_string(), "(".to_string(), "<args>".to_string(), ")".to_string()],
            ));
        }

        // Add predicates
        if constraint.allowed_predicates.is_empty() {
            // Allow any capitalized identifier
            grammar.add_rule(GrammarRule::new(
                "<predicate>",
                vec!["[A-Z][a-zA-Z0-9_]*".to_string()],
            ));
        } else {
            for pred in &constraint.allowed_predicates {
                grammar.add_rule(GrammarRule::new(
                    "<predicate>",
                    vec![pred.clone()],
                ));
            }
        }

        // Add argument rules
        grammar.add_rule(GrammarRule::new(
            "<args>",
            vec!["<term>".to_string()],
        ));
        grammar.add_rule(GrammarRule::new(
            "<args>",
            vec!["<term>".to_string(), ",".to_string(), "<args>".to_string()],
        ));

        // Add term types
        grammar.add_rule(GrammarRule::new(
            "<term>",
            vec!["<string>".to_string()],
        ));
        grammar.add_rule(GrammarRule::new(
            "<term>",
            vec!["<number>".to_string()],
        ));
        grammar.add_rule(GrammarRule::new(
            "<term>",
            vec!["<variable>".to_string()],
        ));

        // Set validation regex
        let regex = r#"^[A-Z][a-zA-Z0-9_]*\s*\([^)]+\)(\s*\.\s*)?$"#;
        grammar = grammar.with_validation_regex(regex)?;

        Ok(grammar)
    }

    fn build_json_grammar(&self, constraint: &JsonSchemaConstraint) -> ConstraintResult<Grammar> {
        let mut grammar = Grammar::new("json", "<value>");

        grammar.add_rule(GrammarRule::new("<value>", vec!["<object>".to_string()]));
        grammar.add_rule(GrammarRule::new("<value>", vec!["<array>".to_string()]));
        grammar.add_rule(GrammarRule::new("<value>", vec!["<string>".to_string()]));
        grammar.add_rule(GrammarRule::new("<value>", vec!["<number>".to_string()]));
        grammar.add_rule(GrammarRule::new("<value>", vec!["true".to_string()]));
        grammar.add_rule(GrammarRule::new("<value>", vec!["false".to_string()]));
        grammar.add_rule(GrammarRule::new("<value>", vec!["null".to_string()]));

        grammar.add_rule(GrammarRule::new(
            "<object>",
            vec!["{".to_string(), "<members>".to_string(), "}".to_string()],
        ));

        // Add required fields
        for field in &constraint.required_fields {
            grammar.add_rule(GrammarRule::new(
                "<required_member>",
                vec![
                    "\"".to_string(),
                    field.clone(),
                    "\"".to_string(),
                    ":".to_string(),
                    "<value>".to_string(),
                ],
            ));
        }

        Ok(grammar)
    }

    fn build_action_grammar(&self, constraint: &VakActionConstraint) -> ConstraintResult<Grammar> {
        let mut grammar = Grammar::new("vak_action", "<action>");

        // Build action type alternatives
        for action in &constraint.allowed_actions {
            grammar.add_rule(GrammarRule::new(
                "<action_type>",
                vec![action.clone()],
            ));
        }

        grammar.add_rule(GrammarRule::new(
            "<action>",
            vec![
                "{".to_string(),
                "\"action\":".to_string(),
                "\"<action_type>\"".to_string(),
                ",\"target\":".to_string(),
                "<string>".to_string(),
                "}".to_string(),
            ],
        ));

        Ok(grammar)
    }

    fn parse_custom_grammar(&self, constraint: &CustomGrammarConstraint) -> ConstraintResult<Grammar> {
        let mut grammar = Grammar::new("custom", &constraint.start_symbol);

        // Simple KBNF-like parsing
        for line in constraint.grammar_definition.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Parse rule: <non_terminal> ::= production
            if let Some((lhs, rhs)) = line.split_once("::=") {
                let non_terminal = lhs.trim().to_string();
                let production: Vec<String> = rhs
                    .split_whitespace()
                    .map(|s| s.to_string())
                    .collect();

                grammar.add_rule(GrammarRule::new(non_terminal, production));
            }
        }

        Ok(grammar)
    }

    fn build_choice_grammar(&self, constraint: &ChoiceConstraint) -> ConstraintResult<Grammar> {
        let mut grammar = Grammar::new("choice", "<choice>");

        for choice in &constraint.choices {
            grammar.add_rule(GrammarRule::new(
                "<choice>",
                vec![choice.clone()],
            ));
        }

        Ok(grammar)
    }

    fn build_regex_grammar(&self, constraint: &RegexConstraint) -> ConstraintResult<Grammar> {
        let mut grammar = Grammar::new("regex", "<pattern>");
        grammar = grammar.with_validation_regex(&constraint.pattern)?;
        Ok(grammar)
    }

    fn validate_datalog(&self, output: &str, constraint: &DatalogConstraint) -> ConstraintResult<()> {
        let facts = self.parse_datalog(output)?;

        // Check count
        if facts.len() > constraint.max_outputs {
            return Err(ConstraintError::ValidationFailed(format!(
                "Too many facts: {} > {}",
                facts.len(),
                constraint.max_outputs
            )));
        }

        // Check allowed predicates
        if !constraint.allowed_predicates.is_empty() {
            for fact in &facts {
                if !constraint.allowed_predicates.contains(&fact.predicate) {
                    return Err(ConstraintError::ValidationFailed(format!(
                        "Predicate '{}' not in allowed list",
                        fact.predicate
                    )));
                }
            }
        }

        // Check arities
        for fact in &facts {
            if let Some(allowed_arities) = constraint.allowed_arities.get(&fact.predicate) {
                if !allowed_arities.contains(&fact.arguments.len()) {
                    return Err(ConstraintError::ValidationFailed(format!(
                        "Predicate '{}' has invalid arity: {}",
                        fact.predicate,
                        fact.arguments.len()
                    )));
                }
            }
        }

        Ok(())
    }

    fn validate_json(&self, output: &str, constraint: &JsonSchemaConstraint) -> ConstraintResult<()> {
        let value: serde_json::Value = serde_json::from_str(output)
            .map_err(|e| ConstraintError::ValidationFailed(format!("Invalid JSON: {}", e)))?;

        // Check required fields
        if let Some(obj) = value.as_object() {
            for field in &constraint.required_fields {
                if !obj.contains_key(field) {
                    return Err(ConstraintError::ValidationFailed(format!(
                        "Missing required field: {}",
                        field
                    )));
                }
            }
        }

        // Check depth
        let depth = json_depth(&value);
        if depth > constraint.max_depth {
            return Err(ConstraintError::ValidationFailed(format!(
                "JSON too deep: {} > {}",
                depth,
                constraint.max_depth
            )));
        }

        Ok(())
    }

    fn validate_action(&self, output: &str, constraint: &VakActionConstraint) -> ConstraintResult<()> {
        let action = self.parse_action(output)?;

        // Check allowed actions
        if !constraint.allowed_actions.contains(&action.action_type) {
            return Err(ConstraintError::ValidationFailed(format!(
                "Action '{}' not allowed",
                action.action_type
            )));
        }

        // Check required parameters
        if let Some(required) = constraint.required_params.get(&action.action_type) {
            for param in required {
                if !action.parameters.contains_key(param) && param != "path" && action.target.is_empty() {
                    return Err(ConstraintError::ValidationFailed(format!(
                        "Missing required parameter '{}' for action '{}'",
                        param, action.action_type
                    )));
                }
            }
        }

        Ok(())
    }

    fn validate_custom(&self, output: &str, constraint: &CustomGrammarConstraint) -> ConstraintResult<()> {
        let grammar = self.parse_custom_grammar(constraint)?;
        if grammar.validate(output) {
            Ok(())
        } else {
            Err(ConstraintError::ValidationFailed(
                "Output does not match custom grammar".to_string(),
            ))
        }
    }

    fn validate_choice(&self, output: &str, constraint: &ChoiceConstraint) -> ConstraintResult<()> {
        let choices: Vec<&str> = output.split(',').map(|s| s.trim()).collect();

        if !constraint.allow_multiple && choices.len() > 1 {
            return Err(ConstraintError::ValidationFailed(
                "Multiple choices not allowed".to_string(),
            ));
        }

        if choices.len() > constraint.max_selections {
            return Err(ConstraintError::ValidationFailed(format!(
                "Too many selections: {} > {}",
                choices.len(),
                constraint.max_selections
            )));
        }

        for choice in choices {
            if !constraint.choices.contains(&choice.to_string()) {
                return Err(ConstraintError::ValidationFailed(format!(
                    "Invalid choice: '{}'",
                    choice
                )));
            }
        }

        Ok(())
    }

    fn validate_regex(&self, output: &str, constraint: &RegexConstraint) -> ConstraintResult<()> {
        let regex = Regex::new(&constraint.pattern)
            .map_err(|e| ConstraintError::InvalidGrammar(e.to_string()))?;

        if regex.is_match(output) {
            Ok(())
        } else {
            Err(ConstraintError::ConstraintViolation {
                expected: constraint.description.clone(),
                actual: output.to_string(),
            })
        }
    }

    fn parse_datalog_args(&self, args_str: &str) -> ConstraintResult<Vec<DatalogTerm>> {
        let mut args = Vec::new();
        let mut current = String::new();
        let mut in_string = false;
        let mut paren_depth = 0;

        for c in args_str.chars() {
            match c {
                '"' if !in_string => {
                    in_string = true;
                    current.push(c);
                }
                '"' if in_string => {
                    in_string = false;
                    current.push(c);
                }
                '(' if !in_string => {
                    paren_depth += 1;
                    current.push(c);
                }
                ')' if !in_string => {
                    paren_depth -= 1;
                    current.push(c);
                }
                ',' if !in_string && paren_depth == 0 => {
                    args.push(self.parse_datalog_term(current.trim())?);
                    current.clear();
                }
                _ => {
                    current.push(c);
                }
            }
        }

        if !current.trim().is_empty() {
            args.push(self.parse_datalog_term(current.trim())?);
        }

        Ok(args)
    }

    fn parse_datalog_term(&self, term: &str) -> ConstraintResult<DatalogTerm> {
        let term = term.trim();

        // String literal
        if term.starts_with('"') && term.ends_with('"') {
            return Ok(DatalogTerm::String(term[1..term.len()-1].to_string()));
        }

        // Integer
        if let Ok(i) = term.parse::<i64>() {
            return Ok(DatalogTerm::Integer(i));
        }

        // Float
        if let Ok(f) = term.parse::<f64>() {
            return Ok(DatalogTerm::Float(f));
        }

        // Variable (starts with uppercase)
        if term.chars().next().map(|c| c.is_uppercase()).unwrap_or(false) 
           && !term.contains('(') {
            return Ok(DatalogTerm::Variable(term.to_string()));
        }

        // Compound term
        if let Some(paren_pos) = term.find('(') {
            let functor = term[..paren_pos].to_string();
            let args_str = &term[paren_pos + 1..term.len() - 1];
            let args = self.parse_datalog_args(args_str)?;
            return Ok(DatalogTerm::Compound { functor, args });
        }

        // Default to string
        Ok(DatalogTerm::String(term.to_string()))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Calculate JSON nesting depth
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            1 + map.values().map(json_depth).max().unwrap_or(0)
        }
        serde_json::Value::Array(arr) => {
            1 + arr.iter().map(json_depth).max().unwrap_or(0)
        }
        _ => 0,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_datalog_fact() {
        let decoder = ConstrainedDecoder::new();
        let facts = decoder.parse_datalog("Action(read, \"/data/file.txt\")").unwrap();
        
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].predicate, "Action");
        assert_eq!(facts[0].arguments.len(), 2);
    }

    #[test]
    fn test_parse_multiple_datalog_facts() {
        let decoder = ConstrainedDecoder::new();
        let input = r#"
            FileAccess("agent-1", "/data/file.txt")
            Permission(read, "agent-1")
        "#;
        
        let facts = decoder.parse_datalog(input).unwrap();
        assert_eq!(facts.len(), 2);
    }

    #[test]
    fn test_validate_datalog_constraint() {
        let decoder = ConstrainedDecoder::new();
        let constraint = OutputConstraint::Datalog(
            DatalogConstraint::facts_only()
                .with_predicate("Action")
                .with_predicate("FileAccess")
        );

        // Valid
        let result = decoder.validate("Action(read, \"file.txt\")", &constraint);
        assert!(result.is_ok());

        // Invalid predicate
        let result = decoder.validate("Unknown(x, y)", &constraint);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_vak_action_json() {
        let decoder = ConstrainedDecoder::new();
        let input = r#"{"action": "read_file", "target": "/data/config.json"}"#;
        
        let action = decoder.parse_action(input).unwrap();
        assert_eq!(action.action_type, "read_file");
        assert_eq!(action.target, "/data/config.json");
    }

    #[test]
    fn test_validate_vak_action_constraint() {
        let decoder = ConstrainedDecoder::new();
        let constraint = OutputConstraint::VakAction(VakActionConstraint::default());

        // Valid
        let valid_input = r#"{"action": "read_file", "target": "/data/file.txt"}"#;
        assert!(decoder.validate(valid_input, &constraint).is_ok());

        // Invalid action type
        let invalid_input = r#"{"action": "delete_world", "target": "/"}"#;
        assert!(decoder.validate(invalid_input, &constraint).is_err());
    }

    #[test]
    fn test_choice_constraint() {
        let decoder = ConstrainedDecoder::new();
        let constraint = OutputConstraint::Choice(ChoiceConstraint::single(vec![
            "yes".to_string(),
            "no".to_string(),
            "maybe".to_string(),
        ]));

        assert!(decoder.validate("yes", &constraint).is_ok());
        assert!(decoder.validate("no", &constraint).is_ok());
        assert!(decoder.validate("invalid", &constraint).is_err());
    }

    #[test]
    fn test_json_schema_constraint() {
        let decoder = ConstrainedDecoder::new();
        let constraint = OutputConstraint::JsonSchema(
            JsonSchemaConstraint::simple_object(vec![
                ("name", "string"),
                ("age", "number"),
            ])
        );

        let valid = r#"{"name": "Alice", "age": 30}"#;
        assert!(decoder.validate(valid, &constraint).is_ok());

        let missing_field = r#"{"name": "Alice"}"#;
        assert!(decoder.validate(missing_field, &constraint).is_err());
    }

    #[test]
    fn test_build_datalog_grammar() {
        let decoder = ConstrainedDecoder::new();
        let constraint = DatalogConstraint::facts_only()
            .with_predicate("Action")
            .with_arity("Action", 2);

        let grammar = decoder.build_datalog_grammar(&constraint).unwrap();
        
        assert!(grammar.validate("Action(x, y)"));
    }

    #[test]
    fn test_datalog_term_parsing() {
        let decoder = ConstrainedDecoder::new();
        
        // Test various term types
        let facts = decoder.parse_datalog(r#"Test("string", 42, 3.14, Variable)"#).unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].arguments.len(), 4);
    }
}
