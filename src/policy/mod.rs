//! ABAC (Attribute-Based Access Control) Policy Engine

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Policy effect: allow or deny
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    /// Allow the action to proceed
    Allow,
    /// Deny the action
    Deny,
}

/// Condition operator for attribute matching
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    /// Exact equality match
    Equals,
    /// Not equal comparison
    NotEquals,
    /// String contains substring
    Contains,
    /// String starts with prefix
    StartsWith,
    /// String ends with suffix
    EndsWith,
    /// Numeric greater than
    GreaterThan,
    /// Numeric less than
    LessThan,
    /// Value is in a set
    In,
}

/// A condition that must be satisfied for a rule to match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// The attribute name to check
    pub attribute: String,
    /// The comparison operator
    pub operator: ConditionOperator,
    /// The expected value to compare against
    pub value: serde_json::Value,
}

/// A single policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique identifier for this rule
    pub id: String,
    /// Whether to allow or deny when matched
    pub effect: PolicyEffect,
    /// Glob pattern for resources this rule applies to
    pub resource_pattern: String,
    /// Glob pattern for actions this rule applies to
    pub action_pattern: String,
    /// Additional conditions that must be satisfied
    #[serde(default)]
    pub conditions: Vec<PolicyCondition>,
    /// Priority for rule ordering (higher = evaluated first)
    #[serde(default)]
    pub priority: i32,
    /// Human-readable description of the rule
    #[serde(default)]
    pub description: Option<String>,
}

/// Context for policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// The agent requesting the action
    pub agent_id: String,
    /// The role of the agent
    pub role: String,
    /// Agent attributes for condition evaluation
    pub attributes: HashMap<String, serde_json::Value>,
    /// Environment attributes for condition evaluation
    pub environment: HashMap<String, serde_json::Value>,
}

/// Result of policy evaluation
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// Whether the action is allowed
    pub allowed: bool,
    /// ID of the rule that matched (if any)
    pub matched_rule: Option<String>,
    /// Human-readable explanation of the decision
    pub reason: String,
    /// Any errors that occurred during evaluation (denied on error for security)
    pub evaluation_errors: Vec<String>,
}

/// Policy rules configuration file format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// List of policy rules
    pub rules: Vec<PolicyRule>,
}

/// The ABAC Policy Engine
#[derive(Debug, Default)]
pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    /// Create a new empty policy engine
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Load rules from a YAML file
    pub fn load_rules<P: AsRef<Path>>(&mut self, path: P) -> Result<(), PolicyError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::IoError(e.to_string()))?;
        let config: PolicyConfig = serde_yaml::from_str(&content)
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;
        self.rules = config.rules;
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(())
    }

    /// Add a rule programmatically
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Evaluate a request against loaded policies
    /// 
    /// Security: Implements "deny on error" behavior - if any condition evaluation
    /// fails, the request is denied to prevent security bypasses.
    pub fn evaluate(
        &self,
        resource: &str,
        action: &str,
        context: &PolicyContext,
    ) -> PolicyDecision {
        // Default deny if no rules match
        let mut decision = PolicyDecision {
            allowed: false,
            matched_rule: None,
            reason: "No matching rule found (default deny)".to_string(),
            evaluation_errors: Vec::new(),
        };

        for rule in &self.rules {
            if self.matches_pattern(&rule.resource_pattern, resource)
                && self.matches_pattern(&rule.action_pattern, action)
            {
                // Evaluate conditions with proper error handling
                match self.evaluate_conditions_safe(&rule.conditions, context) {
                    Ok(true) => {
                        decision = PolicyDecision {
                            allowed: rule.effect == PolicyEffect::Allow,
                            matched_rule: Some(rule.id.clone()),
                            reason: format!(
                                "Matched rule '{}': {:?}",
                                rule.id, rule.effect
                            ),
                            evaluation_errors: Vec::new(),
                        };
                        break;
                    }
                    Ok(false) => {
                        // Conditions didn't match, continue to next rule
                        continue;
                    }
                    Err(errors) => {
                        // Security: Deny on error to prevent bypasses
                        decision = PolicyDecision {
                            allowed: false,
                            matched_rule: Some(rule.id.clone()),
                            reason: format!(
                                "Denied due to condition evaluation error in rule '{}' (deny on error)",
                                rule.id
                            ),
                            evaluation_errors: errors,
                        };
                        // Don't break - continue checking other rules for better error reporting
                        // but keep the denial decision
                    }
                }
            }
        }

        decision
    }

    /// Evaluate a request and return a Result for explicit error handling
    pub fn evaluate_strict(
        &self,
        resource: &str,
        action: &str,
        context: &PolicyContext,
    ) -> Result<PolicyDecision, PolicyError> {
        let decision = self.evaluate(resource, action, context);
        
        if !decision.evaluation_errors.is_empty() {
            return Err(PolicyError::ConditionEvaluationError {
                attribute: "multiple".to_string(),
                reason: decision.evaluation_errors.join("; "),
            });
        }
        
        Ok(decision)
    }

    /// Check if a pattern matches a value (supports wildcards)
    fn matches_pattern(&self, pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            return value.starts_with(prefix);
        }
        if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            return value.ends_with(suffix);
        }
        pattern == value
    }

    /// Evaluate all conditions against context with proper error propagation
    /// Returns Ok(true) if all conditions match, Ok(false) if any don't match,
    /// or Err with list of errors if evaluation fails
    fn evaluate_conditions_safe(
        &self,
        conditions: &[PolicyCondition],
        context: &PolicyContext,
    ) -> Result<bool, Vec<String>> {
        let mut errors = Vec::new();
        
        for condition in conditions {
            match self.evaluate_condition_safe(condition, context) {
                Ok(true) => continue,
                Ok(false) => return Ok(false),
                Err(e) => errors.push(e),
            }
        }
        
        if errors.is_empty() {
            Ok(true)
        } else {
            Err(errors)
        }
    }

    /// Evaluate a single condition with proper error handling
    fn evaluate_condition_safe(
        &self,
        condition: &PolicyCondition,
        context: &PolicyContext,
    ) -> Result<bool, String> {
        let attr_value = self.resolve_attribute(&condition.attribute, context);
        
        match attr_value {
            Some(value) => {
                match self.compare_values_safe(&condition.operator, &value, &condition.value) {
                    Ok(result) => Ok(result),
                    Err(e) => Err(format!(
                        "Failed to compare attribute '{}': {}",
                        condition.attribute, e
                    )),
                }
            }
            None => {
                // Missing attribute is a soft failure - condition doesn't match
                // but it's not an error (could be optional attribute)
                Ok(false)
            }
        }
    }

    /// Resolve an attribute from context
    fn resolve_attribute(
        &self,
        attribute: &str,
        context: &PolicyContext,
    ) -> Option<serde_json::Value> {
        match attribute {
            "agent_id" => Some(serde_json::Value::String(context.agent_id.clone())),
            "role" => Some(serde_json::Value::String(context.role.clone())),
            attr if attr.starts_with("attr.") => {
                let key = &attr[5..];
                context.attributes.get(key).cloned()
            }
            attr if attr.starts_with("env.") => {
                let key = &attr[4..];
                context.environment.get(key).cloned()
            }
            _ => context.attributes.get(attribute).cloned(),
        }
    }

    /// Compare values using the specified operator with proper error handling
    fn compare_values_safe(
        &self,
        operator: &ConditionOperator,
        actual: &serde_json::Value,
        expected: &serde_json::Value,
    ) -> Result<bool, String> {
        match operator {
            ConditionOperator::Equals => Ok(actual == expected),
            ConditionOperator::NotEquals => Ok(actual != expected),
            ConditionOperator::Contains => {
                match (actual.as_str(), expected.as_str()) {
                    (Some(haystack), Some(needle)) => Ok(haystack.contains(needle)),
                    (None, _) => Err("Actual value is not a string for Contains operator".to_string()),
                    (_, None) => Err("Expected value is not a string for Contains operator".to_string()),
                }
            }
            ConditionOperator::StartsWith => {
                match (actual.as_str(), expected.as_str()) {
                    (Some(s), Some(prefix)) => Ok(s.starts_with(prefix)),
                    (None, _) => Err("Actual value is not a string for StartsWith operator".to_string()),
                    (_, None) => Err("Expected value is not a string for StartsWith operator".to_string()),
                }
            }
            ConditionOperator::EndsWith => {
                match (actual.as_str(), expected.as_str()) {
                    (Some(s), Some(suffix)) => Ok(s.ends_with(suffix)),
                    (None, _) => Err("Actual value is not a string for EndsWith operator".to_string()),
                    (_, None) => Err("Expected value is not a string for EndsWith operator".to_string()),
                }
            }
            ConditionOperator::GreaterThan => {
                match (actual.as_f64(), expected.as_f64()) {
                    (Some(a), Some(b)) => Ok(a > b),
                    (None, _) => Err("Actual value is not a number for GreaterThan operator".to_string()),
                    (_, None) => Err("Expected value is not a number for GreaterThan operator".to_string()),
                }
            }
            ConditionOperator::LessThan => {
                match (actual.as_f64(), expected.as_f64()) {
                    (Some(a), Some(b)) => Ok(a < b),
                    (None, _) => Err("Actual value is not a number for LessThan operator".to_string()),
                    (_, None) => Err("Expected value is not a number for LessThan operator".to_string()),
                }
            }
            ConditionOperator::In => {
                match expected.as_array() {
                    Some(arr) => Ok(arr.contains(actual)),
                    None => Err("Expected value is not an array for In operator".to_string()),
                }
            }
        }
    }
}

/// Policy engine errors
#[derive(Debug, Clone)]
pub enum PolicyError {
    /// I/O error reading policy file
    IoError(String),
    /// Error parsing policy file
    ParseError(String),
    /// Invalid rule definition
    InvalidRule(String),
    /// Error evaluating a condition
    ConditionEvaluationError {
        /// The condition that failed
        attribute: String,
        /// The reason for the failure
        reason: String,
    },
    /// Attribute not found during evaluation
    AttributeNotFound(String),
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::IoError(e) => write!(f, "IO error: {}", e),
            PolicyError::ParseError(e) => write!(f, "Parse error: {}", e),
            PolicyError::InvalidRule(e) => write!(f, "Invalid rule: {}", e),
            PolicyError::ConditionEvaluationError { attribute, reason } => {
                write!(f, "Condition evaluation error for '{}': {}", attribute, reason)
            }
            PolicyError::AttributeNotFound(attr) => {
                write!(f, "Attribute not found: {}", attr)
            }
        }
    }
}

impl std::error::Error for PolicyError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> PolicyContext {
        let mut attributes = HashMap::new();
        attributes.insert("clearance".to_string(), serde_json::json!("secret"));
        attributes.insert("department".to_string(), serde_json::json!("engineering"));
        
        PolicyContext {
            agent_id: "agent-001".to_string(),
            role: "developer".to_string(),
            attributes,
            environment: HashMap::new(),
        }
    }

    #[test]
    fn test_allow_rule() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "allow-read".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "files/*".to_string(),
            action_pattern: "read".to_string(),
            conditions: vec![],
            priority: 1,
            description: None,
        });

        let ctx = test_context();
        let decision = engine.evaluate("files/test.txt", "read", &ctx);
        assert!(decision.allowed);
        assert!(decision.evaluation_errors.is_empty());
    }

    #[test]
    fn test_deny_rule() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "deny-delete".to_string(),
            effect: PolicyEffect::Deny,
            resource_pattern: "*".to_string(),
            action_pattern: "delete".to_string(),
            conditions: vec![],
            priority: 1,
            description: None,
        });

        let ctx = test_context();
        let decision = engine.evaluate("files/test.txt", "delete", &ctx);
        assert!(!decision.allowed);
        assert!(decision.evaluation_errors.is_empty());
    }

    #[test]
    fn test_condition_evaluation() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "allow-secret".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "classified/*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "attr.clearance".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("secret"),
            }],
            priority: 1,
            description: None,
        });

        let ctx = test_context();
        let decision = engine.evaluate("classified/doc.pdf", "read", &ctx);
        assert!(decision.allowed);
        assert!(decision.evaluation_errors.is_empty());
    }

    #[test]
    fn test_default_deny() {
        let engine = PolicyEngine::new();
        let ctx = test_context();
        let decision = engine.evaluate("anything", "anything", &ctx);
        assert!(!decision.allowed);
        assert!(decision.evaluation_errors.is_empty());
    }

    #[test]
    fn test_deny_on_type_mismatch_error() {
        // Test that condition evaluation errors result in denial (security)
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "allow-with-bad-condition".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![PolicyCondition {
                // This will cause an error because we're comparing a string with GreaterThan
                attribute: "attr.clearance".to_string(),
                operator: ConditionOperator::GreaterThan,
                value: serde_json::json!(10), // clearance is "secret", not a number
            }],
            priority: 1,
            description: None,
        });

        let ctx = test_context();
        let decision = engine.evaluate("anything", "anything", &ctx);
        // Should be denied due to condition evaluation error (deny on error)
        assert!(!decision.allowed);
        assert!(!decision.evaluation_errors.is_empty());
    }

    #[test]
    fn test_evaluate_strict_returns_error() {
        let mut engine = PolicyEngine::new();
        engine.add_rule(PolicyRule {
            id: "allow-with-bad-condition".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![PolicyCondition {
                attribute: "attr.clearance".to_string(),
                operator: ConditionOperator::GreaterThan,
                value: serde_json::json!(10),
            }],
            priority: 1,
            description: None,
        });

        let ctx = test_context();
        let result = engine.evaluate_strict("anything", "anything", &ctx);
        assert!(result.is_err());
    }
}
