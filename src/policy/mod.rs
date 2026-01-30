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
        };

        for rule in &self.rules {
            if self.matches_pattern(&rule.resource_pattern, resource)
                && self.matches_pattern(&rule.action_pattern, action)
                && self.evaluate_conditions(&rule.conditions, context)
            {
                decision = PolicyDecision {
                    allowed: rule.effect == PolicyEffect::Allow,
                    matched_rule: Some(rule.id.clone()),
                    reason: format!(
                        "Matched rule '{}': {:?}",
                        rule.id, rule.effect
                    ),
                };
                break;
            }
        }

        decision
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

    /// Evaluate all conditions against context
    fn evaluate_conditions(
        &self,
        conditions: &[PolicyCondition],
        context: &PolicyContext,
    ) -> bool {
        conditions.iter().all(|cond| self.evaluate_condition(cond, context))
    }

    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &PolicyCondition, context: &PolicyContext) -> bool {
        let attr_value = self.resolve_attribute(&condition.attribute, context);
        
        match attr_value {
            Some(value) => self.compare_values(&condition.operator, &value, &condition.value),
            None => false,
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

    /// Compare values using the specified operator
    fn compare_values(
        &self,
        operator: &ConditionOperator,
        actual: &serde_json::Value,
        expected: &serde_json::Value,
    ) -> bool {
        match operator {
            ConditionOperator::Equals => actual == expected,
            ConditionOperator::NotEquals => actual != expected,
            ConditionOperator::Contains => {
                if let (Some(haystack), Some(needle)) = (actual.as_str(), expected.as_str()) {
                    haystack.contains(needle)
                } else {
                    false
                }
            }
            ConditionOperator::StartsWith => {
                if let (Some(s), Some(prefix)) = (actual.as_str(), expected.as_str()) {
                    s.starts_with(prefix)
                } else {
                    false
                }
            }
            ConditionOperator::EndsWith => {
                if let (Some(s), Some(suffix)) = (actual.as_str(), expected.as_str()) {
                    s.ends_with(suffix)
                } else {
                    false
                }
            }
            ConditionOperator::GreaterThan => {
                if let (Some(a), Some(b)) = (actual.as_f64(), expected.as_f64()) {
                    a > b
                } else {
                    false
                }
            }
            ConditionOperator::LessThan => {
                if let (Some(a), Some(b)) = (actual.as_f64(), expected.as_f64()) {
                    a < b
                } else {
                    false
                }
            }
            ConditionOperator::In => {
                if let Some(arr) = expected.as_array() {
                    arr.contains(actual)
                } else {
                    false
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
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyError::IoError(e) => write!(f, "IO error: {}", e),
            PolicyError::ParseError(e) => write!(f, "Parse error: {}", e),
            PolicyError::InvalidRule(e) => write!(f, "Invalid rule: {}", e),
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
    }

    #[test]
    fn test_default_deny() {
        let engine = PolicyEngine::new();
        let ctx = test_context();
        let decision = engine.evaluate("anything", "anything", &ctx);
        assert!(!decision.allowed);
    }
}
