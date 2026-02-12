//! Integration tests for policy enforcement (Issue #9)
//!
//! Tests various policy scenarios and edge cases

use std::collections::HashMap;
use vak::policy::{
    ConditionOperator, PolicyCondition, PolicyContext, PolicyEffect, PolicyEngine, PolicyRule,
    RateLimitConfig,
};

/// Helper to create a test context with attributes
fn create_context_with_attrs(
    agent_id: &str,
    role: &str,
    attrs: HashMap<String, serde_json::Value>,
) -> PolicyContext {
    PolicyContext {
        agent_id: agent_id.to_string(),
        role: role.to_string(),
        attributes: attrs,
        environment: HashMap::new(),
    }
}

/// Test: ABAC with multiple conditions
#[test]
fn test_abac_multiple_conditions() {
    let mut engine = PolicyEngine::new_unlimited();
    
    engine.add_rule(PolicyRule {
        id: "admin-full-access".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![
            PolicyCondition {
                attribute: "role".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("admin"),
            },
            PolicyCondition {
                attribute: "attr.clearance".to_string(),
                operator: ConditionOperator::GreaterThan,
                value: serde_json::json!(5),
            },
        ],
        priority: 100,
        description: Some("Admins with high clearance get full access".to_string()),
    });

    // Test: Admin with high clearance - allowed
    let mut attrs = HashMap::new();
    attrs.insert("clearance".to_string(), serde_json::json!(10));
    let ctx1 = create_context_with_attrs("admin-001", "admin", attrs);
    let decision1 = engine.evaluate("secret/data.txt", "delete", &ctx1);
    assert!(decision1.allowed, "Admin with clearance should be allowed");

    // Test: Admin with low clearance - denied
    let mut attrs2 = HashMap::new();
    attrs2.insert("clearance".to_string(), serde_json::json!(3));
    let ctx2 = create_context_with_attrs("admin-002", "admin", attrs2);
    let decision2 = engine.evaluate("secret/data.txt", "delete", &ctx2);
    assert!(!decision2.allowed, "Admin with low clearance should be denied");

    // Test: Non-admin with high clearance - denied
    let mut attrs3 = HashMap::new();
    attrs3.insert("clearance".to_string(), serde_json::json!(10));
    let ctx3 = create_context_with_attrs("user-001", "user", attrs3);
    let decision3 = engine.evaluate("secret/data.txt", "delete", &ctx3);
    assert!(!decision3.allowed, "Non-admin should be denied");
}

/// Test: Pattern matching (wildcards)
#[test]
fn test_pattern_matching_wildcards() {
    let mut engine = PolicyEngine::new_unlimited();

    // Prefix wildcard: *.log
    engine.add_rule(PolicyRule {
        id: "allow-log-read".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "*.log".to_string(),
        action_pattern: "read".to_string(),
        conditions: vec![],
        priority: 1,
        description: None,
    });

    // Suffix wildcard: /tmp/*
    engine.add_rule(PolicyRule {
        id: "allow-tmp-all".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "/tmp/*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![],
        priority: 1,
        description: None,
    });

    let ctx = PolicyContext {
        agent_id: "test".to_string(),
        role: "user".to_string(),
        attributes: HashMap::new(),
        environment: HashMap::new(),
    };

    // Test suffix wildcard
    assert!(engine.evaluate("application.log", "read", &ctx).allowed);
    assert!(engine.evaluate("error.log", "read", &ctx).allowed);
    assert!(!engine.evaluate("application.txt", "read", &ctx).allowed);

    // Test prefix wildcard
    assert!(engine.evaluate("/tmp/cache.dat", "read", &ctx).allowed);
    assert!(engine.evaluate("/tmp/session/data", "write", &ctx).allowed);
    assert!(!engine.evaluate("/var/tmp/cache", "read", &ctx).allowed);
}

/// Test: Condition operators
#[test]
fn test_all_condition_operators() {
    let mut engine = PolicyEngine::new_unlimited();

    // Test Equals
    engine.add_rule(PolicyRule {
        id: "equals-test".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "equals/*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![PolicyCondition {
            attribute: "attr.team".to_string(),
            operator: ConditionOperator::Equals,
            value: serde_json::json!("alpha"),
        }],
        priority: 1,
        description: None,
    });

    // Test In
    engine.add_rule(PolicyRule {
        id: "in-test".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "in/*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![PolicyCondition {
            attribute: "attr.status".to_string(),
            operator: ConditionOperator::In,
            value: serde_json::json!(["active", "pending", "approved"]),
        }],
        priority: 1,
        description: None,
    });

    // Test LessThan
    engine.add_rule(PolicyRule {
        id: "less-than-test".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "quota/*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![PolicyCondition {
            attribute: "attr.usage".to_string(),
            operator: ConditionOperator::LessThan,
            value: serde_json::json!(100),
        }],
        priority: 1,
        description: None,
    });

    // Equals test
    let mut attrs1 = HashMap::new();
    attrs1.insert("team".to_string(), serde_json::json!("alpha"));
    let ctx1 = create_context_with_attrs("test", "user", attrs1);
    assert!(engine.evaluate("equals/resource", "read", &ctx1).allowed);

    // In test
    let mut attrs2 = HashMap::new();
    attrs2.insert("status".to_string(), serde_json::json!("pending"));
    let ctx2 = create_context_with_attrs("test", "user", attrs2);
    assert!(engine.evaluate("in/resource", "read", &ctx2).allowed);

    // LessThan test
    let mut attrs3 = HashMap::new();
    attrs3.insert("usage".to_string(), serde_json::json!(50));
    let ctx3 = create_context_with_attrs("test", "user", attrs3);
    assert!(engine.evaluate("quota/resource", "read", &ctx3).allowed);

    // LessThan test - exceeded
    let mut attrs4 = HashMap::new();
    attrs4.insert("usage".to_string(), serde_json::json!(150));
    let ctx4 = create_context_with_attrs("test", "user", attrs4);
    assert!(!engine.evaluate("quota/resource", "read", &ctx4).allowed);
}

/// Test: Deny on error (security feature)
#[test]
fn test_deny_on_error_security() {
    let mut engine = PolicyEngine::new_unlimited();

    // Rule with type mismatch in condition
    engine.add_rule(PolicyRule {
        id: "type-mismatch".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![PolicyCondition {
            attribute: "attr.name".to_string(), // String attribute
            operator: ConditionOperator::GreaterThan, // Numeric operator
            value: serde_json::json!(10), // Numeric value
        }],
        priority: 1,
        description: None,
    });

    let mut attrs = HashMap::new();
    attrs.insert("name".to_string(), serde_json::json!("Alice")); // String value
    let ctx = create_context_with_attrs("test", "user", attrs);

    let decision = engine.evaluate("resource", "action", &ctx);
    
    // Should be denied due to type mismatch error (deny on error)
    assert!(!decision.allowed);
    assert!(!decision.evaluation_errors.is_empty());
}

/// Test: Policy validation warnings
#[test]
fn test_policy_validation_warnings() {
    // Empty engine
    let engine1 = PolicyEngine::new_unlimited();
    let warnings1 = engine1.validate_config();
    assert!(!warnings1.is_empty());
    assert!(warnings1[0].contains("No policies loaded"));

    // Only deny rules
    let mut engine2 = PolicyEngine::new_unlimited();
    engine2.add_rule(PolicyRule {
        id: "deny-all".to_string(),
        effect: PolicyEffect::Deny,
        resource_pattern: "*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![],
        priority: 1,
        description: None,
    });
    let warnings2 = engine2.validate_config();
    assert!(!warnings2.is_empty());
    assert!(warnings2[0].contains("No Allow policies"));

    // Overly permissive rule
    let mut engine3 = PolicyEngine::new_unlimited();
    engine3.add_rule(PolicyRule {
        id: "allow-all".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![],
        priority: 1,
        description: None,
    });
    let warnings3 = engine3.validate_config();
    assert!(!warnings3.is_empty());
    assert!(warnings3[0].contains("overly permissive"));
}

/// Test: Rate limit configuration
#[test]
fn test_rate_limit_configuration() {
    // Default config
    let config1 = RateLimitConfig::default();
    assert_eq!(config1.per_agent_per_second, 100);
    assert_eq!(config1.burst_size, 10);
    assert!(config1.enabled);

    // Permissive config (for testing)
    let config2 = RateLimitConfig::permissive();
    assert!(!config2.enabled);

    // Custom config
    let config3 = RateLimitConfig {
        per_agent_per_second: 50,
        burst_size: 5,
        enabled: true,
    };
    let engine = PolicyEngine::with_rate_limit(config3);
    // Verify the engine was created with rate limiting (field is private, test via evaluate)
    let ctx = PolicyContext {
        agent_id: "rate-test".to_string(),
        role: "user".to_string(),
        attributes: std::collections::HashMap::new(),
        environment: std::collections::HashMap::new(),
    };
    // Rate-limited evaluation should work
    let _ = engine.evaluate_with_rate_limit("resource", "read", &ctx);
}
