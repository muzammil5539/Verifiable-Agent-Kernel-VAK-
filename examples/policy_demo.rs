//! # Policy Evaluation Demo
//!
//! This example demonstrates the ABAC (Attribute-Based Access Control) policy engine:
//! - Loading policy rules from configuration
//! - Creating policy contexts with different attributes
//! - Evaluating allow/deny decisions
//! - Using conditions for fine-grained access control
//!
//! Run with: `cargo run --example policy_demo`

use std::collections::HashMap;

// Import policy types from the VAK policy module
use vak::policy::{
    PolicyEngine, PolicyRule, PolicyEffect, PolicyCondition, 
    ConditionOperator, PolicyContext, PolicyConfig, PolicyDecision,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== VAK Policy Engine Demo ===\n");

    // =========================================================================
    // Part 1: Create and Configure the Policy Engine
    // =========================================================================
    
    println!("Part 1: Setting up the Policy Engine\n");
    
    let mut engine = PolicyEngine::new();
    
    // -------------------------------------------------------------------------
    // Rule 1: Allow admins to access any resource
    // -------------------------------------------------------------------------
    // This is a high-priority rule that grants full access to administrators
    
    let admin_rule = PolicyRule {
        id: "admin-full-access".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "*".to_string(),        // Match any resource
        action_pattern: "*".to_string(),          // Match any action
        conditions: vec![
            PolicyCondition {
                attribute: "role".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("admin"),
            },
        ],
        priority: 100,  // High priority - evaluated first
        description: Some("Administrators have unrestricted access".to_string()),
    };
    engine.add_rule(admin_rule);
    println!("✓ Added rule: admin-full-access (priority: 100)");
    
    // -------------------------------------------------------------------------
    // Rule 2: Allow users to read public resources
    // -------------------------------------------------------------------------
    
    let public_read_rule = PolicyRule {
        id: "public-read".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "public/*".to_string(),  // Only public resources
        action_pattern: "read".to_string(),        // Only read actions
        conditions: vec![],                        // No additional conditions
        priority: 50,
        description: Some("Anyone can read public resources".to_string()),
    };
    engine.add_rule(public_read_rule);
    println!("✓ Added rule: public-read (priority: 50)");
    
    // -------------------------------------------------------------------------
    // Rule 3: Allow analysts to access data resources during business hours
    // -------------------------------------------------------------------------
    // This demonstrates ABAC with environment-based conditions
    
    let analyst_rule = PolicyRule {
        id: "analyst-data-access".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "data/*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![
            PolicyCondition {
                attribute: "role".to_string(),
                operator: ConditionOperator::Equals,
                value: serde_json::json!("analyst"),
            },
            PolicyCondition {
                attribute: "attr.department".to_string(),
                operator: ConditionOperator::In,
                value: serde_json::json!(["analytics", "research", "data-science"]),
            },
        ],
        priority: 60,
        description: Some("Analysts can access data resources".to_string()),
    };
    engine.add_rule(analyst_rule);
    println!("✓ Added rule: analyst-data-access (priority: 60)");
    
    // -------------------------------------------------------------------------
    // Rule 4: Deny access to sensitive resources by default
    // -------------------------------------------------------------------------
    
    let sensitive_deny_rule = PolicyRule {
        id: "sensitive-deny-default".to_string(),
        effect: PolicyEffect::Deny,
        resource_pattern: "sensitive/*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![],
        priority: 10,  // Low priority - acts as fallback
        description: Some("Deny access to sensitive resources by default".to_string()),
    };
    engine.add_rule(sensitive_deny_rule);
    println!("✓ Added rule: sensitive-deny-default (priority: 10)");
    
    // -------------------------------------------------------------------------
    // Rule 5: Allow security team to access sensitive resources
    // -------------------------------------------------------------------------
    
    let security_sensitive_rule = PolicyRule {
        id: "security-sensitive-access".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "sensitive/*".to_string(),
        action_pattern: "*".to_string(),
        conditions: vec![
            PolicyCondition {
                attribute: "attr.clearance_level".to_string(),
                operator: ConditionOperator::GreaterThan,
                value: serde_json::json!(3),
            },
        ],
        priority: 70,
        description: Some("High-clearance users can access sensitive resources".to_string()),
    };
    engine.add_rule(security_sensitive_rule);
    println!("✓ Added rule: security-sensitive-access (priority: 70)\n");

    // =========================================================================
    // Part 2: Create Different Policy Contexts
    // =========================================================================
    
    println!("Part 2: Creating Policy Contexts\n");
    
    // Context for an admin user
    let admin_context = PolicyContext {
        agent_id: "admin-agent-001".to_string(),
        role: "admin".to_string(),
        attributes: HashMap::from([
            ("department".to_string(), serde_json::json!("it")),
            ("clearance_level".to_string(), serde_json::json!(5)),
        ]),
        environment: HashMap::from([
            ("time_of_day".to_string(), serde_json::json!("business_hours")),
            ("ip_range".to_string(), serde_json::json!("internal")),
        ]),
    };
    println!("✓ Created context: Admin (role=admin, clearance=5)");
    
    // Context for an analyst user
    let analyst_context = PolicyContext {
        agent_id: "analyst-agent-042".to_string(),
        role: "analyst".to_string(),
        attributes: HashMap::from([
            ("department".to_string(), serde_json::json!("analytics")),
            ("clearance_level".to_string(), serde_json::json!(2)),
        ]),
        environment: HashMap::from([
            ("time_of_day".to_string(), serde_json::json!("business_hours")),
        ]),
    };
    println!("✓ Created context: Analyst (role=analyst, dept=analytics, clearance=2)");
    
    // Context for a regular user
    let user_context = PolicyContext {
        agent_id: "user-agent-123".to_string(),
        role: "user".to_string(),
        attributes: HashMap::from([
            ("department".to_string(), serde_json::json!("sales")),
            ("clearance_level".to_string(), serde_json::json!(1)),
        ]),
        environment: HashMap::new(),
    };
    println!("✓ Created context: User (role=user, dept=sales, clearance=1)");
    
    // Context for a security team member
    let security_context = PolicyContext {
        agent_id: "security-agent-007".to_string(),
        role: "security".to_string(),
        attributes: HashMap::from([
            ("department".to_string(), serde_json::json!("security")),
            ("clearance_level".to_string(), serde_json::json!(4)),
        ]),
        environment: HashMap::new(),
    };
    println!("✓ Created context: Security (role=security, clearance=4)\n");

    // =========================================================================
    // Part 3: Evaluate Policies with Different Contexts
    // =========================================================================
    
    println!("Part 3: Policy Evaluation Results\n");
    println!("{:-<70}", "");
    
    // Test cases demonstrating various scenarios
    let test_cases = vec![
        // (resource, action, context, description)
        ("public/docs/readme.txt", "read", &admin_context, "Admin reading public doc"),
        ("public/docs/readme.txt", "read", &user_context, "User reading public doc"),
        ("data/analytics/report.csv", "read", &analyst_context, "Analyst reading analytics data"),
        ("data/analytics/report.csv", "read", &user_context, "User reading analytics data"),
        ("data/analytics/report.csv", "write", &analyst_context, "Analyst writing analytics data"),
        ("sensitive/credentials/api-keys.json", "read", &user_context, "User accessing sensitive data"),
        ("sensitive/credentials/api-keys.json", "read", &security_context, "Security team accessing sensitive data"),
        ("sensitive/audit/logs.json", "read", &admin_context, "Admin accessing sensitive audit logs"),
        ("private/user-data/profile.json", "delete", &user_context, "User deleting private data"),
        ("private/user-data/profile.json", "delete", &admin_context, "Admin deleting private data"),
    ];
    
    for (resource, action, context, description) in test_cases {
        let decision = engine.evaluate(resource, action, context);
        
        let status = if decision.allowed { "✓ ALLOW" } else { "✗ DENY " };
        let rule = decision.matched_rule.as_deref().unwrap_or("(default)");
        
        println!("{} | {} ", status, description);
        println!("         Resource: {}", resource);
        println!("         Action: {}", action);
        println!("         Matched Rule: {}", rule);
        println!("         Reason: {}", decision.reason);
        println!("{:-<70}", "");
    }

    // =========================================================================
    // Part 4: Loading Policies from YAML (Alternative Approach)
    // =========================================================================
    
    println!("\nPart 4: Loading Policies from YAML File\n");
    
    // In production, you would typically load policies from a file:
    //
    // let mut engine = PolicyEngine::new();
    // engine.load_rules("policies/agent_system_policies.yaml")?;
    //
    // Example YAML format:
    // ```yaml
    // rules:
    //   - id: admin-access
    //     effect: allow
    //     resource_pattern: "*"
    //     action_pattern: "*"
    //     conditions:
    //       - attribute: role
    //         operator: equals
    //         value: admin
    //     priority: 100
    //     description: "Full admin access"
    // ```
    
    // Create a sample YAML config (in memory for demo)
    let yaml_config = r#"
rules:
  - id: demo-rule
    effect: allow
    resource_pattern: "demo/*"
    action_pattern: "test"
    conditions: []
    priority: 50
    description: "Demo rule loaded from YAML"
"#;
    
    // Parse the YAML configuration
    let config: PolicyConfig = serde_yaml::from_str(yaml_config)?;
    
    println!("✓ Parsed YAML configuration");
    println!("  Rules loaded: {}", config.rules.len());
    for rule in &config.rules {
        println!("  - {}: {:?} on {}/{}", 
            rule.id, rule.effect, rule.resource_pattern, rule.action_pattern);
    }

    // =========================================================================
    // Part 5: Complex ABAC Conditions
    // =========================================================================
    
    println!("\nPart 5: Advanced ABAC Condition Examples\n");
    
    // Demonstrate all available condition operators
    let operators_demo = vec![
        ("Equals", ConditionOperator::Equals, "role", serde_json::json!("admin")),
        ("NotEquals", ConditionOperator::NotEquals, "status", serde_json::json!("suspended")),
        ("Contains", ConditionOperator::Contains, "permissions", serde_json::json!("write")),
        ("StartsWith", ConditionOperator::StartsWith, "email", serde_json::json!("admin@")),
        ("EndsWith", ConditionOperator::EndsWith, "email", serde_json::json!("@company.com")),
        ("GreaterThan", ConditionOperator::GreaterThan, "clearance_level", serde_json::json!(3)),
        ("LessThan", ConditionOperator::LessThan, "risk_score", serde_json::json!(50)),
        ("In", ConditionOperator::In, "department", serde_json::json!(["eng", "security", "admin"])),
    ];
    
    println!("Available condition operators:");
    for (name, _operator, attr, value) in operators_demo {
        println!("  • {} - Example: {} {:?}", name, attr, value);
    }

    println!("\n=== Policy Demo Complete ===");
    
    Ok(())
}

// =============================================================================
// Helper: Print a policy decision with formatting
// =============================================================================

#[allow(dead_code)]
fn print_decision(
    description: &str,
    decision: &PolicyDecision,
) {
    let icon = if decision.allowed { "✓" } else { "✗" };
    let status = if decision.allowed { "ALLOWED" } else { "DENIED" };
    
    println!("{} {} - {}", icon, status, description);
    println!("  Reason: {}", decision.reason);
    if let Some(rule) = &decision.matched_rule {
        println!("  Matched Rule: {}", rule);
    }
}
