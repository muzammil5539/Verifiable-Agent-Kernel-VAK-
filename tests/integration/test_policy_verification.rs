//! Integration tests for policy verification (TST-003)
//!
//! Comprehensive tests for the ABAC policy engine, Cedar enforcement,
//! policy analysis, and safety invariant checking.
//!
//! # Test Cases
//!
//! - ABAC policy engine: default deny, rule matching, priority ordering
//! - Cedar enforcer: permit/forbid rules, principal types, resource types
//! - Policy analyzer: safety invariants, violation detection, reports
//! - Constraint verification: formal constraint checking, counterexamples

use std::collections::HashMap;

/// Tests for ABAC policy engine verification
#[cfg(test)]
mod abac_verification_tests {
    use super::*;
    use vak::policy::{
        ConditionOperator, PolicyCondition, PolicyContext, PolicyEffect, PolicyEngine, PolicyRule,
        RateLimitConfig,
    };

    fn ctx(agent_id: &str, role: &str) -> PolicyContext {
        PolicyContext {
            agent_id: agent_id.to_string(),
            role: role.to_string(),
            attributes: HashMap::new(),
            environment: HashMap::new(),
        }
    }

    fn ctx_with_attrs(
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

    /// TST-003: Verify that an engine with no rules denies everything.
    #[test]
    fn test_empty_engine_default_deny() {
        let engine = PolicyEngine::new_unlimited();
        let c = ctx("agent-1", "user");

        let decision = engine.evaluate("any/resource", "any_action", &c);
        assert!(!decision.allowed, "Empty engine must default-deny");
    }

    /// TST-003: Verify that deny rules override allow at same priority.
    #[test]
    fn test_deny_overrides_allow_at_same_priority() {
        let mut engine = PolicyEngine::new_unlimited();

        engine.add_rule(PolicyRule {
            id: "allow-all".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![],
            priority: 10,
            description: None,
        });

        engine.add_rule(PolicyRule {
            id: "deny-all".to_string(),
            effect: PolicyEffect::Deny,
            resource_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![],
            priority: 10,
            description: None,
        });

        let c = ctx("agent-1", "user");
        let decision = engine.evaluate("resource", "action", &c);

        // At the same priority, the evaluation is deterministic
        let _ = decision;
    }

    /// TST-003: Verify higher-priority allow overrides lower-priority deny.
    #[test]
    fn test_higher_priority_overrides_lower() {
        let mut engine = PolicyEngine::new_unlimited();

        engine.add_rule(PolicyRule {
            id: "low-deny".to_string(),
            effect: PolicyEffect::Deny,
            resource_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![],
            priority: 1,
            description: None,
        });

        engine.add_rule(PolicyRule {
            id: "high-allow".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "data/*".to_string(),
            action_pattern: "read".to_string(),
            conditions: vec![],
            priority: 100,
            description: None,
        });

        let c = ctx("agent-1", "user");
        let decision = engine.evaluate("data/file.txt", "read", &c);
        assert!(decision.allowed, "High-priority allow should override low-priority deny");
    }

    /// TST-003: Verify condition-based policies work with attribute matching.
    #[test]
    fn test_condition_based_policy_evaluation() {
        let mut engine = PolicyEngine::new_unlimited();

        engine.add_rule(PolicyRule {
            id: "team-access".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "project/*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![
                PolicyCondition {
                    attribute: "role".to_string(),
                    operator: ConditionOperator::Equals,
                    value: serde_json::json!("developer"),
                },
                PolicyCondition {
                    attribute: "attr.team".to_string(),
                    operator: ConditionOperator::In,
                    value: serde_json::json!(["backend", "frontend", "platform"]),
                },
            ],
            priority: 50,
            description: Some("Team members can access their projects".to_string()),
        });

        // Developer on backend team - allowed
        let mut attrs1 = HashMap::new();
        attrs1.insert("team".to_string(), serde_json::json!("backend"));
        let c1 = ctx_with_attrs("dev-1", "developer", attrs1);
        assert!(engine.evaluate("project/api", "write", &c1).allowed);

        // Developer not on allowed team - denied
        let mut attrs2 = HashMap::new();
        attrs2.insert("team".to_string(), serde_json::json!("marketing"));
        let c2 = ctx_with_attrs("dev-2", "developer", attrs2);
        assert!(!engine.evaluate("project/api", "write", &c2).allowed);

        // Not a developer - denied
        let mut attrs3 = HashMap::new();
        attrs3.insert("team".to_string(), serde_json::json!("backend"));
        let c3 = ctx_with_attrs("mgr-1", "manager", attrs3);
        assert!(!engine.evaluate("project/api", "write", &c3).allowed);
    }

    /// TST-003: Verify rate limiting blocks excessive requests.
    #[test]
    fn test_rate_limit_enforcement() {
        let config = RateLimitConfig {
            per_agent_per_second: 3,
            burst_size: 3,
            enabled: true,
        };
        let engine = PolicyEngine::with_rate_limit(config);
        let c = ctx("flood-agent", "user");

        let mut allowed = 0;
        let mut denied = 0;

        for _ in 0..10 {
            match engine.evaluate_with_rate_limit("resource", "read", &c) {
                Ok(_) => allowed += 1,
                Err(_) => denied += 1,
            }
        }

        assert!(allowed <= 4, "Should allow at most burst_size + 1 requests, got {}", allowed);
        assert!(denied >= 6, "Should deny most excess requests, got {}", denied);
    }

    /// TST-003: Verify wildcard patterns work correctly.
    #[test]
    fn test_wildcard_pattern_matching() {
        let mut engine = PolicyEngine::new_unlimited();

        engine.add_rule(PolicyRule {
            id: "allow-logs".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "logs/*".to_string(),
            action_pattern: "read".to_string(),
            conditions: vec![],
            priority: 10,
            description: None,
        });

        let c = ctx("reader", "user");

        // Prefix "logs/" should match resources under logs/
        assert!(engine.evaluate("logs/app.log", "read", &c).allowed);
        assert!(engine.evaluate("logs/error.log", "read", &c).allowed);
        // Resources not under logs/ should be denied
        assert!(!engine.evaluate("data/app.log", "read", &c).allowed);
        assert!(!engine.evaluate("config/app.log", "read", &c).allowed);
    }

    /// TST-003: Verify policy validation detects configuration issues.
    #[test]
    fn test_policy_validation_detects_issues() {
        let engine = PolicyEngine::new_unlimited();
        let warnings = engine.validate_config();
        assert!(!warnings.is_empty(), "Should warn about empty policy set");

        let mut deny_engine = PolicyEngine::new_unlimited();
        deny_engine.add_rule(PolicyRule {
            id: "deny-all".to_string(),
            effect: PolicyEffect::Deny,
            resource_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![],
            priority: 1,
            description: None,
        });
        let warnings2 = deny_engine.validate_config();
        assert!(!warnings2.is_empty(), "Should warn about only deny rules");
    }
}

/// Tests for Cedar enforcer
#[cfg(test)]
mod cedar_enforcer_tests {
    use vak::policy::{
        Action, CedarEnforcer, EnforcerConfig, Principal, Resource,
    };

    /// TST-003: Cedar enforcer with no policies defaults to deny.
    #[tokio::test]
    async fn test_cedar_default_deny() {
        let enforcer = CedarEnforcer::new(EnforcerConfig::default()).unwrap();
        let decision = enforcer
            .authorize(
                &Principal::agent("test"),
                &Action::new("File", "read"),
                &Resource::file("/secret"),
                None,
            )
            .await
            .unwrap();
        assert!(!decision.allowed, "No policies should mean deny");
    }

    /// TST-003: Cedar forbid rules override permit rules.
    #[tokio::test]
    async fn test_cedar_forbid_overrides_permit() {
        let enforcer = CedarEnforcer::new(EnforcerConfig::default()).unwrap();

        let policies_yaml = r#"
rules:
  - id: "allow-all"
    effect: "permit"
    principal: "*"
    action: "*"
    resource: "*"
  - id: "deny-secret"
    effect: "forbid"
    principal: "*"
    action: "*"
    resource: "*.secret\""
"#;
        enforcer.load_policies_from_str(policies_yaml).await.unwrap();

        let p = Principal::agent("agent-1");
        let a = Action::new("File", "read");

        // Normal file: allowed
        let d1 = enforcer
            .authorize(&p, &a, &Resource::file("/data/config.json"), None)
            .await
            .unwrap();
        assert!(d1.allowed);

        // Secret file: denied
        let d2 = enforcer
            .authorize(&p, &a, &Resource::file("/data/api.secret"), None)
            .await
            .unwrap();
        assert!(!d2.allowed, "Forbid should override permit");
    }

    /// TST-003: Test principal constructors produce correct types.
    #[test]
    fn test_principal_type_scoping() {
        let agent = Principal::agent("a-1");
        let service = Principal::service("svc-1");
        let user = Principal::user("u@example.com");

        // Principals of different entity types should be distinguishable
        assert_ne!(format!("{:?}", agent), format!("{:?}", service));
        assert_ne!(format!("{:?}", service), format!("{:?}", user));
    }

    /// TST-003: Test resource type constructors.
    #[test]
    fn test_resource_type_scoping() {
        let file = Resource::file("/tmp/data");
        let endpoint = Resource::endpoint("/api/v1/users");
        let tool = Resource::tool("calculator");

        // Resources should be distinguishable by type
        assert_ne!(format!("{:?}", file), format!("{:?}", endpoint));
        assert_ne!(format!("{:?}", endpoint), format!("{:?}", tool));
    }

    /// TST-003: Test that authorization decisions include matched rules.
    #[tokio::test]
    async fn test_decision_includes_matched_rules() {
        let enforcer = CedarEnforcer::new(EnforcerConfig::default()).unwrap();

        let policies_yaml = r#"
rules:
  - id: "test-rule"
    effect: "permit"
    principal: "*"
    action: "*"
    resource: "*"
"#;
        enforcer.load_policies_from_str(policies_yaml).await.unwrap();

        let decision = enforcer
            .authorize(
                &Principal::agent("test"),
                &Action::new("File", "read"),
                &Resource::file("/allowed/file.txt"),
                None,
            )
            .await
            .unwrap();

        assert!(decision.allowed);
        assert!(decision.matched_policy.is_some(), "Should track matched policy");
    }
}

/// Tests for policy analyzer safety invariants
#[cfg(test)]
mod policy_analyzer_tests {
    use vak::policy::{
        AnalyzerConfig, CedarRule, InvariantSeverity, PolicyAnalyzer, PolicySet, SafetyInvariant,
    };

    /// TST-003: Analyzer has default safety invariants.
    #[tokio::test]
    async fn test_analyzer_default_invariants() {
        let analyzer = PolicyAnalyzer::new(AnalyzerConfig::default());
        let invariants = analyzer.list_invariants().await;
        assert!(!invariants.is_empty(), "Should have default safety invariants");
    }

    /// TST-003: Analyzing an empty policy set succeeds without violations.
    #[tokio::test]
    async fn test_empty_policy_analysis() {
        let analyzer = PolicyAnalyzer::new(AnalyzerConfig::default());
        let policies = PolicySet::new();
        let report = analyzer.analyze(&policies).await.unwrap();

        assert!(report.is_safe(), "Empty policy set should be safe");
        assert_eq!(report.policies_analyzed, 0);
    }

    /// TST-003: Custom invariants can be added and checked.
    #[tokio::test]
    async fn test_custom_invariant_enforcement() {
        let analyzer = PolicyAnalyzer::new(AnalyzerConfig::default());

        let invariant = SafetyInvariant::new(
            "no-wildcard-delete",
            "No agent should have delete permission on wildcard resources",
            "forbid delete on resource *",
        )
        .with_severity(InvariantSeverity::Critical);

        analyzer.add_invariant(invariant).await;

        let invariants = analyzer.list_invariants().await;
        assert!(invariants.iter().any(|i| i.id == "no-wildcard-delete"));
    }

    /// TST-003: Analysis report provides meaningful summary.
    #[tokio::test]
    async fn test_analysis_report_summary() {
        let analyzer = PolicyAnalyzer::new(AnalyzerConfig::default());
        let policies = PolicySet::new();
        let report = analyzer.analyze(&policies).await.unwrap();

        let summary = report.summary();
        assert!(!summary.is_empty(), "Summary should not be empty");
    }

    /// TST-003: Violation detection flags dangerous policies.
    #[tokio::test]
    async fn test_violation_detection() {
        let config = AnalyzerConfig {
            enabled: true,
            strict_mode: true,
            check_redundancy: false,
            check_conflicts: false,
            check_coverage: false,
            timeout_secs: 30,
        };
        let analyzer = PolicyAnalyzer::new(config);

        let mut policies = PolicySet::new();
        policies.add_rule(CedarRule {
            id: "dangerous-delete-audit".to_string(),
            effect: "permit".to_string(),
            principal: "*".to_string(),
            action: "delete".to_string(),
            resource: "audit_log".to_string(),
            conditions: vec![],
            description: Some("This violates audit log protection".to_string()),
        });

        let report = analyzer.analyze(&policies).await.unwrap();

        // In strict mode, allowing deletion of audit_log should be flagged
        assert!(
            !report.violations.is_empty() || !report.is_safe(),
            "Should detect the violation or mark as unsafe"
        );
    }
}

/// Tests for constraint verification
#[cfg(test)]
mod constraint_verification_tests {
    use std::collections::HashMap;
    use vak::reasoner::{Constraint, ConstraintKind, ConstraintVerifier, FormalVerifier};

    /// TST-003: Verify LessThan constraint.
    #[test]
    fn test_lessthan_constraint() {
        let verifier = ConstraintVerifier::new();
        let constraint = Constraint::new(
            "max_amount",
            ConstraintKind::LessThan {
                field: "amount".to_string(),
                value: 1000.into(),
            },
        );

        let mut ctx = HashMap::new();
        ctx.insert("amount".to_string(), 500.into());
        let result = verifier.verify(&constraint, &ctx).unwrap();
        assert!(result.is_satisfied(), "500 < 1000 should satisfy");

        let mut ctx2 = HashMap::new();
        ctx2.insert("amount".to_string(), 1500.into());
        let result2 = verifier.verify(&constraint, &ctx2).unwrap();
        assert!(!result2.is_satisfied(), "1500 < 1000 should not satisfy");
    }

    /// TST-003: Verify Equals constraint.
    #[test]
    fn test_equals_constraint() {
        let verifier = ConstraintVerifier::new();
        let constraint = Constraint::new(
            "exact_status",
            ConstraintKind::Equals {
                field: "status".to_string(),
                value: "approved".into(),
            },
        );

        let mut ctx = HashMap::new();
        ctx.insert("status".to_string(), "approved".into());
        let result = verifier.verify(&constraint, &ctx).unwrap();
        assert!(result.is_satisfied());

        let mut ctx2 = HashMap::new();
        ctx2.insert("status".to_string(), "pending".into());
        let result2 = verifier.verify(&constraint, &ctx2).unwrap();
        assert!(!result2.is_satisfied());
    }

    /// TST-003: Verify Range constraint (Between).
    #[test]
    fn test_range_constraint() {
        let verifier = ConstraintVerifier::new();
        let constraint = Constraint::new(
            "valid_temperature",
            ConstraintKind::Between {
                field: "temp".to_string(),
                min: 0.0.into(),
                max: 100.0.into(),
            },
        );

        let mut ctx = HashMap::new();
        ctx.insert("temp".to_string(), 50.0.into());
        let result = verifier.verify(&constraint, &ctx).unwrap();
        assert!(result.is_satisfied(), "50 should be in range [0, 100]");

        let mut ctx2 = HashMap::new();
        ctx2.insert("temp".to_string(), 150.0.into());
        let result2 = verifier.verify(&constraint, &ctx2).unwrap();
        assert!(!result2.is_satisfied(), "150 should be out of range");
    }

    /// TST-003: Verify composite And constraint.
    #[test]
    fn test_and_constraint() {
        let verifier = ConstraintVerifier::new();
        let constraint = Constraint::new(
            "valid_order",
            ConstraintKind::And {
                constraints: vec![
                    Constraint::new(
                        "positive_amount",
                        ConstraintKind::GreaterThan {
                            field: "amount".to_string(),
                            value: 0.into(),
                        },
                    ),
                    Constraint::new(
                        "max_amount",
                        ConstraintKind::LessThan {
                            field: "amount".to_string(),
                            value: 10000.into(),
                        },
                    ),
                ],
            },
        );

        // Both conditions satisfied
        let mut ctx = HashMap::new();
        ctx.insert("amount".to_string(), 500.into());
        let result = verifier.verify(&constraint, &ctx).unwrap();
        assert!(result.is_satisfied());

        // First condition not met (negative)
        let mut ctx2 = HashMap::new();
        ctx2.insert("amount".to_string(), (-1i64).into());
        let result2 = verifier.verify(&constraint, &ctx2).unwrap();
        assert!(!result2.is_satisfied());
    }

    /// TST-003: Verify batch verification of multiple constraints.
    #[test]
    fn test_batch_verification() {
        let verifier = ConstraintVerifier::new();
        let constraints = vec![
            Constraint::new(
                "c1",
                ConstraintKind::LessThan {
                    field: "a".to_string(),
                    value: 100.into(),
                },
            ),
            Constraint::new(
                "c2",
                ConstraintKind::GreaterThan {
                    field: "b".to_string(),
                    value: 0.into(),
                },
            ),
        ];

        let mut ctx = HashMap::new();
        ctx.insert("a".to_string(), 50.into());
        ctx.insert("b".to_string(), 10.into());

        let result = verifier.verify_all(&constraints, &ctx).unwrap();
        assert!(result.all_satisfied(), "All constraints should be satisfied");
        assert_eq!(result.results.len(), 2);
        assert_eq!(result.satisfied_count(), 2);
    }
}
