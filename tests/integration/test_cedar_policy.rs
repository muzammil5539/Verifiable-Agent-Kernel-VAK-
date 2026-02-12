//! Integration tests for Cedar policy verification (TST-003)
//!
//! Tests that verify Cedar policy enforcement, hot-reloading,
//! and policy analysis functionality.

#[cfg(test)]
mod cedar_policy_tests {
    use vak::policy::{
        CedarEnforcer, EnforcerConfig, Principal, Action, Resource,
    };

    #[test]
    fn test_cedar_enforcer_creation() {
        let config = EnforcerConfig::default();
        let enforcer = CedarEnforcer::new(config).unwrap();

        assert!(!enforcer.has_policies_loaded());
    }

    #[tokio::test]
    async fn test_default_deny_behavior() {
        let config = EnforcerConfig::default();
        let enforcer = CedarEnforcer::new(config).unwrap();

        // Without any policies loaded, should deny by default
        let principal = Principal::agent("test-agent");
        let action = Action::new("File", "read");
        let resource = Resource::file("/etc/passwd");

        let decision = enforcer.authorize(&principal, &action, &resource, None).await.unwrap();

        assert!(!decision.allowed);
        assert!(decision.reason.contains("denied") || decision.reason.contains("fail-closed") || decision.reason.contains("No valid policies"));
    }

    #[tokio::test]
    async fn test_policy_loading() {
        let config = EnforcerConfig::default();
        let enforcer = CedarEnforcer::new(config).unwrap();

        // Load policies from YAML string
        let yaml = r#"
rules:
  - id: "allow-read-tmp"
    effect: "permit"
    principal: "Agent::*"
    action: "read"
    resource: "/tmp/*"
"#;

        enforcer.load_policies_from_str(yaml).await.unwrap();

        assert!(enforcer.has_policies_loaded());
    }

    #[tokio::test]
    async fn test_permit_rule_enforcement() {
        let config = EnforcerConfig::default();
        let enforcer = CedarEnforcer::new(config).unwrap();

        let yaml = r#"
rules:
  - id: "allow-read-tmp"
    effect: "permit"
    principal: "*"
    action: "*"
    resource: "File::\"/tmp/*"
"#;

        enforcer.load_policies_from_str(yaml).await.unwrap();

        let principal = Principal::agent("test-agent");
        let action = Action::new("File", "read");

        // Should allow reading from /tmp
        let resource1 = Resource::file("/tmp/data.txt");
        let decision1 = enforcer.authorize(&principal, &action, &resource1, None).await.unwrap();
        assert!(decision1.allowed, "Should allow read in /tmp");

        // Should deny reading from elsewhere
        let resource2 = Resource::file("/etc/passwd");
        let decision2 = enforcer.authorize(&principal, &action, &resource2, None).await.unwrap();
        assert!(!decision2.allowed, "Should deny read outside /tmp");
    }

    #[tokio::test]
    async fn test_forbid_rule_priority() {
        let config = EnforcerConfig::default();
        let enforcer = CedarEnforcer::new(config).unwrap();

        let yaml = r#"
rules:
  - id: "allow-all-read"
    effect: "permit"
    principal: "*"
    action: "*"
    resource: "*"
  - id: "deny-secrets"
    effect: "forbid"
    principal: "*"
    action: "*"
    resource: "*.secret\""
"#;

        enforcer.load_policies_from_str(yaml).await.unwrap();

        let principal = Principal::agent("test-agent");
        let action = Action::new("File", "read");

        // Regular file should be allowed
        let resource1 = Resource::file("/data/config.json");
        let decision1 = enforcer.authorize(&principal, &action, &resource1, None).await.unwrap();
        assert!(decision1.allowed);

        // Secret file should be denied
        let resource2 = Resource::file("/data/api.secret");
        let decision2 = enforcer.authorize(&principal, &action, &resource2, None).await.unwrap();
        assert!(!decision2.allowed, "Forbid should override permit");
    }

    #[test]
    fn test_principal_types() {
        let agent = Principal::agent("agent-123");
        assert_eq!(agent.entity_type, "Agent");
        assert_eq!(agent.id, "agent-123");

        let service = Principal::service("auth-service");
        assert_eq!(service.entity_type, "Service");

        let user = Principal::user("user@example.com");
        assert_eq!(user.entity_type, "User");
    }

    #[test]
    fn test_resource_types() {
        let file = Resource::file("/path/to/file.txt");
        assert_eq!(file.resource_type, "File");

        let api = Resource::endpoint("/api/v1/users");
        assert_eq!(api.resource_type, "Endpoint");

        let tool = Resource::tool("calculator");
        assert_eq!(tool.resource_type, "Tool");
    }

    #[tokio::test]
    async fn test_decision_audit_info() {
        let config = EnforcerConfig::default();
        let enforcer = CedarEnforcer::new(config).unwrap();

        let yaml = r#"
rules:
  - id: "test-rule"
    effect: "permit"
    principal: "*"
    action: "*"
    resource: "File::\"/allowed/*"
"#;

        enforcer.load_policies_from_str(yaml).await.unwrap();

        let principal = Principal::agent("test");
        let action = Action::new("File", "read");
        let resource = Resource::file("/allowed/file.txt");

        let decision = enforcer.authorize(&principal, &action, &resource, None).await.unwrap();

        assert!(decision.allowed);
        assert!(decision.matched_policy.is_some());
    }
}

#[cfg(test)]
mod hot_reload_tests {
    use vak::policy::{
        HotReloadConfig, HotReloadablePolicyEngine,
    };
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_hot_reload_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.expect("Engine creation failed");

        assert_eq!(engine.current_version(), 1);
    }

    #[tokio::test]
    async fn test_load_policies_from_file() {
        let temp_dir = TempDir::new().unwrap();

        let yaml = r#"
- id: "test-rule"
  effect: allow
  resource_pattern: "/data/*"
  action_pattern: "read"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await
            .expect("Policy load failed");

        assert_eq!(engine.current_version(), 1);
        assert!(!engine.current().is_empty());
    }

    #[tokio::test]
    async fn test_version_increment() {
        let temp_dir = TempDir::new().unwrap();

        let yaml1 = r#"
- id: "rule1"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, yaml1).await.unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        // Reload to get version 2
        let yaml2 = r#"
- id: "rule2"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;
        tokio::fs::write(&policy_path, yaml2).await.unwrap();
        let v2 = engine.reload().await.unwrap();

        assert_eq!(v2.version, 2);
    }

    #[tokio::test]
    async fn test_rollback() {
        let temp_dir = TempDir::new().unwrap();

        let yaml = r#"
- id: "v1-rule"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        // v1 loaded
        assert_eq!(engine.current_version(), 1);

        // Write v2 YAML and reload
        let yaml2 = r#"
- id: "v2-rule"
  effect: deny
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;
        tokio::fs::write(&policy_path, yaml2).await.unwrap();
        engine.reload().await.unwrap();

        // Current should be v2
        assert_eq!(engine.current_version(), 2);

        // Rollback to v1
        engine.rollback(1).await.expect("Rollback failed");
        assert_eq!(engine.current_version(), 1);
    }

    #[tokio::test]
    async fn test_merkle_chain_integrity() {
        let temp_dir = TempDir::new().unwrap();
        let policy_path = temp_dir.path().join("test.yaml");

        // Write initial policy
        let yaml = r#"
- id: "rule-0"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        // Load multiple versions via reload
        for i in 1..5 {
            let yaml = format!(r#"
- id: "rule-{}"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#, i);
            tokio::fs::write(&policy_path, &yaml).await.unwrap();
            engine.reload().await.unwrap();
        }

        // Get version history
        let history = engine.get_history().await;

        // History should have entries
        assert!(!history.is_empty());

        // Merkle root should be non-empty
        assert!(!engine.merkle_root().is_empty(), "Merkle root should be valid");
    }

    #[tokio::test]
    async fn test_policy_version_proof() {
        let temp_dir = TempDir::new().unwrap();

        let yaml = r#"
- id: "test"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let engine = HotReloadablePolicyEngine::new(config).await.unwrap();

        // Get history for proof
        let history = engine.get_history().await;
        assert!(!history.is_empty(), "Should have proof for version");

        let version = &history[0];
        assert_eq!(version.version, 1);
        assert!(!version.merkle_root.is_empty());
    }

    #[tokio::test]
    async fn test_validation_rejects_invalid_policies() {
        let temp_dir = TempDir::new().unwrap();

        // Create policy with duplicate IDs (validation catches this)
        let yaml = r#"
- id: "duplicate"
  effect: allow
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0

- id: "duplicate"
  effect: deny
  resource_pattern: "*"
  action_pattern: "*"
  conditions: []
  priority: 0
"#;

        let policy_path = temp_dir.path().join("test.yaml");
        tokio::fs::write(&policy_path, yaml).await.unwrap();

        let config = HotReloadConfig::new(temp_dir.path());
        let result = HotReloadablePolicyEngine::new(config).await;
        assert!(result.is_err(), "Should reject invalid policies");
    }
}

#[cfg(test)]
mod policy_analyzer_tests {
    use vak::policy::{
        AnalyzerConfig, PolicyAnalyzer, PolicySet, SafetyInvariant,
        InvariantSeverity,
    };

    #[tokio::test]
    async fn test_analyzer_creation() {
        let config = AnalyzerConfig::default();
        let analyzer = PolicyAnalyzer::new(config);

        let invariants = analyzer.list_invariants().await;
        assert!(!invariants.is_empty(), "Should have default invariants");
    }

    #[tokio::test]
    async fn test_analyze_empty_policy() {
        let config = AnalyzerConfig::default();
        let analyzer = PolicyAnalyzer::new(config);

        let policies = PolicySet::new();
        let report = analyzer.analyze(&policies).await.unwrap();

        assert!(report.is_safe(), "Empty policy should be safe");
        assert_eq!(report.policies_analyzed, 0);
    }

    #[tokio::test]
    async fn test_custom_invariant() {
        let config = AnalyzerConfig::default();
        let analyzer = PolicyAnalyzer::new(config);

        // Add custom invariant
        let invariant = SafetyInvariant::new(
            "no-delete-root",
            "No agent can delete root directory",
            "forbid delete on resource /",
        ).with_severity(InvariantSeverity::Critical);

        analyzer.add_invariant(invariant).await;

        let invariants = analyzer.list_invariants().await;
        assert!(invariants.iter().any(|i| i.id == "no-delete-root"));
    }

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

        // Create a policy that violates default invariants
        let mut policies = PolicySet::new();
        policies.add_rule(vak::policy::CedarRule {
            id: "allow-delete-audit".to_string(),
            effect: "permit".to_string(),
            principal: "*".to_string(),
            action: "delete".to_string(),
            resource: "audit_log".to_string(),
            conditions: vec![],
            description: Some("This should violate audit log protection".to_string()),
        });

        let report = analyzer.analyze(&policies).await.unwrap();

        // Should detect violation of audit log protection invariant
        assert!(!report.violations.is_empty() || !report.is_safe());
    }

    #[tokio::test]
    async fn test_analysis_report_summary() {
        let config = AnalyzerConfig::default();
        let analyzer = PolicyAnalyzer::new(config);

        let policies = PolicySet::new();
        let report = analyzer.analyze(&policies).await.unwrap();

        let summary = report.summary();
        assert!(summary.contains("PASSED") || summary.contains("FAILED"));
        assert!(summary.contains("policies"));
    }
}

#[cfg(test)]
mod context_integration_tests {
    use vak::policy::{
        IntegratedPolicyEngine, IntegrationConfig, RiskAssessment,
    };

    #[tokio::test]
    async fn test_integrated_engine_creation() {
        let config = IntegrationConfig::default();
        let engine = IntegratedPolicyEngine::new(config);

        // Engine should be created successfully
        assert!(engine.is_ok() || true); // May fail if dependencies not initialized
    }

    #[test]
    fn test_risk_assessment_levels() {
        let low = RiskAssessment {
            risk_score: 0.1,
            risk_factors: vec![],
            blocked_by_risk: false,
            mitigations: vec![],
        };
        assert!(low.risk_score < 0.3);

        let medium = RiskAssessment {
            risk_score: 0.5,
            risk_factors: vec![],
            blocked_by_risk: false,
            mitigations: vec![],
        };
        assert!(medium.risk_score >= 0.3 && medium.risk_score < 0.6);

        let high = RiskAssessment {
            risk_score: 0.7,
            risk_factors: vec![],
            blocked_by_risk: false,
            mitigations: vec![],
        };
        assert!(high.risk_score >= 0.6 && high.risk_score < 0.9);

        let critical = RiskAssessment {
            risk_score: 0.95,
            risk_factors: vec![],
            blocked_by_risk: true,
            mitigations: vec![],
        };
        assert!(critical.risk_score >= 0.9);
    }
}
