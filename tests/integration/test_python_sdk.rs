//! Python SDK integration tests (TST-006)
//!
//! Tests for the Python binding types and their Rust-level behavior.
//! These tests verify the Rust types that back the Python API without
//! requiring a Python interpreter.
//!
//! Note: Full Python integration tests require `--features python` and
//! a working maturin/PyO3 setup. The tests below validate the core
//! types and logic used by the bindings.

/// Tests for Python SDK types that work without the python feature flag.
///
/// These verify the underlying Rust APIs that the Python bindings expose.
#[cfg(test)]
mod python_sdk_type_tests {
    use std::collections::HashMap;

    /// TST-006: Test that PolicyEngine can be used as the Python SDK would.
    #[test]
    fn test_policy_engine_python_workflow() {
        use vak::policy::{PolicyContext, PolicyEffect, PolicyEngine, PolicyRule};

        // Simulate Python SDK workflow:
        // 1. Create engine
        let mut engine = PolicyEngine::new_unlimited();

        // 2. Add rules (as Python user would via add_rule())
        engine.add_rule(PolicyRule {
            id: "py-rule-1".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "data/*".to_string(),
            action_pattern: "read".to_string(),
            conditions: vec![],
            priority: 10,
            description: Some("Python SDK test rule".to_string()),
        });

        // 3. Evaluate (as Python user would via evaluate())
        let ctx = PolicyContext {
            agent_id: "py-agent-1".to_string(),
            role: "user".to_string(),
            attributes: HashMap::new(),
            environment: HashMap::new(),
        };

        let decision = engine.evaluate("data/file.csv", "read", &ctx);
        assert!(decision.allowed);
    }

    /// TST-006: Test that AuditLogger works as Python SDK would use it.
    #[test]
    fn test_audit_logger_python_workflow() {
        use vak::audit::{AuditDecision, AuditLogger};

        // Simulate Python SDK workflow:
        // 1. Create logger
        let mut logger = AuditLogger::new();

        // 2. Log events
        logger.log("py-agent", "execute", "/tools/calc", AuditDecision::Allowed);
        logger.log("py-agent", "read", "/data/secret", AuditDecision::Denied);

        // 3. Query entries
        let entries = logger.load_all_entries().expect("Failed to load entries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].agent_id, "py-agent");

        // 4. Verify chain integrity
        assert!(logger.verify_chain().is_ok());
    }

    /// TST-006: Test kernel configuration for Python SDK.
    #[test]
    fn test_kernel_config_python_workflow() {
        use vak::kernel::config::KernelConfig;

        // Default config (most common Python SDK usage)
        let default = KernelConfig::default();
        assert!(!default.name.is_empty());

        // Builder pattern (advanced Python SDK usage)
        let custom = KernelConfig::builder()
            .name("python-kernel")
            .max_concurrent_agents(50)
            .build();
        assert_eq!(custom.name, "python-kernel");
        assert_eq!(custom.max_concurrent_agents, 50);
    }

    /// TST-006: Test tool request creation for Python SDK.
    #[test]
    fn test_tool_request_python_workflow() {
        use vak::kernel::types::ToolRequest;

        let request = ToolRequest::new(
            "calculator",
            serde_json::json!({
                "operation": "add",
                "a": 10,
                "b": 20
            }),
        );

        assert_eq!(request.tool_name, "calculator");
        assert!(request.parameters.is_object());

        // Verify hash computation works
        let hash = request.compute_hash();
        assert!(!hash.is_empty());
    }

    /// TST-006: Test agent/session ID generation for Python SDK.
    #[test]
    fn test_id_generation_python_workflow() {
        use vak::kernel::types::{AgentId, SessionId};

        // IDs should be unique
        let a1 = AgentId::new();
        let a2 = AgentId::new();
        assert_ne!(a1, a2);

        let s1 = SessionId::new();
        let s2 = SessionId::new();
        assert_ne!(s1, s2);
    }

    /// TST-006: Test memory operations as Python SDK would use them.
    #[test]
    fn test_memory_ops_python_workflow() {
        use vak::memory::{agent_key, StateManager, StateManagerConfig, StateTier};

        let manager = StateManager::new(StateManagerConfig::default());

        // Python SDK: store_memory(agent_id, key, value)
        let key = agent_key("py-agent", "context");
        manager
            .set_state(&key, b"some context data".to_vec(), StateTier::Ephemeral)
            .expect("Failed to set state");

        // Python SDK: get_memory(agent_id, key)
        let val = manager
            .get_state(&key, StateTier::Ephemeral)
            .expect("Failed to get state")
            .expect("Key should exist");

        assert_eq!(val, b"some context data".to_vec());
    }

    /// TST-006: Test secrets management for Python SDK.
    #[tokio::test]
    async fn test_secrets_python_workflow() {
        use vak::secrets::{MemorySecretsProvider, SecretsManager};

        let provider = MemorySecretsProvider::new();
        let manager = SecretsManager::new(Box::new(provider));

        // Python SDK: set_secret(key, value)
        manager
            .set_secret("OPENAI_API_KEY", "sk-test-12345")
            .await
            .expect("Failed to set secret");

        // Python SDK: get_secret(key)
        let secret = manager
            .get_secret("OPENAI_API_KEY")
            .await
            .expect("Failed to get secret");

        assert_eq!(secret.value(), "sk-test-12345");

        // Python SDK: list_keys()
        let keys = manager.list_keys().await.expect("Failed to list keys");
        assert!(keys.contains(&"OPENAI_API_KEY".to_string()));
    }

    /// TST-006: Test reasoning verification for Python SDK.
    #[test]
    fn test_reasoning_python_workflow() {
        use vak::sandbox::reasoning_host::{PlanVerification, ReasoningConfig, ReasoningHost};

        let mut host = ReasoningHost::new(ReasoningConfig::default());

        // Python SDK: verify_plan(agent_id, action, target, confidence)
        let plan = PlanVerification {
            agent_id: "py-agent".to_string(),
            action_type: "read_file".to_string(),
            target: "/tmp/data.json".to_string(),
            confidence: 0.9,
            params: Default::default(),
        };

        let result = host.verify_plan(&plan);
        assert!(result.allowed, "Safe read should be allowed");
        assert!(result.risk_score < 0.5, "Low risk expected");
    }

    /// TST-006: Test LLM tool definitions for Python SDK.
    #[test]
    fn test_tool_definitions_python_workflow() {
        use vak::lib_integration::{builtin_tool_definitions, ToolDefinition};

        let tools = builtin_tool_definitions();
        assert!(!tools.is_empty(), "Should have built-in tools");

        for tool in &tools {
            // Each tool must have valid name and description
            assert!(!tool.name.is_empty(), "Tool name must not be empty");
            assert!(!tool.description.is_empty(), "Tool description must not be empty");

            // Verify OpenAI format conversion
            let openai = tool.to_openai();
            assert_eq!(openai.function.name, tool.name);

            // Verify Anthropic format conversion
            let anthropic = tool.to_anthropic();
            assert_eq!(anthropic.name, tool.name);
        }
    }

    /// TST-006: Test JSON serialization workflows (critical for Python interop).
    #[test]
    fn test_json_serialization_python_interop() {
        use vak::sandbox::reasoning_host::{VerificationResult, ViolationInfo};

        // Create a result and serialize to JSON (as Python SDK receives it)
        let result = VerificationResult::denied(
            vec![ViolationInfo {
                violation_type: "CriticalAccess".to_string(),
                resource: "/etc/passwd".to_string(),
                rule: "SystemFileProtection".to_string(),
                severity: 0.9,
            }],
            0.85,
        );

        let json = serde_json::to_string(&result).expect("Serialization failed");

        // Python SDK would deserialize this JSON
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["allowed"], false);
        assert!(parsed["violations"].is_array());
        assert_eq!(parsed["violations"][0]["violation_type"], "CriticalAccess");
    }
}
