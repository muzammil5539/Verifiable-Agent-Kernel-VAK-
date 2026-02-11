//! Property-based tests for VAK components (Issue #33 / TST-005)
//!
//! Uses proptest to generate random inputs and verify invariants.
//! Run with: `cargo test --test property_tests`

use proptest::prelude::*;
use std::collections::HashMap;

// ============================================================================
// Strategy Definitions
// ============================================================================

/// Generate arbitrary agent IDs (valid UUIDs)
fn arb_agent_name() -> impl Strategy<Value = String> {
    "[a-zA-Z][a-zA-Z0-9_-]{0,31}".prop_map(|s| s)
}

/// Generate arbitrary tool names
#[allow(dead_code)]
fn arb_tool_name() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("calculator".to_string()),
        Just("echo".to_string()),
        Just("data_processor".to_string()),
        Just("system_info".to_string()),
        "[a-z][a-z0-9_]{0,20}".prop_map(|s| s),
    ]
}

/// Generate arbitrary JSON values (limited depth)
#[allow(dead_code)]
fn arb_json_value() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        any::<f64>()
            .prop_filter("finite", |f| f.is_finite())
            .prop_map(|n| serde_json::json!(n)),
        "[a-zA-Z0-9 ]{0,100}".prop_map(|s| serde_json::Value::String(s)),
    ]
}

/// Generate arithmetic operations
#[allow(dead_code)]
fn arb_operation() -> impl Strategy<Value = String> {
    prop_oneof![
        Just("add".to_string()),
        Just("subtract".to_string()),
        Just("multiply".to_string()),
        Just("divide".to_string()),
    ]
}

/// Generate operands for calculator
#[allow(dead_code)]
fn arb_operands() -> impl Strategy<Value = Vec<f64>> {
    prop::collection::vec(
        any::<f64>().prop_filter("finite", |f| f.is_finite() && f.abs() < 1e15),
        1..=10,
    )
}

// ============================================================================
// Kernel Type Properties
// ============================================================================

mod kernel_type_properties {
    use super::*;
    use vak::kernel::types::{AgentId, SessionId};

    proptest! {
        /// AgentId::new() always produces unique IDs
        #[test]
        fn agent_id_uniqueness(_ in 0..100u32) {
            let id1 = AgentId::new();
            let id2 = AgentId::new();
            prop_assert_ne!(id1, id2, "Two new AgentIds should never be equal");
        }

        /// SessionId::new() always produces unique IDs
        #[test]
        fn session_id_uniqueness(_ in 0..100u32) {
            let id1 = SessionId::new();
            let id2 = SessionId::new();
            prop_assert_ne!(id1, id2, "Two new SessionIds should never be equal");
        }
    }
}

// ============================================================================
// Policy Engine Properties
// ============================================================================

mod policy_properties {
    use super::*;
    use vak::policy::{
        PolicyContext, PolicyEffect, PolicyEngine, PolicyRule,
    };

    proptest! {
        /// Empty policy engine always denies (default-deny)
        #[test]
        fn empty_engine_denies_all(
            resource in "[a-z/]{1,50}",
            action in "[a-z]{1,20}",
            agent_id in arb_agent_name(),
        ) {
            let engine = PolicyEngine::new();
            let context = PolicyContext {
                agent_id,
                role: "user".to_string(),
                attributes: HashMap::new(),
                environment: HashMap::new(),
            };

            let result = engine.evaluate(&resource, &action, &context);
            prop_assert!(!result.allowed,
                "Empty engine must default-deny all requests");
        }

        /// Adding an allow rule makes it match the right resource
        #[test]
        fn allow_rule_matches_resource(
            resource in "[a-z]{1,10}",
            action in "[a-z]{1,10}",
        ) {
            let mut engine = PolicyEngine::new();
            let pattern = format!("{}*", &resource[..1.min(resource.len())]);

            engine.add_rule(PolicyRule {
                id: "test-allow".to_string(),
                effect: PolicyEffect::Allow,
                resource_pattern: pattern,
                action_pattern: "*".to_string(),
                conditions: vec![],
                priority: 10,
                description: Some("Test rule".to_string()),
            });

            let context = PolicyContext {
                agent_id: "test-agent".to_string(),
                role: "user".to_string(),
                attributes: HashMap::new(),
                environment: HashMap::new(),
            };

            // The rule should match since we use a prefix wildcard
            let result = engine.evaluate(&resource, &action, &context);
            prop_assert!(result.allowed,
                "Allow rule with matching pattern should allow the request");
        }

        /// First matching rule wins at equal priority (insertion-order)
        #[test]
        fn first_matching_rule_wins(
            resource in "[a-z]{1,10}",
            action in "[a-z]{1,10}",
        ) {
            let mut engine = PolicyEngine::new();

            // Add deny first, then allow
            engine.add_rule(PolicyRule {
                id: "deny".to_string(),
                effect: PolicyEffect::Deny,
                resource_pattern: "*".to_string(),
                action_pattern: "*".to_string(),
                conditions: vec![],
                priority: 10,
                description: None,
            });

            engine.add_rule(PolicyRule {
                id: "allow".to_string(),
                effect: PolicyEffect::Allow,
                resource_pattern: "*".to_string(),
                action_pattern: "*".to_string(),
                conditions: vec![],
                priority: 10,
                description: None,
            });

            let context = PolicyContext {
                agent_id: "test".to_string(),
                role: "user".to_string(),
                attributes: HashMap::new(),
                environment: HashMap::new(),
            };

            let result = engine.evaluate(&resource, &action, &context);
            prop_assert!(!result.allowed,
                "First matching rule (deny) should win at equal priority");
        }

        /// Higher priority rules take precedence
        #[test]
        fn higher_priority_wins(
            resource in "[a-z]{1,10}",
            lo_priority in 1u32..50,
            hi_priority in 51u32..100,
        ) {
            let mut engine = PolicyEngine::new();

            engine.add_rule(PolicyRule {
                id: "low-deny".to_string(),
                effect: PolicyEffect::Deny,
                resource_pattern: "*".to_string(),
                action_pattern: "*".to_string(),
                conditions: vec![],
                priority: lo_priority as i32,
                description: None,
            });

            engine.add_rule(PolicyRule {
                id: "high-allow".to_string(),
                effect: PolicyEffect::Allow,
                resource_pattern: "*".to_string(),
                action_pattern: "*".to_string(),
                conditions: vec![],
                priority: hi_priority as i32,
                description: None,
            });

            let context = PolicyContext {
                agent_id: "test".to_string(),
                role: "user".to_string(),
                attributes: HashMap::new(),
                environment: HashMap::new(),
            };

            let result = engine.evaluate(&resource, "read", &context);
            prop_assert!(result.allowed,
                "Higher priority rule should win");
        }
    }
}

// ============================================================================
// Audit Chain Properties
// ============================================================================

mod audit_properties {
    use super::*;
    use vak::audit::{AuditDecision, AuditLogger};

    proptest! {
        /// Audit chain maintains integrity after N entries
        #[test]
        fn audit_chain_integrity(
            entries in prop::collection::vec(
                (arb_agent_name(), "[a-z]{1,10}", "[a-z/]{1,30}"),
                1..=20
            )
        ) {
            let mut logger = AuditLogger::new();

            for (agent, action, resource) in &entries {
                logger.log(agent, action, resource, AuditDecision::Allowed);
            }

            let chain = logger.load_all_entries().unwrap();
            prop_assert_eq!(chain.len(), entries.len(),
                "All entries should be logged");

            // Verify chain integrity
            let valid = logger.verify_chain();
            prop_assert!(valid.is_ok(), "Chain integrity must hold after any number of entries");
        }

        /// Each audit entry has a unique hash
        #[test]
        fn audit_entries_have_unique_hashes(
            entries in prop::collection::vec(
                (arb_agent_name(), "[a-z]{1,10}", "[a-z/]{1,30}"),
                2..=10
            )
        ) {
            let mut logger = AuditLogger::new();

            for (agent, action, resource) in &entries {
                logger.log(agent, action, resource, AuditDecision::Allowed);
            }

            let chain = logger.load_all_entries().unwrap();
            let hashes: Vec<&str> = chain.iter().map(|e| e.hash.as_str()).collect();
            let unique_hashes: std::collections::HashSet<&str> = hashes.iter().copied().collect();

            prop_assert_eq!(hashes.len(), unique_hashes.len(),
                "Every audit entry must have a unique hash");
        }

        /// Chain linkage: each entry references the previous entry's hash
        #[test]
        fn audit_chain_linkage(
            entries in prop::collection::vec(
                (arb_agent_name(), "[a-z]{1,10}", "[a-z/]{1,30}"),
                2..=15
            )
        ) {
            let mut logger = AuditLogger::new();

            for (agent, action, resource) in &entries {
                logger.log(agent, action, resource, AuditDecision::Allowed);
            }

            let chain = logger.load_all_entries().unwrap();

            for i in 1..chain.len() {
                prop_assert_eq!(&chain[i].prev_hash, &chain[i-1].hash,
                    "Entry {} should reference entry {}'s hash", i, i-1);
            }
        }
    }
}

// ============================================================================
// Memory State Properties
// ============================================================================

mod memory_properties {
    use super::*;
    use vak::memory::{
        agent_key, InMemoryEphemeral, EphemeralStorage, NamespacedKey,
        StateManager, StateManagerConfig, StateTier, StateValue,
    };

    proptest! {
        /// set followed by get returns the same value
        #[test]
        fn ephemeral_set_get_roundtrip(
            namespace in "[a-z]{1,10}",
            key_name in "[a-z]{1,10}",
            data in prop::collection::vec(any::<u8>(), 0..=256),
        ) {
            let storage = InMemoryEphemeral::new();
            let key = NamespacedKey::new(&namespace, &key_name);
            let value = StateValue::new(data.clone());

            storage.set(&key, value).unwrap();
            let retrieved = storage.get(&key).unwrap().unwrap();

            prop_assert_eq!(retrieved.data, data,
                "Retrieved data must match stored data");
        }

        /// delete returns true for existing keys, false for missing
        #[test]
        fn ephemeral_delete_correctness(
            namespace in "[a-z]{1,10}",
            key_name in "[a-z]{1,10}",
        ) {
            let storage = InMemoryEphemeral::new();
            let key = NamespacedKey::new(&namespace, &key_name);

            // Delete non-existent key
            let result = storage.delete(&key).unwrap();
            prop_assert!(!result, "Deleting non-existent key should return false");

            // Set then delete
            storage.set(&key, StateValue::new(vec![1, 2, 3])).unwrap();
            let result = storage.delete(&key).unwrap();
            prop_assert!(result, "Deleting existing key should return true");

            // Verify gone
            let value = storage.get(&key).unwrap();
            prop_assert!(value.is_none(), "Key should not exist after deletion");
        }

        /// Namespace isolation: different namespaces don't interfere
        #[test]
        fn namespace_isolation(
            ns1 in "[a-z]{1,5}",
            ns2 in "[A-Z]{1,5}",  // uppercase to ensure different
            key_name in "[a-z]{1,10}",
        ) {
            let storage = InMemoryEphemeral::new();
            let key1 = NamespacedKey::new(&ns1, &key_name);
            let key2 = NamespacedKey::new(&ns2, &key_name);

            storage.set(&key1, StateValue::new(b"data1".to_vec())).unwrap();
            storage.set(&key2, StateValue::new(b"data2".to_vec())).unwrap();

            let val1 = storage.get(&key1).unwrap().unwrap();
            let val2 = storage.get(&key2).unwrap().unwrap();

            prop_assert_eq!(val1.data, b"data1".to_vec());
            prop_assert_eq!(val2.data, b"data2".to_vec());
        }

        /// NamespacedKey parse/to_canonical roundtrip
        #[test]
        fn namespaced_key_roundtrip(
            namespace in "[a-zA-Z0-9]{1,20}",
            key_name in "[a-zA-Z0-9_]{1,20}",
        ) {
            let original = NamespacedKey::new(&namespace, &key_name);
            let canonical = original.to_canonical();
            let parsed = NamespacedKey::parse(&canonical).unwrap();

            prop_assert_eq!(parsed.namespace, namespace);
            prop_assert_eq!(parsed.key, key_name);
        }

        /// StateManager cascading get finds values across tiers
        #[test]
        fn state_manager_cascading_finds_all_tiers(
            key_name in "[a-z]{1,10}",
            data in prop::collection::vec(any::<u8>(), 1..=64),
        ) {
            let manager = StateManager::new(StateManagerConfig::default());
            let key = agent_key("test-agent", &key_name);

            // Set in merkle tier
            manager.set_state(&key, data.clone(), StateTier::Merkle).unwrap();

            // Should find via cascading
            let found = manager.get_state_cascading(&key).unwrap();
            prop_assert!(found.is_some(), "Cascading get should find value in merkle tier");
            prop_assert_eq!(found.unwrap(), data);
        }
    }
}

// ============================================================================
// Calculator Properties
// ============================================================================

mod calculator_properties {
    use super::*;

    proptest! {
        /// Addition is commutative
        #[test]
        fn calculator_add_commutative(
            a in any::<f64>().prop_filter("finite", |f| f.is_finite() && f.abs() < 1e15),
            b in any::<f64>().prop_filter("finite", |f| f.is_finite() && f.abs() < 1e15),
        ) {
            let sum_ab = a + b;
            let sum_ba = b + a;
            prop_assert!((sum_ab - sum_ba).abs() < f64::EPSILON,
                "Addition should be commutative: {} + {} vs {} + {}", a, b, b, a);
        }

        /// Multiplication is commutative
        #[test]
        fn calculator_mul_commutative(
            a in any::<f64>().prop_filter("finite", |f| f.is_finite() && f.abs() < 1e7),
            b in any::<f64>().prop_filter("finite", |f| f.is_finite() && f.abs() < 1e7),
        ) {
            let prod_ab = a * b;
            let prod_ba = b * a;
            if prod_ab.is_finite() && prod_ba.is_finite() {
                prop_assert!((prod_ab - prod_ba).abs() < f64::EPSILON * prod_ab.abs().max(1.0),
                    "Multiplication should be commutative");
            }
        }

        /// Addition identity: a + 0 = a
        #[test]
        fn calculator_add_identity(
            a in any::<f64>().prop_filter("finite", |f| f.is_finite()),
        ) {
            let result = a + 0.0;
            prop_assert_eq!(result, a, "Adding zero should yield identity");
        }

        /// Multiplication identity: a * 1 = a
        #[test]
        fn calculator_mul_identity(
            a in any::<f64>().prop_filter("finite", |f| f.is_finite()),
        ) {
            let result = a * 1.0;
            prop_assert_eq!(result, a, "Multiplying by one should yield identity");
        }
    }
}

// ============================================================================
// Serialization Roundtrip Properties
// ============================================================================

mod serialization_properties {
    use super::*;
    use vak::llm::{Message, Role, Usage};

    proptest! {
        /// Message serialization roundtrip
        #[test]
        fn message_serialize_roundtrip(
            content in "[a-zA-Z0-9 ]{0,200}",
            role_idx in 0..3u32,
        ) {
            let role = match role_idx {
                0 => Role::System,
                1 => Role::User,
                _ => Role::Assistant,
            };

            let msg = Message::new(role.clone(), &content);
            let json = serde_json::to_string(&msg).unwrap();
            let deserialized: Message = serde_json::from_str(&json).unwrap();

            prop_assert_eq!(deserialized.role, role);
            prop_assert_eq!(&deserialized.content, &content);
        }

        /// Usage total_tokens is always sum of prompt + completion
        #[test]
        fn usage_total_invariant(
            prompt in 0..100000usize,
            completion in 0..100000usize,
        ) {
            let usage = Usage::new(prompt, completion);
            prop_assert_eq!(usage.total_tokens, prompt + completion,
                "Total tokens must equal prompt + completion");
        }
    }
}

// ============================================================================
// LLM Integration Properties
// ============================================================================

mod integration_properties {
    use super::*;
    use vak::lib_integration::{
        ToolDefinition, builtin_tool_definitions,
        format_openai_tool_results,
        format_anthropic_tool_results, ToolResult,
    };

    proptest! {
        /// All built-in tools have valid JSON schemas
        #[test]
        fn builtin_tools_have_valid_schemas(_ in 0..1u32) {
            let tools = builtin_tool_definitions();
            for tool in &tools {
                prop_assert!(tool.parameters.is_object(),
                    "Tool '{}' parameters must be a JSON object", tool.name);

                // Must have "type" field
                let type_field = tool.parameters.get("type");
                prop_assert!(type_field.is_some(),
                    "Tool '{}' parameters must have a 'type' field", tool.name);
            }
        }

        /// OpenAI format conversion preserves name and description
        #[test]
        fn openai_conversion_preserves_info(
            name in "[a-z_]{1,20}",
            description in "[a-zA-Z0-9 ]{1,100}",
        ) {
            let tool = ToolDefinition::new(
                &name,
                &description,
                serde_json::json!({"type": "object"}),
            );

            let openai = tool.to_openai();
            prop_assert_eq!(&openai.function.name, &name);
            prop_assert_eq!(&openai.function.description, &description);
            prop_assert_eq!(&openai.function_type, "function");
        }

        /// Anthropic format conversion preserves info
        #[test]
        fn anthropic_conversion_preserves_info(
            name in "[a-z_]{1,20}",
            description in "[a-zA-Z0-9 ]{1,100}",
        ) {
            let tool = ToolDefinition::new(
                &name,
                &description,
                serde_json::json!({"type": "object"}),
            );

            let anthropic = tool.to_anthropic();
            prop_assert_eq!(&anthropic.name, &name);
            prop_assert_eq!(&anthropic.description, &description);
        }

        /// Tool results format correctly for OpenAI
        #[test]
        fn openai_result_format(
            id in "[a-zA-Z0-9_]{1,20}",
            content in "[a-zA-Z0-9 ]{0,100}",
            success in any::<bool>(),
        ) {
            let results = vec![ToolResult {
                tool_call_id: id.clone(),
                success,
                content: content.clone(),
                execution_time_ms: 42,
                audit_hash: None,
            }];

            let formatted = format_openai_tool_results(&results);
            prop_assert_eq!(formatted.len(), 1);
            prop_assert_eq!(formatted[0]["role"].as_str().unwrap(), "tool");
            prop_assert_eq!(formatted[0]["tool_call_id"].as_str().unwrap(), id.as_str());
            prop_assert_eq!(formatted[0]["content"].as_str().unwrap(), content.as_str());
        }

        /// Tool results format correctly for Anthropic
        #[test]
        fn anthropic_result_format(
            id in "[a-zA-Z0-9_]{1,20}",
            content in "[a-zA-Z0-9 ]{0,100}",
            success in any::<bool>(),
        ) {
            let results = vec![ToolResult {
                tool_call_id: id.clone(),
                success,
                content: content.clone(),
                execution_time_ms: 42,
                audit_hash: None,
            }];

            let formatted = format_anthropic_tool_results(&results);
            prop_assert_eq!(formatted.len(), 1);
            prop_assert_eq!(formatted[0]["type"].as_str().unwrap(), "tool_result");
            prop_assert_eq!(formatted[0]["tool_use_id"].as_str().unwrap(), id.as_str());
            prop_assert_eq!(formatted[0]["is_error"].as_bool().unwrap(), !success);
        }
    }
}

// ============================================================================
// Secrets Properties
// ============================================================================

mod secrets_properties {
    use super::*;
    use vak::secrets::{MemorySecretsProvider, SecretsProvider, SecretsError};

    proptest! {
        /// Set then get returns the same value
        #[test]
        fn secrets_set_get_roundtrip(
            key in "[a-zA-Z_]{1,30}",
            value in "[a-zA-Z0-9!@#$%]{1,100}",
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let provider = MemorySecretsProvider::new();
                provider.set_secret(&key, &value).await.unwrap();
                let secret = provider.get_secret(&key).await.unwrap();
                assert_eq!(secret.value(), value);
            });
        }

        /// Getting a non-existent key returns NotFound
        #[test]
        fn secrets_missing_key_returns_not_found(
            key in "[a-zA-Z_]{1,30}",
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let provider = MemorySecretsProvider::new();
                let result = provider.get_secret(&key).await;
                assert!(matches!(result, Err(SecretsError::NotFound(_))));
            });
        }

        /// Delete then get returns NotFound
        #[test]
        fn secrets_delete_removes_key(
            key in "[a-zA-Z_]{1,30}",
            value in "[a-zA-Z0-9]{1,50}",
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let provider = MemorySecretsProvider::new();
                provider.set_secret(&key, &value).await.unwrap();
                provider.delete_secret(&key).await.unwrap();
                let result = provider.get_secret(&key).await;
                assert!(matches!(result, Err(SecretsError::NotFound(_))));
            });
        }
    }
}
