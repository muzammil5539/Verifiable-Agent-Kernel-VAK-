//! Benchmarks for the VAK Kernel
//!
//! Run with: `cargo bench`
//!
//! These benchmarks measure the performance of critical kernel operations:
//! - Kernel initialization and configuration
//! - Policy evaluation under various conditions (Issue #17)
//! - Audit logging with hash chain computation
//! - Signed audit entries with ed25519 (Issue #51)
//! - Tool request creation and processing
//! - Rate limiting overhead
//! - Concurrent policy evaluation
//! - Memory state operations across tiers (TST-005)
//! - Knowledge graph entity/relationship/traversal (TST-005)
//! - LLM integration tool definition generation (TST-005)
//! - Migration system performance (TST-005)
//! - Secrets management with caching (Issue #37)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
use rusqlite::Connection;
use tokio::runtime::Runtime;

use vak::audit::{AuditDecision, AuditLogger};
use vak::kernel::config::KernelConfig;
use vak::kernel::types::{AgentId, PolicyDecision, SessionId, ToolRequest};
use vak::kernel::Kernel;
use vak::policy::{
    ConditionOperator, PolicyCondition, PolicyContext, PolicyEffect, PolicyEngine, PolicyRule,
    RateLimitConfig,
};

/// Benchmark kernel initialization with default configuration.
///
/// Measures the time to create a new kernel instance, which includes
/// setting up internal data structures and validating configuration.
fn bench_kernel_init(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("kernel_init_default", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = KernelConfig::default();
                black_box(Kernel::new(config).await.unwrap())
            })
        })
    });
}

/// Benchmark kernel initialization with custom configuration.
fn bench_kernel_init_custom_config(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("kernel_init_custom", |b| {
        b.iter(|| {
            rt.block_on(async {
                let config = KernelConfig::builder()
                    .name("benchmark-kernel")
                    .max_concurrent_agents(100)
                    .build();
                black_box(Kernel::new(config).await.unwrap())
            })
        })
    });
}

/// Benchmark policy evaluation with a simple allow rule.
///
/// This measures the base performance of policy evaluation when
/// a matching allow rule is found immediately.
fn bench_policy_evaluation_simple(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();

    // Add a simple allow rule
    engine.add_rule(PolicyRule {
        id: "allow-read".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "data/*".to_string(),
        action_pattern: "read".to_string(),
        conditions: vec![],
        priority: 10,
        description: Some("Allow read access to data".to_string()),
    });

    let context = PolicyContext {
        agent_id: "bench-agent".to_string(),
        role: "user".to_string(),
        attributes: HashMap::new(),
        environment: HashMap::new(),
    };

    c.bench_function("policy_eval_simple_allow", |b| {
        b.iter(|| black_box(engine.evaluate("data/test.txt", "read", &context)))
    });
}

/// Benchmark policy evaluation with conditions.
///
/// Measures performance when policy rules include condition checks
/// that must be evaluated against the context attributes.
fn bench_policy_evaluation_with_conditions(c: &mut Criterion) {
    let mut engine = PolicyEngine::new();

    // Add a rule with multiple conditions
    engine.add_rule(PolicyRule {
        id: "conditional-access".to_string(),
        effect: PolicyEffect::Allow,
        resource_pattern: "secure/*".to_string(),
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
                value: serde_json::json!(3),
            },
        ],
        priority: 100,
        description: Some("Admin access with clearance".to_string()),
    });

    let mut attributes = HashMap::new();
    attributes.insert("clearance".to_string(), serde_json::json!(5));

    let context = PolicyContext {
        agent_id: "bench-admin".to_string(),
        role: "admin".to_string(),
        attributes,
        environment: HashMap::new(),
    };

    c.bench_function("policy_eval_with_conditions", |b| {
        b.iter(|| black_box(engine.evaluate("secure/classified.doc", "read", &context)))
    });
}

/// Benchmark policy evaluation with many rules.
///
/// Measures how policy evaluation scales as the number of rules increases.
fn bench_policy_evaluation_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("policy_eval_scaling");

    for rule_count in [10, 50, 100, 500].iter() {
        let mut engine = PolicyEngine::new();

        // Add many rules with decreasing priority
        for i in 0..*rule_count {
            engine.add_rule(PolicyRule {
                id: format!("rule-{}", i),
                effect: if i % 2 == 0 {
                    PolicyEffect::Allow
                } else {
                    PolicyEffect::Deny
                },
                resource_pattern: format!("resource-{}/*", i),
                action_pattern: "*".to_string(),
                conditions: vec![],
                priority: (*rule_count - i) as i32,
                description: None,
            });
        }

        // Add a matching rule at the end (lowest priority)
        engine.add_rule(PolicyRule {
            id: "target-rule".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "target/*".to_string(),
            action_pattern: "execute".to_string(),
            conditions: vec![],
            priority: 1,
            description: None,
        });

        let context = PolicyContext {
            agent_id: "bench-agent".to_string(),
            role: "user".to_string(),
            attributes: HashMap::new(),
            environment: HashMap::new(),
        };

        group.throughput(Throughput::Elements(1));
        group.bench_with_input(
            BenchmarkId::from_parameter(rule_count),
            rule_count,
            |b, _| b.iter(|| black_box(engine.evaluate("target/test.dat", "execute", &context))),
        );
    }

    group.finish();
}

/// Benchmark audit logging with hash chain computation.
///
/// Measures the overhead of creating audit entries with
/// cryptographic hash chaining for tamper detection.
fn bench_audit_logging(c: &mut Criterion) {
    c.bench_function("audit_log_single_entry", |b| {
        let mut logger = AuditLogger::new();

        b.iter(|| {
            let entry = logger.log(
                "agent-001",
                "read",
                "/data/test.txt",
                AuditDecision::Allowed,
            );
            black_box(entry.id)
        })
    });
}

/// Benchmark audit chain verification.
///
/// Measures the time to verify the integrity of the audit chain
/// after logging multiple entries.
fn bench_audit_chain_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("audit_chain_verify");

    for entry_count in [10, 100, 1000].iter() {
        let mut logger = AuditLogger::new();

        // Pre-populate the audit log
        for i in 0..*entry_count {
            logger.log(
                format!("agent-{}", i % 10),
                "execute",
                format!("/resource/{}", i),
                if i % 3 == 0 {
                    AuditDecision::Denied
                } else {
                    AuditDecision::Allowed
                },
            );
        }

        group.throughput(Throughput::Elements(*entry_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(entry_count),
            entry_count,
            |b, _| b.iter(|| black_box(logger.verify_chain().is_ok())),
        );
    }

    group.finish();
}

/// Benchmark tool request creation and hash computation.
///
/// Measures the overhead of creating tool requests with
/// integrity hash computation.
fn bench_tool_request_creation(c: &mut Criterion) {
    c.bench_function("tool_request_new", |b| {
        b.iter(|| {
            let request = ToolRequest::new(
                "calculator",
                serde_json::json!({
                    "operation": "add",
                    "operands": [42, 58]
                }),
            );
            black_box(request)
        })
    });
}

/// Benchmark tool request hash computation.
fn bench_tool_request_hash(c: &mut Criterion) {
    let request = ToolRequest::new(
        "data_processor",
        serde_json::json!({
            "action": "transform",
            "data": vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            "config": {
                "normalize": true,
                "scale": 1.5
            }
        }),
    );

    c.bench_function("tool_request_compute_hash", |b| {
        b.iter(|| black_box(request.compute_hash()))
    });
}

/// Benchmark full kernel execute flow (policy + audit).
fn bench_kernel_execute(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    // Pre-create kernel
    let kernel = rt.block_on(async { Kernel::new(KernelConfig::default()).await.unwrap() });

    c.bench_function("kernel_execute_full", |b| {
        b.iter(|| {
            rt.block_on(async {
                let agent_id = AgentId::new();
                let session_id = SessionId::new();
                let request = ToolRequest::new("test_tool", serde_json::json!({"param": "value"}));

                black_box(kernel.execute(&agent_id, &session_id, request).await)
            })
        })
    });
}

/// Benchmark AgentId and SessionId creation.
fn bench_id_creation(c: &mut Criterion) {
    c.bench_function("agent_id_new", |b| b.iter(|| black_box(AgentId::new())));

    c.bench_function("session_id_new", |b| b.iter(|| black_box(SessionId::new())));
}

/// Benchmark PolicyDecision helper methods.
fn bench_policy_decision_checks(c: &mut Criterion) {
    let allow = PolicyDecision::Allow {
        reason: "Authorized".to_string(),
        constraints: None,
    };
    let deny = PolicyDecision::Deny {
        reason: "Unauthorized".to_string(),
        violated_policies: Some(vec!["policy-1".to_string()]),
    };

    c.bench_function("policy_decision_is_allowed", |b| {
        b.iter(|| {
            black_box(allow.is_allowed());
            black_box(deny.is_allowed());
        })
    });
}

/// Benchmark rate limiting overhead (Issue #13).
fn bench_rate_limiting(c: &mut Criterion) {
    let mut group = c.benchmark_group("rate_limiting");

    // Without rate limiting
    let engine_unlimited = PolicyEngine::new_unlimited();
    let context = PolicyContext {
        agent_id: "bench-agent".to_string(),
        role: "user".to_string(),
        attributes: HashMap::new(),
        environment: HashMap::new(),
    };

    group.bench_function("policy_eval_no_rate_limit", |b| {
        b.iter(|| black_box(engine_unlimited.evaluate("test", "read", &context)))
    });

    // With rate limiting enabled (permissive limits for benchmark)
    let config = RateLimitConfig {
        per_agent_per_second: 100000,
        burst_size: 10000,
        enabled: true,
    };
    let engine_limited = PolicyEngine::with_rate_limit(config);

    group.bench_function("policy_eval_with_rate_limit", |b| {
        b.iter(|| {
            black_box(
                engine_limited
                    .evaluate_with_rate_limit("test", "read", &context)
                    .unwrap(),
            )
        })
    });

    group.finish();
}

/// Benchmark concurrent policy evaluations.
fn bench_concurrent_policy_evaluation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_policy");

    for agent_count in [1, 10, 50].iter() {
        let mut engine = PolicyEngine::new_unlimited();
        engine.add_rule(PolicyRule {
            id: "allow-all".to_string(),
            effect: PolicyEffect::Allow,
            resource_pattern: "*".to_string(),
            action_pattern: "*".to_string(),
            conditions: vec![],
            priority: 1,
            description: None,
        });

        let engine = std::sync::Arc::new(engine);

        group.throughput(Throughput::Elements(*agent_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(agent_count),
            agent_count,
            |b, &agent_count| {
                b.iter(|| {
                    rt.block_on(async {
                        let mut handles = Vec::new();
                        for i in 0..agent_count {
                            let engine = engine.clone();
                            handles.push(tokio::spawn(async move {
                                let ctx = PolicyContext {
                                    agent_id: format!("agent-{}", i),
                                    role: "user".to_string(),
                                    attributes: HashMap::new(),
                                    environment: HashMap::new(),
                                };
                                engine.evaluate("resource", "action", &ctx)
                            }));
                        }
                        for handle in handles {
                            black_box(handle.await.unwrap());
                        }
                    })
                })
            },
        );
    }

    group.finish();
}

/// Benchmark policy validation (Issue #19).
fn bench_policy_validation(c: &mut Criterion) {
    let mut engine = PolicyEngine::new_unlimited();

    // Add various rules
    for i in 0..100 {
        engine.add_rule(PolicyRule {
            id: format!("rule-{}", i),
            effect: if i % 2 == 0 {
                PolicyEffect::Allow
            } else {
                PolicyEffect::Deny
            },
            resource_pattern: format!("resource-{}/*", i),
            action_pattern: "*".to_string(),
            conditions: vec![],
            priority: i as i32,
            description: None,
        });
    }

    c.bench_function("policy_validate_config", |b| {
        b.iter(|| black_box(engine.validate_config()))
    });
}


/// Benchmark memory state operations across tiers (TST-005).
///
/// Measures set/get performance for ephemeral and merkle tiers,
/// as well as cascading lookups that search multiple tiers.
fn bench_memory_state_operations(c: &mut Criterion) {
    use vak::memory::{agent_key, StateManager, StateManagerConfig, StateTier};

    let manager = StateManager::new(StateManagerConfig::default());

    let mut group = c.benchmark_group("memory_operations");

    group.bench_function("ephemeral_set", |b| {
        let mut i = 0u64;
        b.iter(|| {
            let key = agent_key("bench-agent", &format!("key_{}", i));
            manager
                .set_state(&key, black_box(b"benchmark_value".to_vec()), StateTier::Ephemeral)
                .unwrap();
            i += 1;
        })
    });

    group.bench_function("ephemeral_get", |b| {
        let key = agent_key("bench-agent", "bench_key");
        manager
            .set_state(&key, b"benchmark_value".to_vec(), StateTier::Ephemeral)
            .unwrap();

        b.iter(|| {
            black_box(manager.get_state(&key, StateTier::Ephemeral).unwrap());
        })
    });

    group.bench_function("merkle_set", |b| {
        let mut i = 0u64;
        b.iter(|| {
            let key = agent_key("bench-agent", &format!("merkle_key_{}", i));
            manager
                .set_state(&key, black_box(b"verified_value".to_vec()), StateTier::Merkle)
                .unwrap();
            i += 1;
        })
    });

    group.bench_function("cascading_get", |b| {
        let key = agent_key("bench-agent", "cascade_key");
        manager
            .set_state(&key, b"cascade_value".to_vec(), StateTier::Merkle)
            .unwrap();

        b.iter(|| {
            black_box(manager.get_state_cascading(&key).unwrap());
        })
    });

    group.finish();
}

/// Benchmark audit logging with grouped sub-benchmarks (TST-005).
///
/// Extends the existing audit benchmarks with grouped log_entry
/// and chain verification benchmarks at different scales.
fn bench_audit_logging_grouped(c: &mut Criterion) {
    use vak::audit::{AuditDecision, AuditLogger};

    let mut group = c.benchmark_group("audit_operations");

    group.bench_function("log_entry", |b| {
        let mut logger = AuditLogger::new();
        b.iter(|| {
            logger.log(
                black_box("bench-agent"),
                black_box("read"),
                black_box("/data/file.txt"),
                AuditDecision::Allowed,
            );
        })
    });

    group.bench_function("verify_chain_10", |b| {
        let mut logger = AuditLogger::new();
        for i in 0..10 {
            logger.log(&format!("agent-{}", i), "read", "/data/file.txt", AuditDecision::Allowed);
        }
        b.iter(|| {
            let _ = black_box(logger.verify_chain());
        })
    });

    group.bench_function("verify_chain_100", |b| {
        let mut logger = AuditLogger::new();
        for i in 0..100 {
            logger.log(&format!("agent-{}", i), "read", "/data/file.txt", AuditDecision::Allowed);
        }
        b.iter(|| {
            let _ = black_box(logger.verify_chain());
        })
    });

    group.finish();
}

/// Benchmark tool definition generation for LLM integration (TST-005).
///
/// Measures performance of generating built-in tool definitions and
/// converting them to OpenAI and Anthropic formats.
fn bench_tool_definitions(c: &mut Criterion) {
    use vak::lib_integration::builtin_tool_definitions;

    let mut group = c.benchmark_group("tool_definitions");

    group.bench_function("builtin_definitions", |b| {
        b.iter(|| {
            black_box(builtin_tool_definitions());
        })
    });

    group.bench_function("to_openai_format", |b| {
        let tools = builtin_tool_definitions();
        b.iter(|| {
            let _: Vec<_> = tools.iter().map(|t| black_box(t.to_openai())).collect();
        })
    });

    group.bench_function("to_anthropic_format", |b| {
        let tools = builtin_tool_definitions();
        b.iter(|| {
            let _: Vec<_> = tools.iter().map(|t| black_box(t.to_anthropic())).collect();
        })
    });

    group.bench_function("tool_definition_serialization", |b| {
        let tools = builtin_tool_definitions();
        b.iter(|| {
            black_box(serde_json::to_string(&tools).unwrap());
        })
    });

    group.finish();
}

/// Benchmark migration system performance (TST-005).
///
/// Measures the time to run all migrations on a fresh in-memory
/// database and check migration status.
fn bench_migrations(c: &mut Criterion) {
    use vak::memory::migrations::MigrationRunner;

    let mut group = c.benchmark_group("migrations");

    group.bench_function("run_all_migrations", |b| {
        b.iter(|| {
            let conn = Connection::open_in_memory().unwrap();
            let runner = MigrationRunner::new(&conn).unwrap();
            black_box(runner.run_all().unwrap());
        })
    });

    group.bench_function("migration_status_check", |b| {
        let conn = Connection::open_in_memory().unwrap();
        let runner = MigrationRunner::new(&conn).unwrap();
        runner.run_all().unwrap();

        b.iter(|| {
            black_box(runner.status().unwrap());
        })
    });

    group.finish();
}

/// Benchmark knowledge graph operations (TST-005).
///
/// Measures entity insertion, relationship creation, traversal,
/// and search performance on graphs of varying sizes.
fn bench_knowledge_graph(c: &mut Criterion) {
    use vak::memory::knowledge_graph::{Entity, KnowledgeGraph, Relationship, RelationType};

    let mut group = c.benchmark_group("knowledge_graph");

    // Entity insertion
    group.bench_function("add_entity", |b| {
        let mut kg = KnowledgeGraph::new("bench");
        let mut i = 0u64;
        b.iter(|| {
            let entity = Entity::new(format!("entity_{}", i), "Server")
                .with_property("ip", format!("10.0.0.{}", i % 255));
            black_box(kg.add_entity(entity).unwrap());
            i += 1;
        })
    });

    // Relationship creation
    group.bench_function("add_relationship", |b| {
        let mut kg = KnowledgeGraph::new("bench");
        let mut entities = Vec::new();
        for i in 0..200 {
            let entity = Entity::new(format!("node_{}", i), "Node");
            entities.push(kg.add_entity(entity).unwrap());
        }

        let mut i = 0u64;
        b.iter(|| {
            let src = entities[(i as usize) % entities.len()].clone();
            let tgt = entities[((i as usize) + 1) % entities.len()].clone();
            let _ = black_box(kg.add_relationship(Relationship::new(
                src,
                tgt,
                RelationType::DependsOn,
            )));
            i += 1;
        })
    });

    // Entity lookup by name
    group.bench_function("get_entity_by_name_100", |b| {
        let mut kg = KnowledgeGraph::new("bench");
        for i in 0..100 {
            let entity = Entity::new(format!("server_{}", i), "Server");
            kg.add_entity(entity).unwrap();
        }

        b.iter(|| {
            black_box(kg.get_entity_by_name("server_50"));
        })
    });

    // Graph traversal (get_related)
    group.bench_function("get_related", |b| {
        let mut kg = KnowledgeGraph::new("bench");
        let root = kg.add_entity(Entity::new("root", "Root")).unwrap();
        for i in 0..50 {
            let child = kg
                .add_entity(Entity::new(format!("child_{}", i), "Child"))
                .unwrap();
            let _ = kg.add_relationship(Relationship::new(
                root.clone(),
                child,
                RelationType::HostsService,
            ));
        }

        b.iter(|| {
            black_box(kg.get_related(root.clone(), Some(RelationType::HostsService)));
        })
    });

    // Graph hash computation
    group.bench_function("compute_hash", |b| {
        let mut kg = KnowledgeGraph::new("bench");
        for i in 0..50 {
            let entity = Entity::new(format!("e_{}", i), "Type")
                .with_property("key", format!("val_{}", i));
            kg.add_entity(entity).unwrap();
        }

        b.iter(|| {
            black_box(kg.compute_hash());
        })
    });

    group.finish();
}

/// Benchmark signed audit entries (TST-005, Issue #51).
///
/// Measures the overhead of ed25519 signing and verification
/// on audit log entries.
fn bench_signed_audit(c: &mut Criterion) {
    use vak::audit::{AuditDecision, AuditLogger, AuditSigner};

    let mut group = c.benchmark_group("signed_audit");

    // Signing overhead
    group.bench_function("log_with_signing", |b| {
        let mut logger = AuditLogger::new_with_signing();
        b.iter(|| {
            logger.log(
                black_box("agent-001"),
                black_box("execute"),
                black_box("/tool/calculator"),
                AuditDecision::Allowed,
            );
        })
    });

    // Signing vs unsigned comparison
    group.bench_function("log_without_signing", |b| {
        let mut logger = AuditLogger::new();
        b.iter(|| {
            logger.log(
                black_box("agent-001"),
                black_box("execute"),
                black_box("/tool/calculator"),
                AuditDecision::Allowed,
            );
        })
    });

    // Signature verification
    group.bench_function("verify_signatures_100", |b| {
        let mut logger = AuditLogger::new_with_signing();
        for i in 0..100 {
            logger.log(
                &format!("agent-{}", i % 10),
                "action",
                &format!("/res/{}", i),
                AuditDecision::Allowed,
            );
        }
        b.iter(|| {
            black_box(logger.verify_all(None).is_ok());
        })
    });

    // Raw signer performance
    group.bench_function("signer_sign_hash", |b| {
        let signer = AuditSigner::new();
        let hash = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        b.iter(|| {
            black_box(signer.sign(hash));
        })
    });

    group.finish();
}

/// Benchmark secrets management operations (TST-005, Issue #37).
///
/// Measures performance of secrets storage, retrieval, and caching.
fn bench_secrets(c: &mut Criterion) {
    use vak::secrets::{MemorySecretsProvider, SecretsManager};

    let rt = Runtime::new().unwrap();
    let mut group = c.benchmark_group("secrets");

    // Secret storage
    group.bench_function("set_secret", |b| {
        let provider = MemorySecretsProvider::new();
        let manager = SecretsManager::new(Box::new(provider));
        let mut i = 0u64;
        b.iter(|| {
            rt.block_on(async {
                manager
                    .set_secret(&format!("key_{}", i), &format!("value_{}", i))
                    .await
                    .unwrap();
            });
            i += 1;
        })
    });

    // Secret retrieval (uncached)
    group.bench_function("get_secret_uncached", |b| {
        let provider = MemorySecretsProvider::new();
        let manager = SecretsManager::new(Box::new(provider));
        rt.block_on(async {
            manager
                .set_secret("bench_key", "bench_value")
                .await
                .unwrap();
        });
        b.iter(|| {
            rt.block_on(async {
                manager.clear_cache();
                black_box(manager.get_secret("bench_key").await.unwrap());
            })
        })
    });

    // Secret retrieval (cached)
    group.bench_function("get_secret_cached", |b| {
        let provider = MemorySecretsProvider::new();
        let manager = SecretsManager::new(Box::new(provider));
        rt.block_on(async {
            manager
                .set_secret("bench_key", "bench_value")
                .await
                .unwrap();
            // Warm the cache
            let _ = manager.get_secret("bench_key").await;
        });
        b.iter(|| {
            rt.block_on(async {
                black_box(manager.get_secret("bench_key").await.unwrap());
            })
        })
    });

    // List keys with many secrets
    group.bench_function("list_keys_100", |b| {
        let provider = MemorySecretsProvider::new();
        let manager = SecretsManager::new(Box::new(provider));
        rt.block_on(async {
            for i in 0..100 {
                manager
                    .set_secret(&format!("key_{}", i), &format!("val_{}", i))
                    .await
                    .unwrap();
            }
        });
        b.iter(|| {
            rt.block_on(async {
                black_box(manager.list_keys().await.unwrap());
            })
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_kernel_init,
    bench_kernel_init_custom_config,
    bench_policy_evaluation_simple,
    bench_policy_evaluation_with_conditions,
    bench_policy_evaluation_scaling,
    bench_audit_logging,
    bench_audit_chain_verification,
    bench_tool_request_creation,
    bench_tool_request_hash,
    bench_kernel_execute,
    bench_id_creation,
    bench_policy_decision_checks,
    bench_rate_limiting,
    bench_concurrent_policy_evaluation,
    bench_policy_validation,
    bench_memory_state_operations,
    bench_audit_logging_grouped,
    bench_tool_definitions,
    bench_migrations,
    bench_knowledge_graph,
    bench_signed_audit,
    bench_secrets,
);
criterion_main!(benches);
