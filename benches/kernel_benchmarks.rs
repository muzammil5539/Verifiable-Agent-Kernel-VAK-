//! Benchmarks for the VAK Kernel
//!
//! Run with: `cargo bench`
//!
//! These benchmarks measure the performance of critical kernel operations:
//! - Kernel initialization and configuration
//! - Policy evaluation under various conditions (Issue #17)
//! - Audit logging with hash chain computation
//! - Tool request creation and processing
//! - Vector store operations
//! - Rate limiting overhead

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::collections::HashMap;
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
);
criterion_main!(benches);
