//! Datalog safety rules on the request path (docs/adr/0020, finding V3).
//!
//! `DatalogGuard` runs `reasoner::datalog`'s rules, now a Datalog program
//! evaluated by Ascent, as an enforced guard. Each test drives
//! `Kernel::execute`.
#![cfg(feature = "reasoner")]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
use vak::kernel::guard::{Assurance, GuardVerdict};
use vak::kernel::types::{
    AgentId, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse,
};
use vak::kernel::{AgentRecord, Guard, Kernel, KernelConfig, ToolHandler};
use vak::reasoner::datalog::DatalogGuard;
use vak::reasoner::{Fact, SafetyEngine};

const TOOLS: [&str; 5] = [
    "delete_file",
    "fs.read",
    "http_request",
    "execute_tool",
    "send_email",
];

/// A tool named `name` that counts its runs.
fn counting(name: &'static str, runs: Arc<AtomicUsize>) -> impl ToolHandler + 'static {
    FunctionHandler::new(name, move |req: &ToolRequest, _agent: &AgentId| {
        let runs = runs.clone();
        let id = req.request_id;
        Box::pin(async move {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResponse::success(id, serde_json::json!("done"), 0))
        }) as HandlerFuture
    })
}

/// A kernel that allows every tool in [`TOOLS`], guarded by `guard`.
async fn kernel(
    runs: &Arc<AtomicUsize>,
    guard: DatalogGuard,
    configure: impl FnOnce(&mut KernelConfig),
) -> Kernel {
    let mut config = KernelConfig::default();
    config.security.allowed_tools = TOOLS.iter().map(|t| (*t).to_string()).collect();
    configure(&mut config);
    let mut builder = Kernel::builder(config).with_guard(Arc::new(guard));
    for tool in TOOLS {
        builder = builder.with_tool(counting(tool, runs.clone()));
    }
    builder.build().await.unwrap()
}

async fn call(
    kernel: &Kernel,
    agent: AgentId,
    tool: &str,
    args: serde_json::Value,
) -> Result<ToolResponse, KernelError> {
    let _ = kernel
        .register_agent(AgentRecord::new(agent, "worker"))
        .await;
    kernel
        .execute(&agent, &SessionId::new(), ToolRequest::new(tool, args))
        .await
}

fn refused_by_guard(result: &Result<ToolResponse, KernelError>) -> &str {
    match result {
        Err(KernelError::PolicyViolation { policy_id, reason }) => {
            assert_eq!(policy_id, "guard.datalog", "{reason}");
            reason
        }
        other => panic!("expected the guard to refuse, got {other:?}"),
    }
}

fn ran(result: Result<ToolResponse, KernelError>) {
    assert!(result.unwrap().success);
}

#[tokio::test]
async fn a_rule_refuses_a_call_the_policy_allowed() {
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(&runs, DatalogGuard::default_rules(), |_| {}).await;
    let agent = AgentId::new();

    // An alias of a critical file, in a system path: two rules.
    let result = call(
        &kernel,
        agent,
        "delete_file",
        serde_json::json!({"path": "/etc//../etc/shadow"}),
    )
    .await;
    let reason = refused_by_guard(&result);
    assert!(
        reason.contains("RULE_001_CRITICAL_DELETE") && reason.contains("RULE_006_SYSTEM_PATH"),
        "{reason}"
    );
    let log = kernel.get_audit_log().await;
    let entry = log.last().unwrap();
    assert!(matches!(
        &entry.decision,
        PolicyDecision::Deny { violated_policies: Some(p), .. } if p == &["guard.datalog"]
    ));
    let check = entry.guards.as_ref().unwrap().checks.last().unwrap();
    assert_eq!(
        (check.guard.as_str(), check.assurance),
        ("datalog", Assurance::Enforced)
    );

    // Every target argument is checked, not just the first.
    let result = call(
        &kernel,
        agent,
        "delete_file",
        serde_json::json!({"path": "/tmp/x", "target": "/etc/passwd"}),
    )
    .await;
    assert!(refused_by_guard(&result).contains("RULE_001"));

    // A restricted command, by its leading words.
    let result = call(
        &kernel,
        agent,
        "execute_tool",
        serde_json::json!({"tool": "rm  -rf /"}),
    )
    .await;
    assert!(refused_by_guard(&result).contains("RULE_005_RESTRICTED_TOOL"));
    assert_eq!(runs.load(Ordering::SeqCst), 0, "nothing ran");

    ran(call(
        &kernel,
        agent,
        "delete_file",
        serde_json::json!({"path": "/tmp/scratch"}),
    )
    .await);
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_call_without_a_target_to_check_is_refused() {
    let runs = Arc::new(AtomicUsize::new(0));
    let guard = DatalogGuard::default_rules().with_tool("fs.read", "read_file", "filename");
    let kernel = kernel(&runs, guard, |_| {}).await;
    let agent = AgentId::new();

    let result = call(&kernel, agent, "delete_file", serde_json::json!({})).await;
    assert!(
        refused_by_guard(&result).contains("no target to check"),
        "{result:?}"
    );
    let result = call(
        &kernel,
        agent,
        "delete_file",
        serde_json::json!({"path": ["/etc/shadow"]}),
    )
    .await;
    assert!(refused_by_guard(&result).contains("isn't a string"));

    // A mapped tool: its action and argument are the mapping's.
    let result = call(
        &kernel,
        agent,
        "fs.read",
        serde_json::json!({"filename": "app/../.env"}),
    )
    .await;
    assert!(refused_by_guard(&result).contains("RULE_003_SENSITIVE_ACCESS"));
    let result = call(
        &kernel,
        agent,
        "fs.read",
        serde_json::json!({"path": "/srv/notes.txt"}),
    )
    .await;
    assert!(refused_by_guard(&result).contains("looked for filename"));
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    ran(call(
        &kernel,
        agent,
        "fs.read",
        serde_json::json!({"filename": "/srv/notes.txt"}),
    )
    .await);
}

#[tokio::test]
async fn negation_and_aggregation_decide_network_calls() {
    let (plain, trusted, risky) = (AgentId::new(), AgentId::new(), AgentId::new());
    let mut engine = SafetyEngine::new();
    for agent in [trusted, risky] {
        engine.add_fact(Fact::agent_capability(agent.to_string(), "network"));
    }
    engine.add_fact(Fact::agent_risk(risky.to_string(), 0.2));
    engine.add_fact(Fact::agent_risk(risky.to_string(), 0.9));
    engine.add_fact(Fact::external_endpoint("https://evil.com"));
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(&runs, DatalogGuard::new(engine).unwrap(), |_| {}).await;
    let fetch = |agent, url: &str| {
        let kernel = &kernel;
        let args = serde_json::json!({ "url": url });
        async move { call(kernel, agent, "http_request", args).await }
    };

    // No `network` capability: a negated atom.
    let result = fetch(plain, "https://example.org/").await;
    assert!(refused_by_guard(&result).contains("RULE_009_NETWORK_CAPABILITY"));
    // The highest of the agent's two scores.
    let result = fetch(risky, "https://example.org/").await;
    assert!(refused_by_guard(&result).contains("RULE_007_HIGH_RISK_NETWORK"));
    // An external endpoint, by host, whatever the spelling.
    let result = fetch(trusted, "HTTP://Evil.COM:8080/exfil").await;
    assert!(refused_by_guard(&result).contains("RULE_004_EXTERNAL_NETWORK"));
    assert_eq!(runs.load(Ordering::SeqCst), 0);

    ran(fetch(trusted, "https://example.org/").await);
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn warnings_escalate_and_the_guard_never_passes() {
    let wary = AgentId::new();
    let mut engine = SafetyEngine::new();
    engine.add_fact(Fact::agent_risk(wary.to_string(), 0.5));
    let guard = DatalogGuard::new(engine).unwrap();
    assert_eq!(
        (guard.name(), guard.assurance()),
        ("datalog", Assurance::Enforced)
    );
    let runs = Arc::new(AtomicUsize::new(0));
    let floored = kernel(&runs, guard, |config| {
        config.policy.min_assurance = BTreeMap::from([
            ("send_email".to_string(), Assurance::Enforced),
            ("delete_file".to_string(), Assurance::Enforced),
        ]);
    })
    .await;

    // Risk over the warning threshold, under the block one: review, which
    // the kernel refuses.
    let result = call(
        &floored,
        wary,
        "execute_tool",
        serde_json::json!({"tool": "ls"}),
    )
    .await;
    let reason = refused_by_guard(&result);
    assert!(reason.contains("approval"), "{reason}");
    let log = floored.get_audit_log().await;
    assert!(matches!(
        &log.last().unwrap().guards.as_ref().unwrap().checks[0].verdict,
        GuardVerdict::Escalate { reason } if reason.contains("0.50")
    ));

    // No rule fires: it abstains, which doesn't meet an enforced floor.
    // Nor does a tool no rule applies to.
    let calm = AgentId::new();
    for (tool, args) in [
        ("delete_file", serde_json::json!({"path": "/tmp/x"})),
        ("send_email", serde_json::json!({"to": "a@example.com"})),
    ] {
        let result = call(&floored, calm, tool, args).await;
        assert!(
            matches!(&result, Err(KernelError::PolicyViolation { policy_id, .. }) if policy_id == "policy.min_assurance"),
            "{tool}: {result:?}"
        );
        let log = floored.get_audit_log().await;
        assert_eq!(
            log.last().unwrap().guards.as_ref().unwrap().checks[0].verdict,
            GuardVerdict::Abstain
        );
    }
    assert_eq!(runs.load(Ordering::SeqCst), 0);

    // Without the floor, an uncovered tool runs.
    let open = kernel(&runs, DatalogGuard::default_rules(), |_| {}).await;
    ran(call(
        &open,
        calm,
        "send_email",
        serde_json::json!({"to": "a@example.com"}),
    )
    .await);
}
