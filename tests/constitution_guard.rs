//! The constitution on the request path (docs/adr/0018, finding K5).
//!
//! `ConstitutionalEngine` existed but `Kernel::execute` never called it.
//! With `policy.constitution` it runs as the first guard. Each test drives
//! `Kernel::execute`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
use vak::kernel::guard::Assurance;
use vak::kernel::types::{
    AgentId, AuditEntry, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse,
};
use vak::kernel::{
    AgentRecord, Constitution, ConstitutionConfig, ConstitutionGuard, ConstitutionalEngine,
    ConstitutionalRule, ConstraintOp, EnforcementPoint, Guard, Kernel, KernelConfig, ToolHandler,
};

fn violated(entry: &AuditEntry) -> Vec<String> {
    match &entry.decision {
        PolicyDecision::Deny {
            violated_policies, ..
        } => violated_policies.clone().unwrap_or_default(),
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// A tool named `name` that counts its runs.
fn counting(name: &'static str, runs: Arc<AtomicUsize>) -> impl ToolHandler + 'static {
    FunctionHandler::new(name, move |req: &ToolRequest, _agent: &AgentId| {
        let runs = runs.clone();
        let id = req.request_id;
        Box::pin(async move {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResponse::success(id, serde_json::json!("ran"), 0))
        }) as HandlerFuture
    })
}

/// A kernel that allows `format_disk` and `read_file`, with the constitution on.
async fn kernel(runs: &Arc<AtomicUsize>, configure: impl FnOnce(&mut KernelConfig)) -> Kernel {
    let mut config = KernelConfig::default();
    config.security.allowed_tools = vec!["format_disk".into(), "read_file".into()];
    config.policy.constitution = true;
    configure(&mut config);
    Kernel::builder(config)
        .with_tool(counting("format_disk", runs.clone()))
        .with_tool(counting("read_file", runs.clone()))
        .build()
        .await
        .unwrap()
}

async fn call(
    kernel: &Kernel,
    tool: &str,
    args: serde_json::Value,
) -> Result<ToolResponse, KernelError> {
    let agent = AgentId::new();
    kernel
        .register_agent(AgentRecord::new(agent, "worker"))
        .await
        .unwrap();
    kernel
        .execute(&agent, &SessionId::new(), ToolRequest::new(tool, args))
        .await
}

#[tokio::test]
async fn the_constitution_refuses_what_its_rules_forbid() {
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(&runs, |_| {}).await;

    // R-001: a destructive action, though the policy allows the tool.
    let result = call(&kernel, "format_disk", serde_json::json!({"disk": "sda"})).await;
    assert!(
        matches!(&result, Err(KernelError::PolicyViolation { policy_id, .. }) if policy_id == "guard.constitution"),
        "{result:?}"
    );
    assert_eq!(
        violated(kernel.get_audit_log().await.last().unwrap()),
        ["guard.constitution"]
    );

    // R-003: any argument naming credentials.
    let result = call(
        &kernel,
        "read_file",
        serde_json::json!({"path": "/srv/credentials.json"}),
    )
    .await;
    assert!(
        matches!(&result, Err(KernelError::PolicyViolation { reason, .. }) if reason.contains("R-003")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0, "neither ran");

    // A call no rule objects to runs. The constitution abstains: R-003
    // always has a resource to read, so it doesn't deny for lack of one.
    let ok = call(
        &kernel,
        "read_file",
        serde_json::json!({"path": "/srv/report.txt"}),
    )
    .await
    .unwrap();
    assert!(ok.success);
    assert_eq!(runs.load(Ordering::SeqCst), 1);

    // Off by default: the same call to format_disk runs.
    let plain = {
        let mut config = KernelConfig::default();
        config.security.allowed_tools = vec!["format_disk".into()];
        Kernel::builder(config)
            .with_tool(counting("format_disk", runs.clone()))
            .build()
            .await
            .unwrap()
    };
    assert!(
        call(&plain, "format_disk", serde_json::json!({}))
            .await
            .unwrap()
            .success
    );
}

#[tokio::test]
async fn abstaining_never_satisfies_an_assurance_floor() {
    // Its rules are a blocklist: finding nothing wrong isn't a check that
    // the call is right, so it must not count as an enforced pass.
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(&runs, |config| {
        config.policy.min_assurance =
            BTreeMap::from([("read_file".to_string(), Assurance::Enforced)]);
    })
    .await;
    let result = call(
        &kernel,
        "read_file",
        serde_json::json!({"path": "/srv/report.txt"}),
    )
    .await;
    assert!(
        matches!(&result, Err(KernelError::PolicyViolation { policy_id, .. }) if policy_id == "policy.min_assurance"),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_rule_needing_review_escalates_and_is_refused() {
    let mut constitution = Constitution::default_safety_constitution();
    constitution
        .add_rule(
            ConstitutionalRule::new(
                "R-REVIEW",
                "P-005",
                "Bulk exports need a human",
                ConstraintOp::NotEquals {
                    field: "parameters.mode".to_string(),
                    value: serde_json::json!("bulk"),
                },
            )
            .with_enforcement_point(EnforcementPoint::PreExecution)
            .with_blocking(false)
            .with_human_review(true),
        )
        .unwrap();
    // Human review is on in the strict config; the default turns it off,
    // and the rule is then a warning.
    let guarded = |config: ConstitutionConfig| {
        ConstitutionGuard::new(ConstitutionalEngine::new(config, constitution.clone())).unwrap()
    };
    let guard = guarded(ConstitutionConfig::strict());
    assert_eq!(
        (guard.name(), guard.assurance()),
        ("constitution", Assurance::Enforced)
    );

    let runs = Arc::new(AtomicUsize::new(0));
    let build = |guard: ConstitutionGuard| {
        let mut config = KernelConfig::default();
        config.security.allowed_tools = vec!["read_file".into()];
        Kernel::builder(config)
            .with_guard(Arc::new(guard))
            .with_tool(counting("read_file", runs.clone()))
            .build()
    };
    let kernel = build(guard).await.unwrap();
    let result = call(&kernel, "read_file", serde_json::json!({"mode": "bulk"})).await;
    assert!(
        matches!(&result, Err(KernelError::PolicyViolation { reason, .. }) if reason.contains("approval")),
        "{result:?}"
    );
    assert!(
        call(&kernel, "read_file", serde_json::json!({"mode": "one"}))
            .await
            .unwrap()
            .success
    );

    let lenient = build(guarded(ConstitutionConfig::default())).await.unwrap();
    assert!(
        call(&lenient, "read_file", serde_json::json!({"mode": "bulk"}))
            .await
            .unwrap()
            .success
    );
}

#[tokio::test]
async fn post_execution_rules_wait_and_dotted_fields_resolve() {
    let mut constitution = Constitution::default_safety_constitution();
    // A post-execution rule reads an outcome. Before the call runs there is
    // none, and a blocking rule evaluated then would deny every call.
    constitution
        .add_rule(
            ConstitutionalRule::new(
                "R-POST",
                "P-002",
                "Outcomes are recorded",
                ConstraintOp::Exists {
                    field: "outcome.recorded".to_string(),
                },
            )
            .with_enforcement_point(EnforcementPoint::PostExecution),
        )
        .unwrap();
    // Exists resolves dotted paths; it used to look them up as one key.
    constitution
        .add_rule(
            ConstitutionalRule::new(
                "R-NAMED",
                "P-002",
                "Calls come from a named agent",
                ConstraintOp::Exists {
                    field: "agent.name".to_string(),
                },
            )
            .with_enforcement_point(EnforcementPoint::PrePolicy),
        )
        .unwrap();
    let runs = Arc::new(AtomicUsize::new(0));
    let mut config = KernelConfig::default();
    config.security.allowed_tools = vec!["read_file".into()];
    let kernel = Kernel::builder(config)
        .with_guard(Arc::new(
            ConstitutionGuard::new(ConstitutionalEngine::new(
                ConstitutionConfig::default(),
                constitution,
            ))
            .unwrap(),
        ))
        .with_tool(counting("read_file", runs.clone()))
        .build()
        .await
        .unwrap();
    assert!(
        call(&kernel, "read_file", serde_json::json!({}))
            .await
            .unwrap()
            .success
    );
}

#[test]
fn a_tampered_constitution_is_refused() {
    // The hash covered rules' IDs and descriptions only: a rule's
    // constraint could be emptied and the constitution still verified.
    let mut constitution = Constitution::default_safety_constitution();
    assert!(constitution.verify_integrity());
    constitution.rules[0].constraint = ConstraintOp::NotIn {
        field: "action".to_string(),
        values: vec![],
    };
    assert!(!constitution.verify_integrity());
    let mut unblocked = Constitution::default_safety_constitution();
    unblocked.rules[2].blocking = false;
    assert!(!unblocked.verify_integrity());
    let mut mutable = Constitution::default_safety_constitution();
    mutable.principles[0].immutable = !mutable.principles[0].immutable;
    assert!(!mutable.verify_integrity());

    let err = ConstitutionGuard::new(ConstitutionalEngine::new(
        ConstitutionConfig::default(),
        constitution,
    ))
    .unwrap_err();
    assert!(err.to_string().contains("integrity"), "{err}");
    assert_eq!(
        ConstitutionGuard::default_safety()
            .constitution()
            .rules
            .len(),
        5
    );
}
