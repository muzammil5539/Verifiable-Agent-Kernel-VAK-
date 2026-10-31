//! The Guard stage, driven through `Kernel::execute` (docs/adr/0013).
//!
//! Each test fails if a guard stops being able to refuse a call the policy
//! allowed, if a guard failure lets a call through, if a heuristic guard can
//! satisfy an `enforced` floor, if the policy's own allow counts toward a
//! floor, or if the decision's audit entry stops recording what each guard
//! said. Guards never see calls the policy denied.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
use vak::kernel::types::{
    AgentId, AuditEntry, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse,
};
use vak::kernel::{
    AgentRecord, Assurance, FunctionGuard, Guard, GuardCheck, GuardRequest, GuardVerdict, Kernel,
    KernelConfig, ToolHandler,
};

/// A host tool that counts how often it actually ran.
fn counting_tool(name: &'static str, runs: Arc<AtomicUsize>) -> impl ToolHandler + 'static {
    FunctionHandler::new(name, move |req: &ToolRequest, _agent: &AgentId| {
        let runs = runs.clone();
        let id = req.request_id;
        Box::pin(async move {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResponse::success(id, serde_json::json!("ran"), 0))
        }) as HandlerFuture
    })
}

/// A guard that always says `verdict`.
fn guard(name: &str, assurance: Assurance, verdict: GuardVerdict) -> Arc<dyn Guard> {
    Arc::new(FunctionGuard::new(name, assurance, move |_req| {
        verdict.clone()
    }))
}

/// A config that allows `tools`, plus the `min_assurance` floor given.
fn config(tools: &[&str], floor: &[(&str, Assurance)]) -> KernelConfig {
    let mut config = KernelConfig::default();
    config
        .security
        .allowed_tools
        .extend(tools.iter().map(|t| (*t).to_string()));
    for (pattern, level) in floor {
        config
            .policy
            .min_assurance
            .insert((*pattern).to_string(), *level);
    }
    config
}

/// Builds a kernel with a counting `pay:charge` tool and the given guards,
/// and registers one agent.
async fn kernel(
    config: KernelConfig,
    guards: Vec<Arc<dyn Guard>>,
    runs: Arc<AtomicUsize>,
) -> (Kernel, AgentId) {
    let mut builder = Kernel::builder(config).with_tool(counting_tool("pay:charge", runs));
    for g in guards {
        builder = builder.with_guard(g);
    }
    let kernel = builder.build().await.expect("kernel builds");
    let agent = AgentId::new();
    kernel
        .register_agent(AgentRecord::new(agent, "worker"))
        .await
        .expect("register");
    (kernel, agent)
}

fn charge() -> ToolRequest {
    ToolRequest::new("pay:charge", serde_json::json!({"amount": 10}))
}

/// The rules a recorded denial names.
fn violated(entry: &AuditEntry) -> Vec<String> {
    match &entry.decision {
        PolicyDecision::Deny {
            violated_policies, ..
        } => violated_policies.clone().unwrap_or_default(),
        other => panic!("expected a denial, got {other:?}"),
    }
}

fn verdicts(entry: &AuditEntry) -> Vec<(String, Assurance, GuardVerdict)> {
    entry
        .guards
        .as_ref()
        .expect("the entry records the guards")
        .checks
        .iter()
        .map(
            |GuardCheck {
                 guard,
                 assurance,
                 verdict,
             }| (guard.clone(), *assurance, verdict.clone()),
        )
        .collect()
}

// Guards can refuse what the policy allowed

#[tokio::test]
async fn a_guard_denial_refuses_an_allowed_call_and_is_recorded() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[]),
        vec![
            guard("rules", Assurance::Enforced, GuardVerdict::Pass),
            guard(
                "limits",
                Assurance::Checked,
                GuardVerdict::deny("over limit"),
            ),
            guard("never-runs", Assurance::Enforced, GuardVerdict::Pass),
        ],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, ref reason })
            if policy_id == "guard.limits" && reason.contains("over limit")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0, "the tool didn't run");

    let log = kernel.get_audit_log().await;
    assert_eq!(log.len(), 1, "one denial, no outcome");
    assert_eq!(violated(&log[0]), ["guard.limits"]);
    assert!(log[0].outcome.is_none());
    assert_eq!(
        verdicts(&log[0]),
        [
            ("rules".to_string(), Assurance::Enforced, GuardVerdict::Pass),
            (
                "limits".to_string(),
                Assurance::Checked,
                GuardVerdict::deny("over limit")
            ),
        ],
        "guards after the refusal don't run"
    );
    kernel.verify_audit_chain().await.expect("chain intact");
}

#[tokio::test]
async fn a_heuristic_guard_can_add_a_denial() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[]),
        vec![guard(
            "judge",
            Assurance::Heuristic,
            GuardVerdict::deny("looks like injection"),
        )],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, .. }) if policy_id == "guard.judge"),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_escalation_is_refused_without_an_approval_channel() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[]),
        vec![guard(
            "large-payments",
            Assurance::Enforced,
            GuardVerdict::escalate("charges over 5 need a human"),
        )],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, ref reason })
            if policy_id == "guard.large-payments" && reason.contains("approval")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    let log = kernel.get_audit_log().await;
    assert_eq!(
        verdicts(&log[0])[0].2,
        GuardVerdict::escalate("charges over 5 need a human"),
        "recorded as an escalation, not a plain denial"
    );
}

#[tokio::test]
async fn guards_never_see_calls_the_policy_denied() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = calls.clone();
    let counter: Arc<dyn Guard> = Arc::new(FunctionGuard::new(
        "counter",
        Assurance::Enforced,
        move |_req| {
            counted.fetch_add(1, Ordering::SeqCst);
            GuardVerdict::Pass
        },
    ));
    let runs = Arc::new(AtomicUsize::new(0));
    // `pay:charge` is not on the allowlist, so the policy denies it.
    let (kernel, agent) = kernel(config(&[], &[]), vec![counter], runs).await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { .. })),
        "{result:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the guard never ran");
    let log = kernel.get_audit_log().await;
    assert!(log[0].guards.is_none(), "nothing to record about guards");
}

#[tokio::test]
async fn guards_see_the_call_and_the_policys_decision() {
    let seen = Arc::new(std::sync::Mutex::new(None));
    let record = seen.clone();
    let inspector: Arc<dyn Guard> = Arc::new(FunctionGuard::new(
        "inspector",
        Assurance::Heuristic,
        move |req: &GuardRequest<'_>| {
            *record.lock().unwrap() = Some((
                req.request.tool_name.clone(),
                req.request.parameters.clone(),
                req.decision.is_allowed(),
                req.principal.map(|p| p.name.clone()),
                req.session_id.is_some(),
            ));
            GuardVerdict::Abstain
        },
    ));
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(config(&["pay:charge"], &[]), vec![inspector], runs).await;

    kernel
        .execute(&agent, &SessionId::new(), charge())
        .await
        .expect("runs");

    let seen = seen.lock().unwrap().clone().expect("the guard ran");
    assert_eq!(
        seen,
        (
            "pay:charge".to_string(),
            serde_json::json!({"amount": 10}),
            true,
            Some("worker".to_string()),
            true
        )
    );
}

// A guard that can't answer doesn't let the call through

#[derive(Debug)]
struct Panicking;

#[async_trait]
impl Guard for Panicking {
    async fn check(&self, _request: &GuardRequest<'_>) -> GuardVerdict {
        panic!("guard bug")
    }
    fn name(&self) -> &str {
        "panicking"
    }
    fn assurance(&self) -> Assurance {
        Assurance::Enforced
    }
}

#[derive(Debug)]
struct Hanging;

#[async_trait]
impl Guard for Hanging {
    async fn check(&self, _request: &GuardRequest<'_>) -> GuardVerdict {
        tokio::time::sleep(Duration::from_secs(60)).await;
        GuardVerdict::Pass
    }
    fn name(&self) -> &str {
        "hanging"
    }
    fn assurance(&self) -> Assurance {
        Assurance::Enforced
    }
}

/// A guard whose `check` panics before it returns its future: written by
/// hand, without `#[async_trait]` on the impl.
#[derive(Debug)]
struct PanicsEagerly;

impl Guard for PanicsEagerly {
    fn check<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        _request: &'life1 GuardRequest<'life2>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = GuardVerdict> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        panic!("panicked building the future")
    }
    fn name(&self) -> &str {
        "eager"
    }
    fn assurance(&self) -> Assurance {
        Assurance::Enforced
    }
}

#[tokio::test]
async fn a_guard_that_panics_before_its_future_exists_denies_and_is_recorded() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[]),
        vec![Arc::new(PanicsEagerly)],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, ref reason })
            if policy_id == "guard.eager" && reason.contains("panicked")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    let log = kernel.get_audit_log().await;
    assert_eq!(
        violated(&log[0]),
        ["guard.eager"],
        "the refusal is recorded"
    );
}

#[tokio::test]
async fn a_blocking_guard_that_answers_after_its_deadline_denies() {
    let runs = Arc::new(AtomicUsize::new(0));
    let mut cfg = config(&["pay:charge"], &[("pay:*", Assurance::Enforced)]);
    cfg.max_execution_time = Duration::from_millis(50);
    // A synchronous check can't be interrupted: it blocks past the deadline,
    // then passes. Its pass must not count.
    let slow: Arc<dyn Guard> = Arc::new(FunctionGuard::new("slow", Assurance::Enforced, |_req| {
        std::thread::sleep(Duration::from_millis(150));
        GuardVerdict::Pass
    }));
    let (kernel, agent) = kernel(cfg, vec![slow], runs.clone()).await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, ref reason })
            if policy_id == "guard.slow" && reason.contains("50 ms")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0, "the late pass didn't count");
}

#[tokio::test]
async fn a_guard_that_panics_denies_and_the_kernel_survives() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[]),
        vec![Arc::new(Panicking)],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, ref reason })
            if policy_id == "guard.panicking" && reason.contains("panicked")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_guard_that_doesnt_answer_in_time_denies() {
    let runs = Arc::new(AtomicUsize::new(0));
    let mut cfg = config(&["pay:charge"], &[]);
    cfg.max_execution_time = Duration::from_millis(50);
    let (kernel, agent) = kernel(cfg, vec![Arc::new(Hanging)], runs.clone()).await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, ref reason })
            if policy_id == "guard.hanging" && reason.contains("50 ms")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
}

// policy.min_assurance

#[tokio::test]
async fn a_heuristic_pass_does_not_meet_an_enforced_floor() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[("pay:*", Assurance::Enforced)]),
        vec![guard("judge", Assurance::Heuristic, GuardVerdict::Pass)],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, ref reason })
            if policy_id == "policy.min_assurance" && reason.contains("enforced")),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    let log = kernel.get_audit_log().await;
    assert_eq!(violated(&log[0]), ["policy.min_assurance"]);
    let guards = log[0].guards.as_ref().unwrap();
    assert_eq!(guards.required, Some(Assurance::Enforced));
    assert_eq!(guards.checks.len(), 1);
}

#[tokio::test]
async fn the_policys_own_allow_does_not_meet_a_floor() {
    let runs = Arc::new(AtomicUsize::new(0));
    // The policy allows the call, and no guard is registered.
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[("pay:*", Assurance::Heuristic)]),
        Vec::new(),
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, .. }) if policy_id == "policy.min_assurance"),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    let log = kernel.get_audit_log().await;
    let guards = log[0].guards.as_ref().unwrap();
    assert_eq!(guards.required, Some(Assurance::Heuristic));
    assert!(guards.checks.is_empty());
}

#[tokio::test]
async fn an_abstention_does_not_meet_a_floor() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[("pay:*", Assurance::Enforced)]),
        vec![
            guard("blocklist", Assurance::Enforced, GuardVerdict::Abstain),
            guard("judge", Assurance::Heuristic, GuardVerdict::Pass),
        ],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, .. }) if policy_id == "policy.min_assurance"),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_pass_at_the_floor_lets_the_call_run_and_is_recorded() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(
            &["pay:charge", "echo"],
            &[
                ("pay:*", Assurance::Checked),
                ("pay:refund", Assurance::Enforced),
            ],
        ),
        vec![
            guard("judge", Assurance::Heuristic, GuardVerdict::Pass),
            guard("schema", Assurance::Checked, GuardVerdict::Pass),
        ],
        runs.clone(),
    )
    .await;

    let response = kernel
        .execute(&agent, &SessionId::new(), charge())
        .await
        .expect("a checked pass meets a checked floor");
    assert!(response.success);
    assert_eq!(runs.load(Ordering::SeqCst), 1);

    let log = kernel.get_audit_log().await;
    assert_eq!(log.len(), 2, "decision, then outcome");
    assert!(log[0].decision.is_allowed());
    let guards = log[0]
        .guards
        .as_ref()
        .expect("the decision records the guards");
    assert_eq!(
        guards.required,
        Some(Assurance::Checked),
        "pay:refund's higher level doesn't match pay:charge"
    );
    assert_eq!(
        verdicts(&log[0]),
        [
            (
                "judge".to_string(),
                Assurance::Heuristic,
                GuardVerdict::Pass
            ),
            ("schema".to_string(), Assurance::Checked, GuardVerdict::Pass),
        ]
    );
    assert!(log[1].guards.is_none(), "the outcome doesn't repeat them");
    let receipt = response.receipt.expect("executed calls carry a receipt");
    assert_eq!((receipt.decision_leaf, receipt.outcome_leaf), (0, 1));
    assert!(log[0].verify_integrity());

    // A tool no pattern covers needs no guard pass.
    let echo = kernel
        .execute(
            &agent,
            &SessionId::new(),
            ToolRequest::new("echo", serde_json::json!({"message": "hi"})),
        )
        .await
        .expect("echo has no floor");
    assert!(echo.success);
}

#[tokio::test]
async fn the_highest_matching_level_applies() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(
            &["pay:charge"],
            &[
                ("pay:*", Assurance::Heuristic),
                ("*:charge", Assurance::Enforced),
            ],
        ),
        vec![guard("schema", Assurance::Checked, GuardVerdict::Pass)],
        runs.clone(),
    )
    .await;

    let result = kernel.execute(&agent, &SessionId::new(), charge()).await;

    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, .. }) if policy_id == "policy.min_assurance"),
        "{result:?}"
    );
    let log = kernel.get_audit_log().await;
    assert_eq!(
        log[0].guards.as_ref().unwrap().required,
        Some(Assurance::Enforced)
    );
}

// The audit record

#[tokio::test]
async fn rewriting_a_recorded_verdict_breaks_the_entry() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[]),
        vec![guard(
            "judge",
            Assurance::Heuristic,
            GuardVerdict::deny("no"),
        )],
        runs,
    )
    .await;
    let _ = kernel.execute(&agent, &SessionId::new(), charge()).await;

    let mut entry = kernel.get_audit_log().await.remove(0);
    assert!(entry.verify_integrity());
    // Rewrite the denial into a pass, keeping the hash.
    entry.guards.as_mut().unwrap().checks[0].verdict = GuardVerdict::Pass;
    assert!(
        !entry.verify_integrity(),
        "the hash commits to each verdict"
    );
    // Or drop the record altogether.
    let mut entry = kernel.get_audit_log().await.remove(0);
    entry.guards = None;
    assert!(!entry.verify_integrity(), "the hash commits to the record");
}

#[tokio::test]
async fn without_guards_or_a_floor_entries_are_unchanged() {
    let kernel = Kernel::new(config(&["echo"], &[])).await.unwrap();
    let agent = AgentId::new();
    kernel
        .register_agent(AgentRecord::new(agent, "worker"))
        .await
        .unwrap();

    kernel
        .execute(
            &agent,
            &SessionId::new(),
            ToolRequest::new("echo", serde_json::json!({"message": "hi"})),
        )
        .await
        .unwrap();

    for entry in kernel.get_audit_log().await {
        assert!(entry.guards.is_none());
        let json = serde_json::to_value(&entry).unwrap();
        assert!(json.get("guards").is_none(), "{json}");
    }
}

#[tokio::test]
async fn guard_records_survive_a_restart_of_a_durable_log() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&["pay:charge"], &[("pay:*", Assurance::Checked)]);
    cfg.audit.log_path = Some(dir.path().join("audit.jsonl"));
    let runs = Arc::new(AtomicUsize::new(0));

    // One run that passes its guard, then one a guard refuses: each kernel
    // reopens the log the previous one wrote.
    {
        let (kernel, agent) = kernel(
            cfg.clone(),
            vec![guard("schema", Assurance::Checked, GuardVerdict::Pass)],
            runs.clone(),
        )
        .await;
        kernel
            .execute(&agent, &SessionId::new(), charge())
            .await
            .expect("runs");
    }
    {
        let (kernel, agent) = kernel(
            cfg.clone(),
            vec![guard(
                "judge",
                Assurance::Heuristic,
                GuardVerdict::deny("no"),
            )],
            runs.clone(),
        )
        .await;
        assert!(kernel
            .execute(&agent, &SessionId::new(), charge())
            .await
            .is_err());
    }

    // Reopening replays and re-verifies every entry's hash.
    let reopened = Kernel::builder(cfg)
        .with_tool(counting_tool("pay:charge", runs))
        .build()
        .await
        .expect("the log verifies on reopen");
    let log = reopened.get_audit_log().await;
    assert_eq!(log.len(), 3, "decision, outcome, denial");
    assert!(log[0].guards.is_some());
    assert!(log[2].guards.is_some());
    assert!(log.iter().all(AuditEntry::verify_integrity));
    reopened.verify_audit_chain().await.expect("chain intact");
}

#[tokio::test]
async fn evaluate_policy_is_the_decide_stage_alone() {
    let runs = Arc::new(AtomicUsize::new(0));
    let (kernel, agent) = kernel(
        config(&["pay:charge"], &[]),
        vec![guard(
            "judge",
            Assurance::Heuristic,
            GuardVerdict::deny("no"),
        )],
        runs,
    )
    .await;

    assert!(kernel.evaluate_policy(&agent, &charge()).await.is_allowed());
    assert!(kernel
        .execute(&agent, &SessionId::new(), charge())
        .await
        .is_err());
}

// Configuration

#[tokio::test]
async fn guards_need_distinct_names() {
    let result = Kernel::builder(KernelConfig::default())
        .with_guard(guard("same", Assurance::Enforced, GuardVerdict::Pass))
        .with_guard(guard("same", Assurance::Heuristic, GuardVerdict::Pass))
        .build()
        .await;
    assert!(
        matches!(result, Err(KernelError::InvalidConfiguration { ref message }) if message.contains("same")),
        "{result:?}"
    );
    let unnamed = Kernel::builder(KernelConfig::default())
        .with_guard(guard("", Assurance::Enforced, GuardVerdict::Pass))
        .build()
        .await;
    assert!(matches!(
        unnamed,
        Err(KernelError::InvalidConfiguration { .. })
    ));
}

#[tokio::test]
async fn a_floor_that_could_never_apply_or_mean_anything_is_refused() {
    for (pattern, level) in [
        ("pay*charge", Assurance::Enforced),
        ("", Assurance::Enforced),
        ("pay:*", Assurance::Experimental),
    ] {
        let result = Kernel::new(config(&[], &[(pattern, level)])).await;
        assert!(
            matches!(result, Err(KernelError::InvalidConfiguration { ref message }) if message.contains("min_assurance")),
            "{pattern} {level}: {result:?}"
        );
    }
}

#[tokio::test]
async fn the_floor_is_read_from_a_config_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel.yaml");
    std::fs::write(
        &path,
        "policy:\n  min_assurance:\n    \"pay:*\": enforced\n    transfer_funds: checked\n",
    )
    .unwrap();
    let config = KernelConfig::from_file(&path).expect("parses");
    assert_eq!(
        config.policy.min_assurance.get("pay:*"),
        Some(&Assurance::Enforced)
    );
    assert_eq!(
        config.policy.min_assurance.get("transfer_funds"),
        Some(&Assurance::Checked)
    );

    std::fs::write(&path, "policy:\n  min_assurance:\n    \"pay:*\": strong\n").unwrap();
    assert!(
        KernelConfig::from_file(&path).is_err(),
        "an unknown level is refused"
    );
}

#[tokio::test]
async fn the_kernel_reports_its_guards() {
    let kernel = Kernel::builder(KernelConfig::default())
        .with_guard(guard("a", Assurance::Enforced, GuardVerdict::Pass))
        .with_guard(guard("b", Assurance::Heuristic, GuardVerdict::Pass))
        .build()
        .await
        .unwrap();
    let names: Vec<_> = kernel.guards().map(|g| g.name().to_string()).collect();
    assert_eq!(names, ["a", "b"]);
    assert!(format!("{kernel:?}").contains("guards"));
}
