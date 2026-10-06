//! The mediation pipeline's stages, driven through `Kernel::execute` the way
//! an embedder would drive them (docs/adr/0003).
//!
//! Each test fails if a stage stops running, starts failing open, or stops
//! recording what it refused: admission (registration, suspension, session
//! binding, the agent's own scope), the budget, principal attributes reaching
//! policy, recording before execution, outcome leaves and receipts, and the
//! file-backed audit log.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use vak::audit::transparency::{
    verify_consistency, verify_inclusion, ConsistencyProof, InclusionProof, TreeHead,
};
use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
use vak::kernel::types::{
    AgentId, AuditEntry, KernelError, PolicyDecision, SessionId, ToolRequest, ToolResponse,
};
use vak::kernel::{
    AgentRecord, AuditLog, AuditLogError, InMemoryAgentRegistry, Kernel, KernelConfig,
    MemoryAuditLog, PolicyDecisionPoint, PolicyRequest, ToolHandler,
};

fn request(tool: &str) -> ToolRequest {
    ToolRequest::new(tool, serde_json::json!({"hello": "world"}))
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

fn config_allowing(tool: &str) -> KernelConfig {
    let mut config = KernelConfig::default();
    config.security.allowed_tools.push(tool.to_string());
    config
}

/// A host tool that counts how often it actually ran.
fn counting_tool(runs: Arc<AtomicUsize>) -> impl ToolHandler + 'static {
    FunctionHandler::new("count", move |req: &ToolRequest, _agent: &AgentId| {
        let runs = runs.clone();
        let id = req.request_id;
        Box::pin(async move {
            runs.fetch_add(1, Ordering::SeqCst);
            Ok(ToolResponse::success(id, serde_json::json!("counted"), 0))
        }) as HandlerFuture
    })
}

// ---------------------------------------------------------------------------
// Receipts and outcome leaves
// ---------------------------------------------------------------------------

#[tokio::test]
async fn receipt_proves_decision_and_outcome() {
    let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
    let response = kernel
        .execute(&AgentId::new(), &SessionId::new(), request("echo"))
        .await
        .unwrap();

    let receipt = response
        .receipt
        .clone()
        .expect("executed calls carry a receipt");
    assert_eq!((receipt.decision_leaf, receipt.outcome_leaf), (0, 1));
    receipt
        .tree_head
        .verify(&kernel.audit_verifying_key())
        .unwrap();

    // Both leaves are provably under the receipt's signed root.
    let entries = kernel.get_audit_log().await;
    for leaf in [receipt.decision_leaf, receipt.outcome_leaf] {
        let entry = &entries[leaf as usize];
        assert!(entry.verify_integrity());
        let proof = kernel
            .prove_audit_inclusion(leaf, receipt.tree_head.head.size)
            .await
            .unwrap();
        verify_inclusion(
            &Kernel::audit_leaf_hash(entry),
            &proof,
            &receipt.tree_head.head.root,
        )
        .unwrap();
    }

    // The outcome links to its decision and commits to the result.
    assert!(entries[0].outcome.is_none());
    let outcome = entries[1].outcome.as_ref().unwrap();
    assert_eq!(outcome.decision_leaf, 0);
    assert!(outcome.success);
    let result_bytes = serde_json::to_vec(response.result.as_ref().unwrap()).unwrap();
    let expected = format!("{:x}", Sha256::digest(&result_bytes));
    assert_eq!(outcome.result_sha256.as_deref(), Some(expected.as_str()));
}

// ---------------------------------------------------------------------------
// Stage 1: Admit
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unregistered_agents_are_refused_when_registration_is_required() {
    let mut config = KernelConfig::default();
    config.security.require_registered_agents = true;
    let kernel = Kernel::new(config).await.unwrap();
    let agent = AgentId::new();

    let result = kernel
        .execute(&agent, &SessionId::new(), request("echo"))
        .await;
    assert!(
        matches!(result, Err(KernelError::AgentNotFound { .. })),
        "{result:?}"
    );
    let log = kernel.get_audit_log().await;
    assert_eq!(log.len(), 1, "the refusal is recorded");
    assert_eq!(violated(&log[0]), ["security.require_registered_agents"]);

    kernel
        .register_agent(AgentRecord::new(agent, "worker"))
        .await
        .unwrap();
    assert!(
        kernel
            .execute(&agent, &SessionId::new(), request("echo"))
            .await
            .unwrap()
            .success
    );
}

#[tokio::test]
async fn suspension_takes_effect_on_the_next_request() {
    let registry = Arc::new(InMemoryAgentRegistry::new());
    let kernel = Kernel::builder(KernelConfig::default())
        .with_agent_registry(registry.clone())
        .build()
        .await
        .unwrap();
    let agent = AgentId::new();
    let session = SessionId::new();
    kernel
        .register_agent(AgentRecord::new(agent, "worker"))
        .await
        .unwrap();
    kernel
        .execute(&agent, &session, request("echo"))
        .await
        .unwrap();

    registry.suspend(&agent, "credential leak").await.unwrap();
    let result = kernel.execute(&agent, &session, request("echo")).await;
    assert!(
        matches!(result, Err(KernelError::AgentSuspended { ref reason, .. }) if reason == "credential leak"),
        "{result:?}"
    );
    assert_eq!(
        violated(kernel.get_audit_log().await.last().unwrap()),
        ["kernel.admission"]
    );

    registry.reinstate(&agent).await.unwrap();
    assert!(kernel
        .execute(&agent, &session, request("echo"))
        .await
        .is_ok());
}

#[tokio::test]
async fn a_session_belongs_to_its_first_agent() {
    let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
    let (alice, mallory, session) = (AgentId::new(), AgentId::new(), SessionId::new());

    kernel
        .execute(&alice, &session, request("echo"))
        .await
        .unwrap();
    let result = kernel.execute(&mallory, &session, request("echo")).await;
    assert!(
        matches!(result, Err(KernelError::SessionConflict { .. })),
        "{result:?}"
    );
    assert_eq!(
        violated(kernel.get_audit_log().await.last().unwrap()),
        ["kernel.session"]
    );

    // The owner keeps using it; once released, it can be bound again.
    assert!(kernel
        .execute(&alice, &session, request("echo"))
        .await
        .is_ok());
    assert!(kernel.end_session(&session).await);
    assert!(kernel
        .execute(&mallory, &session, request("echo"))
        .await
        .is_ok());
}

/// Allows everything. Used to show the agent's own scope still applies.
#[derive(Debug)]
struct AllowAll;

#[async_trait]
impl PolicyDecisionPoint for AllowAll {
    async fn decide(&self, _req: &PolicyRequest<'_>) -> PolicyDecision {
        PolicyDecision::Allow {
            reason: "allow-all".to_string(),
            constraints: None,
        }
    }

    fn name(&self) -> &str {
        "allow-all"
    }
}

#[tokio::test]
async fn an_agents_scope_narrows_any_policy() {
    let kernel = Kernel::builder(KernelConfig::default())
        .with_policy(Arc::new(AllowAll))
        .build()
        .await
        .unwrap();
    let agent = AgentId::new();
    kernel
        .register_agent(
            AgentRecord::new(agent, "reader")
                .with_allowed_tools(["echo", "system_info"])
                .with_blocked_tools(["system_info"]),
        )
        .await
        .unwrap();

    assert!(
        kernel
            .execute(&agent, &SessionId::new(), request("echo"))
            .await
            .unwrap()
            .success
    );
    // Not allowed for this agent, and blocked for this agent: the PDP would
    // allow both, but it never gets asked.
    for tool in ["calculator", "system_info"] {
        let result = kernel
            .execute(&agent, &SessionId::new(), request(tool))
            .await;
        assert!(
            matches!(result, Err(KernelError::PolicyViolation { ref policy_id, .. }) if policy_id == "agent.scope"),
            "{tool}: {result:?}"
        );
        assert_eq!(
            violated(kernel.get_audit_log().await.last().unwrap()),
            ["agent.scope"]
        );
    }
}

// ---------------------------------------------------------------------------
// Stage 2: Budget
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_configured_rate_limit_is_enforced() {
    let mut config = KernelConfig::default();
    config.security.max_requests_per_minute = 2;
    let kernel = Kernel::new(config.clone()).await.unwrap();
    let agent = AgentId::new();
    let session = SessionId::new();

    kernel
        .execute(&agent, &session, request("echo"))
        .await
        .unwrap();
    // A request policy denies still spends budget.
    assert!(matches!(
        kernel.execute(&agent, &session, request("rm_rf")).await,
        Err(KernelError::PolicyViolation { .. })
    ));
    let result = kernel.execute(&agent, &session, request("echo")).await;
    match &result {
        Err(e @ KernelError::RateLimited { retry_after_ms, .. }) => {
            assert!(*retry_after_ms > 0);
            assert!(e.is_recoverable());
        }
        other => panic!("expected RateLimited, got {other:?}"),
    }
    assert_eq!(
        violated(kernel.get_audit_log().await.last().unwrap()),
        ["kernel.budget"]
    );

    // Budgets are per agent.
    assert!(kernel
        .execute(&AgentId::new(), &SessionId::new(), request("echo"))
        .await
        .is_ok());

    // And off means off.
    config.security.enable_rate_limiting = false;
    let unlimited = Kernel::new(config).await.unwrap();
    for _ in 0..10 {
        unlimited
            .execute(&agent, &session, request("echo"))
            .await
            .unwrap();
    }
}

// ---------------------------------------------------------------------------
// Stage 3: principal attributes reach policy (K8)
// ---------------------------------------------------------------------------

const PERMIT_INTERNAL_AGENTS: &str = r#"
version: "1.0"
rules:
  - id: "permit-internal-agents"
    effect: "permit"
    principal: "Agent::*"
    action: "Action::\"Tool::execute\""
    resource: "Tool::*"
    description: "Only internal agents may execute tools"
    conditions:
      - "principal.internal == true"
"#;

#[tokio::test]
async fn principal_internal_comes_from_the_agent_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, PERMIT_INTERNAL_AGENTS).unwrap();
    let mut config = KernelConfig::default();
    config.policy.policy_paths = vec![path];
    let kernel = Kernel::new(config).await.unwrap();

    let (stranger, insider, spoofer) = (AgentId::new(), AgentId::new(), AgentId::new());
    kernel
        .register_agent(AgentRecord::new(insider, "insider").internal(true))
        .await
        .unwrap();
    // An attribute can't override what the kernel knows.
    kernel
        .register_agent(AgentRecord::new(spoofer, "spoofer").with_attribute("internal", true))
        .await
        .unwrap();

    // Every agent used to be internal, so this was allowed for anyone.
    for agent in [stranger, spoofer] {
        assert!(matches!(
            kernel.evaluate_policy(&agent, &request("echo")).await,
            PolicyDecision::Deny { .. }
        ));
    }
    assert!(matches!(
        kernel.evaluate_policy(&insider, &request("echo")).await,
        PolicyDecision::Allow { .. }
    ));
    assert!(
        kernel
            .execute(&insider, &SessionId::new(), request("echo"))
            .await
            .unwrap()
            .success
    );
}

/// Allows only principals whose record says they're on the payments team,
/// and only within a session.
#[derive(Debug)]
struct PaymentsTeamOnly;

#[async_trait]
impl PolicyDecisionPoint for PaymentsTeamOnly {
    async fn decide(&self, req: &PolicyRequest<'_>) -> PolicyDecision {
        let team = req
            .principal
            .and_then(|p| p.attributes.get("team"))
            .and_then(|v| v.as_str());
        if team == Some("payments") && req.session_id.is_some() {
            PolicyDecision::Allow {
                reason: "payments team".to_string(),
                constraints: None,
            }
        } else {
            PolicyDecision::Deny {
                reason: "not payments".to_string(),
                violated_policies: None,
            }
        }
    }

    fn name(&self) -> &str {
        "payments-team-only"
    }
}

#[tokio::test]
async fn the_pdp_sees_the_record_and_the_session() {
    let kernel = Kernel::builder(KernelConfig::default())
        .with_policy(Arc::new(PaymentsTeamOnly))
        .build()
        .await
        .unwrap();
    let (payments, other) = (AgentId::new(), AgentId::new());
    kernel
        .register_agent(AgentRecord::new(payments, "p").with_attribute("team", "payments"))
        .await
        .unwrap();
    kernel
        .register_agent(AgentRecord::new(other, "o").with_attribute("team", "growth"))
        .await
        .unwrap();

    assert!(kernel
        .execute(&payments, &SessionId::new(), request("echo"))
        .await
        .is_ok());
    assert!(matches!(
        kernel
            .execute(&other, &SessionId::new(), request("echo"))
            .await,
        Err(KernelError::PolicyViolation { .. })
    ));
}

// ---------------------------------------------------------------------------
// Stages 5 and 7: record before acting
// ---------------------------------------------------------------------------

/// An audit log whose appends start failing after `fail_from` successes.
#[derive(Debug)]
struct FlakyLog {
    inner: MemoryAuditLog,
    fail_from: usize,
    appends: AtomicUsize,
}

impl FlakyLog {
    fn failing_from(fail_from: usize) -> Self {
        Self {
            inner: MemoryAuditLog::new(),
            fail_from,
            appends: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl AuditLog for FlakyLog {
    async fn append(&self, entry: AuditEntry) -> Result<u64, AuditLogError> {
        if self.appends.fetch_add(1, Ordering::SeqCst) >= self.fail_from {
            return Err(AuditLogError::Io("disk full".to_string()));
        }
        self.inner.append(entry).await
    }

    async fn tree_head(&self) -> TreeHead {
        self.inner.tree_head().await
    }

    async fn inclusion_proof(&self, leaf: u64, size: u64) -> Result<InclusionProof, AuditLogError> {
        self.inner.inclusion_proof(leaf, size).await
    }

    async fn consistency_proof(
        &self,
        old: u64,
        new: u64,
    ) -> Result<ConsistencyProof, AuditLogError> {
        self.inner.consistency_proof(old, new).await
    }

    async fn entries(&self) -> Vec<AuditEntry> {
        self.inner.entries().await
    }

    fn name(&self) -> &str {
        "flaky"
    }
}

#[tokio::test]
async fn a_tool_does_not_run_if_its_decision_cannot_be_recorded() {
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = Kernel::builder(config_allowing("count"))
        .with_audit_log(Arc::new(FlakyLog::failing_from(0)))
        .with_tool(counting_tool(runs.clone()))
        .build()
        .await
        .unwrap();

    let result = kernel
        .execute(&AgentId::new(), &SessionId::new(), request("count"))
        .await;
    assert!(
        matches!(result, Err(KernelError::AuditUnavailable { .. })),
        "{result:?}"
    );
    assert_eq!(runs.load(Ordering::SeqCst), 0, "the tool must not have run");
}

#[tokio::test]
async fn an_unrecorded_outcome_returns_the_response_without_a_receipt() {
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = Kernel::builder(config_allowing("count"))
        .with_audit_log(Arc::new(FlakyLog::failing_from(1)))
        .with_tool(counting_tool(runs.clone()))
        .build()
        .await
        .unwrap();

    // The tool ran; reporting an error would invite a retry of something
    // that already happened.
    let response = kernel
        .execute(&AgentId::new(), &SessionId::new(), request("count"))
        .await
        .unwrap();
    assert!(response.success);
    assert!(response.receipt.is_none());
    assert_eq!(runs.load(Ordering::SeqCst), 1);
    assert_eq!(kernel.get_audit_log().await.len(), 1, "decision only");
}

// ---------------------------------------------------------------------------
// The file-backed audit log
// ---------------------------------------------------------------------------

#[tokio::test]
async fn audit_log_path_persists_across_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit").join("vak.jsonl");
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let mut config = KernelConfig::default();
    config.audit.log_path = Some(path.clone());
    let agent = AgentId::new();

    let first_head = {
        let kernel = Kernel::builder(config.clone())
            .with_audit_signing_key(key.clone())
            .build()
            .await
            .unwrap();
        let session = SessionId::new();
        kernel
            .execute(&agent, &session, request("echo"))
            .await
            .unwrap();
        let _ = kernel.execute(&agent, &session, request("rm_rf")).await;
        kernel.audit_tree_head().await
    };
    assert_eq!(first_head.head.size, 3);

    // A new kernel on the same file continues the same log.
    let kernel = Kernel::builder(config.clone())
        .with_audit_signing_key(key.clone())
        .build()
        .await
        .unwrap();
    assert_eq!(kernel.get_audit_log().await.len(), 3);
    let receipt = kernel
        .execute(&agent, &SessionId::new(), request("echo"))
        .await
        .unwrap()
        .receipt
        .unwrap();
    assert_eq!(receipt.decision_leaf, 3);
    first_head.verify(&key.verifying_key()).unwrap();
    receipt.tree_head.verify(&key.verifying_key()).unwrap();
    let proof = kernel
        .prove_audit_consistency(first_head.head.size, receipt.tree_head.head.size)
        .await
        .unwrap();
    verify_consistency(&proof, &first_head.head.root, &receipt.tree_head.head.root).unwrap();
    kernel.verify_audit_chain().await.unwrap();
    drop(kernel);

    // A rewritten entry stops the next kernel from starting, rather than
    // being silently extended.
    let text = std::fs::read_to_string(&path).unwrap();
    std::fs::write(&path, text.replacen("rm_rf", "rm_rg", 1)).unwrap();
    assert!(matches!(
        Kernel::new(config).await,
        Err(KernelError::InvalidConfiguration { .. })
    ));
}
