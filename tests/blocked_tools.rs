//! `security.blocked_tools` is a hard block (docs/adr/0017).
//!
//! With policy files, Cedar policies or an embedder's decision point, the
//! list used to be only an attribute (`resource.restricted`) that rules
//! could read or ignore, so a rule that permitted a tool without checking
//! it ran a blocked tool. Each test drives `Kernel::execute`.

use std::sync::Arc;

use async_trait::async_trait;
use vak::kernel::types::{
    AgentId, AuditEntry, KernelError, PolicyDecision, SessionId, ToolRequest,
};
use vak::kernel::{Kernel, KernelConfig, PolicyDecisionPoint, PolicyRequest};

fn request(tool: &str) -> ToolRequest {
    ToolRequest::new(tool, serde_json::json!({"message": "hi"}))
}

fn violated(entry: &AuditEntry) -> Vec<String> {
    match &entry.decision {
        PolicyDecision::Deny {
            violated_policies, ..
        } => violated_policies.clone().unwrap_or_default(),
        other => panic!("expected a denial, got {other:?}"),
    }
}

/// Checks `tool` is refused as blocked, and the refusal is audited.
async fn assert_blocked(kernel: &Kernel, tool: &str) {
    let result = kernel
        .execute(&AgentId::new(), &SessionId::new(), request(tool))
        .await;
    assert!(
        matches!(result, Err(KernelError::PolicyViolation { ref policy_id, .. })
            if policy_id == "security.blocked_tools"),
        "{tool}: {result:?}"
    );
    assert_eq!(
        violated(kernel.get_audit_log().await.last().unwrap()),
        ["security.blocked_tools"]
    );
}

async fn assert_runs(kernel: &Kernel, tool: &str) {
    let response = kernel
        .execute(&AgentId::new(), &SessionId::new(), request(tool))
        .await
        .unwrap();
    assert!(response.success, "{tool}: {response:?}");
}

/// A rule permitting every tool, never reading `resource.restricted`.
const PERMIT_EVERY_TOOL: &str = r#"
version: "1.0"
rules:
  - id: "permit-everything"
    effect: "permit"
    principal: "Agent::*"
    action: "Action::\"Tool::execute\""
    resource: "Tool::*"
"#;

#[tokio::test]
async fn a_policy_file_cannot_run_a_blocked_tool() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, PERMIT_EVERY_TOOL).unwrap();
    let mut config = KernelConfig::default();
    config.policy.policy_paths = vec![path];
    config.security.blocked_tools = vec!["echo".to_string()];
    let kernel = Kernel::new(config).await.unwrap();

    assert_blocked(&kernel, "echo").await;
    assert_runs(&kernel, "system_info").await;
    assert_eq!(kernel.policy_decision_point().name(), "cedar-enforcer");
}

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

impl std::fmt::Debug for AllowAll {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AllowAll")
    }
}

#[tokio::test]
async fn an_embedders_decision_point_cannot_run_a_blocked_tool() {
    let mut config = KernelConfig::default();
    config.security.blocked_tools = vec!["echo".to_string(), "calculator".to_string()];
    let kernel = Kernel::builder(config)
        .with_policy(Arc::new(AllowAll))
        .build()
        .await
        .unwrap();

    assert_blocked(&kernel, "echo").await;
    assert_blocked(&kernel, "calculator").await;
    assert_runs(&kernel, "system_info").await;
    assert_eq!(kernel.policy_decision_point().name(), "allow-all");
}

#[tokio::test]
async fn an_empty_list_leaves_the_decision_point_alone() {
    let kernel = Kernel::builder(KernelConfig::default())
        .with_policy(Arc::new(AllowAll))
        .build()
        .await
        .unwrap();
    assert_runs(&kernel, "echo").await;
}

#[cfg(feature = "cedar")]
#[tokio::test]
async fn cedar_policies_cannot_run_a_blocked_tool() {
    let dir = tempfile::tempdir().unwrap();
    let policies = dir.path().join("permit.cedar");
    std::fs::write(
        &policies,
        "permit (principal, action in Vak::Action::\"call\", resource);\n",
    )
    .unwrap();
    let mut config = KernelConfig::default();
    config.policy.format = vak::kernel::config::PolicyFormat::Cedar;
    config.policy.policy_paths = vec![policies];
    config.security.blocked_tools = vec!["echo".to_string()];
    let kernel = Kernel::new(config).await.unwrap();

    assert_eq!(kernel.policy_decision_point().name(), "cedar");
    assert_blocked(&kernel, "echo").await;
    assert_runs(&kernel, "system_info").await;
}
