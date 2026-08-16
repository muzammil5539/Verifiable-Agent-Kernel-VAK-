//! Proves the kernel's authorization decisions come from policy files.
//!
//! Before this wiring, `Kernel::execute` decided authorization itself from a
//! hardcoded allowlist and never read `policies/`. These tests fail if the
//! kernel stops consulting the enforcer, if a `forbid` rule stops biting, or if
//! rule conditions go back to being decorative. See docs/adr/0001.

use std::path::PathBuf;

use vak::kernel::types::{AgentId, PolicyDecision, SessionId, ToolRequest};
use vak::kernel::{Kernel, KernelConfig};

/// Writes a policy file and builds a kernel pointed at it.
async fn kernel_with_policy(dir: &tempfile::TempDir, yaml: &str) -> Kernel {
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, yaml).expect("write policy");

    let mut config = KernelConfig::default();
    config.policy.policy_paths = vec![path];
    Kernel::new(config).await.expect("kernel")
}

fn request(tool: &str) -> ToolRequest {
    ToolRequest::new(tool, serde_json::json!({}))
}

const PERMIT_UNRESTRICTED_TOOLS: &str = r#"
version: "1.0"
rules:
  - id: "permit-tools"
    effect: "permit"
    principal: "Agent::*"
    action: "Action::\"Tool::execute\""
    resource: "Tool::*"
    description: "Allow agents to execute non-restricted tools"
    conditions:
      - "resource.restricted == false"
"#;

#[tokio::test]
async fn policy_file_grants_access() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&dir, PERMIT_UNRESTRICTED_TOOLS).await;

    let decision = kernel
        .evaluate_policy(&AgentId::new(), &request("echo"))
        .await;

    assert!(
        matches!(decision, PolicyDecision::Allow { .. }),
        "permit rule should grant, got {decision:?}"
    );
}

#[tokio::test]
async fn forbid_rule_overrides_permit() {
    let dir = tempfile::tempdir().unwrap();
    let yaml = format!(
        r#"{PERMIT_UNRESTRICTED_TOOLS}
  - id: "forbid-echo"
    effect: "forbid"
    principal: "*"
    action: "*"
    resource: "Tool::\"echo\""
    description: "Block echo specifically"
"#
    );
    let kernel = kernel_with_policy(&dir, &yaml).await;

    let denied = kernel
        .evaluate_policy(&AgentId::new(), &request("echo"))
        .await;
    assert!(
        matches!(denied, PolicyDecision::Deny { .. }),
        "forbid must override permit, got {denied:?}"
    );

    // A different tool is still permitted, proving the forbid was targeted
    // rather than the whole policy set failing closed.
    let allowed = kernel
        .evaluate_policy(&AgentId::new(), &request("calculator"))
        .await;
    assert!(matches!(allowed, PolicyDecision::Allow { .. }));
}

#[tokio::test]
async fn conditions_actually_gate() {
    // `blocked_tools` is what the kernel reports as `resource.restricted`, so a
    // blocked tool must fail the permit rule's condition even though the rule's
    // principal/action/resource globs all match it.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, PERMIT_UNRESTRICTED_TOOLS).unwrap();

    let mut config = KernelConfig::default();
    config.policy.policy_paths = vec![path];
    config.security.blocked_tools = vec!["calculator".to_string()];
    let kernel = Kernel::new(config).await.unwrap();

    let decision = kernel
        .evaluate_policy(&AgentId::new(), &request("calculator"))
        .await;

    assert!(
        matches!(decision, PolicyDecision::Deny { .. }),
        "resource.restricted == false must exclude a blocked tool, got {decision:?}"
    );
}

#[tokio::test]
async fn unresolvable_condition_does_not_grant() {
    // A permit rule referencing an attribute the kernel does not supply must
    // not grant. A typo in a policy file cannot widen access.
    let dir = tempfile::tempdir().unwrap();
    let yaml = r#"
version: "1.0"
rules:
  - id: "permit-typo"
    effect: "permit"
    principal: "Agent::*"
    action: "Action::\"Tool::execute\""
    resource: "Tool::*"
    conditions:
      - "resource.restrictedd == false"
"#;
    let kernel = kernel_with_policy(&dir, yaml).await;

    let decision = kernel
        .evaluate_policy(&AgentId::new(), &request("echo"))
        .await;

    assert!(
        matches!(decision, PolicyDecision::Deny { .. }),
        "a permit rule with an unresolvable condition must not grant, got {decision:?}"
    );
}

#[tokio::test]
async fn missing_policy_file_denies_everything() {
    // Policies were configured but could not be loaded. This must fail closed,
    // not silently fall back to the permissive path.
    let mut config = KernelConfig::default();
    config.policy.policy_paths = vec![PathBuf::from("/nonexistent/policy.yaml")];
    let kernel = Kernel::new(config).await.unwrap();

    let decision = kernel
        .evaluate_policy(&AgentId::new(), &request("echo"))
        .await;

    assert!(
        matches!(decision, PolicyDecision::Deny { .. }),
        "unloadable policy must deny, got {decision:?}"
    );
}

#[tokio::test]
async fn shipped_default_policies_permit_builtin_tools() {
    // Guards the real file in policies/, not a fixture: if its schema drifts
    // away from what the enforcer parses, this fails.
    let mut config = KernelConfig::default();
    config.policy.policy_paths = vec![PathBuf::from("policies/default_policies.yaml")];
    let kernel = Kernel::new(config).await.unwrap();

    let decision = kernel
        .evaluate_policy(&AgentId::new(), &request("echo"))
        .await;

    assert!(
        matches!(decision, PolicyDecision::Allow { .. }),
        "shipped default policy should permit a built-in tool, got {decision:?}"
    );
}

#[tokio::test]
async fn denied_request_is_refused_and_audited() {
    // End to end through execute(): a policy denial must both fail the call and
    // leave a record.
    let dir = tempfile::tempdir().unwrap();
    let yaml = r#"
version: "1.0"
rules:
  - id: "forbid-all"
    effect: "forbid"
    principal: "*"
    action: "*"
    resource: "*"
"#;
    let kernel = kernel_with_policy(&dir, yaml).await;

    let result = kernel
        .execute(&AgentId::new(), &SessionId::new(), request("echo"))
        .await;
    assert!(result.is_err(), "forbidden tool must not execute");

    let log = kernel.get_audit_log().await;
    assert_eq!(log.len(), 1);
    assert!(matches!(log[0].decision, PolicyDecision::Deny { .. }));
    kernel.verify_audit_chain().await.expect("chain intact");
}

#[tokio::test]
async fn no_policy_paths_uses_allowlist_fallback() {
    // Default config names no policy files, so the kernel keeps its previous
    // behaviour: built-ins allowed, everything else denied by default.
    let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
    let agent = AgentId::new();

    let allowed = kernel.evaluate_policy(&agent, &request("echo")).await;
    assert!(matches!(allowed, PolicyDecision::Allow { .. }));

    let denied = kernel.evaluate_policy(&agent, &request("anything")).await;
    assert!(matches!(denied, PolicyDecision::Deny { .. }));
}
