//! Regression tests for the kernel audit chain.
//!
//! These pin down three defects that made the "tamper-evident hash-chained
//! audit trail" inert:
//!
//! 1. `compute_hash` did not cover `decision`, so a `Deny` could be rewritten
//!    into an `Allow` and `verify_integrity()` still returned `true`.
//! 2. `compute_hash` did not cover `previous_hash`, so `with_previous()` was a
//!    no-op and entries could be reordered or spliced freely.
//! 3. `Kernel::execute` never called `with_previous()` at all, and returned
//!    before logging denials.

use vak::kernel::types::{AgentId, AuditEntry, PolicyDecision, SessionId, ToolRequest};
use vak::kernel::{Kernel, KernelConfig};

fn allow() -> PolicyDecision {
    PolicyDecision::Allow {
        reason: "ok".to_string(),
        constraints: None,
    }
}

fn deny() -> PolicyDecision {
    PolicyDecision::Deny {
        reason: "nope".to_string(),
        violated_policies: None,
    }
}

#[test]
fn tampering_with_the_decision_is_detected() {
    let mut entry = AuditEntry::new(AgentId::new(), SessionId::new(), "refund_user", deny());
    assert!(entry.verify_integrity());

    // Flip the recorded verdict without touching anything else.
    entry.decision = allow();

    assert!(
        !entry.verify_integrity(),
        "rewriting Deny -> Allow must invalidate the entry hash"
    );
}

#[test]
fn with_previous_actually_changes_the_hash() {
    let entry = AuditEntry::new(AgentId::new(), SessionId::new(), "read", allow());
    let unlinked = entry.hash.clone();
    let linked = entry.with_previous("deadbeef".to_string());

    assert_ne!(
        unlinked, linked.hash,
        "committing to a predecessor must change the digest"
    );
    assert!(linked.verify_integrity());
}

#[test]
fn reordering_breaks_the_chain() {
    let agent = AgentId::new();
    let session = SessionId::new();

    let first = AuditEntry::new(agent, session, "first", allow());
    let second =
        AuditEntry::new(agent, session, "second", allow()).with_previous(first.hash.clone());
    let third =
        AuditEntry::new(agent, session, "third", allow()).with_previous(second.hash.clone());

    assert!(AuditEntry::verify_chain(&[first.clone(), second.clone(), third.clone()]).is_ok());

    // Drop the middle entry: the chain must not still validate.
    assert!(
        AuditEntry::verify_chain(&[first.clone(), third.clone()]).is_err(),
        "deleting an entry must break the chain"
    );

    // Swap two entries.
    assert!(
        AuditEntry::verify_chain(&[second, first, third]).is_err(),
        "reordering entries must break the chain"
    );
}

#[tokio::test]
async fn kernel_chains_its_audit_entries() {
    let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
    let agent = AgentId::new();
    let session = SessionId::new();

    for _ in 0..3 {
        let request = ToolRequest::new("echo", serde_json::json!({"msg": "hi"}));
        kernel.execute(&agent, &session, request).await.unwrap();
    }

    let log = kernel.get_audit_log().await;
    assert_eq!(log.len(), 3, "every execution must be audited");

    assert!(
        log[1].previous_hash.is_some(),
        "entries after the first must link to their predecessor"
    );
    assert_eq!(log[1].previous_hash.as_deref(), Some(log[0].hash.as_str()));

    kernel
        .verify_audit_chain()
        .await
        .expect("freshly written chain must verify");
}

#[tokio::test]
async fn denied_requests_are_audited() {
    let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
    let agent = AgentId::new();
    let session = SessionId::new();

    // Not a built-in tool and not in the allowlist -> denied by default.
    let request = ToolRequest::new("exfiltrate_secrets", serde_json::json!({}));
    let result = kernel.execute(&agent, &session, request).await;
    assert!(result.is_err(), "unlisted tool must be denied by default");

    let log = kernel.get_audit_log().await;
    assert_eq!(
        log.len(),
        1,
        "a denial is exactly the event an auditor needs; it must be logged"
    );
    assert!(matches!(log[0].decision, PolicyDecision::Deny { .. }));
}
