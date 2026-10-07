//! The kernel's durable audit logs, configured from `KernelConfig` and driven
//! through `Kernel::execute` (docs/adr/0007).
//!
//! These fail if a configured log stops surviving a restart, if a kernel
//! starts on a log that doesn't verify, or if a tool runs when its decision
//! couldn't be stored.

use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use vak::audit::transparency::{verify_consistency, verify_inclusion};
use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
use vak::kernel::types::{AgentId, KernelError, SessionId, ToolRequest, ToolResponse};
use vak::kernel::{AuditLog, AuditLogFormat, Kernel, KernelConfig, SqliteAuditLog, ToolHandler};

fn config(log: &Path, format: AuditLogFormat) -> KernelConfig {
    let mut config = KernelConfig::default();
    config.security.allowed_tools.push("count".to_string());
    config.audit.log_path = Some(log.to_path_buf());
    config.audit.format = format;
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

async fn kernel(config: KernelConfig, runs: Arc<AtomicUsize>) -> Result<Kernel, KernelError> {
    Kernel::builder(config)
        .with_audit_signing_key(SigningKey::from_bytes(&[21u8; 32]))
        .with_tool(counting_tool(runs))
        .build()
        .await
}

fn call() -> ToolRequest {
    ToolRequest::new("count", serde_json::json!({}))
}

#[tokio::test]
async fn receipts_from_a_sqlite_log_verify_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(&dir.path().join("audit.db"), AuditLogFormat::Sqlite);
    let runs = Arc::new(AtomicUsize::new(0));
    let (agent, session) = (AgentId::new(), SessionId::new());

    let receipts = {
        let kernel = kernel(config.clone(), runs.clone()).await.unwrap();
        let mut receipts = Vec::new();
        for _ in 0..3 {
            let response = kernel.execute(&agent, &session, call()).await.unwrap();
            assert!(response.success, "{response:?}");
            receipts.push(response.receipt.unwrap());
        }
        receipts
    };
    assert_eq!(runs.load(Ordering::SeqCst), 3);

    let kernel = kernel(config, runs.clone()).await.unwrap();
    let head = kernel.audit_tree_head().await;
    head.verify(&SigningKey::from_bytes(&[21u8; 32]).verifying_key())
        .unwrap();
    assert_eq!(head.head.size, 6, "a decision and an outcome per call");

    let entries = kernel.get_audit_log().await;
    for receipt in &receipts {
        for leaf in [receipt.decision_leaf, receipt.outcome_leaf] {
            let proof = kernel
                .prove_audit_inclusion(leaf, head.head.size)
                .await
                .unwrap();
            verify_inclusion(
                &Kernel::audit_leaf_hash(&entries[leaf as usize]),
                &proof,
                &head.head.root,
            )
            .unwrap();
        }
        // Each receipt's head is a prefix of the reloaded log.
        let consistency = kernel
            .prove_audit_consistency(receipt.tree_head.head.size, head.head.size)
            .await
            .unwrap();
        verify_consistency(&consistency, &receipt.tree_head.head.root, &head.head.root).unwrap();
    }

    // And the restarted kernel keeps extending the same log.
    let response = kernel.execute(&agent, &session, call()).await.unwrap();
    assert_eq!(response.receipt.unwrap().decision_leaf, 6);
}

#[tokio::test]
async fn a_kernel_will_not_start_on_a_tampered_log() {
    for format in [AuditLogFormat::Jsonl, AuditLogFormat::Sqlite] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let config = config(&path, format);
        {
            let kernel = kernel(config.clone(), Arc::default()).await.unwrap();
            kernel
                .execute(&AgentId::new(), &SessionId::new(), call())
                .await
                .unwrap();
        }

        // Rewrite the recorded tool name without fixing any hash.
        match format {
            AuditLogFormat::Jsonl => {
                let text = std::fs::read_to_string(&path).unwrap();
                std::fs::write(&path, text.replacen("count", "other", 1)).unwrap();
            }
            AuditLogFormat::Sqlite => {
                rusqlite::Connection::open(&path)
                    .unwrap()
                    .execute_batch(
                        "UPDATE vak_audit_log SET entry = replace(entry, 'count', 'other') \
                         WHERE leaf_index = 0",
                    )
                    .unwrap();
            }
        }

        let result = kernel(config, Arc::default()).await;
        assert!(
            matches!(
                result,
                Err(KernelError::InvalidConfiguration { ref message })
                    if message.contains("audit.log_path") && message.contains("corrupt")
            ),
            "{format:?}: {result:?}"
        );
    }
}

#[tokio::test]
async fn a_kernel_will_not_start_on_a_log_in_the_other_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.log");
    kernel(config(&path, AuditLogFormat::Jsonl), Arc::default())
        .await
        .unwrap()
        .execute(&AgentId::new(), &SessionId::new(), call())
        .await
        .unwrap();

    // Never silently started afresh, or repaired.
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        kernel(config(&path, AuditLogFormat::Sqlite), Arc::default()).await,
        Err(KernelError::InvalidConfiguration { .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[tokio::test]
async fn a_tool_does_not_run_when_the_sqlite_log_cannot_store_its_decision() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.db");
    let runs = Arc::new(AtomicUsize::new(0));
    let kernel = kernel(config(&path, AuditLogFormat::Sqlite), runs.clone())
        .await
        .unwrap();

    // Another writer takes the next leaf, so the kernel's insert fails.
    let intruder = SqliteAuditLog::open(&path).await.unwrap();
    let foreign = vak::kernel::types::AuditEntry::new(
        AgentId::new(),
        SessionId::new(),
        "elsewhere",
        vak::kernel::types::PolicyDecision::Inadmissible {
            reason: "not ours".to_string(),
        },
    );
    intruder.append(foreign).await.unwrap();

    for _ in 0..2 {
        let result = kernel
            .execute(&AgentId::new(), &SessionId::new(), call())
            .await;
        assert!(
            matches!(result, Err(KernelError::AuditUnavailable { .. })),
            "{result:?}"
        );
    }
    assert_eq!(runs.load(Ordering::SeqCst), 0, "the tool must not have run");
    assert_eq!(kernel.audit_tree_head().await.head.size, 0);
}
