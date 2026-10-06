//! Signed WASM skills, end to end (docs/adr/0005).
//!
//! `a_signed_skill_runs_and_its_receipt_survives_a_restart` is the Phase 1
//! exit criterion from docs/architecture-v2.md §7: sign a skill, load it,
//! execute it through `Kernel::execute`, and verify inclusion proofs for its
//! decision and outcome leaves against a signed tree head over the log
//! reloaded from disk.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use vak::audit::transparency::{verify_consistency, verify_inclusion};
use vak::kernel::types::{AgentId, KernelError, PolicyDecision, SessionId, ToolRequest};
use vak::kernel::{Kernel, KernelConfig};
use vak::sandbox::signing::{module_digest, sign_skill};
use vak::sandbox::{SkillManifest, SkillPermissions};

/// Echoes its input (the kernel's skill ABI).
const SKILL_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (global $next (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $p))
  (func (export "execute") (param $ptr i32) (param $len i32) (result i32)
    (i32.store (i32.const 0) (local.get $len))
    (memory.copy (i32.const 4) (local.get $ptr) (local.get $len))
    (i32.const 0)))
"#;

const SKILL: &str = "signed_echo";

fn publisher() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

fn manifest() -> SkillManifest {
    SkillManifest {
        name: SKILL.to_string(),
        version: "1.0.0".to_string(),
        description: "Echoes its input".to_string(),
        author: Some("VAK tests".to_string()),
        permissions: SkillPermissions::default(),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: serde_json::json!({"type": "object"}),
        wasm_path: PathBuf::from("echo.wat"),
        signed_by: None,
        signature: None,
    }
}

/// Writes the module and `manifest` (as given) into `dir`.
fn write_skill(dir: &Path, manifest: &SkillManifest) {
    std::fs::write(dir.join("echo.wat"), SKILL_WAT).unwrap();
    std::fs::write(
        dir.join("skill.yaml"),
        serde_yaml::to_string(manifest).unwrap(),
    )
    .unwrap();
}

fn signed_by(key: &SigningKey) -> SkillManifest {
    let mut manifest = manifest();
    sign_skill(&mut manifest, SKILL_WAT.as_bytes(), key).unwrap();
    manifest
}

/// A kernel configured entirely from `KernelConfig`: where skills live,
/// whose signatures to trust, and where the audit log is kept.
fn config(skills: &Path, trusted: Vec<String>) -> KernelConfig {
    let mut config = KernelConfig::default();
    config.security.allowed_tools.push(SKILL.to_string());
    config.security.skills_path = Some(skills.to_path_buf());
    config.security.trusted_skill_keys = trusted;
    config
}

fn call() -> ToolRequest {
    ToolRequest::new(SKILL, serde_json::json!({"hello": "world"}))
}

#[tokio::test]
async fn a_signed_skill_runs_and_its_receipt_survives_a_restart() {
    let skills = tempfile::tempdir().unwrap();
    let logs = tempfile::tempdir().unwrap();
    write_skill(skills.path(), &signed_by(&publisher()));

    let mut config = config(skills.path(), vec![key_hex(&publisher())]);
    config.audit.log_path = Some(logs.path().join("audit.jsonl"));
    let audit_key = SigningKey::from_bytes(&[12u8; 32]);
    let digest = hex::encode(module_digest(SKILL_WAT.as_bytes()));

    // First kernel: run the signed skill.
    let (receipt, first_head) = {
        let kernel = Kernel::builder(config.clone())
            .with_audit_signing_key(audit_key.clone())
            .build()
            .await
            .unwrap();
        let response = kernel
            .execute(&AgentId::new(), &SessionId::new(), call())
            .await
            .unwrap();
        assert!(response.success, "{response:?}");
        assert_eq!(response.result, Some(serde_json::json!({"hello": "world"})));
        (response.receipt.unwrap(), kernel.audit_tree_head().await)
    };

    // Second kernel on the same log: a verifier holding only the audit
    // public key checks both leaves against a fresh signed head.
    let kernel = Kernel::builder(config)
        .with_audit_signing_key(audit_key.clone())
        .build()
        .await
        .unwrap();
    let head = kernel.audit_tree_head().await;
    head.verify(&audit_key.verifying_key()).unwrap();
    first_head.verify(&audit_key.verifying_key()).unwrap();
    assert_eq!(
        head.head, first_head.head,
        "nothing lost across the restart"
    );

    let entries = kernel.get_audit_log().await;
    for leaf in [receipt.decision_leaf, receipt.outcome_leaf] {
        let entry = &entries[leaf as usize];
        assert!(entry.verify_integrity());
        let proof = kernel
            .prove_audit_inclusion(leaf, head.head.size)
            .await
            .unwrap();
        verify_inclusion(&Kernel::audit_leaf_hash(entry), &proof, &head.head.root).unwrap();
    }
    let consistency = kernel
        .prove_audit_consistency(receipt.tree_head.head.size, head.head.size)
        .await
        .unwrap();
    verify_consistency(&consistency, &receipt.tree_head.head.root, &head.head.root).unwrap();

    // The outcome names the exact module that ran: the one that was signed.
    let outcome = entries[receipt.outcome_leaf as usize]
        .outcome
        .as_ref()
        .unwrap();
    assert!(outcome.success);
    assert_eq!(outcome.decision_leaf, receipt.decision_leaf);
    assert_eq!(outcome.module_sha256.as_deref(), Some(digest.as_str()));
}

#[tokio::test]
async fn unsigned_untrusted_and_tampered_skills_never_run() {
    let stranger = SigningKey::from_bytes(&[13u8; 32]);
    let mut widened = signed_by(&publisher());
    widened.permissions.network = true;

    let cases: Vec<(&str, SkillManifest, Vec<String>)> = vec![
        ("no trusted keys", signed_by(&publisher()), vec![]),
        (
            "untrusted publisher",
            signed_by(&stranger),
            vec![key_hex(&publisher())],
        ),
        (
            "permissions widened after signing",
            widened,
            vec![key_hex(&publisher())],
        ),
        ("unsigned", manifest(), vec![key_hex(&publisher())]),
    ];

    for (case, manifest, trusted) in cases {
        let skills = tempfile::tempdir().unwrap();
        write_skill(skills.path(), &manifest);
        let kernel = Kernel::new(config(skills.path(), trusted)).await.unwrap();

        let result = kernel
            .execute(&AgentId::new(), &SessionId::new(), call())
            .await;
        assert!(
            matches!(result, Err(KernelError::ToolNotFound { .. })),
            "{case}: {result:?}"
        );
        assert!(
            kernel.list_tools().await.iter().all(|t| t != SKILL),
            "{case}"
        );
    }
}

#[tokio::test]
async fn unsigned_skills_run_only_when_explicitly_allowed() {
    let skills = tempfile::tempdir().unwrap();
    write_skill(skills.path(), &manifest());
    let mut config = config(skills.path(), vec![]);
    config.security.allow_unsigned_skills = true;
    let kernel = Kernel::new(config).await.unwrap();

    let response = kernel
        .execute(&AgentId::new(), &SessionId::new(), call())
        .await
        .unwrap();
    assert!(response.success);
    // Still pinned to the module that was loaded.
    let log = kernel.get_audit_log().await;
    let outcome = log[1].outcome.as_ref().unwrap();
    assert_eq!(
        outcome.module_sha256,
        Some(hex::encode(module_digest(SKILL_WAT.as_bytes())))
    );
}

#[tokio::test]
async fn a_module_swapped_after_loading_is_refused() {
    let skills = tempfile::tempdir().unwrap();
    write_skill(skills.path(), &signed_by(&publisher()));
    let kernel = Kernel::new(config(skills.path(), vec![key_hex(&publisher())]))
        .await
        .unwrap();

    // Replaced after the signature was checked, before it first ran.
    std::fs::write(
        skills.path().join("echo.wat"),
        format!("{SKILL_WAT} ;; now with extra behaviour"),
    )
    .unwrap();

    let response = kernel
        .execute(&AgentId::new(), &SessionId::new(), call())
        .await
        .unwrap();
    assert!(!response.success);
    let error = response.error.unwrap();
    assert!(error.contains("changed since it was verified"), "{error}");

    // The refusal is on the record, naming the module that was approved.
    let log = kernel.get_audit_log().await;
    assert!(matches!(log[0].decision, PolicyDecision::Allow { .. }));
    let outcome = log[1].outcome.as_ref().unwrap();
    assert!(!outcome.success);
    assert_eq!(
        outcome.module_sha256,
        Some(hex::encode(module_digest(SKILL_WAT.as_bytes())))
    );
}

#[tokio::test]
async fn a_malformed_trusted_key_is_a_configuration_error() {
    let skills = tempfile::tempdir().unwrap();
    let result = Kernel::new(config(skills.path(), vec!["not-a-key".to_string()])).await;
    assert!(matches!(
        result,
        Err(KernelError::InvalidConfiguration { ref message }) if message.contains("trusted_skill_keys")
    ));
}
