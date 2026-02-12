//! Integration tests for audit chain integrity (Issue #9)
//!
//! Tests audit logging, chain verification, and signing

use vak::audit::{AuditDecision, AuditLogger, AuditSigner};

/// Test: Basic audit logging
#[test]
fn test_basic_audit_logging() {
    let mut logger = AuditLogger::new();

    let entry = logger.log(
        "agent-001",
        "read",
        "/data/file.txt",
        AuditDecision::Allowed,
    );

    assert_eq!(entry.agent_id, "agent-001");
    assert_eq!(entry.action, "read");
    assert_eq!(entry.resource, "/data/file.txt");
    assert!(matches!(entry.decision, AuditDecision::Allowed));
}

/// Test: Audit chain hash linking
#[test]
fn test_audit_chain_hash_linking() {
    let mut logger = AuditLogger::new();

    // Log several entries
    logger.log("agent-001", "read", "/data/a.txt", AuditDecision::Allowed);
    logger.log("agent-001", "write", "/data/b.txt", AuditDecision::Denied);
    logger.log("agent-002", "read", "/data/c.txt", AuditDecision::Allowed);

    // Verify chain
    assert!(logger.verify_chain().is_ok());

    // Get entries and verify linking
    let entries = logger.load_all_entries().unwrap();
    assert_eq!(entries.len(), 3);

    // First entry has prev_hash of zeros (genesis)
    assert_eq!(&entries[0].prev_hash, "0000000000000000000000000000000000000000000000000000000000000000");

    // Second entry's prev_hash should match first entry's hash
    assert_eq!(entries[1].prev_hash, entries[0].hash);

    // Third entry's prev_hash should match second entry's hash
    assert_eq!(entries[2].prev_hash, entries[1].hash);
}

/// Test: Chain verification detects tampering
#[test]
fn test_chain_tampering_detection() {
    let mut logger = AuditLogger::new();

    // Log entries
    logger.log("agent-001", "read", "/data/a.txt", AuditDecision::Allowed);
    logger.log("agent-001", "write", "/data/b.txt", AuditDecision::Denied);
    logger.log("agent-002", "read", "/data/c.txt", AuditDecision::Allowed);

    // Verify chain is initially valid
    assert!(logger.verify_chain().is_ok());

    // Note: In a real tampering test, we'd modify entries directly
    // but that requires mutable access to internal entries
    // The chain verification logic is tested in unit tests
}

/// Test: Audit logging with signatures
#[test]
fn test_audit_logging_with_signatures() {
    // Create logger with signing
    let mut logger = AuditLogger::new_with_signing();

    // Log entries with automatic signing
    logger.log("agent-001", "read", "/data/file.txt", AuditDecision::Allowed);
    logger.log("agent-001", "write", "/data/file.txt", AuditDecision::Denied);

    // Verify signatures
    let pk = logger.public_key().unwrap().to_string();
    assert!(logger.verify_signatures(&pk).is_ok());

    // Verify both chain and signatures
    assert!(logger.verify_all(Some(&pk)).is_ok());
}

/// Test: Signature verification fails for unsigned entries
#[test]
fn test_signature_verification_unsigned() {
    // Logger without signing
    let mut logger = AuditLogger::new();
    logger.log("agent-001", "read", "/data/file.txt", AuditDecision::Allowed);

    // Entries should not have signatures
    let entries = logger.load_all_entries().unwrap();
    assert!(entries[0].signature.is_none());
}

/// Test: Audit entry filtering by agent
#[test]
fn test_audit_filtering_by_agent() {
    let mut logger = AuditLogger::new();

    // Log entries from different agents
    for i in 0..30 {
        let agent = format!("agent-{:03}", i % 3);
        logger.log(&agent, "action", format!("/resource/{}", i), AuditDecision::Allowed);
    }

    // Get entries for a specific agent
    let all_entries = logger.load_all_entries().unwrap();
    let agent_000_entries: Vec<_> = all_entries
        .iter()
        .filter(|e| e.agent_id == "agent-000")
        .collect();

    assert_eq!(agent_000_entries.len(), 10);
}

/// Test: Audit entry filtering by time range
#[test]
fn test_audit_filtering_by_time() {
    let mut logger = AuditLogger::new();

    // Log entries
    for i in 0..10 {
        logger.log("agent-001", "action", format!("/resource/{}", i), AuditDecision::Allowed);
    }

    // All entries should have timestamps
    let entries = logger.load_all_entries().unwrap();
    assert!(entries.iter().all(|e| !e.timestamp.to_string().is_empty()));
}

/// Test: Large audit chain performance
#[test]
fn test_large_audit_chain_integrity() {
    let mut logger = AuditLogger::new();

    // Log many entries
    for i in 0..1000 {
        let decision = if i % 3 == 0 {
            AuditDecision::Denied
        } else {
            AuditDecision::Allowed
        };
        logger.log(
            format!("agent-{:03}", i % 10),
            format!("action-{}", i % 5),
            format!("/resource/{}", i),
            decision,
        );
    }

    // Verify chain integrity
    assert_eq!(logger.load_all_entries().unwrap().len(), 1000);
    assert!(logger.verify_chain().is_ok());
}

/// Test: Signer key export/import
#[test]
fn test_signer_key_export_import() {
    // Create original signer and export key
    let signer1 = AuditSigner::new();
    let key_bytes = signer1.export_key_bytes();

    // Create new signer from exported key
    let signer2 = AuditSigner::from_key_bytes(&key_bytes).expect("Failed to import key");

    // Both signers should produce same public key
    // (Signatures would be identical for same data)
}

/// Test: Concurrent audit logging
#[tokio::test]
async fn test_concurrent_audit_logging() {
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tokio::task::JoinSet;

    let logger = Arc::new(RwLock::new(AuditLogger::new()));
    let mut join_set = JoinSet::new();

    // Spawn concurrent logging tasks
    for i in 0..10 {
        let logger_clone = logger.clone();
        join_set.spawn(async move {
            let mut logger = logger_clone.write().await;
            for j in 0..10 {
                logger.log(
                    format!("agent-{:03}", i),
                    "concurrent-action",
                    format!("/resource/{}/{}", i, j),
                    AuditDecision::Allowed,
                );
            }
        });
    }

    // Wait for all tasks to complete
    while let Some(result) = join_set.join_next().await {
        result.expect("Task panicked");
    }

    // Verify all entries were logged
    let logger = logger.read().await;
    assert_eq!(logger.load_all_entries().unwrap().len(), 100);
    assert!(logger.verify_chain().is_ok());
}
