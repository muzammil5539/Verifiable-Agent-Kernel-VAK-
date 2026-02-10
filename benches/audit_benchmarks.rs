use criterion::{criterion_group, criterion_main, Criterion};
use std::fs;
use std::path::PathBuf;
use vak::audit::{AuditBackend, AuditDecision, AuditLogger, FileAuditBackend};

fn setup_benchmark(temp_dir: &PathBuf) -> PathBuf {
    let backend_path = temp_dir.join("audit_bench");
    if backend_path.exists() {
        fs::remove_dir_all(&backend_path).unwrap();
    }
    fs::create_dir_all(&backend_path).unwrap();

    let backend = FileAuditBackend::new(&backend_path).unwrap();
    // Initialize logger to create a valid chain
    let mut logger = AuditLogger::with_backend(Box::new(backend)).unwrap();

    for i in 1..=1000 {
        logger.log(
            format!("agent-{}", i),
            "test",
            "/test",
            AuditDecision::Allowed,
        );
    }
    logger.flush().unwrap();
    backend_path
}

fn bench_audit_logger_init(c: &mut Criterion) {
    let temp_dir = std::env::temp_dir();
    let backend_path = setup_benchmark(&temp_dir);

    c.bench_function("audit_logger_init", |b| {
        b.iter(|| {
            let backend = FileAuditBackend::new(&backend_path).unwrap();
            let _logger = AuditLogger::with_backend(Box::new(backend)).unwrap();
        })
    });

    // Clean up
    if backend_path.exists() {
        fs::remove_dir_all(&backend_path).unwrap();
    }
}

criterion_group!(benches, bench_audit_logger_init);
criterion_main!(benches);
