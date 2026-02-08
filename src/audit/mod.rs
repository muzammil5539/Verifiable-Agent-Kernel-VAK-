//! Cryptographic Audit Logging Module
//!
//! Provides tamper-evident, hash-chained audit logging for agent actions.
//! Supports pluggable backends for persistent storage (Issue #3).
//!
//! # Features
//! - Hash-chained audit entries for tamper detection
//! - Pluggable storage backends (memory, file, database)
//! - Ed25519 signing for non-repudiation (Issue #51)
//! - Chain verification and integrity checks
//! - SQLite backend for queryable storage (Issue #4)
//! - S3 backend for cloud archival
//! - Multi-region S3 replication for disaster recovery
//! - Real-time streaming for live monitoring
//! - Flight recorder for shadow mode (#43)
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::audit::{AuditLogger, AuditDecision, AuditBackend, FileAuditBackend};
//!
//! // Create with file-based persistence
//! let backend = FileAuditBackend::new("/var/log/vak/audit").unwrap();
//! let mut logger = AuditLogger::with_backend(Box::new(backend)).unwrap();
//!
//! logger.log("agent-1", "read", "/data/file.txt", AuditDecision::Allowed);
//! ```

pub mod flight_recorder;
pub mod graphql;
pub mod multi_region;
pub mod otel;
pub mod replay;
pub mod s3_backend;
pub mod streaming;

// New modules
pub mod backend;
pub mod error;
pub mod file;
pub mod logger;
pub mod memory;
pub mod signing;
pub mod sqlite;
pub mod types;

// Re-export core types
pub use backend::AuditBackend;
pub use error::{AuditError, AuditVerificationError};
pub use file::FileAuditBackend;
pub use logger::AuditLogger;
pub use memory::MemoryAuditBackend;
pub use signing::AuditSigner;
pub use sqlite::SqliteAuditBackend;
pub use types::{AuditDecision, AuditEntry, AuditReport};

// Re-export GraphQL/Query API types (OBS-004)
pub use graphql::{
    AuditLogEntry as GqlAuditLogEntry, AuditQueryEngine, AuditStats as GqlAuditStats,
    ChainVerificationResult as GqlChainVerificationResult, PolicyDecisionEntry,
    PolicyDecisionResult, QueryError, QueryRequest, QueryResponse, QueryResult, SortOrder,
};

// Re-export cryptographic replay types (OBS-002)
pub use replay::{
    ActiveReplay, LogMetadata, ReplayConfig, ReplayError, ReplayReport, ReplayResult,
    ReplaySession, ReplayStep, ReplayVerifier, ReplayedResult, StepComparison,
};

// Re-export OpenTelemetry tracing types (OBS-001)
pub use otel::{
    traced_operation, AttributeValue, OtlpExporter, Span as OtelSpan,
    SpanContext as OtelSpanContext, SpanEvent, SpanKind, SpanLink, SpanStatus, TraceContext,
    TracerStats, TracingConfig, TracingError, TracingResult, VakTracer,
};
