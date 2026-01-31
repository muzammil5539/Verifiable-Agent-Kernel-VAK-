# TODO

## Completed Items

- [x] Keep current `registry.rs` changes (no reverts applied).
- [x] Review `src/sandbox/registry.rs` signature verification logic after recent edits; default remains strict, unsigned skills only allowed via explicit dev config.
- [x] Verify call sites use `SkillRegistry::new` (strict) in production flows and reserve `new_permissive_dev` for tests/dev-only paths. Only test helper uses `new_permissive_dev`; examples and code use strict defaults.
- [x] **Issue #3**: Implement persistent audit storage backend (`AuditBackend` trait with `MemoryAuditBackend` and `FileAuditBackend` implementations)
- [x] **Issue #6**: Integrate WASM skill execution with kernel via `SkillRegistry` and `WasmSandbox`
- [x] **Issue #51 (partial)**: Add hash-chained audit entries with signature support (signature field added, signing implementation pending)
- [x] **Issue #4**: Add SQLite backend for queryable persistent storage (`SqliteAuditBackend` with full CRUD, indexes, and queries)
- [x] **Issue #51**: Complete ed25519 signing support for audit entries
  - Added `AuditSigner` with ed25519-dalek for key generation, signing, and verification
  - `AuditLogger::new_with_signing()` for automatic signing
  - `verify_signatures()` and `verify_all()` methods for validation
  - Key export/import for key rotation support
- [x] **Issue #13**: Rate limiting on policy evaluation (February 2026)
  - Added `RateLimitConfig` with per-agent rate limits and burst control
  - Implemented token bucket algorithm in `RateLimiter`
  - Added `PolicyEngine::with_rate_limit()` and `evaluate_with_rate_limit()` methods
  - Added `RateLimitExceeded` and `RateLimitError` variants to `PolicyError`
  - Comprehensive test coverage for rate limiting per agent
- [x] **Issue #9**: Integration tests for kernel + policy + audit workflow (February 2026)
  - Created `tests/integration/` directory structure
  - Added `test_kernel_workflow.rs` with end-to-end workflow tests
  - Added `test_policy_enforcement.rs` with ABAC and pattern matching tests
  - Added `test_audit_integrity.rs` with chain verification tests
  - Tests cover: concurrent agents, rate limiting, policy conflicts, error recovery
- [x] **Issue #10**: Vector store optimization (February 2026)
  - Added `OptimizedVectorStore` with batch operations
  - Added `VectorStoreStats` for performance tracking
  - Added `OptimizationConfig` for tunable search parameters
  - Added batch search capability via `search_batch()`
  - Statistics tracking for search latency and comparison counts
- [x] **Issue #19**: Default deny policy validation on startup (February 2026)
  - Added `has_allow_rules()` method to check for Allow policies
  - Added `validate_config()` method returning warnings for:
    - Empty policy configurations
    - No Allow policies (all actions will be denied)
    - Overly permissive rules (allow * on * with no conditions)
  - Added `rule_count()` method for policy inspection
- [x] **Issue #18**: Async Python SDK documentation and patterns (February 2026)
  - Added `AsyncKernelHelper` with comprehensive usage documentation
  - Documented `run_in_executor` pattern for async frameworks
  - Added FastAPI integration examples
  - Added ThreadPoolExecutor optimization guidance
  - Updated type stubs with all new methods
- [x] **Issue #17**: Benchmarks for critical paths (February 2026)
  - Added `bench_rate_limiting` to measure rate limit overhead
  - Added `bench_concurrent_policy_evaluation` for multi-agent scenarios
  - Added `bench_policy_validation` for config validation
  - Enhanced existing benchmarks with Issue #17 documentation

## In Progress

- [ ] Add migration scripts for other persistent data (policies, agent_sessions, memory_snapshots tables)

## Future Work

- [ ] Implement flight recorder shadow mode (#43)
- [ ] Add PRM gating and backtracking (#47)
- [ ] Implement Merkle DAG memory fabric (#50)
- [ ] Add S3Backend for cloud audit log archival
- [ ] Implement `vak-skill-sign` CLI helper tool
- [ ] Z3 formal verification integration (#12)
- [ ] LangChain / AutoGPT middleware adapter (#45)
- [ ] Basic OSS dashboard and observability (#46)
