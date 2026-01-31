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

## In Progress

- [ ] Add migration scripts for other persistent data (policies, agent_sessions, memory_snapshots tables)

## Future Work

- [ ] **High Priority Issues**: Rate limiting (#13), integration tests (#9), vector store optimization (#10)
- [ ] **Medium Priority Issues**: Default deny policy validation (#19), async Python SDK (#18), benchmarks (#17)
- [ ] Implement flight recorder shadow mode (#43)
- [ ] Add PRM gating and backtracking (#47)
- [ ] Implement Merkle DAG memory fabric (#50)
- [ ] Add S3Backend for cloud audit log archival
- [ ] Implement `vak-skill-sign` CLI helper tool
