# TODO

## Completed Items

- [x] Keep current `registry.rs` changes (no reverts applied).
- [x] Review `src/sandbox/registry.rs` signature verification logic after recent edits; default remains strict, unsigned skills only allowed via explicit dev config.
- [x] Verify call sites use `SkillRegistry::new` (strict) in production flows and reserve `new_permissive_dev` for tests/dev-only paths. Only test helper uses `new_permissive_dev`; examples and code use strict defaults.
- [x] **Issue #3**: Implement persistent audit storage backend (`AuditBackend` trait with `MemoryAuditBackend` and `FileAuditBackend` implementations)
- [x] **Issue #6**: Integrate WASM skill execution with kernel via `SkillRegistry` and `WasmSandbox`
- [x] **Issue #51 (partial)**: Add hash-chained audit entries with signature support (signature field added, signing implementation pending)

## In Progress

- [ ] **Issue #4**: Add database schema and migration system for persistent storage
  - Need to implement SQLite backend using rusqlite or sqlx
  - Create migration scripts for audit_logs, policies, agent_sessions, memory_snapshots tables
  
- [ ] **Issue #51**: Complete ed25519 signing support for audit entries
  - Add ed25519-dalek dependency
  - Implement signing in `AuditLogger::log_with_signature()`
  - Add key rotation support

## Future Work

- [ ] **High Priority Issues**: Rate limiting (#13), integration tests (#9), vector store optimization (#10)
- [ ] **Medium Priority Issues**: Default deny policy validation (#19), async Python SDK (#18), benchmarks (#17)
- [ ] Implement flight recorder shadow mode (#43)
- [ ] Add PRM gating and backtracking (#47)
- [ ] Implement Merkle DAG memory fabric (#50)
