# TODO

- [x] Keep current `registry.rs` changes (no reverts applied).
- [x] Review `src/sandbox/registry.rs` signature verification logic after recent edits; default remains strict, unsigned skills only allowed via explicit dev config.
- [x] Verify call sites use `SkillRegistry::new` (strict) in production flows and reserve `new_permissive_dev` for tests/dev-only paths. Only test helper uses `new_permissive_dev`; examples and code use strict defaults.
