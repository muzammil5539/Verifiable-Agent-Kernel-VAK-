# VAK Implementation TODO

> **Project:** Verifiable Agent Kernel (VAK) / Exo-Cortex
> **Rewritten:** 2026-08-16, replacing a tracker that marked 90/90 items "complete"
> while `tests/integration_root.rs` did not compile and the kernel's request path
> called none of the policy engine, reasoner, memory fabric, or swarm modules.

## How this list is scoped

Every item below was verified by reading the call path, not by confirming a file
exists. The completion bar is:

**A feature is not done until a test drives it through `Kernel::execute`.**

Applying that bar retroactively reclassified most of the previous roadmap. See the
audit report (linked from project memory) for the full finding-by-finding evidence.
Do not restore "100% complete" language until every item in this file is closed —
that language is exactly how the gap went unnoticed for thirteen sprints.

---

## Done (verified, not just present)

- [x] Audit entries commit to the decision and the predecessor hash; tampering,
      reordering and deletion are all now detected — `AuditEntry::verify_chain`
      (`src/kernel/types.rs`, `tests/audit_chain_integrity.rs`)
- [x] `Kernel::execute` denies by default when no rule matches, instead of
      always returning `Allow` (`src/kernel/mod.rs`)
- [x] Denied requests are audited, not just successful ones
- [x] WASM skill registry resolves `.github/skills/` (was hardcoded to a
      nonexistent `skills/` directory)
- [x] `CedarEnforcer` is wired into `Kernel::execute` via `policy.policy_paths`;
      a `ToolRequest` becomes a real `Principal`/`Action`/`Resource` triple
      checked against policy files — see `docs/adr/0001` (`src/kernel/mod.rs`,
      `tests/policy_enforcement.rs`)
- [x] Policy rule `conditions` are evaluated instead of parsed-and-discarded;
      the kernel supplies the attributes conditions read (`src/policy/enforcer.rs`)
- [x] `tests/integration_root.rs` compiles and its 143 tests actually run
      (was broken by a `JoinHandle<u32>`/`JoinHandle<()>` mismatch, silently
      making the whole target un-buildable)
- [x] `cargo clippy --all-targets` and `cargo test --doc` pass with zero errors
      (five pre-existing failures fixed: a bad doctest, a stale PyO3 API call,
      three `3.14`-as-π lint hits)
- [x] Dead, never-compiled `src/kernel/kernel.rs` (427 lines, not a declared
      module) removed
- [x] `CONTEXT.md` and `docs/adr/` established as the place decisions get
      recorded, so the next drift is visible in a diff instead of silent
- [x] `sandbox::async_host` denies when its enforcer can't be built, instead of
      falling back to `CedarEnforcer::new_permissive()`
      (`test_enforcer_construction_failure_denies`)
- [x] SymCC proofs (`docs/adr/0009`, feature `cedar-analysis`): properties written in
      Cedar (ceilings, floors) proven over every request the schema admits, plus
      never-errors for each policy, with confirmed counterexamples; `cedar_check` for CI;
      CI installs cvc5 and proves the shipped policies. `CedarPolicy` hot-reloads, and
      `reload_checked` refuses a set that breaks a property or widens access. It found the
      payments example letting a finance agent use a blocked tool
- [x] Real Cedar (`docs/adr/0008`, feature `cedar`): `policy.format: cedar` decides
      with the `cedar-policy` crate against a schema for VAK's agents, tools and
      per-tool actions (typed arguments). Policies are validated at load, and a call
      that doesn't match the schema, or on which any policy errors, is denied.
      `policies/cedar/default.cedar` ports the default tool rules;
      `tests/cedar_policy.rs` shows it decides like the YAML original
- [x] One audit path (`docs/adr/0007`): the `AuditLog` port records everything the
      kernel mediates; `SqliteAuditLog` (`audit.format: sqlite`) is its durable,
      queryable adapter and refuses a database that doesn't verify; durable appends
      finish even if the caller stops waiting. `AuditLogger` hashes every field
      length-prefixed, `metadata` included (K7), returns write failures as errors, and
      stays verifiable across rotation. `tests/audit_path.rs` drives it through
      `Kernel::execute`
- [x] Feature gates (`docs/adr/0006`): the trusted core builds and tests alone with
      `--no-default-features` (no Wasmtime); `reasoner`, `experimental-zk`, `swarm`,
      `integrations`, `dashboard`, `legacy-tools` and `python` are off by default;
      `--features full` is what CI tests, plus a core-only job
- [x] Signed skills (`docs/adr/0005`): Ed25519 over the module digest and manifest,
      verified against `security.trusted_skill_keys`, unsigned skills refused by default,
      each skill pinned to the module it was verified with, the module digest recorded in
      the outcome leaf. `tests/signed_skills.rs` also meets the Phase 1 exit criterion
      (sign, load, execute, prove both leaves after a restart)
- [x] Shared WASM runtime (`docs/adr/0004`): one engine and a SHA-256-keyed module
      cache per kernel (injectable, so kernels can share), one epoch ticker thread that
      parks while idle, skills run on `spawn_blocking`, skill output bounds-checked.
      `tests/wasm_skills.rs` runs a real module through `Kernel::execute`, including a
      spinning skill on a single-threaded runtime that must not stall other requests
- [x] Mediation pipeline stages from `docs/adr/0003`, all driven through
      `Kernel::execute` in `tests/mediation_pipeline.rs`: Admit (agent registry,
      suspension, session binding, per-agent tool scope moved out of `VakAgent`),
      Budget (`security.enable_rate_limiting` is now enforced), principal attributes
      from the agent record instead of a constant `internal = true`, the `AuditLog`
      port with a durable JSONL adapter (`audit.log_path`), outcome leaves, and
      receipts on `ToolResponse`

---

## P0 — Security: still fails open

- [x] **Upgrade Wasmtime past its advisories** (finding K11 in
      `docs/architecture-v2.md`, ADR 0010). Wasmtime 49.0.2 with default features
      off: Cranelift only, no Winch, component model, GC or WASI. PyO3 0.29.
      `tests/sandbox_escapes.rs` drives each advisory's escape path through
      `Kernel::execute`, tables are capped at 10,000 elements, and `cargo deny check`
      passes. MSRV 1.96.

- [ ] **ZK proofs are not zero-knowledge.** `src/reasoner/zk_proof.rs::verify_response`
      accepts any 64-character hex string as a valid proof of any statement — there is
      no check binding the response to the witness. The module now carries an explicit
      warning, but the public API still returns `valid: true` for forged proofs.
      Decide: (a) implement a real backend (arkworks/bellman — a project, not a patch),
      or (b) rename the module and gate it behind a feature flag that defaults off, with
      the README/API docs updated to stop claiming this property. Do not ship both the
      warning and the unqualified "Zero-Knowledge Proofs — Complete" claim at once.

---

## P1 — Wire the rest of the vision into the kernel

Each of these exists as a well-tested standalone module. None of them sit on the
request path. In order of leverage:

- [x] **Delegate kernel auditing to `AuditLogger`, backed by `MerkleDag`.**
      *Superseded (ADR 0002, 0003, 0007):* the kernel records through the `AuditLog`
      port over an RFC 9162 tree, with receipts, inclusion proofs for any decision,
      and memory, JSONL and SQLite adapters. `AuditLogger` stays a standalone event
      log; it was not made the kernel's.

- [ ] **Gate high-risk actions on the neuro-symbolic reasoner.** PRM scoring,
      the Datalog safety engine (`src/reasoner/datalog.rs`), and the Z3
      verification gateway are implemented and unit-tested, but
      `neurosymbolic_pipeline.rs` is an opt-in parallel path, not something
      `Kernel::execute` calls by default. Define what "high-risk" means for a
      `ToolRequest` (a policy attribute? an explicit tool tag?) and route those
      through PRM → Datalog → Z3 before dispatch, matching the vision's
      "neural proposal → symbolic verification → execution" sandwich. Note
      `Z3Verifier` shells out to a `z3` binary via `std::process::Command` —
      decide what happens when it's not installed (currently: verification is
      silently unavailable).

- [ ] **Ship the WASM skills for real.** No skill manifest (`skill.yaml`) exists
      anywhere in the repo, and there's no build step compiling the five skill
      crates under `.github/skills/` to `wasm32-unknown-unknown` and signing
      them. The registry now points at the right directory (fixed) but has
      nothing to load. *Narrowed:* real modules now run through `Kernel::execute`
      in tests (`tests/wasm_skills.rs`, `tests/signed_skills.rs`), and
      `examples/sign_skill.rs` signs manifests. What remains is a `make skills`
      step that builds the five crates, writes their manifests, and signs them.

- [ ] **Swarm consensus is unreachable from the kernel.** Voting, consensus,
      and sycophancy detection (`src/swarm/`) have no caller outside their own
      tests or `src/integrations/`. Scope this only if multi-agent orchestration
      through `Kernel` is actually a near-term use case — otherwise leave it
      documented as a standalone library the way `lib_integration.rs` already
      exposes other pieces.

---

## P2 — Fix the parts that mislead adopters

- [x] **`SecretScrubber` doesn't redact values under sensitive keys.**
      `scrub_json` and `scrub_map` now redact whole any value under a key in
      `SENSITIVE_KEYS`, matched as a whole key, ignoring case. "author" and
      "max_tokens" keep their values. Nothing on the kernel's path calls the
      scrubber yet.

- [x] **MCP `execute_skill` reports success without running anything** (finding I3
      in `docs/architecture-v2.md`). It now runs every call through
      `Kernel::execute` on the kernel `create_vak_mcp_server` is given; a refused,
      unknown or failed skill is an error result.

- [ ] **The Python SDK's native `Kernel` is not the kernel** (finding I4).
      `PyKernel` in `src/python.rs` has its own `PolicyEngine` and `AuditLogger`
      instead of wrapping `vak::kernel::Kernel`, and `execute_tool` returns
      `success: "true"` without running anything. Wrap `Kernel` (its `execute`,
      receipts and audit proofs) and make an unknown tool an error. `AuditLogger`
      can then be removed or kept on its own merits (`docs/adr/0007`).

- [ ] **Python SDK silently substitutes a fake kernel.** `VakKernel` falls back
      to `_StubKernel` — a pure-Python in-memory imitation with no policy
      enforcement and no real audit chain — whenever the PyO3 extension isn't
      built, which is the default result of `pip install -e ./python`. Make the
      fallback opt-in (`allow_stub=True` or an env var) and loud (a warning on
      every call while active). A trust kernel must never quietly replace
      itself with a mock.

- [ ] **The flagship MVP demo doesn't use VAK.** `examples/code_auditor_python.py`
      — the Autonomous Code Auditor named in the vision as *the* MVP — uses
      `hashlib` and `re` directly and imports nothing from `vak`. Either rewrite
      it against the real Python SDK once P1's reasoner gating exists, or retitle
      it as a design sketch so it stops standing in as proof the kernel is usable
      for real work.

- [ ] **README quick-start does not compile.** `Kernel::create_session()`,
      `KernelConfig::with_policy_path()`, `kernel.audit_logger()`, and
      `get_audit_trail()` are all called in the README's first example; none
      exist. Rewrite the example against the current API (`policy.policy_paths`,
      `get_audit_log()`), and consider adding the example as a doctest so this
      can't drift silently again — it's the same failure mode as the
      integration-test build break.

---

## P3 — Process, so this doesn't happen again

- [ ] **Wire `cargo test` and `cargo clippy --all-targets --all-features` into
      a CI gate that actually blocks merges.** The integration-test build
      break (P0-severity, now fixed) survived thirteen sprints of "complete"
      status updates because nothing ran it. If CI already exists
      (`.github/workflows/ci.yml` is referenced in prior notes), verify it
      is *required* for merge, not merely present.
- [ ] **Do not restore aggregate "N% complete" framing** in this file, the
      README, or CHANGELOG until every P0/P1 item above is closed and verified
      by a test that exercises `Kernel::execute`. Track items as done/open;
      let the reader compute the percentage if they want one.
- [ ] Reconcile `docs/gap-analysis-roadmap.md` and `docs/blue-ocean-opportunity.md`
      against this file — they currently describe both a "~75% complete Beta"
      and a "100% complete v1.0" for the same codebase. Pick one document as
      the live status source (recommend: this file) and mark the others
      historical/point-in-time.

---

## Definition of done (replaces the previous checklist)

A change is done when:

- [ ] A test exercises it through `Kernel::execute` (or the documented public
      entry point, for non-kernel code) — not only through a unit test inside
      the same module
- [ ] `cargo test`, `cargo clippy --all-targets --all-features -- -D warnings`,
      and `cargo fmt --all -- --check` all pass locally
- [ ] Any new fail-open path is impossible by construction, or is explicitly
      justified in an ADR under `docs/adr/`
- [ ] Documentation (README, ARCHITECTURE.md, this file) is updated in the
      same change, not deferred
