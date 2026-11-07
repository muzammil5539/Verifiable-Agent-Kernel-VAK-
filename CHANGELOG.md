# Changelog

All notable changes to the Verifiable Agent Kernel (VAK) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

See `docs/architecture-v2.md` for the audit and design behind these changes, and
`docs/adr/0002-reference-monitor-core-with-ports-and-transparency-log.md` and
`docs/adr/0003-admit-budget-record-outcome-pipeline-stages.md` for the decision records.

### Added
- Datalog safety rules on Ascent, and on the request path (docs/adr/0020, finding V3).
  - **The engine.** The nine built-in rules of `reasoner::datalog::SafetyEngine` are
    an Ascent program evaluated to a fixpoint, no longer Rust closures. Directory
    containment is recursive, the network-capability rule is a stratified negation,
    and an agent's risk is the highest score recorded for it. The closures read an
    arbitrary one of several. The API is unchanged.
  - **The guard.** `reasoner::DatalogGuard`, assurance `enforced`, is added with
    `KernelBuilder::with_guard`.
    - **Verdicts.** It denies on a violation, escalates on a risk warning, and
      otherwise abstains, so it never satisfies a floor.
    - **Targets.** It checks a tool's `path`, `target`, `file`, `url`, `tool` and
      `command` arguments, or the one argument `with_tool` names. It denies a call
      whose target it can't read.
  - **Wider matches.** External endpoints are canonicalised and match by host and
    path: `https://EVIL.com/x` used to pass a fact for `https://evil.com`. Restricted
    tools match by leading words (`rm  -rf /` runs `rm -rf`). A NaN block threshold
    blocks instead of passing everything.
  - **Dependency:** `ascent` 0.8.1, without its parallel feature, behind `reasoner`.
- The prompt-injection detector on the request path (docs/adr/0019, finding R6).
  `reasoner::PromptInjectionGuard`, assurance `heuristic`, added with
  `KernelBuilder::with_guard`.
  - **What it does.** It denies at block level and escalates at review level, which
    the kernel refuses. Otherwise it abstains, so it never satisfies a
    `min_assurance` floor.
  - **What it reads.** Every string in the arguments, keys included, decoded rather
    than as JSON text. Arguments longer than `max_input_length` are denied.
  - **Detector fixes.** Truncation cuts at a character boundary; it used to panic
    inside a multi-byte character. An allowlist match used to clear the whole
    input; it now exempts only the matches it contains. `try_new` refuses invalid
    patterns and thresholds, which `new` drops or accepts.
- The constitution on the request path (docs/adr/0018, finding K5). With
  `policy.constitution`, the default safety constitution runs as the first guard:
  `ConstitutionGuard`, assurance `enforced`.
  - **What it does.** It denies what its rules forbid, escalates rules needing
    review, and otherwise abstains, so it never satisfies a `min_assurance`
    floor.
  - **What it checks.** It evaluates `PrePolicy`, `PreExecution` and `All`
    rules, against a context that always has a `resource`.
  - **For embedders.** They can add one over their own constitution.
- Cedar policies read information-flow labels (ADR 0016).
  - **What Cedar sees.** With `policy.labels.enabled`, a call's label is
    `context.labels` (`integrity`, `public`, `readers`, `sources`), and the tool's
    `external` attribute is `policy.labels.external`.
  - **The schema contract.** The schema must declare `labels` on every action and
    `external` on `Tool`, all required. With labels off, it must declare none of
    them. Optional or partial declarations are refused at load. An optional one
    would let a `has`-guarded forbid skip calls silently.
  - **Mismatches.** If the setting and the schema disagree, every call is denied as
    `policy.labels`. With labels on, an unlabelled call is denied.
  - **The example.** `policies/cedar/examples/labels.cedarschema`, `labels.cedar` and
    `labels.properties.cedar`. SymCC proves that no external call on untrusted
    arguments is allowed, and that private mail reaches only its readers.
  - **Breaking:** `CedarRequest` gains the public fields `labels` and `external`.
- Information-flow labels (ADR 0014; slice 2d). Off unless `policy.labels.enabled`.
  - **Labels.** `kernel::ifc`, in the core: `Label` with `Integrity` (`Trusted <
    Untrusted`), `Readers` (`public` or a set) and `Source` (`user`, `tool:<name>`,
    `skill:<name>`). `Label::join` combines two labels; it and the builders only
    raise a label. `Labeled<T>` keeps a value with its label.
  - **Context labels, per agent.** The kernel keeps one per agent: the join of every
    result it returned to the agent and every label the agent declared. A call's
    arguments get it. A new session doesn't clear it.
  - **Results.** A result's label is its tool's source label joined with its
    arguments'. The label joins the agent's context before the agent sees the
    result, and a failed tool's error counts.
  - **Source labels.** `policy.labels.sources` maps tool-name patterns to source
    labels; overlaps join. An unlisted tool is untrusted, except the built-ins.
    `policy.labels.external` lists the tools policies see as `resource.external`.
  - **Declaring labels.** `Kernel::execute_labeled` takes a `Labeled<ToolRequest>`
    and returns a `Labeled<ToolResponse>`. A declared label only raises the agent's
    context. `Kernel::context_label` reads the context.
  - **Who reads them.** `PolicyRequest::labels` and `GuardRequest::labels`.
    `evaluate_policy` passes the current context label. YAML rules read
    `context.args_integrity`, `args_public`, `args_readers`, `args_sources` and
    `resource.external`. Without labels, a rule that reads them fails closed.
    `ConfigPolicy` ignores labels. Cedar reads them too (below).
  - **The record.** `AuditEntry::label`: the arguments' label on decision and refusal
    entries, the result's on outcome entries. It is hashed only when present, so
    existing logs verify. The Python binding shows it in an entry's details.
  - **Startup checks.** `sources` or `external` set while labels are off are refused,
    as are malformed patterns.
  - **Breaking:** `AuditEntry` gains the public field `label`, and `PolicyConfig` the
    public field `labels`.
- The Guard stage (ADR 0013; slice 2c).
  - **The port.** `kernel::guard`, in the core: the `Guard` port (`check`, `name`,
    `assurance`), `Assurance` (`Experimental < Heuristic < Checked < Enforced`),
    `GuardVerdict` (`Pass`, `Abstain`, `Deny`, `Escalate`), `GuardRequest`,
    `FunctionGuard` and `GuardChecks`.
  - **Running guards.** `KernelBuilder::with_guard` adds a guard, and `Kernel::guards`
    lists them. `Kernel::execute` runs them on calls the policy allowed, in order.
  - **Refusals.** A deny or an escalation refuses the call as
    `KernelError::PolicyViolation` with `policy_id` `guard.<name>`. So does a guard
    that panics, or doesn't answer within `max_execution_time`. A guard that blocks
    the thread can't be interrupted, so its late answer becomes a denial. There is
    no approval channel yet, so escalations refuse.
  - **`policy.min_assurance`.** It maps tool-name patterns to the level a guard must
    have *passed* a call at; the policy's own allow doesn't count. A shortfall is
    refused as `policy.min_assurance`. Malformed patterns and the level
    `experimental` are refused at startup.
  - **The record.** `AuditEntry::guards`, on entries for calls that reached the
    Guard stage, holds the level required and each guard that ran, with its verdict
    and level. It is hashed only when present, so existing logs verify.
  - **No adapters yet,** and nothing changes without guards or a floor.
  - **Breaking:** `AuditEntry` gains the public field `guards`, and `PolicyConfig`
    the public field `min_assurance`.
- `Kernel::load_skill` and `Kernel::skill_manifest` (feature `wasm`): load a WASM skill
  while the kernel runs, verified as skills loaded at startup are, and read a loaded
  skill's manifest. Loading authorizes no one; policy still decides every call.
  `KernelError::SkillRejected` (E016) when a manifest or module can't be read or
  doesn't verify.
- `sandbox::MAX_TABLE_ELEMENTS` (ADR 0010): a skill's tables are capped at 10,000
  elements, at instantiation and on `table.grow`, with either allocator. Tables live in
  host memory, outside the linear-memory limit.
- `tests/sandbox_escapes.rs`: the escape paths named by the Wasmtime advisories in
  finding K11, through `Kernel::execute`.
- The `cedar-analysis` feature (ADR 0009): `policy::cedar::analysis` (`Analyzer`,
  `PolicyProperties`, `AnalysisReport`, `check_reload`, `Widening`, `ReloadRefused`)
  proves properties of Cedar policy sets with SymCC and cvc5 1.3.1. `CedarPolicy::reload`
  and `reload_checked`. `examples/cedar_check.rs` runs the checks in CI.
  `policies/cedar/properties/` holds the default policies' properties.
- The `cedar` feature (ADR 0008; needs Rust 1.89): `policy::cedar` (`CedarPolicySet`,
  `CedarRequest`, `CedarDecision`, `CedarPolicyError`, `VAK_SCHEMA`) and
  `kernel::CedarPolicy`, a `PolicyDecisionPoint` over the `cedar-policy` crate. Selected
  with `policy.format: cedar` (`PolicyFormat`, `VAK_POLICY__FORMAT`), with
  `policy.cedar_schema` (`VAK_POLICY__CEDAR_SCHEMA`) for a schema of your own.
  `policies/cedar/` holds the kernel's schema, the default tool rules in Cedar, and a
  typed-arguments example.
- `kernel::DenyAll`: the decision point used when configured policies can't be loaded.
- `kernel::SqliteAuditLog` (ADR 0007): the kernel's audit log in SQLite, selected with
  `audit.format: sqlite` (`AuditLogFormat`, `VAK_AUDIT__FORMAT`). Each append is a
  durable transaction; opening verifies every row and refuses a database VAK didn't
  create. `AuditLogError::Format`.
- `audit::entry_hash` and `AuditReport::legacy_entries` (ADR 0007).
- Cargo features (ADR 0006): `wasm`, `llm`, `memory`, `reasoner`, `experimental-zk`,
  `swarm`, `integrations`, `dashboard`, `legacy-tools`, `python`, and `full` (everything
  but `python`). `default-features = false` builds the trusted core alone.
- `sandbox::signing` (ADR 0005): Ed25519 skill signatures over the module's SHA-256 and
  every manifest field except `wasm_path`, verified against trusted publisher keys.
  `SkillManifest::signed_by`, `SkillRegistry::module_digest`,
  `SandboxRuntime::prepare_file_pinned`, `SandboxError::ModuleChanged`,
  `AuditOutcome::module_sha256`, and `security.{skills_path, trusted_skill_keys,
  allow_unsigned_skills}`. `examples/sign_skill.rs` generates publisher keys and signs
  manifests.
- `sandbox::SandboxRuntime` (ADR 0004): one Wasmtime engine, a compiled-module cache
  keyed by SHA-256, and one epoch ticker that parks while idle. The kernel runs every
  WASM skill on it, on `tokio::task::spawn_blocking`. `KernelBuilder::{with_sandbox_runtime,
  with_skill_registry}`, `Kernel::sandbox_runtime`, `WasmSandbox::with_runtime`.
- Mediation pipeline stages (ADR 0003). `kernel::identity` (`AgentRegistry`,
  `AgentRecord`, `InMemoryAgentRegistry`) for the Admit stage, `kernel::budget`
  (`Budget`, `AgentRateBudget`, `Unlimited`) for the Budget stage, and
  `kernel::audit_log` (`AuditLog`, `MemoryAuditLog`, `FileAuditLog`) for the Record
  stages. Injected with `KernelBuilder::{with_agent_registry, with_budget,
  with_audit_log}`.
- `Kernel::register_agent`, `Kernel::end_session`, and
  `security.require_registered_agents`.
- Outcome leaves (`AuditEntry::outcome`, `AuditOutcome`) and receipts
  (`ToolResponse::receipt`, `AuditReceipt`).
- `KernelError::{AgentSuspended, SessionConflict, RateLimited, AuditUnavailable}`
  (E012 to E015). `PolicyRequest` gained `principal` and `session_id`.
- `audit::transparency`: RFC 9162 Merkle tree log with inclusion and consistency proofs,
  stand-alone verifiers, and Ed25519-signed tree heads. Tested against the Certificate
  Transparency reference vectors.
- `kernel::ports::PolicyDecisionPoint` and `Kernel::builder`, so embedders can inject a
  policy engine, host-side tool handlers (`with_tool`, `Kernel::register_tool`) and an
  audit signing key.
- `Kernel::audit_tree_head`, `prove_audit_inclusion`, `prove_audit_consistency` and
  `audit_leaf_hash`: any decision can be proven to a third party.
- `KernelError::AuditProof`, `HandlerError::AlreadyRegistered`,
  `CustomHandlerRegistry::{register_arc, register_new}`.

### Changed
- **Breaking:** the `vak` Python package is 1.0.0 (was 0.1.0), for the methods removed
  and changed below. Its version is separate from the crate's. `docs/python-sdk.md`
  has a migration note for each.
- Coverage is measured with cargo-llvm-cov, not tarpaulin (ADR 0012). Tarpaulin's
  ptrace engine reported Wasmtime's signal-based traps as a segfault, so the job never
  finished. `make coverage` and `make coverage-check` run it; it needs
  `llvm-tools-preview`. The floor stays at 80% of lines, and the first measurement is
  75.09%, so the job now fails on the floor (`TODO.md`). `tarpaulin.toml` is removed.
- **Breaking:** Wasmtime 49.0.2 (was 41.0.4), for the 16 advisories in finding K11
  (ADR 0010). Default features are off: Cranelift is the only compiler, and Winch, the
  component model, GC, threads and WASI aren't compiled in. `cargo deny check` passes.
  - **Fuel.** Wasmtime now charges fuel per byte for bulk memory operations, so the
    kernel's fuel budget bounds them too.
  - **Pooling.** `PoolingConfig::max_instances`, `max_memories` and `max_tables` now
    limit core instances; they used to set the component-instance limits, which had no
    effect.
  - **Trap reasons.** A skill that traps fails with the trap's reason ("wasm trap: out
    of bounds memory access"), not only its backtrace.
- PyO3 0.29 (was 0.24), for RUSTSEC-2026-0176 and RUSTSEC-2026-0177 (finding K11). The
  native classes no longer derive `FromPyObject` (`skip_from_py_object`); nothing took
  them by value.
- **Toolchain:** the minimum supported Rust is 1.96, the highest among dependencies
  (Wasmtime 49); it was declared as 1.75, which nothing could build. CI tests stable
  and 1.96, and checks formatting and clippy on stable only. The Dockerfile builds on
  1.96 (it was on 1.75). The metrics endpoint's
  `rust_version` and the Python module's `__rust_version__` come from
  `Cargo.toml` instead of a hardcoded "1.75".
- CI's clippy (`--all-targets --all-features -D warnings`, with `RUSTFLAGS=-D warnings`)
  passes: 24 lints from newer toolchains fixed, plus warnings that only show with some
  features off. The security clippy job (`unwrap_used`, `expect_used`, `panic`) checks
  production code, as CLAUDE.md describes, and passes. Its 96 hits are gone:
  - poisoned locks are recovered rather than unwrapped;
  - an empty plan and a missing "default" role in the neuro-symbolic pipeline no longer
    panic;
  - a missing CAS `base_path` is a configuration error;
  - constant regex patterns carry a scoped, commented `allow`.
- **Breaking:** `audit::streaming::WebhookSink::new` returns a `Result`; it panicked if
  the HTTP client couldn't be built.
- **Breaking:** `CedarPolicy::policies` returns the current set as an
  `Arc<CedarPolicySet>`. The policy loader refuses policies that carry `@property`
  (`CedarPolicyError::PropertyAsPolicy`).
- `policies/cedar/examples/payments.cedar` forbids restricted tools. SymCC showed that
  without it a finance agent could still call a blocked `transfer_funds`.
- `KernelError::PolicyViolation::policy_id` names the policies that denied, when the
  decision point reports them. It used to be `"default"` for every denial.
- **Breaking:** `AuditLogger::log` and `log_with_metadata` return
  `Result<&AuditEntry, AuditError>`. A write the backend refused used to be logged and
  returned as if stored; it is now an error, and the chain is left as it was.
- **Breaking:** `AuditLogger` entries use a version 2 hash: a domain tag and every field
  length-prefixed, `metadata` included (finding K7). Logs written before still verify
  if their version 1 entries come first; `AuditReport::legacy_entries` counts them.
- `serde_json` is built with `float_roundtrip`, so hashed JSON metadata reads back
  exactly.
- `audit.max_log_size_bytes` and `audit.retention_count` are documented as not applying
  to the kernel's log, which is never rotated.
- **Breaking:** default features are now `wasm` and `memory`. `reasoner`, `swarm`,
  `integrations`, `dashboard`, `api` and `tools` need their features (or `full`), and
  `reasoner::zk_proof` needs `experimental-zk`. `kernel::neurosymbolic_pipeline` and
  `sandbox::reasoning_host` need `reasoner`.
- `tools::skill_sign` is behind `legacy-tools`: its signatures don't cover permissions
  and the skill registry can't read them. Use `sandbox::signing`.
- **Breaking:** skill signatures are Ed25519 (`signed_by` + `signature`). The old unkeyed
  SHA-256 "signatures" no longer verify. `SkillSignatureVerifier::{compute_signature,
  sign_manifest}` and `SignatureVerificationResult` are removed; use
  `signing::sign_skill` and `VerifiedSkill`. `SignatureConfig::trusted_keys` now holds hex
  Ed25519 public keys and is enforced.
- **Behaviour change:** a skill loads only if its module file exists, and runs only with
  the module bytes it was verified with at load.
- **Behaviour change:** `security.enable_rate_limiting` and `max_requests_per_minute`
  are enforced (default 60 per agent per minute). They were previously ignored.
- **Behaviour change:** principals reach policy with `internal` from their agent
  record, not a constant `true`. Unregistered agents are not internal.
- **Behaviour change:** an executed call is recorded as two audit entries, a decision
  and an outcome. A session is bound to the first agent that uses it.
- `VakAgent`'s allowed and blocked tools are enforced by the kernel, and refusals are
  audited. `audit.log_path` selects a durable `FileAuditLog`; a log there that can't be
  opened or doesn't verify fails `Kernel::build`.
- **Breaking:** `Kernel::execute` on a permitted tool that doesn't exist now returns
  `Err(KernelError::ToolNotFound)`. It used to return `success: true` from a "default
  handler" that executed nothing.
- The allowlist and `CedarEnforcer` logic moved out of `Kernel` into `kernel::pdp`
  (`ConfigPolicy`, `EnforcerPolicy`). Behaviour is unchanged.
- `VakRuntime::builder()` settings (`with_audit_logging`, `with_policy_enforcement`,
  `with_sandboxing`, `with_default_timeout`) now reach `KernelConfig`.
- Memory Merkle tier hashes with SHA-256 over `(key, value)`, using the RFC 9162 tree
  shape. Proofs carry real sibling paths. `MerkleProof` gained `key` and `verify_for`.
- Z3 verifier: `Matches`, `Forbidden` and list values are rejected instead of being
  translated incorrectly.
- `lib.rs` status table states assurance levels instead of claiming an external audit.

### Fixed
- The constitution's integrity hash covers every field of every rule and
  principle. Before, a rule's constraint or flags could change unnoticed.
  `ConstraintOp::Exists` resolves dotted paths; they never existed.
- `security.blocked_tools` is a hard block (docs/adr/0017).
  - **The hole.** With YAML or Cedar policies, the list was only
    `resource.restricted`, an attribute rules could ignore. A decision point
    passed to `KernelBuilder::with_policy` never saw it. Either way, a rule or
    engine that allowed a tool ran it though it was blocked.
  - **The fix.** The kernel now wraps every decision point in the new
    `kernel::Blocklist`, which denies blocked tools first and is audited as
    `security.blocked_tools`.
- `StateManager` namespaces can't share keys (finding M6).
  - **The collision.** A canonical key was `namespace:key` as given, so
    `("a:b", "c")` and `("a", "b:c")` were the same key. An agent named
    `session` could read session keys, and agent `x:y` could read agent `x`'s.
  - **The fix.** The namespace is now percent-encoded (`%` and `:`), and
    clearing and semantic search match whole namespaces. The new
    `memory::namespace_prefix` builds the encoded prefix. Canonical keys change
    for namespaces containing `:` or `%`, session keys included.
- Snapshot backends (`memory::snapshot_backend`) store each agent's checkpoints
  faithfully (finding M5).
  - **Loading** checks the snapshot is the one asked for, and that it verifies.
  - **Saving** refuses an unverifiable checkpoint.
  - **Directories.** Agent directory names are a one-to-one percent-encoding,
    never `.` or `..`. Before, `a/b` and `a_b` shared a directory and index, and
    agent `..` wrote outside the base directory. Agent IDs containing `/`, `\`,
    `:`, `*`, `?`, `"`, `<`, `>`, `|` or NUL get new directories.
- The content-addressable store (`memory::content_addressable`) is durable and
  tamper-evident (finding M4).
  - **Reopened stores.** A reopened file store reads its compressed blobs. They
    were all hash mismatches, because only in-memory metadata recorded which
    blobs were gzipped.
  - **Repair.** `put` rewrites a blob that doesn't hold its content. It used to
    deduplicate against a corrupted or partial file, leaving the content
    unreadable for good.
  - **Writes.** Blobs are written aside and renamed into place.
  - **Decompression** is capped.
- Time-travel checkpoints (`memory::time_travel`) are tamper-evident (finding M3).
  - **Hash.** The version 2 hash separates its fields, covers the creation
    time, and commits to the parent's hash. A renamed key, shifted metadata or
    a rewritten ancestor used to keep the hashes valid. The new `parent_hash`
    field and `StateCheckpoint::child_of` carry the link. Exports made before
    this change don't import.
  - **Import.** It verifies every snapshot, the head and every branch. A head
    naming a missing snapshot is an error.
  - **Cycles.** Walks up the parents stop at a cycle. One used to loop for
    ever, on import among other paths.
  - **Checkout.** `checkout_by_id` honours `verify_on_access`.
  - **Pruning** keeps every branch's history, not just its head.
  - **Restoring.** `restore_from_checkout` checks the checkout is consistent,
    and marks the restored checkpoint `restored_unverified`: a checkout can't
    prove its state.
- `PublisherRegistry` no longer believes what publishers claim (finding K17).
  - **Registration.** A registration earns nothing. It starts `Unverified`, at
    reputation 0.5, with no verifications, skills, downloads or rating. It used
    to keep whatever the profile claimed, `Official` included. The new
    `mark_official` grants `Official`.
  - **Verification.** A verification must be requested before it is
    completed, once per method, and it expires.
  - **Publishing.** A skill must name its publisher, and can't take an ID
    another publisher owns. Either used to replace the owner's skill. A
    republish keeps its suspension, reports, downloads and rating, and a new
    skill starts with none.
  - **Reports.** Each reporter counts once per skill. Repeated reports from one
    reporter used to suspend the skill and its publisher.
  - **Reputation.** A change must be a number. A NaN passed every minimum.
- Pool capacity and execution limits hold (finding K16).
  - **Pool capacity.** `PoolManager::record_allocation` reserves capacity in one
    atomic step. Concurrent callers could overfill the pool.
  - **Spare deallocations.** One with nothing allocated is ignored. It wrapped
    the count to `u64::MAX`, leaving the pool full for good.
  - **Pool totals.** Products of the pool limits are checked.
  - **`ExecutionLimits::apply`.** It now returns `Result`. It refuses, having
    applied nothing, a memory limit (which needs a `ResourceLimiter`) and fuel
    on an engine without fuel metering; both used to be skipped silently. It
    also honours `async_yield`, which it ignored.
  - **Budgets.** `PreemptionBudget` and `EpochConfig::budget_ms` arithmetic
    saturates.
  - **Deadline docs.** `extend_deadline` resets the deadline, and
    `remaining_epochs` always returns `None`; both now say so.
- Async host operations (`sandbox::async_host`) run only what their policy
  allows (finding K15).
  - **Canonical before checked.** The enforcer matches resources by prefix and
    suffix, and operations were checked as given. `/data/../secret` passed a
    rule for `/data/*`, and `http://allowed@evil/` passed one for
    `http://allowed*`. Paths must now be absolute with no `..`, and `.` and
    repeated separators are removed. URLs must be http or https, with a host
    and no user info, and are normalised. What is checked is what runs.
  - **HTTP.** Redirects aren't followed, a request can't set `Host`, and
    responses are capped by the new `max_response_bytes` (10 MiB by default).
  - **Settings.** `default_timeout` applies to every operation. Before, it
    applied only to HTTP. `queue_when_full` and `max_queue_depth` apply; they
    were ignored.
  - **Keys.** Authorization-cache and executor keys are tuples. Joined with
    `:`, one operation could share another's cached decision, and one agent
    could run in another's context.
  - **Enforcers and cleanup.** `with_enforcer` gives a context, or an
    executor's contexts, an enforcer; there was no way to, so everything was
    denied. `cleanup_inactive` removes idle contexts; it removed nothing.
- `MarketplaceClient::install` no longer trusts the registry (finding K14).
  - **Paths.** Names and versions, including the dependencies a registry lists,
    are checked before they reach a path or URL. A dependency named `../../x`
    used to write outside the install directory.
  - **Binaries.** Every binary must match its version's SHA-256, whether cached
    or downloaded. A cached one used to go unchecked, and downloads were
    checked against the latest version's hash. Downloads are capped by the new
    `max_download_bytes` (64 MiB by default).
  - **Manifest.** It is the skill registry's `SkillManifest`, serialized and
    unsigned, with no permissions. A newline in the registry's description
    used to add manifest keys.
  - **Signatures and publishers.** With `verify_signatures`, the default,
    `install` now refuses with `SignatureUnverifiable`; it used to install
    unverified. A non-empty `trusted_publishers` list alone decides; the
    registry's own `verified` flag used to override it.
  - **Smaller fixes.**
    - Dependency cycles end, and chains are capped at 16 deep.
    - Prereleases need `allow_prerelease`, and yanked versions are refused.
    - `uninstall` deletes only its own skill's files; its glob matched other
      skills' (`calc-*` matches `calc-extra`).
    - The API key goes with every request.
    - Cache ages saturate.
- Reasoning host functions in `sandbox::reasoning_host` fail closed (finding R5).
  - **Approving everything.** The functions `register_reasoning_functions`
    registers, which have no state, returned "allowed" for every plan and
    ignored the rest. They now trap.
  - **Denials read as approvals.** With state, `vak.verify_plan` returned the
    violation count, so a plan denied for its risk alone returned 0, "allowed".
    A denial is now at least 1.
  - **Guest-controlled inputs.** A confidence above about 3.3 zeroed the risk
    score; it is clamped to 0..=1. The plan's `agent_id` is replaced by the
    store's agent. Rules now see that agent instead of `"unknown"`, so an agent's
    risk score and capabilities apply.
  - **Risk scores.** `vak.set_risk_score` set nothing. It now raises the
    caller's score, never lowers it. `ReasoningHost::set_agent_risk` replaces an
    agent's score instead of adding facts read in arbitrary order.
    `set_agent_risk_score` takes `&mut self` and sets the score; it only logged.
    The new `agent_risk` and `raise_agent_risk` read and raise a score.
  - **Smaller fixes.** `get_violation_count` and `is_high_risk_agent` report
    real counts and scores. Plans no longer pile up as unused facts. Guest
    pointers are bounds-checked without overflow. `is_critical_file`
    canonicalises the path.
- WASM host functions in `sandbox::host_funcs` (finding K13).
  - **Host panic.** Guest pointers and lengths were sign-extended and added
    unchecked, outside the panic boundary, so a guest calling
    `vak.fs_read(-1, 2)` panicked the host. They are now unsigned wasm32 values
    with a checked sum.
  - **Fake success.** `vak.fs_read` and `vak.fs_write` returned 0, success by
    their ABI, having done nothing. An allowed call now returns `NOT_IMPLEMENTED`
    (-2).
  - **Audit.** `audit_logging` was never read, so nothing was recorded. Every
    file call, allowed, denied or with an unreadable path, is now recorded in
    `HostFuncState::audit_entries`.
  - **Smaller fixes.** `vak.log` logs its message, escaped and capped at
    `MAX_LOG_MESSAGE` (4 KiB); it used to read only the level.
    `with_panic_boundary_async` catches panics; it awaited the future unguarded.
- `AuditLogger::verify_signatures` refuses an unsigned entry (finding V7).
  - **The hole.** Signatures aren't hashed, so stripping them left a signed log's
    chain intact, and the signature check passed.
  - **What changes.** Failures now name the entry, rather than entry 0. A log
    whose early entries predate signing can check its chain alone.
- `FileAuditBackend::rotate` never overwrites a rotated file.
  - **The loss.** Rotated files were named by the second, so a second rotation in
    the same second renamed over the first and lost its entries. A taken name now
    gets `_1`, `_2`, and so on.
  - **The count.** Reopening a log counted blank lines as entries; it now counts
    entries.
- OpenTelemetry tracing (`audit::otel`; finding I6).
  - **traceparent.** `TraceContext::from_traceparent` accepted any header with four
    `-`-separated fields, so text a client chose, line breaks included, went back
    out through `to_traceparent`. It now parses W3C Trace Context strictly and
    ignores anything else, as the spec requires.
  - **Refused exports.** `OtlpExporter::export` counted any response as exported.
    A 4xx or 5xx is now `ExportFailed`.
  - **Macros.** The exported `trace_inference!`, `trace_logic_check!`,
    `trace_policy_eval!` and `trace_tool_exec!` macros named a module that doesn't
    exist, so no use of them compiled. They now name `audit::otel`.
  - **Settings.** `TracingConfig`'s unapplied settings (`enabled`, `sampling_rate`,
    `export_interval_secs`, `otlp_endpoint`, `detailed_attributes`) say so.
- Audit stream subscribers receive events (finding I5).
  - **Subscriptions were closed from the start.** `AuditStreamManager::subscribe`
    dropped each subscriber's receiver, so nobody received anything. It now returns
    `(SubscriberId, Receiver)`.
  - **Departures.** A subscriber whose receiver is gone is removed at the next
    event.
  - **Counts.** Per-subscriber received and dropped counts are kept.
  - **Retention.** The retention window no longer overflows (a panic in debug
    builds) on an event stamped in the future.
  - **Heartbeats** share the manager's sequence counter, so their numbers no longer
    collide with published events.
  - **Breaking:** `subscribe` and `subscribe_with_name` return the receiver with
    the ID.
- The S3 and multi-region audit backends no longer report uploads they didn't make
  (finding K12).
  - **They never uploaded.** `S3AuditBackend` built an unsigned request, logged
    "upload simulated" and returned its key. By then the buffer had been drained,
    so the entries were gone.
  - **Rotation lost entries.** The synchronous `flush()` returned `Ok`, so an
    `AuditLogger` rotating into either backend evicted entries never stored.
  - **Now they fail closed.** Every flush with entries buffered fails, saying
    uploads aren't implemented (no AWS Signature V4), and the entries stay
    buffered. Rotation keeps what it couldn't archive.
  - **Active-active** returned `Ok` even when every region failed. It now fails
    unless every region stores the entries.
  - **Consistency.** `check_consistency` returned `Ok(true)` without reading a
    region; it now fails. `get_status` reports `consistency_ok: false`, and
    `total_entries` counts entries rather than object keys.
- The flight recorder's hash chain (finding V6).
  - **Edits were missed.** Verification checked only that each event named the one
    before it, so an edited decision or output still verified. It now recomputes
    every hash.
  - **The hash covers every field.** It used to cover only some, leaving input,
    output, error and metadata out. It is now a domain-tagged hash over every field
    (version 2), shared by `FlightEvent`, `ReplayEngine` and `ReplayVerifier`.
  - **Later traces failed.** Every event is chained whatever its trace, but each
    trace was expected to start at genesis, so every trace after the first failed.
    A trace is now checked by checking the whole chain. Once `max_memory_events` has
    trimmed old events, the check starts from the last event trimmed.
  - **Nothing to check is not a pass.** An absent trace, or a recorder with chain
    hashing off, no longer verifies. `ReplayVerifier::verify_trace` returned
    `Ok(true)` without checking anything; it now checks the log, and returns
    `Ok(false)` for an absent trace.
  - **Bad lines are errors.** `ReplayEngine::from_file` refuses a line that isn't an
    event, rather than skipping it.
  - **Breaking:** events recorded with the old hash don't verify.
- The sparse Merkle tree (`memory::sparse_merkle`; finding V4, ADR 0015).
  - **The root commits to every entry.** Every sibling was the empty subtree, so the
    root committed only to the last key written, and proofs for earlier keys failed.
    Every node is now derived from its real children, and the root matches a
    from-scratch reference whatever the insertion order.
  - **Proofs are checked, not trusted.** `SparseProof::verify` derives each step's
    direction and level from the key, binds `is_inclusion` to the presence of a
    value, and requires 64-digit siblings. A forged proof of absence for a present
    key no longer verifies.
  - **Hashes.** Leaves are `SHA-256(0x00 ‖ len ‖ key ‖ len ‖ value)` and nodes
    `SHA-256(0x01 ‖ left ‖ right)`. Keys containing `:` no longer collide.
  - **Shared positions.** A tree shallower than 256 refuses a key whose leaf position
    another key holds (`SparseMerkleError::KeyCollision`), rather than share it.
  - **Removal.** `remove` restores the root the tree had without the key.
  - **Import.** `from_export` rebuilds from the exported entries and refuses an
    export whose root they don't produce (`CorruptExport`).
  - **Breaking:**
    - `insert` and `from_export` return `Result`.
    - `SparseMerkleExport` has `entries` in place of `leaves`.
    - `SparseMerkleError` is `#[non_exhaustive]`.
    - `with_depth` keeps the depth between 1 and 256.
    - Every root and leaf hash changes.
- **Breaking:** the Python SDK answers only from the kernel (finding I4, ADR 0011).
  - **What goes through the kernel.** `evaluate_policy`, `list_tools`, the audit-log
    methods (`get_audit_logs`, `get_audit_entry`, `verify_audit_chain`,
    `get_audit_root_hash`, `export_audit_receipt`) and skills (`load_skill`,
    `list_skills`, `get_skill`) read the Rust kernel's policy decision point, audit log
    and skill registry.
  - **What reaches the kernel's configuration.** `KernelConfig` security and policy
    settings, through the new native `Kernel.from_settings`, which rejects unknown keys.
    `register_agent` passes `allowed_tools` as the agent's scope, and `role` and
    `attributes` for policy.
  - **Removed.** Methods that answered from engines the kernel never consulted. Each
    is listed under Removed, with its kernel equivalent if it has one.
  - **Changed meaning.** These methods remain but answer differently:
    - `VakKernel(config_path=...)` and `from_config` read a kernel configuration
      file and raise `VakError` if it can't be loaded. They used to read the file as
      policy rules for the binding's own engine, and ignore a file that didn't load.
    - `config` together with `config_path` raises `VakError` when a setting the SDK
      passes to the kernel is not the default. The file used to be read as policy
      rules, and of `config` only the Python engine's default effect was used.
    - `evaluate_policy`'s `action` is a tool name, and `context` the call's
      parameters. An unregistered agent raises `AgentNotFoundError`; the agent
      `"system"` used to be accepted. It records nothing; it used to write an audit
      entry.
    - `register_agent` no longer asks policy about `"agent.register"`.
    - Audit entries come from the kernel's log, and `verify_audit_chain` checks it.
      Native entries carry `policy_decision`, `details["hash"]` and
      `details["previous_hash"]` instead of `decision`, `hash` and (from
      `get_audit_entry`) `prev_hash`.
    - `get_audit_root_hash` is the Merkle tree's root, not the last entry's hash.
    - `export_audit_receipt` is the signed tree head (`head`, `timestamp_ms`,
      `signature`, `public_key`). It used to be an empty dict with the native module,
      and the stub's `receipt_id`, `timestamp`, `root_hash` and `entry_count`
      without it.
    - `list_tools`, `list_skills` and `get_skill` answer from the kernel: the tools
      it can run, and the skills it has loaded, by name.
  - **Without the native module,** these methods raise. The stub is deleted.
  - **Defaults.** `ToolRequest.memory_limit_bytes` defaults to 128 MiB.
  - **Bug fix.** `get_audit_logs` compares naive time bounds as local time.
- **Breaking:** the Python SDK runs tools through `Kernel::execute` (finding I4, ADR
  0011). The native `Kernel.execute_tool` returned `success: "true"` without running
  anything, and so did the stub the SDK falls back to without the native module.
  - **How a call runs.** The kernel's policy decides, its audit log records the call,
    and the response carries its receipt.
  - **The tool's input.** A tool gets `{"action": ..., "params": ...}`.
  - **Refusals and failures.** A policy refusal raises `PolicyViolationError`, any
    other refusal raises `ToolExecutionError`, and a tool that ran and failed has
    `success=False`.
  - **Memory.** A `memory_limit` below the 128 MiB the kernel gives every skill is
    refused.
  - **Without the native module,** `execute_tool` raises.
  - **Tests.** `cargo test --features python` links and runs the bindings' tests
    (PyO3's `extension-module` feature moved to `pyproject.toml`).
- `ToolRequest::timeout_ms` is applied. It was ignored, so a caller that asked for a
  tighter limit got the kernel's `max_execution_time`. WASM skills and registered tool
  handlers now stop at whichever limit comes first; a request can't extend the
  kernel's. `ToolRequest::time_limit` computes it.
- **Breaking:** MCP `execute_skill` runs skills through `Kernel::execute` (finding I3).
  It reported "executed successfully" for any skill name without running anything,
  after loading unsigned skills from `./skills` outside the kernel. A refused, unknown
  or failed skill is now an error result, and a successful one returns the kernel's
  receipt. `create_vak_mcp_server` takes an `Arc<Kernel>`, and
  `ExecuteSkillToolHandler::new` takes one too (it was a unit struct). Agent names map
  to stable agent IDs (`mcp_agent_id`).
- **Breaking:** `SecretScrubber::scrub_json` and `scrub_map` redact whole any value
  under a sensitive key, keeping the key; they used to scrub such values by pattern
  only, so `{"password": "hunter2"}` passed through. `is_sensitive_key` matches the
  whole key against `memory::SENSITIVE_KEYS`, ignoring case. It used to match
  substrings, flagging "author" and "max_tokens", and no longer flags keys outside
  the list such as "secret_token" or "api-key".
- `memory::receipts`: a public key or signature of the wrong length fails
  verification. It used to be replaced with zero bytes, and an all-zero key is a
  small-order point that non-strict Ed25519 verification can be forged against.
- `test_signer_key_export_import` checks the imported key (same public key, same
  signatures); it used to assert nothing.
- A durable audit log (`FileAuditLog`) whose caller stopped waiting mid-append could
  store the entry without adding it to the tree. The next entry then linked to the
  wrong predecessor, and the log refused to open. Appends now run to completion
  (ADR 0007).
- `AuditLogger` rotation no longer breaks `verify_chain`, and no longer evicts entries
  it failed to archive.
- Skills were "signed" with an unkeyed hash anyone could recompute, over the module's path
  when the module was missing, and `trusted_keys` was never read (K4).
- WASM skills no longer block a Tokio worker for their whole runtime, and are no longer
  recompiled (with a new engine and a new watchdog thread) on every call (K3).
- A skill's output pointer and length are bounds-checked against guest memory as
  unsigned values. A negative length used to make the host panic while allocating the
  output buffer, unwinding through `Kernel::execute`.
- A WASM skill that hits its wall-clock limit fails with `KernelError::Timeout`, like a
  host handler, instead of a generic execution failure.
- `sandbox::async_host` fell back to an allow-everything enforcer when its policy
  enforcer couldn't be built. It now denies everything instead.
- WASM skills trapped on entry: epoch interruption was enabled with no deadline, and
  Wasmtime's default deadline is 0. A per-execution watchdog now enforces the wall-clock
  timeout, and traps are classified by trap code.
- SMT-LIB injection in the Z3 verifier: field names and string values were spliced into
  the solver script unescaped. Negative numbers were emitted as invalid `-n` literals.
- A panicking host tool handler no longer unwinds through `Kernel::execute`.

### Removed
- **Breaking:** Python SDK methods that answered from engines the kernel never consulted
  (finding I4, ADR 0011). Each now has a kernel equivalent or none; the migration note
  in `docs/python-sdk.md` gives it.
  - **`VakKernel.create_audit_entry`, and `create_audit_entry` on the context from
    `agent_context()`.** They wrote entries the kernel never decided, to the binding's
    own audit logger, or without the native module to the stub's in-memory chain. The
    SDK's audit methods then reported those as the audit log. The kernel's log records
    only calls it mediates (ADR 0007). No equivalent.
  - **`VakKernel.add_policy_hook` and `remove_policy_hook`.** A Python callable decided
    beside the kernel, so the SDK's answer and the kernel's could differ. No equivalent.
  - **`VakKernel.load_policies`.** It loaded rules into the Python `PolicyEngine`,
    which the kernel doesn't consult. With the native module it then raised
    `TypeError`: its arguments didn't match the native `add_policy_rule`. Equivalent:
    a YAML policy file in `PolicyConfig.policy_paths`, read at startup. With policy
    files, `SecurityConfig.allowed_tools` no longer applies, and `blocked_tools`
    blocks only through rules that check `resource.restricted`.
  - **`VakKernel.policy_engine`.** It returned that Python engine as if it were the
    kernel's. No equivalent. `vak.policy.PolicyEngine` remains as a standalone
    evaluator.
  - **`VakKernel.add_safety_rule`.** A rule with action `"block"` stopped
    `execute_tool` in Python, before the kernel saw the call. Equivalent: block the
    call in the kernel, with a forbid rule in a policy file or a narrower
    `AgentConfig.allowed_tools`, or, without policy files, `blocked_tools`.
  - **`VakKernel.add_constraint` and `check_constraints`.** They delegated to
    `ReasonerConfig`; nothing checked constraints before a call. No equivalent.
    `ReasonerConfig.add_constraint` and `check_constraints` remain standalone.
  - **`VakKernel.configure_reasoner` and `reasoner`.** They configured a Python
    `ReasonerConfig` the Rust kernel never read, though the SDK's `execute_tool`
    enforced its block rules. No equivalent; block those calls as for
    `add_safety_rule`. `ReasonerConfig` remains as a standalone evaluator.
  - **`VakKernel.register_skill(SkillManifest)`.** It recorded the manifest in Python.
    With the native module it then raised `TypeError`: its arguments didn't match the
    native `register_skill`. Without it, the stub stored the manifest. Nothing was
    loaded or verified. Equivalent: `load_skill(manifest_path)`.
  - **Native `Kernel.add_policy_rule`.** It added a rule to the binding's own policy
    engine. Equivalent: as `load_policies`.
  - **Native `Kernel.validate_policy_config`, `has_allow_policies` and
    `policy_rule_count`.** They described that engine. No equivalent.
  - **Native `Kernel.register_skill` and `get_skill_info`, and the Rust type
    `vak::python::SkillInfo` (feature `python`).** They managed a map of names beside
    the kernel's registry. Equivalents: `load_skill` and `get_skill`.
  - **Native `Kernel.unregister_skill` and `set_skill_enabled`.** Same map: they
    changed only what `list_tools` and `get_skill_info` reported. The kernel has no call to unload or
    disable a skill. No equivalent; block the tool at startup instead.
  - **Native `Kernel.create_audit_entry`.** As `VakKernel.create_audit_entry`.
  - **`vak._stub`.** Without the native module it answered in the kernel's place and
    allowed every policy question. Kernel-backed methods now raise `VakError`.
- The unused `rs_merkle` dependency.
- `src/prelude.rs`, which was never compiled (`lib.rs` defines `prelude` inline) and
  referenced types that don't exist.

## [1.0.0] - 2026-02-13

### Added
- **v1.0 Milestone**: Production-ready release with full documentation
- **Production Deployment Guide** (`docs/production-deployment.md`): Comprehensive deployment reference covering Docker Compose, Kubernetes with Kustomize, and Helm chart deployments. Includes configuration reference, storage sizing guidelines, scaling strategies, monitoring setup, backup/recovery procedures, and a production readiness checklist.
- **Security Hardening Guide** (`docs/security-hardening.md`): Complete security best practices covering defense-in-depth layers, policy engine hardening, WASM sandbox security, audit log integrity, cryptographic configuration, container security, network security, secrets management, supply chain security, prompt injection protection, rate limiting, and compliance considerations.
- **Performance Tuning Guide** (`docs/performance-tuning.md`): Optimization reference with benchmarking procedures, kernel tuning parameters, policy engine optimization, WASM sandbox performance, audit logging optimization, memory system tuning, Python SDK performance tips, profiling tools, resource sizing formulas, and production monitoring guidance.
- **Troubleshooting Guide** (`docs/troubleshooting.md`): Diagnostic reference covering build issues, runtime errors, policy engine problems, WASM sandbox failures, audit log issues, memory system problems, Python SDK errors, Docker/Kubernetes issues, and performance debugging.
- **Migration Guide** (`docs/migration-guide.md`): Step-by-step upgrade instructions from v0.1, v0.2, and v0.3 to v1.0, covering configuration changes, API compatibility, Python SDK migration, Helm chart migration, and verification steps.

### Changed
- Bumped version to `1.0.0` across all artifacts (Cargo.toml workspace, Helm chart, Dockerfile labels)
- Updated README.md with v1.0 milestone completion, new documentation links, and production status badge
- Updated TODO.md with v1.0 completion status and Sprint 13 tracking
- Updated API.md version reference to v1.0.0
- Updated ARCHITECTURE.md Helm chart version reference
- Updated `.github/skills/README.md` version reference to v1.0
- Updated `examples/CODE_AUDITOR_README.md` status to v1.0

## [0.3.0] - 2026-02-13

### Added
- **v0.3 Milestone**: Full test coverage infrastructure, CI/CD pipeline, infrastructure tooling
- **TST-007**: Cross-module integration tests - comprehensive tests validating interactions between kernel subsystems (policy+audit, memory+audit, reasoner+policy, swarm+audit, end-to-end session lifecycle)
- **TST-008**: Stress & load testing suite - throughput tests (10K+ operations), concurrency stress tests (500 concurrent agents), latency percentile tracking (p50/p95/p99), resource exhaustion tests (50K audit chains, 200 concurrent sessions)
- **TST-009**: Code coverage infrastructure - `tarpaulin.toml` configuration with 80%+ threshold enforcement, branch coverage, HTML+XML output formats
- **INF-004**: CI/CD pipeline (`ci.yml`) - comprehensive GitHub Actions workflow with Rust build (stable + MSRV 1.75), WASM skill builds, code coverage with tarpaulin, Python SDK tests (3.9-3.12 matrix), performance benchmarks, property-based tests with extended cases
- **INF-005**: Makefile for development automation - 30+ targets covering build, test, lint, coverage, benchmarks, security, Docker, profiling, and documentation
- **INF-006**: Performance profiling tooling (`scripts/perf-profile.sh`) - benchmark tracking with baseline comparison, flamegraph generation, compilation timing analysis, binary size analysis, coverage reporting
- **SEC-006**: Dependency freshness monitoring - automated `cargo-outdated` checks in CI with artifact upload
- **SEC-007**: WASM skill integrity verification - CI job that builds all WASM skills and verifies magic bytes for module validity
- Security audit summary job aggregating results from all security checks (cargo-audit, cargo-deny, cargo-geiger, clippy, SBOM, dependency freshness, WASM integrity)

### Changed
- Updated README.md with v0.3 milestone completion, new module status entries, expanded testing/profiling documentation
- Updated TODO.md with Sprint 12 completion, v0.3 task tracking, updated test coverage summary (1,150+ tests)
- Enhanced `security.yml` workflow with dependency freshness, WASM integrity, and summary jobs
- Updated project structure documentation to include `scripts/`, `Makefile`, and `tarpaulin.toml`

## [0.2.0] - 2026-02-13

### Added
- **v0.2 Milestone**: Python SDK stable, ecosystem integrations complete
- **Python SDK - Memory Management**: `store_memory()`, `retrieve_memory()`, `store_episode()`, `retrieve_episodes()`, `search_semantic()` APIs with full stub backend support
- **Python SDK - Swarm Coordination**: `create_voting_session()`, `cast_vote()`, `tally_votes()`, `detect_sycophancy()` APIs with quadratic voting and groupthink detection
- **Python SDK - Audit Chain Verification**: `verify_audit_chain()`, `get_audit_root_hash()`, `export_audit_receipt()` APIs for hash-chain integrity verification
- **Python SDK - Agent Context**: Memory and swarm convenience methods in `_AgentContext` (`store_memory`, `retrieve_memory`, `create_vote`, `cast_vote`)
- **Python SDK - StubKernel**: Full in-memory implementations of all kernel subsystems (agent management, policy evaluation, tool execution, audit logging with SHA-256 hash chain, memory management with Merkle-chained episodes, swarm coordination with quadratic voting, sycophancy detection)
- **MCP Tool Handlers**: `VerifyPlanToolHandler` wired to `SafetyEngine::verify_plan()` for real Datalog rule checking; `ExecuteSkillToolHandler` wired to `SkillRegistry` for actual WASM skill dispatch with safety pre-checks
- **Test Coverage**: `test_memory.py` (15 tests), `test_swarm.py` (18 tests), `test_audit_chain.py` (15 tests) covering all new Python SDK APIs
- **FUT-001**: Zero-Knowledge Proof integration - commitment-based ZK proof system with Fiat-Shamir heuristic, supporting policy compliance proofs, audit integrity proofs, state transition proofs, identity attribute proofs, range proofs, and set membership proofs. Includes `ZkProver`, `ZkVerifier`, `ProofRegistry`, and batch verification.
- **FUT-002**: Constitution Protocol - immutable safety governance layer with fundamental principles (No Harm, Transparency, Least Privilege, Data Protection, Human Override), compound constraint evaluation (AND/OR/NOT), multi-point enforcement (pre-policy, pre-execution, post-execution), tamper-detection via SHA-256 hashing, and configurable blocking/warning modes.
- **FUT-003**: Enhanced PRM fine-tuning toolkit - comprehensive evaluation framework with accuracy, precision, recall, F1, AUROC, and Expected Calibration Error metrics. Includes dataset management (JSONL import/export), calibration analysis, model A/B comparison, optimal threshold search, and prompt template generation for LLM fine-tuning.
- **FUT-004**: Skill marketplace with verified publishers - multi-method publisher verification (GitHub org, GPG key, domain ownership, email), progressive trust levels (Unverified, Basic, Verified, Trusted, Official), community reputation system, malicious skill reporting with auto-suspension, vulnerability scanning for WASM binaries, and skill publishing workflow.
- **DOC-001**: Architecture documentation (ARCHITECTURE.md) - system design, module reference, data flow diagrams, security architecture, deployment guide
- **DOC-002**: API reference documentation (API.md) - complete API reference for all modules including Rust and Python SDK, configuration reference, error codes
- **INF-001**: Kubernetes operator manifests - Kustomize base with namespace, deployment, service, HPA, PDB, NetworkPolicy, ConfigMap, PVC, ServiceAccount
- **INF-002**: Docker images - multi-stage Dockerfile (deps, builder, dev, production), optimized .dockerignore, docker-compose dev profile
- **INF-003**: Helm charts - full chart with values.yaml, 10 templates (deployment, service, ingress, HPA, PDB, NetworkPolicy, ConfigMap, PVC, ServiceAccount, helpers)
- **OBS-002**: Cryptographic replay capability - ReplaySession, ReplayVerifier, ActiveReplay with hash-chain verification and step-by-step replay
- **INT-003**: LangChain Adapter Completion - LLM call interception, callback handler trait, audit integration, tool execution lifecycle management
- **INT-004**: AutoGPT Adapter Completion - PRM-scored command interception, execution result verification, plan progress tracking, callback handler system, sensitive data detection
- **SWM-002**: AgentCard Discovery - well-known endpoint support (`/.well-known/agent.json`), HTTP-based remote agent card fetching, agent card validation, TTL-based caching with eviction, search by capability/name, endpoint management
- Dockerfile and docker-compose.yml for containerized deployment (INF-003)
- CONTRIBUTING.md with development workflow and coding standards (DOC-003)
- CHANGELOG.md for tracking project changes
- MSRV (Minimum Supported Rust Version) set to 1.75 in Cargo.toml (Issue #35)
- Audit log rotation with configurable max entries and archival (Issue #20)
- Policy evaluation caching with LRU cache (Issue #40)
- Improved working memory token estimation with code-aware heuristics (Issue #15)
- Input sanitization guide for skill developers (Issue #14)

## [0.1.0] - 2026-02-10

### Added
- **Core Kernel**: Agent lifecycle management, tool dispatch, async pipeline
- **Policy Engine**: ABAC with Cedar-style enforcement, hot-reloading, dynamic context injection
- **Audit Logging**: Hash-chained immutable logs with ed25519 signing, SQLite/File/S3 backends
- **Memory System**: Merkle DAG, content-addressable storage, time travel debugging, vector store
- **WASM Sandbox**: Wasmtime runtime with fuel metering, epoch-based preemption, pooling allocator
- **Neuro-Symbolic Reasoner**: Datalog rules, Z3 SMT verification, PRM scoring, constrained decoding
- **Swarm Protocol**: A2A communication, quadratic voting, sycophancy detection, consensus mechanisms
- **Integrations**: LangChain adapter, AutoGPT adapter, MCP server, Model Context Protocol
- **Dashboard**: Prometheus metrics, health checks, HTTP server with web UI
- **Python SDK**: PyO3 bindings with async support, type stubs
- **Security**: Prompt injection detection, rate limiting, supply chain hardening, unsafe code audit
- **WASM Skills**: Calculator, crypto-hash, json-validator, text-analyzer, regex-matcher
- **Tools**: vak-skill-sign CLI for Ed25519 skill signing
- **Flight Recorder**: Shadow-mode request/response recording with replay capability
- **Verification Gateway**: Z3/SMT-based formal verification for high-stakes actions
- **Cost Accounting**: Token usage and fuel consumption tracking

### Security
- Ed25519 skill signature verification (default strict, dev-only opt-out)
- Default-deny policy enforcement (POL-007)
- Prompt injection detection with multi-category analysis (SEC-004)
- Per-agent rate limiting with token bucket algorithm (SEC-005)
- Unsafe Rust audit with documented SAFETY comments (SEC-003)

[Unreleased]: https://github.com/vak-project/verifiable-agent-kernel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vak-project/verifiable-agent-kernel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vak-project/verifiable-agent-kernel/releases/tag/v0.1.0
