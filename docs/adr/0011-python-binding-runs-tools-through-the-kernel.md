# The Python SDK answers only from the kernel

Finding I4 in `docs/architecture-v2.md` was that the Python SDK's native `Kernel` was
not the kernel.

- **Its own engine and log.** `PyKernel` held a `PolicyEngine`, an `AuditLogger` and a
  skill registry of names, all of its own. None of them were the kernel's.
- **Fake success.** Its `execute_tool` returned `success: "true"` and an echo of its
  arguments without running anything. The pure-Python stub, which the SDK fell back to
  when the native module failed to import, did the same, and allowed every policy
  question.
- **More engines on top.** The SDK added its own policy hooks, rule engine and safety
  rules.

So a Python caller could be told a tool ran when nothing ran it, and could get a policy
decision or audit record from an engine the kernel never consulted. That is the failure
K1 fixed in the kernel, and "no fake success" in CLAUDE.md forbids it.

## Decisions

**Every answer about policy, tools, skills or the audit log comes from one Rust
`Kernel`.** `PyKernel` owns a kernel and a two-worker Tokio runtime, and blocks on the
kernel's async API (with the GIL released while a tool runs). It keeps no policy engine,
audit log or skill registry of its own.

| SDK method | Kernel |
|---|---|
| `execute_tool` | `Kernel::execute`: admit, budget, decide, record, run, record the outcome, receipt |
| `evaluate_policy(agent, tool, params)` | `Kernel::evaluate_policy`, the Decide stage alone |
| `register_agent` | `Kernel::register_agent`: `allowed_tools` becomes the agent's own scope; `role` and `attributes` become attributes policy can read |
| `list_tools` | `Kernel::list_tools` |
| `load_skill`, `list_skills`, `get_skill` | `Kernel::load_skill` (verified as at startup), `skill_manifest` |
| `get_audit_logs`, `get_audit_entry` | `Kernel::get_audit_log` |
| `verify_audit_chain` | `Kernel::verify_audit_chain` |
| `get_audit_root_hash`, `export_audit_receipt` | `Kernel::audit_tree_head`, signed |
| `VakKernel(config=KernelConfig(...))` | `Kernel.from_settings`: allowlist, blocklist, default decision, policy files, signature checking, time and memory limits, rate limit, audit log path |
| `VakKernel.from_config(path)` | `KernelConfig::from_file`; an unreadable file is an error, not a fallback |

**Settings are never silently dropped.**

- `from_settings` rejects an unknown key.
- A config file given together with non-default `KernelConfig` settings is an error,
  because one would be ignored.
- The SDK's two default-decision settings allow by default only if both say "allow".

**Methods with no kernel equivalent are removed:**

- **Removed from `VakKernel`:** `create_audit_entry`, `add_policy_hook`,
  `remove_policy_hook`, `load_policies`, the `policy_engine` property,
  `add_safety_rule`, `add_constraint`, `check_constraints`, `configure_reasoner`, the
  `reasoner` property, and `register_skill(SkillManifest)` (replaced by
  `load_skill(path)`).
- **Removed from the agent context:** `create_audit_entry`.
- **Why `create_audit_entry` has no equivalent.** The kernel's log records only calls it
  mediated (ADR 0007), so an entry the SDK writes would claim the kernel attested
  something it never saw.
- **Why hooks, rules and safety rules have no equivalent.** They were Python engines
  deciding instead of the kernel's policy decision point, and their denials never
  reached the kernel's log.
- **What remains in Python.** `PolicyEngine` and `ReasonerConfig` remain as standalone
  evaluators, and say the kernel doesn't consult them.

A missing method is honest; a method that answers from the wrong engine is not.

**Without the native module, nothing answers in the kernel's place.**

- The stub is deleted.
- `execute_tool` raises `ToolExecutionError`.
- Policy, tools, skills and audit methods raise `VakError`.
- Agent bookkeeping still works.

**A tool gets `{"action": action, "params": params}`.**

- **The mismatch.** The Python call names a tool, an action and parameters; a kernel
  tool takes one JSON value.
- **The shape chosen.** It is the shape the shipped WASM skills take, and `echo`
  returns it.
- **Built-ins that want another shape fail, with an error.** The calculator wants
  `operation` and `operands`. The call isn't translated.

**Audit entries become the SDK's `AuditEntry` faithfully.**

- **Fields.** Every entry is a tool call: `action` and `resource` are the tool.
  `details` carries the kind (decision or outcome), the leaf index, the session, the
  hashes and the outcome. An outcome's `parent_entry_id` is its decision.
- **Level.** The kernel has no level, so the SDK derives one: WARNING for a refusal,
  ERROR for a failed run, INFO otherwise.

**Limits are never looser than asked.**

- **Time.** `timeout_ms` reaches the kernel as `ToolRequest::timeout_ms`, applied when
  tighter than the kernel's.
- **Memory.** The kernel takes no per-call memory limit. So `execute_tool` refuses a
  `memory_limit` below what the kernel gives every skill (128 MiB by default, the SDK's
  default for agents and requests), with an error that says nothing ran.

**Memory and voting stay in Python.**

- **In both modes.** `vak._local` runs them the same way with or without the native
  module. They decide no policy, write no audit record and run no tool.
- **Docstrings changed.** They no longer claim vector search or kernel enforcement.

**The bindings and the SDK are tested on the native module.**

- **Linking.** PyO3's deprecated `extension-module` feature comes from `pyproject.toml`'s
  maturin features, not `Cargo.toml`, so `cargo test --features python` links.
- **Rust tests.** The tests in `src/python.rs` drive every wrapped method through the
  kernel.
- **CI.** CI runs those, then builds the module and runs the whole Python suite with
  `VAK_REQUIRE_NATIVE` set. In that mode a test that needs the kernel fails instead of
  skipping.
- **Without the module.** The stub-mode run (every Python version) skips the tests that
  need the kernel and checks that kernel methods raise.

## Consequences

- **The 49 Python tests that failed against the native module are resolved.**
  - **Behaviour that no longer exists.** Tests of the Python policy engine, policy
    hooks, `create_audit_entry`, the stub's audit chain and its default-allow are
    deleted.
  - **Rewritten against the kernel.** Agent management, policy evaluation, tool
    execution, audit and the end-to-end scenarios now check what the kernel decided,
    ran and recorded.
  - **Fixed earlier.** Memory and voting were fixed by `vak._local`.
- **Breaking.**
  - The removed methods, and `VakKernel.policy_engine` and `.reasoner`.
  - `evaluate_policy` asks about a tool, not an arbitrary action.
  - Kernel methods raise without the native module.
  - `execute_tool` returns typed values and raises where it used to report success.
  - `ToolRequest.memory_limit_bytes` defaults to 128 MiB (was 64), so a default request
    isn't refused.
  - `register_agent` no longer asks the SDK's policy for "agent.register"; registration
    isn't a policy decision.

## Considered options

**Keeping the stub's answers for development.** A development mode that reports success
for tools that didn't run, or allows every policy question, is the bug this ADR is about.
If it shipped, it would be one `ImportError` away from production.

**Running Python policy hooks inside the kernel's decision point.** That would put
arbitrary Python into the Decide stage, called from the kernel's runtime threads. It
would also need a port for a GIL-holding decision point. Policy belongs in the kernel's
configuration (ADR 0001, 0008).

**An SDK-writable audit log.** Appending application events to the transparency log
would mix the kernel's attestations of mediated calls with claims it can't check
(ADR 0007).

**A per-call memory limit in the kernel.** `ToolRequest` has no memory field, and adding
one changes a public struct that downstream code builds with a literal. Refusing a
tighter limit is honest and changes less. The field can come with the Guard port's
per-call constraints.
