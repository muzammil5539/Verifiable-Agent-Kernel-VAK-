# The Python binding runs tools through the kernel

Finding I4 in `docs/architecture-v2.md` was that the Python SDK's native `Kernel` was
not the kernel. `PyKernel` held a `PolicyEngine` and an `AuditLogger` of its own. Its
`execute_tool` returned `success: "true"` and an echo of its arguments without running
anything. The pure-Python stub, which the SDK falls back to when the native module
fails to import, did the same. So a Python caller could be told a tool ran when
nothing ran it. That is the failure K1 fixed in the kernel, and "no fake success" in
CLAUDE.md forbids it.

## Decisions

**`PyKernel::execute_tool` calls `Kernel::execute`.**

- **The kernel and runtime.** `PyKernel` owns a kernel and a two-worker Tokio runtime,
  and blocks on `Kernel::execute` with the GIL released.
- **Agents.** Each agent registered from Python gets a kernel `AgentId` and a session,
  and is registered in the kernel's agent registry. Unregistering ends the session.
- **What the kernel does.** Its policy decides, its audit log records the decision
  before the tool runs and the outcome after, and its sandbox runs skills. The
  response carries the kernel's receipt.
- **Exceptions.** A policy refusal raises `PermissionError(policy_id, reason)`, which
  the SDK maps to `PolicyViolationError`. Any other refusal raises `RuntimeError`,
  which the SDK maps to `ToolExecutionError`. A tool that ran and failed returns
  `success: False`.
- **Types.** `success` is a `bool`. It was the string `"true"`, which is truthy in
  Python whatever it says.

**A tool gets `{"action": action, "params": params}`.** The Python call names a tool,
an action and parameters; a kernel tool takes one JSON value. This is the shape the
shipped WASM skills take. The built-in calculator wants `operation` and `operands`, so
a Python call with `action="add"` fails there, with an error, rather than being
translated.

**Limits are never looser than asked.**

- **Time.** `timeout_ms` reaches the kernel as `ToolRequest::timeout_ms`, which the
  kernel now applies when it is the tighter limit.
- **Memory.** The kernel takes no per-call memory limit. So the native kernel gives
  every skill 128 MiB, the SDK's default for an agent, and `execute_tool` refuses a
  `memory_limit` below that, with an error that says nothing ran.

**Without the native module, `execute_tool` fails.**

- The stub's `execute_tool` raises.
- `VakKernel.execute_tool` raises `ToolExecutionError` when there is no kernel to run
  the call.
- Tests of the SDK's own logic around a call use an explicit test double
  (`python/tests/conftest.py`, the `fake_tools` fixture). It is labelled as fake and
  exists only in the tests.

**The bindings' tests run.**

- **Linking.** PyO3's `extension-module` feature, deprecated in 0.29, kept libpython
  out of the link, so `cargo test --features python` could not link. It now comes from
  `pyproject.toml`'s maturin features instead of `Cargo.toml`, and the Rust tests in
  `src/python.rs` run, two of them through `Kernel::execute`.
- **CI.** CI runs them, then builds the module with maturin and runs
  `python/tests/test_native_kernel.py` with `VAK_REQUIRE_NATIVE` set, so a missing
  module fails rather than skips.

## Consequences

- **Still outside the kernel.** `evaluate_policy`, the audit-log methods,
  `add_policy_rule` and the skill registry methods still use `PyKernel`'s own engine
  and logger. A call through `VakKernel.execute_tool` is therefore decided twice:
  - first by the SDK's policy hooks and `evaluate_policy`;
  - then by the kernel.

  Either can refuse it. Neither can let through what the other refuses. Moving those
  methods onto the kernel is the rest of I4.
- **The SDK's own audit trail is kept.** It now records the kernel's decision for each
  call (allowed, denied, or the error). Before, it recorded "allowed" before anything
  was decided.
- **Native-mode tests still fail.** 49 Python tests fail against the native module.
  63 did before this change; the 14 that needed a tool to run now use the test double.
  The 49 fail because the SDK and the native module disagree in ways that predate this
  change:
  - the module's own policy engine denies registration by default;
  - several of its methods return different fields than the SDK reads.

  The stub-mode suite, which CI runs on every Python version, passes.
- **Breaking:**
  - `execute_tool` returns typed values.
  - It raises where it used to report success.
  - It needs `memory_limit` of at least 128 MiB.
  - Without the native module, tools don't run.

## Considered options

**Failing `execute_tool` closed until the binding could wrap the kernel.** That was the
fallback if wrapping didn't fit in one slice. It did fit, so the binding runs tools.

**Keeping the stub's success for development.** A development mode that reports
success for tools that didn't run is the bug this ADR is about. If it shipped, it would
be one `ImportError` away from production. Tests that need a tool to "run" say so with a
fixture.

**A per-call memory limit in the kernel.** `ToolRequest` has no memory field, and adding
one changes a public struct that downstream code builds with a literal. Refusing a
tighter limit is honest and changes less. The field can come with the Guard port's
per-call constraints.
