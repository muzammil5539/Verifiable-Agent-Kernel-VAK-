# The constitution runs as an enforced guard that only denies

`ConstitutionalEngine` (`kernel::constitution`) held the default safety constitution:
five principles and five rules, such as no destructive system actions and no access
to credentials. `Kernel::execute` never called it (finding K5). ADR 0013 made guards
the place for checks on allowed calls.

## Decision

**`ConstitutionGuard` adapts the engine to the Guard port.** The kernel runs it first
when `policy.constitution` is on. Embedders can also add one, over a constitution of
their own, with `KernelBuilder::with_guard`.

- **Verdicts.**
  - A blocking violation denies, naming the rules.
  - A violated rule that needs human review escalates, which the kernel refuses: there
    is no approval channel. Only engines with `enable_human_review` set do this, as the
    engine already defines.
  - Otherwise it **abstains, and never passes**. Its rules are a blocklist, so finding
    nothing wrong doesn't show the call is right. A pass would satisfy a
    `policy.min_assurance` floor of `enforced` with no positive check at all.
- **Level.** `Enforced`: deterministic, and a blocking rule it can't evaluate (a field
  the call lacks) denies.
- **Rules evaluated.** `PrePolicy`, `PreExecution` and `All`, each once. A guard runs
  after the policy, so `PrePolicy` rules run late but still run. `PostExecution` rules
  are left out: they read outcomes, so a blocking one would deny every call.
- **The context.** A rule's fields name:
  - `agent_id`, and `session_id` when there is one;
  - `action` and `tool`, both the tool's name;
  - `resource`, the arguments as compact JSON, so rule R-003 sees every argument and
    always has a value (without one, it denied every call);
  - `parameters`, the arguments, for dotted paths;
  - `agent` (name, internal, attributes).
- **Integrity.** The constitution's integrity is checked when the guard is made, and a
  tampered one is refused.

Two fixes it needed:

- **The hash.** Version 1 covered rules' IDs, descriptions and points, run together: a
  rule's constraint, blocking and review flags, priority, and a principle's
  `immutable` flag, could all change unnoticed. Version 2 hashes the JSON of every
  field behind a domain tag.
- **`Exists`.** It looked a dotted path (`agent.name`) up as one key, so such a field
  never existed. It now resolves paths as the other operators do.

## Consequences

- **Off by default,** so no existing kernel changes.
- **Configuration alone can turn it on.** `Kernel::new`, the Python SDK and
  `VakRuntime`, which can't add guards themselves, can use it.
- **It can't satisfy a floor.** A tool under an `enforced` floor still needs a guard
  that checks it and passes.
- **Next guard adapters (TODO.md):** the prompt-injection detector, as heuristic; then
  Datalog on Ascent, as enforced.
- **Tests.** `tests/constitution_guard.rs` drives `Kernel::execute`: R-001 and R-003
  refuse calls the policy allowed; a clean call runs; abstaining fails an `enforced`
  floor; review escalates; post-execution rules wait; dotted fields resolve; a tampered
  constitution is refused.
