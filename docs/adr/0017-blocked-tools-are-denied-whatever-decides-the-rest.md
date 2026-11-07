# Blocked tools are denied whatever decides the rest

`security.blocked_tools` lists tools the kernel must never run.

- **What it meant before.** `ConfigPolicy`, used when no policy files are configured,
  denied them first. With YAML or Cedar policies the list became an attribute,
  `resource.restricted`, that rules could read or ignore. An embedder's own decision
  point never saw it.
- **The hole.** A rule that permitted a tool without testing `restricted` ran a blocked
  tool. So did any decision point passed to `KernelBuilder::with_policy`. The shipped
  default policies test it, so the hole needed a rule written differently, but nothing
  said so.

## Decision

**A blocked tool is denied before any decision point is asked.**

- **How.** The kernel wraps whatever decides (`ConfigPolicy`, YAML policies, Cedar, or an
  embedder's) in `kernel::pdp::Blocklist` whenever the list isn't empty.
- **The decision recorded.** A blocked tool gets the same denial `ConfigPolicy` gave:
  reason "Tool 'x' is blocked by security policy", violated policy
  `security.blocked_tools`. It is audited like any other denial.
- **Everything else** goes to the wrapped decision point, unchanged.
- **The name.** The wrapper reports the wrapped decision point's `name()`, so logs and
  checks such as `policy_decision_point().name() == "deny-all"` still name the engine.
- **Policies still see the list.** It stays `resource.restricted`, so existing rules
  keep working.
- **An empty list adds no wrapper.**

## Consequences

- **The list can't be widened.** Neither a policy file nor an embedder's decision point
  can run a blocked tool. To allow one, remove it from the list.
- **The kernel composes, it doesn't decide.** The wrapper is a `PolicyDecisionPoint`
  like any other, so the "policy is a port" rule holds.
- **Don't remove it as redundant.** It can look redundant beside `ConfigPolicy`'s own
  check. Without it, the list is advisory whenever policies are loaded.
- **Tests.** `tests/blocked_tools.rs` drives `Kernel::execute` with a permit-everything
  YAML rule, a permit-everything Cedar policy and an allow-all embedder decision point,
  each with a blocked tool.
