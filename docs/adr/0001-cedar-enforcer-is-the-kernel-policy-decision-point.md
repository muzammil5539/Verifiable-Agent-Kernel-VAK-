# CedarEnforcer is the kernel's policy decision point

`Kernel::execute` previously made authorization decisions itself, using a hardcoded
allowlist/blocklist read from `KernelConfig`, and never consulted the `CedarEnforcer` or
any file under `policies/`. We moved the decision into `CedarEnforcer` so that policy
lives in data rather than in kernel code, which is the property the project's
"verifiable kernel" claim rests on.

## Considered options

`src/policy/` contains two engines with incompatible rule schemas. We chose
`CedarEnforcer` (`policy/enforcer.rs`) over `PolicyEngine` (`policy/mod.rs`) because it
already fails closed when no policies are loaded, it is async and so fits the kernel's
request path, and its schema matches all ten shipped `policies/*.yaml` files.
`PolicyEngine` had the better condition evaluator but would have required rewriting
every policy file.

## Consequences

Three consequences are non-obvious:

**Conditions had to be implemented, not just wired.** `CedarEnforcer` parsed
`rule.conditions` into `Vec<String>` and then never read them — `rule_matches` compared
only the principal/action/resource globs. Wiring the enforcer in as-is would have
replaced a hardcoded allowlist with a policy file whose conditions were decorative, so
condition evaluation is part of this change. Conditions on a rule are ANDed. A condition
that cannot be parsed or resolved denies the request and logs a warning; gaps fail
closed and stay visible rather than silently widening access.

**The kernel populates the attributes that conditions read.** Nothing in the codebase
set `resource.restricted`, `resource.owner` or `principal.internal`, so
`default_policies.yaml`'s only tool-permit rule (`resource.restricted == false`) could
never have fired and every tool would have been denied. The kernel now supplies these
from facts it already holds: `restricted` from `security.blocked_tools`, `internal` from
whether the tool is a kernel built-in, `owner` from the requesting agent.

**The enforcer is opt-in, and the fallback is stricter than the policy.** When
`policy.policy_paths` is empty the kernel keeps using the allowlist plus
`policy.default_decision` (which defaults to deny). This keeps existing embedders
working, and matters only because the fallback is *more* restrictive than a loaded
policy set would be — there is no configuration in which skipping the enforcer widens
access. When `policy_paths` is set and loading fails, the kernel denies everything
rather than falling back.
