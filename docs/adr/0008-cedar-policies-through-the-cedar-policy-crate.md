# Cedar policies through the cedar-policy crate

ADR 0001 made `CedarEnforcer` the kernel's policy decision point. Its policies are
"Cedar-style" YAML: globs over strings, with conditions parsed at evaluation time, and
no schema. Nothing checks that a policy refers to attributes that exist, and nothing can
analyse a policy set as a whole. `docs/architecture-v2.md` §4.1 plans to evaluate
policies with the real `cedar-policy` crate, validate them against a schema when they
load, and later check properties of the whole set with SymCC. This is the first half of
that plan: the evaluation adapter.

## Decisions

**A `cedar` feature and `policy.format: cedar`.** The `cedar` feature compiles in
`policy::cedar` (the engine) and `kernel::CedarPolicy` (its `PolicyDecisionPoint`).
`policy.format: cedar` selects it, and YAML remains the default. `policy.policy_paths`
names `.cedar` files, or directories whose `*.cedar` files are loaded.
`policy.cedar_schema` names the schema; without it the kernel uses its own,
`policies/cedar/vak.cedarschema`.

**One request shape.** Every tool call reaches Cedar as:

| | |
|---|---|
| principal | `Vak::Agent::"<agent id>"`, with `internal`, `name`, and the record's attributes |
| action | `Vak::Action::"<tool>"` if the schema declares it, otherwise `Vak::Action::"call"` |
| resource | `Vak::Tool::"<tool>"`, with `restricted` (from `security.blocked_tools`) and `builtin` |
| context | `{ session, arguments }` |

Cedar types a request's context by its action, so typed tool arguments need an action
per tool. A schema can declare one, `in ["call"]` so that rules about any call still
cover it, with the argument types its policies read. A tool without its own action is
decided as `call`, and its arguments are not passed: `arguments` is `{}`.

**The schema is the contract, and it is checked on both sides.**

- Policies are validated against the schema in strict mode when they load. A policy that
  reads an attribute the schema doesn't declare fails the load.
- The kernel's side is checked too. At load, a probe request must match the schema.
- At request time, a call that doesn't match the schema is denied. That covers an
  argument that is missing, mistyped, fractional (Cedar has no floats) or undeclared.
  An extra argument is denied rather than dropped, because the tool would act on a
  field no policy saw.
- The kernel passes every attribute on the agent's record, so an attribute the schema
  doesn't declare denies that agent's requests, with a reason naming it. The alternative
  was to pass only declared attributes. That means reading attribute names out of the
  schema, and a mistake there could silently drop an attribute a `forbid` reads, which
  widens access. Strictness costs a schema edit, never access.
- The kernel sets `internal` and `name` after the record's attributes, so a record can't
  override them.

**Fail closed where Cedar doesn't.** Cedar skips a policy whose evaluation errors. For a
`forbid`, that lets the request through: in a test, a `forbid` that overflows on
multiplication leaves Cedar's answer at `Allow`. The adapter denies any request on which
a policy errors, and names the policy.

If the schema or policies can't be loaded, the kernel decides with `DenyAll`, whose
denials carry the load error. That matches ADR 0001's behaviour for YAML.
`KernelConfig::validate` refuses `policy.format: cedar` in a build without the feature.

**Policies are named.** A policy's id is its `@id("…")` annotation, or `<file>/policyN`
without one. Ids must be unique across files, and a duplicate fails the load. They appear
in the decision's reason and `violated_policies`, so in the audit log.
`KernelError::PolicyViolation::policy_id` now carries them for any decision point. It
used to say `"default"` whatever had denied.

**What was ported.** `policies/cedar/default.cedar` holds the tool-call rules of
`policies/default_policies.yaml`. A test runs 24 calls through both: six tools, blocked or
not, internal agent or not. Both engines decide every one the same way, and six of them
are allowed. The YAML file's file, network and memory rules govern actions the kernel
doesn't decide through this port (host functions inside the sandbox), so they aren't
ported. The other YAML files either use `PolicyEngine`'s format, which the kernel never
loads, or are descriptive configuration. `policies/cedar/examples/payments.*` shows typed
arguments instead: a `transfer_funds` action whose amount and currency policies read.

**`security.blocked_tools` stays an attribute.** It reaches Cedar as `restricted`, as in
ADR 0001, rather than as a deny before Cedar. A permit that doesn't check it can
therefore allow a blocked tool. That is the kind of property SymCC is for: "no policy
permits a restricted tool" is the first check planned for CI.

## Considered options

**One action with untyped arguments.** Strict validation needs the context typed per
action, and Cedar's validator doesn't accept open records.

**Inferring the format from file extensions.** As with `audit.format` (ADR 0007), the
setting is explicit.

**Failing `Kernel::build` when policies don't load.** That would make a broken policy file
visible earlier. It would also differ from the YAML path, which denies everything
instead. Hot reload, which comes with the SymCC checks, needs a rule for a reload that
fails, and both paths should get that rule together.

**Replacing the YAML engine.** It is the default and stays one until the remaining YAML
rules have a home.

## Consequences

- The `cedar` feature needs Rust 1.89 and adds 64 packages to the core's 210. It is part
  of `full`, so CI tests it.
- Each request builds its entities from JSON against the schema. That is not yet
  measured; a benchmark should come before the YAML engine is retired.
- Policies load once, when the kernel is built. Reloading comes with the SymCC slice,
  which can check a new set against the old one before swapping it in.
- **Behaviour change:** `KernelError::PolicyViolation::policy_id` names the policy that
  denied, when the decision point says which did.
