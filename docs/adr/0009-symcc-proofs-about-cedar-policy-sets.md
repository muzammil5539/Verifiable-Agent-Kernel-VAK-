# SymCC proofs about Cedar policy sets

ADR 0008 made the kernel evaluate real Cedar. Evaluation answers whether one request is
allowed. A reviewer of a policy change needs answers about every request: can any agent
call a blocked tool now? Does this edit take access away from something that needs it?
`docs/architecture-v2.md` §4.1 plans those answers from SymCC, Cedar's symbolic compiler.
SymCC translates a policy set into SMT and asks cvc5, and its encoding is verified in
Lean. This is that plan.

## Decisions

**A `cedar-analysis` feature over `cedar-policy-symcc` 0.7.** It adds
`policy::cedar::analysis`, plus a checked reload on `kernel::CedarPolicy`. The checks
start cvc5 1.3.1 as a separate process: the version SymCC is verified against, found
through the `CVC5` environment variable or on `PATH`. The feature adds 4 packages to
`cedar`'s 274. It is part of `full`, so it compiles in CI. The solver is needed only to
run checks.

**Properties are written in Cedar.** A property is a policy set. Each of its policies
carries `@property("<name>")` and `@kind("ceiling")` or `@kind("floor")`, and the policies
sharing a name form one property. Properties are validated against the policies' schema,
like policies.

- **A ceiling** bounds what the policies may allow: every request the policies allow,
  the ceiling allows. "No policy permits a restricted tool" is
  `permit (principal, action, resource) when { !resource.restricted };`.
- **A floor** is what the policies must keep allowing: every request the floor allows,
  the policies allow.

SymCC checks each with `check_implies` in every request environment of the schema (each
principal type, action and resource type). Writing properties in the policy language
means no second language and no translation step, and a reviewer reads them the way they
read policies. A property that needs `context.arguments` is scoped to the action that has
them, because that is the only place they type-check.

**Never-errors is always checked.** For every policy, SymCC checks that no request makes
it fail to evaluate. Since ADR 0008 the kernel denies any request on which a policy
errors, while Cedar, and so SymCC's model of it, skips that policy. When no policy can
error, the two agree. So a ceiling proven by SymCC holds for the kernel in any case,
because the kernel only ever denies more. A floor holds for the kernel only together with
never-errors.

**Counterexamples are confirmed.** A failed check comes with a concrete request and entity
store. The analysis re-runs it through the Cedar evaluator and records whether the
evaluator reproduces the failure. A counterexample the evaluator doesn't reproduce would
mean the analysis and the evaluator disagree, and the report says so.

**Checks cover every request the schema admits, not only the ones the kernel makes.**
That keeps ceilings sound. It can make a floor fail on a request the kernel never
produces, such as a tool called `dd` that is marked `builtin`, so the shipped floor names
the tools it protects by id. A request that doesn't match the schema never reaches Cedar;
the kernel denies it first (ADR 0008).

**Reloads.**

- `CedarPolicy` now holds its policy set behind an `ArcSwap`. A decision uses one set
  throughout, and a reload takes effect from the next decision.
- `reload` swaps a set in unchecked.
- `reload_checked` swaps it in only if three things hold. Every property holds of the new
  set. None of its policies can error. And, unless `Widening::Allow` is given, it allows
  nothing the current set doesn't.
- `Widening::Allow` is for a reviewed change meant to grant access. Properties still
  apply, so it cannot break a ceiling.
- A checked reload must keep the schema. The properties were validated against it, and a
  new schema changes what requests look like, so that takes a restart.
- A reload that fails, or can't be analysed, leaves the current set in force. Reloads are
  serialised, so each is checked against the set it replaces.
- That answers the question ADR 0008 left open: at startup, policies that fail to load
  make the kernel deny everything; on reload, the policies already in force stay.

**CI proves the shipped policies.** `examples/cedar_check.rs` loads policies the way the
kernel does and runs the properties, the never-errors checks and, with `--baseline`, the
no-widening check. It exits 1 with a counterexample when a check fails. CI downloads cvc5
1.3.1, pins it by SHA-256, and runs it:

- on the default policies with `policies/cedar/properties/`;
- on the payments example with its properties;
- on pull requests, against the base branch's policies, as a no-widening report that
  doesn't block, because widening can be intended.

Tests that need the solver are `#[ignore]`d, so without cvc5 they show as ignored rather
than passing. CI runs them with `--include-ignored`, and without a solver they fail.

**What it found.** The slice 2a example `payments.cedar` let a finance agent call
`transfer_funds` after the tool had been put in `security.blocked_tools`: its permit never
read `resource.restricted`. The restricted-tools ceiling fails on it, with the
counterexample of a finance agent sending 1000 USD through a restricted tool. The example
now carries a forbid on restricted tools, and a test keeps the unguarded version failing.

## Considered options

**Properties in a separate format** (YAML, or a property DSL). Each would need its own
translation into SMT, and that translation would be unverified. Cedar properties reuse
SymCC's verified encoding.

**Running the checks when the kernel starts.** That would need cvc5 on every production
host, and a check failure at startup has no safe answer other than denying everything,
which DenyAll already gives a policy that doesn't load. Checks run in CI and on reload,
where a failure has somewhere to go.

**Skipping solver tests when cvc5 is absent.** A test that passes without running is
indistinguishable from one that ran. Ignored tests are visibly ignored.

**Making the base-branch comparison block merges.** Granting access is sometimes the
point of a change. The check reports, and a reviewer decides.

## Consequences

- The analysis is only as strong as the properties written. Three ship for the default
  policies, and two for the payments example.
- **Breaking:**
  - `CedarPolicy::policies` returns an `Arc<CedarPolicySet>` (the current set) instead of
    a reference.
  - `CedarPolicyError` has a `PropertyAsPolicy` variant. A file of properties loaded as
    policies would grant what it bounds, so the policy loader refuses any policy carrying
    `@property`.
- Checks are fast for policy sets this size: proving the default policies' properties
  takes about 20 ms, cvc5 included. How they scale with hundreds of policies is not yet
  measured.
