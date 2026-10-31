# Guards narrow allowed calls, and policy can require their assurance

`docs/architecture-v2.md` §5.1 puts a Guard stage between Decide and Record: zero or
more extra checks on each call the policy allowed. Each check declares an assurance
level, and "a policy can require, for example, `min_assurance = Enforced` for
`payment:*`, so an LLM judge can *add* denials but never be the only thing standing
between an agent and a high-risk action" (§3.4, §5.1). Until now stage 4 was a comment
in `Kernel::execute`. Finding K5 records the checks waiting for it: the constitution,
the neuro-symbolic pipeline and the reasoner's guards, none of which `Kernel::execute`
calls.

This slice adds the port, the levels, the floor and the record. It adds no adapters.

## Decisions

**A `Guard` port in the core.** `kernel::guard` defines it, ungated, beside the other
ports:

```rust
#[async_trait]
pub trait Guard: Send + Sync + Debug {
    async fn check(&self, request: &GuardRequest<'_>) -> GuardVerdict;
    fn name(&self) -> &str;
    fn assurance(&self) -> Assurance;
}
```

- **How guards are added.** `KernelBuilder::with_guard` adds one. Guards run in the order
  added, and there are none by default.
- **Names.** Each guard needs a unique, non-empty name, or the kernel refuses to build:
  a refusal is recorded as rule `guard.<name>`, which has to say which guard refused.
- **What a guard sees.** `GuardRequest` carries what the PDP saw (agent, call, the
  agent's record, session) and the PDP's decision. It is `#[non_exhaustive]`, like
  `PolicyRequest`, so information-flow labels can be added without breaking guards.
- **`FunctionGuard`** makes a guard from a synchronous function.

**Four levels, declared per guard.** `Assurance` is `Experimental < Heuristic <
Checked < Enforced`, with the meanings in §3.4: Enforced is deterministic and total,
Checked is sound but partial, Heuristic is a signal that can be wrong, and Experimental
is not sound. A guard declares one level for all its verdicts, and the kernel records
the level beside each verdict, so a guard can't claim a stronger check for one call.

**Four verdicts: `Pass`, `Abstain`, `Deny`, `Escalate`.** §5.1 names three. `Abstain`
is added because the floor below counts passes. Without it, a guard that checks only
file paths would answer `Pass` to a payment, and that pass would meet a payments floor
it never checked. `Abstain` says "not mine": it lets the call go on and counts toward
nothing.

**Guards only narrow.** They run only on calls the PDP allowed. Anything else is
recorded and refused at Decide, as before. Only an explicit `Allow` goes on, so a
decision kind added later can't fall through to execution. Then:

- **Any guard can refuse.** A `Deny` or `Escalate` from any guard refuses the call,
  whatever its level, so a heuristic can add denials.
- **The first refusal ends the stage.** Later guards don't run: an LLM judge isn't
  paid for a call already refused.
- **A failed guard denies.** A guard that panics, even before its check
  starts, denies. So does one that hasn't answered within `max_execution_time`,
  or answers only after it. Each guard's name and level are read once, when the
  kernel is built.

**`Escalate` refuses until there is an approval channel.**

- **Why.** §5.2 lists `ApprovalChannel` as a later port whose default is deny.
- **How it surfaces.** The refusal is `KernelError::PolicyViolation` with `policy_id`
  `guard.<name>`. The reason says approval was asked for and no channel is configured.
- **How it is recorded.** As an escalation, not as a plain denial.
- **No new error yet.** Neither `KernelError` nor `PolicyDecision` gains a variant
  until the channel exists. Only then can a caller do something different with "needs
  a human".

**`policy.min_assurance`: a floor in kernel configuration.**

- **Format.** A map from a tool-name pattern to a level:

  ```yaml
  policy:
    min_assurance:
      "payment:*": enforced
      transfer_funds: checked
  ```

  Patterns are those of YAML policy rules: `*`, `prefix*`, `*suffix` or an exact name.
  The two share one matcher.
- **When it is met.** A call is admitted only if a guard of the required level or
  above returned `Pass`. Where patterns overlap, the highest level applies.
- **The PDP's allow doesn't count.** Every built-in PDP is deterministic, so if its
  allow counted as Enforced, every floor would be met and none would mean anything.
- **What it applies to.** It holds whatever the PDP: `ConfigPolicy`, YAML, Cedar,
  `DenyAll` or an injected one. It also holds whatever `policy.enabled` says.
- **Failing closed.** With no guard of the level registered, matching calls are
  refused. A shortfall is recorded as rule `policy.min_assurance`.
- **Validation at startup.** A pattern the matcher can't honour (`pay*ment`, `*pay*`,
  empty) is refused, because it would silently never apply. So is the level
  `experimental`: a floor an unsound check could meet would mean nothing.

**The decision's audit entry records the guards.**

- **The field.** `AuditEntry` gains `guards: Option<GuardChecks>`: the level required,
  and each guard that ran, with its level, verdict and reason. "Audit records which
  levels contributed to each decision" (§3.4).
- **Where it is set.** On an allowed call's decision entry, and on the entry for a
  guard or floor refusal. It is not set on outcome entries, which link to their
  decision entry.
- **When it is absent.** When no guard ran and no level was required. It is serialized
  and hashed only when present, behind its own tag, as `outcome` is (ADR 0003). Entries
  without it are byte-for-byte what they were, so existing JSONL and SQLite logs still
  verify on open.

**`evaluate_policy` stays the Decide stage alone.** It runs no guards and applies no
floor, so `execute` can refuse a call it allows. That was already true of admission
and budget. Python's `evaluate_policy` says so.

## Consequences

- **No behaviour change by default.** No guards and an empty `min_assurance` leave
  every call and every audit entry as before.
- **Breaking:** `AuditEntry` gains a public field. Code that builds one with a struct
  literal, rather than `AuditEntry::new`, needs `guards: None`. Nothing in the
  repository does.
- **Breaking:** `PolicyConfig` gains the public field `min_assurance`. A struct
  literal needs it, or `..Default::default()`.
- **A guard that blocks can't be stopped.** The deadline interrupts a guard only
  where it awaits. A guard that blocks the thread, such as a `FunctionGuard`
  making a synchronous network call, can't be interrupted.
  - **If it answers late,** its answer is replaced by a denial.
  - **If it never answers,** the call waits with it, holding the executor thread.

  Slow checks belong in async guards, or on `spawn_blocking`.
- **Breaking, for older binaries.** An older binary can't open a log written with guard
  records: it drops the unknown field, recomputes the hash without it, and refuses the
  log as tampered. Outcome records had the same property (ADR 0003).
- **Guards reach only builder embedders.** They are added with the builder. The Python
  SDK and `VakRuntime` build their kernels with `Kernel::new`, so they can't add one. A
  `min_assurance` floor in their config file still applies, so for them it refuses
  every matching call. That fails closed, and it is documented.
- **No Enforced guard exists yet.** A floor of `enforced` refuses its tools until an
  embedder adds such a guard. The adapters are the next slices:
  - **The constitution (K5).** In the core, Enforced. It should answer `Abstain`, not
    `Pass`, when no rule objects: its rules are a blocklist, and a blocklist that
    doesn't object hasn't checked the call.
  - **The prompt-injection detector.** Behind `reasoner`, Heuristic, after its UTF-8
    slicing panic is fixed.
  - **Datalog on Ascent.** Later.
- **Guards see a call before it is recorded.**
  - Stage 4 runs before stage 5, so a guard that calls out, such as an LLM judge,
    sends a call's arguments before the decision is appended.
  - If that append fails, the call doesn't run, but nothing records what the guard
    saw.
- **A refused call still costs budget.** Budget is charged at stage 2, as for a policy
  denial (ADR 0003).

## Considered options

**`@min_assurance` annotations on Cedar permit policies.** This puts the floor in the
policy language. It was not chosen for now, for three reasons:

- **Cedar only.** The YAML and config PDPs would have no floor.
- **It needs a transport.** It has to reach the kernel through `PolicyDecision`, which
  isn't `#[non_exhaustive]`, so that is a breaking change.
- **Cedar can't name tools by pattern.** It can't express `payment:*` against today's
  schema.

It also opens a hole in checked reloads. SymCC compares allow-sets, and annotations
have no semantics, so a reload that drops an annotation would pass as not widening.
This can come later beside the configuration floor, with the kernel taking the higher
of the two and a reload check per level.

**A field on YAML rules.** The YAML enforcer takes the first permit that matches. A
broad earlier permit (`permit-safe-tools` matches every unrestricted tool) would hide a
later one carrying the requirement.

**Counting the PDP's allow toward the floor.** That makes every floor vacuous while a
built-in PDP decides.

**Three verdicts, as §5.1 lists.** Without `Abstain`, any guard's `Pass` meets any
floor whether or not it checked the call.

**A per-verdict assurance level.** It lets a guard claim a stronger check for one call
than it declares.

**`KernelError::EscalationRequired`.** It would be breaking now, and it means nothing
to a caller until an approval channel can act on it.

**Guards before Decide**, with guard results as policy context. That reverses the
order in §5.1, and it runs guards, possibly LLM calls, on requests the policy denies
anyway. Information-flow labels will reach the PDP as context (§4.4); guard verdicts
don't need to.

**Running every guard rather than stopping at the first refusal.** That records more,
but it pays for checks whose answer can't change the outcome.
