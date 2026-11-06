# Information-flow labels, kept per agent, that only rise

`docs/architecture-v2.md` §4.4 names VAK's most distinctive opportunity: a kernel on
every tool call is where **information-flow control** belongs. Indirect prompt
injection lets any tool result carry instructions. Detecting those is a heuristic.
What a kernel can enforce is where data came from:

- **Labels on results.** Each result gets a label: its source, its integrity
  (`trusted` or `untrusted`) and its confidentiality (who may read it).
- **Policies on arguments.** Policies refuse consequential calls on untrusted
  arguments, e.g. `forbid(action == "email:send") when { context.args_integrity ==
  "untrusted" && resource.external }`.

The prior art:

- **CaMeL** tracks a capability on every value in its own interpreter.
- **FIDES** keeps a label on the planner's context: the join of everything the planner
  has read.

VAK sees only tool calls. It can't see what an agent does between them. This slice adds
the labels, tracks them per agent, hands them to the policy and the guards, and records
them. In the flowchart in §5 this is the LABELS box between BUDGET and PDP. It is the
first step of the Decide stage, so the stage numbers of ADR 0003 and ADR 0013 stand.

## Decisions

**A label is a lattice element** (`kernel::ifc::Label`). It has three parts:

- **Integrity.** `Trusted < Untrusted`. The join is the greater.
- **Readers.** `public`, or the readers named. The join keeps only the readers both
  allow. Two labels with no reader in common join to the empty list, which means no
  one. It is not the same as `public`.
- **Sources.** `user`, `tool:<name>` or `skill:<name>`. The join is the union.

The default label is the lowest: trusted, public, from nowhere. Joining it with any
label leaves that label unchanged. `join` and the label's builders only raise it, and
the kernel never lowers an agent's label. Unit tests check the lattice laws over a
sample of labels.

**The kernel keeps a context label per agent**, as FIDES does for the planner. It is
the join of every result returned to the agent and every label the agent declared.

- **What a call's arguments get.** The kernel can't see which value an argument came
  from. So the arguments get the agent's whole context label: everything it has been
  given may have shaped every call it makes afterwards. This is the principle
  Beurer-Kellner et al. share across their design patterns: once an agent has read
  untrusted input, that input must not be able to trigger consequential actions. It is
  coarse, and it is sound.
- **Why one label serves both names.** `context.integrity` and `context.args_integrity`
  in §4.4 are one label today. Policies read it as `args_*`. A later slice can make the
  argument label more precise than the context: with value handles, in the manner of
  CaMeL or FIDES variables, an agent passes a result by reference without reading it.
  Then a separate context label earns its own name.

**Per agent, not per session.** This is the decision a maintainer is most likely to
reverse by accident.

- **Why not per session.** A session looks like the natural unit of an agent's context.
  But the MCP gateway and `VakRuntime::execute_tool_call` open a new session for every
  call. A per-session label would never accumulate there. A tainted agent's next call
  would look clean, and a rule on untrusted arguments would let it through: failing
  open.
- **No implicit reset.** Ending a session doesn't clear the label, and nothing else
  clears it either. The way to start a clean context is a new agent ID, which only the
  embedder can mint. The Python binding mints one each time an agent is registered.

**Declared labels only raise.** `Kernel::execute_labeled` takes a
`Labeled<ToolRequest>`: a request with the label of its arguments. It returns a
`Labeled<ToolResponse>`.

- **What a declaration is for.** Data the kernel never returned, such as a page an
  agent framework fetched itself.
- **What it can do.** The declared label is joined into the agent's context, never
  substituted for it. So declaring `trusted` changes nothing. An agent is not trusted
  to lower a label.
- **When it joins.** It joins at the Labels stage, whatever the decision, because the
  agent holds that data either way.
- **When labels are off.** `execute_labeled` refuses with `InvalidConfiguration`,
  before anything runs or is recorded. The kernel would otherwise return a label it
  didn't compute.
- **Size.** A declared label naming more than 256 sources, or more than 256 readers
  (`ifc::MAX_DECLARED`), is refused with `ResourceLimitExceeded`, before anything runs
  or is recorded. It would otherwise be kept in the agent's context and copied into
  every later audit entry. Sources from results need no bound: only tools that exist
  add one.
- **What `execute` does.** It is `execute_labeled` with the lowest label, and with the
  result's label dropped.

**What a result gets.** The tool's source label, joined with its arguments' label,
since a tool's output can depend on its input. The label joins the agent's context
before the response returns, so the agent can't use the result in a call that doesn't
see it.

- **A failed tool's error is labelled the same.** The error text reaches the agent and
  can carry an attacker's words.
- **A tool that doesn't exist** produced nothing. Its outcome carries the arguments'
  label.
- **Concurrent calls.** A concurrent call decided before the join can't contain the
  result, because the agent didn't have it yet.

**Source labels come from configuration, and fail closed.** `policy.labels.sources`
maps tool-name patterns to a label (integrity and readers). It uses the matcher of
`policy.min_assurance` and YAML rules. Where patterns overlap, their labels are joined.

- **Unlisted tools are untrusted.** A tool no pattern matches is untrusted: host
  handlers and WASM skills alike. Nothing is known about where their output comes from.
- **Except built-ins.** The built-ins (`echo`, `calculator`, `data_processor`,
  `system_info`) compute only from their arguments or from the kernel. They add no
  taint, and their results carry their arguments' label.
- **Configuration can change either way.** It can trust a handler or distrust a
  built-in. It is the embedder's endorsement, made in a file the agent can't write.
- **Readers default to `public`.** Confidentiality is opt-in. A default of "no one"
  would forbid every flow the moment labels are on.

**`policy.labels.external` marks tools that send data outside.** Policies read it as
`resource.external`. An unlisted tool isn't external. That default only narrows what
rules that ask about `external` refuse; a rule can refuse on integrity alone.

**Policies and guards see the label.**

- **`PolicyRequest` and `GuardRequest` gain `labels: Option<&Label>`.** Both are
  `#[non_exhaustive]`, so this breaks no implementation. ADR 0013 kept `GuardRequest`
  open for exactly this.
- **YAML rules.** The YAML enforcer gives them:
  - `context.args_integrity`: `"trusted"` or `"untrusted"`;
  - `context.args_public`;
  - `context.args_readers`: only when not public;
  - `context.args_sources`;
  - `resource.external`.

  Without labels none is set. A condition that reads one then can't be evaluated, so a
  forbid fires and a permit doesn't grant (ADR 0001). A rule on labels can't be
  satisfied by their absence.
- **`evaluate_policy`.** It passes the agent's current context label and doesn't change
  it.
- **`ConfigPolicy` ignores labels.** It has no rule language. Label rules need YAML
  policy files.
- **Cedar is a separate slice.** Its schema is strict: the kernel refuses a schema that
  doesn't accept what it supplies, and denies requests that don't match (ADR 0008).
  Supplying `context.labels` would break every custom schema, and the contract needs
  care. A Cedar policy that reads `context.labels` today fails validation against the
  shipped schema, and the kernel then denies everything. So no Cedar rule is silently
  ignored.

**The audit log records labels.** `AuditEntry` gains `label: Option<Label>`.

- **Decision entries.** A decision entry, and a policy or guard refusal, records the
  arguments' label: what the policy saw.
- **Outcome entries.** An outcome entry records the result's label.
- **Admit and budget refusals** come before the Labels stage, and record none.
- **Hashing.** The field is serialized and hashed only when present, behind its own tag
  `label`, as `guards` and `outcome` are (ADR 0003, ADR 0013). Entries without it hash
  byte for byte as before, so existing JSONL and SQLite logs still verify.

**Labels are off by default** (`policy.labels.enabled: false`). Configuring `sources`
or `external` while labels are off is refused at startup: nothing would ever apply
them. This is the same rule as ADR 0013's floors that could never apply.

## Consequences

- **No behaviour change by default.** With labels off, decisions, audit entries and
  responses are as before.
- **The assurance is `Enforced` for propagation inside the kernel.** It is only as good
  as the agent framework's hygiene outside it, and the docs say so. That hygiene has
  two parts:
  - **Declared labels.** Data the kernel never returned must be declared.
  - **Agent identity.** Each context needs its own agent ID, and an agent must not be
    able to choose a fresh one.

  The MCP gateway breaks the second part. Its `agent_id` is an argument of the MCP
  call, which the calling model fills in. Unless `security.require_registered_agents`
  is set, a client can shed its label, as it can its budget, by changing the name.
- **Coarse.** One untrusted read taints every later call by that agent.
  - **For the embedder.** It can give a task a fresh agent, or trust a source that
    deserves it.
  - **For precision.** It needs value handles, a later slice.
- **Memory.** One label per agent that has made a call, kept as long as the kernel.
  Agents aren't unregistered from the kernel, so a long-running embedder that mints an
  agent per task keeps one small label per task.
- **Breaking:** `AuditEntry` gains a public field. Code that builds one with a struct
  literal, rather than `AuditEntry::new`, needs `label: None`.
- **Breaking:** `PolicyConfig` gains the public field `labels`. A struct literal needs
  it, or `..Default::default()`.
- **Breaking, for older binaries.** An older binary can't open a log written with
  labels, as with guard and outcome records.
- **Python.** The binding shows a recorded label in an audit entry's details. It has no
  way yet to declare labels or read a result's label. `execute_tool` still tracks the
  agent's context when labels are on.

## Considered options

**Per-session labels.** These fail open on the two front-ends that open a session per
call, as above.

**Agent-supplied labels that replace the kernel's.** The agent is the thing whose
decisions an injection controls. Letting it say "this is trusted" defeats the purpose.

**A field on `ToolRequest` for the declared label, and on `ToolResponse` for the
result's.** Neither struct is `#[non_exhaustive]`. Embedders build `ToolRequest`
literals, as `ToolRequest`'s own documentation example does, and tool handlers return
`ToolResponse` literals.
`Labeled<ToolRequest>` and `Labeled<ToolResponse>` carry the same information without
breaking them.

**A kernel-level rule table in configuration**, like `policy.min_assurance`, e.g.
"these tools need trusted arguments". It would hold for every PDP. But §4.4 puts the
rules in policy, and "policy is a port" keeps rules out of the kernel. YAML rules
already express them. A guard could add a PDP-independent check later.

**Trusting unlisted tools.** That fails open: a new web-fetch handler would be trusted
until someone remembered to list it.

**Leaving built-ins untrusted too.** Their outputs come from their arguments or from
the kernel itself. Joining the arguments' label already carries any taint through.

**Clearing labels when a session ends, or when an agent is re-registered.** Either one
launders a label through an act the caller controls.
