# Verifiable Agent Kernel

A control plane that sits between an LLM-driven agent and the outside world, deciding
whether each proposed action is permitted and leaving a tamper-evident record of the
decision.

## Language

### Authorization

**Principal**:
The entity asking to act — an Agent, User, or Service, identified by a UID like
`Agent::"01J..."`.
_Avoid_: caller, subject, requester

**Action**:
The verb being authorized, typed and named, e.g. `Action::"Tool::execute"`.
_Avoid_: operation, command, syscall

**Resource**:
The thing being acted upon, e.g. `Tool::"calculator"` or `File::"/etc/shadow"`.
_Avoid_: target, object

**Rule**:
A single `permit` or `forbid` entry in a policy file, matching a principal/action/resource
triple and optionally guarded by conditions.
_Avoid_: policy (a policy is a *set* of rules)

**Condition**:
A guard on a rule, written `<operand> <op> <operand>`, that must hold for the rule to
apply. Operands read entity attributes (`resource.restricted`), the dynamic context
(`context.trust_score`), a bare entity (`principal`), or a literal.

**Attribute**:
A named value carried by a Principal or Resource that conditions read. The kernel
supplies these; policy files only consume them.

**Decision**:
The enforcer's verdict on one request — allowed or denied, with a reason and the rule
that decided it.
_Avoid_: result, verdict, outcome

**Enforcer**:
The component that turns a request plus a rule set into a Decision. The kernel's policy
decision point.
_Avoid_: policy engine (ambiguous here — see Flagged ambiguities)

**Deny by default**:
The rule that an unmatched request is refused. Holds in both the enforcer path and the
kernel's fallback path.
_Avoid_: fail closed (broader — covers error handling too, not just non-matching)

### Provenance

**Audit entry**:
One immutable record of a decision, hashed over all of its fields including the decision
and its predecessor's hash.

**Audit chain**:
The ordered sequence of audit entries. Intact only if every entry's hash is
self-consistent and commits to the entry before it.

**Skill**:
A WASM module the kernel can execute as a tool, loaded from a manifest and identified by
name.
_Avoid_: plugin, extension, tool (a tool may be a built-in instead)

**Built-in tool**:
A tool the kernel handles directly rather than dispatching to a Skill — `echo`,
`calculator`, `data_processor`, `system_info`.

## Relationships

- A **Principal** requests an **Action** on a **Resource**; the **Enforcer** returns a **Decision**
- A **Rule** matches a principal/action/resource triple and holds only if all its **Conditions** hold
- **Conditions** read **Attributes**, which the kernel supplies — never the policy file
- A `forbid` **Rule** beats a `permit` **Rule** regardless of order in the file
- Every **Decision** produces exactly one **Audit entry**, appended to the **Audit chain**
- A **Tool** is either a **Built-in tool** or a **Skill**

## Example dialogue

> **Dev:** The policy says `resource.restricted == false`. Where does `restricted` come from — is it in the policy file?
>
> **Domain expert:** No. A policy file only ever *reads* attributes. The kernel decides what `restricted` means and supplies it — today that's "the tool is in `blocked_tools`". If the policy asked about an attribute the kernel doesn't supply, the rule can't grant.
>
> **Dev:** So a typo in a condition silently disables the rule?
>
> **Domain expert:** It disables it, but not silently — an unresolvable condition on a `permit` logs a warning and the rule doesn't grant. On a `forbid` it's stronger: the request is denied outright. A prohibition we can't read must never become permission.
>
> **Dev:** And if the whole policy file is missing?
>
> **Domain expert:** Then every request is denied. That's different from configuring *no* policy files at all, which falls back to the allowlist. Configured-but-broken is an error; not-configured is a choice.

## Flagged ambiguities

- **"policy engine"** was used for two different types: `CedarEnforcer` (`policy/enforcer.rs`) and `PolicyEngine` (`policy/mod.rs`), which have incompatible rule schemas. Resolved: the kernel's decision point is the **Enforcer** (`CedarEnforcer`); `PolicyEngine` is a separate, currently unwired implementation. Prefer "enforcer" when talking about the kernel's authorization path. See docs/adr/0001.

- **"policy"** was used for both a single rule and a whole file. Resolved: a **Rule** is one entry; a policy *file* holds a rule set.

- **"default deny"** appeared in three places with different meanings: `EnforcerConfig::default_deny` (enforcer-internal), `PolicyConfig::default_decision` (kernel fallback), and the design principle. Resolved: all three now agree on refusing unmatched requests; the design principle is the **Deny by default** entry above.

- **"restricted"** vs **"blocked"**: policy files say `resource.restricted`, kernel config says `blocked_tools`. Resolved: they are the same concept, bridged by the kernel. Prefer **blocked** when talking about configuration, **restricted** when quoting a policy condition.
