# Cedar policies read labels when the schema declares them, whole

ADR 0014 gave YAML policies and guards the information-flow label of each call's
arguments, and left Cedar for its own slice.

- **Why Cedar took more care.** Cedar validates strictly against a schema (ADR 0008).
  The kernel refuses a schema that doesn't accept what it supplies, and denies a request
  that doesn't match it.
- **What adding labels would have broken.** Adding `context.labels` and an `external`
  tool attribute to what the kernel supplies would break every custom schema.
- **The trap in making them optional.** Making them optional breaks nothing, but opens
  a quieter hole. A forbid written `when { context has labels && context.labels.integrity
  == "untrusted" }` never fires while labels are off, and nothing says so.

## Decisions

**A schema declares labels whole, or not at all.**

- **What a labels schema declares.** It declares `labels` in the context of every
  action that applies to requests, and `external` on `Tool`, all required.
- **What other schemas declare.** None of it.
- **What load refuses.** Anything in between is refused when the policies load (a
  contract error, so the kernel denies everything and says why):
  - **An optional declaration,** for the silent forbid above.
  - **A partial one,** such as labels on the generic action but not a tool's own, or
    labels without `external`. These can't be supplied whole.
- **How the kernel checks.** It reads the declarations from the schema's JSON form,
  following references to common types. Each action's context is checked, not just the
  generic one. A tool's own action has its own context, which a probe of the generic
  action can't see.
- **The shipped schema is unchanged.** `policies/cedar/vak.cedarschema` declares no
  labels, so no existing setup changes.
- **An example labels schema ships.** `policies/cedar/examples/labels.cedarschema` is
  one to copy.

**The setting and the schema must agree.**

- **When.** `policy.labels.enabled` on needs a labels schema, and off needs one without
  labels.
- **Otherwise every call is denied.** The kernel builds a `DenyAll` naming the mismatch,
  and `CedarPolicy` checks again on every decision, so a reload can't slip one in. The
  rule id is `policy.labels`.
- **An unlabelled call is denied too.** With labels on, a call with no label is denied
  rather than decided. A rule on labels can't be satisfied by their absence. Only a PDP
  called outside `Kernel::execute` can see one.

**What Cedar sees:**

| | |
|---|---|
| `context.labels.integrity` | `"trusted"` or `"untrusted"` |
| `context.labels.public` | whether anyone may read the arguments |
| `context.labels.readers` | `Set<String>`, empty when public |
| `context.labels.sources` | `Set<String>`: `"user"`, `"tool:<name>"`, `"skill:<name>"` |
| `resource.external` | the tool is in `policy.labels.external` |

`readers` is a set, so a policy can check a recipient against it:
`context.labels.readers.contains(context.arguments.to)`. That is CaMeL's readers
check, which YAML conditions can't express.

**The example is proved, not only tested.** `labels.properties.cedar` states three
ceilings and a floor, and SymCC proves them over every request the schema admits:

- restricted tools are never called;
- no external call on untrusted arguments;
- private mail reaches only its readers;
- trusted public mail still goes.

Without the untrusted-arguments forbid, the analysis returns a confirmed
counterexample.

## Consequences

- **No change by default.** The shipped schema declares no labels, and labels are off.
- **A labels schema is a commitment.** Turning labels off means switching back to a
  schema without them, and the kernel refuses the mismatch rather than guess.
- **Breaking:** `CedarRequest` gains the public fields `labels` and `external`. A struct
  literal needs them.
- **Common types in other namespaces aren't followed.** A context the kernel can't
  resolve to a record is refused at load, since the kernel can't tell whether it
  declares labels.

## Considered options

**Optional declarations, supplied when labels are on.** Nothing breaks, but `has`-guarded
forbids silently stop firing whenever labels are off.

**Probing each tool's action at decision time** for labels the call doesn't carry. The
probe has to build a context of the declared label type. A schema with a different
shape for `labels` rejects the probe, so the hazard goes unseen. Reading the declarations
sees them whatever their shape.

**Putting `external` in the context rather than on `Tool`.** §4.4 writes
`resource.external`, and it describes the tool, not the call.

**Labels in the shipped schema.** It would make every Cedar setup a labels setup, and
every one with labels off would be refused.
