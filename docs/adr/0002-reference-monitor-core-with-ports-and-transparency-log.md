# A reference-monitor core with ports, and a transparency log for audit

VAK's value to an embedding application is one guarantee: every agent action is decided
by policy, recorded before it runs, and provably so. An audit of the code against its
claims (`docs/architecture-v2.md` §2) found the request path didn't deliver that
guarantee:

- A permitted tool with no implementation returned a fake success.
- Every WASM skill trapped on entry, because no epoch deadline was set.
- Library users could add tools only by dropping WASM files on disk.
- The audit trail, a hash chain held in RAM, couldn't prove to anyone outside the
  process that it hadn't been truncated and re-extended.

Meanwhile about 80k lines of research prototypes compiled into the same crate with no
boundary around the trusted core.

We decided to treat the kernel as a **reference monitor** (Anderson, 1972): one
mediation point, kept small, with everything else behind traits ("ports") that
embedders implement or replace. We also decided to record decisions in an **RFC 9162
Merkle tree** rather than a bare hash chain.

## Considered options

**Ports.** We considered a full hexagonal split now, with separate crates for core,
audit, sandbox and policy. We chose to introduce the ports inside the existing crate
first, for two reasons. Splitting first would mean moving 80k lines before the
interfaces have been tried. And the existing `kernel::custom_handlers::ToolHandler`
trait was already the right shape for tool execution; it only needed to be wired in.
`kernel::traits` was not reused: its `PolicyEvaluator` returns a parallel
`TraitPolicyDecision` type, and nothing implemented or called it.

**Audit structure.** We considered:

- keeping the hash chain and anchoring its head externally;
- a sparse Merkle tree;
- an RFC 6962/9162 history tree.

Only the history tree gives both O(log n) inclusion proofs *and* consistency proofs
between any two sizes. Consistency proofs are what make truncation and rewriting
detectable by a third party who saw an earlier head (Crosby & Wallach, 2009). It is
also the construction Certificate Transparency, Sigstore Rekor and Go's checksum
database already rely on, so the roots are checkable against published test vectors,
which we do.

## Consequences

- `Kernel::builder(config)` accepts a `PolicyDecisionPoint`, tool handlers, and an audit
  signing key. `Kernel::new(config)` is unchanged for existing callers; it builds the
  same `ConfigPolicy` or `EnforcerPolicy` that `evaluate_policy` used to inline.
- **Behaviour change:** executing a tool that is permitted but doesn't exist now
  returns `Err(KernelError::ToolNotFound)` instead of `Ok` with `success: true`.
  Callers that relied on the fake success were relying on a false report.
- Registering a tool doesn't authorize it. The PDP still decides every call, so with
  the default config a new tool must be added to `security.allowed_tools` or to a
  policy. Handler names can't shadow built-ins or replace an existing handler. Swapping
  the code behind a tool name is a security event, not a convenience.
- The kernel's audit entries keep their per-entry chain hash. Each entry's hash is also
  a leaf of the Merkle tree, so nothing already recorded changes meaning. Verifying one
  entry without trusting the kernel takes two checks: `AuditEntry::verify_integrity`,
  and `verify_inclusion` of `Kernel::audit_leaf_hash(entry)` against a signed tree head.
  Neither alone is sufficient; the doc comment on `audit_leaf_hash` explains why.
- Tree heads are signed with a per-kernel Ed25519 key unless one is supplied. A
  generated key detects tampering within one process lifetime only. Deployments that
  need durable evidence must supply a key and persist the log. Persistence is the
  `AuditLog` port in Phase 1.
- The `audit::AuditLogger` (file, SQLite and S3 backends) is still not the kernel's audit
  path. Unifying them behind an `AuditLog` port is Phase 1 work, not done here.
