# The pipeline's admit, budget and outcome stages, and an audit log port

`docs/architecture-v2.md` §5.1 names eight stages for `Kernel::execute`: admit, budget,
decide, guard, record, execute, record outcome, respond. After Phase 0 only three of
them ran. That left four guarantees the design claims, but the code didn't deliver:

- **Principal attributes were constant.** Every agent reached policy as
  `internal = true` (K8), so a rule meant for internal agents applied to everyone.
- **Per-agent tool limits weren't mediated.** `VakAgent` checked its own allowed and
  blocked tools before calling the kernel. Any other caller of `Kernel::execute` with
  the same `AgentId` bypassed them, and the refusals were never audited. That breaks
  complete mediation.
- **The rate limit in config was decorative.** `security.enable_rate_limiting`
  (default `true`) and `max_requests_per_minute` (default 60) were read by nothing (K5).
- **The audit log couldn't outlive the process.** `audit.log_path` was ignored, and a
  caller got no evidence back for a call, only the response.

We decided to build the missing stages behind two new ports (`AgentRegistry` and
`Budget`), to put the audit log behind a third (`AuditLog`), and to make every executed
call produce two leaves plus a receipt.

## Decisions

**Admit looks the agent up on every call.** `AgentRegistry::lookup` returns an
`AgentRecord`: attributes, `internal`, status, and the agent's own allowed and blocked
tools. There is no cache, so a suspension takes effect on the agent's next request.
An unknown agent gets an anonymous record (`internal = false`, no attributes) unless
`security.require_registered_agents` is set, in which case it is refused.

**The agent's own scope is checked in the kernel, before the PDP.** Scope can only
narrow. Checking it before policy means an injected `PolicyDecisionPoint` can't widen
what an agent's record allows. `VakAgent` now registers its record with the kernel and
no longer checks anything itself.

**Each session binds to the first agent that uses it.** Another agent presenting the
same `SessionId` gets `SessionConflict`. This matters once policies read session
history, which is how safety properties over an action prefix are stated.

**The budget is charged before policy.** A flood is throttled before it costs policy
evaluations, and requests that policy would deny still count, so an agent probing the
policy gets throttled too. The default `AgentRateBudget` is a per-agent token bucket:
capacity `max_requests_per_minute`, refilling at that rate ÷ 60 per second. It reuses
`rate_limiter::TokenBucket`. We didn't use `RateLimiter` as it stands, because its
per-action window is keyed by action alone, so a "tool:execute" limit would be shared by
every agent.

**Every refusal is recorded.** A request stopped at admit, budget or decide gets one
`Deny` leaf, naming the rule that stopped it (`security.require_registered_agents`,
`kernel.admission`, `kernel.session`, `agent.scope`, `kernel.budget`), before the error
returns.

**Two leaves per executed call.** The decision leaf is appended before the tool runs.
An outcome leaf is appended afterwards, with `{decision_leaf, success, error,
result_sha256, execution_time_ms}`. The outcome stores the result's digest, not the
result. `AuditEntry::outcome` is hashed only when present, so decision entries hash
exactly as they did before, and existing chains still verify.

**Receipts.** `ToolResponse::receipt` carries both leaf indices and a signed tree head
taken after the outcome leaf. It costs O(log n) hashes and one signature per call.
Proofs stay on demand.

**The audit log is a port, and an append is a promise.** `AuditLog::append` returns
`Ok` only once the entry is stored. `FileAuditLog` writes a JSONL line, then
`flush` and `sync_data`. On open it verifies the whole chain and rebuilds the tree. It
refuses a corrupt file, including a torn last line, rather than repairing it. After a
failed write it refuses every further append until it is reopened, because the file may
end in a partial line.

## Considered options

**Where to enforce per-agent scope.** We considered putting scope into the PDP, as
`architecture-v2.md` §7 first suggested. That would make every PDP implementation,
including embedder-supplied ones, responsible for re-implementing it. A separate check
in the kernel holds for any PDP, by construction.

**What to do when the outcome can't be recorded.** Returning an error would tell the
agent that an action which already happened didn't, and the agent might retry it: a
second payment. We return the response with `receipt: None` and log an error. The
decision leaf is already durable, so "recorded before acting" still holds.

**Whether to record rate-limited requests.** Recording them lets a flooding agent grow
the log. Not recording them hides exactly the behaviour an auditor wants to see. We
record them, and leave aggregation (one leaf per agent per window, with a count) as a
follow-up.

**Repairing a torn last line.** A line without a trailing newline was never
acknowledged, because `append` returns only after the full line is synced, so dropping
it would be safe. We still refuse it. An operator should see that the process crashed
mid-write, and the kernel shouldn't edit its own evidence.

## Consequences

- **Behaviour change:** rate limiting is now enforced. Every agent gets 60 requests per
  minute by default, with bursts of up to 60. Deployments that relied on the limit being
  ignored must raise `max_requests_per_minute` or set `enable_rate_limiting = false`.
- **Behaviour change:** principals are no longer assumed internal. A policy that relied
  on `principal.internal == true` for every agent must register its internal agents
  with `.internal(true)`.
- **Behaviour change:** an executed call produces two audit entries instead of one.
  Code that counted `get_audit_log()` entries per call must count decisions only
  (`outcome.is_none()`).
- `Kernel::active_session_count` now counts bound sessions. It used to be always 0,
  because nothing populated the map. Sessions stay bound until `Kernel::end_session`.
- The in-process token buckets and session map are per kernel. A fleet of kernels
  serving the same agents needs shared adapters behind `Budget` and `AgentRegistry`.
- `audit::AuditLogger`, with its SQLite and S3 backends, is still not the kernel's
  audit path. Making it an `AuditLog` adapter, or removing it, is Phase 1 slice 1e.
