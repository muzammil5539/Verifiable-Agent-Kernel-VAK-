# Datalog safety rules run on Ascent, as an enforced guard

`reasoner::datalog::SafetyEngine` was called a Datalog engine, but its nine rules
were Rust closures run in a loop (finding V3). There was no fixpoint, no recursion
and no negation semantics, and facts matched by exact string. The path bypass
(`/etc//shadow`) was fixed lexically, but the engine stayed `Heuristic` until it was
ported. `Kernel::execute` never called it. `docs/architecture-v2.md` §4.5 names
Ascent as the engine; ADR 0013 makes guards the place for checks on allowed calls.

## Decision

### The built-in rules are an Ascent program

[Ascent](https://github.com/s-arash/ascent) (Sahebolamri, Gilray and Micinski, CC
2022) compiles Datalog to Rust through a macro and evaluates it semi-naively to a
fixpoint. It supports stratified negation and aggregation. We use 0.8.1 with
`default-features = false`, so no rayon. It is MIT-licensed, needs Rust 1.85 (below
our MSRV) and generates no `unsafe`. It is behind `reasoner`, which already gates
this module.

- **The knowledge base becomes input relations,** and each check is one run. The
  inputs are the facts, the action checked, and `applies(rule, action)` from a
  table of the nine rules.
- **Paths.** `within(path, dir)` is recursive: the transitive closure of
  `parent(path, dir)`, so a system path covers every depth under it.
  - A sensitive pattern matches an absolute path exactly, or any relative
    component suffix (`.env` in any directory).
  - Both join on paths canonicalised as before.
- **An agent's risk is an aggregate:** the highest score recorded for it, else 0.
  The closures read whichever score the hash set yielded first, so a stale low score
  could hide a high one.
- **Rule 9 is a negation:** an agent *without* `network`.
- **What stays Rust:**
  - **Helpers** that compute values from strings (canonical paths, parents,
    suffixes, endpoints). They run inside rules.
  - **Rules added with `SafetyEngine::add_rule`.** Their checks are Rust functions
    and run after the program, as before.
- **The API is unchanged.** `SafetyEngine`, `Fact`, `SafetyVerdict`, `check_action`
  and `verify_plan` keep their behaviour, with these exceptions:
  - violations come in rule order;
  - `skip_defaults` drops the built-in rules, which it always did;
  - the comparisons below are wider.

### Bypasses closed with it

The path fix (V3) left two exact-string comparisons:

- **Endpoints** are canonicalised: URLs are parsed, and their scheme and host
  lowercased, default port dropped, dot segments resolved and fragment dropped.
  - **What a fact covers.** An `ExternalEndpoint` covers its host, on any scheme or
    port and with a trailing dot or not, at its path and under it. It used to
    match only the identical string, so `https://EVIL.com/x` passed a fact for
    `https://evil.com`.
  - **Non-URLs** still compare exactly.
- **Restricted tools** match by leading words, with whitespace collapsed: `rm  -rf /`
  runs `rm -rf`, but `ddrescue` doesn't run `dd`.
- **A NaN `block_threshold`** used to compare false and block nothing. It now blocks
  every network action that rule 7 covers.

### `DatalogGuard` adapts the engine to the Guard port

It is behind `reasoner`. Embedders add it with `KernelBuilder::with_guard`, over the
default rules (`default_rules()`) or an engine with their own facts (`new`).

- **The action** is the tool's name.
- **The targets** are every string argument named `path`, `target`, `file`, `url`,
  `tool` or `command`, each checked as the calling agent. `with_tool` maps a tool to
  another action and a single argument.
- **Verdicts.**
  - **A tool no rule applies to:** abstain.
  - **A violation:** deny, naming the rules.
  - **A warning** (the agent's risk over `warning_threshold`): escalate, which the
    kernel refuses.
  - **No violation: abstain, never pass.** The rules forbid. None firing doesn't
    show the call is right, and a pass would satisfy an `enforced` floor with no
    positive check, as in ADR 0018.
  - **No target to check** (none of the arguments is present, or one isn't a
    string): deny, since a rule can't be evaluated without one.
- **Level: `Enforced`.** The program is deterministic, total over the actions it
  covers, and fails closed when it can't read a target.
- **Construction refuses non-finite thresholds,** since NaN compares false.

## Consequences

- **Off unless added,** so no existing kernel changes.
- **A new dependency.** With `reasoner`, `ascent` adds eleven crates to the build,
  all MIT, Apache-2.0 or Zlib, which `deny.toml` allows.
  - Two are second copies, `hashbrown` 0.15 and `petgraph` 0.8, which cargo-deny
    warns about but doesn't refuse.
  - No MSRV change.
- **Limits, documented.**
  - **Symlinks.** Paths are compared lexically: resolving symlinks needs the
    filesystem, which a pure check must not read.
  - **Schemeless endpoints** (`evil.com`) compare exactly.
  - **Rust checks.** Added rules are Rust checks, not Datalog. A runtime rule
    language would need an interpreter.
- **Stronger checks are now writable.** Rules across a plan's actions, such as
  reading a sensitive file and then calling out, are Datalog joins over
  `proposed`. None ships yet.
- **Floors.** No shipped guard passes, so an `enforced` floor still needs an
  embedder's guard that checks positively. A Datalog `permitted` relation would let
  this one pass; that is future work.
- **Tests.** `tests/datalog_guard.rs` drives `Kernel::execute`:
  - **Denials.** An aliased critical file is refused, and audited as enforced. Every
    target argument is checked. Restricted commands are refused by their leading
    words.
  - **Targets.** A missing or non-string target is refused, and a mapped tool uses
    its mapping.
  - **Network calls.** The negation, the risk aggregate and endpoint aliases each
    refuse one.
  - **Warnings** escalate.
  - **Floors.** Abstaining fails an `enforced` floor, for covered and uncovered
    tools.

  Unit tests cover recursion at depth, rule order, the threshold, rule 8,
  endpoints, commands, skipped defaults and construction.
