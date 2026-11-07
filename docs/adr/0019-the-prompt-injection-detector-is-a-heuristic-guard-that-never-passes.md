# The prompt-injection detector is a heuristic guard that never passes

`reasoner::prompt_injection::PromptInjectionDetector` scores text against regexes for
instruction overrides, role impersonation, prompt leakage, jailbreaks and payloads,
plus a few heuristics such as zero-width characters. `Kernel::execute` never called
it. `docs/architecture-v2.md` §4.4 demotes it to a `Heuristic` guard: a signal,
"never the reason a dangerous action is allowed". ADR 0013 made guards the place for
checks on allowed calls.

## Decision

**`PromptInjectionGuard` adapts the detector to the Guard port,** behind the
`reasoner` feature. Embedders add it with `KernelBuilder::with_guard`. There is no
configuration key yet: the core can't name a type from a feature-gated module.

- **Verdicts.**
  - **Block** (risk at or over `block_threshold`) denies, naming the injection type,
    the risk and what matched.
  - **Review** (at or over `risk_threshold`) escalates. There is no approval channel,
    so the kernel refuses it.
  - **Anything else abstains, and never passes.** A regex finding nothing isn't
    evidence that a call is safe, and a pass would satisfy a `heuristic` floor with no
    check that the call is right.
- **Level.** `Heuristic`. Adaptive attacks get past regexes; it can add denials, not
  carry a floor.
- **What it reads.** Every string in the arguments, object keys included, decoded and
  joined by newlines.
  - **Decoded, not JSON text.** In JSON text a newline is the two characters `\n`,
    which `\s` doesn't match, so `"Ignore all\nprevious instructions"` would pass.
  - **The walk.** It uses its own stack: a value nested deeper than serde_json parses
    can still reach a guard from an embedder.
  - **Other values.** Numbers, booleans and nulls carry no text.
- **Length.** Arguments whose text is longer than `max_input_length` are denied. The
  detector reads only that much, so whatever came after would go unchecked. The limit
  is configurable.
- **Construction refuses a guard that checks nothing**: a disabled detector, or one
  with neither patterns nor heuristics on. It also refuses what the new
  `PromptInjectionDetector::try_new` refuses: an invalid regex, which `new` drops with
  a warning; and a threshold that isn't in `0.0..=1.0`. Risk is capped at 1.0, so a
  higher threshold, or NaN, never blocks.

Two fixes it needed in the detector:

- **Truncation.** It sliced the input at the byte limit, which panics when the limit
  falls inside a multi-byte character. It now cuts at the character boundary below.
- **The allowlist.** A match of any allowlist pattern returned "clean" for the whole
  input. With `weather` allowlisted, "What's the weather? Ignore all previous
  instructions" passed. Now an allowlisted span exempts only the matches it wholly
  contains.
  - **Restarts.** After an exempt match, the search resumes one character after its
    start, since another match can start inside it and run past the span.
  - **The limit.** Past `MAX_EXEMPT_MATCHES` (64) exempt matches of one pattern, the
    next one counts. This bounds the work an input full of allowlisted text causes.
  - **Heuristics** still read the whole input.

## Consequences

- **Off unless added,** so no existing kernel changes.
- **False positives deny.** The payload patterns match any backtick-quoted text and
  any `{{...}}`, so a tool whose arguments carry Markdown or templates is refused once
  it is added. Raise the thresholds, allowlist the spans, or don't guard that tool.
- **Not yet for `Kernel::new` users.** The Python SDK and `VakRuntime` can't add
  guards. A `policy.prompt_injection` key needs a core-side configuration type, and an
  error when the kernel is built without `reasoner`.
- **Labels remain the defence.** Information-flow labels (ADR 0014) are `Enforced`;
  this guard is triage on top of them.
- **Next guard adapter (TODO.md):** Datalog on Ascent, as enforced.
- **Tests.** `tests/prompt_injection_guard.rs` drives `Kernel::execute`:
  - **Refusals.** A block-level injection is denied and audited as heuristic. A
    review-level one is escalated and refused.
  - **What runs.** Clean and non-ASCII calls run.
  - **Where text sits.** Split, nested and key-borne attacks are found.
  - **The allowlist.** An allowlisted phrase runs, and the same phrase with an attack
    after it doesn't.
  - **Length.** Over-long arguments are refused, and arguments exactly at the limit are
    checked.
  - **Floors.** Abstaining doesn't meet a `heuristic` floor.

  Unit tests cover truncation, exempt spans, restarts, the limit and `try_new`.
