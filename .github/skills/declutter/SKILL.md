---
name: declutter
description: Remove banner comments, emoji, dead code and unsupported claims from code and Markdown, and check the result still builds.
---

# Declutter

Use this when a codebase or its docs have picked up decoration and claims nobody checked. It was first run on this repo in commits `65199ca` and `eebbcfb`.

## 1. Scan

```bash
python3 .github/skills/declutter/declutter.py scan
```

It lists emoji, `allow(dead_code)` markers and phrases such as "production ready" or "100% complete", and counts `// ====` banner lines.

## 2. Mechanical fixes

```bash
python3 .github/skills/declutter/declutter.py banners --fix   # keeps section titles
python3 .github/skills/declutter/declutter.py emoji --fix
cargo fmt --all
```

Read the emoji diff before committing. Replace a marker that carried meaning (a severity colour, a pass/fail icon) with a word, such as `[HIGH]` or `OK:`, and leave quoted text alone, for example a doc that quotes the claim it refutes.

## 3. Dead code

Delete every `#[allow(dead_code)]` and run `cargo check --all-targets --features full`. Each warning is either dead code to delete or a field a public API needs. Fields in test fixtures that mirror a data model can keep the allow, with a reason in a comment. Unused helper functions and examples go. If a parameter exists only to feed a deleted field, remove the parameter and its call sites. Serde response structs can drop fields they never read.

## 4. Claims in prose

Check status claims against the code, not against other docs. For this repo the source of truth is `docs/architecture-v2.md`. A status table that says "Complete 100%" for a module the audit lists as unsound is wrong, and rewriting it matters more than rewording it. Also check that links point at files that exist, and that code samples in a README compile (paste into a temporary `examples/` file, run it, delete it).

Leave ADRs, the changelog and any live spec alone: they are records.

## 5. Wording

Run the slop checker from the `slopmonster` skill on changed Markdown. Fix real findings, such as hype words, "not just X but Y", em-dash stacks and invented numbers. Accept the rest when they are legitimate technical lists or table semicolons, and say so.

## 6. Verify and commit

```bash
cargo clippy --all-targets --features full -- -D warnings
cargo test --features full
cargo test --no-default-features
```

Commit code and docs separately. A change that only deletes comments and dead code should show zero behaviour change in the tests.
