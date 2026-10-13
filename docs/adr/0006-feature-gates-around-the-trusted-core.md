# Feature gates around the trusted core

The reference-monitor argument in `docs/architecture-v2.md` §1 needs a trusted core
small enough to review. Until now that boundary was only a convention: one crate
compiled about 80k lines, including research modules the design classifies as
Heuristic or Experimental (the reasoner, the ZK prototypes, swarm consensus). An
embedder that wanted the kernel got all of it, and Wasmtime with it.

We made everything outside the core a Cargo feature. `default-features = false` builds
the core alone: `kernel` (minus WASM skills and the neuro-symbolic pipeline), `policy`,
`audit`, `secrets` and `lib_integration`.

## Decisions

**The core is fixed, not a feature.** It always builds, and it may not import a
feature-gated module. Where core code used one, the using code moved behind the gate
instead. The kernel's WASM path (registry, runtime, pinned execution) moved from
`kernel/mod.rs` into `kernel/skills.rs` behind `wasm`. Without it, a name that isn't a
built-in or a registered handler is `ToolNotFound`, which is what a missing skill already
was.

**Features follow the import graph.** Each feature implies the features its modules
import:

| Feature | Default | Implies | Why that default |
|---|---|---|---|
| `wasm` | on | | Skills are the main way to add untrusted tools |
| `memory` | on | `llm` | Existing users of `vak::memory` |
| `llm` | via `memory` | | |
| `reasoner` | off | `llm` | Heuristic; outside the trusted core |
| `experimental-zk` | off | `reasoner` | Not a sound proof system (V1) |
| `swarm` | off | | Unauthenticated votes (S1) |
| `integrations` | off | `reasoner`, `wasm` | All three adapters embed the reasoner; MCP carries I3 |
| `dashboard` | off | `swarm` | `dashboard` and `api` import each other and `swarm::a2a` |
| `legacy-tools` | off | | `tools::skill_sign` signs without permissions in a format the registry can't read |
| `python` | off | | PyO3; built by maturin |
| `full` | off | everything but `python` | What CI tests |

**Dependencies follow the features.** `wasmtime`, `petgraph`, `tokio-stream` and
`base64` are optional. `rs_merkle`, which nothing used, is removed. The core depends on
210 packages instead of 301, with no Wasmtime.

**Tests stay where they were, gated where they need a feature.** Test files and modules
that need a feature carry `cfg` attributes; benches keep one fixed `criterion_group!`
list, and gated bench functions do nothing when their feature is off. CI tests with
`--features full`, so no test stops running, and adds a job that builds and tests with
`--no-default-features`, so the core can't silently grow a dependency on a gated module.

## Considered options

**Splitting the workspace now** (`vak-core`, `vak-reasoner` and so on). That enforces
the boundary through the compiler rather than through `cfg`, and it is Phase 3. Features
first let the boundary be tested and adjusted without moving 80k lines between crates.

**Keeping `integrations` on by default**, as §5.3 originally planned. Its adapters
use the reasoner throughout. Gating each use separately would have left a default build
with integrations that silently skip their safety checks. Turning the whole module off
by default is the honest version.

**Removing `tools::skill_sign`** outright. Nothing in the crate uses it, and its output
doesn't load. It is gated rather than deleted so this change stays reversible. Its
removal can be a separate decision.

## Consequences

- **Breaking:** `vak::reasoner`, `vak::swarm`, `vak::integrations`, `vak::dashboard`,
  `vak::api` and `vak::tools` need their features (or `full`).
  `vak::reasoner::zk_proof` needs `experimental-zk`.
- `cargo test` with default features no longer runs the gated modules' tests. Use
  `cargo test --features full` (or `make test`). `make test-core` runs the core alone.
- Coverage measures with `full` (`make coverage`; ADR 0012), so the 80% gate covers the
  same code as before.
- `cargo clippy --all-targets --features full -- -D warnings` reports the same 24 lints
  as before this change, all in modules it didn't touch.
