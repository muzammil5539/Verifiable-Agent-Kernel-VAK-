# Wasmtime 49, compiled with Cranelift only

The WASM sandbox is the guarantee behind CLAUDE.md's "WASM isolation" invariant: skill
code runs where it can't reach the host. Finding K11 in `docs/architecture-v2.md` is
that the sandbox was Wasmtime 41.0.4, which has 16 RustSec advisories and no patched
41.x release. Several are sandbox escapes. Patched releases are the 36 LTS line, 48.0.4
and later 48.x releases, and 49.0.2 and later.

## Decisions

**Wasmtime 49.0.2.** The release line VAK was already following. It is patched against
all 16 advisories, and `cargo deny check advisories` passes with it.

**Default features off. These are the features compiled in:**

| Feature | Why VAK needs it |
|---|---|
| `cranelift` | The compiler. Skills are compiled to native code on first use. |
| `runtime` | Instantiating and running modules. |
| `std` | Wasmtime on a hosted OS. |
| `pooling-allocator` | `SandboxRuntimeConfig::pooling` (ADR 0004). |
| `wat` | Skills and tests written in the text format. |
| `async` | `sandbox::epoch_config` yields to the executor at epoch deadlines. |
| `parallel-compilation` | Compiles a module's functions on several threads. |

Everything else Wasmtime enables by default stays out:

- **Winch**, the baseline compiler. There is one code path from a skill to machine
  code, and it is Cranelift.
- **The component model.**
- **GC, threads and stack switching.**
- **WASI.** There is no `wasmtime-wasi` crate in the dependency tree. ADR 0004 already
  refuses any skill that imports anything.
- **Tooling:** the compilation cache, profiling, debugging, core dumps and the Pulley
  interpreter.
- **`compile-time-builtins`.** It pulled in `wasm-compose` and with it three
  unmaintained crates (`im-rc`, `bitmaps`, `sized-chunks`) that `cargo deny` reported.

Re-enabling default features would bring all of this back. `winch_is_not_compiled_in`
would then fail.

**Where each advisory stands.** All are fixed in 49.0.2. Ten are also in code VAK no
longer compiles. The tests are in `tests/sandbox_escapes.rs`, and every guest-facing one
runs through `Kernel::execute`.

| Advisories | What they are | Why VAK is not exposed | Test |
|---|---|---|---|
| RUSTSEC-2026-0086, -0089, -0094, -0095 | Winch: a sandbox escape, host data leakage, a `table.grow` result masked wrongly, and a host panic on `table.fill`. | Winch isn't compiled in. The same guest operations on Cranelift fail inside the guest. | `winch_is_not_compiled_in`, `table_operations_fail_inside_the_guest` |
| RUSTSEC-2026-0085, -0091, -0092, -0093, -0316, -0327 | The component model: string transcoding out-of-bounds access and panics, a `flags` lifting panic, a hostcall fuel bypass, and a native stack buffer overflow. | The component model isn't compiled in. A component given as a skill is refused. | `components_are_refused` |
| RUSTSEC-2026-0269 | A WASI filesystem escape. | No WASI. A skill importing `path_open` is refused before it runs. | `a_skill_importing_wasi_is_refused` |
| RUSTSEC-2026-0096 | A Cranelift miscompile of guest heap accesses (aarch64). | Fixed. Accesses at and past the end of memory trap, before and after `memory.grow`, on both allocators. | `guest_memory_accesses_stay_in_bounds` |
| RUSTSEC-2026-0087 | `f64x2.splat` of a load on Cranelift x86-64 could fault or load outside the sandbox. | Fixed. A splat of the last 8 bytes of memory reads exactly them. | `f64x2_splat_reads_only_its_operand` |
| RUSTSEC-2026-0088 | Data leaking between pooling-allocator instances. | Fixed. With one instance slot, each run reuses memory the last run wrote a secret into, including grown pages, and reads zeros. | `pooled_instances_never_see_each_others_memory` |
| RUSTSEC-2026-0114 | A host panic allocating a table larger than the address space. | Fixed, and tables are now capped (below). | `table_operations_fail_inside_the_guest` |
| RUSTSEC-2026-0222 | Stores mixing up type indices between engines. | Fixed. VAK never mixes engines: a runtime's stores, linker and modules come from its one engine. Two runtimes running the same skill keep indirect-call type checks apart. | `two_engines_keep_their_types_apart` |

The aarch64 and x86-64 fixes are tested on whichever architecture runs the tests. CI
runs x86-64.

**Tables are capped at `sandbox::MAX_TABLE_ELEMENTS` (10,000 elements).**

- **Why.** The store limiter bounded linear memory only. A table lives in host memory,
  outside that bound.
- **What the uncapped test showed.** Without the cap, `table.grow` toward 2^32 elements
  made the host try to allocate 34,359,738,360 bytes. Wasmtime 49 failed that
  allocation cleanly. On a host that overcommits, a smaller grow could be granted, and
  would then be filled.
- **Where it applies.** At instantiation and on every `table.grow`, with either
  allocator. 10,000 is the pooling allocator's default, so the limit is the same
  whichever allocator runs a skill. The shipped skills declare tables of 27 to 36
  elements.

**The pooling allocator's limits now limit instances.**

- **Before.** `create_pooling_engine` set `total_component_instances` and
  `max_{memories,tables}_per_component`. Those apply to component instances, which VAK
  never creates. So `PoolingConfig::max_instances`, `max_memories` and `max_tables` had
  no effect, and core instances used Wasmtime's defaults.
- **Now.** They set the core-module knobs: `total_core_instances` and
  `max_{memories,tables}_per_module`.

**Trap reasons are reported.**

- **The problem.** A Wasmtime error's `Display` is its outermost context, the guest
  backtrace. A trapped skill's error, and its outcome leaf in the audit log, said where
  the guest stopped but not why.
- **The change.** The sandbox now renders a trap by its code, for example
  `wasm trap: out of bounds memory access`. Fuel and deadline traps are still mapped to
  `FuelExhausted` and `Timeout`.

**MSRV 1.96.**

- Wasmtime 49 declares `rust-version = "1.96"`, so the workspace does too.
- CI's minimum-version job runs 1.96.
- The Dockerfile moved from Rust 1.75, which hasn't built VAK since the MSRV went to 1.90.
- Anyone building VAK or its Python wheel needs Rust 1.96 or later.

## Consequences

**Fuel now bounds bulk operations.**

- **The change.** Wasmtime 49 charges a unit of fuel per byte for `memory.fill`,
  `memory.copy` and `memory.init`, and per element for table and array bulk operations.
  Before, a bulk operation cost a few units whatever its length.
- **Effect on the kernel's budget.** The fixed budget of 10 million units now covers
  about 10 MB of bulk copying, where before it allowed seconds of it.
- **Shipped skills.** All five run unchanged.
- **Tests.** A skill that spins on `memory.fill` now runs out of fuel in milliseconds.
  So `tests/wasm_skills.rs` spins on a chain of square roots, and checks two things
  separately:
  - Fuel stops the skill without stalling other requests.
  - A one-millisecond deadline stops it before the fuel runs out.

**Breaking.**

- Rust 1.96 is required.
- Wasmtime types are part of the public API, for example `SandboxRuntime::engine` and
  the host-function linkers. Embedders that use them need Wasmtime 49 as well.
- Wasmtime 49 has its own error type. The host functions in `sandbox::host_funcs` and
  `sandbox::reasoning_host` now return `wasmtime::Result`.
- `PoolingConfig::max_instances` now limits core instances. A config that set it below
  the concurrency it actually ran at is now enforced.
- A skill whose table needs more than 10,000 elements fails to instantiate.

## Considered options

**The Wasmtime 36 LTS line.** It is patched and has a lower minimum Rust version. But it
is five major versions back from what the sandbox was written against, and an LTS line
takes security fixes only until its support ends. Following the current line gets fixes
first. Its MSRV moves faster, and we accept that.

**Keeping default features.** Ten of the sixteen advisories are in Winch, the component
model or WASI. VAK uses none of them, so compiling them in is attack surface with
nothing to show for it. When the Component Model work (Phase 3) needs components, it
turns on `component-model` alone, under a new ADR.

**Testing the advisories' exploits directly.** The advisories publish no exploits, and
several need Winch or a component to trigger. The tests check the property each one
breaks, through the kernel, so they still catch a regression that reaches the
property some other way.
