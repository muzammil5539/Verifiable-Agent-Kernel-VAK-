# Coverage is measured with cargo-llvm-cov

CI's Code Coverage job ran `cargo tarpaulin`. On Linux, tarpaulin's default engine
traces the test process with ptrace. Under ptrace, a SIGSEGV in the test process stops
the run: tarpaulin reports "A segfault occurred while executing tests" and fails.

Wasmtime raises SIGSEGV on purpose. A guest's out-of-bounds load hits a guard page, and
Wasmtime's signal handler turns the fault into a trap. `tests/sandbox_escapes.rs` drives
exactly those paths through `Kernel::execute` (ADR 0010), so the job failed on every
run. It never got far enough to check the 80% floor.

## Decisions

**cargo-llvm-cov measures coverage.**

- **How it works.** It builds with LLVM's source-based instrumentation and runs the
  tests as ordinary processes. Nothing traces them, so Wasmtime's handler gets its
  signals.
- **Where it runs.** `make coverage` runs the tests and writes HTML and Cobertura
  reports to `coverage/`. `make coverage-check` does the same, then fails under 80% line
  coverage. CI runs `make coverage-check` and uploads the reports even when the floor
  fails.
- **What it measures.** The same scope tarpaulin was configured for: the `vak` crate
  built with `full` (ADR 0006), excluding `tests/`, `benches/` and `examples/`.
- **What it needs.** `cargo install cargo-llvm-cov` and
  `rustup component add llvm-tools-preview`.

**Debug info is off in coverage builds.** Coverage comes from the instrumentation, not
from DWARF. Measured locally, the instrumented build was 13 GB with debug info and
2.1 GB without.

**The floor stays at 80% of lines.**

- **The first measurement.** It is 75.09% (34,402 of 45,813 lines), so the job fails on
  the floor instead of crashing.
- **Why the floor wasn't lowered.** Lowering it to pass would turn the gate into a
  record of what the code happens to do. Raising coverage is in `TODO.md`.
- **What counts.** cargo-llvm-cov counts lines, regions and functions. The floor is on
  lines, as tarpaulin's was. Tarpaulin's `branch = true` is dropped, because branch
  coverage needs a nightly toolchain under cargo-llvm-cov.

`tarpaulin.toml` is deleted.

## Considered options

**Tarpaulin's llvm engine.** It ran `sandbox_escapes` without the segfault. But it took
14 minutes to map the coverage of one test binary (`wasm_skills`), and over 10 minutes
for the next, before the run hit a 50-minute timeout. The suite has 15 test binaries.
cargo-llvm-cov runs and reports all of them in about 11 minutes on the same machine.

**Turning off Wasmtime's signal-based traps** (`Config::signals_based_traps(false)`)
under coverage. Wasmtime would then use explicit bounds checks. The coverage run would
measure a sandbox configured differently from the one that ships, on exactly the tests
that exist to check the shipped one.

**Leaving `sandbox_escapes` out of the coverage run.** The tests would still run in the
Build & Test job, but the coverage job would skip the sandbox's escape paths. A gate
should not need its hardest tests removed to run.

**Going back to tarpaulin.** With the ptrace engine, the job fails again as soon as a
test makes Wasmtime trap.
