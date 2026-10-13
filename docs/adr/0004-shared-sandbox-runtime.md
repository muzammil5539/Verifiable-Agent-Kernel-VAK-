# One sandbox runtime per kernel, skills off the async executor

Every WASM skill call used to build a new `wasmtime::Engine`, recompile the module from
disk, and start a watchdog thread. It then ran synchronously inside the kernel's
`async fn execute` (finding K3 in `docs/architecture-v2.md`). Compiling dominates the
cost of a short skill. A skill that ran for its full time limit also held a Tokio
worker for that whole time; on a single-threaded runtime, nothing else could run.

We introduced `sandbox::SandboxRuntime`: one engine, a cache of compiled modules, and
one epoch ticker. The kernel runs every skill call on it, on
`tokio::task::spawn_blocking`.

## Decisions

**One runtime per kernel, injectable; not a process-wide global.** A global would hide
its configuration (tick, cache size, pooling) from the embedder, and would make tests
share state. `KernelBuilder::with_sandbox_runtime` lets several kernels share one
runtime, which gives the same sharing explicitly. Without one, the kernel builds its
own on the first skill call, so a kernel that never runs a skill never pays for an
engine or a thread.

**Cache by the module's SHA-256, not its path.** A file replaced on disk is recompiled.
The same bytes behind two paths, or two kernels, compile once. The digest is also what
slice 1c will sign, so the module that was verified is the module that runs. The cache
holds `InstancePre`, so import resolution happens once too. It is bounded
(`max_cached_modules`, default 64) and evicts the oldest entry.

**One ticker thread that parks while idle.** Wall-clock deadlines need something to
advance the engine's epoch. A thread per call, as before, costs a spawn and a join per
call. The existing `EpochTicker` is a Tokio task, which would tie the deadline to the
health of the executor it's meant to protect from. The runtime's thread waits on a
condition variable while no execution is in flight, ticks every 10 ms while any is, and
is joined when the runtime drops. Deadlines stay per store and wall-clock: each store's
epoch callback compares against its own deadline, so one execution's ticks can't cut
another short.

**Pooling is opt-in.** The pooling allocator reserves
`max_instances × max_memory_per_instance` of virtual address space up front, 51 GB
with the default `PoolingConfig`, and some container limits refuse that. On-demand
allocation is the default, and `SandboxRuntimeConfig::pooling` turns pooling on. The
runtime forces fuel metering and epoch interruption on, whatever the pooling config
says.

**Skills get no imports.** `prepare` refuses a module that imports anything, as
`Linker::new` + `instantiate` already did implicitly. Host capabilities arrive with
the Component Model work, each one re-entering the kernel's policy decision point.

## Considered options

**`spawn_blocking` versus Wasmtime's async support.** Async stores (`call_async`,
fuel or epoch yielding) let a skill yield to the executor instead of occupying a
thread. They also need an async-enabled engine, `Send` host state, and different call
paths throughout. `spawn_blocking` gets the property that matters now, that the
executor never blocks, with no change to the skill ABI. The cost is one blocking-pool
thread per concurrently running skill; bounding that is the `async_pipeline`
backpressure work.

**Caching `Module` versus `InstancePre`.** `InstancePre` also caches import resolution,
and costs nothing extra while skills have no imports. When host imports arrive, the
linker becomes part of the cache key.

## Consequences

- A WASM skill's time limit is now reported as `KernelError::Timeout`, like a host
  handler's, and its output pointer and length are bounds-checked as unsigned values
  against guest memory. A negative length used to be cast to a `usize` above
  `isize::MAX`, so allocating the output buffer panicked in the host, and the panic
  unwound through `Kernel::execute`.
- A panic while running a skill fails that call ("skill execution panicked"). It no
  longer unwinds into the kernel.
- `WasmSandbox::new` still builds a runtime of its own, so existing callers behave as
  before. `WasmSandbox::with_runtime` shares one.
- Skill signatures are still unkeyed hashes (K4). That is slice 1c; the cache's digest
  is the hook it will use.
