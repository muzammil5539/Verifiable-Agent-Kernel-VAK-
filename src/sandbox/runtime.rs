//! The shared WASM runtime: one engine, a compiled-module cache, and one
//! epoch ticker, for every skill a kernel runs.
//!
//! Before this module, every skill call built a new `wasmtime::Engine`,
//! recompiled the module from disk, and started a watchdog thread, and the
//! call then ran synchronously inside the kernel's `async fn`, blocking a
//! Tokio worker for the skill's whole runtime (K3 in
//! `docs/architecture-v2.md`). Wasmtime's own guidance for servers is the
//! shape here: one shared [`Engine`], modules compiled once and cached (as
//! [`InstancePre`], so imports are resolved once too), and one thread
//! advancing the engine's epoch. The kernel runs each call on
//! `tokio::task::spawn_blocking`. See `docs/adr/0004`.
//!
//! # Time limits
//!
//! Each execution gets a wall-clock deadline, checked in the store's epoch
//! callback. Epochs are engine-wide, so a deadline counted in ticks would let
//! one execution's ticks cut another short; comparing against the clock
//! doesn't. The ticker only runs while at least one execution is in flight,
//! so an idle runtime costs one parked thread.
//!
//! # Host safety
//!
//! A skill's output pointer and length are untrusted. They are read as
//! unsigned, checked against the guest memory's size, and only then copied,
//! so a skill can't make the host allocate an arbitrary amount of memory or
//! overflow pointer arithmetic.

use std::collections::{HashMap, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use wasmtime::{Config, Engine, InstancePre, Linker, Module, Store, UpdateDeadline};

use super::pooling::{create_pooling_engine, PoolingConfig};
use super::{SandboxConfig, SandboxError, SandboxState};

/// How a [`SandboxRuntime`] is built.
#[derive(Debug, Clone)]
pub struct SandboxRuntimeConfig {
    /// How often the engine's epoch advances while a skill runs. This is the
    /// precision of the wall-clock deadline. Default 10 ms.
    pub tick: Duration,
    /// Compiled modules kept in the cache. The oldest is evicted beyond
    /// this. Default 64.
    pub max_cached_modules: usize,
    /// Use Wasmtime's pooling allocator with these limits. `None` (the
    /// default) allocates instance memory on demand. Pooling reserves
    /// `max_instances × max_memory_per_instance` of virtual address space
    /// up front, which some containers refuse, so it is opt-in.
    pub pooling: Option<PoolingConfig>,
}

impl Default for SandboxRuntimeConfig {
    fn default() -> Self {
        Self {
            tick: Duration::from_millis(10),
            max_cached_modules: 64,
            pooling: None,
        }
    }
}

/// Counters describing what a runtime has done.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SandboxRuntimeStats {
    /// Modules compiled (cache misses).
    pub compiled_modules: u64,
    /// Requests served from the module cache.
    pub cache_hits: u64,
    /// Modules currently cached.
    pub cached_modules: usize,
    /// Executions started.
    pub executions: u64,
    /// Executions currently running.
    pub active_executions: usize,
}

/// A compiled skill, ready to instantiate. Cheap to clone.
#[derive(Clone)]
pub struct PreparedSkill {
    digest: [u8; 32],
    pre: InstancePre<SandboxState>,
}

impl PreparedSkill {
    /// Hex SHA-256 of the module bytes this skill was compiled from.
    #[must_use]
    pub fn digest_hex(&self) -> String {
        hex::encode(self.digest)
    }
}

impl std::fmt::Debug for PreparedSkill {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedSkill")
            .field("digest", &self.digest_hex())
            .finish_non_exhaustive()
    }
}

/// One engine, one module cache and one epoch ticker, shared by every skill
/// execution that goes through it. `Send + Sync`; share it as
/// `Arc<SandboxRuntime>`.
pub struct SandboxRuntime {
    engine: Engine,
    linker: Linker<SandboxState>,
    cache: Mutex<ModuleCache>,
    pump: EpochPump,
    compiled: AtomicU64,
    hits: AtomicU64,
    executions: AtomicU64,
}

impl std::fmt::Debug for SandboxRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxRuntime")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl SandboxRuntime {
    /// Builds the engine and starts the (parked) epoch ticker.
    ///
    /// # Errors
    ///
    /// [`SandboxError::EngineCreation`] if the engine can't be built or the
    /// ticker thread can't be started. Without the ticker no deadline would
    /// ever be checked, so the runtime refuses to exist rather than run
    /// skills without a time limit.
    pub fn new(config: SandboxRuntimeConfig) -> Result<Self, SandboxError> {
        let engine = match &config.pooling {
            Some(pooling) => {
                // The sandbox's limits depend on both; never let a pooling
                // config switch them off.
                let mut pooling = pooling.clone();
                pooling.epoch_interruption = true;
                pooling.consume_fuel = true;
                create_pooling_engine(&pooling)
                    .map_err(|e| SandboxError::EngineCreation(e.to_string()))?
            }
            None => {
                let mut wasm_config = Config::new();
                wasm_config.consume_fuel(true);
                wasm_config.epoch_interruption(true);
                Engine::new(&wasm_config)
                    .map_err(|e| SandboxError::EngineCreation(e.to_string()))?
            }
        };
        let pump = EpochPump::start(engine.clone(), config.tick.max(Duration::from_millis(1)))?;

        Ok(Self {
            linker: Linker::new(&engine),
            engine,
            cache: Mutex::new(ModuleCache::new(config.max_cached_modules.max(1))),
            pump,
            compiled: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            executions: AtomicU64::new(0),
        })
    }

    /// The shared engine.
    #[must_use]
    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// What this runtime has done so far.
    #[must_use]
    pub fn stats(&self) -> SandboxRuntimeStats {
        SandboxRuntimeStats {
            compiled_modules: self.compiled.load(Ordering::Relaxed),
            cache_hits: self.hits.load(Ordering::Relaxed),
            cached_modules: self.cache().len(),
            executions: self.executions.load(Ordering::Relaxed),
            active_executions: self.pump.active(),
        }
    }

    /// Compiles `wasm` (binary or text format), or returns the cached
    /// compilation of identical bytes.
    ///
    /// # Errors
    ///
    /// [`SandboxError::ModuleLoad`] if the bytes aren't a valid module, and
    /// [`SandboxError::Instantiation`] if it imports anything: skills get no
    /// host imports until the Component Model work grants them explicitly.
    pub fn prepare(&self, wasm: &[u8]) -> Result<PreparedSkill, SandboxError> {
        let digest: [u8; 32] = Sha256::digest(wasm).into();
        if let Some(pre) = self.cache().get(&digest) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(PreparedSkill { digest, pre });
        }

        // Compile outside the lock: it can take a while, and two threads
        // racing to compile the same bytes is merely wasted work.
        let module =
            Module::new(&self.engine, wasm).map_err(|e| SandboxError::ModuleLoad(e.to_string()))?;
        let pre = self
            .linker
            .instantiate_pre(&module)
            .map_err(|e| SandboxError::Instantiation(e.to_string()))?;
        self.compiled.fetch_add(1, Ordering::Relaxed);
        self.cache().insert(digest, pre.clone());
        Ok(PreparedSkill { digest, pre })
    }

    /// Reads and prepares the module at `path`. The cache is keyed by the
    /// file's contents, so a file replaced on disk is recompiled.
    ///
    /// # Errors
    ///
    /// As [`SandboxRuntime::prepare`], plus [`SandboxError::ModuleLoad`] if
    /// the file can't be read.
    pub fn prepare_file(&self, path: &Path) -> Result<PreparedSkill, SandboxError> {
        let bytes = std::fs::read(path)
            .map_err(|e| SandboxError::ModuleLoad(format!("{}: {e}", path.display())))?;
        self.prepare(&bytes)
    }

    /// Runs `func` with the skill ABI: the input JSON is copied into guest
    /// memory through the guest's `alloc(len) -> ptr`, then
    /// `func(ptr, len) -> out` is called, and the output is a little-endian
    /// `u32` length at `out` followed by that many bytes of JSON.
    ///
    /// Blocks until the call finishes, traps, runs out of fuel or passes
    /// `limits.timeout`. Call it from `spawn_blocking`, not from async code.
    ///
    /// # Errors
    ///
    /// [`SandboxError::Timeout`], [`SandboxError::FuelExhausted`], or
    /// another [`SandboxError`] describing what went wrong.
    pub fn execute_json(
        &self,
        skill: &PreparedSkill,
        limits: &SandboxConfig,
        func: &str,
        input: &serde_json::Value,
    ) -> Result<serde_json::Value, SandboxError> {
        let (mut store, _running) = self.store(limits)?;
        let instance = skill
            .pre
            .instantiate(&mut store)
            .map_err(|e| classify(e, limits, |e| SandboxError::Instantiation(e.to_string())))?;

        let input_json =
            serde_json::to_string(input).map_err(|e| SandboxError::InvalidInput(e.to_string()))?;
        let input_bytes = input_json.as_bytes();
        let input_len = i32::try_from(input_bytes.len())
            .map_err(|_| SandboxError::InvalidInput("input larger than 2 GiB".into()))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| SandboxError::Instantiation("Module has no exported memory".into()))?;
        let alloc_fn = instance
            .get_typed_func::<i32, i32>(&mut store, "alloc")
            .map_err(|_| SandboxError::FunctionNotFound("alloc".into()))?;
        let target_fn = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, func)
            .map_err(|_| SandboxError::FunctionNotFound(func.into()))?;

        let input_ptr = alloc_fn
            .call(&mut store, input_len)
            .map_err(|e| classify(e, limits, |_| SandboxError::GuestAllocation))?;
        memory
            .write(&mut store, guest_offset(input_ptr), input_bytes)
            .map_err(|_| SandboxError::MemoryLimitExceeded)?;

        let output_ptr = target_fn
            .call(&mut store, (input_ptr, input_len))
            .map_err(|e| classify(e, limits, |e| SandboxError::Execution(e.to_string())))?;

        // Everything below is read from untrusted guest memory: bound-check
        // before allocating or slicing.
        let data = memory.data(&store);
        let start = guest_offset(output_ptr);
        let len_end = start
            .checked_add(4)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| SandboxError::InvalidOutput("output pointer out of bounds".into()))?;
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&data[start..len_end]);
        let output_len = u32::from_le_bytes(len_bytes) as usize;
        let end = len_end
            .checked_add(output_len)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                SandboxError::InvalidOutput(format!(
                    "output length {output_len} runs past guest memory"
                ))
            })?;

        let output = std::str::from_utf8(&data[len_end..end])
            .map_err(|e| SandboxError::InvalidOutput(e.to_string()))?;
        serde_json::from_str(output).map_err(|e| SandboxError::InvalidOutput(e.to_string()))
    }

    /// Runs a function that takes nothing and returns an `i32`.
    ///
    /// # Errors
    ///
    /// As [`SandboxRuntime::execute_json`].
    pub fn execute_i32(
        &self,
        skill: &PreparedSkill,
        limits: &SandboxConfig,
        func: &str,
    ) -> Result<i32, SandboxError> {
        let (mut store, _running) = self.store(limits)?;
        let instance = skill
            .pre
            .instantiate(&mut store)
            .map_err(|e| classify(e, limits, |e| SandboxError::Instantiation(e.to_string())))?;
        let target_fn = instance
            .get_typed_func::<(), i32>(&mut store, func)
            .map_err(|_| SandboxError::FunctionNotFound(func.into()))?;
        target_fn
            .call(&mut store, ())
            .map_err(|e| classify(e, limits, |e| SandboxError::Execution(e.to_string())))
    }

    /// A store with `limits` applied and its deadline armed, plus a guard
    /// that keeps the ticker running until the execution ends.
    fn store(
        &self,
        limits: &SandboxConfig,
    ) -> Result<(Store<SandboxState>, Running<'_>), SandboxError> {
        let mut store = Store::new(&self.engine, SandboxState::new(limits));
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(limits.fuel_limit)
            .map_err(|e| SandboxError::EngineCreation(format!("Failed to set fuel: {e}")))?;

        // The deadline covers instantiation too (start functions run there).
        let deadline = Instant::now() + limits.timeout;
        store.set_epoch_deadline(1);
        store.epoch_deadline_callback(move |_| {
            if Instant::now() >= deadline {
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });

        self.executions.fetch_add(1, Ordering::Relaxed);
        Ok((store, self.pump.begin()))
    }

    fn cache(&self) -> MutexGuard<'_, ModuleCache> {
        // A panic while holding this lock can only come from a bug in the
        // cache's own few lines; its contents are still consistent.
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Maps a Wasmtime error to a sandbox error by its trap code, so a deadline
/// or fuel trap is reported as such whatever the timing.
fn classify(
    error: wasmtime::Error,
    limits: &SandboxConfig,
    otherwise: impl FnOnce(wasmtime::Error) -> SandboxError,
) -> SandboxError {
    match error.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::Interrupt) => SandboxError::Timeout(limits.timeout),
        Some(wasmtime::Trap::OutOfFuel) => SandboxError::FuelExhausted,
        _ => otherwise(error),
    }
}

/// A wasm32 pointer as an offset into linear memory. Guest pointers are
/// unsigned; reading them as `i32` and casting would sign-extend.
fn guest_offset(ptr: i32) -> usize {
    u32::from_le_bytes(ptr.to_le_bytes()) as usize
}

/// Compiled modules by content digest, evicting the oldest beyond capacity.
struct ModuleCache {
    entries: HashMap<[u8; 32], InstancePre<SandboxState>>,
    order: VecDeque<[u8; 32]>,
    capacity: usize,
}

impl ModuleCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn len(&self) -> usize {
        self.entries.len()
    }

    fn get(&self, digest: &[u8; 32]) -> Option<InstancePre<SandboxState>> {
        self.entries.get(digest).cloned()
    }

    fn insert(&mut self, digest: [u8; 32], pre: InstancePre<SandboxState>) {
        if self.entries.insert(digest, pre).is_some() {
            return; // another thread compiled the same bytes first
        }
        self.order.push_back(digest);
        while self.entries.len() > self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.entries.remove(&oldest);
                }
                None => break,
            }
        }
    }
}

/// One thread that advances the engine's epoch every `tick`, but only while
/// an execution is running. Stopped and joined on drop.
struct EpochPump {
    shared: Arc<PumpShared>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct PumpShared {
    state: Mutex<PumpState>,
    wake: Condvar,
}

#[derive(Default)]
struct PumpState {
    active: usize,
    stopping: bool,
}

impl PumpShared {
    fn lock(&self) -> MutexGuard<'_, PumpState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl EpochPump {
    fn start(engine: Engine, tick: Duration) -> Result<Self, SandboxError> {
        let shared = Arc::new(PumpShared {
            state: Mutex::new(PumpState::default()),
            wake: Condvar::new(),
        });
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("vak-wasm-epoch".into())
            .spawn(move || Self::run(&engine, &thread_shared, tick))
            .map_err(|e| {
                SandboxError::EngineCreation(format!("failed to start epoch ticker: {e}"))
            })?;
        Ok(Self {
            shared,
            thread: Some(thread),
        })
    }

    fn run(engine: &Engine, shared: &PumpShared, tick: Duration) {
        let mut state = shared.lock();
        loop {
            // Park until something runs.
            state = shared
                .wake
                .wait_while(state, |s| s.active == 0 && !s.stopping)
                .unwrap_or_else(PoisonError::into_inner);
            if state.stopping {
                return;
            }
            // Sleep one tick, waking early only to stop.
            let (next, _) = shared
                .wake
                .wait_timeout_while(state, tick, |s| !s.stopping)
                .unwrap_or_else(PoisonError::into_inner);
            state = next;
            if state.stopping {
                return;
            }
            engine.increment_epoch();
        }
    }

    fn begin(&self) -> Running<'_> {
        let mut state = self.shared.lock();
        state.active += 1;
        if state.active == 1 {
            self.shared.wake.notify_all();
        }
        Running {
            shared: &self.shared,
        }
    }

    fn active(&self) -> usize {
        self.shared.lock().active
    }
}

impl Drop for EpochPump {
    fn drop(&mut self) {
        self.shared.lock().stopping = true;
        self.shared.wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Keeps the epoch ticker running for one execution.
struct Running<'a> {
    shared: &'a PumpShared,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let mut state = self.shared.lock();
        state.active = state.active.saturating_sub(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The skill ABI: `execute` echoes its input; `spin` never returns;
    /// `bad_len` returns an output whose length runs past memory;
    /// `bad_ptr` returns a pointer past the end of memory.
    const SKILL_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $next (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $next))
            (global.set $next (i32.add (global.get $next) (local.get $len)))
            (local.get $p))
          (func (export "execute") (param $ptr i32) (param $len i32) (result i32)
            (i32.store (i32.const 0) (local.get $len))
            (memory.copy (i32.const 4) (local.get $ptr) (local.get $len))
            (i32.const 0))
          (func (export "bad_len") (param $ptr i32) (param $len i32) (result i32)
            (i32.store (i32.const 0) (i32.const -1))
            (i32.const 0))
          (func (export "bad_ptr") (param $ptr i32) (param $len i32) (result i32)
            (i32.const -2))
          (func (export "answer") (result i32)
            (i32.const 42))
          (func (export "spin") (result i32)
            (loop $l (br $l))
            (i32.const 0)))
    "#;

    fn runtime() -> SandboxRuntime {
        SandboxRuntime::new(SandboxRuntimeConfig::default()).unwrap()
    }

    #[test]
    fn test_modules_are_compiled_once_per_content() {
        let runtime = runtime();
        let first = runtime.prepare(SKILL_WAT.as_bytes()).unwrap();
        let second = runtime.prepare(SKILL_WAT.as_bytes()).unwrap();
        assert_eq!(first.digest_hex(), second.digest_hex());
        let stats = runtime.stats();
        assert_eq!((stats.compiled_modules, stats.cache_hits), (1, 1));

        // Different bytes are a different module.
        runtime
            .prepare(b"(module (func (export \"answer\") (result i32) (i32.const 7)))")
            .unwrap();
        assert_eq!(runtime.stats().compiled_modules, 2);
        assert_eq!(runtime.stats().cached_modules, 2);
    }

    #[test]
    fn test_cache_evicts_oldest_beyond_capacity() {
        let runtime = SandboxRuntime::new(SandboxRuntimeConfig {
            max_cached_modules: 2,
            ..SandboxRuntimeConfig::default()
        })
        .unwrap();
        for n in 0..3 {
            let wat = format!("(module (func (export \"answer\") (result i32) (i32.const {n})))");
            runtime.prepare(wat.as_bytes()).unwrap();
        }
        assert_eq!(runtime.stats().cached_modules, 2);
        // The first was evicted, so preparing it again compiles.
        runtime
            .prepare(b"(module (func (export \"answer\") (result i32) (i32.const 0)))")
            .unwrap();
        assert_eq!(runtime.stats().compiled_modules, 4);
    }

    #[test]
    fn test_modules_with_imports_are_refused() {
        let result = runtime().prepare(b"(module (import \"env\" \"f\" (func)))");
        assert!(matches!(result, Err(SandboxError::Instantiation(_))));
    }

    #[test]
    fn test_execute_json_round_trip() {
        let runtime = runtime();
        let skill = runtime.prepare(SKILL_WAT.as_bytes()).unwrap();
        let input = serde_json::json!({"operands": [1, 2, 3]});
        let output = runtime
            .execute_json(&skill, &SandboxConfig::default(), "execute", &input)
            .unwrap();
        assert_eq!(output, input);
        assert_eq!(
            runtime
                .execute_i32(&skill, &SandboxConfig::default(), "answer")
                .unwrap(),
            42
        );
        assert_eq!(runtime.stats().executions, 2);
        assert_eq!(runtime.stats().active_executions, 0);
    }

    #[test]
    fn test_untrusted_output_is_bounds_checked() {
        // Regression: the output length was read as i32 and cast to usize,
        // so -1 became usize::MAX and allocating the buffer panicked in the
        // host; the pointer was also added to with i32 arithmetic.
        let runtime = runtime();
        let skill = runtime.prepare(SKILL_WAT.as_bytes()).unwrap();
        let limits = SandboxConfig::default();
        let input = serde_json::json!({});
        for func in ["bad_len", "bad_ptr"] {
            let result = runtime.execute_json(&skill, &limits, func, &input);
            assert!(
                matches!(result, Err(SandboxError::InvalidOutput(_))),
                "{func}: {result:?}"
            );
        }
    }

    #[test]
    fn test_deadline_with_shared_ticker() {
        let runtime = runtime();
        let skill = runtime.prepare(SKILL_WAT.as_bytes()).unwrap();
        let limits = SandboxConfig {
            fuel_limit: u64::MAX / 2,
            timeout: Duration::from_millis(100),
            ..SandboxConfig::default()
        };
        let started = Instant::now();
        let result = runtime.execute_i32(&skill, &limits, "spin");
        assert!(
            matches!(result, Err(SandboxError::Timeout(_))),
            "{result:?}"
        );
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert!(started.elapsed() < Duration::from_secs(5));
        // The ticker parks again afterwards.
        assert_eq!(runtime.stats().active_executions, 0);
    }

    #[test]
    fn test_pooling_allocator_runs_skills() {
        let runtime = SandboxRuntime::new(SandboxRuntimeConfig {
            pooling: Some(PoolingConfig::minimal()),
            ..SandboxRuntimeConfig::default()
        })
        .unwrap();
        let skill = runtime.prepare(SKILL_WAT.as_bytes()).unwrap();
        assert_eq!(
            runtime
                .execute_i32(&skill, &SandboxConfig::default(), "answer")
                .unwrap(),
            42
        );
    }

    #[test]
    fn test_runtime_drops_cleanly_while_idle() {
        // Joins the parked ticker thread; a hang here is the failure.
        let runtime = runtime();
        drop(runtime);
    }
}
