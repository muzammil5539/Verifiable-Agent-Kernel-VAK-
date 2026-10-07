//! The escape paths named by the Wasmtime advisories that finding K11 lists
//! against 41.0.4, driven through `Kernel::execute` on 49 (docs/adr/0010).
//!
//! Each test names the advisories it covers. Some are about code VAK doesn't
//! compile in (Winch, the component model, WASI). For those the test shows
//! the code is absent: Wasmtime refuses to build a Winch engine, and the
//! kernel refuses a component or a skill that imports WASI. The rest run the
//! guest behaviour the advisory names and check that the guest gets a trap
//! or a failed `grow`, the host doesn't panic, and the kernel keeps serving.

#![cfg(feature = "wasm")]

use std::path::Path;
use std::sync::Arc;

use vak::kernel::types::{AgentId, SessionId, ToolRequest};
use vak::kernel::{Kernel, KernelConfig};
use vak::sandbox::{PoolingConfig, SandboxRuntime, SandboxRuntimeConfig, SkillRegistry};

/// A skill implementing the kernel's ABI that runs one probe, chosen by the
/// first letter of its input (a JSON string). It answers `"ok"` when the
/// probe behaves and `"leak"` when it observes something it shouldn't.
/// Probes that should trap don't answer.
const PROBE_WAT: &str = r#"
(module
  (type $to_i32 (func (result i32)))
  (type $to_i64 (func (result i64)))
  (memory (export "memory") 1 4)
  (table $small 2 4 funcref)
  (table $open 1 funcref)
  (elem (table $small) (i32.const 0) func $seven)
  (global $next (mut i32) (i32.const 1024))
  (data (i32.const 16) "\04\00\00\00\22ok\22")
  (data (i32.const 32) "\06\00\00\00\22leak\22")
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $p))
  (func $seven (type $to_i32) (i32.const 7))
  (func $recurse (result i32) (call $recurse))
  (func (export "execute") (param $ptr i32) (param $len i32) (result i32)
    (local $cmd i32)
    (local $end i32)
    (local.set $cmd (i32.load8_u offset=1 (local.get $ptr)))
    (local.set $end (i32.mul (memory.size) (i32.const 65536)))

    ;; 'e': the last word of memory is readable.
    (if (i32.eq (local.get $cmd) (i32.const 101))
      (then (drop (i32.load (i32.sub (local.get $end) (i32.const 4))))))
    ;; 'r': a word straddling the end of memory is not.
    (if (i32.eq (local.get $cmd) (i32.const 114))
      (then (drop (i32.load (i32.sub (local.get $end) (i32.const 3))))))
    ;; 'n': nor is the top of the 32-bit address space.
    (if (i32.eq (local.get $cmd) (i32.const 110))
      (then (drop (i64.load (i32.const -8)))))
    ;; 'w': nor is a write whose static offset carries it past 4 GiB.
    (if (i32.eq (local.get $cmd) (i32.const 119))
      (then (i32.store offset=4294967295 (i32.const 1) (i32.const 0))))
    ;; 'g': after memory.grow the new last word is readable...
    (if (i32.eq (local.get $cmd) (i32.const 103))
      (then
        (drop (memory.grow (i32.const 1)))
        (drop (i32.load (i32.sub (i32.mul (memory.size) (i32.const 65536)) (i32.const 4))))))
    ;; 'G': ...and the word after it is not.
    (if (i32.eq (local.get $cmd) (i32.const 71))
      (then
        (drop (memory.grow (i32.const 1)))
        (drop (i32.load (i32.mul (memory.size) (i32.const 65536))))))
    ;; 's': f64x2.splat of a load from the last 8 bytes of memory reads
    ;; those 8 bytes and nothing past them.
    (if (i32.eq (local.get $cmd) (i32.const 115))
      (then
        (f64.store (i32.sub (local.get $end) (i32.const 8)) (f64.const 1.5))
        (if (f64.ne
              (f64x2.extract_lane 1
                (f64x2.splat (f64.load (i32.sub (local.get $end) (i32.const 8)))))
              (f64.const 1.5))
          (then (return (i32.const 32))))))
    ;; 'k': table.grow past a table's declared maximum fails with -1.
    (if (i32.eq (local.get $cmd) (i32.const 107))
      (then
        (if (i32.ne (table.grow $small (ref.null func) (i32.const 10)) (i32.const -1))
          (then (return (i32.const 32))))))
    ;; 'K': so does growing an unbounded table toward 2^32 elements.
    (if (i32.eq (local.get $cmd) (i32.const 75))
      (then
        (if (i32.ne (table.grow $open (ref.null func) (i32.const -2)) (i32.const -1))
          (then (return (i32.const 32))))
        (if (i32.ne (table.grow $open (ref.null func) (i32.const 20000)) (i32.const -1))
          (then (return (i32.const 32))))
        (if (i32.ne (table.size $open) (i32.const 1))
          (then (return (i32.const 32))))))
    ;; 'f': table.fill past the end of a table traps.
    (if (i32.eq (local.get $cmd) (i32.const 102))
      (then (table.fill $small (i32.const 1) (ref.null func) (i32.const 5))))
    ;; 'i': call_indirect with the right type calls the function...
    (if (i32.eq (local.get $cmd) (i32.const 105))
      (then
        (if (i32.ne (call_indirect $small (type $to_i32) (i32.const 0)) (i32.const 7))
          (then (return (i32.const 32))))))
    ;; 'c': ...with the wrong type it traps...
    (if (i32.eq (local.get $cmd) (i32.const 99))
      (then (drop (call_indirect $small (type $to_i64) (i32.const 0)))))
    ;; 'u': ...and so it does on an empty slot.
    (if (i32.eq (local.get $cmd) (i32.const 117))
      (then (drop (call_indirect $small (type $to_i32) (i32.const 1)))))
    ;; 'x': unbounded recursion exhausts the guest's stack.
    (if (i32.eq (local.get $cmd) (i32.const 120))
      (then (drop (call $recurse))))
    (i32.const 16)))
"#;

/// Writes a secret into its memory, including pages it grew, on "w"; on any
/// other input grows the same way and answers `"leak"` if it can read any of
/// the secret.
const POOL_WAT: &str = r#"
(module
  (memory (export "memory") 1 16)
  (global $next (mut i32) (i32.const 1024))
  (data (i32.const 16) "\04\00\00\00\22ok\22")
  (data (i32.const 32) "\06\00\00\00\22leak\22")
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $next))
    (global.set $next (i32.add (global.get $next) (local.get $len)))
    (local.get $p))
  (func (export "execute") (param $ptr i32) (param $len i32) (result i32)
    (local $end i32)
    (drop (memory.grow (i32.const 8)))
    (local.set $end (i32.mul (memory.size) (i32.const 65536)))
    (if (i32.eq (i32.load8_u offset=1 (local.get $ptr)) (i32.const 119))
      (then
        (i64.store (i32.const 512) (i64.const 0x5ec2e75ec2e7))
        (i64.store (i32.const 65536) (i64.const 0x5ec2e75ec2e7))
        (i64.store (i32.sub (local.get $end) (i32.const 8)) (i64.const 0x5ec2e75ec2e7))
        (return (i32.const 16))))
    (if (i64.ne
          (i64.or
            (i64.or (i64.load (i32.const 512)) (i64.load (i32.const 65536)))
            (i64.load (i32.sub (local.get $end) (i32.const 8))))
          (i64.const 0))
      (then (return (i32.const 32))))
    (i32.const 16)))
"#;

/// Declares a table of 2^32 - 1 elements.
const HUGE_TABLE_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (table 4294967295 funcref)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "execute") (param i32 i32) (result i32) (i32.const 0)))
"#;

/// Imports the WASI call the filesystem advisory is about.
const WASI_WAT: &str = r#"
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "execute") (param i32 i32) (result i32) (i32.const 0)))
"#;

/// The preamble of a component, not a core module.
const COMPONENT: &[u8] = b"\0asm\x0d\x00\x01\x00";

/// Writes each `(name, file, bytes)` skill into its own directory under
/// `dir` and returns a registry that has loaded them all.
fn registry(dir: &Path, skills: &[(&str, &str, &[u8])]) -> SkillRegistry {
    let mut registry = SkillRegistry::new_permissive_dev(dir.to_path_buf());
    for (name, file, bytes) in skills {
        let skill_dir = dir.join(name);
        std::fs::create_dir_all(&skill_dir).unwrap();
        std::fs::write(skill_dir.join(file), bytes).unwrap();
        let manifest = skill_dir.join("skill.yaml");
        std::fs::write(
            &manifest,
            format!(
                "name: {name}\nversion: \"1.0.0\"\ndescription: probe\n\
                 input_schema: {{type: object}}\noutput_schema: {{type: object}}\n\
                 wasm_path: {file}\n"
            ),
        )
        .unwrap();
        registry.load_skill(&manifest).unwrap();
    }
    registry
}

async fn kernel(dir: &Path, runtime: Arc<SandboxRuntime>) -> Kernel {
    let skills: [(&str, &str, &[u8]); 5] = [
        ("probe", "probe.wat", PROBE_WAT.as_bytes()),
        ("pool", "pool.wat", POOL_WAT.as_bytes()),
        ("huge_table", "huge_table.wat", HUGE_TABLE_WAT.as_bytes()),
        ("wasi", "wasi.wat", WASI_WAT.as_bytes()),
        ("component", "component.wasm", COMPONENT),
    ];
    let mut config = KernelConfig::default();
    config
        .security
        .allowed_tools
        .extend(skills.iter().map(|(name, _, _)| name.to_string()));
    Kernel::builder(config)
        .with_skill_registry(registry(dir, &skills))
        .with_sandbox_runtime(runtime)
        .build()
        .await
        .unwrap()
}

fn runtime(pooling: Option<PoolingConfig>) -> Arc<SandboxRuntime> {
    Arc::new(
        SandboxRuntime::new(SandboxRuntimeConfig {
            pooling,
            ..SandboxRuntimeConfig::default()
        })
        .unwrap(),
    )
}

/// A pool of one instance slot, so every execution reuses the last one's.
/// The probe has two tables.
fn one_slot() -> PoolingConfig {
    PoolingConfig {
        max_instances: 1,
        max_tables: 2,
        ..PoolingConfig::minimal()
    }
}

/// Runs `tool` with `input` through `Kernel::execute`: its answer, or why
/// it failed.
async fn run(kernel: &Kernel, tool: &str, input: &str) -> Result<serde_json::Value, String> {
    match kernel
        .execute(
            &AgentId::new(),
            &SessionId::new(),
            ToolRequest::new(tool, serde_json::json!(input)),
        )
        .await
    {
        Ok(response) if response.success => Ok(response.result.unwrap_or_default()),
        Ok(response) => Err(response.error.unwrap_or_default()),
        Err(e) => Err(e.to_string()),
    }
}

/// The probe answered "ok".
async fn behaves(kernel: &Kernel, tool: &str, input: &str) {
    assert_eq!(
        run(kernel, tool, input).await,
        Ok(serde_json::json!("ok")),
        "{tool} {input}"
    );
}

/// The probe trapped with `trap`: the guest stopped, the host didn't panic.
async fn traps(kernel: &Kernel, tool: &str, input: &str, trap: &str) {
    let error = run(kernel, tool, input).await.unwrap_err();
    assert!(error.contains(trap), "{tool} {input}: {error}");
    assert!(!error.contains("panicked"), "{tool} {input}: {error}");
}

/// The kernel still runs a built-in and a skill.
async fn still_serves(kernel: &Kernel) {
    let echo = kernel
        .execute(
            &AgentId::new(),
            &SessionId::new(),
            ToolRequest::new("echo", serde_json::json!(1)),
        )
        .await
        .unwrap();
    assert!(echo.success);
    behaves(kernel, "probe", "e").await;
}

/// RUSTSEC-2026-0096 (a Cranelift miscompile of guest heap accesses, on
/// aarch64) and RUSTSEC-2026-0095 (a sandbox-escaping access under Winch):
/// every access at or past the end of linear memory traps, on both
/// allocators, and every access inside it works.
#[tokio::test]
async fn guest_memory_accesses_stay_in_bounds() {
    for pooling in [None, Some(one_slot())] {
        let dir = tempfile::tempdir().unwrap();
        let kernel = kernel(dir.path(), runtime(pooling)).await;

        behaves(&kernel, "probe", "e").await;
        behaves(&kernel, "probe", "g").await;
        for probe in ["r", "n", "w", "G"] {
            traps(&kernel, "probe", probe, "out of bounds memory access").await;
        }
        still_serves(&kernel).await;
    }
}

/// RUSTSEC-2026-0087: `f64x2.splat` of a load on Cranelift x86-64 could
/// fault or load from outside the sandbox. Splatting the last 8 bytes of
/// memory must read exactly those bytes.
#[tokio::test]
async fn f64x2_splat_reads_only_its_operand() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = kernel(dir.path(), runtime(None)).await;
    for _ in 0..3 {
        behaves(&kernel, "probe", "s").await;
    }
}

/// RUSTSEC-2026-0088: data leaking between instances of the pooling
/// allocator. With one slot, every execution reuses the memory the last one
/// wrote a secret into, including the pages it grew.
#[tokio::test]
async fn pooled_instances_never_see_each_others_memory() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = kernel(dir.path(), runtime(Some(one_slot()))).await;
    for _ in 0..20 {
        behaves(&kernel, "pool", "w").await;
        behaves(&kernel, "pool", "r").await;
    }
}

/// RUSTSEC-2026-0094 (a `table.grow` result masked wrongly under Winch),
/// RUSTSEC-2026-0089 (a host panic on `table.fill` under Winch) and
/// RUSTSEC-2026-0114 (a host panic allocating a table larger than the
/// address space). A grow past a table's maximum or the sandbox's table cap
/// fails with -1; a fill past a table's end traps; a module declaring a
/// table of 2^32 - 1 elements is refused before anything is allocated.
#[tokio::test]
async fn table_operations_fail_inside_the_guest() {
    for pooling in [None, Some(one_slot())] {
        let dir = tempfile::tempdir().unwrap();
        let kernel = kernel(dir.path(), runtime(pooling)).await;

        behaves(&kernel, "probe", "k").await;
        behaves(&kernel, "probe", "K").await;
        traps(&kernel, "probe", "f", "out of bounds table access").await;

        let error = run(&kernel, "huge_table", "x").await.unwrap_err();
        assert!(error.contains("WASM execution failed"), "{error}");
        assert!(!error.contains("panicked"), "{error}");
        still_serves(&kernel).await;
    }
}

/// RUSTSEC-2026-0222: stores mixing up type indices between engines. Two
/// kernels with a runtime (an engine) each run the same skill, alternately:
/// indirect calls check types against their own engine's registry.
#[tokio::test]
async fn two_engines_keep_their_types_apart() {
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = kernel(a_dir.path(), runtime(None)).await;
    let b = kernel(b_dir.path(), runtime(None)).await;
    for _ in 0..3 {
        for kernel in [&a, &b] {
            behaves(kernel, "probe", "i").await;
            traps(kernel, "probe", "c", "indirect call type mismatch").await;
            traps(kernel, "probe", "u", "uninitialized element").await;
        }
    }
    assert!(!Arc::ptr_eq(
        a.sandbox_runtime().unwrap(),
        b.sandbox_runtime().unwrap()
    ));
}

/// A guest that recurses forever exhausts its own stack, not the host's.
#[tokio::test]
async fn unbounded_recursion_traps() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = kernel(dir.path(), runtime(None)).await;
    traps(&kernel, "probe", "x", "call stack exhausted").await;
    still_serves(&kernel).await;
}

/// RUSTSEC-2026-0085, -0091, -0092, -0093, -0316 and -0327 are all in the
/// component model, which VAK doesn't compile in: a component is refused
/// as a skill.
#[tokio::test]
async fn components_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = kernel(dir.path(), runtime(None)).await;
    let error = run(&kernel, "component", "x").await.unwrap_err();
    assert!(error.contains("WASM execution failed"), "{error}");
    assert!(error.contains("component"), "{error}");
    still_serves(&kernel).await;
}

/// RUSTSEC-2026-0269 is a filesystem escape in WASI. Skills get no host
/// imports, so one that imports WASI is refused before it runs.
#[tokio::test]
async fn a_skill_importing_wasi_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = kernel(dir.path(), runtime(None)).await;
    let error = run(&kernel, "wasi", "x").await.unwrap_err();
    assert!(error.contains("path_open"), "{error}");
    still_serves(&kernel).await;
}

/// RUSTSEC-2026-0086, -0089, -0094 and -0095 are in Winch, which VAK
/// doesn't compile in: Wasmtime refuses to build an engine that uses it.
#[test]
fn winch_is_not_compiled_in() {
    let mut config = wasmtime::Config::new();
    config.strategy(wasmtime::Strategy::Winch);
    let error = wasmtime::Engine::new(&config)
        .err()
        .map(|e| format!("{e:#}"));
    assert!(
        error.as_deref().is_some_and(|e| e.contains("winch")),
        "{error:?}"
    );

    // Cranelift, which the sandbox runtime uses, is.
    let mut config = wasmtime::Config::new();
    config.strategy(wasmtime::Strategy::Cranelift);
    assert!(wasmtime::Engine::new(&config).is_ok());
}
