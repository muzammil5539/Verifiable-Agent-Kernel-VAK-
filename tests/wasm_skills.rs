//! WASM skills through `Kernel::execute`, on the shared sandbox runtime
//! (docs/adr/0004).
//!
//! These fail if skills go back to being compiled on every call, if a
//! spinning skill can stall the async runtime, if a skill's time limit stops
//! being enforced, or if a skill's output can make the host misbehave.

#![cfg(feature = "wasm")]

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vak::kernel::types::{AgentId, SessionId, ToolRequest};
use vak::kernel::{Kernel, KernelConfig};
use vak::sandbox::{SandboxRuntime, SandboxRuntimeConfig, SkillRegistry};

/// A skill implementing the kernel's ABI. `execute` echoes its input unless
/// the input is the JSON string "spin" or "lie".
///
/// "spin" loops forever over a chain of square roots. Each costs one unit of
/// fuel but waits on the one before it, so the kernel's fuel budget lasts tens
/// of milliseconds rather than a few. (It used to loop over a 64 KiB
/// `memory.fill`, which Wasmtime 49 charges a unit of fuel per byte.)
///
/// "lie" claims an output length that runs past its memory.
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
    (local $x f64)
    ;; "spin" is 6 bytes with quotes, starting with '"s'
    (if (i32.and (i32.eq (local.get $len) (i32.const 6))
                 (i32.eq (i32.load8_u offset=1 (local.get $ptr)) (i32.const 115)))
      (then
        (local.set $x (f64.const 1e300))
        (loop $l
          (local.set $x
            (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt
            (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt
              (f64.add (local.get $x) (f64.const 1e300)))))))))))))))))))
          (br $l))))
    ;; "lie" is 5 bytes with quotes, starting with '"l'
    (if (i32.and (i32.eq (local.get $len) (i32.const 5))
                 (i32.eq (i32.load8_u offset=1 (local.get $ptr)) (i32.const 108)))
      (then
        (i32.store (i32.const 0) (i32.const -1))
        (return (i32.const 0))))
    (i32.store (i32.const 0) (local.get $len))
    (memory.copy (i32.const 4) (local.get $ptr) (local.get $len))
    (i32.const 0)))
"#;

/// Writes the skill and its manifest into `dir` and returns a registry that
/// has loaded it. Signatures are not checked: real skill signing is Phase 1
/// slice 1c (finding K4).
fn registry_with_echo_skill(dir: &Path) -> SkillRegistry {
    std::fs::write(dir.join("echo.wat"), SKILL_WAT).unwrap();
    let manifest = dir.join("skill.yaml");
    std::fs::write(
        &manifest,
        r#"
name: wasm_echo
version: "1.0.0"
description: Echoes its input
input_schema: {type: object}
output_schema: {type: object}
wasm_path: echo.wat
"#,
    )
    .unwrap();
    let mut registry = SkillRegistry::new_permissive_dev(dir.to_path_buf());
    registry.load_skill(&manifest).unwrap();
    registry
}

fn config(timeout: Duration) -> KernelConfig {
    let mut config = KernelConfig::default();
    config.security.allowed_tools.push("wasm_echo".to_string());
    config.max_execution_time = timeout;
    config
}

async fn kernel(dir: &Path, timeout: Duration, runtime: Arc<SandboxRuntime>) -> Kernel {
    Kernel::builder(config(timeout))
        .with_skill_registry(registry_with_echo_skill(dir))
        .with_sandbox_runtime(runtime)
        .build()
        .await
        .unwrap()
}

fn call(input: serde_json::Value) -> ToolRequest {
    ToolRequest::new("wasm_echo", input)
}

#[tokio::test]
async fn a_skill_runs_and_is_compiled_once() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = Arc::new(SandboxRuntime::new(SandboxRuntimeConfig::default()).unwrap());
    let kernel = kernel(dir.path(), Duration::from_secs(5), runtime.clone()).await;
    let agent = AgentId::new();
    let session = SessionId::new();

    for n in 0..3 {
        let input = serde_json::json!({"n": n});
        let response = kernel
            .execute(&agent, &session, call(input.clone()))
            .await
            .unwrap();
        assert!(response.success, "{response:?}");
        assert_eq!(response.result, Some(input));
        assert!(response.receipt.is_some());
    }

    let stats = runtime.stats();
    assert_eq!(stats.compiled_modules, 1, "{stats:?}");
    assert_eq!(stats.cache_hits, 2, "{stats:?}");
    assert_eq!(stats.executions, 3);
    assert_eq!(stats.active_executions, 0);
}

#[tokio::test]
async fn kernels_can_share_one_runtime() {
    let runtime = Arc::new(SandboxRuntime::new(SandboxRuntimeConfig::default()).unwrap());
    let (a_dir, b_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let a = kernel(a_dir.path(), Duration::from_secs(5), runtime.clone()).await;
    let b = kernel(b_dir.path(), Duration::from_secs(5), runtime.clone()).await;

    for kernel in [&a, &b] {
        assert!(
            kernel
                .execute(
                    &AgentId::new(),
                    &SessionId::new(),
                    call(serde_json::json!({}))
                )
                .await
                .unwrap()
                .success
        );
    }
    // Same bytes in two files, two kernels: one compilation.
    assert_eq!(runtime.stats().compiled_modules, 1);
    assert!(Arc::ptr_eq(a.sandbox_runtime().unwrap(), &runtime));
}

#[tokio::test]
async fn a_kernel_builds_its_runtime_on_the_first_skill_call() {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Kernel::builder(config(Duration::from_secs(5)))
        .with_skill_registry(registry_with_echo_skill(dir.path()))
        .build()
        .await
        .unwrap();
    assert!(kernel.sandbox_runtime().is_none());

    kernel
        .execute(
            &AgentId::new(),
            &SessionId::new(),
            call(serde_json::json!({})),
        )
        .await
        .unwrap();
    assert_eq!(kernel.sandbox_runtime().unwrap().stats().executions, 1);
}

// A single-threaded runtime: if the skill ran on the async executor, nothing
// else could make progress until it finished.
#[tokio::test(flavor = "current_thread")]
async fn a_spinning_skill_runs_out_of_fuel_without_stalling_other_requests() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = Arc::new(SandboxRuntime::new(SandboxRuntimeConfig::default()).unwrap());
    // A deadline far away: only fuel can stop the skill.
    let kernel = kernel(dir.path(), Duration::from_secs(60), runtime).await;
    let (agent, session) = (AgentId::new(), SessionId::new());

    let started = Instant::now();
    let spin = async {
        let spun = kernel
            .execute(&agent, &session, call(serde_json::json!("spin")))
            .await;
        (spun, started.elapsed())
    };
    let meanwhile = async {
        // Wait on a timer, which only fires if the executor is free.
        tokio::time::sleep(Duration::from_millis(1)).await;
        let response = kernel
            .execute(
                &agent,
                &session,
                ToolRequest::new("echo", serde_json::json!(1)),
            )
            .await
            .unwrap();
        assert!(response.success);
        started.elapsed()
    };
    let ((spun, spin_done_at), echo_done_at) = tokio::join!(spin, meanwhile);

    assert!(
        echo_done_at < spin_done_at,
        "a built-in call finished at {echo_done_at:?}, after the spinning skill \
         ({spin_done_at:?}): it waited behind it"
    );
    let spun = spun.unwrap();
    assert!(!spun.success);
    let error = spun.error.unwrap();
    assert!(error.contains("Fuel exhausted"), "{error}");

    // The outcome leaf records the failure.
    let log = kernel.get_audit_log().await;
    let outcome = log
        .iter()
        .filter_map(|e| e.outcome.as_ref())
        .find(|o| !o.success)
        .unwrap();
    assert!(outcome.error.as_ref().unwrap().contains("Fuel exhausted"));
}

/// Fuel stops a skill that computes. The deadline stops one that is slow for
/// its fuel. Here the deadline is a millisecond and the ticker ticks every
/// millisecond, so it fires well before the skill could spend the kernel's
/// fuel budget.
#[tokio::test]
async fn a_skill_past_its_deadline_is_stopped() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = Arc::new(
        SandboxRuntime::new(SandboxRuntimeConfig {
            tick: Duration::from_millis(1),
            ..SandboxRuntimeConfig::default()
        })
        .unwrap(),
    );
    let kernel = kernel(dir.path(), Duration::from_millis(1), runtime).await;
    let (agent, session) = (AgentId::new(), SessionId::new());

    let result = kernel
        .execute(&agent, &session, call(serde_json::json!("spin")))
        .await;
    let error = match result {
        Ok(response) => {
            assert!(!response.success, "{response:?}");
            response.error.unwrap()
        }
        Err(e) => e.to_string(),
    };
    assert!(error.contains("timed out"), "{error}");

    // The kernel keeps serving afterwards.
    let echo = kernel
        .execute(
            &agent,
            &session,
            ToolRequest::new("echo", serde_json::json!(1)),
        )
        .await
        .unwrap();
    assert!(echo.success);
}

#[tokio::test]
async fn a_lying_skill_cannot_make_the_host_misbehave() {
    let dir = tempfile::tempdir().unwrap();
    let runtime = Arc::new(SandboxRuntime::new(SandboxRuntimeConfig::default()).unwrap());
    let kernel = kernel(dir.path(), Duration::from_secs(5), runtime).await;

    let response = kernel
        .execute(
            &AgentId::new(),
            &SessionId::new(),
            call(serde_json::json!("lie")),
        )
        .await
        .unwrap();
    assert!(!response.success);
    assert!(
        response
            .error
            .as_ref()
            .unwrap()
            .contains("Invalid JSON output"),
        "{response:?}"
    );

    // And the kernel still serves.
    assert!(
        kernel
            .execute(
                &AgentId::new(),
                &SessionId::new(),
                call(serde_json::json!({}))
            )
            .await
            .unwrap()
            .success
    );
}

#[tokio::test]
async fn a_skill_whose_module_is_missing_fails_the_call() {
    let dir = tempfile::tempdir().unwrap();
    let registry = registry_with_echo_skill(dir.path());
    std::fs::remove_file(dir.path().join("echo.wat")).unwrap();
    let kernel = Kernel::builder(config(Duration::from_secs(5)))
        .with_skill_registry(registry)
        .build()
        .await
        .unwrap();

    let result = kernel
        .execute(
            &AgentId::new(),
            &SessionId::new(),
            call(serde_json::json!({})),
        )
        .await
        .unwrap();
    assert!(!result.success);
    let error = result.error.unwrap();
    assert!(error.contains("Failed to load WASM module"), "{error}");
}
