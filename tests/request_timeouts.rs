//! `ToolRequest::timeout_ms` through `Kernel::execute`.
//!
//! These fail if a request's time limit stops being applied when it is
//! tighter than the kernel's, or if a request can extend the kernel's.

use std::time::{Duration, Instant};

use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
use vak::kernel::types::{AgentId, SessionId, ToolRequest, ToolResponse};
use vak::kernel::{Kernel, KernelConfig};

/// A host tool that takes 2 seconds.
fn slow_tool() -> impl vak::kernel::ToolHandler + 'static {
    FunctionHandler::new("slow_tool", |req: &ToolRequest, _agent: &AgentId| {
        let id = req.request_id;
        Box::pin(async move {
            tokio::time::sleep(Duration::from_secs(2)).await;
            Ok(ToolResponse::success(id, serde_json::json!("done"), 0))
        }) as HandlerFuture
    })
}

async fn kernel(max_execution_time: Duration) -> Kernel {
    let mut config = KernelConfig::default();
    config.security.allowed_tools.push("slow_tool".to_string());
    config.max_execution_time = max_execution_time;
    Kernel::builder(config)
        .with_tool(slow_tool())
        .build()
        .await
        .unwrap()
}

/// Runs `request` and returns why it failed.
async fn failure(kernel: &Kernel, request: ToolRequest) -> String {
    match kernel
        .execute(&AgentId::new(), &SessionId::new(), request)
        .await
    {
        Ok(response) => {
            assert!(!response.success, "{response:?}");
            response.error.unwrap()
        }
        Err(e) => e.to_string(),
    }
}

#[tokio::test]
async fn a_tighter_request_limit_stops_a_handler() {
    let kernel = kernel(Duration::from_secs(60)).await;
    let started = Instant::now();
    let error = failure(
        &kernel,
        ToolRequest::new("slow_tool", serde_json::json!({})).with_timeout(20),
    )
    .await;
    assert!(error.contains("timed out after 20ms"), "{error}");
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn a_request_cannot_extend_the_kernels_limit() {
    let kernel = kernel(Duration::from_millis(30)).await;
    let error = failure(
        &kernel,
        ToolRequest::new("slow_tool", serde_json::json!({})).with_timeout(60_000),
    )
    .await;
    assert!(error.contains("timed out after 30ms"), "{error}");
}

#[test]
fn the_sooner_limit_wins() {
    let kernel_limit = Duration::from_secs(5);
    let request = ToolRequest::new("t", serde_json::json!({}));
    assert_eq!(request.time_limit(kernel_limit), kernel_limit);
    assert_eq!(
        request.clone().with_timeout(10).time_limit(kernel_limit),
        Duration::from_millis(10)
    );
    assert_eq!(
        request.with_timeout(10_000).time_limit(kernel_limit),
        kernel_limit
    );
}

#[cfg(feature = "wasm")]
mod skills {
    use super::*;
    use std::sync::Arc;
    use vak::sandbox::{SandboxRuntime, SandboxRuntimeConfig, SkillRegistry};

    /// Spins until stopped.
    const SPIN_WAT: &str = r#"
(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "execute") (param i32 i32) (result i32)
    (local $x f64)
    (loop $l
      (local.set $x (f64.sqrt (f64.sqrt (f64.sqrt (f64.sqrt
        (f64.add (local.get $x) (f64.const 1e300)))))))
      (br $l))
    (i32.const 0)))
"#;

    /// A spinning skill with the kernel's limit at a minute stops at the
    /// request's millisecond, long before its fuel runs out.
    #[tokio::test]
    async fn a_tighter_request_limit_stops_a_skill() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("spin.wat"), SPIN_WAT).unwrap();
        let manifest = dir.path().join("spin.yaml");
        std::fs::write(
            &manifest,
            "name: spin\nversion: \"1.0.0\"\ndescription: spins\n\
             input_schema: {type: object}\noutput_schema: {type: object}\n\
             wasm_path: spin.wat\n",
        )
        .unwrap();
        let mut registry = SkillRegistry::new_permissive_dev(dir.path().to_path_buf());
        registry.load_skill(&manifest).unwrap();

        let mut config = KernelConfig::default();
        config.security.allowed_tools.push("spin".to_string());
        config.max_execution_time = Duration::from_secs(60);
        let runtime = SandboxRuntime::new(SandboxRuntimeConfig {
            tick: Duration::from_millis(1),
            ..SandboxRuntimeConfig::default()
        })
        .unwrap();
        let kernel = Kernel::builder(config)
            .with_skill_registry(registry)
            .with_sandbox_runtime(Arc::new(runtime))
            .build()
            .await
            .unwrap();

        let error = failure(
            &kernel,
            ToolRequest::new("spin", serde_json::json!({})).with_timeout(1),
        )
        .await;
        assert!(error.contains("timed out after 1ms"), "{error}");
    }
}
