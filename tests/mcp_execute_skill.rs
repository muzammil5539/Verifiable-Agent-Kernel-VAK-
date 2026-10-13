//! MCP `execute_skill` runs skills through `Kernel::execute` (finding I3).
//!
//! These fail if the tool reports success for a skill that didn't run, if
//! it runs a skill the kernel's policy refuses, or if a call it makes
//! leaves no record in the kernel's audit log.

#![cfg(all(feature = "integrations", feature = "wasm"))]

use std::path::Path;
use std::sync::Arc;

use vak::integrations::mcp::{create_vak_mcp_server, mcp_agent_id, JsonRpcRequest, McpServer};
use vak::kernel::types::{AgentId, PolicyDecision};
use vak::kernel::{Kernel, KernelConfig};
use vak::sandbox::SkillRegistry;

/// Echoes its input (the kernel's skill ABI).
const ECHO_WAT: &str = r#"
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
    (i32.const 0)))
"#;

/// A kernel that knows the skills `wasm_echo` and `blocked_echo` (the same
/// module) and blocks the second, and an MCP server over it.
async fn server(dir: &Path) -> (Arc<Kernel>, McpServer) {
    let mut registry = SkillRegistry::new_permissive_dev(dir.to_path_buf());
    std::fs::write(dir.join("echo.wat"), ECHO_WAT).unwrap();
    for name in ["wasm_echo", "blocked_echo"] {
        let manifest = dir.join(format!("{name}.yaml"));
        std::fs::write(
            &manifest,
            format!(
                "name: {name}\nversion: \"1.0.0\"\ndescription: Echoes its input\n\
                 input_schema: {{type: object}}\noutput_schema: {{type: object}}\n\
                 wasm_path: echo.wat\n"
            ),
        )
        .unwrap();
        registry.load_skill(&manifest).unwrap();
    }
    let mut config = KernelConfig::default();
    config.security.allowed_tools.push("wasm_echo".to_string());
    config
        .security
        .blocked_tools
        .push("blocked_echo".to_string());
    let kernel = Arc::new(
        Kernel::builder(config)
            .with_skill_registry(registry)
            .build()
            .await
            .unwrap(),
    );
    let server = create_vak_mcp_server(kernel.clone()).await;
    (kernel, server)
}

/// Calls `execute_skill` and returns the tool result's text and `isError`.
async fn execute_skill(server: &McpServer, arguments: serde_json::Value) -> (String, bool) {
    let response = server
        .handle_request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: serde_json::json!(1),
            method: "tools/call".to_string(),
            params: serde_json::json!({"name": "execute_skill", "arguments": arguments}),
        })
        .await;
    let result = response.result.unwrap();
    let text = result["content"][0]["text"].as_str().unwrap().to_string();
    (text, result["isError"].as_bool().unwrap())
}

#[tokio::test]
async fn a_skill_runs_through_the_kernel_and_returns_its_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let (kernel, server) = server(dir.path()).await;

    let (text, is_error) = execute_skill(
        &server,
        serde_json::json!({
            "skill_id": "wasm_echo",
            "input": {"x": 1},
            "agent_id": "claude-desktop",
        }),
    )
    .await;
    assert!(!is_error, "{text}");
    let answer: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(answer["result"], serde_json::json!({"x": 1}));

    // The kernel decided and recorded it, under the agent the name maps to,
    // and the receipt points at those records.
    let log = kernel.get_audit_log().await;
    assert_eq!(log.len(), 2, "a decision leaf and an outcome leaf");
    assert!(log
        .iter()
        .all(|e| e.agent_id == mcp_agent_id("claude-desktop")));
    assert!(matches!(log[0].decision, PolicyDecision::Allow { .. }));
    assert!(log[1].outcome.as_ref().unwrap().success);
    assert_eq!(answer["receipt"]["decision_leaf"], 0);
    assert_eq!(answer["receipt"]["outcome_leaf"], 1);
}

#[tokio::test]
async fn a_skill_the_kernel_refuses_does_not_run() {
    let dir = tempfile::tempdir().unwrap();
    let (kernel, server) = server(dir.path()).await;

    let (text, is_error) = execute_skill(
        &server,
        serde_json::json!({"skill_id": "blocked_echo", "input": {"x": 1}}),
    )
    .await;
    assert!(is_error, "{text}");
    assert!(text.contains("did not run"), "{text}");
    assert!(!text.contains("\"x\""), "{text}");

    let log = kernel.get_audit_log().await;
    assert_eq!(log.len(), 1, "the refusal is recorded");
    assert!(matches!(log[0].decision, PolicyDecision::Deny { .. }));
    assert!(log[0].outcome.is_none(), "nothing ran");
}

#[tokio::test]
async fn an_unknown_skill_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let (_kernel, server) = server(dir.path()).await;

    let (text, is_error) = execute_skill(
        &server,
        serde_json::json!({"skill_id": "no_such_skill", "input": {}}),
    )
    .await;
    assert!(is_error, "{text}");
    assert!(!text.contains("successfully"), "{text}");
}

#[test]
fn agent_names_map_to_stable_ids() {
    assert_eq!(
        mcp_agent_id("claude-desktop"),
        mcp_agent_id("claude-desktop")
    );
    assert_ne!(mcp_agent_id("claude-desktop"), mcp_agent_id("anonymous"));
    let uuid = "0190f5a0-0000-7000-8000-000000000001";
    assert_eq!(mcp_agent_id(uuid), AgentId::parse(uuid).unwrap());
}
