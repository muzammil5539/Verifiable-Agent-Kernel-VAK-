//! Cedar policies through `Kernel::execute` (docs/adr/0008).
//!
//! These fail if the Cedar port of the default policies stops deciding tool
//! calls the way the YAML original does, if a tool runs that a Cedar policy
//! forbids or doesn't permit, if a call whose arguments don't match the
//! schema gets through, or if policies that fail to load stop denying.

use std::path::{Path, PathBuf};

use vak::kernel::types::KernelError;
use vak::kernel::{Kernel, KernelConfig, PolicyFormat};

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn cedar_config(schema: Option<&str>, policies: &[&str]) -> KernelConfig {
    let mut config = KernelConfig::default();
    config.policy.format = PolicyFormat::Cedar;
    config.policy.cedar_schema = schema.map(repo);
    config.policy.policy_paths = policies.iter().map(|p| repo(p)).collect();
    config
}

#[cfg(not(feature = "cedar"))]
#[tokio::test]
async fn cedar_policies_need_the_cedar_feature() {
    let result = Kernel::new(cedar_config(None, &["policies/cedar"])).await;
    assert!(matches!(
        result,
        Err(KernelError::InvalidConfiguration { ref message }) if message.contains("cedar")
    ));
}

#[cfg(feature = "cedar")]
mod with_cedar {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
    use vak::kernel::types::{AgentId, SessionId, ToolRequest};
    use vak::kernel::types::{PolicyDecision, ToolResponse};
    use vak::kernel::{AgentRecord, ToolHandler};

    /// Every combination the default policies distinguish: built-ins, the
    /// tools they forbid by name, and an unknown tool; blocked or not; an
    /// internal agent or not.
    #[tokio::test]
    async fn the_cedar_port_decides_tool_calls_like_the_yaml_policies() {
        let tools = ["echo", "calculator", "rm -rf", "dd", "mkfs", "custom_tool"];
        let (mut compared, mut allowed) = (0, 0);
        for blocked in [false, true] {
            let configure = |mut config: KernelConfig| {
                if blocked {
                    config.security.blocked_tools = tools.iter().map(|t| t.to_string()).collect();
                }
                config
            };
            let mut yaml = KernelConfig::default();
            yaml.policy.policy_paths = vec![repo("policies/default_policies.yaml")];
            let yaml = Kernel::new(configure(yaml)).await.unwrap();
            let cedar = Kernel::new(configure(cedar_config(None, &["policies/cedar"])))
                .await
                .unwrap();

            for internal in [false, true] {
                let agent = AgentId::new();
                let record = AgentRecord::new(agent, "agent").internal(internal);
                yaml.register_agent(record.clone()).await.unwrap();
                cedar.register_agent(record).await.unwrap();

                for tool in tools {
                    let request = ToolRequest::new(tool, serde_json::json!({}));
                    let by_yaml = yaml.evaluate_policy(&agent, &request).await;
                    let by_cedar = cedar.evaluate_policy(&agent, &request).await;
                    assert_eq!(
                        by_yaml.is_allowed(),
                        by_cedar.is_allowed(),
                        "{tool} (blocked: {blocked}, internal: {internal}): \
                         YAML {by_yaml:?}, Cedar {by_cedar:?}"
                    );
                    compared += 1;
                    allowed += usize::from(by_cedar.is_allowed());
                }
            }
        }
        assert_eq!(compared, 24);
        // echo, calculator and custom_tool, unblocked, for both agents: the
        // comparison is between two loaded policy sets, not two denials.
        assert_eq!(allowed, 6);
    }

    #[tokio::test]
    async fn a_cedar_kernel_runs_what_policy_permits_and_records_why() {
        let kernel = Kernel::new(cedar_config(None, &["policies/cedar"]))
            .await
            .unwrap();
        let (agent, session) = (AgentId::new(), SessionId::new());

        let response = kernel
            .execute(
                &agent,
                &session,
                ToolRequest::new("echo", serde_json::json!({"x": 1})),
            )
            .await
            .unwrap();
        assert!(response.success);

        let refused = kernel
            .execute(
                &agent,
                &session,
                ToolRequest::new("dd", serde_json::json!({})),
            )
            .await;
        assert!(
            matches!(
                refused,
                Err(KernelError::PolicyViolation { ref policy_id, .. }) if policy_id == "forbid-dd"
            ),
            "{refused:?}"
        );

        let log = kernel.get_audit_log().await;
        match &log[0].decision {
            PolicyDecision::Allow { reason, .. } => {
                assert!(reason.contains("permit-safe-tools"), "{reason}");
            }
            other => panic!("expected an allow, got {other:?}"),
        }
        match &log.last().unwrap().decision {
            PolicyDecision::Deny {
                violated_policies, ..
            } => assert_eq!(violated_policies, &Some(vec!["forbid-dd".to_string()])),
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    /// A host tool standing in for a payment API, counting how often it ran.
    fn transfer_funds(runs: Arc<AtomicUsize>) -> impl ToolHandler + 'static {
        FunctionHandler::new(
            "transfer_funds",
            move |req: &ToolRequest, _agent: &AgentId| {
                let runs = runs.clone();
                let id = req.request_id;
                Box::pin(async move {
                    runs.fetch_add(1, Ordering::SeqCst);
                    Ok(ToolResponse::success(id, serde_json::json!("sent"), 0))
                }) as HandlerFuture
            },
        )
    }

    #[tokio::test]
    async fn policies_read_a_tools_typed_arguments() {
        let runs = Arc::new(AtomicUsize::new(0));
        let kernel = Kernel::builder(cedar_config(
            Some("policies/cedar/examples/payments.cedarschema"),
            &["policies/cedar/examples/payments.cedar"],
        ))
        .with_tool(transfer_funds(runs.clone()))
        .build()
        .await
        .unwrap();

        let clerk = AgentId::new();
        kernel
            .register_agent(AgentRecord::new(clerk, "clerk").with_attribute("team", "finance"))
            .await
            .unwrap();
        let stranger = AgentId::new();
        kernel
            .register_agent(AgentRecord::new(stranger, "stranger"))
            .await
            .unwrap();

        let transfer = |amount: serde_json::Value, currency: &str| {
            ToolRequest::new(
                "transfer_funds",
                serde_json::json!({"amount": amount, "currency": currency, "to": "acct-9"}),
            )
        };
        let run = |agent: AgentId, request: ToolRequest| {
            let kernel = &kernel;
            async move {
                kernel
                    .execute(&agent, &SessionId::new(), request)
                    .await
                    .map(|r| r.success)
            }
        };

        assert!(run(clerk, transfer(500.into(), "USD")).await.unwrap());
        assert_eq!(runs.load(Ordering::SeqCst), 1);

        let denied: [(&str, AgentId, ToolRequest, &str); 5] = [
            (
                "over the limit",
                clerk,
                transfer(5000.into(), "USD"),
                "No Cedar policy permits",
            ),
            (
                "wrong currency",
                clerk,
                transfer(5.into(), "JPY"),
                "transfers-in-usd-or-eur-only",
            ),
            (
                "not finance",
                stranger,
                transfer(5.into(), "USD"),
                "No Cedar policy permits",
            ),
            (
                "an argument the schema doesn't declare",
                clerk,
                ToolRequest::new(
                    "transfer_funds",
                    serde_json::json!({
                        "amount": 5, "currency": "USD", "to": "acct-9",
                        "also_to": "acct-666"
                    }),
                ),
                "doesn't match the schema",
            ),
            (
                "a fractional amount",
                clerk,
                transfer(serde_json::json!(5.5), "USD"),
                "doesn't match the schema",
            ),
        ];
        for (case, agent, request, why) in denied {
            match run(agent, request).await {
                Err(KernelError::PolicyViolation { reason, policy_id }) => assert!(
                    reason.contains(why) || policy_id.contains(why),
                    "{case}: {policy_id}: {reason}"
                ),
                other => panic!("{case}: expected a policy violation, got {other:?}"),
            }
        }
        assert_eq!(runs.load(Ordering::SeqCst), 1, "denied transfers never ran");
    }

    #[tokio::test]
    async fn policies_that_fail_to_load_deny_everything_and_say_why() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("broken.cedar"),
            "permit (principal, action, resource) when { principal.clearance > 3 };",
        )
        .unwrap();
        let mut config = cedar_config(None, &[]);
        config.policy.policy_paths = vec![dir.path().to_path_buf()];
        let kernel = Kernel::new(config).await.unwrap();

        let result = kernel
            .execute(
                &AgentId::new(),
                &SessionId::new(),
                ToolRequest::new("echo", serde_json::json!({})),
            )
            .await;
        match result {
            Err(KernelError::PolicyViolation { reason, .. }) => {
                assert!(reason.contains("failed to load"), "{reason}");
                assert!(reason.contains("clearance"), "{reason}");
            }
            other => panic!("expected a denial, got {other:?}"),
        }
        assert_eq!(
            kernel.get_audit_log().await.len(),
            1,
            "the denial is recorded"
        );

        let no_policies = Kernel::new(cedar_config(None, &[])).await.unwrap();
        assert!(!no_policies
            .evaluate_policy(
                &AgentId::new(),
                &ToolRequest::new("echo", serde_json::json!({}))
            )
            .await
            .is_allowed());
    }
}
