//! Proofs about Cedar policy sets with SymCC, and checked reloads through
//! the kernel (docs/adr/0009).
//!
//! Tests that run the solver need cvc5 1.3.1 (the `CVC5` environment
//! variable, or `cvc5` on `PATH`), so they are ignored by default. CI runs
//! them with `--include-ignored`. Without cvc5 they fail rather than pass.

#![cfg(feature = "cedar-analysis")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use vak::kernel::types::{AgentId, ToolRequest};
use vak::kernel::{CedarPolicy, Kernel, KernelConfig, PolicyFormat};
use vak::policy::cedar::analysis::{
    AnalysisError, Analyzer, Check, PolicyProperties, ReloadRefused, Widening,
};
use vak::policy::cedar::{CedarPolicySet, VAK_SCHEMA};

const NEEDS_CVC5: &str = "needs cvc5 1.3.1 (set CVC5)";

fn repo(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(path)
}

fn read(path: &str) -> String {
    std::fs::read_to_string(repo(path)).unwrap()
}

fn default_policies() -> CedarPolicySet {
    CedarPolicySet::load(None, &[repo("policies/cedar")]).unwrap()
}

fn default_properties(policies: &CedarPolicySet) -> PolicyProperties {
    PolicyProperties::load(policies, &[repo("policies/cedar/properties")]).unwrap()
}

/// The default policies plus `extra`.
fn default_with(extra: &str) -> CedarPolicySet {
    CedarPolicySet::from_sources(
        VAK_SCHEMA,
        &[
            (
                "default.cedar".to_string(),
                read("policies/cedar/default.cedar"),
            ),
            ("extra.cedar".to_string(), extra.to_string()),
        ],
    )
    .unwrap()
}

fn payments(policies: &str) -> CedarPolicySet {
    CedarPolicySet::from_sources(
        &read("policies/cedar/examples/payments.cedarschema"),
        &[("payments.cedar".to_string(), policies.to_string())],
    )
    .unwrap()
}

fn payments_properties(policies: &CedarPolicySet) -> PolicyProperties {
    PolicyProperties::load(
        policies,
        &[repo("policies/cedar/examples/payments.properties.cedar")],
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "needs cvc5 1.3.1 (set CVC5)"]
async fn the_shipped_policies_have_their_properties() {
    let mut analyzer = Analyzer::new().expect(NEEDS_CVC5);

    let policies = default_policies();
    let report = analyzer
        .check(&policies, &default_properties(&policies))
        .await
        .unwrap();
    assert!(report.holds(), "{report}");
    // Three properties, and one never-errors check per policy.
    assert_eq!(report.outcomes.len(), 3 + 4);

    let payments = payments(&read("policies/cedar/examples/payments.cedar"));
    let report = analyzer
        .check(&payments, &payments_properties(&payments))
        .await
        .unwrap();
    assert!(report.holds(), "{report}");
}

#[tokio::test]
#[ignore = "needs cvc5 1.3.1 (set CVC5)"]
async fn a_permit_that_forgets_restricted_tools_breaks_the_ceiling() {
    let mut analyzer = Analyzer::new().expect(NEEDS_CVC5);
    // payments.cedar without its `restricted-tools-never` forbid: a finance
    // agent could still call transfer_funds after it was blocked.
    let shipped = read("policies/cedar/examples/payments.cedar");
    let start = shipped.find("@id(\"restricted-tools-never\")").unwrap();
    let end = shipped
        .find("@id(\"finance-transfers-up-to-1000\")")
        .unwrap();
    let unguarded = payments(&format!("{}{}", &shipped[..start], &shipped[end..]));

    let report = analyzer
        .check(&unguarded, &payments_properties(&unguarded))
        .await
        .unwrap();
    let outcome = report
        .outcome(&Check::Ceiling(
            "restricted-tools-are-never-called".to_string(),
        ))
        .unwrap();
    assert!(!outcome.holds(), "{report}");
    let violation = &outcome.violations[0];
    assert!(violation.confirmed, "the evaluator reproduces it");
    assert!(
        violation.environment.contains("transfer_funds"),
        "{violation:?}"
    );
    assert!(
        violation.counterexample.contains("restricted: true"),
        "{violation:?}"
    );
    // The other ceiling still holds: the gap is only about blocked tools.
    assert!(report
        .outcome(&Check::Ceiling(
            "transfers-are-small-and-by-finance".to_string()
        ))
        .unwrap()
        .holds());
}

#[tokio::test]
#[ignore = "needs cvc5 1.3.1 (set CVC5)"]
async fn a_policy_that_can_fail_to_evaluate_is_reported() {
    let mut analyzer = Analyzer::new().expect(NEEDS_CVC5);
    let shipped = read("policies/cedar/examples/payments.cedar");
    let policies = payments(&format!(
        "{shipped}\n@id(\"fee-check\")\nforbid (principal, action == Vak::Action::\"transfer_funds\", resource)\n\
         when {{ context.arguments.amount * 1000000000000 > 5000000000000000 }};"
    ));

    let report = analyzer
        .check(&policies, &PolicyProperties::default())
        .await
        .unwrap();
    let outcome = report
        .outcome(&Check::NeverErrors("fee-check".to_string()))
        .unwrap();
    assert!(!outcome.holds(), "{report}");
    assert!(outcome.violations[0].confirmed);
    assert_eq!(report.failures().count(), 1, "{report}");
}

#[tokio::test]
#[ignore = "needs cvc5 1.3.1 (set CVC5)"]
async fn a_floor_catches_a_policy_that_takes_access_away() {
    let mut analyzer = Analyzer::new().expect(NEEDS_CVC5);
    let policies = default_with(
        r#"@id("no-echo") forbid (principal, action, resource == Vak::Tool::"echo");"#,
    );
    let report = analyzer
        .check(&policies, &default_properties(&policies))
        .await
        .unwrap();
    let floor = report
        .outcome(&Check::Floor(
            "unrestricted-builtins-stay-callable".to_string(),
        ))
        .unwrap();
    assert!(!floor.holds(), "{report}");
    assert!(floor.violations[0]
        .counterexample
        .contains("Vak::Tool::\"echo\""));
    // Taking access away breaks no ceiling.
    assert_eq!(report.failures().count(), 1, "{report}");
}

fn kernel_config() -> KernelConfig {
    let mut config = KernelConfig::default();
    config.policy.format = PolicyFormat::Cedar;
    config
}

async fn allowed(kernel: &Kernel, tool: &str) -> bool {
    kernel
        .evaluate_policy(
            &AgentId::new(),
            &ToolRequest::new(tool, serde_json::json!({})),
        )
        .await
        .is_allowed()
}

#[tokio::test]
#[ignore = "needs cvc5 1.3.1 (set CVC5)"]
async fn a_reload_that_widens_access_is_refused_and_changes_nothing() {
    let mut analyzer = Analyzer::new().expect(NEEDS_CVC5);
    let config = kernel_config();
    let policies = default_policies();
    let properties = default_properties(&policies);
    let pdp = Arc::new(CedarPolicy::new(policies, &config));
    let kernel = Kernel::builder(config)
        .with_policy(pdp.clone())
        .build()
        .await
        .unwrap();
    assert!(!allowed(&kernel, "dd").await);

    // Drop the forbid on `dd`: wider, and it breaks a ceiling.
    let without_dd = CedarPolicySet::from_sources(
        VAK_SCHEMA,
        &[(
            "default.cedar".to_string(),
            read("policies/cedar/default.cedar")
                .replace("@id(\"forbid-dd\")\nforbid", "@id(\"forbid-dd\")\npermit"),
        )],
    )
    .unwrap();
    let refused = pdp
        .reload_checked(
            without_dd.clone(),
            &properties,
            &mut analyzer,
            Widening::Refuse,
        )
        .await
        .unwrap_err();
    match &refused {
        ReloadRefused::Violations(report) => {
            assert!(!report
                .outcome(&Check::Ceiling(
                    "dangerous-tools-are-never-called".to_string()
                ))
                .unwrap()
                .holds());
            assert!(!report.outcome(&Check::NoWidening).unwrap().holds());
        }
        other => panic!("expected violations, got {other:?}"),
    }
    // Allowing widening doesn't let a broken ceiling through either.
    assert!(pdp
        .reload_checked(without_dd, &properties, &mut analyzer, Widening::Allow)
        .await
        .is_err());
    assert!(
        !allowed(&kernel, "dd").await,
        "the old policies stay in force"
    );
}

#[tokio::test]
#[ignore = "needs cvc5 1.3.1 (set CVC5)"]
async fn a_reload_that_narrows_access_takes_effect() {
    let mut analyzer = Analyzer::new().expect(NEEDS_CVC5);
    let config = kernel_config();
    let policies = default_policies();
    let properties = default_properties(&policies);
    let pdp = Arc::new(CedarPolicy::new(policies, &config));
    let kernel = Kernel::builder(config)
        .with_policy(pdp.clone())
        .build()
        .await
        .unwrap();
    assert!(allowed(&kernel, "shell").await);

    let narrower = default_with(
        r#"@id("no-shell") forbid (principal, action, resource == Vak::Tool::"shell");"#,
    );
    let report = pdp
        .reload_checked(narrower, &properties, &mut analyzer, Widening::Refuse)
        .await
        .unwrap();
    assert!(report.outcome(&Check::NoWidening).unwrap().holds());
    assert!(!allowed(&kernel, "shell").await);
    assert!(allowed(&kernel, "echo").await);

    // Widening back is refused by default, and accepted when allowed: the
    // properties still hold.
    let back = default_policies();
    assert!(pdp
        .reload_checked(back.clone(), &properties, &mut analyzer, Widening::Refuse)
        .await
        .is_err());
    pdp.reload_checked(back, &properties, &mut analyzer, Widening::Allow)
        .await
        .unwrap();
    assert!(allowed(&kernel, "shell").await);
}

#[tokio::test]
#[ignore = "needs cvc5 1.3.1 (set CVC5)"]
async fn a_checked_reload_cannot_change_the_schema() {
    let mut analyzer = Analyzer::new().expect(NEEDS_CVC5);
    let policies = default_policies();
    let properties = default_properties(&policies);
    let pdp = CedarPolicy::new(policies, &kernel_config());

    let other_schema = payments(&read("policies/cedar/examples/payments.cedar"));
    for widening in [Widening::Refuse, Widening::Allow] {
        let refused = pdp
            .reload_checked(other_schema.clone(), &properties, &mut analyzer, widening)
            .await
            .unwrap_err();
        assert_eq!(
            refused,
            ReloadRefused::Analysis(AnalysisError::SchemaChanged),
            "{widening:?}"
        );
    }
    assert!(pdp.policies().tool_actions().next().is_none(), "unchanged");
}

/// Unchecked reloads need no solver.
#[tokio::test]
async fn an_unchecked_reload_takes_effect_on_the_next_decision() {
    let config = kernel_config();
    let pdp = Arc::new(CedarPolicy::new(default_policies(), &config));
    let kernel = Kernel::builder(config)
        .with_policy(pdp.clone())
        .build()
        .await
        .unwrap();
    assert!(allowed(&kernel, "echo").await);

    pdp.reload(default_with(
        r#"@id("no-echo") forbid (principal, action, resource == Vak::Tool::"echo");"#,
    ))
    .await;
    assert!(!allowed(&kernel, "echo").await);
    assert!(pdp.policies().policy_ids().any(|id| id == "no-echo"));
}
