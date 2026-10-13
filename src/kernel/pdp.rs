//! The kernel's built-in policy decision points.
//!
//! [`policy_from_config`] picks one from [`KernelConfig`], which is what
//! [`Kernel::new`](super::Kernel::new) uses:
//!
//! - `CedarPolicy` when `policy.format` is `cedar` (docs/adr/0008; needs
//!   the `cedar` feature). If the schema or policies can't be loaded, a
//!   [`DenyAll`] naming why.
//! - [`EnforcerPolicy`] when `policy.policy_paths` names YAML policy files
//!   (docs/adr/0001). If they can't be loaded, the enforcer denies everything.
//! - [`ConfigPolicy`] otherwise: the blocklist, the allowlist, then
//!   `policy.default_decision`, which defaults to deny.
//!
//! Embedders that want a different engine implement
//! [`PolicyDecisionPoint`] and pass it to
//! [`KernelBuilder::with_policy`](super::KernelBuilder::with_policy).

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{info, warn};

use super::config::{DefaultPolicyDecision, KernelConfig, PolicyFormat};
use super::ports::{PolicyDecisionPoint, PolicyRequest};
use super::types::PolicyDecision;
use super::BUILTIN_TOOLS;
use crate::policy::enforcer::{
    Action as PolicyAction, CedarEnforcer, EnforcerConfig, PolicyContext, Principal, Resource,
};

/// Builds the decision point that `config` describes.
///
/// When `policy.policy_paths` is empty this is a [`ConfigPolicy`], which is
/// stricter than any loaded policy set would be, so skipping the enforcer
/// never widens access. When policy files *are* configured but can't be
/// loaded, the result is an enforcer with no rules, which denies every
/// request: a misconfigured policy path must not silently downgrade to the
/// fallback.
pub async fn policy_from_config(config: &KernelConfig) -> Arc<dyn PolicyDecisionPoint> {
    if config.policy.enabled && config.policy.format == PolicyFormat::Cedar {
        return cedar_from_config(config);
    }
    if !config.policy.enabled || config.policy.policy_paths.is_empty() {
        return Arc::new(ConfigPolicy::new(config.clone()));
    }

    let enforcer = match CedarEnforcer::new(EnforcerConfig::default()) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, "Failed to construct policy enforcer");
            return Arc::new(EnforcerPolicy::new(CedarEnforcer::new_denying(), config));
        }
    };

    // `load_policies` replaces the whole rule set, so loading several files
    // through it would silently keep only the last. Merge instead.
    let mut loaded_any = false;
    for path in &config.policy.policy_paths {
        match enforcer.merge_policies(path).await {
            Ok(count) => {
                info!(path = %path.display(), rules = count, "Loaded policy file");
                loaded_any = true;
            }
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "Failed to load policy file - kernel will deny all requests"
                );
                return Arc::new(EnforcerPolicy::new(CedarEnforcer::new_denying(), config));
            }
        }
    }

    if !loaded_any {
        tracing::error!("No policy rules loaded - kernel will deny all requests");
        return Arc::new(EnforcerPolicy::new(CedarEnforcer::new_denying(), config));
    }

    Arc::new(EnforcerPolicy::new(enforcer, config))
}

/// The Cedar decision point `config` describes, or a [`DenyAll`] saying why
/// there isn't one.
#[cfg(feature = "cedar")]
fn cedar_from_config(config: &KernelConfig) -> Arc<dyn PolicyDecisionPoint> {
    use crate::policy::cedar::CedarPolicySet;

    if config.policy.policy_paths.is_empty() {
        return Arc::new(DenyAll::new(
            "policy.format is cedar, but policy.policy_paths names no policies",
        ));
    }
    match CedarPolicySet::load(
        config.policy.cedar_schema.as_deref(),
        &config.policy.policy_paths,
    ) {
        Ok(policies) => {
            info!(
                policies = policies.policy_ids().count(),
                tool_actions = policies.tool_actions().count(),
                "Loaded Cedar policies"
            );
            Arc::new(CedarPolicy::new(policies, config))
        }
        Err(e) => {
            tracing::error!(error = %e, "Failed to load Cedar policies - kernel will deny all requests");
            Arc::new(DenyAll::new(format!("Cedar policies failed to load: {e}")))
        }
    }
}

/// `KernelConfig::validate` refuses `policy.format: cedar` without the
/// feature; this only keeps a config that skipped validation closed.
#[cfg(not(feature = "cedar"))]
fn cedar_from_config(_config: &KernelConfig) -> Arc<dyn PolicyDecisionPoint> {
    Arc::new(DenyAll::new(
        "policy.format is cedar, but this build of vak lacks the `cedar` feature",
    ))
}

/// Constraints attached to an allowed request, derived from config.
fn execution_constraints(config: &KernelConfig) -> Option<Vec<String>> {
    let mut constraints = Vec::new();

    if config.max_execution_time.as_millis() > 0 {
        constraints.push(format!(
            "max_execution_time_ms:{}",
            config.max_execution_time.as_millis()
        ));
    }
    if config.resources.max_memory_mb > 0 {
        constraints.push(format!("max_memory_mb:{}", config.resources.max_memory_mb));
    }
    if config.security.enable_sandboxing {
        constraints.push("sandboxed:true".to_string());
    }

    if constraints.is_empty() {
        None
    } else {
        Some(constraints)
    }
}

/// Decides from `KernelConfig` alone: blocklist, allowlist, then the default
/// decision.
///
/// 1. A tool in `security.blocked_tools` is denied.
/// 2. If `security.allowed_tools` is non-empty, a tool not in it is denied.
/// 3. If `policy.enabled` is false, the request is allowed.
/// 4. A tool in the allowlist is allowed.
/// 5. Anything else gets `policy.default_decision`, which defaults to deny.
#[derive(Debug, Clone)]
pub struct ConfigPolicy {
    config: KernelConfig,
}

impl ConfigPolicy {
    /// Creates a decision point over `config`.
    #[must_use]
    pub fn new(config: KernelConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl PolicyDecisionPoint for ConfigPolicy {
    async fn decide(&self, req: &PolicyRequest<'_>) -> PolicyDecision {
        let tool = &req.request.tool_name;
        let security = &self.config.security;

        if security.blocked_tools.contains(tool) {
            warn!(tool = %tool, "Tool is in blocked list");
            return PolicyDecision::Deny {
                reason: format!("Tool '{tool}' is blocked by security policy"),
                violated_policies: Some(vec!["security.blocked_tools".to_string()]),
            };
        }

        if !security.allowed_tools.is_empty() && !security.allowed_tools.contains(tool) {
            warn!(tool = %tool, "Tool not in allowed list");
            return PolicyDecision::Deny {
                reason: format!("Tool '{tool}' is not in the allowed tools list"),
                violated_policies: Some(vec!["security.allowed_tools".to_string()]),
            };
        }

        if !self.config.policy.enabled {
            return PolicyDecision::Allow {
                reason: "Policy enforcement is disabled".to_string(),
                constraints: None,
            };
        }

        // No rule matched. Fall back to the configured default decision rather
        // than allowing: `deny` is the documented default, and a kernel whose
        // whole premise is "no policy = no access" must not fail open.
        //
        // An explicit allowlist entry counts as a matching allow rule; anything
        // else reaching this point is unmatched.
        if !security.allowed_tools.contains(tool) {
            match self.config.policy.default_decision {
                DefaultPolicyDecision::Deny => {
                    warn!(tool = %tool, "No policy rule matched; denying by default");
                    return PolicyDecision::Deny {
                        reason: format!(
                            "No policy rule permits tool '{tool}' (default decision is deny)"
                        ),
                        violated_policies: Some(vec!["policy.default_decision".to_string()]),
                    };
                }
                DefaultPolicyDecision::Allow => {
                    warn!(
                        tool = %tool,
                        "No policy rule matched; allowing because default decision is allow"
                    );
                }
            }
        }

        PolicyDecision::Allow {
            reason: format!("Agent {} authorized to execute tool '{tool}'", req.agent_id),
            constraints: execution_constraints(&self.config),
        }
    }

    fn name(&self) -> &str {
        "config"
    }
}

/// Decides with a [`CedarEnforcer`] over YAML policy files (docs/adr/0001).
///
/// The kernel supplies the entity attributes that policy conditions read.
/// Nothing else populates them, so without this the shipped
/// `default_policies.yaml`, whose only tool-permit rule is guarded by
/// `resource.restricted == false`, could never grant anything.
#[derive(Debug)]
pub struct EnforcerPolicy {
    enforcer: CedarEnforcer,
    blocked_tools: Vec<String>,
    constraints: Option<Vec<String>>,
}

impl EnforcerPolicy {
    /// Wraps an enforcer, taking the attributes it needs from `config`.
    #[must_use]
    pub fn new(enforcer: CedarEnforcer, config: &KernelConfig) -> Self {
        Self {
            enforcer,
            blocked_tools: config.security.blocked_tools.clone(),
            constraints: execution_constraints(config),
        }
    }
}

#[async_trait]
impl PolicyDecisionPoint for EnforcerPolicy {
    async fn decide(&self, req: &PolicyRequest<'_>) -> PolicyDecision {
        let tool = &req.request.tool_name;

        // Principal attributes come from the agent's record (docs/adr/0003).
        // This used to be a constant `internal = true` for every agent (K8).
        // Without a record nothing is known, so nothing is assumed.
        let mut principal = Principal::agent(req.agent_id.to_string());
        if let Some(record) = req.principal {
            for (key, value) in &record.attributes {
                principal = principal.with_attribute(key.clone(), value.clone());
            }
        }
        // Set last, so a record attribute can't override what the kernel
        // knows.
        let principal = principal
            .with_attribute("internal", req.principal.is_some_and(|r| r.internal))
            .with_attribute("id", req.agent_id.to_string());

        let resource = Resource::tool(tool.clone())
            .with_attribute("restricted", self.blocked_tools.contains(tool))
            .with_attribute("internal", BUILTIN_TOOLS.contains(&tool.as_str()))
            .with_attribute("owner", principal.to_entity_uid());

        let action = PolicyAction::tool_execute();
        let context = PolicyContext::new().with_current_time();

        match self
            .enforcer
            .authorize(&principal, &action, &resource, Some(&context))
            .await
        {
            Ok(decision) if decision.is_allowed() => PolicyDecision::Allow {
                reason: decision.reason.clone(),
                constraints: self.constraints.clone(),
            },
            Ok(decision) => PolicyDecision::Deny {
                reason: decision.reason.clone(),
                violated_policies: decision.matched_policy.map(|p| vec![p]),
            },
            Err(e) => {
                // An evaluation failure is not permission.
                tracing::error!(error = %e, tool = %tool, "Policy evaluation failed - denying");
                PolicyDecision::Deny {
                    reason: format!("Policy evaluation failed: {e}"),
                    violated_policies: None,
                }
            }
        }
    }

    fn name(&self) -> &str {
        "cedar-enforcer"
    }
}

/// Denies every request, giving the same reason each time. What the kernel
/// decides with when the configured policies can't be loaded: a policy that
/// can't be read must not become no policy at all.
#[derive(Debug, Clone)]
pub struct DenyAll {
    reason: String,
}

impl DenyAll {
    /// A decision point that denies everything because of `reason`.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

#[async_trait]
impl PolicyDecisionPoint for DenyAll {
    async fn decide(&self, _req: &PolicyRequest<'_>) -> PolicyDecision {
        PolicyDecision::Deny {
            reason: self.reason.clone(),
            violated_policies: None,
        }
    }

    fn name(&self) -> &str {
        "deny-all"
    }
}

/// Decides with Cedar policies, evaluated by the `cedar-policy` crate
/// (docs/adr/0008).
///
/// The principal's attributes come from its agent record, and the tool's
/// from config: `restricted` from `security.blocked_tools`, `builtin` from
/// the kernel's built-in tools. Anything Cedar can't decide cleanly (a call
/// that doesn't match the schema, a policy that fails to evaluate) is denied.
///
/// The policy set can be replaced while the kernel runs. Each decision uses
/// one set throughout; a reload takes effect from the next decision. With
/// the `cedar-analysis` feature, [`CedarPolicy::reload_checked`] swaps a new
/// set in only once SymCC has proven it safe (docs/adr/0009). To reload, keep
/// an `Arc<CedarPolicy>` and give the kernel a clone with
/// [`KernelBuilder::with_policy`](super::KernelBuilder::with_policy).
#[cfg(feature = "cedar")]
#[derive(Debug)]
pub struct CedarPolicy {
    policies: arc_swap::ArcSwap<crate::policy::cedar::CedarPolicySet>,
    /// Serialises reloads, so a checked reload is checked against the set it
    /// replaces.
    reloading: tokio::sync::Mutex<()>,
    blocked_tools: Vec<String>,
    constraints: Option<Vec<String>>,
}

#[cfg(feature = "cedar")]
impl CedarPolicy {
    /// Decides with `policies`, taking tool attributes and execution
    /// constraints from `config`.
    #[must_use]
    pub fn new(policies: crate::policy::cedar::CedarPolicySet, config: &KernelConfig) -> Self {
        Self {
            policies: arc_swap::ArcSwap::from_pointee(policies),
            reloading: tokio::sync::Mutex::new(()),
            blocked_tools: config.security.blocked_tools.clone(),
            constraints: execution_constraints(config),
        }
    }

    /// The policies this decision point currently decides with.
    #[must_use]
    pub fn policies(&self) -> Arc<crate::policy::cedar::CedarPolicySet> {
        self.policies.load_full()
    }

    /// Replaces the policies without analysing them. The new set was
    /// validated against its schema when it was loaded; nothing else is
    /// checked. Prefer [`CedarPolicy::reload_checked`] where cvc5 is
    /// available.
    pub async fn reload(&self, policies: crate::policy::cedar::CedarPolicySet) {
        let _reloading = self.reloading.lock().await;
        self.policies.store(Arc::new(policies));
        info!("Cedar policies reloaded without analysis");
    }

    /// Replaces the policies only if SymCC proves, for every request the
    /// schema admits, that `properties` hold of them, that none of them
    /// ever errors, and (unless `widening` allows it) that they allow
    /// nothing the current policies don't. Otherwise the current policies
    /// stay in force.
    ///
    /// # Errors
    ///
    /// [`ReloadRefused`](crate::policy::cedar::analysis::ReloadRefused),
    /// with the failing checks and their counterexamples, or with why the
    /// analysis couldn't run.
    #[cfg(feature = "cedar-analysis")]
    pub async fn reload_checked(
        &self,
        policies: crate::policy::cedar::CedarPolicySet,
        properties: &crate::policy::cedar::analysis::PolicyProperties,
        analyzer: &mut crate::policy::cedar::analysis::Analyzer,
        widening: crate::policy::cedar::analysis::Widening,
    ) -> Result<
        crate::policy::cedar::analysis::AnalysisReport,
        crate::policy::cedar::analysis::ReloadRefused,
    > {
        let _reloading = self.reloading.lock().await;
        let current = self.policies.load_full();
        match crate::policy::cedar::analysis::check_reload(
            analyzer, &current, &policies, properties, widening,
        )
        .await
        {
            Ok(report) => {
                self.policies.store(Arc::new(policies));
                info!(
                    checks = report.outcomes.len(),
                    "Cedar policies reloaded after analysis"
                );
                Ok(report)
            }
            Err(refused) => {
                warn!(error = %refused, "Cedar policy reload refused; current policies stay in force");
                Err(refused)
            }
        }
    }
}

#[cfg(feature = "cedar")]
#[async_trait]
impl PolicyDecisionPoint for CedarPolicy {
    async fn decide(&self, req: &PolicyRequest<'_>) -> PolicyDecision {
        use crate::policy::cedar::{CedarDecision, CedarRequest};
        use std::collections::HashMap;

        let tool = &req.request.tool_name;
        let agent_id = req.agent_id.to_string();
        let session = req.session_id.map(ToString::to_string).unwrap_or_default();
        let no_attributes = HashMap::new();
        // Without a record nothing is known about the agent, so nothing is
        // assumed.
        let (agent_name, internal, attributes) = match req.principal {
            Some(record) => (record.name.as_str(), record.internal, &record.attributes),
            None => ("", false, &no_attributes),
        };

        let decision = self.policies.load().authorize(&CedarRequest {
            agent_id: &agent_id,
            agent_name,
            internal,
            attributes,
            tool,
            restricted: self.blocked_tools.contains(tool),
            builtin: BUILTIN_TOOLS.contains(&tool.as_str()),
            session: &session,
            arguments: &req.request.parameters,
        });

        match decision {
            CedarDecision::Allow { policies } => PolicyDecision::Allow {
                reason: format!("Permitted by Cedar policy {}", policies.join(", ")),
                constraints: self.constraints.clone(),
            },
            CedarDecision::Forbid { policies } => {
                warn!(tool = %tool, policies = ?policies, "Forbidden by Cedar policy");
                PolicyDecision::Deny {
                    reason: format!("Forbidden by Cedar policy {}", policies.join(", ")),
                    violated_policies: Some(policies),
                }
            }
            CedarDecision::NotPermitted => PolicyDecision::Deny {
                reason: format!("No Cedar policy permits tool '{tool}' (default deny)"),
                violated_policies: None,
            },
            CedarDecision::Error { reason, policies } => {
                tracing::error!(tool = %tool, error = %reason, "Cedar could not decide - denying");
                PolicyDecision::Deny {
                    reason: format!("Cedar could not decide: {reason}"),
                    violated_policies: (!policies.is_empty()).then_some(policies),
                }
            }
        }
    }

    fn name(&self) -> &str {
        "cedar"
    }
}
