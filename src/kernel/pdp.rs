//! The kernel's built-in policy decision points.
//!
//! [`policy_from_config`] picks one from [`KernelConfig`], which is what
//! [`Kernel::new`](super::Kernel::new) uses:
//!
//! - [`EnforcerPolicy`] when `policy.policy_paths` names policy files
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

use super::config::{DefaultPolicyDecision, KernelConfig};
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

        // `internal` is not yet derived from the agent's identity; every
        // agent is treated as internal. Tracked as K8 in
        // docs/architecture-v2.md.
        let principal = Principal::agent(req.agent_id.to_string())
            .with_attribute("internal", true)
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
