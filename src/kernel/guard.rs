//! Guards: extra checks on a call the policy allowed (Guard stage).
//!
//! After the [`PolicyDecisionPoint`](super::ports::PolicyDecisionPoint)
//! allows a call, [`Kernel::execute`](super::Kernel::execute) runs the
//! registered [`Guard`]s in order, stopping at the first refusal, before it
//! records the decision. A guard can only
//! narrow: it passes, abstains, denies, or asks for human approval. It can
//! never turn a denial into an allow. See `docs/adr/0013`.
//!
//! Each guard declares an [`Assurance`] level, the strength of what it
//! checks. A heuristic guard, such as an LLM judge, can add denials. But
//! `policy.min_assurance` can require that a guard of at least some level
//! *passed* a call, so a heuristic is never the only check on a high-risk
//! tool:
//!
//! ```yaml
//! policy:
//!   min_assurance:
//!     "payment:*": enforced
//! ```
//!
//! The verdict of each guard that ran is recorded in the decision's audit
//! entry ([`AuditEntry::guards`](super::types::AuditEntry::guards)).

use std::collections::BTreeMap;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use super::identity::AgentRecord;
use super::ports::PolicyRequest;
use super::types::{AgentId, PolicyDecision, SessionId, ToolRequest};

/// How strong a guard's check is (`docs/architecture-v2.md` §3.4).
///
/// Ordered from weakest to strongest, so `Assurance::Heuristic <
/// Assurance::Enforced`. A requirement of level *L* is met by a guard of
/// level *L* or above.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Assurance {
    /// Not sound: a prototype or research check.
    Experimental,
    /// A useful signal that can be wrong, such as an LLM judge, a regex or
    /// an entropy score. It must never be the only check on a dangerous
    /// action.
    Heuristic,
    /// Sound but partial: right about what it checks, such as a schema, but
    /// it doesn't check everything.
    Checked,
    /// Deterministic and total, and fails closed.
    Enforced,
}

impl Assurance {
    /// The level's name as configuration spells it (`"enforced"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Assurance::Experimental => "experimental",
            Assurance::Heuristic => "heuristic",
            Assurance::Checked => "checked",
            Assurance::Enforced => "enforced",
        }
    }
}

impl fmt::Display for Assurance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a [`Guard`] is asked to check: a call, and the policy's decision to
/// allow it.
///
/// Marked `#[non_exhaustive]`, like [`PolicyRequest`], so the kernel can hand
/// guards more context (information-flow labels, session history) without
/// breaking them. Construct it with [`GuardRequest::new`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct GuardRequest<'a> {
    /// The agent asking to act.
    pub agent_id: &'a AgentId,
    /// The tool call it wants to make.
    pub request: &'a ToolRequest,
    /// The agent's record. Always set by [`Kernel::execute`](super::Kernel::execute).
    pub principal: Option<&'a AgentRecord>,
    /// The session the call belongs to.
    pub session_id: Option<&'a SessionId>,
    /// What the policy decided: always an allow, since guards only see
    /// calls the policy allowed.
    pub decision: &'a PolicyDecision,
}

impl<'a> GuardRequest<'a> {
    /// The request the policy decided, with its decision.
    #[must_use]
    pub fn new(policy: &PolicyRequest<'a>, decision: &'a PolicyDecision) -> Self {
        Self {
            agent_id: policy.agent_id,
            request: policy.request,
            principal: policy.principal,
            session_id: policy.session_id,
            decision,
        }
    }
}

/// What a guard says about one call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
#[non_exhaustive]
pub enum GuardVerdict {
    /// The guard checked the call and found nothing wrong. Only a pass
    /// counts toward `policy.min_assurance`.
    Pass,
    /// The call is outside what the guard checks. It neither allows nor
    /// denies, and doesn't count toward `policy.min_assurance`.
    Abstain,
    /// The guard refuses the call.
    Deny {
        /// Why.
        reason: String,
    },
    /// The call needs a human's approval. There is no approval channel yet,
    /// so the kernel refuses it (`docs/architecture-v2.md` §5.2).
    Escalate {
        /// What the human would be asked to approve.
        reason: String,
    },
}

impl GuardVerdict {
    /// A denial for `reason`.
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        GuardVerdict::Deny {
            reason: reason.into(),
        }
    }

    /// An escalation for `reason`.
    #[must_use]
    pub fn escalate(reason: impl Into<String>) -> Self {
        GuardVerdict::Escalate {
            reason: reason.into(),
        }
    }

    /// Whether this verdict lets the call go on: a pass or an abstention.
    #[must_use]
    pub fn lets_through(&self) -> bool {
        matches!(self, GuardVerdict::Pass | GuardVerdict::Abstain)
    }
}

/// An extra check on a call the policy allowed (Guard stage).
///
/// # Contract
///
/// - **Fail closed.** A guard that can't reach a verdict, because its model
///   is down or its input won't parse, answers [`GuardVerdict::Deny`], never
///   `Pass`. The kernel also turns a panic, or an answer that comes after
///   `max_execution_time`, into a denial.
/// - **Don't block the thread.** The kernel can stop a guard only where it
///   awaits. A guard that blocks (a slow synchronous call, a lock) can't be
///   interrupted: if it answers late, its answer becomes a denial, but if it
///   never answers, the call waits with it. Do slow work asynchronously, or
///   on `tokio::task::spawn_blocking`.
/// - **Abstain when it isn't yours.** A guard that doesn't check this kind
///   of call answers [`GuardVerdict::Abstain`]. A `Pass` claims the call was
///   checked at the guard's [`Assurance`], and counts toward
///   `policy.min_assurance`.
/// - **No side effects.** The kernel stops at the first refusal, so later
///   guards may not run.
/// - **Unique name.** The kernel refuses to build with two guards of one
///   name. A refusal is recorded as rule `guard.<name>`.
/// - **Fixed identity.** The kernel reads `name` and `assurance` once, when
///   it is built, and records every verdict under them.
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use vak::kernel::guard::{Assurance, Guard, GuardRequest, GuardVerdict};
///
/// /// Refuses any call whose arguments mention a credentials file.
/// #[derive(Debug)]
/// struct NoCredentialFiles;
///
/// #[async_trait]
/// impl Guard for NoCredentialFiles {
///     async fn check(&self, request: &GuardRequest<'_>) -> GuardVerdict {
///         if request.request.parameters.to_string().contains(".aws/credentials") {
///             GuardVerdict::deny("arguments name a credentials file")
///         } else {
///             GuardVerdict::Pass
///         }
///     }
///
///     fn name(&self) -> &str {
///         "no-credential-files"
///     }
///
///     fn assurance(&self) -> Assurance {
///         Assurance::Heuristic
///     }
/// }
/// ```
#[async_trait]
pub trait Guard: Send + Sync + fmt::Debug {
    /// Checks `request`, which the policy has already allowed.
    async fn check(&self, request: &GuardRequest<'_>) -> GuardVerdict;

    /// The guard's name, recorded with each verdict.
    fn name(&self) -> &str;

    /// How strong the guard's check is.
    fn assurance(&self) -> Assurance;
}

/// The signature of a [`FunctionGuard`]'s check.
pub type GuardFn = dyn Fn(&GuardRequest<'_>) -> GuardVerdict + Send + Sync;

/// A [`Guard`] from a synchronous function.
///
/// The function runs on the kernel's executor, so it must be quick and must
/// not block: the kernel can't interrupt it (see [`Guard`]). Write a slow
/// check as an async [`Guard`] instead.
pub struct FunctionGuard {
    name: String,
    assurance: Assurance,
    check: Box<GuardFn>,
}

impl FunctionGuard {
    /// A guard called `name`, at `assurance`, that runs `check`.
    pub fn new(
        name: impl Into<String>,
        assurance: Assurance,
        check: impl Fn(&GuardRequest<'_>) -> GuardVerdict + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.into(),
            assurance,
            check: Box::new(check),
        }
    }
}

impl fmt::Debug for FunctionGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunctionGuard")
            .field("name", &self.name)
            .field("assurance", &self.assurance)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl Guard for FunctionGuard {
    async fn check(&self, request: &GuardRequest<'_>) -> GuardVerdict {
        (self.check)(request)
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn assurance(&self) -> Assurance {
        self.assurance
    }
}

/// One guard's verdict on a call, as recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardCheck {
    /// The guard's name.
    pub guard: String,
    /// The guard's assurance level.
    pub assurance: Assurance,
    /// What it said.
    #[serde(flatten)]
    pub verdict: GuardVerdict,
}

/// What the Guard stage did with a call: recorded in the decision's audit
/// entry ([`AuditEntry::guards`](super::types::AuditEntry::guards)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardChecks {
    /// The level `policy.min_assurance` required for this tool, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<Assurance>,
    /// Each guard that ran, in order. Guards after a refusal don't run.
    pub checks: Vec<GuardCheck>,
}

impl GuardChecks {
    /// Whether a guard of at least `level` passed.
    #[must_use]
    pub fn passed_at(&self, level: Assurance) -> bool {
        self.checks
            .iter()
            .any(|c| c.verdict == GuardVerdict::Pass && c.assurance >= level)
    }
}

/// The level `min_assurance` requires for `tool`: the highest level of any
/// pattern that matches it, or `None`.
#[must_use]
pub fn required_assurance(
    min_assurance: &BTreeMap<String, Assurance>,
    tool: &str,
) -> Option<Assurance> {
    min_assurance
        .iter()
        .filter(|(pattern, _)| tool_pattern_matches(pattern, tool))
        .map(|(_, level)| *level)
        .max()
}

/// Whether a `min_assurance` tool pattern matches `tool`. Patterns are
/// `*`, `prefix*`, `*suffix` or an exact name, as in YAML policy rules.
#[must_use]
pub fn tool_pattern_matches(pattern: &str, tool: &str) -> bool {
    crate::policy::enforcer::pattern_matches(pattern, tool)
}

/// Checks a `min_assurance` level. `experimental` can't be a requirement:
/// an unsound check proves nothing, so a floor it could meet would mean
/// nothing.
///
/// # Errors
///
/// Returns a description of the problem.
pub fn validate_required_level(level: Assurance) -> Result<(), String> {
    if level == Assurance::Experimental {
        return Err(
            "'experimental' can't be required: an unsound check proves nothing; use 'heuristic' or above"
                .to_string(),
        );
    }
    Ok(())
}

/// Checks a `min_assurance` tool pattern. A pattern the matcher can't honour,
/// such as `pay*ment` or `*pay*`, would never match anything, and the
/// requirement would silently not apply.
///
/// # Errors
///
/// Returns a description of the problem.
pub fn validate_tool_pattern(pattern: &str) -> Result<(), String> {
    if pattern.is_empty() {
        return Err("a tool pattern can't be empty".to_string());
    }
    if pattern == "*" {
        return Ok(());
    }
    let inner = pattern
        .strip_suffix('*')
        .or_else(|| pattern.strip_prefix('*'))
        .unwrap_or(pattern);
    if inner.contains('*') {
        return Err(format!(
            "tool pattern '{pattern}' can only use '*' alone, at the start or at the end"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_assurance_orders_weakest_to_strongest() {
        assert!(Assurance::Experimental < Assurance::Heuristic);
        assert!(Assurance::Heuristic < Assurance::Checked);
        assert!(Assurance::Checked < Assurance::Enforced);
    }

    #[test]
    fn test_assurance_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Assurance::Enforced).unwrap(),
            "\"enforced\""
        );
        let parsed: Assurance = serde_json::from_str("\"checked\"").unwrap();
        assert_eq!(parsed, Assurance::Checked);
        assert!(serde_json::from_str::<Assurance>("\"strong\"").is_err());
        assert_eq!(Assurance::Heuristic.to_string(), "heuristic");
    }

    #[test]
    fn test_required_assurance_takes_the_highest_match() {
        let table = BTreeMap::from([
            ("payment:*".to_string(), Assurance::Checked),
            ("payment:refund".to_string(), Assurance::Enforced),
            ("*".to_string(), Assurance::Heuristic),
        ]);
        assert_eq!(
            required_assurance(&table, "payment:refund"),
            Some(Assurance::Enforced)
        );
        assert_eq!(
            required_assurance(&table, "payment:charge"),
            Some(Assurance::Checked)
        );
        assert_eq!(
            required_assurance(&table, "echo"),
            Some(Assurance::Heuristic)
        );
        assert_eq!(required_assurance(&BTreeMap::new(), "echo"), None);
    }

    #[test]
    fn test_tool_patterns() {
        assert!(tool_pattern_matches("payment:*", "payment:charge"));
        assert!(!tool_pattern_matches("payment:*", "refund"));
        assert!(tool_pattern_matches("*_delete", "file_delete"));
        assert!(tool_pattern_matches("echo", "echo"));
        assert!(!tool_pattern_matches("echo", "echo2"));
        for ok in ["*", "payment:*", "*_delete", "echo"] {
            assert!(validate_tool_pattern(ok).is_ok(), "{ok}");
        }
        for bad in ["", "pay*ment", "*pay*", "**"] {
            assert!(validate_tool_pattern(bad).is_err(), "{bad}");
        }
        assert!(validate_required_level(Assurance::Experimental).is_err());
        assert!(validate_required_level(Assurance::Heuristic).is_ok());
    }

    #[test]
    fn test_check_records_round_trip_through_json() {
        let checks = GuardChecks {
            required: Some(Assurance::Enforced),
            checks: vec![
                GuardCheck {
                    guard: "judge".to_string(),
                    assurance: Assurance::Heuristic,
                    verdict: GuardVerdict::Pass,
                },
                GuardCheck {
                    guard: "rules".to_string(),
                    assurance: Assurance::Enforced,
                    verdict: GuardVerdict::deny("no"),
                },
            ],
        };
        let json = serde_json::to_string(&checks).unwrap();
        assert_eq!(
            json,
            r#"{"required":"enforced","checks":[{"guard":"judge","assurance":"heuristic","verdict":"pass"},{"guard":"rules","assurance":"enforced","verdict":"deny","reason":"no"}]}"#
        );
        let back: GuardChecks = serde_json::from_str(&json).unwrap();
        assert_eq!(back, checks);
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn test_only_a_pass_at_the_level_counts() {
        let check = |assurance, verdict| GuardCheck {
            guard: "g".to_string(),
            assurance,
            verdict,
        };
        let checks = GuardChecks {
            required: None,
            checks: vec![
                check(Assurance::Enforced, GuardVerdict::Abstain),
                check(Assurance::Heuristic, GuardVerdict::Pass),
            ],
        };
        assert!(checks.passed_at(Assurance::Heuristic));
        assert!(!checks.passed_at(Assurance::Checked));
        assert!(!checks.passed_at(Assurance::Enforced));
    }

    #[tokio::test]
    async fn test_function_guard() {
        let guard = FunctionGuard::new("no-rm", Assurance::Enforced, |req| {
            if req.request.tool_name == "rm" {
                GuardVerdict::deny("rm")
            } else {
                GuardVerdict::Abstain
            }
        });
        let agent = AgentId::new();
        let allow = PolicyDecision::Allow {
            reason: "test".to_string(),
            constraints: None,
        };
        let rm = ToolRequest::new("rm", serde_json::json!({}));
        let echo = ToolRequest::new("echo", serde_json::json!({}));
        let ask = |tool| GuardRequest::new(&PolicyRequest::new(&agent, tool), &allow);
        assert_eq!(guard.check(&ask(&rm)).await, GuardVerdict::deny("rm"));
        assert_eq!(guard.check(&ask(&echo)).await, GuardVerdict::Abstain);
        assert!(ask(&rm).decision.is_allowed());
        assert_eq!(guard.name(), "no-rm");
        assert_eq!(guard.assurance(), Assurance::Enforced);
        assert!(format!("{guard:?}").contains("no-rm"));
        assert!(GuardVerdict::Abstain.lets_through());
        assert!(!GuardVerdict::escalate("ask").lets_through());
    }
}
