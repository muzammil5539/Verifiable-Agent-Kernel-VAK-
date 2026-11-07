//! Datalog Safety Rules Engine (NSR-001, NSR-002)
//!
//! This module provides a Datalog-based safety verification system. Its
//! built-in rules are a Datalog program, compiled by the Ascent crate and
//! evaluated to a fixpoint for each check: joins, recursion (the directories
//! a path lies in), stratified negation (an agent *without* a capability)
//! and aggregation (an agent's highest risk score). It used to be a list of
//! Rust closures (finding V3, `docs/adr/0020`).
//!
//! # Architecture
//!
//! The Datalog engine operates in the "Neuro-Symbolic Sandwich":
//! 1. Neural: LLM proposes an action
//! 2. Symbolic: Datalog validates against safety rules
//! 3. Execute: Only if validation passes
//!
//! # Features
//!
//! - Compile-time Datalog rules (Ascent), evaluated to a fixpoint
//! - Paths, endpoints and commands compared in canonical form
//! - Safety violation detection before action execution, on the kernel's
//!   request path as [`DatalogGuard`]
//! - Risk-based access control integration
//! - File and network access restrictions
//! - Custom rule definitions
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::reasoner::datalog::{SafetyEngine, Fact, SafetyVerdict};
//!
//! let mut engine = SafetyEngine::new();
//!
//! // Add facts about the environment
//! engine.add_fact(Fact::critical_file("/etc/shadow"));
//! engine.add_fact(Fact::critical_file("/etc/passwd"));
//!
//! // Check if an action is safe
//! let verdict = engine.check_action("delete_file", "/etc/shadow");
//! assert!(verdict.is_violation());
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.4.1: Neuro-Symbolic Hybrid Architecture
//! - Gap Analysis Section 6.2: The Neuro-Symbolic "Safety Valve"
//! - Ascent: Sahebolamri, Gilray and Micinski, "Seamless Deductive
//!   Inference via Macros", CC 2022; https://github.com/s-arash/ascent

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur in the Datalog engine
#[derive(Debug, Error)]
pub enum DatalogError {
    /// Invalid fact
    #[error("Invalid fact: {0}")]
    InvalidFact(String),

    /// Rule evaluation error
    #[error("Rule evaluation error: {0}")]
    EvaluationError(String),

    /// Unknown action type
    #[error("Unknown action type: {0}")]
    UnknownAction(String),
}

/// Result type for Datalog operations
pub type DatalogResult<T> = Result<T, DatalogError>;

/// Canonicalise a path lexically, without touching the filesystem (finding V3).
///
/// Collapses repeated separators, drops `.` components, resolves `..`, and
/// cuts the path at the first NUL byte (a C filesystem call would stop there).
/// An absolute path cannot climb above `/`. A relative path keeps leading
/// `..` components, because the working directory is unknown. The empty
/// relative path becomes `.`.
///
/// Symlinks and case-insensitive filesystems are out of scope: resolving them
/// needs the filesystem, which a pure rule check must not read.
pub fn canonical_path(path: &str) -> String {
    let path = path.split('\0').next().unwrap_or("");
    let absolute = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(parts.last(), Some(&last) if last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    match (absolute, parts.is_empty()) {
        (true, true) => "/".to_string(),
        (false, true) => ".".to_string(),
        (true, false) => format!("/{}", parts.join("/")),
        (false, false) => parts.join("/"),
    }
}

/// A fact in the Datalog knowledge base
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Fact {
    /// A file is marked as critical (cannot be deleted/modified)
    CriticalFile(String),

    /// A file is marked as sensitive (restricted access)
    SensitiveFile(String),

    /// A path is a system path
    SystemPath(String),

    /// An endpoint is external (requires extra validation)
    ExternalEndpoint(String),

    /// An endpoint is internal (trusted)
    InternalEndpoint(String),

    /// An agent has a specific capability
    AgentCapability {
        /// Unique identifier of the agent
        agent_id: String,
        /// The capability the agent possesses
        capability: String,
    },

    /// An agent has a risk score (stored as integer basis points for Hash/Eq)
    AgentRiskScore {
        /// Unique identifier of the agent
        agent_id: String,
        /// Risk score in basis points (1/100th of a percent)
        score_bp: u32,
    },

    /// A tool is available
    AvailableTool(String),

    /// A tool is restricted
    RestrictedTool(String),

    /// An action was proposed
    ProposedAction {
        /// Type of the proposed action
        action_type: String,
        /// Target of the proposed action
        target: String,
        /// Identifier of the agent proposing the action
        agent_id: String,
    },

    /// Custom fact with key-value
    Custom {
        /// Predicate name for the custom fact
        predicate: String,
        /// Arguments for the custom fact
        args: Vec<String>,
    },
}

impl PartialEq for Fact {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Fact::CriticalFile(a), Fact::CriticalFile(b)) => a == b,
            (Fact::SensitiveFile(a), Fact::SensitiveFile(b)) => a == b,
            (Fact::SystemPath(a), Fact::SystemPath(b)) => a == b,
            (Fact::ExternalEndpoint(a), Fact::ExternalEndpoint(b)) => a == b,
            (Fact::InternalEndpoint(a), Fact::InternalEndpoint(b)) => a == b,
            (
                Fact::AgentCapability {
                    agent_id: a1,
                    capability: c1,
                },
                Fact::AgentCapability {
                    agent_id: a2,
                    capability: c2,
                },
            ) => a1 == a2 && c1 == c2,
            (
                Fact::AgentRiskScore {
                    agent_id: a1,
                    score_bp: s1,
                },
                Fact::AgentRiskScore {
                    agent_id: a2,
                    score_bp: s2,
                },
            ) => a1 == a2 && s1 == s2,
            (Fact::AvailableTool(a), Fact::AvailableTool(b)) => a == b,
            (Fact::RestrictedTool(a), Fact::RestrictedTool(b)) => a == b,
            (
                Fact::ProposedAction {
                    action_type: a1,
                    target: t1,
                    agent_id: ag1,
                },
                Fact::ProposedAction {
                    action_type: a2,
                    target: t2,
                    agent_id: ag2,
                },
            ) => a1 == a2 && t1 == t2 && ag1 == ag2,
            (
                Fact::Custom {
                    predicate: p1,
                    args: a1,
                },
                Fact::Custom {
                    predicate: p2,
                    args: a2,
                },
            ) => p1 == p2 && a1 == a2,
            _ => false,
        }
    }
}

impl Eq for Fact {}

impl std::hash::Hash for Fact {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::mem::discriminant(self).hash(state);
        match self {
            Fact::CriticalFile(s) => s.hash(state),
            Fact::SensitiveFile(s) => s.hash(state),
            Fact::SystemPath(s) => s.hash(state),
            Fact::ExternalEndpoint(s) => s.hash(state),
            Fact::InternalEndpoint(s) => s.hash(state),
            Fact::AgentCapability {
                agent_id,
                capability,
            } => {
                agent_id.hash(state);
                capability.hash(state);
            }
            Fact::AgentRiskScore { agent_id, score_bp } => {
                agent_id.hash(state);
                score_bp.hash(state);
            }
            Fact::AvailableTool(s) => s.hash(state),
            Fact::RestrictedTool(s) => s.hash(state),
            Fact::ProposedAction {
                action_type,
                target,
                agent_id,
            } => {
                action_type.hash(state);
                target.hash(state);
                agent_id.hash(state);
            }
            Fact::Custom { predicate, args } => {
                predicate.hash(state);
                args.hash(state);
            }
        }
    }
}

impl Fact {
    /// The fact with its paths, endpoints and commands canonicalised
    /// (finding V3). The engine stores and looks up facts in this form.
    fn canonical(self) -> Self {
        match self {
            Fact::CriticalFile(p) => Fact::CriticalFile(canonical_path(&p)),
            Fact::SensitiveFile(p) => Fact::SensitiveFile(canonical_path(&p)),
            Fact::SystemPath(p) => Fact::SystemPath(canonical_path(&p)),
            Fact::ExternalEndpoint(e) => Fact::ExternalEndpoint(canonical_endpoint(&e)),
            Fact::InternalEndpoint(e) => Fact::InternalEndpoint(canonical_endpoint(&e)),
            Fact::RestrictedTool(t) => Fact::RestrictedTool(canonical_command(&t)),
            other => other,
        }
    }

    /// Create a critical file fact
    pub fn critical_file(path: impl Into<String>) -> Self {
        Fact::CriticalFile(path.into())
    }

    /// Create a sensitive file fact
    pub fn sensitive_file(path: impl Into<String>) -> Self {
        Fact::SensitiveFile(path.into())
    }

    /// Create a system path fact
    pub fn system_path(path: impl Into<String>) -> Self {
        Fact::SystemPath(path.into())
    }

    /// Create an external endpoint fact
    pub fn external_endpoint(url: impl Into<String>) -> Self {
        Fact::ExternalEndpoint(url.into())
    }

    /// Create an agent capability fact
    pub fn agent_capability(agent_id: impl Into<String>, capability: impl Into<String>) -> Self {
        Fact::AgentCapability {
            agent_id: agent_id.into(),
            capability: capability.into(),
        }
    }

    /// Create an agent risk score fact (score is 0.0-1.0, stored as basis points 0-10000)
    pub fn agent_risk(agent_id: impl Into<String>, score: f64) -> Self {
        Fact::AgentRiskScore {
            agent_id: agent_id.into(),
            score_bp: (score.clamp(0.0, 1.0) * 10000.0) as u32,
        }
    }

    /// Create a custom fact
    pub fn custom(predicate: impl Into<String>, args: Vec<String>) -> Self {
        Fact::Custom {
            predicate: predicate.into(),
            args,
        }
    }
}

/// Represents a safety rule violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Rule that was violated
    pub rule_id: String,
    /// Human-readable description
    pub description: String,
    /// Severity level (0.0 - 1.0)
    pub severity: f64,
    /// Action that caused the violation
    pub action: String,
    /// Target of the action
    pub target: String,
    /// Facts that led to this violation
    pub triggering_facts: Vec<String>,
}

impl Violation {
    /// Create a new violation
    pub fn new(
        rule_id: impl Into<String>,
        description: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
    ) -> Self {
        Self {
            rule_id: rule_id.into(),
            description: description.into(),
            severity: 1.0,
            action: action.into(),
            target: target.into(),
            triggering_facts: Vec::new(),
        }
    }

    /// Set severity
    pub fn with_severity(mut self, severity: f64) -> Self {
        self.severity = severity.clamp(0.0, 1.0);
        self
    }

    /// Add triggering fact
    pub fn with_fact(mut self, fact: impl Into<String>) -> Self {
        self.triggering_facts.push(fact.into());
        self
    }
}

/// Result of safety verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SafetyVerdict {
    /// Action is safe to proceed
    Safe,

    /// Action violates safety rules
    Violation(Vec<Violation>),

    /// Action requires additional review (warning)
    Warning {
        /// Description of the warning condition
        message: String,
        /// Computed risk score for the action
        risk_score: f64,
    },

    /// Could not determine safety (fail-closed: treat as unsafe)
    Unknown(String),
}

impl SafetyVerdict {
    /// Check if safe
    pub fn is_safe(&self) -> bool {
        matches!(self, SafetyVerdict::Safe)
    }

    /// Check if violation
    pub fn is_violation(&self) -> bool {
        matches!(self, SafetyVerdict::Violation(_))
    }

    /// Check if warning
    pub fn is_warning(&self) -> bool {
        matches!(self, SafetyVerdict::Warning { .. })
    }

    /// Get violations if any
    pub fn violations(&self) -> Option<&[Violation]> {
        match self {
            SafetyVerdict::Violation(v) => Some(v),
            _ => None,
        }
    }
}

/// A rule added with [`SafetyEngine::add_rule`]: a Rust check, run after
/// the built-in Datalog program.
#[derive(Debug, Clone)]
pub struct SafetyRule {
    /// Unique rule ID
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Action types this rule applies to (`"*"` for every action)
    pub applies_to: Vec<String>,
    /// The check function
    checker: RuleChecker,
}

type RuleChecker = fn(&SafetyEngine, &str, &str, &str) -> Option<Violation>;

impl SafetyRule {
    /// Create a new safety rule
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        applies_to: Vec<String>,
        checker: RuleChecker,
    ) -> Self {
        Self {
            id: id.into(),
            description: description.into(),
            applies_to,
            checker,
        }
    }
}

// The built-in rules (finding V3)

/// Deleting a critical file.
pub const RULE_001_CRITICAL_DELETE: &str = "RULE_001_CRITICAL_DELETE";
/// Modifying a critical file.
pub const RULE_002_CRITICAL_MODIFY: &str = "RULE_002_CRITICAL_MODIFY";
/// Reading a sensitive file.
pub const RULE_003_SENSITIVE_ACCESS: &str = "RULE_003_SENSITIVE_ACCESS";
/// A request to an external endpoint.
pub const RULE_004_EXTERNAL_NETWORK: &str = "RULE_004_EXTERNAL_NETWORK";
/// Running a restricted tool.
pub const RULE_005_RESTRICTED_TOOL: &str = "RULE_005_RESTRICTED_TOOL";
/// Writing in a system path.
pub const RULE_006_SYSTEM_PATH: &str = "RULE_006_SYSTEM_PATH";
/// Network access by an agent whose risk is over `block_threshold`.
pub const RULE_007_HIGH_RISK_NETWORK: &str = "RULE_007_HIGH_RISK_NETWORK";
/// An external API call by an agent whose risk is over 0.5.
pub const RULE_008_RISK_EXTERNAL_API: &str = "RULE_008_RISK_EXTERNAL_API";
/// Network access by an agent without the `network` capability.
pub const RULE_009_NETWORK_CAPABILITY: &str = "RULE_009_NETWORK_CAPABILITY";

/// A built-in rule's ID, description and the actions it applies to. Its
/// logic is a rule of [`program::SafetyProgram`].
struct BuiltinRule {
    id: &'static str,
    description: &'static str,
    actions: &'static [&'static str],
}

/// The built-in rules, in the order their violations are reported.
const BUILTIN_RULES: [BuiltinRule; 9] = [
    BuiltinRule {
        id: RULE_001_CRITICAL_DELETE,
        description: "Cannot delete critical system files",
        actions: &["delete_file", "remove"],
    },
    BuiltinRule {
        id: RULE_002_CRITICAL_MODIFY,
        description: "Cannot modify critical system files",
        actions: &["write_file", "modify", "append"],
    },
    BuiltinRule {
        id: RULE_003_SENSITIVE_ACCESS,
        description: "Cannot access sensitive files without proper capability",
        actions: &["read_file", "open"],
    },
    BuiltinRule {
        id: RULE_004_EXTERNAL_NETWORK,
        description: "External network requests require validation",
        actions: &["http_request", "network_call"],
    },
    BuiltinRule {
        id: RULE_005_RESTRICTED_TOOL,
        description: "Cannot use restricted tools",
        actions: &["execute_tool", "call_tool"],
    },
    BuiltinRule {
        id: RULE_006_SYSTEM_PATH,
        description: "System path operations are restricted",
        actions: &["write_file", "delete_file", "create_dir"],
    },
    BuiltinRule {
        id: RULE_007_HIGH_RISK_NETWORK,
        description: "High-risk agents cannot make network requests",
        actions: &["http_request", "network_call", "fetch", "socket_connect"],
    },
    BuiltinRule {
        id: RULE_008_RISK_EXTERNAL_API,
        description: "Risk-based external API access control",
        actions: &["http_request", "api_call"],
    },
    BuiltinRule {
        id: RULE_009_NETWORK_CAPABILITY,
        description: "Network operations require network capability",
        actions: &[
            "http_request",
            "network_call",
            "fetch",
            "socket_connect",
            "dns_lookup",
        ],
    },
];

/// The capability network actions need (rule 9).
const NETWORK: &str = "network";

/// Risk above this many basis points makes an external API call a
/// violation (rule 8).
const EXTERNAL_API_RISK_BP: i64 = 5_000;

/// The directory a canonical path lies in, or `None` at the top: `/`, `.`,
/// a single relative component (whose base is unknown), or a path ending in
/// `..`.
fn parent_dir(path: &str) -> Option<String> {
    let (head, last) = path.rsplit_once('/')?;
    if last == ".." || last.is_empty() {
        return None;
    }
    Some(if head.is_empty() { "/" } else { head }.to_string())
}

/// Every relative suffix of a canonical path, by whole components:
/// `/home/user/.env` gives `home/user/.env`, `user/.env` and `.env`.
fn relative_suffixes(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    (0..parts.len())
        .map(|i| parts.iter().skip(i).copied().collect::<Vec<_>>().join("/"))
        .collect()
}

/// Canonicalise an endpoint for comparison (finding V3).
///
/// A URL with a host is parsed and reserialised, which lowercases the
/// scheme and host, drops a default port and resolves dot segments; its
/// fragment is dropped. Anything else is only trimmed.
pub fn canonical_endpoint(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    match reqwest::Url::parse(endpoint) {
        Ok(mut url) if url.has_host() => {
            url.set_fragment(None);
            url.into()
        }
        _ => endpoint.to_string(),
    }
}

/// Whether the canonical `target` is at the canonical `endpoint`: on its
/// host, on any scheme or port, at its path or under it. Non-URLs compare
/// exactly.
fn endpoint_within(target: &str, endpoint: &str) -> bool {
    use reqwest::Url;
    let host = |url: &Url| {
        url.host_str()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
    };
    match (Url::parse(target), Url::parse(endpoint)) {
        (Ok(t), Ok(e)) if t.has_host() && e.has_host() => {
            // A URL's path starts with `/`, so a root endpoint (`""` here)
            // covers every path on its host.
            let base = e.path().trim_end_matches('/');
            host(&t) == host(&e)
                && (t.path() == base
                    || t.path()
                        .strip_prefix(base)
                        .is_some_and(|rest| rest.starts_with('/')))
        }
        _ => target == endpoint,
    }
}

/// A command with its whitespace collapsed, for comparison.
fn canonical_command(command: &str) -> String {
    command.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Whether `command` runs the restricted `tool`: its words start with the
/// tool's, so `rm -rf /tmp` runs `rm -rf`, and `ddrescue` doesn't run `dd`.
fn runs_restricted(command: &str, tool: &str) -> bool {
    let tool: Vec<&str> = tool.split_whitespace().collect();
    let command: Vec<&str> = command.split_whitespace().collect();
    !tool.is_empty() && command.starts_with(&tool)
}

/// `block_threshold` in basis points. A risk score `r` (in basis points
/// `bp`) is over the threshold `t` exactly when `bp > floor(t * 10_000)`.
/// NaN, which no score is over, becomes the lowest value, so a broken
/// threshold blocks rather than allows.
fn threshold_bp(threshold: f64) -> i64 {
    if threshold.is_nan() {
        i64::MIN
    } else {
        // Saturating: infinities become i64::MIN and i64::MAX.
        (threshold * 10_000.0).floor() as i64
    }
}

/// The built-in rules as a Datalog program, evaluated by Ascent to a
/// fixpoint (semi-naive, with stratified negation and aggregation).
mod program {
    use super::{
        canonical_endpoint, canonical_path, endpoint_within, parent_dir, relative_suffixes,
        runs_restricted, EXTERNAL_API_RISK_BP, NETWORK, RULE_001_CRITICAL_DELETE,
        RULE_002_CRITICAL_MODIFY, RULE_003_SENSITIVE_ACCESS, RULE_004_EXTERNAL_NETWORK,
        RULE_005_RESTRICTED_TOOL, RULE_006_SYSTEM_PATH, RULE_007_HIGH_RISK_NETWORK,
        RULE_008_RISK_EXTERNAL_API, RULE_009_NETWORK_CAPABILITY,
    };

    ascent::ascent! {
        pub(super) struct SafetyProgram;

        // Inputs: the action checked, which rules apply to which actions,
        // and the knowledge base (paths and endpoints canonical).
        relation proposed(String, String, String); // action, target, agent
        relation applies(&'static str, String); // rule, action
        relation critical_file(String);
        relation sensitive_file(String); // an absolute path, or a relative pattern
        relation system_path(String);
        relation external_endpoint(String);
        relation restricted_tool(String);
        relation capability(String, String); // agent, capability
        relation risk(String, i64); // agent, basis points
        relation block_above(i64); // basis points

        // Paths: each target's canonical form, and every directory it is in.
        relation canon(String, String); // target, canonical path
        relation node(String);
        relation parent(String, String);
        relation within(String, String); // path, itself or a directory above it
        relation suffix(String, String); // path, a relative suffix of it
        relation sensitive(String, String); // path, the pattern it matches

        canon(t.clone(), canonical_path(t)) <-- proposed(_, t, _);
        node(c.clone()) <-- canon(_, c);
        parent(c.clone(), p) <-- node(c), if let Some(p) = parent_dir(c);
        node(p.clone()) <-- parent(_, p);
        within(c.clone(), c.clone()) <-- node(c);
        within(c.clone(), a.clone()) <-- parent(c, p), within(p, a);
        suffix(c.clone(), s) <-- canon(_, c), for s in relative_suffixes(c);
        sensitive(c.clone(), c.clone()) <-- canon(_, c), sensitive_file(c), if c.starts_with('/');
        sensitive(c.clone(), p.clone()) <-- suffix(c, p), sensitive_file(p);

        // Endpoints and commands.
        relation endpoint(String, String); // target, canonical endpoint
        relation external(String, String); // target, the endpoint it is at
        relation restricted(String, String); // target, the tool it runs
        endpoint(t.clone(), canonical_endpoint(t)) <-- proposed(_, t, _);
        external(t.clone(), e.clone()) <--
            endpoint(t, k), external_endpoint(e), if endpoint_within(k, e);
        restricted(t.clone(), x.clone()) <--
            proposed(_, t, _), restricted_tool(x), if runs_restricted(t, x);

        // Each agent's risk: the highest score recorded for it, else 0.
        relation agent(String);
        relation max_risk(String, i64);
        agent(ag.clone()) <-- proposed(_, _, ag);
        max_risk(ag.clone(), m) <--
            agent(ag), agg m = ascent::aggregators::max(bp) in risk(ag, bp);
        max_risk(ag.clone(), 0) <-- agent(ag), !risk(ag, _);

        // The rules: rule, action, target, the fact behind it, risk.
        relation violation(&'static str, String, String, String, i64);

        violation(RULE_001_CRITICAL_DELETE, a.clone(), t.clone(), format!("CriticalFile({c:?})"), 0) <--
            proposed(a, t, _), applies(r, a), if *r == RULE_001_CRITICAL_DELETE,
            canon(t, c), critical_file(c);
        violation(RULE_002_CRITICAL_MODIFY, a.clone(), t.clone(), format!("CriticalFile({c:?})"), 0) <--
            proposed(a, t, _), applies(r, a), if *r == RULE_002_CRITICAL_MODIFY,
            canon(t, c), critical_file(c);
        violation(RULE_003_SENSITIVE_ACCESS, a.clone(), t.clone(), format!("SensitiveFile({p:?})"), 0) <--
            proposed(a, t, _), applies(r, a), if *r == RULE_003_SENSITIVE_ACCESS,
            canon(t, c), sensitive(c, p);
        violation(RULE_004_EXTERNAL_NETWORK, a.clone(), t.clone(), format!("ExternalEndpoint({e:?})"), 0) <--
            proposed(a, t, _), applies(r, a), if *r == RULE_004_EXTERNAL_NETWORK,
            external(t, e);
        violation(RULE_005_RESTRICTED_TOOL, a.clone(), t.clone(), format!("RestrictedTool({x:?})"), 0) <--
            proposed(a, t, _), applies(r, a), if *r == RULE_005_RESTRICTED_TOOL,
            restricted(t, x);
        violation(RULE_006_SYSTEM_PATH, a.clone(), t.clone(), format!("SystemPath({s:?})"), 0) <--
            proposed(a, t, _), applies(r, a), if *r == RULE_006_SYSTEM_PATH,
            canon(t, c), within(c, s), system_path(s);
        violation(RULE_007_HIGH_RISK_NETWORK, a.clone(), t.clone(), format!("AgentRiskScore({ag:?}, {bp})"), *bp) <--
            proposed(a, t, ag), applies(r, a), if *r == RULE_007_HIGH_RISK_NETWORK,
            max_risk(ag, bp), block_above(th), if bp > th;
        violation(RULE_008_RISK_EXTERNAL_API, a.clone(), t.clone(), format!("ExternalEndpoint({e:?}), AgentRiskScore({ag:?}, {bp})"), *bp) <--
            proposed(a, t, ag), applies(r, a), if *r == RULE_008_RISK_EXTERNAL_API,
            external(t, e), max_risk(ag, bp), if *bp > EXTERNAL_API_RISK_BP;
        violation(RULE_009_NETWORK_CAPABILITY, a.clone(), t.clone(), format!("!AgentCapability({ag:?}, {NETWORK:?})"), 0) <--
            proposed(a, t, ag), applies(r, a), if *r == RULE_009_NETWORK_CAPABILITY,
            !capability(ag, NETWORK.to_string());
    }
}

/// The safety engine: a knowledge base of facts, the built-in rules as a
/// Datalog program (finding V3), and any rules added with
/// [`SafetyEngine::add_rule`].
pub struct SafetyEngine {
    /// Knowledge base of facts
    facts: HashSet<Fact>,
    /// Whether the built-in rules apply
    builtin: bool,
    /// Rules added with `add_rule`
    rules: Vec<SafetyRule>,
    /// Statistics
    stats: SafetyStats,
    /// Configuration
    config: SafetyConfig,
}

/// Configuration for the safety engine
#[derive(Debug, Clone)]
pub struct SafetyConfig {
    /// Fail closed on unknown actions
    pub fail_closed: bool,
    /// Risk threshold for warnings (0.0 - 1.0)
    pub warning_threshold: f64,
    /// Risk threshold for blocking (0.0 - 1.0)
    pub block_threshold: f64,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            fail_closed: true,
            warning_threshold: 0.3,
            block_threshold: 0.7,
        }
    }
}

/// Statistics for the safety engine
#[derive(Debug, Default)]
pub struct SafetyStats {
    /// Total checks performed
    pub total_checks: u64,
    /// Safe verdicts
    pub safe_verdicts: u64,
    /// Violation verdicts
    pub violations: u64,
    /// Warning verdicts
    pub warnings: u64,
}

impl std::fmt::Debug for SafetyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SafetyEngine")
            .field("facts_count", &self.facts.len())
            .field("rules_count", &self.rule_count())
            .field("stats", &self.stats)
            .finish()
    }
}

impl Default for SafetyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SafetyEngine {
    /// Create a new safety engine with the built-in rules and default facts
    pub fn new() -> Self {
        let mut engine = Self {
            facts: HashSet::new(),
            builtin: true,
            rules: Vec::new(),
            stats: SafetyStats::default(),
            config: SafetyConfig::default(),
        };
        engine.add_default_facts();
        engine
    }

    /// Create with custom configuration
    pub fn with_config(config: SafetyConfig) -> Self {
        let mut engine = Self::new();
        engine.config = config;
        engine
    }

    /// The engine's configuration.
    #[must_use]
    pub fn config(&self) -> &SafetyConfig {
        &self.config
    }

    /// Add default critical file facts
    fn add_default_facts(&mut self) {
        // Critical system files (as per Gap Analysis example)
        for path in ["/etc/shadow", "/etc/passwd", "/etc/hosts", "/etc/sudoers"] {
            self.facts.insert(Fact::CriticalFile(path.to_string()));
        }
        // Sensitive files
        for pattern in [".env", "secrets.json", ".ssh/id_rsa", ".aws/credentials"] {
            self.facts.insert(Fact::SensitiveFile(pattern.to_string()));
        }
        // System paths
        for path in ["/etc", "/usr", "/var", "/bin", "/sbin"] {
            self.facts.insert(Fact::SystemPath(path.to_string()));
        }
        // Restricted tools
        for tool in ["rm -rf", "dd", "mkfs"] {
            self.facts.insert(Fact::RestrictedTool(tool.to_string()));
        }
    }

    /// Add a fact to the knowledge base. Paths, endpoints and commands are
    /// canonicalised.
    pub fn add_fact(&mut self, fact: Fact) {
        debug!(?fact, "Adding fact to knowledge base");
        self.facts.insert(fact.canonical());
    }

    /// Remove a fact from the knowledge base
    pub fn remove_fact(&mut self, fact: &Fact) -> bool {
        self.facts.remove(&fact.clone().canonical())
    }

    /// Check if a fact exists
    pub fn has_fact(&self, fact: &Fact) -> bool {
        self.facts.contains(&fact.clone().canonical())
    }

    /// Add a custom safety rule
    pub fn add_rule(&mut self, rule: SafetyRule) {
        info!(rule_id = %rule.id, "Adding custom safety rule");
        self.rules.push(rule);
    }

    /// Whether any rule applies to `action`: a built-in rule, or an added
    /// one that names it or `"*"`.
    #[must_use]
    pub fn covers(&self, action: &str) -> bool {
        (self.builtin
            && BUILTIN_RULES
                .iter()
                .any(|rule| rule.actions.contains(&action)))
            || self
                .rules
                .iter()
                .any(|rule| rule.applies_to.iter().any(|a| a == action || a == "*"))
    }

    /// Runs the built-in program for one action: its violations, in rule
    /// order, and the agent's risk score.
    fn evaluate(&self, action: &str, target: &str, agent_id: &str) -> (Vec<Violation>, f64) {
        let mut program = program::SafetyProgram::default();
        program
            .proposed
            .push((action.to_string(), target.to_string(), agent_id.to_string()));
        if self.builtin {
            for rule in &BUILTIN_RULES {
                program
                    .applies
                    .extend(rule.actions.iter().map(|a| (rule.id, (*a).to_string())));
            }
        }
        for fact in &self.facts {
            match fact {
                Fact::CriticalFile(p) => program.critical_file.push((p.clone(),)),
                Fact::SensitiveFile(p) => program.sensitive_file.push((p.clone(),)),
                Fact::SystemPath(p) => program.system_path.push((p.clone(),)),
                Fact::ExternalEndpoint(e) => program.external_endpoint.push((e.clone(),)),
                Fact::RestrictedTool(t) => program.restricted_tool.push((t.clone(),)),
                Fact::AgentCapability {
                    agent_id,
                    capability,
                } => program
                    .capability
                    .push((agent_id.clone(), capability.clone())),
                Fact::AgentRiskScore { agent_id, score_bp } => {
                    program.risk.push((agent_id.clone(), i64::from(*score_bp)))
                }
                Fact::InternalEndpoint(_)
                | Fact::AvailableTool(_)
                | Fact::ProposedAction { .. }
                | Fact::Custom { .. } => {}
            }
        }
        program
            .block_above
            .push((threshold_bp(self.config.block_threshold),));
        program.run();

        let risk_bp = program
            .max_risk
            .iter()
            .find(|(agent, _)| agent == agent_id)
            .map_or(0, |(_, bp)| *bp);
        let mut found: Vec<_> = program.violation.into_iter().collect();
        let order = |rule: &str| BUILTIN_RULES.iter().position(|r| r.id == rule);
        found.sort_by(|a, b| (order(a.0), &a.3).cmp(&(order(b.0), &b.3)));
        let violations = found
            .into_iter()
            .map(|(rule, action, target, fact, bp)| {
                let risk = bp as f64 / 10_000.0;
                let (description, severity) = match rule {
                    RULE_001_CRITICAL_DELETE => {
                        (format!("Attempted to delete critical file: {target}"), 1.0)
                    }
                    RULE_002_CRITICAL_MODIFY => {
                        (format!("Attempted to modify critical file: {target}"), 1.0)
                    }
                    RULE_003_SENSITIVE_ACCESS => {
                        (format!("Attempted to access sensitive file: {target}"), 0.8)
                    }
                    RULE_004_EXTERNAL_NETWORK => (
                        format!("Attempted external network request to: {target}"),
                        0.6,
                    ),
                    RULE_005_RESTRICTED_TOOL => {
                        (format!("Attempted to use restricted tool: {target}"), 0.9)
                    }
                    RULE_006_SYSTEM_PATH => (
                        format!("Attempted operation in system path: {target}"),
                        0.9,
                    ),
                    RULE_007_HIGH_RISK_NETWORK => (
                        format!(
                            "Agent {agent_id} (risk: {risk:.2}) blocked from network access to: {target}"
                        ),
                        risk,
                    ),
                    RULE_008_RISK_EXTERNAL_API => (
                        format!(
                            "Agent {agent_id} (risk: {risk:.2}) has elevated risk for external API: {target}"
                        ),
                        (risk * 1.2).min(1.0),
                    ),
                    _ => (
                        format!(
                            "Agent {agent_id} lacks '{NETWORK}' capability for: {action} {target}"
                        ),
                        0.7,
                    ),
                };
                Violation::new(rule, description, action, target)
                    .with_severity(severity)
                    .with_fact(fact)
            })
            .collect();
        (violations, risk_bp as f64 / 10_000.0)
    }

    /// Check if an action is safe
    pub fn check_action(&mut self, action: &str, target: &str) -> SafetyVerdict {
        self.check_action_with_agent(action, target, "unknown")
    }

    /// Check if an action is safe with agent context.
    ///
    /// The built-in rules run as a Datalog program; then each added rule
    /// that applies. With an agent's risk over `warning_threshold` and no
    /// violation, the verdict is a warning.
    pub fn check_action_with_agent(
        &mut self,
        action: &str,
        target: &str,
        agent_id: &str,
    ) -> SafetyVerdict {
        self.stats.total_checks += 1;

        let (mut violations, risk_score) = self.evaluate(action, target, agent_id);
        for rule in &self.rules {
            if rule.applies_to.iter().any(|a| a == action || a == "*") {
                if let Some(violation) = (rule.checker)(self, action, target, agent_id) {
                    violations.push(violation);
                }
            }
        }

        // Determine verdict
        if !violations.is_empty() {
            self.stats.violations += 1;
            warn!(
                action = action,
                target = target,
                agent = agent_id,
                violations = violations.len(),
                "Safety violations detected"
            );
            SafetyVerdict::Violation(violations)
        } else if risk_score > self.config.warning_threshold {
            self.stats.warnings += 1;
            SafetyVerdict::Warning {
                message: format!(
                    "Agent {} has elevated risk score: {:.2}",
                    agent_id, risk_score
                ),
                risk_score,
            }
        } else {
            self.stats.safe_verdicts += 1;
            SafetyVerdict::Safe
        }
    }

    /// Verify a plan (multiple actions)
    pub fn verify_plan(&mut self, plan: &[(&str, &str)], agent_id: &str) -> SafetyVerdict {
        let mut all_violations = Vec::new();
        let mut max_risk = 0.0f64;

        for (action, target) in plan {
            match self.check_action_with_agent(action, target, agent_id) {
                SafetyVerdict::Violation(v) => all_violations.extend(v),
                SafetyVerdict::Warning { risk_score, .. } => {
                    max_risk = max_risk.max(risk_score);
                }
                _ => {}
            }
        }

        if !all_violations.is_empty() {
            SafetyVerdict::Violation(all_violations)
        } else if max_risk > self.config.warning_threshold {
            SafetyVerdict::Warning {
                message: format!("Plan has elevated risk score: {:.2}", max_risk),
                risk_score: max_risk,
            }
        } else {
            SafetyVerdict::Safe
        }
    }

    /// Get statistics
    pub fn stats(&self) -> &SafetyStats {
        &self.stats
    }

    /// Get fact count
    pub fn fact_count(&self) -> usize {
        self.facts.len()
    }

    /// The number of rules: the built-in ones, unless skipped, and those
    /// added.
    pub fn rule_count(&self) -> usize {
        let builtin = if self.builtin { BUILTIN_RULES.len() } else { 0 };
        builtin + self.rules.len()
    }

    /// The built-in rules' IDs and descriptions, unless skipped.
    pub fn builtin_rules(&self) -> Vec<(&'static str, &'static str)> {
        if !self.builtin {
            return Vec::new();
        }
        BUILTIN_RULES
            .iter()
            .map(|rule| (rule.id, rule.description))
            .collect()
    }

    /// Clear all facts (keeps rules)
    pub fn clear_facts(&mut self) {
        self.facts.clear();
    }
}

/// Builder for safety engine with custom rules
#[derive(Default)]
pub struct SafetyEngineBuilder {
    config: SafetyConfig,
    additional_facts: Vec<Fact>,
    skip_defaults: bool,
}

impl SafetyEngineBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set configuration
    pub fn config(mut self, config: SafetyConfig) -> Self {
        self.config = config;
        self
    }

    /// Add a fact
    pub fn add_fact(mut self, fact: Fact) -> Self {
        self.additional_facts.push(fact);
        self
    }

    /// Skip the built-in rules and the default facts
    pub fn skip_defaults(mut self) -> Self {
        self.skip_defaults = true;
        self
    }

    /// Build the engine
    pub fn build(self) -> SafetyEngine {
        let mut engine = if self.skip_defaults {
            SafetyEngine {
                facts: HashSet::new(),
                builtin: false,
                rules: Vec::new(),
                stats: SafetyStats::default(),
                config: self.config,
            }
        } else {
            SafetyEngine::with_config(self.config)
        };

        for fact in self.additional_facts {
            engine.add_fact(fact);
        }

        engine
    }
}

// Guard adapter

/// The arguments [`DatalogGuard`] reads a tool's targets from, unless
/// [`DatalogGuard::with_tool`] names one.
pub const TARGET_ARGUMENTS: [&str; 6] = ["path", "target", "file", "url", "tool", "command"];

/// The safety engine on the kernel's request path, as an enforced
/// [`Guard`](crate::kernel::guard::Guard) (`docs/adr/0020`).
///
/// A call's action is its tool's name, and its targets are the string
/// arguments named in [`TARGET_ARGUMENTS`]: each is checked, as the calling
/// agent. [`DatalogGuard::with_tool`] maps a tool to another action and one
/// argument.
///
/// - **A tool no rule applies to:** it abstains.
/// - **A violation** denies, naming the rules.
/// - **A warning** (the agent's risk over `warning_threshold`) escalates,
///   which the kernel refuses: there is no approval channel.
/// - **No violation:** it abstains, and never passes. The rules forbid; none
///   firing doesn't show a call is right, so it must not satisfy a
///   `policy.min_assurance` floor.
/// - **No target to check** (no such argument, or one that isn't a string)
///   denies: a rule can't be evaluated without one.
#[derive(Debug)]
pub struct DatalogGuard {
    engine: std::sync::Mutex<SafetyEngine>,
    tools: std::collections::BTreeMap<String, (String, String)>,
}

impl DatalogGuard {
    /// The guard's name, recorded with each verdict as `guard.datalog`.
    pub const NAME: &'static str = "datalog";

    /// A guard checking calls against `engine`'s rules and facts.
    ///
    /// # Errors
    ///
    /// [`DatalogError::EvaluationError`] if a threshold in the engine's
    /// configuration isn't a finite number: NaN compares false, so a NaN
    /// warning threshold would never warn.
    pub fn new(engine: SafetyEngine) -> DatalogResult<Self> {
        let config = engine.config();
        for (name, value) in [
            ("warning_threshold", config.warning_threshold),
            ("block_threshold", config.block_threshold),
        ] {
            if !value.is_finite() {
                return Err(DatalogError::EvaluationError(format!(
                    "{name} must be a finite number, not {value}"
                )));
            }
        }
        Ok(Self {
            engine: std::sync::Mutex::new(engine),
            tools: std::collections::BTreeMap::new(),
        })
    }

    /// A guard over the built-in rules and default facts.
    #[must_use]
    pub fn default_rules() -> Self {
        Self {
            engine: std::sync::Mutex::new(SafetyEngine::new()),
            tools: std::collections::BTreeMap::new(),
        }
    }

    /// Checks `tool`'s calls as `action`, on the target in `argument`.
    #[must_use]
    pub fn with_tool(
        mut self,
        tool: impl Into<String>,
        action: impl Into<String>,
        argument: impl Into<String>,
    ) -> Self {
        self.tools
            .insert(tool.into(), (action.into(), argument.into()));
        self
    }

    /// The verdict on a call, without the async wrapper.
    fn decide(
        &self,
        request: &crate::kernel::guard::GuardRequest<'_>,
    ) -> crate::kernel::guard::GuardVerdict {
        use crate::kernel::guard::GuardVerdict;
        let tool = request.request.tool_name.as_str();
        let (action, arguments): (&str, Vec<&str>) = match self.tools.get(tool) {
            Some((action, argument)) => (action, vec![argument.as_str()]),
            None => (tool, TARGET_ARGUMENTS.to_vec()),
        };
        let Ok(mut engine) = self.engine.lock() else {
            return GuardVerdict::deny("datalog: the safety engine is unavailable");
        };
        if !engine.covers(action) {
            return GuardVerdict::Abstain;
        }
        let mut targets = Vec::new();
        for argument in &arguments {
            match request.request.parameters.get(*argument) {
                Some(serde_json::Value::String(target)) => targets.push(target.as_str()),
                Some(_) => {
                    return GuardVerdict::deny(format!(
                        "datalog: {action}'s `{argument}` argument isn't a string, so the \
                         rules can't check it"
                    ))
                }
                None => {}
            }
        }
        if targets.is_empty() {
            return GuardVerdict::deny(format!(
                "datalog: rules apply to {action}, but the call has no target to check \
                 (looked for {})",
                arguments.join(", ")
            ));
        }
        let plan: Vec<(&str, &str)> = targets.iter().map(|target| (action, *target)).collect();
        match engine.verify_plan(&plan, &request.agent_id.to_string()) {
            SafetyVerdict::Violation(violations) => {
                let mut rules: Vec<String> = violations
                    .iter()
                    .map(|v| format!("{} ({})", v.rule_id, v.description))
                    .collect();
                rules.dedup();
                GuardVerdict::deny(format!("datalog: {}", rules.join("; ")))
            }
            SafetyVerdict::Warning { message, .. } => GuardVerdict::Escalate {
                reason: format!("datalog: {message}"),
            },
            SafetyVerdict::Unknown(why) => GuardVerdict::deny(format!("datalog: {why}")),
            SafetyVerdict::Safe => GuardVerdict::Abstain,
        }
    }
}

#[async_trait::async_trait]
impl crate::kernel::guard::Guard for DatalogGuard {
    async fn check(
        &self,
        request: &crate::kernel::guard::GuardRequest<'_>,
    ) -> crate::kernel::guard::GuardVerdict {
        self.decide(request)
    }

    fn name(&self) -> &str {
        Self::NAME
    }

    fn assurance(&self) -> crate::kernel::guard::Assurance {
        crate::kernel::guard::Assurance::Enforced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_critical_file_protection() {
        let mut engine = SafetyEngine::new();

        // Try to delete /etc/shadow
        let verdict = engine.check_action("delete_file", "/etc/shadow");
        assert!(verdict.is_violation());

        if let SafetyVerdict::Violation(violations) = verdict {
            // /etc/shadow triggers multiple rules:
            // - RULE_001_CRITICAL_DELETE (critical file)
            // - RULE_006_SYSTEM_PATH (/etc is a system path)
            assert!(
                !violations.is_empty(),
                "Expected at least 1 violation, got {}",
                violations.len()
            );
            assert!(
                violations
                    .iter()
                    .any(|v| v.rule_id == "RULE_001_CRITICAL_DELETE"),
                "Expected RULE_001_CRITICAL_DELETE in violations"
            );
        }
    }

    #[test]
    fn test_safe_action() {
        let mut engine = SafetyEngine::new();

        // Reading a normal file should be safe
        let verdict = engine.check_action("read_file", "/home/user/document.txt");
        assert!(verdict.is_safe());
    }

    #[test]
    fn test_sensitive_file_access() {
        let mut engine = SafetyEngine::new();

        // Accessing .env should trigger violation
        let verdict = engine.check_action("read_file", ".env");
        assert!(verdict.is_violation());
    }

    #[test]
    fn test_system_path_protection() {
        let mut engine = SafetyEngine::new();

        // Writing to /etc should be blocked
        let verdict = engine.check_action("write_file", "/etc/custom.conf");
        assert!(verdict.is_violation());
    }

    #[test]
    fn test_custom_fact() {
        let mut engine = SafetyEngine::new();

        // Add custom critical file
        engine.add_fact(Fact::critical_file("/my/important/file"));

        // Should now be protected
        let verdict = engine.check_action("delete_file", "/my/important/file");
        assert!(verdict.is_violation());
    }

    #[test]
    fn test_agent_risk_score() {
        let mut engine = SafetyEngine::new();

        // Add high risk agent
        engine.add_fact(Fact::agent_risk("risky-agent", 0.5));

        // Check action - should get warning
        let verdict =
            engine.check_action_with_agent("read_file", "/home/user/file.txt", "risky-agent");

        assert!(verdict.is_warning());
    }

    #[test]
    fn test_plan_verification() {
        let mut engine = SafetyEngine::new();

        // Plan with one unsafe action
        let plan = vec![
            ("read_file", "/home/user/data.txt"),
            ("delete_file", "/etc/hosts"), // Unsafe!
            ("write_file", "/tmp/output.txt"),
        ];

        let verdict = engine.verify_plan(&plan, "test-agent");
        assert!(verdict.is_violation());
    }

    #[test]
    fn test_builder() {
        let engine = SafetyEngineBuilder::new()
            .config(SafetyConfig {
                fail_closed: true,
                warning_threshold: 0.2,
                block_threshold: 0.5,
            })
            .add_fact(Fact::critical_file("/custom/file"))
            .build();

        assert!(engine.has_fact(&Fact::critical_file("/custom/file")));
    }

    #[test]
    fn test_restricted_tool() {
        let mut engine = SafetyEngine::new();

        // Try to use rm -rf
        let verdict = engine.check_action("execute_tool", "rm -rf");
        assert!(verdict.is_violation());
    }

    // --- V3: paths are compared in canonical form ---

    #[test]
    fn canonical_path_cases() {
        for (input, want) in [
            ("/etc/shadow", "/etc/shadow"),
            ("/etc//shadow", "/etc/shadow"),
            ("/etc/./shadow", "/etc/shadow"),
            ("/etc/../etc/shadow", "/etc/shadow"),
            ("/etc/shadow/", "/etc/shadow"),
            ("//etc///shadow", "/etc/shadow"),
            ("/../../etc/shadow", "/etc/shadow"),
            ("/", "/"),
            ("/..", "/"),
            ("", "."),
            ("./.env", ".env"),
            ("a/../.env", ".env"),
            ("../x", "../x"),
            ("a/../../x", "../x"),
            ("/etc/shadow\0.txt", "/etc/shadow"),
        ] {
            assert_eq!(canonical_path(input), want, "input {input:?}");
        }
    }

    #[test]
    fn canonical_path_is_idempotent() {
        for input in ["/a//b/../c/.", "x/../../y", "", "/", "./a/./b/", "../.."] {
            let once = canonical_path(input);
            assert_eq!(canonical_path(&once), once, "input {input:?}");
        }
    }

    #[test]
    fn v3_critical_file_cannot_be_reached_by_aliases() {
        let mut engine = SafetyEngine::new();
        for target in [
            "/etc//shadow",
            "/etc/../etc/shadow",
            "/etc/./shadow",
            "/etc/shadow/",
            "/tmp/../etc/shadow",
            "/etc/shadow\0.txt",
        ] {
            for action in ["delete_file", "write_file"] {
                let verdict = engine.check_action(action, target);
                let SafetyVerdict::Violation(v) = verdict else {
                    panic!("{action} {target:?} was not refused");
                };
                assert!(
                    v.iter().any(|x| matches!(
                        x.rule_id.as_str(),
                        "RULE_001_CRITICAL_DELETE" | "RULE_002_CRITICAL_MODIFY"
                    )),
                    "{action} {target:?} missed the critical-file rule"
                );
            }
        }
    }

    #[test]
    fn v3_sensitive_file_matches_in_any_directory() {
        let mut engine = SafetyEngine::new();
        for target in [
            "./.env",
            "app/../.env",
            "/home/user/.env",
            "/home/user/.ssh//id_rsa",
            "/root/.aws/./credentials",
        ] {
            assert!(
                engine.check_action("read_file", target).is_violation(),
                "{target:?} was not refused"
            );
        }
        // Only whole components match.
        assert!(engine
            .check_action("read_file", "/home/user/my.env")
            .is_safe());
        assert!(engine
            .check_action("read_file", "/home/user/.envrc")
            .is_safe());
    }

    #[test]
    fn v3_system_path_matches_whole_components() {
        let mut engine = SafetyEngine::new();
        assert!(engine
            .check_action("create_dir", "/tmp/../etc/new")
            .is_violation());
        assert!(engine.check_action("create_dir", "/etc").is_violation());
        // `/etcetera` and `/usrlocal` are not under `/etc` or `/usr`.
        assert!(engine.check_action("create_dir", "/etcetera/x").is_safe());
        assert!(engine.check_action("create_dir", "/usrlocal").is_safe());
    }

    #[test]
    fn v3_facts_added_by_callers_are_canonicalised() {
        let mut engine = SafetyEngine::new();
        engine.add_fact(Fact::critical_file("/srv//data/../keys/"));
        assert!(engine.has_fact(&Fact::critical_file("/srv/keys")));
        assert!(engine
            .check_action("delete_file", "/srv/./keys")
            .is_violation());
        assert!(engine.remove_fact(&Fact::critical_file("/srv/x/../keys")));
        assert!(!engine.has_fact(&Fact::critical_file("/srv/keys")));
    }

    // --- V3: the built-in rules are a Datalog program ---

    fn rules_of(verdict: &SafetyVerdict) -> Vec<&str> {
        verdict
            .violations()
            .unwrap_or_default()
            .iter()
            .map(|v| v.rule_id.as_str())
            .collect()
    }

    #[test]
    fn path_helpers() {
        for (path, parent) in [
            ("/", None),
            (".", None),
            ("a", None),
            ("..", None),
            ("../..", None),
            ("/etc", Some("/")),
            ("/etc/shadow", Some("/etc")),
            ("a/b", Some("a")),
            ("../x", Some("..")),
        ] {
            assert_eq!(parent_dir(path).as_deref(), parent, "{path:?}");
        }
        assert_eq!(
            relative_suffixes("/home/user/.env"),
            ["home/user/.env", "user/.env", ".env"]
        );
        assert_eq!(relative_suffixes("a/.env"), ["a/.env", ".env"]);
        assert!(relative_suffixes("/").is_empty());
    }

    #[test]
    fn containment_is_recursive_over_any_depth() {
        // `within` is the transitive closure of `parent`, derived to a
        // fixpoint; the closures it replaced compared one string prefix.
        let mut engine = SafetyEngineBuilder::new()
            .skip_defaults()
            .add_fact(Fact::system_path("srv/data"))
            .build();
        engine.builtin = true;
        let deep = format!("srv/data/{}", vec!["d"; 50].join("/"));
        assert_eq!(
            rules_of(&engine.check_action("create_dir", &deep)),
            [RULE_006_SYSTEM_PATH]
        );
        assert!(engine.check_action("create_dir", "srv/database").is_safe());
        assert!(engine.check_action("create_dir", "srv").is_safe());
    }

    #[test]
    fn violations_come_in_rule_order_with_their_facts() {
        let mut engine = SafetyEngine::new();
        let verdict = engine.check_action("delete_file", "/etc//shadow");
        assert_eq!(
            rules_of(&verdict),
            [RULE_001_CRITICAL_DELETE, RULE_006_SYSTEM_PATH]
        );
        let violations = verdict.violations().unwrap_or_default();
        assert_eq!(
            violations[0].triggering_facts,
            [r#"CriticalFile("/etc/shadow")"#]
        );
        assert_eq!(violations[0].target, "/etc//shadow");
        assert_eq!(violations[0].severity, 1.0);
        assert_eq!(violations[1].triggering_facts, [r#"SystemPath("/etc")"#]);
        assert_eq!(violations[1].severity, 0.9);
        // Writing a critical file breaks rule 2, not rule 1.
        assert_eq!(
            rules_of(&engine.check_action("write_file", "/etc/passwd")),
            [RULE_002_CRITICAL_MODIFY, RULE_006_SYSTEM_PATH]
        );
        // An absolute sensitive file matches that file only.
        engine.add_fact(Fact::sensitive_file("/srv/keys.pem"));
        assert_eq!(
            rules_of(&engine.check_action("read_file", "/srv//keys.pem")),
            [RULE_003_SENSITIVE_ACCESS]
        );
        assert!(engine
            .check_action("read_file", "/other/srv/keys.pem")
            .is_safe());
        let read = engine.check_action("open", "/home/u/.ssh/id_rsa");
        assert_eq!(rules_of(&read), [RULE_003_SENSITIVE_ACCESS]);
        assert_eq!(read.violations().unwrap_or_default()[0].severity, 0.8);
    }

    #[test]
    fn violations_are_ordered_whatever_the_fact_order() {
        // Facts reach the program in hash-set order, which varies between
        // engines; the report must not.
        let expected = [
            RULE_004_EXTERNAL_NETWORK,
            RULE_007_HIGH_RISK_NETWORK,
            RULE_008_RISK_EXTERNAL_API,
            RULE_009_NETWORK_CAPABILITY,
        ];
        for round in 0..20 {
            let mut paths = vec!["/srv", "/srv/a", "/srv/a/b", "/srv/a/b/c"];
            if round % 2 == 1 {
                paths.reverse();
            }
            let mut engine = SafetyEngine::new();
            for path in paths {
                engine.add_fact(Fact::system_path(path));
            }
            engine.add_fact(Fact::external_endpoint("https://x.example"));
            engine.add_fact(Fact::agent_risk("ag", 0.95));
            let facts: Vec<String> = engine
                .check_action("create_dir", "/srv/a/b/c/d")
                .violations()
                .unwrap_or_default()
                .iter()
                .flat_map(|v| v.triggering_facts.clone())
                .collect();
            assert_eq!(
                facts,
                [
                    r#"SystemPath("/srv")"#,
                    r#"SystemPath("/srv/a")"#,
                    r#"SystemPath("/srv/a/b")"#,
                    r#"SystemPath("/srv/a/b/c")"#,
                ],
                "round {round}"
            );
            assert_eq!(
                rules_of(&engine.check_action_with_agent(
                    "http_request",
                    "https://x.example/",
                    "ag"
                )),
                expected,
                "round {round}"
            );
        }
    }

    #[test]
    fn an_agents_risk_is_its_highest_score() {
        // Two scores for one agent: the closure read whichever the hash set
        // yielded first, so a stale low score could hide a high one.
        let mut engine = SafetyEngine::new();
        engine.add_fact(Fact::agent_capability("ag", "network"));
        engine.add_fact(Fact::agent_risk("ag", 0.2));
        engine.add_fact(Fact::agent_risk("ag", 0.9));
        let verdict = engine.check_action_with_agent("fetch", "https://example.org", "ag");
        assert_eq!(rules_of(&verdict), [RULE_007_HIGH_RISK_NETWORK]);
        let v = &verdict.violations().unwrap_or_default()[0];
        assert_eq!(v.severity, 0.9);
        assert!(v.description.contains("risk: 0.90"), "{}", v.description);
        assert_eq!(v.triggering_facts, [r#"AgentRiskScore("ag", 9000)"#]);

        // At the threshold isn't over it.
        let mut at = SafetyEngine::new();
        at.add_fact(Fact::agent_capability("ag", "network"));
        at.add_fact(Fact::agent_risk("ag", 0.7));
        assert!(at
            .check_action_with_agent("fetch", "https://example.org", "ag")
            .is_warning());
    }

    #[test]
    fn the_block_threshold_fails_closed() {
        assert_eq!(threshold_bp(0.7), 7_000);
        assert_eq!(threshold_bp(0.0), 0);
        assert_eq!(threshold_bp(f64::NAN), i64::MIN);
        assert_eq!(threshold_bp(f64::INFINITY), i64::MAX);
        assert_eq!(threshold_bp(f64::NEG_INFINITY), i64::MIN);
        // An agent with no score has risk 0, so a NaN or negative threshold
        // blocks it: NaN used to compare false and block nothing.
        for block_threshold in [f64::NAN, -0.1] {
            let mut engine = SafetyEngine::with_config(SafetyConfig {
                block_threshold,
                ..SafetyConfig::default()
            });
            engine.add_fact(Fact::agent_capability("ag", "network"));
            assert_eq!(
                rules_of(&engine.check_action_with_agent("fetch", "https://example.org", "ag")),
                [RULE_007_HIGH_RISK_NETWORK],
                "{block_threshold}"
            );
        }
    }

    #[test]
    fn network_actions_need_the_capability() {
        // Rule 9 is a negation: the agent has no `network` capability.
        let mut engine = SafetyEngine::new();
        engine.add_fact(Fact::agent_capability("other", "network"));
        engine.add_fact(Fact::agent_capability("ag", "files"));
        let verdict = engine.check_action_with_agent("dns_lookup", "example.org", "ag");
        assert_eq!(rules_of(&verdict), [RULE_009_NETWORK_CAPABILITY]);
        assert_eq!(
            verdict.violations().unwrap_or_default()[0].triggering_facts,
            [r#"!AgentCapability("ag", "network")"#]
        );
        engine.add_fact(Fact::agent_capability("ag", "network"));
        assert!(engine
            .check_action_with_agent("dns_lookup", "example.org", "ag")
            .is_safe());
    }

    #[test]
    fn endpoints_match_by_host_and_path() {
        assert_eq!(
            canonical_endpoint(" HTTPS://Evil.COM:443/a/./b#frag "),
            "https://evil.com/a/b"
        );
        assert_eq!(canonical_endpoint("intranet"), "intranet");
        let mut engine = SafetyEngine::new();
        engine.add_fact(Fact::agent_capability("ag", "network"));
        engine.add_fact(Fact::external_endpoint("https://evil.com"));
        engine.add_fact(Fact::external_endpoint("https://api.x.com/v1/"));
        engine.add_fact(Fact::external_endpoint("intranet"));
        assert!(engine.has_fact(&Fact::external_endpoint("HTTPS://EVIL.COM/")));
        let mut external = |target: &str| {
            rules_of(&engine.check_action_with_agent("http_request", target, "ag"))
                .contains(&RULE_004_EXTERNAL_NETWORK)
        };
        // Exact strings used to match: case, a port, a trailing dot or
        // another path all got past the fact.
        for target in [
            "https://EVIL.com/steal",
            "http://evil.com:8080/x",
            "https://evil.com./",
            "https://user@evil.com/",
            "https://api.x.com/v1",
            "https://api.x.com/v1/users",
            "intranet",
        ] {
            assert!(external(target), "{target}");
        }
        for target in [
            "https://evil.com.attacker.net/",
            "https://notevil.com/",
            "https://evil.com@good.example/",
            "https://api.x.com/v10",
            "https://api.x.com/v1/../admin",
            "intranet2",
        ] {
            assert!(!external(target), "{target}");
        }
        assert!(endpoint_within("https://a.com/x", "https://a.com"));
        assert!(!endpoint_within("not a url", "https://a.com"));
    }

    #[test]
    fn external_api_calls_by_risky_agents_break_rule_8() {
        let mut engine = SafetyEngine::new();
        engine.add_fact(Fact::agent_capability("ag", "network"));
        engine.add_fact(Fact::external_endpoint("https://api.x.com"));
        engine.add_fact(Fact::agent_risk("ag", 0.6));
        let verdict = engine.check_action_with_agent("api_call", "https://api.x.com/q", "ag");
        assert_eq!(rules_of(&verdict), [RULE_008_RISK_EXTERNAL_API]);
        let v = &verdict.violations().unwrap_or_default()[0];
        assert!((v.severity - 0.72).abs() < 1e-9, "{}", v.severity);
        // At 0.5 it isn't over.
        engine.add_fact(Fact::agent_risk("calm", 0.5));
        engine.add_fact(Fact::agent_capability("calm", "network"));
        assert!(!engine
            .check_action_with_agent("api_call", "https://api.x.com/q", "calm")
            .is_violation());
    }

    #[test]
    fn restricted_tools_match_by_leading_words() {
        let mut engine = SafetyEngine::new();
        engine.add_fact(Fact::RestrictedTool("  shred   -u ".to_string()));
        assert!(engine.has_fact(&Fact::RestrictedTool("shred -u".to_string())));
        assert!(engine.has_fact(&Fact::RestrictedTool("rm   -rf".to_string())));
        for target in ["rm  -rf /tmp", "dd if=/dev/zero", "mkfs", "shred -u x"] {
            assert_eq!(
                rules_of(&engine.check_action("execute_tool", target)),
                [RULE_005_RESTRICTED_TOOL],
                "{target}"
            );
        }
        for target in ["ddrescue", "rm -r", "rm", "shred"] {
            assert!(
                engine.check_action("call_tool", target).is_safe(),
                "{target}"
            );
        }
        assert!(!runs_restricted("anything", "   "));
    }

    #[test]
    fn skipped_defaults_leave_only_added_rules() {
        let mut engine = SafetyEngineBuilder::new().skip_defaults().build();
        assert_eq!(engine.rule_count(), 0);
        assert!(engine.builtin_rules().is_empty());
        assert!(!engine.covers("delete_file"));
        engine.add_fact(Fact::critical_file("/etc/shadow"));
        assert!(engine.check_action("delete_file", "/etc/shadow").is_safe());

        engine.add_rule(SafetyRule::new(
            "NO_TMP",
            "Nothing under /tmp",
            vec!["*".to_string()],
            |_, action, target, _| {
                target
                    .starts_with("/tmp")
                    .then(|| Violation::new("NO_TMP", "tmp", action, target))
            },
        ));
        assert_eq!(engine.rule_count(), 1);
        assert!(engine.covers("anything"));
        assert_eq!(
            rules_of(&engine.check_action("anything", "/tmp/x")),
            ["NO_TMP"]
        );

        let defaults = SafetyEngine::new();
        assert_eq!(defaults.rule_count(), 9);
        assert_eq!(defaults.builtin_rules()[0].0, RULE_001_CRITICAL_DELETE);
        assert!(defaults.covers("dns_lookup"));
        assert!(!defaults.covers("send_email"));
        assert!(format!("{defaults:?}").contains("rules_count: 9"));
    }

    #[test]
    fn the_guard_refuses_thresholds_it_cant_compare() {
        for (warning_threshold, block_threshold) in [
            (f64::NAN, 0.7),
            (0.3, f64::NAN),
            (f64::INFINITY, 0.7),
            (0.3, f64::NEG_INFINITY),
        ] {
            let engine = SafetyEngine::with_config(SafetyConfig {
                warning_threshold,
                block_threshold,
                ..SafetyConfig::default()
            });
            assert!(
                matches!(DatalogGuard::new(engine), Err(DatalogError::EvaluationError(m)) if m.contains("finite")),
                "{warning_threshold} {block_threshold}"
            );
        }
        let guard = DatalogGuard::new(SafetyEngine::new()).unwrap().with_tool(
            "fs.rm",
            "delete_file",
            "name",
        );
        assert_eq!(
            guard.tools.get("fs.rm"),
            Some(&("delete_file".to_string(), "name".to_string()))
        );
        assert!(format!("{:?}", DatalogGuard::default_rules()).contains("SafetyEngine"));
    }
}
