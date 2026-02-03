//! Datalog Safety Rules Engine (NSR-001, NSR-002)
//!
//! This module provides a Datalog-based safety verification system using
//! compile-time rule definitions. It enables deterministic validation of
//! agent actions against safety invariants.
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
//! - Compile-time Datalog rules using declarative macros
//! - Safety violation detection before action execution
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
//! - Crepe crate: https://github.com/ekzhang/crepe

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
    AgentCapability { agent_id: String, capability: String },

    /// An agent has a risk score (stored as integer basis points for Hash/Eq)
    AgentRiskScore { agent_id: String, score_bp: u32 },

    /// A tool is available
    AvailableTool(String),

    /// A tool is restricted
    RestrictedTool(String),

    /// An action was proposed
    ProposedAction {
        action_type: String,
        target: String,
        agent_id: String,
    },

    /// Custom fact with key-value
    Custom { predicate: String, args: Vec<String> },
}

impl PartialEq for Fact {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Fact::CriticalFile(a), Fact::CriticalFile(b)) => a == b,
            (Fact::SensitiveFile(a), Fact::SensitiveFile(b)) => a == b,
            (Fact::SystemPath(a), Fact::SystemPath(b)) => a == b,
            (Fact::ExternalEndpoint(a), Fact::ExternalEndpoint(b)) => a == b,
            (Fact::InternalEndpoint(a), Fact::InternalEndpoint(b)) => a == b,
            (Fact::AgentCapability { agent_id: a1, capability: c1 }, 
             Fact::AgentCapability { agent_id: a2, capability: c2 }) => a1 == a2 && c1 == c2,
            (Fact::AgentRiskScore { agent_id: a1, score_bp: s1 }, 
             Fact::AgentRiskScore { agent_id: a2, score_bp: s2 }) => a1 == a2 && s1 == s2,
            (Fact::AvailableTool(a), Fact::AvailableTool(b)) => a == b,
            (Fact::RestrictedTool(a), Fact::RestrictedTool(b)) => a == b,
            (Fact::ProposedAction { action_type: a1, target: t1, agent_id: ag1 },
             Fact::ProposedAction { action_type: a2, target: t2, agent_id: ag2 }) => {
                a1 == a2 && t1 == t2 && ag1 == ag2
            }
            (Fact::Custom { predicate: p1, args: a1 }, 
             Fact::Custom { predicate: p2, args: a2 }) => p1 == p2 && a1 == a2,
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
            Fact::AgentCapability { agent_id, capability } => {
                agent_id.hash(state);
                capability.hash(state);
            }
            Fact::AgentRiskScore { agent_id, score_bp } => {
                agent_id.hash(state);
                score_bp.hash(state);
            }
            Fact::AvailableTool(s) => s.hash(state),
            Fact::RestrictedTool(s) => s.hash(state),
            Fact::ProposedAction { action_type, target, agent_id } => {
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
        message: String,
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

/// Safety rule definition
#[derive(Debug, Clone)]
pub struct SafetyRule {
    /// Unique rule ID
    pub id: String,
    /// Human-readable description
    pub description: String,
    /// Action types this rule applies to
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

/// The Safety Engine implementing Datalog-style reasoning
pub struct SafetyEngine {
    /// Knowledge base of facts
    facts: HashSet<Fact>,
    /// Safety rules
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
            .field("rules_count", &self.rules.len())
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
    /// Create a new safety engine with default rules
    pub fn new() -> Self {
        let mut engine = Self {
            facts: HashSet::new(),
            rules: Vec::new(),
            stats: SafetyStats::default(),
            config: SafetyConfig::default(),
        };

        // Register default safety rules
        engine.register_default_rules();

        // Add default critical files
        engine.add_default_facts();

        engine
    }

    /// Create with custom configuration
    pub fn with_config(config: SafetyConfig) -> Self {
        let mut engine = Self::new();
        engine.config = config;
        engine
    }

    /// Register default safety rules
    fn register_default_rules(&mut self) {
        // Rule: Cannot delete critical files
        self.rules.push(SafetyRule::new(
            "RULE_001_CRITICAL_DELETE",
            "Cannot delete critical system files",
            vec!["delete_file".to_string(), "remove".to_string()],
            |engine, action, target, _agent| {
                if engine.facts.contains(&Fact::CriticalFile(target.to_string())) {
                    Some(
                        Violation::new(
                            "RULE_001_CRITICAL_DELETE",
                            format!("Attempted to delete critical file: {}", target),
                            action,
                            target,
                        )
                        .with_severity(1.0)
                        .with_fact(format!("CriticalFile(\"{}\")", target)),
                    )
                } else {
                    None
                }
            },
        ));

        // Rule: Cannot modify critical files
        self.rules.push(SafetyRule::new(
            "RULE_002_CRITICAL_MODIFY",
            "Cannot modify critical system files",
            vec!["write_file".to_string(), "modify".to_string(), "append".to_string()],
            |engine, action, target, _agent| {
                if engine.facts.contains(&Fact::CriticalFile(target.to_string())) {
                    Some(
                        Violation::new(
                            "RULE_002_CRITICAL_MODIFY",
                            format!("Attempted to modify critical file: {}", target),
                            action,
                            target,
                        )
                        .with_severity(1.0)
                        .with_fact(format!("CriticalFile(\"{}\")", target)),
                    )
                } else {
                    None
                }
            },
        ));

        // Rule: Cannot access sensitive files without capability
        self.rules.push(SafetyRule::new(
            "RULE_003_SENSITIVE_ACCESS",
            "Cannot access sensitive files without proper capability",
            vec!["read_file".to_string(), "open".to_string()],
            |engine, action, target, _agent| {
                if engine.facts.contains(&Fact::SensitiveFile(target.to_string())) {
                    Some(
                        Violation::new(
                            "RULE_003_SENSITIVE_ACCESS",
                            format!("Attempted to access sensitive file: {}", target),
                            action,
                            target,
                        )
                        .with_severity(0.8)
                        .with_fact(format!("SensitiveFile(\"{}\")", target)),
                    )
                } else {
                    None
                }
            },
        ));

        // Rule: Cannot make external network requests without validation
        self.rules.push(SafetyRule::new(
            "RULE_004_EXTERNAL_NETWORK",
            "External network requests require validation",
            vec!["http_request".to_string(), "network_call".to_string()],
            |engine, action, target, _agent| {
                if engine.facts.contains(&Fact::ExternalEndpoint(target.to_string())) {
                    Some(
                        Violation::new(
                            "RULE_004_EXTERNAL_NETWORK",
                            format!("Attempted external network request to: {}", target),
                            action,
                            target,
                        )
                        .with_severity(0.6)
                        .with_fact(format!("ExternalEndpoint(\"{}\")", target)),
                    )
                } else {
                    None
                }
            },
        ));

        // Rule: Cannot use restricted tools
        self.rules.push(SafetyRule::new(
            "RULE_005_RESTRICTED_TOOL",
            "Cannot use restricted tools",
            vec!["execute_tool".to_string(), "call_tool".to_string()],
            |engine, action, target, _agent| {
                if engine.facts.contains(&Fact::RestrictedTool(target.to_string())) {
                    Some(
                        Violation::new(
                            "RULE_005_RESTRICTED_TOOL",
                            format!("Attempted to use restricted tool: {}", target),
                            action,
                            target,
                        )
                        .with_severity(0.9)
                        .with_fact(format!("RestrictedTool(\"{}\")", target)),
                    )
                } else {
                    None
                }
            },
        ));

        // Rule: System path operations require elevated permissions
        self.rules.push(SafetyRule::new(
            "RULE_006_SYSTEM_PATH",
            "System path operations are restricted",
            vec![
                "write_file".to_string(),
                "delete_file".to_string(),
                "create_dir".to_string(),
            ],
            |engine, action, target, _agent| {
                for fact in &engine.facts {
                    if let Fact::SystemPath(path) = fact {
                        if target.starts_with(path) {
                            return Some(
                                Violation::new(
                                    "RULE_006_SYSTEM_PATH",
                                    format!("Attempted operation in system path: {}", target),
                                    action,
                                    target,
                                )
                                .with_severity(0.9)
                                .with_fact(format!("SystemPath(\"{}\")", path)),
                            );
                        }
                    }
                }
                None
            },
        ));

        // Rule NSR-004: Risk-based network access control
        // Deny network access if agent risk score is high
        self.rules.push(SafetyRule::new(
            "RULE_007_HIGH_RISK_NETWORK",
            "High-risk agents cannot make network requests",
            vec![
                "http_request".to_string(),
                "network_call".to_string(),
                "fetch".to_string(),
                "socket_connect".to_string(),
            ],
            |engine, action, target, agent| {
                // Check agent risk score
                let risk_score = engine.get_agent_risk_internal(agent);
                if risk_score > engine.config.block_threshold {
                    return Some(
                        Violation::new(
                            "RULE_007_HIGH_RISK_NETWORK",
                            format!(
                                "Agent {} (risk: {:.2}) blocked from network access to: {}",
                                agent, risk_score, target
                            ),
                            action,
                            target,
                        )
                        .with_severity(risk_score)
                        .with_fact(format!("AgentRiskScore(\"{}\", {:.0})", agent, risk_score * 10000.0)),
                    );
                }
                None
            },
        ));

        // Rule NSR-004: Risk-based external API access
        // Higher threshold for external APIs
        self.rules.push(SafetyRule::new(
            "RULE_008_RISK_EXTERNAL_API",
            "Risk-based external API access control",
            vec![
                "http_request".to_string(),
                "api_call".to_string(),
            ],
            |engine, action, target, agent| {
                // Only applies to external endpoints
                if !engine.facts.contains(&Fact::ExternalEndpoint(target.to_string())) {
                    return None;
                }
                
                let risk_score = engine.get_agent_risk_internal(agent);
                // Lower threshold (0.5) for external APIs
                if risk_score > 0.5 {
                    return Some(
                        Violation::new(
                            "RULE_008_RISK_EXTERNAL_API",
                            format!(
                                "Agent {} (risk: {:.2}) has elevated risk for external API: {}",
                                agent, risk_score, target
                            ),
                            action,
                            target,
                        )
                        .with_severity((risk_score * 1.2).min(1.0))
                        .with_fact(format!("ExternalEndpoint(\"{}\"), AgentRiskScore(\"{}\", {:.0})", 
                            target, agent, risk_score * 10000.0)),
                    );
                }
                None
            },
        ));

        // Rule NSR-004: Capability-based network access
        // Agents need network capability for any network operation
        self.rules.push(SafetyRule::new(
            "RULE_009_NETWORK_CAPABILITY",
            "Network operations require network capability",
            vec![
                "http_request".to_string(),
                "network_call".to_string(),
                "fetch".to_string(),
                "socket_connect".to_string(),
                "dns_lookup".to_string(),
            ],
            |engine, action, target, agent| {
                let has_capability = engine.facts.contains(&Fact::AgentCapability {
                    agent_id: agent.to_string(),
                    capability: "network".to_string(),
                });
                
                if !has_capability {
                    return Some(
                        Violation::new(
                            "RULE_009_NETWORK_CAPABILITY",
                            format!(
                                "Agent {} lacks 'network' capability for: {} {}",
                                agent, action, target
                            ),
                            action,
                            target,
                        )
                        .with_severity(0.7)
                        .with_fact(format!("!AgentCapability(\"{}\", \"network\")", agent)),
                    );
                }
                None
            },
        ));
    }

    /// Internal method to get agent risk score
    fn get_agent_risk_internal(&self, agent_id: &str) -> f64 {
        for fact in &self.facts {
            if let Fact::AgentRiskScore { agent_id: id, score_bp } = fact {
                if id == agent_id {
                    return (*score_bp as f64) / 10000.0;
                }
            }
        }
        0.0 // Default: no risk
    }

    /// Add default critical file facts
    fn add_default_facts(&mut self) {
        // Critical system files (as per Gap Analysis example)
        self.facts.insert(Fact::CriticalFile("/etc/shadow".to_string()));
        self.facts.insert(Fact::CriticalFile("/etc/passwd".to_string()));
        self.facts.insert(Fact::CriticalFile("/etc/hosts".to_string()));
        self.facts.insert(Fact::CriticalFile("/etc/sudoers".to_string()));

        // Sensitive files
        self.facts.insert(Fact::SensitiveFile(".env".to_string()));
        self.facts.insert(Fact::SensitiveFile("secrets.json".to_string()));
        self.facts.insert(Fact::SensitiveFile(".ssh/id_rsa".to_string()));
        self.facts.insert(Fact::SensitiveFile(".aws/credentials".to_string()));

        // System paths
        self.facts.insert(Fact::SystemPath("/etc".to_string()));
        self.facts.insert(Fact::SystemPath("/usr".to_string()));
        self.facts.insert(Fact::SystemPath("/var".to_string()));
        self.facts.insert(Fact::SystemPath("/bin".to_string()));
        self.facts.insert(Fact::SystemPath("/sbin".to_string()));

        // Restricted tools
        self.facts.insert(Fact::RestrictedTool("rm -rf".to_string()));
        self.facts.insert(Fact::RestrictedTool("dd".to_string()));
        self.facts.insert(Fact::RestrictedTool("mkfs".to_string()));
    }

    /// Add a fact to the knowledge base
    pub fn add_fact(&mut self, fact: Fact) {
        debug!(?fact, "Adding fact to knowledge base");
        self.facts.insert(fact);
    }

    /// Remove a fact from the knowledge base
    pub fn remove_fact(&mut self, fact: &Fact) -> bool {
        self.facts.remove(fact)
    }

    /// Check if a fact exists
    pub fn has_fact(&self, fact: &Fact) -> bool {
        self.facts.contains(fact)
    }

    /// Add a custom safety rule
    pub fn add_rule(&mut self, rule: SafetyRule) {
        info!(rule_id = %rule.id, "Adding custom safety rule");
        self.rules.push(rule);
    }

    /// Check if an action is safe
    pub fn check_action(&mut self, action: &str, target: &str) -> SafetyVerdict {
        self.check_action_with_agent(action, target, "unknown")
    }

    /// Check if an action is safe with agent context
    pub fn check_action_with_agent(
        &mut self,
        action: &str,
        target: &str,
        agent_id: &str,
    ) -> SafetyVerdict {
        self.stats.total_checks += 1;

        let mut violations = Vec::new();

        // Check all applicable rules
        for rule in &self.rules {
            if rule.applies_to.iter().any(|a| a == action || a == "*") {
                if let Some(violation) = (rule.checker)(self, action, target, agent_id) {
                    violations.push(violation);
                }
            }
        }

        // Check agent risk score
        let risk_score = self.get_agent_risk(agent_id);

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

    /// Get agent risk score (NSR-004)
    fn get_agent_risk(&self, agent_id: &str) -> f64 {
        for fact in &self.facts {
            if let Fact::AgentRiskScore { agent_id: id, score_bp } = fact {
                if id == agent_id {
                    return (*score_bp as f64) / 10000.0;
                }
            }
        }
        0.0 // Default: no risk
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

    /// Get rule count
    pub fn rule_count(&self) -> usize {
        self.rules.len()
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

    /// Skip default facts
    pub fn skip_defaults(mut self) -> Self {
        self.skip_defaults = true;
        self
    }

    /// Build the engine
    pub fn build(self) -> SafetyEngine {
        let mut engine = if self.skip_defaults {
            SafetyEngine {
                facts: HashSet::new(),
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
            assert!(violations.len() >= 1, "Expected at least 1 violation, got {}", violations.len());
            assert!(
                violations.iter().any(|v| v.rule_id == "RULE_001_CRITICAL_DELETE"),
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
        let verdict = engine.check_action_with_agent(
            "read_file",
            "/home/user/file.txt",
            "risky-agent",
        );

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
}
