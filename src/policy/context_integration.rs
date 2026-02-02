//! Policy Context Integration Module (POL-005)
//!
//! Provides the bridge between dynamic context collection and Cedar policy evaluation.
//! This module ensures that every policy decision has access to real-time system state,
//! agent reputation, and environmental factors.
//!
//! # Architecture
//!
//! ```text
//! Request -> Context Collector -> Cedar Evaluator -> Decision
//!                |
//!                v
//!          System Metrics
//!          Agent Reputation
//!          Time/Location
//! ```
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::policy::context_integration::{IntegratedPolicyEngine, IntegrationConfig};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let engine = IntegratedPolicyEngine::new(IntegrationConfig::default())?;
//!
//! // Authorize with full context
//! let result = engine.authorize_with_context(
//!     "agent-123",
//!     "read",
//!     "/data/secrets.json",
//! ).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Gap Analysis Section 2.2.2: Context-Aware Authorization
//! - Gap Analysis Phase 2.2: Context Injection Pipeline

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::warn;

use super::context::{
    AgentReputation, ContextConfig, DynamicContextCollector, SystemMetrics,
};
use super::enforcer::{
    Action, CedarEnforcer, Decision as PolicyDecision, EnforcerConfig, EnforcerError,
    PolicyContext, Principal, Resource,
};

/// Errors for integrated policy operations
#[derive(Debug, Error)]
pub enum IntegrationError {
    /// Context collection failed
    #[error("Context collection failed: {0}")]
    ContextError(String),

    /// Policy evaluation failed
    #[error("Policy evaluation failed: {0}")]
    PolicyError(#[from] EnforcerError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Rate limit exceeded
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// Result type for integration operations
pub type IntegrationResult<T> = Result<T, IntegrationError>;

/// Configuration for integrated policy engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Enforcer configuration
    pub enforcer: EnforcerConfig,
    /// Context collector configuration
    pub context: ContextConfig,
    /// Enable context caching
    pub cache_context: bool,
    /// Context cache TTL
    pub cache_ttl: Duration,
    /// Enable audit logging of decisions
    pub audit_decisions: bool,
    /// High-risk threshold for additional checks
    pub high_risk_threshold: f64,
    /// Enable reputation-based access control
    pub enable_reputation: bool,
}

impl Default for IntegrationConfig {
    fn default() -> Self {
        Self {
            enforcer: EnforcerConfig::default(),
            context: ContextConfig::default(),
            cache_context: true,
            cache_ttl: Duration::from_secs(30),
            audit_decisions: true,
            high_risk_threshold: 0.7,
            enable_reputation: true,
        }
    }
}

impl IntegrationConfig {
    /// Create production configuration
    pub fn production() -> Self {
        Self {
            enforcer: EnforcerConfig::strict(),
            context: ContextConfig::production(),
            cache_context: true,
            cache_ttl: Duration::from_secs(60),
            audit_decisions: true,
            high_risk_threshold: 0.6,
            enable_reputation: true,
        }
    }

    /// Create test configuration
    pub fn for_testing() -> Self {
        Self {
            enforcer: EnforcerConfig::permissive(),
            context: ContextConfig::minimal(),
            cache_context: false,
            cache_ttl: Duration::from_secs(0),
            audit_decisions: false,
            high_risk_threshold: 0.9,
            enable_reputation: false,
        }
    }
}

/// Enriched authorization decision with context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedDecision {
    /// Base policy decision
    pub decision: PolicyDecision,
    /// Context used for evaluation
    pub context_snapshot: ContextSnapshot,
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
    /// Decision timestamp
    pub timestamp: u64,
    /// Evaluation duration (microseconds)
    pub evaluation_duration_us: u64,
}

impl EnrichedDecision {
    /// Check if action is allowed
    pub fn is_allowed(&self) -> bool {
        self.decision.is_allowed() && !self.risk_assessment.blocked_by_risk
    }

    /// Get denial reason
    pub fn denial_reason(&self) -> Option<String> {
        if self.risk_assessment.blocked_by_risk {
            Some(format!(
                "Blocked by risk assessment: score {} exceeds threshold",
                self.risk_assessment.risk_score
            ))
        } else if !self.decision.is_allowed() {
            Some(self.decision.reason().to_string())
        } else {
            None
        }
    }
}

/// Snapshot of context at decision time
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSnapshot {
    /// System load at decision time
    pub system_load: Option<f64>,
    /// Agent trust score
    pub trust_score: Option<f64>,
    /// Alert mode active
    pub alert_mode: bool,
    /// Decision timestamp
    pub timestamp: u64,
}

/// Risk assessment result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    /// Computed risk score (0.0 - 1.0)
    pub risk_score: f64,
    /// Risk factors identified
    pub risk_factors: Vec<RiskFactor>,
    /// Whether request was blocked by risk
    pub blocked_by_risk: bool,
    /// Suggested mitigations
    pub mitigations: Vec<String>,
}

/// Individual risk factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    /// Factor name
    pub name: String,
    /// Factor weight (0.0 - 1.0)
    pub weight: f64,
    /// Factor description
    pub description: String,
}

/// Integrated policy engine combining context and enforcement
pub struct IntegratedPolicyEngine {
    config: IntegrationConfig,
    /// Policy enforcer
    enforcer: Arc<CedarEnforcer>,
    /// Context collector
    context_collector: Arc<DynamicContextCollector>,
    /// Decision audit log
    audit_log: Arc<RwLock<Vec<EnrichedDecision>>>,
}

impl std::fmt::Debug for IntegratedPolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntegratedPolicyEngine")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl IntegratedPolicyEngine {
    /// Create a new integrated policy engine
    pub fn new(config: IntegrationConfig) -> IntegrationResult<Self> {
        let enforcer = CedarEnforcer::new(config.enforcer.clone())
            .map_err(|e| IntegrationError::PolicyError(e))?;
        let context_collector = DynamicContextCollector::new(config.context.clone());

        Ok(Self {
            config,
            enforcer: Arc::new(enforcer),
            context_collector: Arc::new(context_collector),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create with permissive defaults (for testing)
    pub fn permissive() -> Self {
        let enforcer = CedarEnforcer::new_permissive();
        let context_collector = DynamicContextCollector::new(ContextConfig::minimal());

        Self {
            config: IntegrationConfig::for_testing(),
            enforcer: Arc::new(enforcer),
            context_collector: Arc::new(context_collector),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Authorize with full context collection
    pub async fn authorize_with_context(
        &self,
        agent_id: &str,
        action: &str,
        resource: &str,
    ) -> IntegrationResult<EnrichedDecision> {
        let start = Instant::now();

        // Collect context
        let context = self.collect_context_for_agent(agent_id).await?;

        // Perform risk assessment
        let risk_assessment = self.assess_risk(agent_id, action, resource, &context).await;

        // If high risk, potentially block
        if risk_assessment.blocked_by_risk {
            warn!(
                agent_id = %agent_id,
                action = %action,
                resource = %resource,
                risk_score = %risk_assessment.risk_score,
                "Request blocked by risk assessment"
            );
        }

        // Build Cedar entities
        let principal = Principal::agent(agent_id);
        let cedar_action = Action::new("Agent", action);
        let cedar_resource = Resource::new("Resource", resource);

        // Evaluate policy with context
        let decision = self
            .enforcer
            .authorize(&principal, &cedar_action, &cedar_resource, Some(&context))
            .await?;

        let enriched = EnrichedDecision {
            decision,
            context_snapshot: ContextSnapshot {
                system_load: context.system_load,
                trust_score: context.trust_score,
                alert_mode: context.alert_mode.unwrap_or(false),
                timestamp: current_timestamp(),
            },
            risk_assessment,
            timestamp: current_timestamp(),
            evaluation_duration_us: start.elapsed().as_micros() as u64,
        };

        // Update reputation based on decision
        self.update_reputation_after_decision(agent_id, action, &enriched)
            .await;

        // Audit log
        if self.config.audit_decisions {
            self.log_decision(&enriched).await;
        }

        Ok(enriched)
    }

    /// Authorize without context (faster, less accurate)
    pub async fn authorize_simple(
        &self,
        agent_id: &str,
        action: &str,
        resource: &str,
    ) -> IntegrationResult<PolicyDecision> {
        let principal = Principal::agent(agent_id);
        let cedar_action = Action::new("Agent", action);
        let cedar_resource = Resource::new("Resource", resource);

        Ok(self.enforcer.authorize(&principal, &cedar_action, &cedar_resource, None).await?)
    }

    /// Batch authorization with context
    pub async fn authorize_batch(
        &self,
        agent_id: &str,
        requests: &[(String, String)], // (action, resource)
    ) -> IntegrationResult<Vec<EnrichedDecision>> {
        // Collect context once
        let context = self.collect_context_for_agent(agent_id).await?;

        let mut results = Vec::with_capacity(requests.len());

        for (action, resource) in requests {
            let start = Instant::now();
            let risk_assessment = self.assess_risk(agent_id, action, resource, &context).await;

            let principal = Principal::agent(agent_id);
            let cedar_action = Action::new("Agent", action);
            let cedar_resource = Resource::new("Resource", resource);

            let decision = self
                .enforcer
                .authorize(&principal, &cedar_action, &cedar_resource, Some(&context))
                .await?;

            results.push(EnrichedDecision {
                decision,
                context_snapshot: ContextSnapshot {
                    system_load: context.system_load,
                    trust_score: context.trust_score,
                    alert_mode: context.alert_mode.unwrap_or(false),
                    timestamp: current_timestamp(),
                },
                risk_assessment,
                timestamp: current_timestamp(),
                evaluation_duration_us: start.elapsed().as_micros() as u64,
            });
        }

        Ok(results)
    }

    /// Collect context for an agent
    async fn collect_context_for_agent(&self, agent_id: &str) -> IntegrationResult<PolicyContext> {
        self.context_collector
            .collect_context(agent_id)
            .await
            .map_err(|e| IntegrationError::ContextError(e.to_string()))
    }

    /// Assess risk for a request
    async fn assess_risk(
        &self,
        _agent_id: &str,
        action: &str,
        resource: &str,
        context: &PolicyContext,
    ) -> RiskAssessment {
        let mut risk_factors = Vec::new();
        let mut total_risk = 0.0;

        // Factor 1: Trust score (inverted)
        if let Some(trust_score) = context.trust_score {
            let risk = 1.0 - trust_score;
            if risk > 0.3 {
                risk_factors.push(RiskFactor {
                    name: "low_trust".to_string(),
                    weight: risk * 0.3,
                    description: format!("Agent trust score is low: {:.2}", trust_score),
                });
                total_risk += risk * 0.3;
            }
        }

        // Factor 2: System load
        if let Some(load) = context.system_load {
            if load > 0.8 {
                risk_factors.push(RiskFactor {
                    name: "high_load".to_string(),
                    weight: (load - 0.8) * 0.5,
                    description: format!("System under high load: {:.2}", load),
                });
                total_risk += (load - 0.8) * 0.2;
            }
        }

        // Factor 3: Sensitive resource access
        let sensitive_patterns = vec![
            "secret",
            "password",
            "key",
            "credential",
            "private",
            "/etc/",
            ".env",
        ];
        if sensitive_patterns.iter().any(|p| resource.to_lowercase().contains(p)) {
            risk_factors.push(RiskFactor {
                name: "sensitive_resource".to_string(),
                weight: 0.3,
                description: "Accessing potentially sensitive resource".to_string(),
            });
            total_risk += 0.3;
        }

        // Factor 4: Destructive action
        let destructive_actions = vec!["delete", "drop", "remove", "truncate", "destroy"];
        if destructive_actions.iter().any(|a| action.to_lowercase().contains(a)) {
            risk_factors.push(RiskFactor {
                name: "destructive_action".to_string(),
                weight: 0.4,
                description: "Performing potentially destructive action".to_string(),
            });
            total_risk += 0.4;
        }

        // Factor 5: Alert mode
        if context.alert_mode.unwrap_or(false) {
            risk_factors.push(RiskFactor {
                name: "alert_mode".to_string(),
                weight: 0.2,
                description: "System is in alert mode".to_string(),
            });
            total_risk += 0.2;
        }

        let risk_score = total_risk.min(1.0);
        let blocked_by_risk = self.config.enable_reputation
            && risk_score > self.config.high_risk_threshold;

        let mut mitigations = Vec::new();
        if risk_score > 0.5 {
            mitigations.push("Consider using a more privileged agent".to_string());
            mitigations.push("Wait for system load to decrease".to_string());
        }
        if blocked_by_risk {
            mitigations.push("Request manual approval".to_string());
        }

        RiskAssessment {
            risk_score,
            risk_factors,
            blocked_by_risk,
            mitigations,
        }
    }

    /// Update agent reputation after a decision
    async fn update_reputation_after_decision(
        &self,
        agent_id: &str,
        action: &str,
        decision: &EnrichedDecision,
    ) {
        if !self.config.enable_reputation {
            return;
        }

        let success = decision.is_allowed();
        let violation = !decision.decision.is_allowed();

        self.context_collector
            .update_reputation(agent_id, action, success, violation)
            .await;
    }

    /// Log a decision to the audit log
    async fn log_decision(&self, decision: &EnrichedDecision) {
        let mut log = self.audit_log.write().await;
        log.push(decision.clone());

        // Keep audit log bounded
        if log.len() > 10000 {
            log.drain(0..5000);
        }
    }

    /// Get recent audit decisions
    pub async fn get_audit_log(&self, limit: usize) -> Vec<EnrichedDecision> {
        let log = self.audit_log.read().await;
        log.iter().rev().take(limit).cloned().collect()
    }

    /// Update system metrics
    pub async fn update_system_metrics(&self, metrics: SystemMetrics) {
        self.context_collector.update_system_metrics(metrics).await;
    }

    /// Get agent reputation
    pub async fn get_agent_reputation(&self, agent_id: &str) -> Option<AgentReputation> {
        self.context_collector.get_reputation(agent_id).await
    }

    /// Load policies from file
    pub async fn load_policies(&self, path: &str) -> IntegrationResult<()> {
        self.enforcer
            .load_policies(path)
            .await
            .map_err(|e| IntegrationError::PolicyError(e))
    }
}

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integrated_engine_creation() {
        let engine = IntegratedPolicyEngine::permissive();
        assert!(engine.config.enforcer.enabled);
    }

    #[tokio::test]
    async fn test_simple_authorization() {
        let engine = IntegratedPolicyEngine::permissive();
        let decision = engine.authorize_simple("agent-1", "read", "/data/file.txt").unwrap();
        assert!(decision.is_allowed());
    }

    #[tokio::test]
    async fn test_context_authorization() {
        let engine = IntegratedPolicyEngine::permissive();
        let decision = engine
            .authorize_with_context("agent-1", "read", "/data/file.txt")
            .await
            .unwrap();

        assert!(decision.context_snapshot.timestamp > 0);
        assert!(decision.evaluation_duration_us > 0);
    }

    #[tokio::test]
    async fn test_risk_assessment_sensitive_resource() {
        let engine = IntegratedPolicyEngine::permissive();
        let decision = engine
            .authorize_with_context("agent-1", "read", "/secrets/api_key")
            .await
            .unwrap();

        assert!(decision.risk_assessment.risk_score > 0.0);
        assert!(decision
            .risk_assessment
            .risk_factors
            .iter()
            .any(|f| f.name == "sensitive_resource"));
    }

    #[tokio::test]
    async fn test_risk_assessment_destructive_action() {
        let engine = IntegratedPolicyEngine::permissive();
        let decision = engine
            .authorize_with_context("agent-1", "delete", "/data/file.txt")
            .await
            .unwrap();

        assert!(decision.risk_assessment.risk_score > 0.0);
        assert!(decision
            .risk_assessment
            .risk_factors
            .iter()
            .any(|f| f.name == "destructive_action"));
    }

    #[tokio::test]
    async fn test_batch_authorization() {
        let engine = IntegratedPolicyEngine::permissive();
        let requests = vec![
            ("read".to_string(), "/file1.txt".to_string()),
            ("write".to_string(), "/file2.txt".to_string()),
        ];

        let results = engine.authorize_batch("agent-1", &requests).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_audit_log() {
        let config = IntegrationConfig {
            audit_decisions: true,
            ..IntegrationConfig::for_testing()
        };
        let engine = IntegratedPolicyEngine::new(config).unwrap();

        // Make some decisions
        engine
            .authorize_with_context("agent-1", "read", "/file.txt")
            .await
            .unwrap();

        let log = engine.get_audit_log(10).await;
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn test_enriched_decision_denial() {
        let decision = EnrichedDecision {
            decision: PolicyDecision::deny("Test denial"),
            context_snapshot: ContextSnapshot {
                system_load: Some(0.5),
                trust_score: Some(0.8),
                alert_mode: false,
                timestamp: 0,
            },
            risk_assessment: RiskAssessment {
                risk_score: 0.3,
                risk_factors: vec![],
                blocked_by_risk: false,
                mitigations: vec![],
            },
            timestamp: 0,
            evaluation_duration_us: 100,
        };

        assert!(!decision.is_allowed());
        assert!(decision.denial_reason().is_some());
    }
}
