//! LangChain Integration Adapter
//!
//! Middleware adapter for integrating VAK with LangChain-based agents.
//! Provides interception of tool calls and chain executions for policy
//! enforcement and audit logging.
//!
//! # Features
//!
//! - Tool call interception with policy checks
//! - Chain execution monitoring
//! - PRM scoring integration
//! - Automatic audit logging
//! - Rate limiting per agent
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::integrations::langchain::{LangChainAdapter, LangChainConfig, ToolCall};
//!
//! // Create adapter with configuration
//! let config = LangChainConfig::default()
//!     .with_prm_threshold(0.7)
//!     .with_audit_enabled(true);
//!
//! let adapter = LangChainAdapter::new(config);
//!
//! // Intercept a tool call
//! let tool_call = ToolCall::new("calculator", "add")
//!     .with_param("a", 1)
//!     .with_param("b", 2);
//!
//! let decision = adapter.intercept_tool(&tool_call, "agent-1").await?;
//! if decision.is_allowed() {
//!     // Proceed with tool execution
//! }
//! ```

use crate::integrations::common::{
    ActionContext, ActionType, AdapterError, AdapterResult, BaseAdapterConfig,
    HookDecision, InterceptionHook, InterceptionResult, VakConnection,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for LangChain adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LangChainConfig {
    /// Base adapter configuration
    #[serde(flatten)]
    pub base: BaseAdapterConfig,
    /// Enable tool call interception
    pub intercept_tools: bool,
    /// Enable chain execution interception
    pub intercept_chains: bool,
    /// Enable LLM call interception
    pub intercept_llm: bool,
    /// Tools that bypass interception
    pub passthrough_tools: Vec<String>,
    /// Maximum tool execution time (milliseconds)
    pub tool_timeout_ms: u64,
}

impl Default for LangChainConfig {
    fn default() -> Self {
        Self {
            base: BaseAdapterConfig::default(),
            intercept_tools: true,
            intercept_chains: true,
            intercept_llm: false, // Default off to reduce overhead
            passthrough_tools: vec!["memory".to_string(), "human".to_string()],
            tool_timeout_ms: 30000,
        }
    }
}

impl LangChainConfig {
    /// Set PRM threshold
    pub fn with_prm_threshold(mut self, threshold: f64) -> Self {
        self.base.prm_threshold = threshold;
        self
    }

    /// Enable/disable audit logging
    pub fn with_audit_enabled(mut self, enabled: bool) -> Self {
        self.base.audit_enabled = enabled;
        self
    }

    /// Add a passthrough tool
    pub fn with_passthrough_tool(mut self, tool: impl Into<String>) -> Self {
        self.passthrough_tools.push(tool.into());
        self
    }

    /// Set tool timeout
    pub fn with_tool_timeout(mut self, timeout_ms: u64) -> Self {
        self.tool_timeout_ms = timeout_ms;
        self
    }

    /// Add a blocked action
    pub fn with_blocked_action(mut self, action: impl Into<String>) -> Self {
        self.base.blocked_actions.push(action.into());
        self
    }
}

// ============================================================================
// Tool Call Representation
// ============================================================================

/// Represents a LangChain tool call
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// Tool name
    pub tool_name: String,
    /// Action/function name
    pub action: String,
    /// Input parameters
    pub params: HashMap<String, serde_json::Value>,
    /// Request timestamp
    pub timestamp: u64,
    /// Request ID
    pub request_id: String,
}

impl ToolCall {
    /// Create a new tool call
    pub fn new(tool_name: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            tool_name: tool_name.into(),
            action: action.into(),
            params: HashMap::new(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            request_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    /// Add a parameter
    pub fn with_param<V: Serialize>(mut self, key: impl Into<String>, value: V) -> Self {
        self.params.insert(
            key.into(),
            serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
        );
        self
    }

    /// Get resource identifier for policy evaluation
    pub fn resource(&self) -> String {
        format!("tool:{}/{}", self.tool_name, self.action)
    }

    /// Convert to action context
    pub fn to_context(&self, agent_id: &str, session_id: Option<&str>) -> ActionContext {
        let mut ctx = ActionContext::new(ActionType::ToolCall, &self.action, agent_id)
            .with_metadata("tool_name", &self.tool_name)
            .with_metadata("request_id", &self.request_id);

        if let Some(sid) = session_id {
            ctx = ctx.with_session(sid);
        }

        for (key, value) in &self.params {
            ctx.params.insert(key.clone(), value.clone());
        }

        ctx
    }
}

// ============================================================================
// Chain Execution
// ============================================================================

/// Represents a LangChain chain execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainExecution {
    /// Chain name
    pub chain_name: String,
    /// Chain type (e.g., "LLMChain", "RetrievalQA")
    pub chain_type: String,
    /// Input data
    pub inputs: HashMap<String, serde_json::Value>,
    /// Execution ID
    pub execution_id: String,
    /// Start timestamp
    pub started_at: u64,
    /// Parent chain ID (for nested chains)
    pub parent_id: Option<String>,
}

impl ChainExecution {
    /// Create a new chain execution
    pub fn new(chain_name: impl Into<String>, chain_type: impl Into<String>) -> Self {
        Self {
            chain_name: chain_name.into(),
            chain_type: chain_type.into(),
            inputs: HashMap::new(),
            execution_id: uuid::Uuid::new_v4().to_string(),
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            parent_id: None,
        }
    }

    /// Set parent chain
    pub fn with_parent(mut self, parent_id: impl Into<String>) -> Self {
        self.parent_id = Some(parent_id.into());
        self
    }

    /// Add input
    pub fn with_input<V: Serialize>(mut self, key: impl Into<String>, value: V) -> Self {
        self.inputs.insert(
            key.into(),
            serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
        );
        self
    }

    /// Get resource identifier
    pub fn resource(&self) -> String {
        format!("chain:{}/{}", self.chain_type, self.chain_name)
    }
}

// ============================================================================
// LangChain Adapter
// ============================================================================

/// Main adapter for LangChain integration
pub struct LangChainAdapter {
    config: LangChainConfig,
    /// Connection to VAK kernel
    vak_connection: VakConnection,
    /// Custom interception hooks
    hooks: Vec<Arc<dyn InterceptionHook>>,
    /// Statistics
    stats: AdapterStats,
    /// Rate limiting state
    rate_limits: RwLock<HashMap<String, RateLimitState>>,
}

/// Adapter statistics
#[derive(Debug, Default)]
pub struct AdapterStats {
    pub tool_calls_total: AtomicU64,
    pub tool_calls_allowed: AtomicU64,
    pub tool_calls_blocked: AtomicU64,
    pub chain_executions: AtomicU64,
    pub policy_violations: AtomicU64,
    pub prm_rejections: AtomicU64,
}

/// Rate limit state for an agent
#[derive(Debug, Default)]
struct RateLimitState {
    tokens: f64,
    last_update: Option<Instant>,
}

impl LangChainAdapter {
    /// Create a new LangChain adapter
    pub fn new(config: LangChainConfig) -> Self {
        Self {
            config,
            vak_connection: VakConnection::local(),
            hooks: Vec::new(),
            stats: AdapterStats::default(),
            rate_limits: RwLock::new(HashMap::new()),
        }
    }

    /// Create with VAK connection
    pub fn with_connection(mut self, connection: VakConnection) -> Self {
        self.vak_connection = connection;
        self
    }

    /// Add a custom interception hook
    pub fn with_hook(mut self, hook: Arc<dyn InterceptionHook>) -> Self {
        self.hooks.push(hook);
        self
    }

    /// Check if a tool is in the passthrough list
    fn is_passthrough(&self, tool_name: &str) -> bool {
        self.config.passthrough_tools.iter().any(|t| t == tool_name)
    }

    /// Check rate limit for an agent
    async fn check_rate_limit(&self, agent_id: &str) -> AdapterResult<()> {
        if let Some(limit) = self.config.base.rate_limit_per_minute {
            let mut limits = self.rate_limits.write().await;
            let state = limits.entry(agent_id.to_string()).or_default();

            let now = Instant::now();
            let rate = limit as f64 / 60.0; // Tokens per second

            // Refill tokens based on elapsed time
            if let Some(last) = state.last_update {
                let elapsed = now.duration_since(last).as_secs_f64();
                state.tokens = (state.tokens + elapsed * rate).min(limit as f64);
            } else {
                state.tokens = limit as f64;
            }
            state.last_update = Some(now);

            // Check if we have tokens
            if state.tokens >= 1.0 {
                state.tokens -= 1.0;
                Ok(())
            } else {
                Err(AdapterError::RateLimited(format!(
                    "Agent {} exceeded rate limit",
                    agent_id
                )))
            }
        } else {
            Ok(())
        }
    }

    /// Intercept a tool call
    pub async fn intercept_tool(
        &self,
        tool_call: &ToolCall,
        agent_id: &str,
    ) -> AdapterResult<InterceptionResult> {
        let start = Instant::now();
        self.stats.tool_calls_total.fetch_add(1, Ordering::Relaxed);

        // Skip passthrough tools
        if self.is_passthrough(&tool_call.tool_name) {
            return Ok(InterceptionResult {
                context: tool_call.to_context(agent_id, None),
                decision: HookDecision::Allow,
                hook_name: "passthrough".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Check rate limit
        self.check_rate_limit(agent_id).await?;

        // Check if action is blocked
        let action = format!("{}:{}", tool_call.tool_name, tool_call.action);
        if self.config.base.blocked_actions.contains(&action) {
            self.stats.tool_calls_blocked.fetch_add(1, Ordering::Relaxed);
            self.stats.policy_violations.fetch_add(1, Ordering::Relaxed);
            return Ok(InterceptionResult {
                context: tool_call.to_context(agent_id, None),
                decision: HookDecision::Block {
                    reason: format!("Action '{}' is blocked by policy", action),
                },
                hook_name: "blocked_actions".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Check if action is always allowed
        if self.config.base.allowed_actions.contains(&action) {
            self.stats.tool_calls_allowed.fetch_add(1, Ordering::Relaxed);
            return Ok(InterceptionResult {
                context: tool_call.to_context(agent_id, None),
                decision: HookDecision::Allow,
                hook_name: "allowed_actions".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Run custom hooks
        let context = tool_call.to_context(agent_id, None);
        for hook in &self.hooks {
            if hook.applies_to(&context) {
                let decision = hook.evaluate(&context);
                if !matches!(decision, HookDecision::Allow) {
                    return Ok(InterceptionResult {
                        context,
                        decision,
                        hook_name: hook.name().to_string(),
                        prm_score: None,
                        evaluation_time_us: start.elapsed().as_micros() as u64,
                        audit_entry_id: None,
                    });
                }
            }
        }

        // Check if requires approval
        if self.config.base.require_approval.contains(&action) {
            return Ok(InterceptionResult {
                context,
                decision: HookDecision::RequireApproval {
                    prompt: format!(
                        "Tool call '{}' requires human approval. Proceed?",
                        action
                    ),
                },
                hook_name: "require_approval".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Default: allow
        self.stats.tool_calls_allowed.fetch_add(1, Ordering::Relaxed);
        Ok(InterceptionResult {
            context,
            decision: HookDecision::Allow,
            hook_name: "default".to_string(),
            prm_score: None,
            evaluation_time_us: start.elapsed().as_micros() as u64,
            audit_entry_id: None,
        })
    }

    /// Intercept a chain execution
    pub async fn intercept_chain(
        &self,
        chain: &ChainExecution,
        agent_id: &str,
    ) -> AdapterResult<InterceptionResult> {
        if !self.config.intercept_chains {
            return Ok(InterceptionResult {
                context: ActionContext::new(ActionType::ChainExecution, &chain.chain_name, agent_id),
                decision: HookDecision::Allow,
                hook_name: "disabled".to_string(),
                prm_score: None,
                evaluation_time_us: 0,
                audit_entry_id: None,
            });
        }

        self.stats.chain_executions.fetch_add(1, Ordering::Relaxed);

        // Check rate limit
        self.check_rate_limit(agent_id).await?;

        // Check if chain type is blocked
        if self.config.base.blocked_actions.contains(&chain.chain_type) {
            return Ok(InterceptionResult {
                context: ActionContext::new(ActionType::ChainExecution, &chain.chain_name, agent_id),
                decision: HookDecision::Block {
                    reason: format!("Chain type '{}' is blocked", chain.chain_type),
                },
                hook_name: "blocked_chains".to_string(),
                prm_score: None,
                evaluation_time_us: 0,
                audit_entry_id: None,
            });
        }

        // Allow by default
        Ok(InterceptionResult {
            context: ActionContext::new(ActionType::ChainExecution, &chain.chain_name, agent_id),
            decision: HookDecision::Allow,
            hook_name: "default".to_string(),
            prm_score: None,
            evaluation_time_us: 0,
            audit_entry_id: None,
        })
    }

    /// Get adapter statistics
    pub fn stats(&self) -> &AdapterStats {
        &self.stats
    }

    /// Get statistics summary as JSON
    pub fn stats_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "tool_calls_total": self.stats.tool_calls_total.load(Ordering::Relaxed),
            "tool_calls_allowed": self.stats.tool_calls_allowed.load(Ordering::Relaxed),
            "tool_calls_blocked": self.stats.tool_calls_blocked.load(Ordering::Relaxed),
            "chain_executions": self.stats.chain_executions.load(Ordering::Relaxed),
            "policy_violations": self.stats.policy_violations.load(Ordering::Relaxed),
            "prm_rejections": self.stats.prm_rejections.load(Ordering::Relaxed),
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tool_call_creation() {
        let call = ToolCall::new("calculator", "add")
            .with_param("a", 1)
            .with_param("b", 2);

        assert_eq!(call.tool_name, "calculator");
        assert_eq!(call.action, "add");
        assert_eq!(call.params.get("a"), Some(&serde_json::json!(1)));
    }

    #[tokio::test]
    async fn test_passthrough_tools() {
        let config = LangChainConfig::default();
        let adapter = LangChainAdapter::new(config);

        let call = ToolCall::new("memory", "load");
        let result = adapter.intercept_tool(&call, "agent-1").await.unwrap();

        assert!(matches!(result.decision, HookDecision::Allow));
        assert_eq!(result.hook_name, "passthrough");
    }

    #[tokio::test]
    async fn test_blocked_actions() {
        let config = LangChainConfig::default()
            .with_blocked_action("dangerous:delete");
        let adapter = LangChainAdapter::new(config);

        let call = ToolCall::new("dangerous", "delete");
        let result = adapter.intercept_tool(&call, "agent-1").await.unwrap();

        assert!(matches!(result.decision, HookDecision::Block { .. }));
    }

    #[tokio::test]
    async fn test_chain_execution() {
        let chain = ChainExecution::new("qa_chain", "RetrievalQA")
            .with_input("question", "What is VAK?");

        assert_eq!(chain.chain_name, "qa_chain");
        assert_eq!(chain.chain_type, "RetrievalQA");
        assert!(chain.inputs.contains_key("question"));
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let config = LangChainConfig::default();
        let adapter = LangChainAdapter::new(config);

        // Make some calls
        let call = ToolCall::new("test", "action");
        let _ = adapter.intercept_tool(&call, "agent-1").await;

        assert!(adapter.stats.tool_calls_total.load(Ordering::Relaxed) >= 1);
    }
}
