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
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
//! if matches!(decision.decision, vak::integrations::common::HookDecision::Allow) {
//!     // Proceed with tool execution
//! }
//! # Ok(())
//! # }
//! ```

use crate::integrations::common::{
    ActionContext, ActionType, AdapterError, AdapterResult, BaseAdapterConfig, HookDecision,
    InterceptionHook, InterceptionResult, VakConnection,
};
use crate::kernel::rate_limiter::{RateLimiter, ResourceKey};
use crate::reasoner::{ProcessRewardModel, ReasoningStep};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

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
    /// Rate limiter (optional)
    rate_limiter: Option<Arc<RateLimiter>>,
    /// PRM model (optional)
    prm: Option<Arc<dyn ProcessRewardModel>>,
    /// Callback handlers for lifecycle events (INT-003)
    callbacks: Vec<Arc<dyn LangChainCallbackHandler>>,
}

/// Adapter statistics
#[derive(Debug, Default)]
pub struct AdapterStats {
    /// Total number of tool calls intercepted
    pub tool_calls_total: AtomicU64,
    /// Number of tool calls that were allowed
    pub tool_calls_allowed: AtomicU64,
    /// Number of tool calls that were blocked
    pub tool_calls_blocked: AtomicU64,
    /// Number of chain executions intercepted
    pub chain_executions: AtomicU64,
    /// Number of policy violations detected
    pub policy_violations: AtomicU64,
    /// Number of rejections due to low PRM scores
    pub prm_rejections: AtomicU64,
}

impl LangChainAdapter {
    /// Create a new LangChain adapter
    pub fn new(config: LangChainConfig) -> Self {
        Self {
            config,
            vak_connection: VakConnection::local(),
            hooks: Vec::new(),
            stats: AdapterStats::default(),
            rate_limiter: None,
            prm: None,
            callbacks: Vec::new(),
        }
    }

    /// Create with VAK connection
    pub fn with_connection(mut self, connection: VakConnection) -> Self {
        self.vak_connection = connection;
        self
    }

    /// Set rate limiter
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<RateLimiter>) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Set PRM model
    pub fn with_prm(mut self, prm: Arc<dyn ProcessRewardModel>) -> Self {
        self.prm = Some(prm);
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
        if let Some(limiter) = &self.rate_limiter {
            // Check global agent limit
            let key = ResourceKey::new(agent_id, "execute", "tool");
            let result = limiter.check(&key).await;
            if !result.allowed {
                return Err(AdapterError::RateLimited(format!(
                    "Agent {} exceeded rate limit. Retry after {}s",
                    agent_id,
                    result.retry_after_secs.unwrap_or(1)
                )));
            }
        }
        Ok(())
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
            self.stats
                .tool_calls_blocked
                .fetch_add(1, Ordering::Relaxed);
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
            self.stats
                .tool_calls_allowed
                .fetch_add(1, Ordering::Relaxed);
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
                    prompt: format!("Tool call '{}' requires human approval. Proceed?", action),
                },
                hook_name: "require_approval".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Default: allow
        self.stats
            .tool_calls_allowed
            .fetch_add(1, Ordering::Relaxed);
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
                context: ActionContext::new(
                    ActionType::ChainExecution,
                    &chain.chain_name,
                    agent_id,
                ),
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
                context: ActionContext::new(
                    ActionType::ChainExecution,
                    &chain.chain_name,
                    agent_id,
                ),
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

    /// Intercept a tool call with full PRM scoring integration (INT-003)
    ///
    /// This method performs comprehensive evaluation including:
    /// - Rate limiting checks
    /// - Policy evaluation
    /// - PRM scoring for reasoning quality
    /// - Audit logging
    ///
    /// # Arguments
    /// * `tool_call` - The tool call to evaluate
    /// * `agent_id` - Identifier of the calling agent
    /// * `reasoning_context` - Optional reasoning context for PRM scoring
    ///
    /// # Returns
    /// * `InterceptionResult` with detailed evaluation including PRM score
    pub async fn intercept_tool_with_prm(
        &self,
        tool_call: &ToolCall,
        agent_id: &str,
        reasoning_context: Option<&ReasoningContext>,
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
            self.stats
                .tool_calls_blocked
                .fetch_add(1, Ordering::Relaxed);
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

        // PRM scoring if reasoning context is provided
        let prm_score = if let Some(ctx) = reasoning_context {
            let score = self.evaluate_prm_score(ctx, &action).await;

            // Check against threshold
            if score < self.config.base.prm_threshold {
                self.stats.prm_rejections.fetch_add(1, Ordering::Relaxed);
                self.stats
                    .tool_calls_blocked
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(InterceptionResult {
                    context: tool_call.to_context(agent_id, None),
                    decision: HookDecision::Block {
                        reason: format!(
                            "PRM score {:.2} below threshold {:.2}. Reasoning quality insufficient.",
                            score, self.config.base.prm_threshold
                        ),
                    },
                    hook_name: "prm_gating".to_string(),
                    prm_score: Some(score),
                    evaluation_time_us: start.elapsed().as_micros() as u64,
                    audit_entry_id: None,
                });
            }
            Some(score)
        } else {
            None
        };

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
                        prm_score,
                        evaluation_time_us: start.elapsed().as_micros() as u64,
                        audit_entry_id: None,
                    });
                }
            }
        }

        // Default: allow
        self.stats
            .tool_calls_allowed
            .fetch_add(1, Ordering::Relaxed);
        Ok(InterceptionResult {
            context,
            decision: HookDecision::Allow,
            hook_name: "default".to_string(),
            prm_score,
            evaluation_time_us: start.elapsed().as_micros() as u64,
            audit_entry_id: None,
        })
    }

    /// Evaluate PRM score for a reasoning context
    async fn evaluate_prm_score(&self, ctx: &ReasoningContext, action: &str) -> f64 {
        // Use real PRM if available
        if let Some(prm) = &self.prm {
            let step_num = ctx.reasoning_steps.len() + 1;
            let thought = ctx.reasoning_steps.last().cloned().unwrap_or_default();
            let step = ReasoningStep::new(step_num, thought).with_action(action);

            let context_str = ctx
                .goal
                .clone()
                .unwrap_or_else(|| "Unknown goal".to_string());

            match prm.score_step(&step, &context_str).await {
                Ok(score) => return score.score,
                Err(e) => {
                    tracing::warn!("PRM scoring failed: {}", e);
                    // Fallback to heuristic
                }
            }
        }

        // Simplified PRM scoring based on reasoning quality indicators (fallback)
        let mut score = 0.5; // Base score

        // Check reasoning chain length (longer chains may indicate more thorough reasoning)
        if ctx.reasoning_steps.len() >= 2 {
            score += 0.1;
        }

        // Check for presence of observation and planning
        if ctx.has_observation {
            score += 0.1;
        }
        if ctx.has_plan {
            score += 0.1;
        }

        // Check confidence
        score += ctx.confidence * 0.2;

        // Penalize if action seems risky without proper justification
        let risky_actions = ["delete", "write", "execute", "modify", "remove"];
        let action_lower = action.to_lowercase();
        if risky_actions.iter().any(|r| action_lower.contains(r))
            && (ctx.reasoning_steps.len() < 3 || !ctx.has_plan) {
                score -= 0.2;
            }

        score.clamp(0.0, 1.0)
    }

    /// Batch intercept multiple tool calls
    pub async fn intercept_tools_batch(
        &self,
        tool_calls: &[ToolCall],
        agent_id: &str,
    ) -> Vec<AdapterResult<InterceptionResult>> {
        let mut results = Vec::with_capacity(tool_calls.len());
        for call in tool_calls {
            results.push(self.intercept_tool(call, agent_id).await);
        }
        results
    }
}

/// Reasoning context for PRM scoring (INT-003)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReasoningContext {
    /// Reasoning steps taken so far
    pub reasoning_steps: Vec<String>,
    /// Whether the agent made an observation
    pub has_observation: bool,
    /// Whether the agent has a plan
    pub has_plan: bool,
    /// Agent's confidence in the action (0.0 - 1.0)
    pub confidence: f64,
    /// Goal being pursued
    pub goal: Option<String>,
    /// Previous actions in this reasoning chain
    pub previous_actions: Vec<String>,
}

impl Default for ReasoningContext {
    fn default() -> Self {
        Self {
            reasoning_steps: Vec::new(),
            has_observation: false,
            has_plan: false,
            confidence: 0.5,
            goal: None,
            previous_actions: Vec::new(),
        }
    }
}

impl ReasoningContext {
    /// Create a new reasoning context
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a reasoning step
    pub fn with_step(mut self, step: impl Into<String>) -> Self {
        self.reasoning_steps.push(step.into());
        self
    }

    /// Mark that an observation was made
    pub fn with_observation(mut self) -> Self {
        self.has_observation = true;
        self
    }

    /// Mark that a plan exists
    pub fn with_plan(mut self) -> Self {
        self.has_plan = true;
        self
    }

    /// Set confidence level
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Set goal
    pub fn with_goal(mut self, goal: impl Into<String>) -> Self {
        self.goal = Some(goal.into());
        self
    }
}

// ============================================================================
// LLM Call Representation (INT-003)
// ============================================================================

/// Represents an LLM call being intercepted
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmCall {
    /// Model identifier (e.g., "gpt-4", "claude-3")
    pub model: String,
    /// Prompt or messages being sent
    pub messages: Vec<LlmMessage>,
    /// Temperature setting
    pub temperature: Option<f64>,
    /// Maximum tokens
    pub max_tokens: Option<u32>,
    /// Request ID
    pub request_id: String,
    /// Timestamp
    pub timestamp: u64,
}

/// A single message in an LLM conversation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmMessage {
    /// Role of the message sender
    pub role: String,
    /// Content of the message
    pub content: String,
}

impl LlmCall {
    /// Create a new LLM call
    pub fn new(model: impl Into<String>) -> Self {
        Self {
            model: model.into(),
            messages: Vec::new(),
            temperature: None,
            max_tokens: None,
            request_id: uuid::Uuid::new_v4().to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Add a message to the call
    pub fn with_message(mut self, role: impl Into<String>, content: impl Into<String>) -> Self {
        self.messages.push(LlmMessage {
            role: role.into(),
            content: content.into(),
        });
        self
    }

    /// Set temperature
    pub fn with_temperature(mut self, temp: f64) -> Self {
        self.temperature = Some(temp);
        self
    }

    /// Set max tokens
    pub fn with_max_tokens(mut self, max: u32) -> Self {
        self.max_tokens = Some(max);
        self
    }

    /// Get total token estimate (rough: 4 chars per token)
    pub fn estimated_tokens(&self) -> usize {
        self.messages
            .iter()
            .map(|m| m.content.len() / 4 + m.role.len() / 4)
            .sum()
    }

    /// Convert to action context
    pub fn to_context(&self, agent_id: &str) -> ActionContext {
        ActionContext::new(ActionType::LlmCall, &self.model, agent_id)
            .with_metadata("request_id", &self.request_id)
            .with_metadata("model", &self.model)
            .with_metadata("message_count", &self.messages.len().to_string())
    }
}

// ============================================================================
// Tool Execution Result (INT-003)
// ============================================================================

/// Records the result of a tool execution for audit tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecutionRecord {
    /// The original tool call
    pub tool_call: ToolCall,
    /// Agent that made the call
    pub agent_id: String,
    /// Whether execution succeeded
    pub success: bool,
    /// Output from the tool
    pub output: Option<serde_json::Value>,
    /// Error message if failed
    pub error: Option<String>,
    /// Execution duration in milliseconds
    pub duration_ms: u64,
    /// Timestamp of completion
    pub completed_at: u64,
    /// Associated audit entry ID
    pub audit_entry_id: Option<String>,
}

// ============================================================================
// Callback Handler Trait (INT-003)
// ============================================================================

/// LangChain-style callback handler for lifecycle events.
///
/// Implement this trait to receive notifications about tool calls,
/// chain executions, and LLM calls as they happen.
#[async_trait::async_trait]
pub trait LangChainCallbackHandler: Send + Sync {
    /// Called when a tool execution starts
    async fn on_tool_start(&self, tool_call: &ToolCall, agent_id: &str) {
        let _ = (tool_call, agent_id);
    }

    /// Called when a tool execution completes
    async fn on_tool_end(&self, record: &ToolExecutionRecord) {
        let _ = record;
    }

    /// Called when a tool execution fails
    async fn on_tool_error(&self, tool_call: &ToolCall, error: &str) {
        let _ = (tool_call, error);
    }

    /// Called when a chain execution starts
    async fn on_chain_start(&self, chain: &ChainExecution, agent_id: &str) {
        let _ = (chain, agent_id);
    }

    /// Called when a chain execution completes
    async fn on_chain_end(&self, chain: &ChainExecution, output: &serde_json::Value) {
        let _ = (chain, output);
    }

    /// Called when an LLM call starts
    async fn on_llm_start(&self, llm_call: &LlmCall, agent_id: &str) {
        let _ = (llm_call, agent_id);
    }

    /// Called when an LLM call completes
    async fn on_llm_end(&self, llm_call: &LlmCall, response: &str) {
        let _ = (llm_call, response);
    }

    /// Called when an action is blocked by policy
    async fn on_action_blocked(&self, context: &ActionContext, reason: &str) {
        let _ = (context, reason);
    }
}

/// Audit-logging callback handler that records all events (INT-003)
pub struct AuditCallbackHandler {
    /// Records of all tool executions
    records: Arc<tokio::sync::RwLock<Vec<ToolExecutionRecord>>>,
}

impl AuditCallbackHandler {
    /// Create a new audit callback handler
    pub fn new() -> Self {
        Self {
            records: Arc::new(tokio::sync::RwLock::new(Vec::new())),
        }
    }

    /// Get all recorded tool execution records
    pub async fn get_records(&self) -> Vec<ToolExecutionRecord> {
        self.records.read().await.clone()
    }

    /// Get the number of recorded executions
    pub async fn record_count(&self) -> usize {
        self.records.read().await.len()
    }
}

impl Default for AuditCallbackHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl LangChainCallbackHandler for AuditCallbackHandler {
    async fn on_tool_start(&self, tool_call: &ToolCall, agent_id: &str) {
        tracing::info!(
            tool = %tool_call.tool_name,
            action = %tool_call.action,
            agent = %agent_id,
            "Tool execution started"
        );
    }

    async fn on_tool_end(&self, record: &ToolExecutionRecord) {
        tracing::info!(
            tool = %record.tool_call.tool_name,
            success = %record.success,
            duration_ms = %record.duration_ms,
            "Tool execution completed"
        );
        let mut records = self.records.write().await;
        records.push(record.clone());
    }

    async fn on_tool_error(&self, tool_call: &ToolCall, error: &str) {
        tracing::error!(
            tool = %tool_call.tool_name,
            error = %error,
            "Tool execution failed"
        );
    }

    async fn on_action_blocked(&self, context: &ActionContext, reason: &str) {
        tracing::warn!(
            action = %context.name,
            agent = %context.agent_id,
            reason = %reason,
            "Action blocked by policy"
        );
    }
}

// ============================================================================
// Extended LangChain Adapter Methods (INT-003)
// ============================================================================

impl LangChainAdapter {
    /// Add a callback handler
    pub fn with_callback(mut self, callback: Arc<dyn LangChainCallbackHandler>) -> Self {
        self.callbacks.push(callback);
        self
    }

    /// Intercept an LLM call with policy checking and audit logging (INT-003)
    ///
    /// Evaluates the LLM call against rate limits, blocked actions,
    /// and custom hooks before allowing it to proceed.
    pub async fn intercept_llm(
        &self,
        llm_call: &LlmCall,
        agent_id: &str,
    ) -> AdapterResult<InterceptionResult> {
        let start = Instant::now();

        if !self.config.intercept_llm {
            return Ok(InterceptionResult {
                context: llm_call.to_context(agent_id),
                decision: HookDecision::Allow,
                hook_name: "disabled".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Notify callbacks
        for cb in &self.callbacks {
            cb.on_llm_start(llm_call, agent_id).await;
        }

        // Check rate limit
        self.check_rate_limit(agent_id).await?;

        // Check if LLM model is blocked
        let model_action = format!("llm:{}", llm_call.model);
        if self.config.base.blocked_actions.contains(&model_action) {
            let context = llm_call.to_context(agent_id);
            let reason = format!("LLM model '{}' is blocked by policy", llm_call.model);

            for cb in &self.callbacks {
                cb.on_action_blocked(&context, &reason).await;
            }

            return Ok(InterceptionResult {
                context,
                decision: HookDecision::Block { reason },
                hook_name: "blocked_models".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Check token limits
        let estimated_tokens = llm_call.estimated_tokens();
        if estimated_tokens > 100_000 {
            return Ok(InterceptionResult {
                context: llm_call.to_context(agent_id),
                decision: HookDecision::Block {
                    reason: format!(
                        "Estimated token count {} exceeds safety limit",
                        estimated_tokens
                    ),
                },
                hook_name: "token_limit".to_string(),
                prm_score: None,
                evaluation_time_us: start.elapsed().as_micros() as u64,
                audit_entry_id: None,
            });
        }

        // Run custom hooks
        let context = llm_call.to_context(agent_id);
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

        Ok(InterceptionResult {
            context,
            decision: HookDecision::Allow,
            hook_name: "default".to_string(),
            prm_score: None,
            evaluation_time_us: start.elapsed().as_micros() as u64,
            audit_entry_id: None,
        })
    }

    /// Record the result of a tool execution for audit tracking (INT-003)
    pub async fn record_tool_result(
        &self,
        tool_call: &ToolCall,
        agent_id: &str,
        success: bool,
        output: Option<serde_json::Value>,
        error: Option<String>,
        duration_ms: u64,
    ) -> ToolExecutionRecord {
        let record = ToolExecutionRecord {
            tool_call: tool_call.clone(),
            agent_id: agent_id.to_string(),
            success,
            output,
            error: error.clone(),
            duration_ms,
            completed_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            audit_entry_id: None,
        };

        // Notify callbacks
        if success {
            for cb in &self.callbacks {
                cb.on_tool_end(&record).await;
            }
        } else if let Some(ref err) = error {
            for cb in &self.callbacks {
                cb.on_tool_error(tool_call, err).await;
            }
        }

        record
    }

    /// Execute a full tool call lifecycle: intercept, execute callback, record (INT-003)
    ///
    /// This method provides a complete tool call flow:
    /// 1. Intercept and check policies
    /// 2. Notify callbacks of tool start
    /// 3. Execute the provided function
    /// 4. Record the result
    /// 5. Notify callbacks of tool end
    pub async fn execute_tool<F, Fut>(
        &self,
        tool_call: &ToolCall,
        agent_id: &str,
        executor: F,
    ) -> AdapterResult<ToolExecutionRecord>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, String>>,
    {
        // Step 1: Intercept
        let interception = self.intercept_tool(tool_call, agent_id).await?;

        if !matches!(interception.decision, HookDecision::Allow) {
            let reason = match &interception.decision {
                HookDecision::Block { reason } => reason.clone(),
                _ => "Action not allowed".to_string(),
            };
            return Ok(ToolExecutionRecord {
                tool_call: tool_call.clone(),
                agent_id: agent_id.to_string(),
                success: false,
                output: None,
                error: Some(reason),
                duration_ms: 0,
                completed_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                audit_entry_id: None,
            });
        }

        // Step 2: Notify start
        for cb in &self.callbacks {
            cb.on_tool_start(tool_call, agent_id).await;
        }

        // Step 3: Execute
        let start = Instant::now();
        let result = executor().await;
        let duration_ms = start.elapsed().as_millis() as u64;

        // Step 4: Record & notify
        match result {
            Ok(output) => {
                self.record_tool_result(
                    tool_call,
                    agent_id,
                    true,
                    Some(output),
                    None,
                    duration_ms,
                )
                .await;
                Ok(ToolExecutionRecord {
                    tool_call: tool_call.clone(),
                    agent_id: agent_id.to_string(),
                    success: true,
                    output: None,
                    error: None,
                    duration_ms,
                    completed_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    audit_entry_id: None,
                })
            }
            Err(err) => {
                self.record_tool_result(
                    tool_call,
                    agent_id,
                    false,
                    None,
                    Some(err.clone()),
                    duration_ms,
                )
                .await;
                Ok(ToolExecutionRecord {
                    tool_call: tool_call.clone(),
                    agent_id: agent_id.to_string(),
                    success: false,
                    output: None,
                    error: Some(err),
                    duration_ms,
                    completed_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                    audit_entry_id: None,
                })
            }
        }
    }

    /// Get callback handlers count
    pub fn callback_count(&self) -> usize {
        self.callbacks.len()
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
        let config = LangChainConfig::default().with_blocked_action("dangerous:delete");
        let adapter = LangChainAdapter::new(config);

        let call = ToolCall::new("dangerous", "delete");
        let result = adapter.intercept_tool(&call, "agent-1").await.unwrap();

        assert!(matches!(result.decision, HookDecision::Block { .. }));
    }

    #[tokio::test]
    async fn test_chain_execution() {
        let chain =
            ChainExecution::new("qa_chain", "RetrievalQA").with_input("question", "What is VAK?");

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

    #[tokio::test]
    async fn test_llm_call_creation() {
        let call = LlmCall::new("gpt-4")
            .with_message("system", "You are helpful")
            .with_message("user", "Hello")
            .with_temperature(0.7)
            .with_max_tokens(1000);

        assert_eq!(call.model, "gpt-4");
        assert_eq!(call.messages.len(), 2);
        assert_eq!(call.temperature, Some(0.7));
        assert_eq!(call.max_tokens, Some(1000));
    }

    #[tokio::test]
    async fn test_llm_interception_disabled() {
        let config = LangChainConfig::default(); // intercept_llm is false by default
        let adapter = LangChainAdapter::new(config);

        let call = LlmCall::new("gpt-4").with_message("user", "test");
        let result = adapter.intercept_llm(&call, "agent-1").await.unwrap();

        assert!(matches!(result.decision, HookDecision::Allow));
        assert_eq!(result.hook_name, "disabled");
    }

    #[tokio::test]
    async fn test_llm_interception_blocked_model() {
        let mut config = LangChainConfig::default();
        config.intercept_llm = true;
        config.base.blocked_actions.push("llm:dangerous-model".to_string());
        let adapter = LangChainAdapter::new(config);

        let call = LlmCall::new("dangerous-model").with_message("user", "test");
        let result = adapter.intercept_llm(&call, "agent-1").await.unwrap();

        assert!(matches!(result.decision, HookDecision::Block { .. }));
    }

    #[tokio::test]
    async fn test_callback_handler() {
        let handler = Arc::new(AuditCallbackHandler::new());

        let config = LangChainConfig::default();
        let adapter = LangChainAdapter::new(config).with_callback(handler.clone());

        assert_eq!(adapter.callback_count(), 1);

        let call = ToolCall::new("test", "action");
        let _ = adapter
            .record_tool_result(&call, "agent-1", true, Some(serde_json::json!(42)), None, 100)
            .await;

        assert_eq!(handler.record_count().await, 1);
    }

    #[tokio::test]
    async fn test_execute_tool_lifecycle() {
        let config = LangChainConfig::default();
        let adapter = LangChainAdapter::new(config);

        let call = ToolCall::new("calculator", "add")
            .with_param("a", 1)
            .with_param("b", 2);

        let record = adapter
            .execute_tool(&call, "agent-1", || async { Ok(serde_json::json!(3)) })
            .await
            .unwrap();

        assert!(record.success);
    }

    #[tokio::test]
    async fn test_execute_tool_failure() {
        let config = LangChainConfig::default();
        let adapter = LangChainAdapter::new(config);

        let call = ToolCall::new("calculator", "divide");

        let record = adapter
            .execute_tool(&call, "agent-1", || async {
                Err("Division by zero".to_string())
            })
            .await
            .unwrap();

        assert!(!record.success);
        assert_eq!(record.error, Some("Division by zero".to_string()));
    }

    #[test]
    fn test_llm_token_estimation() {
        let call = LlmCall::new("gpt-4")
            .with_message("user", "Hello world, this is a test message");

        assert!(call.estimated_tokens() > 0);
    }
}
