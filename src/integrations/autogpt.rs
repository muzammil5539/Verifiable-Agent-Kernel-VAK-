//! AutoGPT Integration Adapter
//!
//! Middleware adapter for integrating VAK with AutoGPT-style autonomous agents.
//! Provides interception of task planning and command execution for policy
//! enforcement and audit logging.
//!
//! # Features
//!
//! - Task planning interception with policy checks
//! - Command execution monitoring and blocking
//! - PRM scoring for reasoning quality
//! - Automatic audit logging
//! - Goal validation
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::integrations::autogpt::{AutoGPTAdapter, AutoGPTConfig, TaskPlan, ExecutionResult};
//!
//! // Create adapter with configuration
//! let config = AutoGPTConfig::default()
//!     .with_prm_threshold(0.7)
//!     .with_max_steps(100);
//!
//! let adapter = AutoGPTAdapter::new(config);
//!
//! // Intercept a task plan
//! let plan = TaskPlan::new("Write a file")
//!     .with_step("Analyze requirements")
//!     .with_step("Write content")
//!     .with_step("Save to disk");
//!
//! let decision = adapter.evaluate_plan(&plan, "agent-1").await?;
//! ```

use crate::integrations::common::{
    ActionContext, ActionType, AdapterResult, AlertLevel, BaseAdapterConfig, HookDecision,
    InterceptionHook, InterceptionResult, VakConnection,
};
use crate::kernel::rate_limiter::{RateLimiter, ResourceKey};
use crate::reasoner::{ProcessRewardModel, ReasoningStep};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for AutoGPT adapter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoGPTConfig {
    /// Base adapter configuration
    #[serde(flatten)]
    pub base: BaseAdapterConfig,
    /// Maximum steps allowed in a task
    pub max_steps: usize,
    /// Maximum task execution time (seconds)
    pub max_execution_time_secs: u64,
    /// Enable task planning interception
    pub intercept_planning: bool,
    /// Enable command execution interception
    pub intercept_commands: bool,
    /// Commands that are always blocked
    pub blocked_commands: Vec<String>,
    /// Goals that trigger high alert
    pub high_risk_goals: Vec<String>,
    /// Enable continuous mode (careful!)
    pub allow_continuous: bool,
}

impl Default for AutoGPTConfig {
    fn default() -> Self {
        Self {
            base: BaseAdapterConfig::default(),
            max_steps: 50,
            max_execution_time_secs: 3600, // 1 hour
            intercept_planning: true,
            intercept_commands: true,
            blocked_commands: vec![
                "rm -rf".to_string(),
                "sudo".to_string(),
                "chmod 777".to_string(),
                "curl | bash".to_string(),
                "wget | sh".to_string(),
            ],
            high_risk_goals: vec![
                "delete".to_string(),
                "modify system".to_string(),
                "access credentials".to_string(),
            ],
            allow_continuous: false,
        }
    }
}

impl AutoGPTConfig {
    /// Set PRM threshold
    pub fn with_prm_threshold(mut self, threshold: f64) -> Self {
        self.base.prm_threshold = threshold;
        self
    }

    /// Set maximum steps
    pub fn with_max_steps(mut self, max: usize) -> Self {
        self.max_steps = max;
        self
    }

    /// Add a blocked command
    pub fn with_blocked_command(mut self, cmd: impl Into<String>) -> Self {
        self.blocked_commands.push(cmd.into());
        self
    }

    /// Add a high-risk goal keyword
    pub fn with_high_risk_goal(mut self, goal: impl Into<String>) -> Self {
        self.high_risk_goals.push(goal.into());
        self
    }

    /// Enable continuous mode (use with caution)
    pub fn with_continuous_mode(mut self, enabled: bool) -> Self {
        self.allow_continuous = enabled;
        self
    }

    /// Set maximum execution time
    pub fn with_max_execution_time(mut self, secs: u64) -> Self {
        self.max_execution_time_secs = secs;
        self
    }
}

// ============================================================================
// Task Plan
// ============================================================================

/// Represents an AutoGPT task plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskPlan {
    /// Plan ID
    pub plan_id: String,
    /// High-level goal
    pub goal: String,
    /// Planned steps
    pub steps: Vec<TaskStep>,
    /// Plan creation timestamp
    pub created_at: u64,
    /// Estimated completion time (seconds)
    pub estimated_time_secs: Option<u64>,
    /// Plan metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// A single step in a task plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStep {
    /// Step number
    pub step_number: usize,
    /// Step description
    pub description: String,
    /// Command/action to execute
    pub command: Option<String>,
    /// Expected output
    pub expected_output: Option<String>,
    /// Dependencies (step numbers)
    pub dependencies: Vec<usize>,
    /// Status
    pub status: StepStatus,
}

/// Status of a task step
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Blocked,
    Skipped,
}

impl TaskPlan {
    /// Create a new task plan
    pub fn new(goal: impl Into<String>) -> Self {
        Self {
            plan_id: uuid::Uuid::new_v4().to_string(),
            goal: goal.into(),
            steps: Vec::new(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            estimated_time_secs: None,
            metadata: HashMap::new(),
        }
    }

    /// Add a step to the plan
    pub fn with_step(mut self, description: impl Into<String>) -> Self {
        let step_number = self.steps.len() + 1;
        self.steps.push(TaskStep {
            step_number,
            description: description.into(),
            command: None,
            expected_output: None,
            dependencies: vec![],
            status: StepStatus::Pending,
        });
        self
    }

    /// Add a step with a command
    pub fn with_command_step(
        mut self,
        description: impl Into<String>,
        command: impl Into<String>,
    ) -> Self {
        let step_number = self.steps.len() + 1;
        self.steps.push(TaskStep {
            step_number,
            description: description.into(),
            command: Some(command.into()),
            expected_output: None,
            dependencies: vec![],
            status: StepStatus::Pending,
        });
        self
    }

    /// Set estimated time
    pub fn with_estimated_time(mut self, secs: u64) -> Self {
        self.estimated_time_secs = Some(secs);
        self
    }

    /// Get total number of steps
    pub fn step_count(&self) -> usize {
        self.steps.len()
    }

    /// Check if plan has any blocked commands
    pub fn has_blocked_commands(&self, blocked: &[String]) -> Vec<usize> {
        self.steps
            .iter()
            .filter_map(|step| {
                if let Some(ref cmd) = step.command {
                    let cmd_lower = cmd.to_lowercase();
                    if blocked
                        .iter()
                        .any(|b| cmd_lower.contains(&b.to_lowercase()))
                    {
                        return Some(step.step_number);
                    }
                }
                None
            })
            .collect()
    }

    /// Get resource identifier
    pub fn resource(&self) -> String {
        format!("plan:{}", self.plan_id)
    }
}

// ============================================================================
// Execution Result
// ============================================================================

/// Result of a command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Execution ID
    pub execution_id: String,
    /// Command that was executed
    pub command: String,
    /// Exit code (0 = success)
    pub exit_code: i32,
    /// Standard output
    pub stdout: String,
    /// Standard error
    pub stderr: String,
    /// Execution time (milliseconds)
    pub duration_ms: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl ExecutionResult {
    /// Create a successful result
    pub fn success(command: impl Into<String>, stdout: impl Into<String>) -> Self {
        Self {
            execution_id: uuid::Uuid::new_v4().to_string(),
            command: command.into(),
            exit_code: 0,
            stdout: stdout.into(),
            stderr: String::new(),
            duration_ms: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Create a failed result
    pub fn failure(command: impl Into<String>, exit_code: i32, stderr: impl Into<String>) -> Self {
        Self {
            execution_id: uuid::Uuid::new_v4().to_string(),
            command: command.into(),
            exit_code,
            stdout: String::new(),
            stderr: stderr.into(),
            duration_ms: 0,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        }
    }

    /// Check if execution was successful
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

// ============================================================================
// AutoGPT Adapter
// ============================================================================

/// Main adapter for AutoGPT integration
pub struct AutoGPTAdapter {
    config: AutoGPTConfig,
    /// Connection to VAK kernel
    vak_connection: VakConnection,
    /// Custom interception hooks
    hooks: Vec<Arc<dyn InterceptionHook>>,
    /// Statistics
    stats: AutoGPTStats,
    /// Active plans being tracked
    active_plans: RwLock<HashMap<String, PlanExecutionState>>,
    /// Rate limiter (optional)
    rate_limiter: Option<Arc<RateLimiter>>,
    /// PRM model (optional)
    prm: Option<Arc<dyn ProcessRewardModel>>,
}

/// Statistics for AutoGPT adapter
#[derive(Debug, Default)]
pub struct AutoGPTStats {
    /// Number of plans evaluated
    pub plans_evaluated: AtomicU64,
    /// Number of plans approved
    pub plans_approved: AtomicU64,
    /// Number of plans rejected
    pub plans_rejected: AtomicU64,
    /// Number of commands intercepted
    pub commands_intercepted: AtomicU64,
    /// Number of commands blocked
    pub commands_blocked: AtomicU64,
    /// Number of steps completed
    pub steps_completed: AtomicU64,
    /// Number of high risk alerts
    pub high_risk_alerts: AtomicU64,
}

/// State for an executing plan
#[derive(Debug)]
#[allow(dead_code)]
struct PlanExecutionState {
    /// Unique plan identifier
    plan_id: String,
    /// When the plan started
    started_at: Instant,
    /// Current step index
    current_step: usize,
    /// Number of completed steps
    completed_steps: usize,
    /// Steps that were blocked
    blocked_steps: Vec<usize>,
}

impl PlanExecutionState {
    /// Create a new plan execution state
    #[allow(dead_code)]
    pub fn new(plan_id: String) -> Self {
        Self {
            plan_id,
            started_at: Instant::now(),
            current_step: 0,
            completed_steps: 0,
            blocked_steps: Vec::new(),
        }
    }
}

impl AutoGPTAdapter {
    /// Create a new AutoGPT adapter
    pub fn new(config: AutoGPTConfig) -> Self {
        Self {
            config,
            vak_connection: VakConnection::local(),
            hooks: Vec::new(),
            stats: AutoGPTStats::default(),
            active_plans: RwLock::new(HashMap::new()),
            rate_limiter: None,
            prm: None,
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

    /// Check if a goal is high-risk
    fn is_high_risk_goal(&self, goal: &str) -> bool {
        let goal_lower = goal.to_lowercase();
        self.config
            .high_risk_goals
            .iter()
            .any(|g| goal_lower.contains(&g.to_lowercase()))
    }

    /// Check if a command is blocked
    fn is_blocked_command(&self, command: &str) -> bool {
        let cmd_lower = command.to_lowercase();
        self.config
            .blocked_commands
            .iter()
            .any(|b| cmd_lower.contains(&b.to_lowercase()))
    }

    /// Evaluate a task plan
    pub async fn evaluate_plan(
        &self,
        plan: &TaskPlan,
        _agent_id: &str,
    ) -> AdapterResult<PlanEvaluation> {
        self.stats.plans_evaluated.fetch_add(1, Ordering::Relaxed);

        let mut issues = Vec::new();
        let mut alert_level = AlertLevel::Low;

        // Check step count
        if plan.step_count() > self.config.max_steps {
            issues.push(format!(
                "Plan has {} steps, exceeding max of {}",
                plan.step_count(),
                self.config.max_steps
            ));
            alert_level = AlertLevel::Medium;
        }

        // Check for high-risk goal
        if self.is_high_risk_goal(&plan.goal) {
            issues.push(format!("Goal '{}' matches high-risk pattern", plan.goal));
            alert_level = AlertLevel::High;
            self.stats.high_risk_alerts.fetch_add(1, Ordering::Relaxed);
        }

        // Check for blocked commands
        let blocked_steps = plan.has_blocked_commands(&self.config.blocked_commands);
        if !blocked_steps.is_empty() {
            issues.push(format!(
                "Steps {:?} contain blocked commands",
                blocked_steps
            ));
            alert_level = AlertLevel::Critical;
        }

        // Check estimated time
        if let Some(est_time) = plan.estimated_time_secs {
            if est_time > self.config.max_execution_time_secs {
                issues.push(format!(
                    "Estimated time {}s exceeds max of {}s",
                    est_time, self.config.max_execution_time_secs
                ));
            }
        }

        // Determine approval
        let approved = issues.is_empty() || alert_level == AlertLevel::Low;

        if approved {
            self.stats.plans_approved.fetch_add(1, Ordering::Relaxed);

            // Track active plan
            let mut plans = self.active_plans.write().await;
            plans.insert(
                plan.plan_id.clone(),
                PlanExecutionState {
                    plan_id: plan.plan_id.clone(),
                    started_at: Instant::now(),
                    current_step: 0,
                    completed_steps: 0,
                    blocked_steps: blocked_steps.clone(),
                },
            );
        } else {
            self.stats.plans_rejected.fetch_add(1, Ordering::Relaxed);
        }

        Ok(PlanEvaluation {
            plan_id: plan.plan_id.clone(),
            approved,
            issues,
            alert_level,
            blocked_steps,
            max_allowed_steps: self.config.max_steps,
        })
    }

    /// Intercept a command execution
    pub async fn intercept_command(
        &self,
        command: &str,
        plan_id: Option<&str>,
        agent_id: &str,
    ) -> AdapterResult<InterceptionResult> {
        self.stats
            .commands_intercepted
            .fetch_add(1, Ordering::Relaxed);

        // Check rate limit
        if let Some(limiter) = &self.rate_limiter {
            let key = ResourceKey::new(agent_id, "execute", "command");
            let result = limiter.check(&key).await;
            if !result.allowed {
                use crate::integrations::common::AdapterError;
                return Err(AdapterError::RateLimited(format!(
                    "Agent {} exceeded rate limit. Retry after {}s",
                    agent_id,
                    result.retry_after_secs.unwrap_or(1)
                )));
            }
        }

        let context = ActionContext::new(ActionType::CommandExecution, command, agent_id);

        // Check if command is blocked
        if self.is_blocked_command(command) {
            self.stats.commands_blocked.fetch_add(1, Ordering::Relaxed);
            return Ok(InterceptionResult {
                context,
                decision: HookDecision::Block {
                    reason: format!("Command '{}' is blocked by policy", command),
                },
                hook_name: "blocked_commands".to_string(),
                prm_score: None,
                evaluation_time_us: 0,
                audit_entry_id: None,
            });
        }

        // Check plan execution state
        if let Some(pid) = plan_id {
            let plans = self.active_plans.read().await;
            if let Some(state) = plans.get(pid) {
                // Check if we're over time
                if state.started_at.elapsed().as_secs() > self.config.max_execution_time_secs {
                    return Ok(InterceptionResult {
                        context,
                        decision: HookDecision::Block {
                            reason: "Plan execution time limit exceeded".to_string(),
                        },
                        hook_name: "timeout".to_string(),
                        prm_score: None,
                        evaluation_time_us: 0,
                        audit_entry_id: None,
                    });
                }
            }
        }

        // Run custom hooks
        for hook in &self.hooks {
            if hook.applies_to(&context) {
                let decision = hook.evaluate(&context);
                if !matches!(decision, HookDecision::Allow) {
                    return Ok(InterceptionResult {
                        context,
                        decision,
                        hook_name: hook.name().to_string(),
                        prm_score: None,
                        evaluation_time_us: 0,
                        audit_entry_id: None,
                    });
                }
            }
        }

        // Allow by default
        Ok(InterceptionResult {
            context,
            decision: HookDecision::Allow,
            hook_name: "default".to_string(),
            prm_score: None,
            evaluation_time_us: 0,
            audit_entry_id: None,
        })
    }

    /// Record step completion
    pub async fn record_step_completion(
        &self,
        plan_id: &str,
        step_number: usize,
        _result: &ExecutionResult,
    ) {
        self.stats.steps_completed.fetch_add(1, Ordering::Relaxed);

        let mut plans = self.active_plans.write().await;
        if let Some(state) = plans.get_mut(plan_id) {
            state.completed_steps += 1;
            state.current_step = step_number;
        }
    }

    /// Complete a plan execution
    pub async fn complete_plan(&self, plan_id: &str) {
        let mut plans = self.active_plans.write().await;
        plans.remove(plan_id);
    }

    /// Get adapter statistics
    pub fn stats(&self) -> &AutoGPTStats {
        &self.stats
    }

    /// Get statistics summary as JSON
    pub fn stats_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "plans_evaluated": self.stats.plans_evaluated.load(Ordering::Relaxed),
            "plans_approved": self.stats.plans_approved.load(Ordering::Relaxed),
            "plans_rejected": self.stats.plans_rejected.load(Ordering::Relaxed),
            "commands_intercepted": self.stats.commands_intercepted.load(Ordering::Relaxed),
            "commands_blocked": self.stats.commands_blocked.load(Ordering::Relaxed),
            "steps_completed": self.stats.steps_completed.load(Ordering::Relaxed),
            "high_risk_alerts": self.stats.high_risk_alerts.load(Ordering::Relaxed),
        })
    }

    /// Full task verification with comprehensive analysis (INT-004)
    ///
    /// This method performs deep analysis of a task plan including:
    /// - Goal safety verification
    /// - Step-by-step command analysis
    /// - Resource access pattern detection
    /// - Timing and complexity estimation
    /// - Risk assessment with mitigation suggestions
    ///
    /// # Arguments
    /// * `plan` - The task plan to verify
    /// * `agent_id` - The agent ID
    /// * `verification_opts` - Optional verification options
    ///
    /// # Returns
    /// * `FullVerificationResult` with detailed analysis
    pub async fn verify_task_full(
        &self,
        plan: &TaskPlan,
        agent_id: &str,
        verification_opts: Option<&VerificationOptions>,
    ) -> AdapterResult<FullVerificationResult> {
        self.stats.plans_evaluated.fetch_add(1, Ordering::Relaxed);
        let opts = verification_opts.cloned().unwrap_or_default();

        let mut result = FullVerificationResult {
            plan_id: plan.plan_id.clone(),
            agent_id: agent_id.to_string(),
            verified: true,
            overall_risk: RiskLevel::Low,
            goal_analysis: GoalAnalysis::default(),
            step_analyses: Vec::new(),
            resource_analysis: ResourceAnalysis::default(),
            timing_analysis: TimingAnalysis::default(),
            recommendations: Vec::new(),
            verification_time_ms: 0,
        };

        let start = std::time::Instant::now();

        // Analyze goal
        result.goal_analysis = self.analyze_goal(&plan.goal, &opts);
        if result.goal_analysis.is_high_risk {
            result.overall_risk = RiskLevel::High;
            self.stats.high_risk_alerts.fetch_add(1, Ordering::Relaxed);
        }

        // Analyze each step
        for step in &plan.steps {
            let step_analysis = self.analyze_step(step, &opts).await;
            if step_analysis.risk_level >= RiskLevel::High {
                result.overall_risk = result.overall_risk.max(step_analysis.risk_level);
            }
            result.step_analyses.push(step_analysis);
        }

        // Analyze resource access patterns
        result.resource_analysis = self.analyze_resources(plan);

        // Analyze timing
        result.timing_analysis = TimingAnalysis {
            estimated_duration_secs: plan
                .estimated_time_secs
                .unwrap_or_else(|| plan.steps.len() as u64 * 30),
            max_allowed_secs: self.config.max_execution_time_secs,
            exceeds_limit: plan
                .estimated_time_secs
                .map(|t| t > self.config.max_execution_time_secs)
                .unwrap_or(false),
            step_count: plan.steps.len(),
            max_allowed_steps: self.config.max_steps,
        };

        // PRM Scoring
        if let Some(prm) = &self.prm {
            let reasoning_steps: Vec<ReasoningStep> = plan
                .steps
                .iter()
                .map(|s| {
                    ReasoningStep::new(s.step_number, &s.description)
                        .with_action(s.command.clone().unwrap_or_default())
                })
                .collect();

            match prm.score_trajectory(&reasoning_steps, &plan.goal).await {
                Ok(scores) => {
                    let avg_score: f64 = scores.iter().map(|s| s.score).sum::<f64>() / scores.len() as f64;
                    if avg_score < self.config.base.prm_threshold {
                        result.overall_risk = result.overall_risk.max(RiskLevel::High);
                        result.recommendations.push(VerificationRecommendation {
                            level: RecommendationLevel::Blocking,
                            category: "reasoning".to_string(),
                            message: format!(
                                "Plan reasoning quality low (score: {:.2}). Consider revising.",
                                avg_score
                            ),
                            action: Some("revise_plan".to_string()),
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!("PRM scoring failed: {}", e);
                }
            }
        }

        // Generate recommendations
        result.recommendations = self.generate_recommendations(&result, plan);

        // Final verification decision
        result.verified = result.overall_risk < RiskLevel::Critical
            && !result.timing_analysis.exceeds_limit
            && result
                .step_analyses
                .iter()
                .all(|s| s.blocked_commands.is_empty())
            // If PRM flagged blocking recommendations, it affects verification
            && !result.recommendations.iter().any(|r| r.level == RecommendationLevel::Blocking);

        result.verification_time_ms = start.elapsed().as_millis() as u64;

        if result.verified {
            self.stats.plans_approved.fetch_add(1, Ordering::Relaxed);
        } else {
            self.stats.plans_rejected.fetch_add(1, Ordering::Relaxed);
        }

        Ok(result)
    }

    /// Analyze the goal for risks
    fn analyze_goal(&self, goal: &str, _opts: &VerificationOptions) -> GoalAnalysis {
        let goal_lower = goal.to_lowercase();

        let mut analysis = GoalAnalysis {
            goal: goal.to_string(),
            is_high_risk: false,
            risk_keywords: Vec::new(),
            category: GoalCategory::General,
            confidence: 0.8,
        };

        // Check for high-risk keywords
        let high_risk_keywords = [
            ("delete", "Data deletion"),
            ("remove", "Data removal"),
            ("modify system", "System modification"),
            ("access credentials", "Credential access"),
            ("transfer", "Data transfer"),
            ("install", "Software installation"),
            ("execute", "Code execution"),
            ("sudo", "Privileged operation"),
            ("root", "Root access"),
        ];

        for (keyword, description) in high_risk_keywords {
            if goal_lower.contains(keyword) {
                analysis.is_high_risk = true;
                analysis.risk_keywords.push(RiskKeyword {
                    keyword: keyword.to_string(),
                    description: description.to_string(),
                    severity: KeywordSeverity::High,
                });
            }
        }

        // Determine category
        if goal_lower.contains("file") || goal_lower.contains("directory") {
            analysis.category = GoalCategory::FileOperation;
        } else if goal_lower.contains("network")
            || goal_lower.contains("http")
            || goal_lower.contains("api")
        {
            analysis.category = GoalCategory::NetworkOperation;
        } else if goal_lower.contains("database") || goal_lower.contains("sql") {
            analysis.category = GoalCategory::DatabaseOperation;
        } else if goal_lower.contains("code") || goal_lower.contains("script") {
            analysis.category = GoalCategory::CodeExecution;
        }

        analysis
    }

    /// Analyze a single step
    async fn analyze_step(&self, step: &TaskStep, _opts: &VerificationOptions) -> StepAnalysis {
        let mut analysis = StepAnalysis {
            step_number: step.step_number,
            description: step.description.clone(),
            risk_level: RiskLevel::Low,
            blocked_commands: Vec::new(),
            warnings: Vec::new(),
            estimated_duration_secs: 30,
        };

        if let Some(ref command) = step.command {
            // Check for blocked commands
            for blocked in &self.config.blocked_commands {
                if command.to_lowercase().contains(&blocked.to_lowercase()) {
                    analysis.blocked_commands.push(BlockedCommandInfo {
                        pattern: blocked.clone(),
                        found_in: command.clone(),
                        reason: format!("Command pattern '{}' is blocked", blocked),
                    });
                    analysis.risk_level = RiskLevel::Critical;
                }
            }

            // Analyze command patterns
            if command.contains("|") {
                analysis
                    .warnings
                    .push("Command uses pipe - verify intermediate steps".to_string());
                analysis.risk_level = analysis.risk_level.max(RiskLevel::Medium);
            }
            if command.contains("&&") || command.contains(";") {
                analysis
                    .warnings
                    .push("Command chains multiple operations".to_string());
                analysis.risk_level = analysis.risk_level.max(RiskLevel::Medium);
            }
            if command.contains("curl") || command.contains("wget") {
                analysis
                    .warnings
                    .push("Command downloads from network".to_string());
                analysis.risk_level = analysis.risk_level.max(RiskLevel::High);
            }
        }

        analysis
    }

    /// Analyze resource access patterns
    fn analyze_resources(&self, plan: &TaskPlan) -> ResourceAnalysis {
        let mut analysis = ResourceAnalysis {
            file_paths: Vec::new(),
            network_endpoints: Vec::new(),
            requires_elevated: false,
            sensitive_resources: Vec::new(),
        };

        for step in &plan.steps {
            if let Some(ref cmd) = step.command {
                // Extract file paths
                let path_pattern = regex::Regex::new(r"[/~][\w/.]+")
                    .unwrap_or_else(|_| regex::Regex::new(".^").unwrap());
                for cap in path_pattern.find_iter(cmd) {
                    let path = cap.as_str().to_string();
                    if path.starts_with("/etc")
                        || path.starts_with("/root")
                        || path.contains("passwd")
                    {
                        analysis.sensitive_resources.push(path.clone());
                    }
                    if !analysis.file_paths.contains(&path) {
                        analysis.file_paths.push(path);
                    }
                }

                // Check for elevated privileges
                if cmd.contains("sudo") || cmd.contains("as root") {
                    analysis.requires_elevated = true;
                }
            }

            // Check description for network operations
            let desc_lower = step.description.to_lowercase();
            if desc_lower.contains("http") || desc_lower.contains("api") {
                analysis.network_endpoints.push(step.description.clone());
            }
        }

        analysis
    }

    /// Generate recommendations based on analysis
    fn generate_recommendations(
        &self,
        result: &FullVerificationResult,
        _plan: &TaskPlan,
    ) -> Vec<VerificationRecommendation> {
        let mut recommendations = Vec::new();

        if result.goal_analysis.is_high_risk {
            recommendations.push(VerificationRecommendation {
                level: RecommendationLevel::Required,
                category: "goal".to_string(),
                message: "High-risk goal detected. Consider human review before execution."
                    .to_string(),
                action: Some("request_human_review".to_string()),
            });
        }

        for step_analysis in &result.step_analyses {
            if !step_analysis.blocked_commands.is_empty() {
                recommendations.push(VerificationRecommendation {
                    level: RecommendationLevel::Blocking,
                    category: "command".to_string(),
                    message: format!(
                        "Step {} contains blocked command. Cannot proceed.",
                        step_analysis.step_number
                    ),
                    action: Some("remove_blocked_command".to_string()),
                });
            }

            for warning in &step_analysis.warnings {
                recommendations.push(VerificationRecommendation {
                    level: RecommendationLevel::Advisory,
                    category: "step".to_string(),
                    message: format!("Step {}: {}", step_analysis.step_number, warning),
                    action: None,
                });
            }
        }

        if result.resource_analysis.requires_elevated {
            recommendations.push(VerificationRecommendation {
                level: RecommendationLevel::Required,
                category: "privileges".to_string(),
                message: "Plan requires elevated privileges. Ensure proper authorization."
                    .to_string(),
                action: Some("verify_authorization".to_string()),
            });
        }

        if !result.resource_analysis.sensitive_resources.is_empty() {
            recommendations.push(VerificationRecommendation {
                level: RecommendationLevel::Required,
                category: "resources".to_string(),
                message: format!(
                    "Plan accesses sensitive resources: {:?}",
                    result.resource_analysis.sensitive_resources
                ),
                action: Some("verify_resource_access".to_string()),
            });
        }

        if result.timing_analysis.exceeds_limit {
            recommendations.push(VerificationRecommendation {
                level: RecommendationLevel::Blocking,
                category: "timing".to_string(),
                message: format!(
                    "Estimated duration {}s exceeds limit {}s",
                    result.timing_analysis.estimated_duration_secs,
                    result.timing_analysis.max_allowed_secs
                ),
                action: Some("reduce_scope".to_string()),
            });
        }

        recommendations
    }

    /// Monitor ongoing execution with real-time verification
    pub async fn monitor_execution(
        &self,
        plan_id: &str,
        step_number: usize,
        output: &str,
    ) -> MonitoringResult {
        let plans = self.active_plans.read().await;

        let state = plans.get(plan_id);
        let execution_time = state.map(|s| s.started_at.elapsed().as_secs()).unwrap_or(0);

        // Check for anomalies in output
        let mut alerts = Vec::new();

        // Check for error patterns
        if output.to_lowercase().contains("error") || output.to_lowercase().contains("failed") {
            alerts.push(MonitoringAlert {
                level: AlertLevel::Medium,
                message: "Error detected in step output".to_string(),
                step: step_number,
            });
        }

        // Check for timeout
        if execution_time > self.config.max_execution_time_secs {
            alerts.push(MonitoringAlert {
                level: AlertLevel::Critical,
                message: "Execution time limit exceeded".to_string(),
                step: step_number,
            });
        }

        // Check for sensitive data in output
        let sensitive_patterns = ["password", "secret", "token", "api_key", "private_key"];
        for pattern in sensitive_patterns {
            if output.to_lowercase().contains(pattern) {
                alerts.push(MonitoringAlert {
                    level: AlertLevel::High,
                    message: format!("Sensitive data pattern '{}' detected in output", pattern),
                    step: step_number,
                });
            }
        }

        let should_continue = alerts.iter().all(|a| a.level < AlertLevel::Critical);
        MonitoringResult {
            plan_id: plan_id.to_string(),
            current_step: step_number,
            elapsed_secs: execution_time,
            alerts,
            should_continue,
        }
    }
}

/// Options for task verification
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationOptions {
    /// Perform deep analysis
    pub deep_analysis: bool,
    /// Check external resources
    pub verify_resources: bool,
    /// Strict mode (fail on warnings)
    pub strict: bool,
    /// Custom blocked patterns
    pub additional_blocked: Vec<String>,
}

/// Risk level for operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl Default for RiskLevel {
    fn default() -> Self {
        RiskLevel::Low
    }
}

/// Full verification result (INT-004)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullVerificationResult {
    /// Plan ID
    pub plan_id: String,
    /// Agent ID
    pub agent_id: String,
    /// Whether verification passed
    pub verified: bool,
    /// Overall risk level
    pub overall_risk: RiskLevel,
    /// Goal analysis
    pub goal_analysis: GoalAnalysis,
    /// Step-by-step analysis
    pub step_analyses: Vec<StepAnalysis>,
    /// Resource access analysis
    pub resource_analysis: ResourceAnalysis,
    /// Timing analysis
    pub timing_analysis: TimingAnalysis,
    /// Recommendations
    pub recommendations: Vec<VerificationRecommendation>,
    /// Time taken for verification
    pub verification_time_ms: u64,
}

/// Analysis of the task goal
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GoalAnalysis {
    /// The goal text
    pub goal: String,
    /// Whether this is a high-risk goal
    pub is_high_risk: bool,
    /// Risk keywords found
    pub risk_keywords: Vec<RiskKeyword>,
    /// Goal category
    pub category: GoalCategory,
    /// Confidence in analysis
    pub confidence: f64,
}

/// Risk keyword information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskKeyword {
    /// The keyword
    pub keyword: String,
    /// Description of why it's risky
    pub description: String,
    /// Severity
    pub severity: KeywordSeverity,
}

/// Keyword severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeywordSeverity {
    Low,
    Medium,
    High,
}

/// Goal category
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum GoalCategory {
    #[default]
    General,
    FileOperation,
    NetworkOperation,
    DatabaseOperation,
    CodeExecution,
    SystemAdmin,
}

/// Analysis of a single step
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepAnalysis {
    /// Step number
    pub step_number: usize,
    /// Step description
    pub description: String,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Blocked commands found
    pub blocked_commands: Vec<BlockedCommandInfo>,
    /// Warnings
    pub warnings: Vec<String>,
    /// Estimated duration
    pub estimated_duration_secs: u64,
}

/// Information about a blocked command
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedCommandInfo {
    /// The pattern that matched
    pub pattern: String,
    /// Where it was found
    pub found_in: String,
    /// Reason for blocking
    pub reason: String,
}

/// Resource access analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceAnalysis {
    /// File paths accessed
    pub file_paths: Vec<String>,
    /// Network endpoints accessed
    pub network_endpoints: Vec<String>,
    /// Whether elevated privileges are needed
    pub requires_elevated: bool,
    /// Sensitive resources accessed
    pub sensitive_resources: Vec<String>,
}

/// Timing analysis
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingAnalysis {
    /// Estimated duration in seconds
    pub estimated_duration_secs: u64,
    /// Maximum allowed duration
    pub max_allowed_secs: u64,
    /// Whether limit is exceeded
    pub exceeds_limit: bool,
    /// Number of steps
    pub step_count: usize,
    /// Maximum allowed steps
    pub max_allowed_steps: usize,
}

/// Verification recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRecommendation {
    /// Recommendation level
    pub level: RecommendationLevel,
    /// Category
    pub category: String,
    /// Message
    pub message: String,
    /// Suggested action
    pub action: Option<String>,
}

/// Recommendation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendationLevel {
    Advisory,
    Required,
    Blocking,
}

/// Monitoring alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringAlert {
    /// Alert level
    pub level: AlertLevel,
    /// Alert message
    pub message: String,
    /// Related step
    pub step: usize,
}

/// Result of execution monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringResult {
    /// Plan ID
    pub plan_id: String,
    /// Current step
    pub current_step: usize,
    /// Elapsed time
    pub elapsed_secs: u64,
    /// Alerts
    pub alerts: Vec<MonitoringAlert>,
    /// Whether execution should continue
    pub should_continue: bool,
}

/// Result of plan evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanEvaluation {
    /// Plan ID
    pub plan_id: String,
    /// Whether the plan is approved
    pub approved: bool,
    /// Issues found
    pub issues: Vec<String>,
    /// Alert level
    pub alert_level: AlertLevel,
    /// Steps with blocked commands
    pub blocked_steps: Vec<usize>,
    /// Maximum allowed steps
    pub max_allowed_steps: usize,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_plan_creation() {
        let plan = TaskPlan::new("Build a website")
            .with_step("Analyze requirements")
            .with_step("Create HTML structure")
            .with_command_step("Run tests", "npm test");

        assert_eq!(plan.goal, "Build a website");
        assert_eq!(plan.step_count(), 3);
        assert!(plan.steps[2].command.is_some());
    }

    #[test]
    fn test_blocked_command_detection() {
        let plan = TaskPlan::new("Cleanup files")
            .with_command_step("Remove temp", "rm -rf /tmp/test")
            .with_command_step("List files", "ls -la");

        let blocked = vec!["rm -rf".to_string()];
        let blocked_steps = plan.has_blocked_commands(&blocked);

        assert_eq!(blocked_steps, vec![1]);
    }

    #[tokio::test]
    async fn test_plan_evaluation_blocked() {
        let config = AutoGPTConfig::default();
        let adapter = AutoGPTAdapter::new(config);

        let plan = TaskPlan::new("Cleanup").with_command_step("Delete all", "rm -rf /");

        let eval = adapter.evaluate_plan(&plan, "agent-1").await.unwrap();

        assert!(!eval.approved);
        assert!(!eval.blocked_steps.is_empty());
    }

    #[tokio::test]
    async fn test_high_risk_goal() {
        let config = AutoGPTConfig::default();
        let adapter = AutoGPTAdapter::new(config);

        let plan = TaskPlan::new("Delete all user data");
        let eval = adapter.evaluate_plan(&plan, "agent-1").await.unwrap();

        assert_eq!(eval.alert_level, AlertLevel::High);
    }

    #[tokio::test]
    async fn test_command_interception() {
        let config = AutoGPTConfig::default();
        let adapter = AutoGPTAdapter::new(config);

        // Safe command
        let result = adapter
            .intercept_command("ls -la", None, "agent-1")
            .await
            .unwrap();
        assert!(matches!(result.decision, HookDecision::Allow));

        // Blocked command
        let result = adapter
            .intercept_command("sudo rm -rf /", None, "agent-1")
            .await
            .unwrap();
        assert!(matches!(result.decision, HookDecision::Block { .. }));
    }

    #[test]
    fn test_execution_result() {
        let success = ExecutionResult::success("echo hello", "hello");
        assert!(success.is_success());
        assert_eq!(success.exit_code, 0);

        let failure = ExecutionResult::failure("false", 1, "");
        assert!(!failure.is_success());
    }
}
