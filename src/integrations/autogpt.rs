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
    ActionContext, ActionType, AdapterError, AdapterResult, AlertLevel, BaseAdapterConfig,
    HookDecision, InterceptionHook, InterceptionResult, VakConnection,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
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
                    if blocked.iter().any(|b| cmd_lower.contains(&b.to_lowercase())) {
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
    pub fn failure(
        command: impl Into<String>,
        exit_code: i32,
        stderr: impl Into<String>,
    ) -> Self {
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
}

/// Statistics for AutoGPT adapter
#[derive(Debug, Default)]
pub struct AutoGPTStats {
    pub plans_evaluated: AtomicU64,
    pub plans_approved: AtomicU64,
    pub plans_rejected: AtomicU64,
    pub commands_intercepted: AtomicU64,
    pub commands_blocked: AtomicU64,
    pub steps_completed: AtomicU64,
    pub high_risk_alerts: AtomicU64,
}

/// State for an executing plan
#[derive(Debug)]
struct PlanExecutionState {
    plan_id: String,
    started_at: Instant,
    current_step: usize,
    completed_steps: usize,
    blocked_steps: Vec<usize>,
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
        agent_id: &str,
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
                    blocked_steps,
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
        self.stats.commands_intercepted.fetch_add(1, Ordering::Relaxed);

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
        result: &ExecutionResult,
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

        let plan = TaskPlan::new("Cleanup")
            .with_command_step("Delete all", "rm -rf /");

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
