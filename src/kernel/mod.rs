//! # VAK Kernel Module
//!
//! This module contains the core kernel implementation for the Verifiable Agent Kernel.
//! It provides the central execution engine, policy enforcement, and audit capabilities.
//!
//! ## Submodules
//!
//! - [`types`]: Core type definitions (AgentId, SessionId, PolicyDecision, etc.)
//! - [`config`]: Kernel configuration structures and validation
//! - [`traits`]: Async traits for policy evaluation, audit, state, and tool execution
//! - [`async_pipeline`]: Async request processing pipeline for multi-agent throughput (Issue #44)
//! - [`custom_handlers`]: Custom tool handler registry for runtime extensibility
//! - [`ports`]: Traits the mediation pipeline calls, one per stage
//! - [`identity`]: Agent records and the agent registry (Admit stage)
//! - [`budget`]: Per-agent budgets (Budget stage)
//! - [`pdp`]: Built-in policy decision points (config allowlist, CedarEnforcer)
//! - [`audit_log`]: The audit log port, with memory and file adapters
//!
//! ## Mediation
//!
//! [`Kernel::execute`] is the single mediation point. Every request passes,
//! in order: **admit** (the agent's record, status, session and own tool
//! scope, via [`ports::AgentRegistry`]), **budget** ([`ports::Budget`]),
//! **decide** ([`ports::PolicyDecisionPoint`]), **record** the decision
//! ([`ports::AuditLog`]), **execute**, **record the outcome**, and
//! **respond** with an [`types::AuditReceipt`]. A request stopped at any
//! stage is still recorded. If the decision can't be recorded, the tool
//! doesn't run.
//!
//! Tools resolve in order: built-ins, handlers registered with
//! [`Kernel::register_tool`] or [`KernelBuilder::with_tool`], WASM skills.
//! Anything else is [`KernelError::ToolNotFound`]; the kernel never reports
//! success for a tool that did not run.
//!
//! The audit log is an RFC 9162 Merkle tree ([`crate::audit::transparency`]),
//! so any decision can be proven to a third party with
//! [`Kernel::prove_audit_inclusion`] against a [`Kernel::audit_tree_head`].
//! See `docs/architecture-v2.md` and `docs/adr/0003`.
//!
//! ## Architecture Overview
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                        VAK Kernel                           │
//! ├─────────────────────────────────────────────────────────────┤
//! │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │   Policy    │  │    Audit     │  │     Session      │   │
//! │  │   Engine    │  │   Logger     │  │    Manager       │   │
//! │  └─────────────┘  └──────────────┘  └──────────────────┘   │
//! │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
//! │  │    Tool     │  │    State     │  │    Sandbox       │   │
//! │  │  Registry   │  │   Manager    │  │    Runtime       │   │
//! │  └─────────────┘  └──────────────┘  └──────────────────┘   │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod async_pipeline;
pub mod audit_log;
pub mod budget;
pub mod config;
pub mod constitution;
pub mod custom_handlers;
pub mod error;
pub mod identity;
pub mod neurosymbolic_pipeline;
pub mod pdp;
pub mod ports;
pub mod rate_limiter;
pub mod traits;
pub mod types;

// Re-export commonly used types at the module level
pub use self::config::{DefaultPolicyDecision, KernelConfig};
pub use self::custom_handlers::{
    CustomHandlerRegistry, FunctionHandler, HandlerError, HandlerMetadata, HandlerResult,
    ToolHandler,
};
pub use self::neurosymbolic_pipeline::{
    AgentPlan, ExecutionResult, NeuroSymbolicPipeline, PipelineConfig, PipelineError,
    ProposedAction,
};
pub use self::rate_limiter::{LimitResult, RateLimitConfig, RateLimiter, ResourceKey};

// Re-export Constitution Protocol types (FUT-002)
pub use self::constitution::{
    Constitution, ConstitutionConfig, ConstitutionError, ConstitutionResult, ConstitutionStats,
    ConstitutionalDecision, ConstitutionalEngine, ConstitutionalRule, ConstraintOp,
    EnforcementPoint, Principle, RuleViolation,
};

/// Tools handled directly by the kernel, without going through the WASM
/// sandbox. Any other tool name is dispatched to the skill registry.
pub const BUILTIN_TOOLS: &[&str] = &["echo", "calculator", "data_processor", "system_info"];

pub use self::audit_log::{AuditLogError, FileAuditLog, MemoryAuditLog};
pub use self::budget::{AgentRateBudget, BudgetDecision, Unlimited};
pub use self::identity::{AgentRecord, AgentStatus, InMemoryAgentRegistry, RegistryError};
pub use self::pdp::{ConfigPolicy, EnforcerPolicy};
pub use self::ports::{AgentRegistry, AuditLog, Budget, PolicyDecisionPoint, PolicyRequest};

use std::collections::hash_map::Entry;
use std::path::PathBuf;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use futures::FutureExt;
use rand::rngs::OsRng;
use sha2::{Digest as _, Sha256};
use tokio::sync::RwLock;
use tracing::{info, instrument, warn};

use self::types::{
    AgentId, AuditEntry, AuditOutcome, AuditReceipt, KernelError, PolicyDecision, SessionId,
    ToolRequest, ToolResponse,
};

// Import sandbox and skill registry for WASM execution (Issue #6)
use crate::sandbox::{SandboxConfig, SkillRegistry, WasmSandbox};

use crate::audit::transparency::{ConsistencyProof, Digest, InclusionProof, SignedTreeHead};

/// The main kernel instance that manages agent execution and policy enforcement.
///
/// The `Kernel` is the central component of VAK, responsible for:
/// - Processing tool requests from agents
/// - Enforcing security policies
/// - Maintaining audit logs
/// - Managing agent sessions
/// - Executing WASM skills in sandboxed environments (Issue #6)
///
/// # Thread Safety
///
/// `Kernel` is designed to be shared across threads. Clone the `Arc<Kernel>`
/// to share ownership between tasks.
///
/// # Example
///
/// ```rust,no_run
/// use vak::kernel::{Kernel, KernelConfig};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = KernelConfig::default();
/// let kernel = Kernel::new(config).await?;
///
/// // Kernel is now ready to process requests
/// # Ok(())
/// # }
/// ```
pub struct Kernel {
    /// Kernel configuration
    config: KernelConfig,

    /// Where decisions and outcomes are recorded. In memory unless
    /// `audit.log_path` is set or a log is injected.
    audit: Arc<dyn AuditLog>,

    /// Key that signs audit tree heads.
    audit_key: SigningKey,

    /// Looks up the requesting agent (Admit stage).
    agents: Arc<dyn AgentRegistry>,

    /// Charges each admitted request (Budget stage).
    budget: Arc<dyn Budget>,

    /// Each session is bound to the first agent that uses it.
    sessions: Arc<RwLock<std::collections::HashMap<SessionId, AgentId>>>,

    /// Skill registry for WASM tools (Issue #6)
    skill_registry: Arc<RwLock<SkillRegistry>>,

    /// Sandbox configuration for WASM execution
    sandbox_config: SandboxConfig,

    /// Decides every request. See [`pdp::policy_from_config`] for the default.
    policy: Arc<dyn PolicyDecisionPoint>,

    /// Host-side tool handlers registered by the embedder.
    tools: Arc<CustomHandlerRegistry>,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel")
            .field("name", &self.config.name)
            .field("policy", &self.policy.name())
            .field("agents", &self.agents.name())
            .field("budget", &self.budget.name())
            .field("audit", &self.audit.name())
            .field(
                "audit_key",
                &hex::encode(self.audit_key.verifying_key().to_bytes()),
            )
            .finish_non_exhaustive()
    }
}

/// Builds a [`Kernel`] with injected components.
///
/// Anything not supplied comes from the [`KernelConfig`], exactly as
/// [`Kernel::new`] would build it.
///
/// # Example
///
/// ```rust
/// use std::sync::Arc;
/// use vak::kernel::custom_handlers::{FunctionHandler, HandlerFuture};
/// use vak::kernel::types::{AgentId, SessionId, ToolRequest, ToolResponse};
/// use vak::kernel::{Kernel, KernelConfig};
///
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut config = KernelConfig::default();
/// // Registering a tool makes it exist; a policy still has to permit it.
/// config.security.allowed_tools.push("greet".to_string());
///
/// let greet = FunctionHandler::new("greet", |req: &ToolRequest, _agent: &AgentId| {
///     let id = req.request_id;
///     let name = req.parameters["name"].as_str().unwrap_or("world").to_string();
///     Box::pin(async move {
///         Ok(ToolResponse::success(id, serde_json::json!(format!("hello, {name}")), 0))
///     }) as HandlerFuture
/// });
///
/// let kernel = Kernel::builder(config).with_tool(greet).build().await?;
///
/// let request = ToolRequest::new("greet", serde_json::json!({"name": "VAK"}));
/// let response = kernel.execute(&AgentId::new(), &SessionId::new(), request).await?;
/// assert_eq!(response.result, Some(serde_json::json!("hello, VAK")));
///
/// // The decision is in the audit log and provable against a signed head.
/// let head = kernel.audit_tree_head().await;
/// assert!(head.verify(&kernel.audit_verifying_key()).is_ok());
/// let proof = kernel.prove_audit_inclusion(0, head.head.size).await?;
/// let entry = &kernel.get_audit_log().await[0];
/// vak::audit::transparency::verify_inclusion(
///     &Kernel::audit_leaf_hash(entry),
///     &proof,
///     &head.head.root,
/// )?;
/// # Ok(())
/// # }
/// ```
pub struct KernelBuilder {
    config: KernelConfig,
    policy: Option<Arc<dyn PolicyDecisionPoint>>,
    tools: Vec<Arc<dyn ToolHandler>>,
    audit_key: Option<SigningKey>,
    audit_log: Option<Arc<dyn AuditLog>>,
    agents: Option<Arc<dyn AgentRegistry>>,
    budget: Option<Arc<dyn Budget>>,
}

impl std::fmt::Debug for KernelBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelBuilder")
            .field("name", &self.config.name)
            .field(
                "policy",
                &self.policy.as_ref().map(|p| p.name().to_string()),
            )
            .field(
                "tools",
                &self.tools.iter().map(|t| t.name()).collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

impl KernelBuilder {
    /// Starts a builder from `config`.
    #[must_use]
    pub fn new(config: KernelConfig) -> Self {
        Self {
            config,
            policy: None,
            tools: Vec::new(),
            audit_key: None,
            audit_log: None,
            agents: None,
            budget: None,
        }
    }

    /// Uses `policy` to decide every request, instead of the decision point
    /// `config` describes.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<dyn PolicyDecisionPoint>) -> Self {
        self.policy = Some(policy);
        self
    }

    /// Registers a host-side tool handler. The tool still has to be permitted
    /// by policy before it runs.
    #[must_use]
    pub fn with_tool<H: ToolHandler + 'static>(mut self, handler: H) -> Self {
        self.tools.push(Arc::new(handler));
        self
    }

    /// Signs audit tree heads with `key`. Without this a fresh key is
    /// generated per kernel, which is enough to detect tampering within one
    /// process's lifetime but not across restarts.
    #[must_use]
    pub fn with_audit_signing_key(mut self, key: SigningKey) -> Self {
        self.audit_key = Some(key);
        self
    }

    /// Records into `log`, instead of the log `config.audit.log_path`
    /// describes.
    #[must_use]
    pub fn with_audit_log(mut self, log: Arc<dyn AuditLog>) -> Self {
        self.audit_log = Some(log);
        self
    }

    /// Looks agents up in `registry`, instead of an empty
    /// [`InMemoryAgentRegistry`].
    #[must_use]
    pub fn with_agent_registry(mut self, registry: Arc<dyn AgentRegistry>) -> Self {
        self.agents = Some(registry);
        self
    }

    /// Charges requests to `budget`, instead of the one `config.security`
    /// describes.
    #[must_use]
    pub fn with_budget(mut self, budget: Arc<dyn Budget>) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Builds the kernel.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid, a tool handler's
    /// name collides with a built-in tool or another handler, or
    /// `audit.log_path` is set and the log there can't be opened or doesn't
    /// verify. A configured log that can't be used never falls back to an
    /// in-memory one.
    pub async fn build(self) -> Result<Kernel, KernelError> {
        let config = self.config;
        config.validate()?;

        info!(
            kernel_name = %config.name,
            max_agents = config.max_concurrent_agents,
            "Initializing VAK kernel"
        );

        // Initialize skill registry (Issue #6).
        //
        // The path was previously hardcoded to "skills", which does not exist
        // in this repo (the skill crates live under .github/skills), so the
        // registry silently loaded nothing and every non-builtin tool failed.
        let skills_dir = Kernel::resolve_skills_dir();
        let mut skill_registry = SkillRegistry::new(skills_dir.clone());

        // Try to load skills from directory
        if skills_dir.exists() {
            match skill_registry.load_all_skills() {
                Ok(ids) => info!(count = ids.len(), "Loaded skills from registry"),
                Err(e) => warn!(error = %e, "Failed to load skills from registry"),
            }
        }

        // Configure sandbox based on kernel config
        let sandbox_config = SandboxConfig {
            memory_limit: (config.resources.max_memory_mb as usize) * 1024 * 1024, // Convert MB to bytes
            fuel_limit: 10_000_000, // Default fuel limit
            timeout: config.max_execution_time,
        };

        let policy = match self.policy {
            Some(policy) => policy,
            None => pdp::policy_from_config(&config).await,
        };
        info!(policy = policy.name(), "Policy decision point ready");

        let tools = Arc::new(CustomHandlerRegistry::with_timeout(
            (config.max_execution_time.as_millis() as u64).max(1),
        ));
        for handler in self.tools {
            Kernel::check_tool_name(handler.name())?;
            tools
                .register_new(handler)
                .await
                .map_err(|e| KernelError::InvalidConfiguration {
                    message: e.to_string(),
                })?;
        }

        let audit: Arc<dyn AuditLog> = match (self.audit_log, &config.audit.log_path) {
            (Some(log), _) => log,
            (None, Some(path)) => Arc::new(FileAuditLog::open(path).await.map_err(|e| {
                KernelError::InvalidConfiguration {
                    message: format!("audit.log_path: {e}"),
                }
            })?),
            (None, None) => Arc::new(MemoryAuditLog::new()),
        };

        let budget: Arc<dyn Budget> = match self.budget {
            Some(budget) => budget,
            None if config.security.enable_rate_limiting => Arc::new(AgentRateBudget::per_minute(
                config.security.max_requests_per_minute,
            )),
            None => Arc::new(Unlimited),
        };

        let agents = self
            .agents
            .unwrap_or_else(|| Arc::new(InMemoryAgentRegistry::new()));

        info!(
            audit = audit.name(),
            budget = budget.name(),
            agents = agents.name(),
            "Mediation ports ready"
        );

        Ok(Kernel {
            config,
            audit,
            audit_key: self
                .audit_key
                .unwrap_or_else(|| SigningKey::generate(&mut OsRng)),
            agents,
            budget,
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
            skill_registry: Arc::new(RwLock::new(skill_registry)),
            sandbox_config,
            policy,
            tools,
        })
    }
}

impl Kernel {
    /// Creates a new kernel instance with the given configuration.
    ///
    /// Equivalent to `Kernel::builder(config).build()`. Use
    /// [`Kernel::builder`] to inject a policy decision point, tool handlers,
    /// or an audit signing key.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel fails to initialize (e.g., invalid configuration).
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use vak::kernel::{Kernel, KernelConfig};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let kernel = Kernel::new(KernelConfig::default()).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[instrument(skip(config), fields(kernel_name = %config.name))]
    pub async fn new(config: KernelConfig) -> Result<Self, KernelError> {
        KernelBuilder::new(config).build().await
    }

    /// Starts building a kernel with injected components.
    #[must_use]
    pub fn builder(config: KernelConfig) -> KernelBuilder {
        KernelBuilder::new(config)
    }

    /// Returns a reference to the kernel configuration.
    #[must_use]
    pub fn config(&self) -> &KernelConfig {
        &self.config
    }

    /// The decision point this kernel consults.
    #[must_use]
    pub fn policy_decision_point(&self) -> &Arc<dyn PolicyDecisionPoint> {
        &self.policy
    }

    /// Registers a host-side tool handler.
    ///
    /// Registration makes a tool *exist*; it does not authorize anyone to
    /// call it. The policy decision point still decides every call.
    ///
    /// Handlers run in-process, like the built-in tools, so register only
    /// code you trust. Untrusted code belongs in a WASM skill, where it runs
    /// in the sandbox. A handler that panics fails its call with
    /// [`KernelError::ToolExecutionFailed`]; a handler that overruns
    /// `max_execution_time` fails with [`KernelError::Timeout`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidConfiguration`] if the name is empty,
    /// shadows a built-in tool, or is already registered.
    pub async fn register_tool<H: ToolHandler + 'static>(
        &self,
        handler: H,
    ) -> Result<(), KernelError> {
        Self::check_tool_name(handler.name())?;
        self.tools
            .register_new(Arc::new(handler))
            .await
            .map_err(|e| KernelError::InvalidConfiguration {
                message: e.to_string(),
            })
    }

    fn check_tool_name(name: &str) -> Result<(), KernelError> {
        if name.is_empty() {
            return Err(KernelError::InvalidConfiguration {
                message: "tool name must not be empty".to_string(),
            });
        }
        if BUILTIN_TOOLS.contains(&name) {
            return Err(KernelError::InvalidConfiguration {
                message: format!("tool '{name}' would shadow a built-in tool"),
            });
        }
        Ok(())
    }

    /// Resolves the directory to load WASM skill manifests from.
    ///
    /// `VAK_SKILLS_PATH` wins if set (containers mount skills elsewhere);
    /// otherwise the first location that exists is used.
    fn resolve_skills_dir() -> PathBuf {
        if let Ok(path) = std::env::var("VAK_SKILLS_PATH") {
            return PathBuf::from(path);
        }
        [".github/skills", "skills"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_dir())
            .unwrap_or_else(|| PathBuf::from("skills"))
    }

    /// The agent registry the Admit stage consults.
    #[must_use]
    pub fn agent_registry(&self) -> &Arc<dyn AgentRegistry> {
        &self.agents
    }

    /// The audit log decisions and outcomes are recorded in.
    #[must_use]
    pub fn audit_log(&self) -> &Arc<dyn AuditLog> {
        &self.audit
    }

    /// Registers an agent, or replaces its record.
    ///
    /// The record's attributes reach policy as `principal.*`, and its own
    /// tool scope narrows what policy allows. Registration does not grant
    /// anything by itself.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::InvalidConfiguration`] if the registry is
    /// read-only.
    pub async fn register_agent(&self, record: AgentRecord) -> Result<(), KernelError> {
        self.agents
            .register(record)
            .await
            .map_err(|e| KernelError::InvalidConfiguration {
                message: e.to_string(),
            })
    }

    /// Releases a session, so its ID is no longer bound to an agent.
    /// Returns whether it was bound.
    pub async fn end_session(&self, session_id: &SessionId) -> bool {
        self.sessions.write().await.remove(session_id).is_some()
    }

    /// The record the kernel uses for `agent_id`: the registered one, or an
    /// anonymous one if the agent isn't registered.
    async fn principal(&self, agent_id: &AgentId) -> Option<AgentRecord> {
        match self.agents.lookup(agent_id).await {
            Some(record) => Some(record),
            None if self.config.security.require_registered_agents => None,
            None => Some(AgentRecord::anonymous(*agent_id)),
        }
    }

    /// Evaluates a policy decision for a given tool request.
    ///
    /// Delegates to the kernel's [`PolicyDecisionPoint`], with the agent's
    /// record as the principal. With [`Kernel::new`] that is chosen from
    /// config by [`pdp::policy_from_config`]: a [`EnforcerPolicy`] when
    /// `policy.policy_paths` names files (docs/adr/0001), otherwise a
    /// [`ConfigPolicy`] that denies unmatched tools by default.
    ///
    /// This is the Decide stage alone. It doesn't check the agent's status,
    /// session or own scope, doesn't charge a budget, and records nothing;
    /// [`Kernel::execute`] does all of that.
    #[instrument(skip(self, request), fields(agent_id = %agent_id, tool = %request.tool_name))]
    pub async fn evaluate_policy(
        &self,
        agent_id: &AgentId,
        request: &ToolRequest,
    ) -> PolicyDecision {
        info!(
            agent_id = %agent_id,
            tool = %request.tool_name,
            policy = self.policy.name(),
            "Evaluating policy for tool request"
        );
        let Some(principal) = self.principal(agent_id).await else {
            return PolicyDecision::Deny {
                reason: format!("Agent {agent_id} is not registered"),
                violated_policies: Some(vec!["security.require_registered_agents".to_string()]),
            };
        };
        self.policy
            .decide(&PolicyRequest::new(agent_id, request).with_principal(&principal))
            .await
    }

    /// Executes a tool request through the mediation pipeline.
    ///
    /// 1. **Admit**: the agent must be registered (if
    ///    `security.require_registered_agents`) and active, the session must
    ///    be its own, and the tool must be inside the agent's own scope.
    /// 2. **Budget**: the request is charged to the agent's budget.
    /// 3. **Decide**: the policy decision point must allow it.
    /// 4. **Guard**: planned (Phase 2); nothing runs here yet.
    /// 5. **Record**: the decision is appended to the audit log. If that
    ///    fails, the tool does not run.
    /// 6. **Execute** the tool.
    /// 7. **Record the outcome**, linked to the decision.
    /// 8. **Respond**, with an [`AuditReceipt`] naming both leaves.
    ///
    /// A request stopped at stages 1 to 3 is recorded as a denial before
    /// the error is returned. See `docs/adr/0003`.
    ///
    /// # Arguments
    ///
    /// * `agent_id` - The ID of the agent making the request
    /// * `session_id` - The session ID for the request
    /// * `request` - The tool request to execute
    ///
    /// # Errors
    ///
    /// - [`KernelError::AgentNotFound`], [`KernelError::AgentSuspended`],
    ///   [`KernelError::SessionConflict`]: refused at admission
    /// - [`KernelError::PolicyViolation`]: outside the agent's scope
    ///   (`policy_id` `"agent.scope"`), or denied by policy
    /// - [`KernelError::RateLimited`]: over budget
    /// - [`KernelError::AuditUnavailable`]: the decision couldn't be
    ///   recorded, so nothing ran
    /// - [`KernelError::ToolNotFound`]: no such tool
    ///
    /// A tool that runs and fails is not an error here: the response has
    /// `success: false`.
    #[instrument(skip(self, request), fields(
        agent_id = %agent_id,
        session_id = %session_id,
        tool = %request.tool_name
    ))]
    pub async fn execute(
        &self,
        agent_id: &AgentId,
        session_id: &SessionId,
        request: ToolRequest,
    ) -> Result<ToolResponse, KernelError> {
        // Stage 1: Admit.
        let principal = match self.admit(agent_id, session_id, &request).await {
            Ok(principal) => principal,
            Err((decision, error)) => {
                self.record_rejection(agent_id, session_id, &request, decision)
                    .await;
                return Err(error);
            }
        };

        // Stage 2: Budget. Charged before policy, so requests the policy
        // would deny still count.
        if let BudgetDecision::Exceeded {
            reason,
            retry_after_ms,
        } = self.budget.charge(&principal, &request).await
        {
            warn!(agent_id = %agent_id, %reason, "Request over budget");
            let decision = deny(format!("Budget exceeded: {reason}"), "kernel.budget");
            self.record_rejection(agent_id, session_id, &request, decision)
                .await;
            return Err(KernelError::RateLimited {
                reason,
                retry_after_ms,
            });
        }

        // Stage 3: Decide.
        let decision = self
            .policy
            .decide(
                &PolicyRequest::new(agent_id, &request)
                    .with_principal(&principal)
                    .with_session(session_id),
            )
            .await;

        // Stage 4 (Guard) arrives with the Guard port in Phase 2.

        // Stage 5: Record the decision *before* acting on it. Denials are
        // audited too: a rejected action is exactly the event an auditor
        // most needs to see.
        if let PolicyDecision::Deny { reason, .. } | PolicyDecision::Inadmissible { reason } =
            &decision
        {
            let reason = reason.clone();
            self.record_rejection(agent_id, session_id, &request, decision)
                .await;
            return Err(KernelError::PolicyViolation {
                policy_id: "default".to_string(),
                reason,
            });
        }
        let decision_entry = AuditEntry::new(
            *agent_id,
            *session_id,
            request.tool_name.clone(),
            decision.clone(),
        );
        let decision_leaf = self.audit.append(decision_entry).await.map_err(|e| {
            tracing::error!(error = %e, "Could not record decision - not executing");
            KernelError::AuditUnavailable {
                message: e.to_string(),
            }
        })?;

        // Stage 6: Execute.
        let start_time = std::time::Instant::now();
        let execution_result = self.dispatch_tool(agent_id, &request).await;
        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // Stage 7: Record the outcome, linked to the decision. The tool has
        // already run, so a failure here must not turn into an error: the
        // agent would think the action didn't happen and might repeat it. A
        // response without a receipt is the signal instead.
        let outcome = AuditOutcome {
            decision_leaf,
            success: execution_result.is_ok(),
            error: execution_result.as_ref().err().map(ToString::to_string),
            result_sha256: execution_result.as_ref().ok().map(result_digest),
            execution_time_ms,
        };
        let outcome_entry =
            AuditEntry::new(*agent_id, *session_id, request.tool_name.clone(), decision)
                .with_outcome(outcome);
        let receipt = match self.audit.append(outcome_entry).await {
            Ok(outcome_leaf) => Some(AuditReceipt {
                decision_leaf,
                outcome_leaf,
                tree_head: self.audit_tree_head().await,
            }),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    decision_leaf,
                    "Tool ran but its outcome could not be recorded"
                );
                None
            }
        };

        // Stage 8: Respond.
        let response = match execution_result {
            // A tool that doesn't exist is the caller's error, not a failed
            // execution, and must never be reported as anything that ran.
            Err(e @ KernelError::ToolNotFound { .. }) => return Err(e),
            Ok(result) => ToolResponse {
                request_id: request.request_id,
                success: true,
                result: Some(result),
                error: None,
                execution_time_ms,
                receipt,
            },
            Err(e) => ToolResponse {
                request_id: request.request_id,
                success: false,
                result: None,
                error: Some(e.to_string()),
                execution_time_ms,
                receipt,
            },
        };

        Ok(response)
    }

    /// The Admit stage. On refusal, returns the decision to record and the
    /// error to return.
    async fn admit(
        &self,
        agent_id: &AgentId,
        session_id: &SessionId,
        request: &ToolRequest,
    ) -> Result<AgentRecord, (PolicyDecision, KernelError)> {
        let Some(principal) = self.principal(agent_id).await else {
            warn!(agent_id = %agent_id, "Unregistered agent refused");
            return Err((
                deny(
                    format!("Agent {agent_id} is not registered"),
                    "security.require_registered_agents",
                ),
                KernelError::AgentNotFound {
                    agent_id: agent_id.to_string(),
                },
            ));
        };

        if let AgentStatus::Suspended { reason } = &principal.status {
            warn!(agent_id = %agent_id, %reason, "Suspended agent refused");
            return Err((
                deny(format!("Agent is suspended: {reason}"), "kernel.admission"),
                KernelError::AgentSuspended {
                    agent_id: agent_id.to_string(),
                    reason: reason.clone(),
                },
            ));
        }

        match self.sessions.write().await.entry(*session_id) {
            Entry::Occupied(bound) if bound.get() != agent_id => {
                warn!(agent_id = %agent_id, session_id = %session_id, "Session belongs to another agent");
                return Err((
                    deny(
                        format!("Session {session_id} belongs to another agent"),
                        "kernel.session",
                    ),
                    KernelError::SessionConflict {
                        session_id: session_id.to_string(),
                    },
                ));
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(slot) => {
                slot.insert(*agent_id);
            }
        }

        if let Some(reason) = principal.scope_violation(&request.tool_name) {
            warn!(agent_id = %agent_id, tool = %request.tool_name, "Tool outside agent scope");
            return Err((
                deny(reason.clone(), "agent.scope"),
                KernelError::PolicyViolation {
                    policy_id: "agent.scope".to_string(),
                    reason,
                },
            ));
        }

        Ok(principal)
    }

    /// Records a refused request. The request is refused whether or not this
    /// succeeds, so a failure is logged rather than returned: the caller
    /// needs the real reason for the refusal.
    async fn record_rejection(
        &self,
        agent_id: &AgentId,
        session_id: &SessionId,
        request: &ToolRequest,
        decision: PolicyDecision,
    ) {
        let entry = AuditEntry::new(*agent_id, *session_id, request.tool_name.clone(), decision);
        if let Err(e) = self.audit.append(entry).await {
            tracing::error!(error = %e, tool = %request.tool_name, "Could not record a refused request");
        }
    }

    /// Dispatches a tool request to the appropriate handler.
    ///
    /// # Arguments
    ///
    /// * `request` - The tool request to dispatch
    ///
    /// # Returns
    ///
    /// The result of the tool execution as a JSON value.
    ///
    /// # Built-in Tools
    ///
    /// The kernel provides several built-in tools:
    /// - `echo`: Returns the input parameters as-is
    /// - `calculator`: Performs basic arithmetic operations
    /// - `data_processor`: Processes data arrays with various operations
    /// - `system_info`: Returns system information (kernel version, etc.)
    async fn dispatch_tool(
        &self,
        agent_id: &AgentId,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        match request.tool_name.as_str() {
            "echo" => {
                // Echo tool: returns the input parameters
                Ok(request.parameters.clone())
            }
            "calculator" => {
                // Calculator tool: performs basic arithmetic
                self.handle_calculator(request).await
            }
            "data_processor" => {
                // Data processor: summarize, transform, filter data
                self.handle_data_processor(request).await
            }
            "system_info" => {
                // System info: return kernel information
                Ok(serde_json::json!({
                    "kernel_name": self.config.name,
                    "version": crate::VERSION,
                    "max_concurrent_agents": self.config.max_concurrent_agents,
                    "sandboxing_enabled": self.config.security.enable_sandboxing,
                    "audit_enabled": self.config.audit.enabled,
                }))
            }
            name => {
                if self.tools.has_handler(name).await {
                    self.execute_registered_tool(agent_id, request).await
                } else {
                    // Try to execute as WASM skill (Issue #6)
                    self.execute_wasm_skill(request).await
                }
            }
        }
    }

    /// Runs a handler registered with [`Kernel::register_tool`].
    async fn execute_registered_tool(
        &self,
        agent_id: &AgentId,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        let failed = |reason: String| KernelError::ToolExecutionFailed {
            tool_name: request.tool_name.clone(),
            reason,
        };
        // Handlers are embedder code running in-process. A panic in one must
        // fail that call, not unwind through the kernel into the caller.
        let outcome = std::panic::AssertUnwindSafe(self.tools.execute(request, agent_id))
            .catch_unwind()
            .await;
        let Ok(result) = outcome else {
            tracing::error!(tool = %request.tool_name, "Tool handler panicked");
            return Err(failed("handler panicked".to_string()));
        };
        match result {
            Ok(response) if response.success => {
                Ok(response.result.unwrap_or(serde_json::Value::Null))
            }
            Ok(response) => Err(failed(
                response
                    .error
                    .unwrap_or_else(|| "handler reported failure".to_string()),
            )),
            Err(HandlerError::Timeout(ms)) => Err(KernelError::Timeout { timeout_ms: ms }),
            Err(e) => Err(failed(e.to_string())),
        }
    }

    /// Executes a WASM skill in the sandbox (Issue #6)
    ///
    /// This method handles the execution flow:
    /// 1. Look up skill in registry by name
    /// 2. Load the WASM module if found
    /// 3. Execute in sandboxed environment with resource limits
    /// 4. Return the result, or [`KernelError::ToolNotFound`] if no skill has
    ///    that name
    async fn execute_wasm_skill(
        &self,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        // Check if skill exists in registry
        let registry = self.skill_registry.read().await;

        if let Some(manifest) = registry.get_skill_by_name(&request.tool_name) {
            // Skill found - try to execute in sandbox
            info!(
                tool = %request.tool_name,
                version = %manifest.version,
                "Executing WASM skill"
            );

            // Create sandbox with configured limits
            let mut sandbox = WasmSandbox::new(self.sandbox_config.clone()).map_err(|e| {
                KernelError::ToolExecutionFailed {
                    tool_name: request.tool_name.clone(),
                    reason: format!("Failed to create sandbox: {}", e),
                }
            })?;

            // Load the WASM module
            sandbox
                .load_skill_from_file(&manifest.wasm_path)
                .map_err(|e| KernelError::ToolExecutionFailed {
                    tool_name: request.tool_name.clone(),
                    reason: format!("Failed to load WASM module: {}", e),
                })?;

            // Execute the skill
            // WASM skills expose an "execute" function that takes JSON input
            let result = sandbox
                .execute("execute", &request.parameters)
                .map_err(|e| KernelError::ToolExecutionFailed {
                    tool_name: request.tool_name.clone(),
                    reason: format!("WASM execution failed: {}", e),
                })?;

            Ok(result)
        } else {
            // Fail closed. This used to return a success response from a
            // "default handler" that executed nothing, so an agent could be
            // told an action happened when it hadn't.
            warn!(tool = %request.tool_name, "Tool not found");
            Err(KernelError::ToolNotFound {
                tool_name: request.tool_name.clone(),
            })
        }
    }

    /// List available tools/skills
    pub async fn list_tools(&self) -> Vec<String> {
        let registry = self.skill_registry.read().await;
        let mut tools = vec![
            "echo".to_string(),
            "calculator".to_string(),
            "data_processor".to_string(),
            "system_info".to_string(),
        ];

        // Host-side handlers registered by the embedder
        for handler in self.tools.list_handlers().await {
            tools.push(handler.name);
        }

        // Add registered WASM skills
        for skill in registry.list_skills() {
            tools.push(skill.name.clone());
        }

        tools
    }

    /// Handles calculator tool requests.
    async fn handle_calculator(
        &self,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        let operation = request
            .parameters
            .get("operation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "calculator".to_string(),
                reason: "Missing 'operation' parameter".to_string(),
            })?;

        let operands = request
            .parameters
            .get("operands")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "calculator".to_string(),
                reason: "Missing or invalid 'operands' parameter".to_string(),
            })?;

        let numbers: Result<Vec<f64>, _> = operands
            .iter()
            .map(|v| {
                v.as_f64().ok_or_else(|| KernelError::ToolExecutionFailed {
                    tool_name: "calculator".to_string(),
                    reason: "Operands must be numbers".to_string(),
                })
            })
            .collect();

        let numbers = numbers?;

        let result = match operation {
            "add" => numbers.iter().sum::<f64>(),
            "subtract" => {
                if numbers.is_empty() {
                    0.0
                } else {
                    numbers.iter().skip(1).fold(numbers[0], |acc, x| acc - x)
                }
            }
            "multiply" => numbers.iter().product::<f64>(),
            "divide" => {
                if numbers.is_empty() {
                    return Err(KernelError::ToolExecutionFailed {
                        tool_name: "calculator".to_string(),
                        reason: "Division requires at least one operand".to_string(),
                    });
                }
                if numbers.iter().skip(1).any(|&x| x == 0.0) {
                    return Err(KernelError::ToolExecutionFailed {
                        tool_name: "calculator".to_string(),
                        reason: "Division by zero".to_string(),
                    });
                }
                numbers.iter().skip(1).fold(numbers[0], |acc, x| acc / x)
            }
            _ => {
                return Err(KernelError::ToolExecutionFailed {
                    tool_name: "calculator".to_string(),
                    reason: format!("Unknown operation: {}", operation),
                });
            }
        };

        Ok(serde_json::json!({
            "operation": operation,
            "operands": operands,
            "result": result
        }))
    }

    /// Handles data processor tool requests.
    async fn handle_data_processor(
        &self,
        request: &ToolRequest,
    ) -> Result<serde_json::Value, KernelError> {
        let action = request
            .parameters
            .get("action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "data_processor".to_string(),
                reason: "Missing 'action' parameter".to_string(),
            })?;

        let data = request
            .parameters
            .get("data")
            .and_then(|v| v.as_array())
            .ok_or_else(|| KernelError::ToolExecutionFailed {
                tool_name: "data_processor".to_string(),
                reason: "Missing or invalid 'data' parameter".to_string(),
            })?;

        match action {
            "summarize" => {
                let numbers: Vec<f64> = data.iter().filter_map(|v| v.as_f64()).collect();

                if numbers.is_empty() {
                    return Ok(serde_json::json!({
                        "action": "summarize",
                        "count": 0,
                        "message": "No numeric data to summarize"
                    }));
                }

                let sum: f64 = numbers.iter().sum();
                let count = numbers.len();
                let mean = sum / count as f64;
                let min = numbers.iter().cloned().fold(f64::INFINITY, f64::min);
                let max = numbers.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

                Ok(serde_json::json!({
                    "action": "summarize",
                    "count": count,
                    "sum": sum,
                    "mean": mean,
                    "min": min,
                    "max": max
                }))
            }
            "count" => Ok(serde_json::json!({
                "action": "count",
                "count": data.len()
            })),
            "filter" => {
                let predicate = request
                    .parameters
                    .get("predicate")
                    .and_then(|v| v.as_str())
                    .unwrap_or("non_null");

                let filtered: Vec<&serde_json::Value> = match predicate {
                    "non_null" => data.iter().filter(|v| !v.is_null()).collect(),
                    "numbers" => data.iter().filter(|v| v.is_number()).collect(),
                    "strings" => data.iter().filter(|v| v.is_string()).collect(),
                    _ => data.iter().collect(),
                };

                Ok(serde_json::json!({
                    "action": "filter",
                    "predicate": predicate,
                    "original_count": data.len(),
                    "filtered_count": filtered.len(),
                    "filtered_data": filtered
                }))
            }
            _ => Err(KernelError::ToolExecutionFailed {
                tool_name: "data_processor".to_string(),
                reason: format!("Unknown action: {}", action),
            }),
        }
    }

    /// The Merkle leaf hash of an audit entry: `leaf_hash(entry.hash)`, over
    /// the entry's hex hash string as bytes.
    ///
    /// To verify one entry without trusting the kernel, check both:
    ///
    /// 1. [`AuditEntry::verify_integrity`]: the entry's fields match its hash.
    /// 2. [`crate::audit::transparency::verify_inclusion`] of this leaf hash
    ///    against a signed tree head's root.
    ///
    /// The first alone can be satisfied by a rewritten entry with a
    /// recomputed hash; the second alone by a rewritten entry that kept its
    /// old hash.
    #[must_use]
    pub fn audit_leaf_hash(entry: &AuditEntry) -> Digest {
        audit_log::entry_leaf_hash(entry)
    }

    /// Retrieves the audit log entries.
    ///
    /// In production, this would support pagination and filtering.
    pub async fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit.entries().await
    }

    /// Verifies the integrity of the kernel's audit chain.
    ///
    /// Returns `Err(index)` identifying the first entry that has been altered,
    /// reordered, or spliced in.
    pub async fn verify_audit_chain(&self) -> Result<(), usize> {
        AuditEntry::verify_chain(&self.audit.entries().await)
    }

    /// The current audit tree head, signed with the kernel's audit key.
    ///
    /// Publish these. Anyone who has seen a head can later demand a
    /// [`Kernel::prove_audit_consistency`] proof, which the kernel cannot
    /// produce if it has since dropped or rewritten any entry.
    pub async fn audit_tree_head(&self) -> SignedTreeHead {
        let head = self.audit.tree_head().await;
        let timestamp_ms = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap_or(0);
        head.sign(&self.audit_key, timestamp_ms)
    }

    /// The public key that verifies [`Kernel::audit_tree_head`] signatures.
    #[must_use]
    pub fn audit_verifying_key(&self) -> VerifyingKey {
        self.audit_key.verifying_key()
    }

    /// Proves that the audit entry at `leaf_index` is in the tree of the
    /// first `tree_size` entries. Verify with
    /// [`crate::audit::transparency::verify_inclusion`] and
    /// [`Kernel::audit_leaf_hash`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::AuditProof`] if the index or size is out of range.
    pub async fn prove_audit_inclusion(
        &self,
        leaf_index: u64,
        tree_size: u64,
    ) -> Result<InclusionProof, KernelError> {
        self.audit
            .inclusion_proof(leaf_index, tree_size)
            .await
            .map_err(audit_proof_error)
    }

    /// Proves that the audit tree of `old_size` entries is a prefix of the
    /// tree of `new_size` entries. Verify with
    /// [`crate::audit::transparency::verify_consistency`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::AuditProof`] if the sizes are out of range.
    pub async fn prove_audit_consistency(
        &self,
        old_size: u64,
        new_size: u64,
    ) -> Result<ConsistencyProof, KernelError> {
        self.audit
            .consistency_proof(old_size, new_size)
            .await
            .map_err(audit_proof_error)
    }

    /// Returns the number of sessions currently bound to an agent.
    pub async fn active_session_count(&self) -> usize {
        self.sessions.read().await.len()
    }
}

fn audit_proof_error(e: AuditLogError) -> KernelError {
    KernelError::AuditProof {
        message: e.to_string(),
    }
}

/// A denial recorded for a request refused before (or by) policy.
fn deny(reason: String, rule: &str) -> PolicyDecision {
    PolicyDecision::Deny {
        reason,
        violated_policies: Some(vec![rule.to_string()]),
    }
}

/// Hex SHA-256 of a tool result's JSON serialization.
fn result_digest(result: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(result).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

#[cfg(test)]
mod tests {
    use self::config::{PolicyConfig, SecurityConfig};
    use super::*;

    #[tokio::test]
    async fn test_kernel_creation() {
        let config = KernelConfig::default();
        let kernel = Kernel::new(config).await;
        assert!(kernel.is_ok());
    }

    fn request_for(tool: &str) -> ToolRequest {
        ToolRequest {
            request_id: uuid::Uuid::new_v4(),
            tool_name: tool.to_string(),
            parameters: serde_json::json!({}),
            timeout_ms: Some(5000),
        }
    }

    #[tokio::test]
    async fn test_policy_allows_builtin_tools() {
        let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
        let agent_id = AgentId::new();

        let decision = kernel
            .evaluate_policy(&agent_id, &request_for("echo"))
            .await;
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn test_policy_denies_unmatched_tool_by_default() {
        let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
        let agent_id = AgentId::new();

        // No rule permits "test_tool", and the default decision is Deny.
        // A kernel whose premise is "no policy = no access" must not fail open.
        let decision = kernel
            .evaluate_policy(&agent_id, &request_for("test_tool"))
            .await;
        assert!(
            matches!(decision, PolicyDecision::Deny { .. }),
            "unmatched tool must be denied, got {decision:?}"
        );
    }

    #[tokio::test]
    async fn test_policy_default_decision_allow_is_honoured() {
        // `default_decision` governs the case where no allowlist constrains
        // the request. A non-empty allowlist is itself a policy and stays
        // authoritative, so clear it to reach the fallback.
        let config = KernelConfig {
            security: SecurityConfig {
                allowed_tools: Vec::new(),
                ..Default::default()
            },
            policy: PolicyConfig {
                default_decision: DefaultPolicyDecision::Allow,
                ..Default::default()
            },
            ..Default::default()
        };
        let kernel = Kernel::new(config).await.unwrap();
        let agent_id = AgentId::new();

        let decision = kernel
            .evaluate_policy(&agent_id, &request_for("test_tool"))
            .await;
        assert!(matches!(decision, PolicyDecision::Allow { .. }));
    }

    #[tokio::test]
    async fn test_empty_allowlist_still_denies_by_default() {
        // The dangerous combination: no allowlist configured at all. This must
        // deny, not fall through to allow.
        let config = KernelConfig {
            security: SecurityConfig {
                allowed_tools: Vec::new(),
                ..Default::default()
            },
            ..Default::default()
        };
        let kernel = Kernel::new(config).await.unwrap();
        let agent_id = AgentId::new();

        let decision = kernel
            .evaluate_policy(&agent_id, &request_for("test_tool"))
            .await;
        assert!(
            matches!(decision, PolicyDecision::Deny { .. }),
            "empty allowlist must not mean 'allow everything'"
        );
    }

    // ------------------------------------------------------------------
    // Mediation pipeline: ports, registered tools, fail-closed dispatch,
    // and audit proofs (docs/architecture-v2.md §5)
    // ------------------------------------------------------------------

    use crate::audit::transparency::{verify_consistency, verify_inclusion};
    use crate::kernel::custom_handlers::HandlerFuture;

    fn greet_handler(
    ) -> FunctionHandler<impl Fn(&ToolRequest, &AgentId) -> HandlerFuture + Send + Sync> {
        FunctionHandler::new("greet", |req: &ToolRequest, _agent: &AgentId| {
            let id = req.request_id;
            Box::pin(async move { Ok(ToolResponse::success(id, serde_json::json!("hello"), 0)) })
                as HandlerFuture
        })
    }

    fn config_allowing(tools: &[&str]) -> KernelConfig {
        let mut config = KernelConfig::default();
        config
            .security
            .allowed_tools
            .extend(tools.iter().map(|t| t.to_string()));
        config
    }

    #[tokio::test]
    async fn test_unknown_tool_fails_closed() {
        // Regression: a permitted tool with no implementation used to return
        // success from a "default handler" that executed nothing.
        let kernel = Kernel::new(config_allowing(&["transfer_funds"]))
            .await
            .unwrap();
        let result = kernel
            .execute(
                &AgentId::new(),
                &SessionId::new(),
                request_for("transfer_funds"),
            )
            .await;
        assert!(
            matches!(result, Err(KernelError::ToolNotFound { ref tool_name }) if tool_name == "transfer_funds"),
            "got {result:?}"
        );
        // The attempt is still on the record: the decision, then an outcome
        // saying nothing ran.
        let entries = kernel.get_audit_log().await;
        assert_eq!(entries.len(), 2);
        let outcome = entries[1].outcome.as_ref().unwrap();
        assert_eq!(outcome.decision_leaf, 0);
        assert!(!outcome.success);
        assert!(outcome.error.as_ref().unwrap().contains("not found"));
        assert!(outcome.result_sha256.is_none());
    }

    #[tokio::test]
    async fn test_registered_tool_runs_when_permitted() {
        let kernel = Kernel::builder(config_allowing(&["greet"]))
            .with_tool(greet_handler())
            .build()
            .await
            .unwrap();
        let response = kernel
            .execute(&AgentId::new(), &SessionId::new(), request_for("greet"))
            .await
            .unwrap();
        assert!(response.success);
        assert_eq!(response.result, Some(serde_json::json!("hello")));
        assert!(kernel.list_tools().await.contains(&"greet".to_string()));
    }

    #[tokio::test]
    async fn test_registered_tool_still_needs_policy() {
        // Registering a tool makes it exist; it does not authorize it.
        let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
        kernel.register_tool(greet_handler()).await.unwrap();
        let result = kernel
            .execute(&AgentId::new(), &SessionId::new(), request_for("greet"))
            .await;
        assert!(matches!(result, Err(KernelError::PolicyViolation { .. })));
    }

    #[tokio::test]
    async fn test_tool_registration_rejects_shadowing_and_duplicates() {
        let kernel = Kernel::new(KernelConfig::default()).await.unwrap();

        let shadow = FunctionHandler::new("echo", |req: &ToolRequest, _: &AgentId| {
            let id = req.request_id;
            Box::pin(async move { Ok(ToolResponse::success(id, serde_json::json!("pwned"), 0)) })
                as HandlerFuture
        });
        assert!(matches!(
            kernel.register_tool(shadow).await,
            Err(KernelError::InvalidConfiguration { .. })
        ));

        kernel.register_tool(greet_handler()).await.unwrap();
        assert!(matches!(
            kernel.register_tool(greet_handler()).await,
            Err(KernelError::InvalidConfiguration { .. })
        ));

        let duplicate_at_build = Kernel::builder(KernelConfig::default())
            .with_tool(greet_handler())
            .with_tool(greet_handler())
            .build()
            .await;
        assert!(duplicate_at_build.is_err());
    }

    #[tokio::test]
    async fn test_panicking_handler_does_not_unwind_through_kernel() {
        let panicking = FunctionHandler::new("boom", |req: &ToolRequest, _: &AgentId| {
            let id = req.request_id;
            let buggy = true;
            Box::pin(async move {
                if buggy {
                    panic!("handler bug");
                }
                Ok(ToolResponse::success(id, serde_json::json!(null), 0))
            }) as HandlerFuture
        });
        let kernel = Kernel::builder(config_allowing(&["boom"]))
            .with_tool(panicking)
            .build()
            .await
            .unwrap();
        let response = kernel
            .execute(&AgentId::new(), &SessionId::new(), request_for("boom"))
            .await
            .unwrap();
        assert!(!response.success);
        assert!(response.error.unwrap().contains("panicked"));

        // The kernel is still serviceable afterwards.
        assert!(
            kernel
                .execute(&AgentId::new(), &SessionId::new(), request_for("echo"))
                .await
                .unwrap()
                .success
        );
    }

    #[tokio::test]
    async fn test_slow_handler_times_out() {
        let slow = FunctionHandler::new("slow", |req: &ToolRequest, _: &AgentId| {
            let id = req.request_id;
            Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                Ok(ToolResponse::success(id, serde_json::json!(null), 0))
            }) as HandlerFuture
        });
        let mut config = config_allowing(&["slow"]);
        config.max_execution_time = std::time::Duration::from_millis(50);
        let kernel = Kernel::builder(config)
            .with_tool(slow)
            .build()
            .await
            .unwrap();
        let response = kernel
            .execute(&AgentId::new(), &SessionId::new(), request_for("slow"))
            .await
            .unwrap();
        assert!(!response.success);
        assert!(response.error.unwrap().contains("timed out"));
    }

    #[tokio::test]
    async fn test_handler_failure_is_reported_not_hidden() {
        let failing = FunctionHandler::new("flaky", |req: &ToolRequest, _: &AgentId| {
            let id = req.request_id;
            Box::pin(async move { Ok(ToolResponse::failure(id, "upstream down", 0)) })
                as HandlerFuture
        });
        let kernel = Kernel::builder(config_allowing(&["flaky"]))
            .with_tool(failing)
            .build()
            .await
            .unwrap();
        let response = kernel
            .execute(&AgentId::new(), &SessionId::new(), request_for("flaky"))
            .await
            .unwrap();
        assert!(!response.success);
        assert!(response.error.unwrap().contains("upstream down"));
    }

    /// Denies everything and counts calls, to show the kernel consults an
    /// injected decision point instead of its config.
    #[derive(Debug, Default)]
    struct DenyAll {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl PolicyDecisionPoint for DenyAll {
        async fn decide(&self, _req: &PolicyRequest<'_>) -> PolicyDecision {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            PolicyDecision::Deny {
                reason: "deny-all".to_string(),
                violated_policies: None,
            }
        }

        fn name(&self) -> &str {
            "deny-all"
        }
    }

    #[tokio::test]
    async fn test_injected_policy_overrides_config() {
        let pdp = Arc::new(DenyAll::default());
        let kernel = Kernel::builder(KernelConfig::default())
            .with_policy(pdp.clone())
            .build()
            .await
            .unwrap();
        assert_eq!(kernel.policy_decision_point().name(), "deny-all");

        // `echo` is allowed by the default config, but the injected PDP wins.
        let result = kernel
            .execute(&AgentId::new(), &SessionId::new(), request_for("echo"))
            .await;
        assert!(matches!(result, Err(KernelError::PolicyViolation { .. })));
        assert_eq!(pdp.calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_audit_decisions_are_provable_to_a_third_party() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let kernel = Kernel::builder(KernelConfig::default())
            .with_audit_signing_key(key.clone())
            .build()
            .await
            .unwrap();
        let agent = AgentId::new();
        let session = SessionId::new();

        kernel
            .execute(&agent, &session, request_for("echo"))
            .await
            .unwrap();
        let first_head = kernel.audit_tree_head().await;

        let _ = kernel.execute(&agent, &session, request_for("rm_rf")).await; // denied
        kernel
            .execute(&agent, &session, request_for("system_info"))
            .await
            .unwrap();
        let head = kernel.audit_tree_head().await;

        // The verifier trusts only the key, not the kernel.
        assert_eq!(kernel.audit_verifying_key(), key.verifying_key());
        head.verify(&key.verifying_key()).unwrap();
        first_head.verify(&key.verifying_key()).unwrap();
        // echo: decision + outcome; rm_rf: one denial; system_info: decision
        // + outcome.
        assert_eq!(head.head.size, 5);

        // Every decision, including the denial, is provably in the log.
        let entries = kernel.get_audit_log().await;
        for (index, entry) in entries.iter().enumerate() {
            let proof = kernel
                .prove_audit_inclusion(index as u64, head.head.size)
                .await
                .unwrap();
            verify_inclusion(&Kernel::audit_leaf_hash(entry), &proof, &head.head.root).unwrap();
        }
        assert!(matches!(entries[2].decision, PolicyDecision::Deny { .. }));
        assert!(entries[2].outcome.is_none());

        // The later head extends the earlier one.
        let consistency = kernel
            .prove_audit_consistency(first_head.head.size, head.head.size)
            .await
            .unwrap();
        verify_consistency(&consistency, &first_head.head.root, &head.head.root).unwrap();

        // Out-of-range requests are errors, not panics.
        assert!(matches!(
            kernel.prove_audit_inclusion(5, 5).await,
            Err(KernelError::AuditProof { .. })
        ));
        assert!(matches!(
            kernel.prove_audit_consistency(1, 6).await,
            Err(KernelError::AuditProof { .. })
        ));
    }

    #[tokio::test]
    async fn test_audit_proof_fails_for_altered_entry() {
        let kernel = Kernel::new(KernelConfig::default()).await.unwrap();
        kernel
            .execute(&AgentId::new(), &SessionId::new(), request_for("echo"))
            .await
            .unwrap();
        let head = kernel.audit_tree_head().await;
        let proof = kernel
            .prove_audit_inclusion(0, head.head.size)
            .await
            .unwrap();
        let original = kernel.get_audit_log().await.remove(0);
        assert!(original.verify_integrity());
        verify_inclusion(&Kernel::audit_leaf_hash(&original), &proof, &head.head.root).unwrap();

        let denied = PolicyDecision::Deny {
            reason: "rewritten".to_string(),
            violated_policies: None,
        };

        // Forgery 1: rewrite the decision, keep the old hash. The leaf still
        // matches, which is why a verifier must also check the entry against
        // its own hash.
        let mut kept_hash = original.clone();
        kept_hash.decision = denied.clone();
        assert!(!kept_hash.verify_integrity());

        // Forgery 2: rewrite the decision and recompute the hash. The entry
        // is self-consistent, but it is no longer the leaf under the
        // published root. (An empty predecessor hashes like none, so this is
        // exactly the hash an attacker would compute.)
        let mut rehashed = original.clone();
        rehashed.decision = denied;
        let rehashed = rehashed.with_previous(String::new());
        assert!(rehashed.verify_integrity());
        assert!(
            verify_inclusion(&Kernel::audit_leaf_hash(&rehashed), &proof, &head.head.root).is_err()
        );
    }
}
