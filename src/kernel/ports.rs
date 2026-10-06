//! Ports: the traits the kernel's mediation pipeline calls.
//!
//! The kernel owns *mediation*: every request is admitted, budgeted,
//! decided, recorded, then executed, in that order. It does not own *how*
//! agents are looked up, budgets kept, decisions made, records stored or
//! tools run. Those sit behind the traits re-exported here, so an embedder
//! can supply a real Cedar engine, a database-backed registry, or a test
//! double without forking the kernel. See `docs/architecture-v2.md` §5.2 and
//! `docs/adr/0003`.
//!
//! | Stage | Port |
//! |---|---|
//! | Admit | [`AgentRegistry`] |
//! | Budget | [`Budget`] |
//! | Decide | [`PolicyDecisionPoint`] |
//! | Record | [`AuditLog`] |
//! | Execute | [`ToolHandler`] |

use async_trait::async_trait;

pub use super::audit_log::AuditLog;
pub use super::budget::Budget;
pub use super::custom_handlers::ToolHandler;
pub use super::identity::AgentRegistry;

use super::identity::AgentRecord;
use super::types::{AgentId, PolicyDecision, SessionId, ToolRequest};

/// What a [`PolicyDecisionPoint`] is asked to decide.
///
/// Marked `#[non_exhaustive]` because the pipeline will hand the PDP more
/// context over time (session history, information-flow labels); adding a
/// field must not break existing implementations. Construct it with
/// [`PolicyRequest::new`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct PolicyRequest<'a> {
    /// The agent asking to act.
    pub agent_id: &'a AgentId,
    /// The tool call it wants to make.
    pub request: &'a ToolRequest,
    /// The agent's record from the Admit stage. Its attributes are what
    /// policy conditions read as `principal.*`. `None` only when the PDP is
    /// called outside `Kernel::execute`; treat that as an agent about which
    /// nothing is known.
    pub principal: Option<&'a AgentRecord>,
    /// The session the request was made in.
    pub session_id: Option<&'a SessionId>,
}

impl<'a> PolicyRequest<'a> {
    /// Creates a policy request.
    #[must_use]
    pub fn new(agent_id: &'a AgentId, request: &'a ToolRequest) -> Self {
        Self {
            agent_id,
            request,
            principal: None,
            session_id: None,
        }
    }

    /// Attaches the agent's record.
    #[must_use]
    pub fn with_principal(mut self, principal: &'a AgentRecord) -> Self {
        self.principal = Some(principal);
        self
    }

    /// Attaches the session.
    #[must_use]
    pub fn with_session(mut self, session_id: &'a SessionId) -> Self {
        self.session_id = Some(session_id);
        self
    }
}

/// Decides whether an agent may perform an action.
///
/// Implementations must fail closed: if a decision cannot be reached (a
/// policy failed to evaluate, a backend is unreachable), the answer is
/// [`PolicyDecision::Deny`], never `Allow`. The kernel records whatever is
/// returned in the audit log before acting on it.
///
/// # Example
///
/// ```rust
/// use async_trait::async_trait;
/// use vak::kernel::ports::{PolicyDecisionPoint, PolicyRequest};
/// use vak::kernel::types::PolicyDecision;
///
/// /// Allows only read-only tools.
/// #[derive(Debug)]
/// struct ReadOnly;
///
/// #[async_trait]
/// impl PolicyDecisionPoint for ReadOnly {
///     async fn decide(&self, req: &PolicyRequest<'_>) -> PolicyDecision {
///         if req.request.tool_name.starts_with("read_") {
///             PolicyDecision::Allow { reason: "read-only tool".into(), constraints: None }
///         } else {
///             PolicyDecision::Deny { reason: "not read-only".into(), violated_policies: None }
///         }
///     }
///
///     fn name(&self) -> &str {
///         "read-only"
///     }
/// }
/// ```
#[async_trait]
pub trait PolicyDecisionPoint: Send + Sync + std::fmt::Debug {
    /// Decides one request.
    async fn decide(&self, request: &PolicyRequest<'_>) -> PolicyDecision;

    /// A short name identifying this decision point in logs.
    fn name(&self) -> &str;
}
