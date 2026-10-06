//! Agent identity: who is asking, and what they are allowed to ask for.
//!
//! The Admit stage of [`Kernel::execute`](super::Kernel::execute) looks the
//! requesting agent up in an [`AgentRegistry`] on every call. The
//! [`AgentRecord`] it gets back supplies:
//!
//! - the attributes policy conditions read (`principal.internal`, …), which
//!   used to be a constant `internal = true` for every agent (K8 in
//!   `docs/architecture-v2.md`);
//! - the agent's status, so a suspension takes effect on its next request;
//! - the agent's own tool scope, which can only narrow what policy allows.
//!
//! Before this module, per-agent tool lists lived in
//! [`VakAgent`](crate::lib_integration::VakAgent) and were checked on the
//! client side, so any other caller of the kernel bypassed them and their
//! rejections were never audited. See `docs/adr/0003`.

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use super::types::AgentId;

/// Whether an agent may act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum AgentStatus {
    /// The agent may make requests.
    #[default]
    Active,
    /// The agent is refused until reinstated.
    Suspended {
        /// Why it was suspended; recorded in the audit log on each refusal.
        reason: String,
    },
}

/// What the kernel knows about one agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentRecord {
    /// The agent's identifier.
    pub id: AgentId,
    /// A human-readable name, for logs.
    pub name: String,
    /// Reaches policy as `principal.internal`.
    pub internal: bool,
    /// Whether the agent may act.
    #[serde(default)]
    pub status: AgentStatus,
    /// If set, the only tools this agent may call. `None` means the record
    /// does not narrow anything and policy alone decides.
    #[serde(default)]
    pub allowed_tools: Option<Vec<String>>,
    /// Tools this agent may never call, whatever policy says.
    #[serde(default)]
    pub blocked_tools: Vec<String>,
    /// Further attributes, which reach policy as `principal.<key>`.
    #[serde(default)]
    pub attributes: HashMap<String, serde_json::Value>,
}

impl AgentRecord {
    /// A record for a registered agent: active, not internal, no narrowing.
    #[must_use]
    pub fn new(id: AgentId, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            internal: false,
            status: AgentStatus::Active,
            allowed_tools: None,
            blocked_tools: Vec::new(),
            attributes: HashMap::new(),
        }
    }

    /// The record used for an agent the registry doesn't know, when
    /// unregistered agents are admitted. It assumes nothing: not internal,
    /// no attributes. Policy decides as it would for any principal.
    #[must_use]
    pub fn anonymous(id: AgentId) -> Self {
        Self::new(id, "anonymous")
    }

    /// Marks the agent as internal (`principal.internal == true`).
    #[must_use]
    pub fn internal(mut self, internal: bool) -> Self {
        self.internal = internal;
        self
    }

    /// Restricts the agent to `tools`.
    #[must_use]
    pub fn with_allowed_tools<I, S>(mut self, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_tools = Some(tools.into_iter().map(Into::into).collect());
        self
    }

    /// Forbids the agent from calling `tools`.
    #[must_use]
    pub fn with_blocked_tools<I, S>(mut self, tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.blocked_tools = tools.into_iter().map(Into::into).collect();
        self
    }

    /// Adds an attribute that policy conditions can read as `principal.<key>`.
    #[must_use]
    pub fn with_attribute(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Whether the agent's own scope includes `tool`.
    ///
    /// This only narrows: `true` means the record doesn't forbid the tool,
    /// not that the agent may call it. Policy still decides.
    #[must_use]
    pub fn permits_tool(&self, tool: &str) -> bool {
        self.scope_violation(tool).is_none()
    }

    /// Why the agent's own scope excludes `tool`, or `None` if it doesn't.
    #[must_use]
    pub fn scope_violation(&self, tool: &str) -> Option<String> {
        if self.blocked_tools.iter().any(|t| t == tool) {
            return Some(format!(
                "Tool '{tool}' is blocked for agent '{}'",
                self.name
            ));
        }
        match &self.allowed_tools {
            Some(allowed) if !allowed.iter().any(|t| t == tool) => Some(format!(
                "Tool '{tool}' is not in the allowed tools list for agent '{}'",
                self.name
            )),
            _ => None,
        }
    }
}

/// Errors from changing a registry.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum RegistryError {
    /// This registry is read-only from the kernel's side.
    #[error("agent registry '{0}' does not accept registrations")]
    ReadOnly(String),
    /// The agent is not registered.
    #[error("agent not registered: {0}")]
    NotFound(AgentId),
}

/// Looks up agents for the Admit stage.
///
/// Implementations must fail closed: if the backing store can't be reached,
/// [`AgentRegistry::lookup`] returns `None`. The kernel then treats the agent
/// as unknown, which with `security.require_registered_agents` set means the
/// request is refused.
#[async_trait]
pub trait AgentRegistry: Send + Sync + fmt::Debug {
    /// The record for `agent_id`, or `None` if it isn't registered.
    async fn lookup(&self, agent_id: &AgentId) -> Option<AgentRecord>;

    /// Adds or replaces a record. Read-only registries keep the default,
    /// which refuses.
    async fn register(&self, record: AgentRecord) -> Result<(), RegistryError> {
        let _ = record;
        Err(RegistryError::ReadOnly(self.name().to_string()))
    }

    /// A short name identifying this registry in logs.
    fn name(&self) -> &str;
}

/// An [`AgentRegistry`] held in memory. The default.
#[derive(Debug, Default)]
pub struct InMemoryAgentRegistry {
    agents: RwLock<HashMap<AgentId, AgentRecord>>,
}

impl InMemoryAgentRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Suspends an agent. Takes effect on its next request.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NotFound`] if the agent isn't registered.
    pub async fn suspend(
        &self,
        agent_id: &AgentId,
        reason: impl Into<String>,
    ) -> Result<(), RegistryError> {
        self.set_status(
            agent_id,
            AgentStatus::Suspended {
                reason: reason.into(),
            },
        )
        .await
    }

    /// Reinstates a suspended agent.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError::NotFound`] if the agent isn't registered.
    pub async fn reinstate(&self, agent_id: &AgentId) -> Result<(), RegistryError> {
        self.set_status(agent_id, AgentStatus::Active).await
    }

    /// Removes an agent. Returns its record if it was registered.
    pub async fn remove(&self, agent_id: &AgentId) -> Option<AgentRecord> {
        self.agents.write().await.remove(agent_id)
    }

    /// Number of registered agents.
    pub async fn len(&self) -> usize {
        self.agents.read().await.len()
    }

    /// Whether no agents are registered.
    pub async fn is_empty(&self) -> bool {
        self.agents.read().await.is_empty()
    }

    async fn set_status(
        &self,
        agent_id: &AgentId,
        status: AgentStatus,
    ) -> Result<(), RegistryError> {
        let mut agents = self.agents.write().await;
        let record = agents
            .get_mut(agent_id)
            .ok_or(RegistryError::NotFound(*agent_id))?;
        record.status = status;
        Ok(())
    }
}

#[async_trait]
impl AgentRegistry for InMemoryAgentRegistry {
    async fn lookup(&self, agent_id: &AgentId) -> Option<AgentRecord> {
        self.agents.read().await.get(agent_id).cloned()
    }

    async fn register(&self, record: AgentRecord) -> Result<(), RegistryError> {
        self.agents.write().await.insert(record.id, record);
        Ok(())
    }

    fn name(&self) -> &str {
        "in-memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_only_narrows() {
        let id = AgentId::new();
        assert!(AgentRecord::new(id, "a").permits_tool("anything"));

        let narrowed = AgentRecord::new(id, "a").with_allowed_tools(["echo", "calculator"]);
        assert!(narrowed.permits_tool("echo"));
        assert!(!narrowed.permits_tool("system_info"));

        // Blocked wins over allowed.
        let both = narrowed.with_blocked_tools(["echo"]);
        assert!(!both.permits_tool("echo"));
        assert!(both.permits_tool("calculator"));
    }

    #[test]
    fn test_anonymous_assumes_nothing() {
        let record = AgentRecord::anonymous(AgentId::new());
        assert!(!record.internal);
        assert!(record.attributes.is_empty());
        assert_eq!(record.status, AgentStatus::Active);
    }

    #[tokio::test]
    async fn test_in_memory_registry_lifecycle() {
        let registry = InMemoryAgentRegistry::new();
        let id = AgentId::new();
        assert!(registry.lookup(&id).await.is_none());
        assert_eq!(
            registry.suspend(&id, "x").await,
            Err(RegistryError::NotFound(id))
        );

        registry
            .register(AgentRecord::new(id, "worker").internal(true))
            .await
            .unwrap();
        assert!(registry.lookup(&id).await.unwrap().internal);

        registry.suspend(&id, "compromised").await.unwrap();
        assert!(matches!(
            registry.lookup(&id).await.unwrap().status,
            AgentStatus::Suspended { ref reason } if reason == "compromised"
        ));

        registry.reinstate(&id).await.unwrap();
        assert_eq!(
            registry.lookup(&id).await.unwrap().status,
            AgentStatus::Active
        );

        assert!(registry.remove(&id).await.is_some());
        assert!(registry.is_empty().await);
    }

    #[derive(Debug)]
    struct ReadOnly;

    #[async_trait]
    impl AgentRegistry for ReadOnly {
        async fn lookup(&self, _agent_id: &AgentId) -> Option<AgentRecord> {
            None
        }

        fn name(&self) -> &str {
            "read-only"
        }
    }

    #[tokio::test]
    async fn test_registration_refused_by_default() {
        let result = ReadOnly
            .register(AgentRecord::anonymous(AgentId::new()))
            .await;
        assert_eq!(result, Err(RegistryError::ReadOnly("read-only".into())));
    }
}
