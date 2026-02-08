//! Agent-to-Agent (A2A) Protocol Support (SWM-001)
//!
//! Implements standard A2A protocol for inter-agent communication,
//! including AgentCard discovery, message routing, and capability exchange.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, Error)]
pub enum A2AError {
    #[error("Agent not found: {0}")]
    AgentNotFound(String),
    #[error("Message delivery failed: {0}")]
    DeliveryFailed(String),
    #[error("Protocol error: {0}")]
    ProtocolError(String),
    #[error("Capability not supported: {0}")]
    CapabilityNotSupported(String),
    #[error("Operation timed out")]
    Timeout,
}

pub type A2AResult<T> = Result<T, A2AError>;

// ============================================================================
// Agent Card
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub capabilities: Vec<A2ACapability>,
    pub endpoint: Option<String>,
    pub public_key: Option<String>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: SystemTime,
    pub updated_at: SystemTime,
}

impl AgentCard {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let now = SystemTime::now();
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            version: "1.0.0".to_string(),
            capabilities: Vec::new(),
            endpoint: None,
            public_key: None,
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    pub fn with_capability(mut self, capability: A2ACapability) -> Self {
        self.capabilities.push(capability);
        self
    }

    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    pub fn has_capability(&self, capability_type: &str) -> bool {
        self.capabilities
            .iter()
            .any(|c| c.capability_type == capability_type)
    }
}

// ============================================================================
// Capability
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2ACapability {
    pub capability_type: String,
    pub version: String,
    pub description: String,
    pub input_schema: Option<serde_json::Value>,
    pub output_schema: Option<serde_json::Value>,
    pub enabled: bool,
}

impl A2ACapability {
    pub fn new(capability_type: impl Into<String>) -> Self {
        Self {
            capability_type: capability_type.into(),
            version: "1.0.0".to_string(),
            description: String::new(),
            input_schema: None,
            output_schema: None,
            enabled: true,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }
}

// ============================================================================
// Message Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum A2AMessageType {
    Query,
    Response,
    Proposal,
    Vote,
    Consensus,
    Heartbeat,
    Error,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2AMessage {
    pub id: String,
    pub message_type: A2AMessageType,
    pub from: String,
    pub to: String,
    pub payload: serde_json::Value,
    pub correlation_id: Option<String>,
    pub timestamp: SystemTime,
    pub signature: Option<String>,
    pub protocol_version: String,
}

impl A2AMessage {
    pub fn new(
        message_type: A2AMessageType,
        from: impl Into<String>,
        to: impl Into<String>,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::now_v7().to_string(),
            message_type,
            from: from.into(),
            to: to.into(),
            payload,
            correlation_id: None,
            timestamp: SystemTime::now(),
            signature: None,
            protocol_version: "1.0".to_string(),
        }
    }

    pub fn query(from: impl Into<String>, to: impl Into<String>, query: serde_json::Value) -> Self {
        Self::new(A2AMessageType::Query, from, to, query)
    }

    pub fn response(
        from: impl Into<String>,
        to: impl Into<String>,
        response: serde_json::Value,
        correlation_id: impl Into<String>,
    ) -> Self {
        let mut msg = Self::new(A2AMessageType::Response, from, to, response);
        msg.correlation_id = Some(correlation_id.into());
        msg
    }

    pub fn heartbeat(from: impl Into<String>, to: impl Into<String>) -> Self {
        Self::new(A2AMessageType::Heartbeat, from, to, serde_json::json!({}))
    }
}

// ============================================================================
// Discovery Service
// ============================================================================

pub struct DiscoveryService {
    agents: RwLock<HashMap<String, AgentCard>>,
    last_seen: RwLock<HashMap<String, SystemTime>>,
    heartbeat_timeout: Duration,
}

impl DiscoveryService {
    pub fn new() -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            last_seen: RwLock::new(HashMap::new()),
            heartbeat_timeout: Duration::from_secs(60),
        }
    }

    pub async fn register(&self, card: AgentCard) -> A2AResult<()> {
        let id = card.id.clone();
        let mut agents = self.agents.write().await;
        let mut last_seen = self.last_seen.write().await;
        agents.insert(id.clone(), card);
        last_seen.insert(id.clone(), SystemTime::now());
        info!(agent_id = %id, "Agent registered");
        Ok(())
    }

    pub async fn unregister(&self, agent_id: &str) -> A2AResult<()> {
        let mut agents = self.agents.write().await;
        let mut last_seen = self.last_seen.write().await;
        agents.remove(agent_id);
        last_seen.remove(agent_id);
        info!(agent_id = %agent_id, "Agent unregistered");
        Ok(())
    }

    pub async fn get_agent(&self, agent_id: &str) -> Option<AgentCard> {
        let agents = self.agents.read().await;
        agents.get(agent_id).cloned()
    }

    pub async fn list_agents(&self) -> Vec<AgentCard> {
        let agents = self.agents.read().await;
        agents.values().cloned().collect()
    }

    pub async fn find_by_capability(&self, capability_type: &str) -> Vec<AgentCard> {
        let agents = self.agents.read().await;
        agents
            .values()
            .filter(|a| a.has_capability(capability_type))
            .cloned()
            .collect()
    }

    pub async fn heartbeat(&self, agent_id: &str) -> A2AResult<()> {
        let mut last_seen = self.last_seen.write().await;
        if last_seen.contains_key(agent_id) {
            last_seen.insert(agent_id.to_string(), SystemTime::now());
            Ok(())
        } else {
            Err(A2AError::AgentNotFound(agent_id.to_string()))
        }
    }

    pub async fn is_alive(&self, agent_id: &str) -> bool {
        let last_seen = self.last_seen.read().await;
        if let Some(time) = last_seen.get(agent_id) {
            time.elapsed()
                .map(|d| d < self.heartbeat_timeout)
                .unwrap_or(false)
        } else {
            false
        }
    }

    pub async fn prune_dead_agents(&self) -> Vec<String> {
        let mut agents = self.agents.write().await;
        let mut last_seen = self.last_seen.write().await;
        let mut pruned = Vec::new();

        let dead: Vec<_> = last_seen
            .iter()
            .filter(|(_, time)| {
                time.elapsed()
                    .map(|d| d >= self.heartbeat_timeout)
                    .unwrap_or(true)
            })
            .map(|(id, _)| id.clone())
            .collect();

        for id in dead {
            agents.remove(&id);
            last_seen.remove(&id);
            pruned.push(id);
        }

        if !pruned.is_empty() {
            warn!(count = pruned.len(), "Pruned dead agents");
        }
        pruned
    }
}

impl Default for DiscoveryService {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// A2A Protocol
// ============================================================================

pub struct A2AProtocol {
    discovery: Arc<DiscoveryService>,
    message_handlers: RwLock<HashMap<String, Vec<Box<dyn Fn(&A2AMessage) + Send + Sync>>>>,
    pending_responses: RwLock<HashMap<String, tokio::sync::oneshot::Sender<A2AMessage>>>,
}

impl A2AProtocol {
    pub fn new() -> Self {
        Self {
            discovery: Arc::new(DiscoveryService::new()),
            message_handlers: RwLock::new(HashMap::new()),
            pending_responses: RwLock::new(HashMap::new()),
        }
    }

    pub fn discovery(&self) -> &Arc<DiscoveryService> {
        &self.discovery
    }

    pub async fn send(&self, message: A2AMessage) -> A2AResult<()> {
        let agents = self.discovery.agents.read().await;
        if !agents.contains_key(&message.to) {
            return Err(A2AError::AgentNotFound(message.to.clone()));
        }

        let handlers = self.message_handlers.read().await;
        if let Some(agent_handlers) = handlers.get(&message.to) {
            for handler in agent_handlers {
                handler(&message);
            }
        }

        debug!(from = %message.from, to = %message.to, "Message sent");
        Ok(())
    }

    pub async fn send_and_wait(
        &self,
        message: A2AMessage,
        timeout: Duration,
    ) -> A2AResult<A2AMessage> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let msg_id = message.id.clone();

        {
            let mut pending = self.pending_responses.write().await;
            pending.insert(msg_id.clone(), tx);
        }

        self.send(message).await?;

        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(_)) => Err(A2AError::DeliveryFailed("Channel closed".to_string())),
            Err(_) => {
                let mut pending = self.pending_responses.write().await;
                pending.remove(&msg_id);
                Err(A2AError::Timeout)
            }
        }
    }

    pub async fn handle_response(&self, response: A2AMessage) {
        if let Some(correlation_id) = &response.correlation_id {
            let mut pending = self.pending_responses.write().await;
            if let Some(tx) = pending.remove(correlation_id) {
                let _ = tx.send(response);
            }
        }
    }
}

impl Default for A2AProtocol {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_card_creation() {
        let card = AgentCard::new("agent-1", "Test Agent")
            .with_description("A test agent")
            .with_capability(A2ACapability::new("reasoning"));

        assert_eq!(card.id, "agent-1");
        assert!(card.has_capability("reasoning"));
        assert!(!card.has_capability("coding"));
    }

    #[test]
    fn test_message_creation() {
        let msg = A2AMessage::query("agent-1", "agent-2", serde_json::json!({"query": "test"}));
        assert!(matches!(msg.message_type, A2AMessageType::Query));
        assert_eq!(msg.from, "agent-1");
        assert_eq!(msg.to, "agent-2");
    }

    #[tokio::test]
    async fn test_discovery_service() {
        let service = DiscoveryService::new();
        let card = AgentCard::new("agent-1", "Test Agent");

        service.register(card).await.unwrap();

        assert!(service.get_agent("agent-1").await.is_some());
        assert!(service.get_agent("nonexistent").await.is_none());

        service.unregister("agent-1").await.unwrap();
        assert!(service.get_agent("agent-1").await.is_none());
    }

    #[tokio::test]
    async fn test_find_by_capability() {
        let service = DiscoveryService::new();

        let card1 =
            AgentCard::new("agent-1", "Agent 1").with_capability(A2ACapability::new("reasoning"));
        let card2 =
            AgentCard::new("agent-2", "Agent 2").with_capability(A2ACapability::new("coding"));

        service.register(card1).await.unwrap();
        service.register(card2).await.unwrap();

        let reasoning_agents = service.find_by_capability("reasoning").await;
        assert_eq!(reasoning_agents.len(), 1);
        assert_eq!(reasoning_agents[0].id, "agent-1");
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let service = DiscoveryService::new();
        let card = AgentCard::new("agent-1", "Test Agent");

        service.register(card).await.unwrap();
        assert!(service.is_alive("agent-1").await);

        service.heartbeat("agent-1").await.unwrap();
        assert!(service.is_alive("agent-1").await);
    }

    #[tokio::test]
    async fn test_protocol_send() {
        let protocol = A2AProtocol::new();

        let card = AgentCard::new("agent-1", "Test Agent");
        protocol.discovery().register(card).await.unwrap();

        let msg = A2AMessage::heartbeat("agent-2", "agent-1");
        let result = protocol.send(msg).await;
        assert!(result.is_ok());
    }
}
