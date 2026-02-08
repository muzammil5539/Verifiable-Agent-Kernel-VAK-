//! Swarm Message Types
//!
//! Defines message types for communication between swarm agents.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

use super::SwarmAgentId;

/// A message in the swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmMessage {
    /// Unique message ID
    pub id: String,
    /// Sender agent ID
    pub from: SwarmAgentId,
    /// Optional recipient (None = broadcast)
    pub to: Option<SwarmAgentId>,
    /// Message type
    pub message_type: SwarmMessageType,
    /// Message payload
    pub payload: serde_json::Value,
    /// Timestamp
    pub timestamp: SystemTime,
}

/// Types of swarm messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SwarmMessageType {
    /// Task assignment
    TaskAssignment,
    /// Task completion
    TaskComplete,
    /// Voting request
    VoteRequest,
    /// Vote cast
    VoteCast,
    /// Consensus reached
    ConsensusReached,
    /// Heartbeat
    Heartbeat,
    /// Error notification
    Error,
    /// Custom message
    Custom(String),
}

impl SwarmMessage {
    /// Create a new broadcast message
    pub fn broadcast(
        from: SwarmAgentId,
        message_type: SwarmMessageType,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            from,
            to: None,
            message_type,
            payload,
            timestamp: SystemTime::now(),
        }
    }

    /// Create a directed message
    pub fn directed(
        from: SwarmAgentId,
        to: SwarmAgentId,
        message_type: SwarmMessageType,
        payload: serde_json::Value,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            from,
            to: Some(to),
            message_type,
            payload,
            timestamp: SystemTime::now(),
        }
    }
}
