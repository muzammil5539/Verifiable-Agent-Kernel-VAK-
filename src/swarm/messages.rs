//! Inter-Agent Message Types
//!
//! This module defines the message types used for communication between
//! agents in the swarm. Messages are structured to support various
//! collaboration patterns and consensus mechanisms.
//!
//! # Message Types
//!
//! - **Proposal**: A suggestion or plan from an agent
//! - **Critique**: Feedback or criticism of a proposal
//! - **Agreement**: Expression of support
//! - **Disagreement**: Expression of opposition
//! - **Evidence**: Supporting data or facts
//!
//! # Example
//!
//! ```rust
//! use vak::swarm::messages::{SwarmMessage, MessageType, Proposal, Critique};
//!
//! // Create a proposal
//! let proposal = Proposal::new("Refactor the authentication module");
//!
//! // Create a critique
//! let critique = Critique::new("Consider backward compatibility");
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use super::SwarmAgentId;

// ============================================================================
// Message ID
// ============================================================================

/// Unique identifier for a message
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MessageId(pub Uuid);

impl MessageId {
    /// Create a new unique message ID
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Create from an existing UUID
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MessageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Msg({})", self.0)
    }
}

// ============================================================================
// Message Priority
// ============================================================================

/// Priority level of a message
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MessagePriority {
    /// Low priority, can be processed later
    Low = 0,
    /// Normal priority
    Normal = 1,
    /// High priority, process soon
    High = 2,
    /// Urgent, process immediately
    Urgent = 3,
    /// Critical, may affect safety
    Critical = 4,
}

impl Default for MessagePriority {
    fn default() -> Self {
        MessagePriority::Normal
    }
}

// ============================================================================
// Message Type
// ============================================================================

/// Types of messages that can be sent between agents
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// A proposal or suggestion
    Proposal,
    /// Critique or feedback on a proposal
    Critique,
    /// Agreement with a proposal or position
    Agreement,
    /// Disagreement with a proposal or position
    Disagreement,
    /// Evidence or supporting data
    Evidence,
    /// A query or question
    Query,
    /// A response to a query
    Response,
    /// Status update
    Status,
    /// Request for action
    Request,
    /// Acknowledgment of receipt
    Ack,
    /// Error or failure notification
    Error,
    /// Heartbeat for liveness detection
    Heartbeat,
    /// Custom message type
    Custom(String),
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Proposal => write!(f, "Proposal"),
            MessageType::Critique => write!(f, "Critique"),
            MessageType::Agreement => write!(f, "Agreement"),
            MessageType::Disagreement => write!(f, "Disagreement"),
            MessageType::Evidence => write!(f, "Evidence"),
            MessageType::Query => write!(f, "Query"),
            MessageType::Response => write!(f, "Response"),
            MessageType::Status => write!(f, "Status"),
            MessageType::Request => write!(f, "Request"),
            MessageType::Ack => write!(f, "Ack"),
            MessageType::Error => write!(f, "Error"),
            MessageType::Heartbeat => write!(f, "Heartbeat"),
            MessageType::Custom(name) => write!(f, "Custom({})", name),
        }
    }
}

// ============================================================================
// Swarm Message
// ============================================================================

/// A message sent between agents in the swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmMessage {
    /// Unique message ID
    pub id: MessageId,
    /// Sender agent ID
    pub sender: SwarmAgentId,
    /// Recipient agent ID (None for broadcast)
    pub recipient: Option<SwarmAgentId>,
    /// Type of message
    pub message_type: MessageType,
    /// Message content
    pub content: MessageContent,
    /// Priority level
    pub priority: MessagePriority,
    /// Reference to parent message (for replies)
    pub in_reply_to: Option<MessageId>,
    /// Timestamp when message was created
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Time-to-live in seconds (0 = no expiry)
    pub ttl: u64,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

impl SwarmMessage {
    /// Create a new message
    pub fn new(
        sender: SwarmAgentId,
        message_type: MessageType,
        content: MessageContent,
    ) -> Self {
        Self {
            id: MessageId::new(),
            sender,
            recipient: None,
            message_type,
            content,
            priority: MessagePriority::Normal,
            in_reply_to: None,
            timestamp: chrono::Utc::now(),
            ttl: 0,
            metadata: HashMap::new(),
        }
    }

    /// Set the recipient
    pub fn to(mut self, recipient: SwarmAgentId) -> Self {
        self.recipient = Some(recipient);
        self
    }

    /// Set as a reply to another message
    pub fn reply_to(mut self, message_id: MessageId) -> Self {
        self.in_reply_to = Some(message_id);
        self
    }

    /// Set the priority
    pub fn with_priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set the TTL
    pub fn with_ttl(mut self, ttl_seconds: u64) -> Self {
        self.ttl = ttl_seconds;
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Check if message has expired
    pub fn is_expired(&self) -> bool {
        if self.ttl == 0 {
            return false;
        }
        let age = chrono::Utc::now()
            .signed_duration_since(self.timestamp)
            .num_seconds();
        age as u64 > self.ttl
    }

    /// Check if this is a broadcast message
    pub fn is_broadcast(&self) -> bool {
        self.recipient.is_none()
    }

    /// Check if this is a reply
    pub fn is_reply(&self) -> bool {
        self.in_reply_to.is_some()
    }
}

// ============================================================================
// Message Content
// ============================================================================

/// Content of a swarm message
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MessageContent {
    /// A proposal
    Proposal(Proposal),
    /// A critique
    Critique(Critique),
    /// An agreement
    Agreement(Agreement),
    /// A disagreement
    Disagreement(Disagreement),
    /// Evidence
    Evidence(Evidence),
    /// Text content
    Text(String),
    /// JSON data
    Json(serde_json::Value),
    /// Binary data (base64 encoded)
    Binary(String),
}

// ============================================================================
// Proposal
// ============================================================================

/// A proposal or suggestion from an agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Title of the proposal
    pub title: String,
    /// Detailed description
    pub description: Option<String>,
    /// Action items or steps
    pub actions: Vec<String>,
    /// Expected outcomes
    pub expected_outcomes: Vec<String>,
    /// Risks or concerns
    pub risks: Vec<String>,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
    /// Supporting evidence IDs
    pub evidence_ids: Vec<MessageId>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

impl Proposal {
    /// Create a new proposal
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            description: None,
            actions: Vec::new(),
            expected_outcomes: Vec::new(),
            risks: Vec::new(),
            confidence: 0.5,
            evidence_ids: Vec::new(),
            tags: Vec::new(),
        }
    }

    /// Add a description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add an action item
    pub fn with_action(mut self, action: impl Into<String>) -> Self {
        self.actions.push(action.into());
        self
    }

    /// Add multiple actions
    pub fn with_actions(mut self, actions: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.actions.extend(actions.into_iter().map(Into::into));
        self
    }

    /// Add an expected outcome
    pub fn with_outcome(mut self, outcome: impl Into<String>) -> Self {
        self.expected_outcomes.push(outcome.into());
        self
    }

    /// Add a risk
    pub fn with_risk(mut self, risk: impl Into<String>) -> Self {
        self.risks.push(risk.into());
        self
    }

    /// Set the confidence level
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Link supporting evidence
    pub fn with_evidence(mut self, evidence_id: MessageId) -> Self {
        self.evidence_ids.push(evidence_id);
        self
    }
}

// ============================================================================
// Critique
// ============================================================================

/// Feedback or criticism of a proposal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Critique {
    /// Main feedback point
    pub feedback: String,
    /// Severity of the critique (0.0 = minor, 1.0 = critical)
    pub severity: f64,
    /// Specific issues identified
    pub issues: Vec<CritiqueIssue>,
    /// Suggestions for improvement
    pub suggestions: Vec<String>,
    /// Reference to the proposal being critiqued
    pub proposal_id: Option<MessageId>,
    /// Overall assessment (positive/negative/neutral)
    pub assessment: Assessment,
}

/// An individual issue in a critique
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CritiqueIssue {
    /// Issue description
    pub description: String,
    /// Category of issue
    pub category: IssueCategory,
    /// How critical is this issue
    pub severity: f64,
    /// Suggested fix
    pub suggested_fix: Option<String>,
}

/// Categories of issues
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IssueCategory {
    /// Logical flaw
    Logic,
    /// Missing information
    Incomplete,
    /// Factual error
    Factual,
    /// Safety concern
    Safety,
    /// Performance issue
    Performance,
    /// Scalability concern
    Scalability,
    /// Security vulnerability
    Security,
    /// Maintainability issue
    Maintainability,
    /// Other
    Other(String),
}

/// Overall assessment of a critique
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Assessment {
    /// Strongly supportive
    StronglyPositive,
    /// Generally supportive
    Positive,
    /// Neutral or mixed
    Neutral,
    /// Generally opposed
    Negative,
    /// Strongly opposed
    StronglyNegative,
}

impl Critique {
    /// Create a new critique
    pub fn new(feedback: impl Into<String>) -> Self {
        Self {
            feedback: feedback.into(),
            severity: 0.5,
            issues: Vec::new(),
            suggestions: Vec::new(),
            proposal_id: None,
            assessment: Assessment::Neutral,
        }
    }

    /// Set the severity
    pub fn with_severity(mut self, severity: f64) -> Self {
        self.severity = severity.clamp(0.0, 1.0);
        self
    }

    /// Add an issue
    pub fn with_issue(mut self, issue: CritiqueIssue) -> Self {
        self.issues.push(issue);
        self
    }

    /// Add a suggestion
    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    /// Reference a proposal
    pub fn for_proposal(mut self, proposal_id: MessageId) -> Self {
        self.proposal_id = Some(proposal_id);
        self
    }

    /// Set the assessment
    pub fn with_assessment(mut self, assessment: Assessment) -> Self {
        self.assessment = assessment;
        self
    }
}

impl CritiqueIssue {
    /// Create a new issue
    pub fn new(description: impl Into<String>, category: IssueCategory) -> Self {
        Self {
            description: description.into(),
            category,
            severity: 0.5,
            suggested_fix: None,
        }
    }

    /// Set the severity
    pub fn with_severity(mut self, severity: f64) -> Self {
        self.severity = severity.clamp(0.0, 1.0);
        self
    }

    /// Add a suggested fix
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.suggested_fix = Some(fix.into());
        self
    }
}

// ============================================================================
// Agreement
// ============================================================================

/// Expression of support for a proposal or position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agreement {
    /// The position being agreed with
    pub target_id: MessageId,
    /// Strength of agreement (0.0 to 1.0)
    pub strength: f64,
    /// Reasoning for agreement
    pub reasoning: Option<String>,
    /// Conditions or caveats
    pub conditions: Vec<String>,
}

impl Agreement {
    /// Create a new agreement
    pub fn new(target_id: MessageId) -> Self {
        Self {
            target_id,
            strength: 1.0,
            reasoning: None,
            conditions: Vec::new(),
        }
    }

    /// Set the strength
    pub fn with_strength(mut self, strength: f64) -> Self {
        self.strength = strength.clamp(0.0, 1.0);
        self
    }

    /// Add reasoning
    pub fn with_reasoning(mut self, reasoning: impl Into<String>) -> Self {
        self.reasoning = Some(reasoning.into());
        self
    }

    /// Add a condition
    pub fn with_condition(mut self, condition: impl Into<String>) -> Self {
        self.conditions.push(condition.into());
        self
    }
}

// ============================================================================
// Disagreement
// ============================================================================

/// Expression of opposition to a proposal or position
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Disagreement {
    /// The position being disagreed with
    pub target_id: MessageId,
    /// Strength of disagreement (0.0 to 1.0)
    pub strength: f64,
    /// Reasoning for disagreement
    pub reasoning: String,
    /// Alternative proposal (if any)
    pub alternative: Option<String>,
    /// Specific points of contention
    pub contentions: Vec<String>,
}

impl Disagreement {
    /// Create a new disagreement
    pub fn new(target_id: MessageId, reasoning: impl Into<String>) -> Self {
        Self {
            target_id,
            strength: 1.0,
            reasoning: reasoning.into(),
            alternative: None,
            contentions: Vec::new(),
        }
    }

    /// Set the strength
    pub fn with_strength(mut self, strength: f64) -> Self {
        self.strength = strength.clamp(0.0, 1.0);
        self
    }

    /// Propose an alternative
    pub fn with_alternative(mut self, alternative: impl Into<String>) -> Self {
        self.alternative = Some(alternative.into());
        self
    }

    /// Add a point of contention
    pub fn with_contention(mut self, contention: impl Into<String>) -> Self {
        self.contentions.push(contention.into());
        self
    }
}

// ============================================================================
// Evidence
// ============================================================================

/// Supporting evidence or data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    /// Title of the evidence
    pub title: String,
    /// Type of evidence
    pub evidence_type: EvidenceType,
    /// The actual evidence data
    pub data: EvidenceData,
    /// Source of the evidence
    pub source: Option<String>,
    /// Confidence in the evidence (0.0 to 1.0)
    pub confidence: f64,
    /// Related proposals this evidence supports
    pub supports: Vec<MessageId>,
    /// Related proposals this evidence refutes
    pub refutes: Vec<MessageId>,
}

/// Types of evidence
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Factual data
    Fact,
    /// Statistical data
    Statistic,
    /// Example or case study
    Example,
    /// Expert opinion
    ExpertOpinion,
    /// Experimental result
    Experiment,
    /// Reference to external source
    Reference,
    /// Logical argument
    Argument,
    /// Other
    Other(String),
}

/// The actual evidence data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvidenceData {
    /// Text evidence
    Text(String),
    /// Numeric value
    Numeric(f64),
    /// URL/link to source
    Url(String),
    /// Structured data
    Structured(serde_json::Value),
    /// Code snippet
    Code { language: String, content: String },
}

impl Evidence {
    /// Create new text evidence
    pub fn text(title: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            evidence_type: EvidenceType::Fact,
            data: EvidenceData::Text(content.into()),
            source: None,
            confidence: 0.8,
            supports: Vec::new(),
            refutes: Vec::new(),
        }
    }

    /// Create new numeric evidence
    pub fn numeric(title: impl Into<String>, value: f64) -> Self {
        Self {
            title: title.into(),
            evidence_type: EvidenceType::Statistic,
            data: EvidenceData::Numeric(value),
            source: None,
            confidence: 0.8,
            supports: Vec::new(),
            refutes: Vec::new(),
        }
    }

    /// Create new reference evidence
    pub fn reference(title: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            evidence_type: EvidenceType::Reference,
            data: EvidenceData::Url(url.into()),
            source: None,
            confidence: 0.8,
            supports: Vec::new(),
            refutes: Vec::new(),
        }
    }

    /// Set the evidence type
    pub fn with_type(mut self, evidence_type: EvidenceType) -> Self {
        self.evidence_type = evidence_type;
        self
    }

    /// Set the source
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Set the confidence
    pub fn with_confidence(mut self, confidence: f64) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Mark as supporting a proposal
    pub fn supports_proposal(mut self, proposal_id: MessageId) -> Self {
        self.supports.push(proposal_id);
        self
    }

    /// Mark as refuting a proposal
    pub fn refutes_proposal(mut self, proposal_id: MessageId) -> Self {
        self.refutes.push(proposal_id);
        self
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id() {
        let id1 = MessageId::new();
        let id2 = MessageId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_message_priority_ordering() {
        assert!(MessagePriority::Critical > MessagePriority::Urgent);
        assert!(MessagePriority::Urgent > MessagePriority::High);
        assert!(MessagePriority::High > MessagePriority::Normal);
        assert!(MessagePriority::Normal > MessagePriority::Low);
    }

    #[test]
    fn test_proposal_creation() {
        let proposal = Proposal::new("Test Proposal")
            .with_description("A test proposal")
            .with_action("Step 1")
            .with_action("Step 2")
            .with_outcome("Expected result")
            .with_risk("Potential risk")
            .with_confidence(0.9)
            .with_tag("test");

        assert_eq!(proposal.title, "Test Proposal");
        assert!(proposal.description.is_some());
        assert_eq!(proposal.actions.len(), 2);
        assert_eq!(proposal.expected_outcomes.len(), 1);
        assert_eq!(proposal.risks.len(), 1);
        assert!((proposal.confidence - 0.9).abs() < 0.001);
        assert_eq!(proposal.tags.len(), 1);
    }

    #[test]
    fn test_critique_creation() {
        let issue = CritiqueIssue::new("Missing validation", IssueCategory::Logic)
            .with_severity(0.8)
            .with_fix("Add input validation");

        let critique = Critique::new("Needs improvement")
            .with_severity(0.7)
            .with_issue(issue)
            .with_suggestion("Consider edge cases")
            .with_assessment(Assessment::Negative);

        assert_eq!(critique.feedback, "Needs improvement");
        assert!((critique.severity - 0.7).abs() < 0.001);
        assert_eq!(critique.issues.len(), 1);
        assert_eq!(critique.suggestions.len(), 1);
        assert_eq!(critique.assessment, Assessment::Negative);
    }

    #[test]
    fn test_agreement_creation() {
        let target_id = MessageId::new();
        let agreement = Agreement::new(target_id.clone())
            .with_strength(0.8)
            .with_reasoning("Good approach")
            .with_condition("If budget allows");

        assert_eq!(agreement.target_id, target_id);
        assert!((agreement.strength - 0.8).abs() < 0.001);
        assert!(agreement.reasoning.is_some());
        assert_eq!(agreement.conditions.len(), 1);
    }

    #[test]
    fn test_disagreement_creation() {
        let target_id = MessageId::new();
        let disagreement = Disagreement::new(target_id.clone(), "Flawed logic")
            .with_strength(0.9)
            .with_alternative("Better approach")
            .with_contention("Point 1");

        assert_eq!(disagreement.target_id, target_id);
        assert_eq!(disagreement.reasoning, "Flawed logic");
        assert!(disagreement.alternative.is_some());
        assert_eq!(disagreement.contentions.len(), 1);
    }

    #[test]
    fn test_evidence_creation() {
        let text_evidence = Evidence::text("Finding", "Important discovery")
            .with_source("Research paper")
            .with_confidence(0.95);

        assert_eq!(text_evidence.title, "Finding");
        assert!(text_evidence.source.is_some());
        assert!((text_evidence.confidence - 0.95).abs() < 0.001);

        let numeric_evidence = Evidence::numeric("Metric", 42.0)
            .with_type(EvidenceType::Statistic);

        assert!(matches!(numeric_evidence.data, EvidenceData::Numeric(42.0)));

        let reference = Evidence::reference("Paper", "https://example.com/paper.pdf");
        assert!(matches!(reference.data, EvidenceData::Url(_)));
    }

    #[test]
    fn test_swarm_message_creation() {
        let sender = SwarmAgentId::new();
        let proposal = Proposal::new("Test");
        
        let message = SwarmMessage::new(
            sender.clone(),
            MessageType::Proposal,
            MessageContent::Proposal(proposal),
        );

        assert_eq!(message.sender, sender);
        assert!(message.is_broadcast()); // No recipient
        assert!(!message.is_reply());
        assert!(!message.is_expired());
    }

    #[test]
    fn test_swarm_message_with_recipient() {
        let sender = SwarmAgentId::new();
        let recipient = SwarmAgentId::new();
        
        let message = SwarmMessage::new(
            sender,
            MessageType::Query,
            MessageContent::Text("Hello".to_string()),
        )
        .to(recipient.clone())
        .with_priority(MessagePriority::High)
        .with_ttl(60);

        assert!(!message.is_broadcast());
        assert_eq!(message.recipient, Some(recipient));
        assert_eq!(message.priority, MessagePriority::High);
        assert_eq!(message.ttl, 60);
    }

    #[test]
    fn test_swarm_message_reply() {
        let sender = SwarmAgentId::new();
        let original_id = MessageId::new();
        
        let reply = SwarmMessage::new(
            sender,
            MessageType::Response,
            MessageContent::Text("Response".to_string()),
        )
        .reply_to(original_id.clone());

        assert!(reply.is_reply());
        assert_eq!(reply.in_reply_to, Some(original_id));
    }

    #[test]
    fn test_critique_issue_categories() {
        let logic_issue = CritiqueIssue::new("Flaw", IssueCategory::Logic);
        assert_eq!(logic_issue.category, IssueCategory::Logic);

        let custom_issue = CritiqueIssue::new("Custom", IssueCategory::Other("Custom".to_string()));
        assert!(matches!(custom_issue.category, IssueCategory::Other(_)));
    }

    #[test]
    fn test_assessment_variants() {
        let assessments = vec![
            Assessment::StronglyPositive,
            Assessment::Positive,
            Assessment::Neutral,
            Assessment::Negative,
            Assessment::StronglyNegative,
        ];

        for assessment in assessments {
            let critique = Critique::new("Test").with_assessment(assessment.clone());
            assert_eq!(critique.assessment, assessment);
        }
    }
}
