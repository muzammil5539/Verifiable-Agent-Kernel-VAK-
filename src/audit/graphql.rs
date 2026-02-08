//! Query API for Audit Logs (OBS-004)
//!
//! Provides a query API for rich querying capabilities over audit logs,
//! enabling forensic analysis and compliance reporting.
//!
//! # Overview
//!
//! The API enables:
//! - Flexible querying of audit logs
//! - Aggregations and analytics  
//! - Forensic filtering by agent, time range, action type
//!
//! # Example
//!
//! ```rust
//! use vak::audit::graphql::{AuditQueryEngine, QueryRequest};
//!
//! let engine = AuditQueryEngine::new();
//!
//! // Query logs
//! let request = QueryRequest::logs()
//!     .with_limit(10)
//!     .with_agent_filter("agent-1");
//!
//! let result = engine.query_logs(&request);
//! ```
//!
//! # References
//!
//! - OBS-004: GraphQL API for Audit Queries
//! - Gap Analysis Section 6.4: Forensic and Debugging Capabilities

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::info;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during query operations
#[derive(Debug, Error)]
pub enum QueryError {
    /// Invalid query
    #[error("Invalid query: {0}")]
    InvalidQuery(String),

    /// Query execution failed
    #[error("Query execution failed: {0}")]
    ExecutionFailed(String),

    /// Resource not found
    #[error("Resource not found: {0}")]
    NotFound(String),
}

/// Result type for query operations
pub type QueryResult<T> = Result<T, QueryError>;

// ============================================================================
// Data Types
// ============================================================================

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// Unique entry ID
    pub id: String,
    /// Agent ID that performed the action
    pub agent_id: String,
    /// Session ID
    pub session_id: String,
    /// Action performed
    pub action: String,
    /// Resource accessed
    pub resource: String,
    /// Decision made (allow/deny)
    pub decision: String,
    /// Timestamp (Unix epoch milliseconds)
    pub timestamp_ms: i64,
    /// Hash of this entry
    pub hash: String,
    /// Previous entry hash (for chain verification)
    pub prev_hash: Option<String>,
    /// Additional metadata
    pub metadata: Option<String>,
}

impl AuditLogEntry {
    /// Create a new audit log entry
    pub fn new(
        agent_id: impl Into<String>,
        session_id: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        decision: impl Into<String>,
    ) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let agent_id = agent_id.into();
        let session_id = session_id.into();
        let action = action.into();
        let resource = resource.into();
        let decision = decision.into();

        let mut hasher = Sha256::new();
        hasher.update(agent_id.as_bytes());
        hasher.update(session_id.as_bytes());
        hasher.update(action.as_bytes());
        hasher.update(resource.as_bytes());
        hasher.update(decision.as_bytes());
        hasher.update(timestamp_ms.to_le_bytes());
        let hash = hex::encode(hasher.finalize());

        let id = format!("audit-{}-{}", timestamp_ms, &hash[..8]);

        Self {
            id,
            agent_id,
            session_id,
            action,
            resource,
            decision,
            timestamp_ms,
            hash,
            prev_hash: None,
            metadata: None,
        }
    }
}

/// Policy decision result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionResult {
    /// Action was allowed
    Allow,
    /// Action was denied
    Deny,
    /// Decision was deferred
    Defer,
    /// Error during evaluation
    Error,
}

/// Policy decision entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecisionEntry {
    /// Decision ID
    pub id: String,
    /// Agent ID
    pub agent_id: String,
    /// Policy ID that matched
    pub policy_id: String,
    /// Action requested
    pub action: String,
    /// Resource requested
    pub resource: String,
    /// Decision result
    pub decision: PolicyDecisionResult,
    /// Reason for decision
    pub reason: Option<String>,
    /// Evaluation time in microseconds
    pub eval_time_us: i64,
    /// Timestamp
    pub timestamp_ms: i64,
}

/// Audit statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    /// Total number of entries
    pub total_entries: i64,
    /// Entries in the last hour
    pub entries_last_hour: i64,
    /// Entries in the last 24 hours
    pub entries_last_day: i64,
    /// Number of unique agents
    pub unique_agents: i64,
    /// Number of denied actions
    pub denied_count: i64,
    /// Number of allowed actions
    pub allowed_count: i64,
    /// Most recent entry timestamp
    pub latest_timestamp_ms: Option<i64>,
    /// Oldest entry timestamp
    pub oldest_timestamp_ms: Option<i64>,
}

/// Chain verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerificationResult {
    /// Whether the chain is valid
    pub valid: bool,
    /// Error message if invalid
    pub error: Option<String>,
    /// Number of entries verified
    pub entries_verified: i64,
    /// Index of first invalid entry (if any)
    pub first_invalid_index: Option<i64>,
}

// ============================================================================
// Query Types
// ============================================================================

/// Sort order for queries
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SortOrder {
    /// Ascending order
    Asc,
    /// Descending order (default)
    #[default]
    Desc,
}

/// Query request for audit logs
#[derive(Debug, Clone, Default)]
pub struct QueryRequest {
    /// Filter by agent ID
    pub agent_id: Option<String>,
    /// Filter by session ID
    pub session_id: Option<String>,
    /// Filter by action
    pub action: Option<String>,
    /// Filter by decision
    pub decision: Option<String>,
    /// Filter by time range start
    pub start_time_ms: Option<i64>,
    /// Filter by time range end
    pub end_time_ms: Option<i64>,
    /// Maximum number of results
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Sort order
    pub sort_order: SortOrder,
    /// Sort by field
    pub sort_by: Option<String>,
}

impl QueryRequest {
    /// Create a new query for logs
    pub fn logs() -> Self {
        Self::default()
    }

    /// Filter by agent ID
    pub fn with_agent_filter(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Filter by session ID
    pub fn with_session_filter(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Filter by action
    pub fn with_action_filter(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// Filter by decision
    pub fn with_decision_filter(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    /// Filter by time range
    pub fn with_time_range(mut self, start_ms: i64, end_ms: i64) -> Self {
        self.start_time_ms = Some(start_ms);
        self.end_time_ms = Some(end_ms);
        self
    }

    /// Set maximum results
    pub fn with_limit(mut self, limit: usize) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Set pagination offset
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Set sort order
    pub fn with_sort(mut self, field: impl Into<String>, order: SortOrder) -> Self {
        self.sort_by = Some(field.into());
        self.sort_order = order;
        self
    }
}

/// Query response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResponse<T> {
    /// Query results
    pub data: Vec<T>,
    /// Total count (before pagination)
    pub total_count: usize,
    /// Whether there are more results
    pub has_more: bool,
}

// ============================================================================
// Query Engine
// ============================================================================

/// Audit query engine
pub struct AuditQueryEngine {
    /// Audit log storage
    logs: Arc<RwLock<Vec<AuditLogEntry>>>,
    /// Policy decisions
    policy_decisions: Arc<RwLock<Vec<PolicyDecisionEntry>>>,
}

impl Default for AuditQueryEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditQueryEngine {
    /// Create a new query engine
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            policy_decisions: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Add an audit log entry
    pub fn add_log(&self, mut entry: AuditLogEntry) {
        let mut logs = self.logs.write().unwrap();
        if let Some(last) = logs.last() {
            entry.prev_hash = Some(last.hash.clone());
        }
        info!(entry_id = %entry.id, "Added audit log entry");
        logs.push(entry);
    }

    /// Add a policy decision
    pub fn add_policy_decision(&self, entry: PolicyDecisionEntry) {
        let mut decisions = self.policy_decisions.write().unwrap();
        decisions.push(entry);
    }

    /// Query audit logs
    pub fn query_logs(&self, request: &QueryRequest) -> QueryResponse<AuditLogEntry> {
        let logs = self.logs.read().unwrap();

        let filtered: Vec<AuditLogEntry> = logs
            .iter()
            .filter(|log| {
                if let Some(ref agent_id) = request.agent_id {
                    if &log.agent_id != agent_id {
                        return false;
                    }
                }
                if let Some(ref session_id) = request.session_id {
                    if &log.session_id != session_id {
                        return false;
                    }
                }
                if let Some(ref action) = request.action {
                    if &log.action != action {
                        return false;
                    }
                }
                if let Some(ref decision) = request.decision {
                    if &log.decision != decision {
                        return false;
                    }
                }
                if let Some(start) = request.start_time_ms {
                    if log.timestamp_ms < start {
                        return false;
                    }
                }
                if let Some(end) = request.end_time_ms {
                    if log.timestamp_ms > end {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        let total_count = filtered.len();

        let mut sorted = filtered;
        match request.sort_order {
            SortOrder::Asc => sorted.sort_by_key(|l| l.timestamp_ms),
            SortOrder::Desc => sorted.sort_by_key(|l| std::cmp::Reverse(l.timestamp_ms)),
        }

        let offset = request.offset.unwrap_or(0);
        let limit = request.limit.unwrap_or(50).min(1000);

        let data: Vec<_> = sorted.into_iter().skip(offset).take(limit).collect();
        let has_more = offset + data.len() < total_count;

        QueryResponse {
            data,
            total_count,
            has_more,
        }
    }

    /// Get audit statistics
    pub fn get_stats(&self) -> AuditStats {
        let logs = self.logs.read().unwrap();

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let hour_ago = now_ms - 3_600_000;
        let day_ago = now_ms - 86_400_000;

        let entries_last_hour = logs.iter().filter(|l| l.timestamp_ms >= hour_ago).count() as i64;
        let entries_last_day = logs.iter().filter(|l| l.timestamp_ms >= day_ago).count() as i64;

        let unique_agents: HashSet<_> = logs.iter().map(|l| &l.agent_id).collect();

        let denied_count = logs.iter().filter(|l| l.decision == "deny").count() as i64;
        let allowed_count = logs.iter().filter(|l| l.decision == "allow").count() as i64;

        let latest_timestamp_ms = logs.iter().map(|l| l.timestamp_ms).max();
        let oldest_timestamp_ms = logs.iter().map(|l| l.timestamp_ms).min();

        AuditStats {
            total_entries: logs.len() as i64,
            entries_last_hour,
            entries_last_day,
            unique_agents: unique_agents.len() as i64,
            denied_count,
            allowed_count,
            latest_timestamp_ms,
            oldest_timestamp_ms,
        }
    }

    /// Verify chain integrity
    pub fn verify_chain(&self) -> ChainVerificationResult {
        let logs = self.logs.read().unwrap();

        if logs.is_empty() {
            return ChainVerificationResult {
                valid: true,
                error: None,
                entries_verified: 0,
                first_invalid_index: None,
            };
        }

        let mut prev_hash: Option<String> = None;
        for (i, log) in logs.iter().enumerate() {
            if let Some(ref expected) = prev_hash {
                if log.prev_hash.as_ref() != Some(expected) {
                    return ChainVerificationResult {
                        valid: false,
                        error: Some(format!(
                            "Hash chain broken at index {}: expected {}, got {:?}",
                            i, expected, log.prev_hash
                        )),
                        entries_verified: i as i64,
                        first_invalid_index: Some(i as i64),
                    };
                }
            }
            prev_hash = Some(log.hash.clone());
        }

        ChainVerificationResult {
            valid: true,
            error: None,
            entries_verified: logs.len() as i64,
            first_invalid_index: None,
        }
    }

    /// Get unique agent IDs
    pub fn get_agents(&self) -> Vec<String> {
        let logs = self.logs.read().unwrap();
        let mut agents: Vec<String> = logs
            .iter()
            .map(|l| l.agent_id.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        agents.sort();
        agents
    }

    /// Get unique actions
    pub fn get_actions(&self) -> Vec<String> {
        let logs = self.logs.read().unwrap();
        let mut actions: Vec<String> = logs
            .iter()
            .map(|l| l.action.clone())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        actions.sort();
        actions
    }

    /// Clear all logs
    pub fn clear(&self) {
        let mut logs = self.logs.write().unwrap();
        let count = logs.len();
        logs.clear();
        info!(count, "Cleared audit logs");
    }

    /// Get log count
    pub fn log_count(&self) -> usize {
        self.logs.read().unwrap().len()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_engine() -> AuditQueryEngine {
        let engine = AuditQueryEngine::new();

        for i in 0..10 {
            let entry = AuditLogEntry::new(
                format!("agent-{}", i % 3),
                format!("session-{}", i % 2),
                if i % 2 == 0 { "read" } else { "write" },
                format!("/resource/{}", i),
                if i % 4 == 0 { "deny" } else { "allow" },
            );
            engine.add_log(entry);
        }

        engine
    }

    #[test]
    fn test_query_logs() {
        let engine = create_test_engine();
        let request = QueryRequest::logs().with_limit(5);
        let response = engine.query_logs(&request);

        assert_eq!(response.data.len(), 5);
        assert_eq!(response.total_count, 10);
        assert!(response.has_more);
    }

    #[test]
    fn test_filter_by_agent() {
        let engine = create_test_engine();
        let request = QueryRequest::logs().with_agent_filter("agent-0");
        let response = engine.query_logs(&request);

        for log in &response.data {
            assert_eq!(log.agent_id, "agent-0");
        }
    }

    #[test]
    fn test_filter_by_action() {
        let engine = create_test_engine();
        let request = QueryRequest::logs().with_action_filter("read");
        let response = engine.query_logs(&request);

        for log in &response.data {
            assert_eq!(log.action, "read");
        }
    }

    #[test]
    fn test_get_stats() {
        let engine = create_test_engine();
        let stats = engine.get_stats();

        assert_eq!(stats.total_entries, 10);
        assert_eq!(stats.unique_agents, 3);
    }

    #[test]
    fn test_verify_chain() {
        let engine = create_test_engine();
        let result = engine.verify_chain();

        assert!(result.valid);
        assert_eq!(result.entries_verified, 10);
    }

    #[test]
    fn test_get_agents() {
        let engine = create_test_engine();
        let agents = engine.get_agents();

        assert_eq!(agents.len(), 3);
        assert!(agents.contains(&"agent-0".to_string()));
        assert!(agents.contains(&"agent-1".to_string()));
        assert!(agents.contains(&"agent-2".to_string()));
    }

    #[test]
    fn test_get_actions() {
        let engine = create_test_engine();
        let actions = engine.get_actions();

        assert_eq!(actions.len(), 2);
        assert!(actions.contains(&"read".to_string()));
        assert!(actions.contains(&"write".to_string()));
    }

    #[test]
    fn test_clear() {
        let engine = create_test_engine();
        assert_eq!(engine.log_count(), 10);

        engine.clear();
        assert_eq!(engine.log_count(), 0);
    }

    #[test]
    fn test_pagination() {
        let engine = create_test_engine();

        let request = QueryRequest::logs().with_limit(3).with_offset(0);
        let page1 = engine.query_logs(&request);
        assert_eq!(page1.data.len(), 3);
        assert!(page1.has_more);

        let request = QueryRequest::logs().with_limit(3).with_offset(3);
        let page2 = engine.query_logs(&request);
        assert_eq!(page2.data.len(), 3);
        assert!(page2.has_more);

        let request = QueryRequest::logs().with_limit(3).with_offset(9);
        let page4 = engine.query_logs(&request);
        assert_eq!(page4.data.len(), 1);
        assert!(!page4.has_more);
    }
}
