# Audit Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** provides cryptographic audit trails for all agent operations. This agent manages audit logging, OpenTelemetry tracing, query APIs, and compliance reporting.

## Task Description

Manage the VAK audit system including:
- Append-only audit logging
- OpenTelemetry distributed tracing
- GraphQL query API
- Flight recorder for debugging
- Compliance report generation
- Cost accounting

## Available Commands

```bash
# Test audit modules
cargo test --package vak --lib audit

# Run audit query examples
cargo run --example audit_query

# Export traces to Jaeger
OTEL_EXPORTER_JAEGER_ENDPOINT=http://localhost:14268/api/traces cargo run
```

## Files This Agent Can Modify

### Audit Implementation
- `src/audit/mod.rs` - Module root
- `src/audit/logger.rs` - Core audit logger
- `src/audit/otel.rs` - OpenTelemetry integration
- `src/audit/graphql.rs` - Query API
- `src/audit/flight_recorder.rs` - Debug recording
- `src/audit/compliance.rs` - Compliance reports

### Dashboard
- `src/dashboard/mod.rs` - Dashboard module
- `src/dashboard/cost_accounting.rs` - Cost tracking
- `src/dashboard/metrics.rs` - Prometheus metrics
- `src/dashboard/health.rs` - Health checks

## Audit Logger Implementation

### Core Logger
```rust
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AuditLogger {
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    chain_head: Arc<RwLock<ContentHash>>,
}

impl AuditLogger {
    pub async fn log(&self, entry: AuditEntry) -> Result<ContentHash, AuditError> {
        let mut entries = self.entries.write().await;
        let mut head = self.chain_head.write().await;
        
        // Link to previous entry
        let mut entry = entry;
        entry.previous_hash = *head;
        
        // Compute hash
        let hash = entry.compute_hash();
        entry.entry_hash = hash;
        
        // Store
        entries.push(entry);
        *head = hash;
        
        Ok(hash)
    }

    pub async fn verify_integrity(&self) -> Result<(), AuditError> {
        let entries = self.entries.read().await;
        let mut expected_prev = ContentHash::genesis();
        
        for entry in entries.iter() {
            if entry.previous_hash != expected_prev {
                return Err(AuditError::ChainBroken {
                    entry_id: entry.id.clone(),
                    expected: expected_prev,
                    actual: entry.previous_hash,
                });
            }
            let computed = entry.compute_hash();
            if computed != entry.entry_hash {
                return Err(AuditError::HashMismatch {
                    entry_id: entry.id.clone(),
                });
            }
            expected_prev = entry.entry_hash;
        }
        
        Ok(())
    }
}
```

### Audit Entry Structure
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: AgentId,
    pub session_id: SessionId,
    pub action: String,
    pub resource: String,
    pub decision: PolicyDecision,
    pub context: serde_json::Value,
    pub previous_hash: ContentHash,
    pub entry_hash: ContentHash,
}

impl AuditEntry {
    pub fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(&self.previous_hash.0);
        hasher.update(self.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.agent_id.as_bytes());
        hasher.update(self.action.as_bytes());
        hasher.update(self.resource.as_bytes());
        hasher.update(self.decision.as_bytes());
        ContentHash(hasher.finalize().into())
    }
}
```

### OpenTelemetry Integration
```rust
use tracing::{span, Level, Span};
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub struct VakTracer {
    provider: TracerProvider,
}

impl VakTracer {
    pub fn trace_tool_exec(&self, tool: &str, agent_id: &AgentId) -> Span {
        let span = span!(
            Level::INFO,
            "tool_execution",
            tool = %tool,
            agent_id = %agent_id,
            otel.kind = "INTERNAL"
        );
        span
    }

    pub fn trace_policy_eval(&self, action: &str, resource: &str) -> Span {
        span!(
            Level::INFO,
            "policy_evaluation",
            action = %action,
            resource = %resource,
            otel.kind = "INTERNAL"
        )
    }

    pub fn trace_inference(&self, model: &str, tokens: u32) -> Span {
        span!(
            Level::INFO,
            "llm_inference",
            model = %model,
            tokens = %tokens,
            otel.kind = "CLIENT"
        )
    }
}
```

### Query API
```rust
pub struct AuditQueryEngine {
    logger: Arc<AuditLogger>,
}

impl AuditQueryEngine {
    pub async fn query(&self, request: QueryRequest) -> Result<QueryResponse, QueryError> {
        let entries = self.logger.entries.read().await;
        
        let filtered: Vec<_> = entries
            .iter()
            .filter(|e| request.matches(e))
            .skip(request.offset)
            .take(request.limit)
            .cloned()
            .collect();
        
        let stats = AuditStats {
            total_entries: entries.len(),
            filtered_count: filtered.len(),
            unique_agents: entries.iter().map(|e| &e.agent_id).collect::<HashSet<_>>().len(),
        };
        
        Ok(QueryResponse {
            entries: filtered,
            stats,
            chain_valid: self.logger.verify_integrity().await.is_ok(),
        })
    }
}

#[derive(Debug, Deserialize)]
pub struct QueryRequest {
    pub agent_id: Option<AgentId>,
    pub session_id: Option<SessionId>,
    pub action: Option<String>,
    pub decision: Option<PolicyDecision>,
    pub from_time: Option<DateTime<Utc>>,
    pub to_time: Option<DateTime<Utc>>,
    pub offset: usize,
    pub limit: usize,
}
```

### Cost Accounting
```rust
pub struct CostAccountant {
    costs: Arc<RwLock<HashMap<AgentId, AgentCost>>>,
    pricing: PricingConfig,
}

#[derive(Default)]
pub struct AgentCost {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub wasm_fuel: u64,
    pub storage_bytes: u64,
    pub network_bytes: u64,
    pub api_calls: HashMap<String, u64>,
}

impl AgentCost {
    pub fn total_cost(&self, pricing: &PricingConfig) -> f64 {
        let token_cost = (self.input_tokens as f64 * pricing.input_token_rate)
            + (self.output_tokens as f64 * pricing.output_token_rate);
        let compute_cost = self.wasm_fuel as f64 * pricing.fuel_rate;
        let storage_cost = self.storage_bytes as f64 * pricing.storage_rate;
        let network_cost = self.network_bytes as f64 * pricing.network_rate;
        
        token_cost + compute_cost + storage_cost + network_cost
    }
}
```

## Guardrails

### DO
- Hash-chain all audit entries
- Include timestamps in UTC
- Log both successful and failed operations
- Include policy decision in every entry
- Support querying by multiple criteria
- Export metrics to Prometheus
- Implement log rotation

### DON'T
- Log secrets or PII without scrubbing
- Allow modification of historical entries
- Skip logging for "internal" operations
- Use mutable fields in logged entries
- Break the hash chain
- Log excessive detail that impacts performance

### Compliance Requirements
- All operations must be logged
- Logs must be tamper-evident
- Logs must be queryable for audit
- Retention policy must be configurable
- Access to logs must be controlled

## Testing Patterns

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_chain_integrity() {
        let logger = AuditLogger::new();
        
        for i in 0..100 {
            logger.log(create_entry(i)).await.unwrap();
        }
        
        assert!(logger.verify_integrity().await.is_ok());
    }

    #[tokio::test]
    async fn test_query_by_agent() {
        let logger = AuditLogger::new();
        let agent1 = AgentId::new("agent-1");
        let agent2 = AgentId::new("agent-2");
        
        logger.log(entry_for_agent(&agent1)).await.unwrap();
        logger.log(entry_for_agent(&agent2)).await.unwrap();
        logger.log(entry_for_agent(&agent1)).await.unwrap();
        
        let engine = AuditQueryEngine::new(Arc::new(logger));
        let response = engine.query(QueryRequest {
            agent_id: Some(agent1.clone()),
            ..Default::default()
        }).await.unwrap();
        
        assert_eq!(response.entries.len(), 2);
    }

    #[tokio::test]
    async fn test_cost_accounting() {
        let accountant = CostAccountant::new(PricingConfig::default());
        let agent = AgentId::new("agent-1");
        
        accountant.record_tokens(&agent, 1000, 500).await;
        accountant.record_fuel(&agent, 10000).await;
        
        let cost = accountant.get_cost(&agent).await.unwrap();
        assert!(cost.total_cost(&PricingConfig::default()) > 0.0);
    }
}
```

## Related Agents
- [Memory and Provenance Agent](Memory and Provenance Agent.agent.md)
- [Policy Engine Agent](Policy Engine Agent.agent.md)
- [Rust Code Generator Agent](Rust Code Generator Agent.agent.md)