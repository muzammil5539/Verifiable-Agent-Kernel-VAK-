//! Budgets: the Budget stage of the mediation pipeline.
//!
//! [`Kernel::execute`](super::Kernel::execute) charges every admitted request
//! to the agent's [`Budget`] before policy is consulted, so a flood of
//! requests is throttled before it costs policy evaluations, and an agent
//! probing the policy with denied requests is throttled too.
//!
//! `security.enable_rate_limiting` and `security.max_requests_per_minute`
//! were in [`KernelConfig`](super::KernelConfig) before this module existed,
//! but nothing enforced them (K5 in `docs/architecture-v2.md`).

use std::collections::HashMap;
use std::fmt;
use std::time::Instant;

use async_trait::async_trait;
use tokio::sync::Mutex;

use super::identity::AgentRecord;
use super::rate_limiter::TokenBucket;
use super::types::{AgentId, ToolRequest};

/// The answer to "may this agent spend one more request now?"
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetDecision {
    /// The request fits the budget, and has been charged to it.
    Within,
    /// The request does not fit. Nothing was charged.
    Exceeded {
        /// Which limit was hit.
        reason: String,
        /// How long until a request would fit.
        retry_after_ms: u64,
    },
}

/// Keeps per-agent budgets for the Budget stage.
///
/// [`Budget::charge`] both checks and spends: a `Within` answer means one unit
/// has been used. Implementations that can't reach their backing store must
/// answer `Exceeded`.
#[async_trait]
pub trait Budget: Send + Sync + fmt::Debug {
    /// Charges one request by `principal` to its budget.
    async fn charge(&self, principal: &AgentRecord, request: &ToolRequest) -> BudgetDecision;

    /// A short name identifying this budget in logs.
    fn name(&self) -> &str;
}

/// No limits. Used when `security.enable_rate_limiting` is off.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unlimited;

#[async_trait]
impl Budget for Unlimited {
    async fn charge(&self, _principal: &AgentRecord, _request: &ToolRequest) -> BudgetDecision {
        BudgetDecision::Within
    }

    fn name(&self) -> &str {
        "unlimited"
    }
}

/// Beyond this many tracked agents, buckets that have refilled completely
/// are dropped; a full bucket is indistinguishable from a new one.
const PRUNE_THRESHOLD: usize = 10_000;

/// A token bucket per agent: up to `per_minute` requests in a burst,
/// refilling at `per_minute / 60` per second. The default when
/// `security.enable_rate_limiting` is on.
///
/// The buckets live in this process, so the limit is per kernel instance.
/// A fleet of kernels sharing agents needs a shared counter behind the
/// [`Budget`] port instead.
pub struct AgentRateBudget {
    per_minute: u32,
    buckets: Mutex<HashMap<AgentId, TokenBucket>>,
}

impl fmt::Debug for AgentRateBudget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentRateBudget")
            .field("per_minute", &self.per_minute)
            .finish_non_exhaustive()
    }
}

impl AgentRateBudget {
    /// Allows each agent `per_minute` requests per minute. Zero allows none.
    #[must_use]
    pub fn per_minute(per_minute: u32) -> Self {
        Self {
            per_minute,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn new_bucket(&self) -> TokenBucket {
        let capacity = f64::from(self.per_minute);
        TokenBucket {
            tokens: capacity,
            max_tokens: capacity,
            refill_rate: capacity / 60.0,
            last_refill: Instant::now(),
        }
    }
}

#[async_trait]
impl Budget for AgentRateBudget {
    async fn charge(&self, principal: &AgentRecord, _request: &ToolRequest) -> BudgetDecision {
        let mut buckets = self.buckets.lock().await;
        if buckets.len() > PRUNE_THRESHOLD {
            buckets.retain(|_, bucket| bucket.available_tokens() < bucket.max_tokens);
        }
        let bucket = buckets
            .entry(principal.id)
            .or_insert_with(|| self.new_bucket());
        if bucket.try_consume() {
            return BudgetDecision::Within;
        }

        let retry_after_ms = if bucket.refill_rate > 0.0 {
            let missing = (1.0 - bucket.available_tokens()).max(0.0);
            // Bounded by 60s / per_minute, so the cast cannot overflow.
            (missing / bucket.refill_rate * 1000.0).ceil() as u64
        } else {
            u64::MAX
        };
        BudgetDecision::Exceeded {
            reason: format!("more than {} requests per minute", self.per_minute),
            retry_after_ms,
        }
    }

    fn name(&self) -> &str {
        "agent-rate"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> ToolRequest {
        ToolRequest::new("echo", serde_json::json!({}))
    }

    #[tokio::test]
    async fn test_burst_then_exceeded() {
        let budget = AgentRateBudget::per_minute(3);
        let agent = AgentRecord::anonymous(AgentId::new());
        for _ in 0..3 {
            assert_eq!(
                budget.charge(&agent, &request()).await,
                BudgetDecision::Within
            );
        }
        match budget.charge(&agent, &request()).await {
            BudgetDecision::Exceeded { retry_after_ms, .. } => {
                // One token refills every 20s at 3/min.
                assert!(retry_after_ms > 0 && retry_after_ms <= 20_000);
            }
            BudgetDecision::Within => panic!("fourth request must exceed a 3/min budget"),
        }
    }

    #[tokio::test]
    async fn test_budgets_are_per_agent() {
        let budget = AgentRateBudget::per_minute(1);
        let a = AgentRecord::anonymous(AgentId::new());
        let b = AgentRecord::anonymous(AgentId::new());
        assert_eq!(budget.charge(&a, &request()).await, BudgetDecision::Within);
        assert!(matches!(
            budget.charge(&a, &request()).await,
            BudgetDecision::Exceeded { .. }
        ));
        assert_eq!(budget.charge(&b, &request()).await, BudgetDecision::Within);
    }

    #[tokio::test]
    async fn test_zero_allows_nothing() {
        let budget = AgentRateBudget::per_minute(0);
        let agent = AgentRecord::anonymous(AgentId::new());
        assert_eq!(
            budget.charge(&agent, &request()).await,
            BudgetDecision::Exceeded {
                reason: "more than 0 requests per minute".to_string(),
                retry_after_ms: u64::MAX,
            }
        );
    }

    #[tokio::test]
    async fn test_unlimited() {
        let agent = AgentRecord::anonymous(AgentId::new());
        for _ in 0..1000 {
            assert_eq!(
                Unlimited.charge(&agent, &request()).await,
                BudgetDecision::Within
            );
        }
    }
}
