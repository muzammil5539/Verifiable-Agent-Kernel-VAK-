//! OSS Dashboard and Observability Module (Issue #46)
//!
//! Provides a basic web-based dashboard and metrics endpoint for monitoring
//! the VAK kernel in production environments.
//!
//! # Features
//!
//! - Prometheus metrics endpoint (`/metrics`)
//! - Health check endpoint (`/health`)
//! - Readiness probe (`/ready`)
//! - Basic HTML dashboard (`/dashboard`)
//! - Audit log viewer
//! - Agent activity monitor
//! - Policy violation alerts
//! - Cost accounting and billing (OBS-003)
//!
//! # Example
//!
//! ```rust,no_run
//! use vak::dashboard::{DashboardServer, DashboardConfig};
//!
//! let config = DashboardConfig::default()
//!     .with_port(8080)
//!     .with_metrics_path("/metrics");
//!
//! let server = DashboardServer::new(config);
//! server.start().await;
//! ```

pub mod cost_accounting;
pub mod health;
pub mod metrics;
pub mod server;

pub use cost_accounting::{
    ApiUsage, BillingReport, CostAccountant, CostBreakdown, CostConfig, CostError, CostResult,
    ExecutionCost, FuelUsage, GlobalCostStats, IoUsage, PricingRates, TokenUsage,
};
pub use health::{HealthChecker, HealthStatus, ReadinessStatus};
pub use metrics::{MetricsCollector, MetricsConfig, PrometheusExporter};
pub use server::{DashboardConfig, DashboardServer};
