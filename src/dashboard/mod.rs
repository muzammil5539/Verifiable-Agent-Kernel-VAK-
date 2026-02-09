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
//! use vak::dashboard::{DashboardServer, DashboardConfig, MetricsCollector, HealthChecker};
//! use vak::dashboard::metrics::MetricsConfig;
//! use vak::swarm::a2a::DiscoveryService;
//! use std::sync::Arc;
//!
//! let config = DashboardConfig::default()
//!     .with_port(8080);
//!
//! let metrics = Arc::new(MetricsCollector::new(MetricsConfig::default()));
//! let health = Arc::new(HealthChecker::new());
//! let discovery = Arc::new(DiscoveryService::new());
//!
//! let server = DashboardServer::new(config, metrics, health, discovery);
//! let address = server.address();
//! println!("Dashboard available at http://{}", address);
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
