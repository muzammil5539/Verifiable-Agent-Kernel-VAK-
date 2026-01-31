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

pub mod metrics;
pub mod health;
pub mod server;

pub use metrics::{MetricsCollector, MetricsConfig, PrometheusExporter};
pub use health::{HealthChecker, HealthStatus, ReadinessStatus};
pub use server::{DashboardServer, DashboardConfig};
