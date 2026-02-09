//! Dashboard Server and HTML/JS Interface
//!
//! Provides a simple HTTP server with a basic web dashboard for monitoring
//! VAK kernel operations.

use super::health::{HealthChecker, HealthStatus};
use super::metrics::MetricsCollector;
use crate::swarm::a2a::DiscoveryService;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the dashboard server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Server bind address
    pub bind_address: String,
    /// Server port
    pub port: u16,
    /// Enable dashboard UI
    pub enable_dashboard: bool,
    /// Enable metrics endpoint
    pub enable_metrics: bool,
    /// Enable health endpoints
    pub enable_health: bool,
    /// Dashboard title
    pub title: String,
    /// Refresh interval in seconds
    pub refresh_interval_secs: u64,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            port: 8080,
            enable_dashboard: true,
            enable_metrics: true,
            enable_health: true,
            title: "VAK Dashboard".to_string(),
            refresh_interval_secs: 5,
        }
    }
}

impl DashboardConfig {
    /// Sets the server port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    /// Sets the server bind address.
    pub fn with_bind_address(mut self, address: impl Into<String>) -> Self {
        self.bind_address = address.into();
        self
    }

    /// Sets the dashboard title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

    /// Creates a configuration with only metrics and health endpoints enabled.
    pub fn metrics_only() -> Self {
        Self {
            enable_dashboard: false,
            enable_health: true,
            enable_metrics: true,
            ..Default::default()
        }
    }
}

// ============================================================================
// Dashboard Server
// ============================================================================

/// Dashboard server for VAK monitoring
pub struct DashboardServer {
    config: DashboardConfig,
    metrics: Arc<MetricsCollector>,
    health: Arc<HealthChecker>,
    discovery: Arc<DiscoveryService>,
}

impl std::fmt::Debug for DashboardServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DashboardServer")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl DashboardServer {
    /// Create a new dashboard server
    pub fn new(
        config: DashboardConfig,
        metrics: Arc<MetricsCollector>,
        health: Arc<HealthChecker>,
        discovery: Arc<DiscoveryService>,
    ) -> Self {
        Self {
            config,
            metrics,
            health,
            discovery,
        }
    }

    /// Get server address
    pub fn address(&self) -> String {
        format!("{}:{}", self.config.bind_address, self.config.port)
    }

    /// Generate metrics response
    pub fn metrics_response(&self) -> HttpResponse {
        HttpResponse {
            status: 200,
            content_type: "text/plain; charset=utf-8".to_string(),
            body: self.metrics.export_prometheus(),
        }
    }

    /// Generate metrics JSON response
    pub fn metrics_json_response(&self) -> HttpResponse {
        HttpResponse {
            status: 200,
            content_type: "application/json".to_string(),
            body: self.metrics.to_json().to_string(),
        }
    }

    /// Generate health response
    pub fn health_response(&self) -> HttpResponse {
        let health = self.health.check_health();
        HttpResponse {
            status: health.status.http_status_code(),
            content_type: "application/json".to_string(),
            body: health.to_json(),
        }
    }

    /// Generate readiness response
    pub fn ready_response(&self) -> HttpResponse {
        let readiness = self.health.check_readiness();
        HttpResponse {
            status: readiness.status.http_status_code(),
            content_type: "application/json".to_string(),
            body: readiness.to_json(),
        }
    }

    /// Generate liveness response
    pub fn live_response(&self) -> HttpResponse {
        let status = self.health.check_liveness();
        HttpResponse {
            status: status.http_status_code(),
            content_type: "application/json".to_string(),
            body: serde_json::json!({
                "status": "healthy",
                "uptime_seconds": self.health.uptime_seconds()
            })
            .to_string(),
        }
    }

    /// Generate dashboard HTML
    pub fn dashboard_response(&self) -> HttpResponse {
        let html = generate_dashboard_html(&self.config, &self.metrics, &self.health);
        HttpResponse {
            status: 200,
            content_type: "text/html; charset=utf-8".to_string(),
            body: html,
        }
    }

    /// Handle HTTP request
    pub async fn handle_request(&self, path: &str, method: &str) -> HttpResponse {
        // Try built-in routes first
        match (method, path) {
            ("GET", "/") | ("GET", "/dashboard") if self.config.enable_dashboard => {
                return self.dashboard_response();
            }
            ("GET", "/metrics") if self.config.enable_metrics => return self.metrics_response(),
            ("GET", "/metrics.json") if self.config.enable_metrics => {
                return self.metrics_json_response()
            }
            ("GET", "/health") if self.config.enable_health => return self.health_response(),
            ("GET", "/ready") if self.config.enable_health => return self.ready_response(),
            ("GET", "/live") if self.config.enable_health => return self.live_response(),
            ("GET", "/api/stats") => return self.metrics_json_response(),
            _ => {}
        }

        // Try API extensions
        if let Some(response) = crate::api::a2a::handle_request(&self.discovery, path, method).await
        {
            return response;
        }

        HttpResponse {
            status: 404,
            content_type: "application/json".to_string(),
            body: r#"{"error": "Not found"}"#.to_string(),
        }
    }
}

// ============================================================================
// HTTP Response
// ============================================================================

/// Simple HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Content-Type header value.
    pub content_type: String,
    /// Response body content.
    pub body: String,
}

impl HttpResponse {
    /// Formats this response as a raw HTTP/1.1 response string.
    pub fn to_http_string(&self) -> String {
        let status_text = match self.status {
            200 => "OK",
            404 => "Not Found",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Unknown",
        };

        format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            self.status,
            status_text,
            self.content_type,
            self.body.len(),
            self.body
        )
    }
}

// ============================================================================
// Dashboard HTML Generator
// ============================================================================

fn generate_dashboard_html(
    config: &DashboardConfig,
    metrics: &MetricsCollector,
    health: &HealthChecker,
) -> String {
    let health_check = health.check_health();
    let metrics_json = metrics.to_json();

    format!(
        include_str!("dashboard.html"),
        refresh = config.refresh_interval_secs,
        title = config.title,
        status = format!("{:?}", health_check.status),
        status_class = match health_check.status {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        },
        uptime = format_duration(health.uptime_seconds()),
        policy_total = metrics_json["counters"]["policy_evaluations_total"],
        policy_allowed = metrics_json["counters"]["policy_evaluations_allowed"],
        policy_denied = metrics_json["counters"]["policy_evaluations_denied"],
        tool_total = metrics_json["counters"]["tool_executions_total"],
        tool_success = metrics_json["counters"]["tool_executions_success"],
        tool_failure = metrics_json["counters"]["tool_executions_failure"],
        active_agents = metrics_json["gauges"]["active_agents"],
        active_sessions = metrics_json["gauges"]["active_sessions"],
        audit_entries = metrics_json["counters"]["audit_entries_total"],
        prm_evaluations = metrics_json["counters"]["prm_evaluations_total"],
        prm_backtracks = metrics_json["counters"]["prm_backtrack_triggered"],
        wasm_executions = metrics_json["counters"]["wasm_executions_total"],
        skills_loaded = metrics_json["gauges"]["skills_loaded"],
        memory_usage = format_bytes(
            metrics_json["gauges"]["memory_usage_bytes"]
                .as_f64()
                .unwrap_or(0.0)
        ),
        components_html = generate_components_html(&health_check.components),
        version = env!("CARGO_PKG_VERSION"),
    )
}

fn generate_components_html(
    components: &HashMap<String, super::health::ComponentHealth>,
) -> String {
    let mut html = String::new();

    for (name, component) in components {
        let status_class = match component.status {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        };

        let message = component.message.as_deref().unwrap_or("");

        html.push_str(&format!(
            include_str!("component.html"),
            name = name,
            message = if message.is_empty() {
                "".to_string()
            } else {
                format!(
                    "<span style=\"color: var(--text-secondary); font-size: 0.75rem;\">{}</span>",
                    message
                )
            },
            status_class = status_class,
        ));
    }

    if html.is_empty() {
        html = r#"<div class="component"><span class="component-name">No components registered</span></div>"#.to_string();
    }

    html
}

fn format_duration(seconds: f64) -> String {
    let total_seconds = seconds as u64;
    let days = total_seconds / 86400;
    let hours = (total_seconds % 86400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let secs = total_seconds % 60;

    if days > 0 {
        format!("{}d {}h {}m", days, hours, minutes)
    } else if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, secs)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, secs)
    } else {
        format!("{}s", secs)
    }
}

fn format_bytes(bytes: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes >= GB {
        format!("{:.2} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes / KB)
    } else {
        format!("{:.0} B", bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dashboard_config_default() {
        let config = DashboardConfig::default();
        assert_eq!(config.port, 8080);
        assert!(config.enable_dashboard);
        assert!(config.enable_metrics);
        assert!(config.enable_health);
    }

    #[test]
    fn test_dashboard_config_builder() {
        let config = DashboardConfig::default()
            .with_port(9090)
            .with_bind_address("127.0.0.1")
            .with_title("My Dashboard");

        assert_eq!(config.port, 9090);
        assert_eq!(config.bind_address, "127.0.0.1");
        assert_eq!(config.title, "My Dashboard");
    }

    #[test]
    fn test_metrics_only_config() {
        let config = DashboardConfig::metrics_only();
        assert!(!config.enable_dashboard);
        assert!(config.enable_metrics);
        assert!(config.enable_health);
    }

    #[test]
    fn test_http_response() {
        let response = HttpResponse {
            status: 200,
            content_type: "application/json".to_string(),
            body: r#"{"test": true}"#.to_string(),
        };

        let http = response.to_http_string();
        assert!(http.contains("HTTP/1.1 200 OK"));
        assert!(http.contains("application/json"));
        assert!(http.contains(r#"{"test": true}"#));
    }

    #[test]
    fn test_dashboard_server_metrics() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());
        let discovery = Arc::new(DiscoveryService::new());

        let server = DashboardServer::new(config, metrics, health, discovery);

        let response = server.metrics_response();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("vak_"));
    }

    #[test]
    fn test_dashboard_server_health() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());
        let discovery = Arc::new(DiscoveryService::new());

        let server = DashboardServer::new(config, metrics, health, discovery);

        let response = server.health_response();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("\"status\":"));
    }

    #[test]
    fn test_dashboard_server_ready() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());
        let discovery = Arc::new(DiscoveryService::new());

        let server = DashboardServer::new(config, metrics, health, discovery);

        // Not ready by default
        let response = server.ready_response();
        assert_eq!(response.status, 503);
    }

    #[test]
    fn test_dashboard_server_live() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());
        let discovery = Arc::new(DiscoveryService::new());

        let server = DashboardServer::new(config, metrics, health, discovery);

        let response = server.live_response();
        assert_eq!(response.status, 200);
    }

    #[test]
    fn test_dashboard_server_html() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());
        let discovery = Arc::new(DiscoveryService::new());

        let server = DashboardServer::new(config, metrics, health, discovery);

        let response = server.dashboard_response();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("<!DOCTYPE html>"));
        assert!(response.body.contains("VAK Dashboard"));
    }

    #[tokio::test]
    async fn test_handle_request_routing() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());
        let discovery = Arc::new(DiscoveryService::new());

        let server = DashboardServer::new(config, metrics, health, discovery);

        assert_eq!(server.handle_request("/metrics", "GET").await.status, 200);
        assert_eq!(server.handle_request("/health", "GET").await.status, 200);
        assert_eq!(server.handle_request("/ready", "GET").await.status, 503);
        assert_eq!(server.handle_request("/live", "GET").await.status, 200);
        assert_eq!(server.handle_request("/dashboard", "GET").await.status, 200);
        assert_eq!(server.handle_request("/", "GET").await.status, 200);
        assert_eq!(server.handle_request("/unknown", "GET").await.status, 404);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30.0), "30s");
        assert_eq!(format_duration(90.0), "1m 30s");
        assert_eq!(format_duration(3700.0), "1h 1m 40s");
        assert_eq!(format_duration(90061.0), "1d 1h 1m");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500.0), "500 B");
        assert_eq!(format_bytes(1536.0), "1.50 KB");
        assert_eq!(format_bytes(1572864.0), "1.50 MB");
        assert_eq!(format_bytes(1610612736.0), "1.50 GB");
    }
}
