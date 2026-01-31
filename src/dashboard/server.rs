//! Dashboard Server and HTML/JS Interface
//!
//! Provides a simple HTTP server with a basic web dashboard for monitoring
//! VAK kernel operations.

use super::health::{HealthChecker, HealthStatus, ReadinessStatus};
use super::metrics::MetricsCollector;
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
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn with_bind_address(mut self, address: impl Into<String>) -> Self {
        self.bind_address = address.into();
        self
    }

    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = title.into();
        self
    }

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
}

impl DashboardServer {
    pub fn new(
        config: DashboardConfig,
        metrics: Arc<MetricsCollector>,
        health: Arc<HealthChecker>,
    ) -> Self {
        Self {
            config,
            metrics,
            health,
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
    pub fn handle_request(&self, path: &str, method: &str) -> HttpResponse {
        match (method, path) {
            ("GET", "/") | ("GET", "/dashboard") if self.config.enable_dashboard => {
                self.dashboard_response()
            }
            ("GET", "/metrics") if self.config.enable_metrics => self.metrics_response(),
            ("GET", "/metrics.json") if self.config.enable_metrics => self.metrics_json_response(),
            ("GET", "/health") if self.config.enable_health => self.health_response(),
            ("GET", "/ready") if self.config.enable_health => self.ready_response(),
            ("GET", "/live") if self.config.enable_health => self.live_response(),
            ("GET", "/api/stats") => self.metrics_json_response(),
            _ => HttpResponse {
                status: 404,
                content_type: "application/json".to_string(),
                body: r#"{"error": "Not found"}"#.to_string(),
            },
        }
    }
}

// ============================================================================
// HTTP Response
// ============================================================================

/// Simple HTTP response
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl HttpResponse {
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
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="{refresh}">
    <title>{title}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --accent-green: #22c55e;
            --accent-yellow: #eab308;
            --accent-red: #ef4444;
            --accent-blue: #3b82f6;
            --accent-purple: #a855f7;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
            padding-bottom: 1rem;
            border-bottom: 1px solid var(--bg-tertiary);
        }}
        
        h1 {{
            font-size: 1.75rem;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        
        .logo {{
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, var(--accent-blue), var(--accent-purple));
            border-radius: 8px;
        }}
        
        .status-badge {{
            padding: 0.5rem 1rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 500;
        }}
        
        .status-healthy {{
            background: rgba(34, 197, 94, 0.2);
            color: var(--accent-green);
        }}
        
        .status-degraded {{
            background: rgba(234, 179, 8, 0.2);
            color: var(--accent-yellow);
        }}
        
        .status-unhealthy {{
            background: rgba(239, 68, 68, 0.2);
            color: var(--accent-red);
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .card {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            border: 1px solid var(--bg-tertiary);
        }}
        
        .card-title {{
            font-size: 0.875rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.75rem;
        }}
        
        .card-value {{
            font-size: 2.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        .card-subtitle {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-top: 0.25rem;
        }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .metric {{
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
        }}
        
        .metric-label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 0.25rem;
        }}
        
        .metric-value {{
            font-size: 1.25rem;
            font-weight: 600;
        }}
        
        .components {{
            margin-top: 2rem;
        }}
        
        .component {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1rem;
            background: var(--bg-tertiary);
            border-radius: 8px;
            margin-bottom: 0.5rem;
        }}
        
        .component-name {{
            font-weight: 500;
        }}
        
        .component-status {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        
        .status-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }}
        
        .status-dot.healthy {{
            background: var(--accent-green);
        }}
        
        .status-dot.degraded {{
            background: var(--accent-yellow);
        }}
        
        .status-dot.unhealthy {{
            background: var(--accent-red);
        }}
        
        footer {{
            margin-top: 2rem;
            padding-top: 1rem;
            border-top: 1px solid var(--bg-tertiary);
            display: flex;
            justify-content: space-between;
            color: var(--text-secondary);
            font-size: 0.75rem;
        }}
        
        .links a {{
            color: var(--accent-blue);
            text-decoration: none;
            margin-left: 1rem;
        }}
        
        .links a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>
                <div class="logo"></div>
                {title}
            </h1>
            <span class="status-badge status-{status_class}">{status}</span>
        </header>
        
        <div class="grid">
            <div class="card">
                <div class="card-title">Uptime</div>
                <div class="card-value">{uptime}</div>
                <div class="card-subtitle">Since last restart</div>
            </div>
            
            <div class="card">
                <div class="card-title">Policy Evaluations</div>
                <div class="card-value">{policy_total}</div>
                <div class="card-subtitle">{policy_allowed} allowed / {policy_denied} denied</div>
            </div>
            
            <div class="card">
                <div class="card-title">Tool Executions</div>
                <div class="card-value">{tool_total}</div>
                <div class="card-subtitle">{tool_success} success / {tool_failure} failure</div>
            </div>
            
            <div class="card">
                <div class="card-title">Active Agents</div>
                <div class="card-value">{active_agents}</div>
                <div class="card-subtitle">{active_sessions} active sessions</div>
            </div>
        </div>
        
        <div class="card">
            <div class="card-title">Metrics Overview</div>
            <div class="metrics-grid">
                <div class="metric">
                    <div class="metric-label">Audit Entries</div>
                    <div class="metric-value">{audit_entries}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">PRM Evaluations</div>
                    <div class="metric-value">{prm_evaluations}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Backtrack Triggers</div>
                    <div class="metric-value">{prm_backtracks}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">WASM Executions</div>
                    <div class="metric-value">{wasm_executions}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Skills Loaded</div>
                    <div class="metric-value">{skills_loaded}</div>
                </div>
                <div class="metric">
                    <div class="metric-label">Memory Usage</div>
                    <div class="metric-value">{memory_usage}</div>
                </div>
            </div>
        </div>
        
        <div class="card components">
            <div class="card-title">Component Health</div>
            {components_html}
        </div>
        
        <footer>
            <div>VAK v{version} • Auto-refresh every {refresh}s</div>
            <div class="links">
                <a href="/metrics">Prometheus Metrics</a>
                <a href="/health">Health JSON</a>
                <a href="/ready">Readiness</a>
                <a href="/api/stats">API Stats</a>
            </div>
        </footer>
    </div>
    
    <script>
        // Auto-refresh handled by meta tag
        console.log('VAK Dashboard loaded');
    </script>
</body>
</html>"#,
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
        memory_usage = format_bytes(metrics_json["gauges"]["memory_usage_bytes"].as_f64().unwrap_or(0.0)),
        components_html = generate_components_html(&health_check.components),
        version = env!("CARGO_PKG_VERSION"),
    )
}

fn generate_components_html(components: &HashMap<String, super::health::ComponentHealth>) -> String {
    let mut html = String::new();
    
    for (name, component) in components {
        let status_class = match component.status {
            HealthStatus::Healthy => "healthy",
            HealthStatus::Degraded => "degraded",
            HealthStatus::Unhealthy => "unhealthy",
        };
        
        let message = component.message.as_deref().unwrap_or("");
        
        html.push_str(&format!(
            r#"<div class="component">
                <span class="component-name">{name}</span>
                <div class="component-status">
                    {message}
                    <span class="status-dot {status_class}"></span>
                </div>
            </div>"#,
            name = name,
            message = if message.is_empty() { "".to_string() } else { format!("<span style=\"color: var(--text-secondary); font-size: 0.75rem;\">{}</span>", message) },
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

        let server = DashboardServer::new(config, metrics, health);
        
        let response = server.metrics_response();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("vak_"));
    }

    #[test]
    fn test_dashboard_server_health() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());

        let server = DashboardServer::new(config, metrics, health);
        
        let response = server.health_response();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("\"status\":"));
    }

    #[test]
    fn test_dashboard_server_ready() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());

        let server = DashboardServer::new(config, metrics, health);
        
        // Not ready by default
        let response = server.ready_response();
        assert_eq!(response.status, 503);
    }

    #[test]
    fn test_dashboard_server_live() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());

        let server = DashboardServer::new(config, metrics, health);
        
        let response = server.live_response();
        assert_eq!(response.status, 200);
    }

    #[test]
    fn test_dashboard_server_html() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());

        let server = DashboardServer::new(config, metrics, health);
        
        let response = server.dashboard_response();
        assert_eq!(response.status, 200);
        assert!(response.body.contains("<!DOCTYPE html>"));
        assert!(response.body.contains("VAK Dashboard"));
    }

    #[test]
    fn test_handle_request_routing() {
        let config = DashboardConfig::default();
        let metrics = Arc::new(MetricsCollector::default());
        let health = Arc::new(HealthChecker::new());

        let server = DashboardServer::new(config, metrics, health);

        assert_eq!(server.handle_request("/metrics", "GET").status, 200);
        assert_eq!(server.handle_request("/health", "GET").status, 200);
        assert_eq!(server.handle_request("/ready", "GET").status, 503);
        assert_eq!(server.handle_request("/live", "GET").status, 200);
        assert_eq!(server.handle_request("/dashboard", "GET").status, 200);
        assert_eq!(server.handle_request("/", "GET").status, 200);
        assert_eq!(server.handle_request("/unknown", "GET").status, 404);
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
