//! Metrics Collection and Prometheus Export
//!
//! This module provides metrics collection for VAK kernel operations
//! with Prometheus-compatible export format.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for metrics collection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable metrics collection
    pub enabled: bool,
    /// Metrics endpoint path
    pub endpoint: String,
    /// Collection interval in seconds
    pub collection_interval_secs: u64,
    /// Enable histogram metrics
    pub enable_histograms: bool,
    /// Histogram buckets for latency measurements
    pub latency_buckets_ms: Vec<f64>,
    /// Labels to add to all metrics
    pub global_labels: HashMap<String, String>,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: "/metrics".to_string(),
            collection_interval_secs: 15,
            enable_histograms: true,
            latency_buckets_ms: vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0],
            global_labels: HashMap::new(),
        }
    }
}

impl MetricsConfig {
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.global_labels.insert(key.into(), value.into());
        self
    }
}

// ============================================================================
// Metric Types
// ============================================================================

/// A counter metric (monotonically increasing)
#[derive(Debug)]
pub struct Counter {
    name: String,
    help: String,
    value: AtomicU64,
    labels: HashMap<String, String>,
}

impl Counter {
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            value: AtomicU64::new(0),
            labels: HashMap::new(),
        }
    }

    pub fn with_labels(mut self, labels: HashMap<String, String>) -> Self {
        self.labels = labels;
        self
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_by(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn to_prometheus(&self, global_labels: &HashMap<String, String>) -> String {
        let labels = self.format_labels(global_labels);
        format!(
            "# HELP {} {}\n# TYPE {} counter\n{}{} {}\n",
            self.name,
            self.help,
            self.name,
            self.name,
            labels,
            self.get()
        )
    }

    fn format_labels(&self, global_labels: &HashMap<String, String>) -> String {
        let mut all_labels = global_labels.clone();
        all_labels.extend(self.labels.clone());
        if all_labels.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = all_labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// A gauge metric (can go up or down)
#[derive(Debug)]
pub struct Gauge {
    name: String,
    help: String,
    value: Arc<RwLock<f64>>,
    labels: HashMap<String, String>,
}

impl Gauge {
    pub fn new(name: impl Into<String>, help: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            help: help.into(),
            value: Arc::new(RwLock::new(0.0)),
            labels: HashMap::new(),
        }
    }

    pub fn with_labels(mut self, labels: HashMap<String, String>) -> Self {
        self.labels = labels;
        self
    }

    pub fn set(&self, v: f64) {
        if let Ok(mut value) = self.value.write() {
            *value = v;
        }
    }

    pub fn inc(&self) {
        if let Ok(mut value) = self.value.write() {
            *value += 1.0;
        }
    }

    pub fn dec(&self) {
        if let Ok(mut value) = self.value.write() {
            *value -= 1.0;
        }
    }

    pub fn get(&self) -> f64 {
        self.value.read().map(|v| *v).unwrap_or(0.0)
    }

    pub fn to_prometheus(&self, global_labels: &HashMap<String, String>) -> String {
        let labels = self.format_labels(global_labels);
        format!(
            "# HELP {} {}\n# TYPE {} gauge\n{}{} {}\n",
            self.name,
            self.help,
            self.name,
            self.name,
            labels,
            self.get()
        )
    }

    fn format_labels(&self, global_labels: &HashMap<String, String>) -> String {
        let mut all_labels = global_labels.clone();
        all_labels.extend(self.labels.clone());
        if all_labels.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = all_labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

/// A histogram metric for latency distribution
#[derive(Debug)]
pub struct Histogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    bucket_counts: Vec<AtomicU64>,
    sum: Arc<RwLock<f64>>,
    count: AtomicU64,
    labels: HashMap<String, String>,
}

impl Histogram {
    pub fn new(name: impl Into<String>, help: impl Into<String>, buckets: Vec<f64>) -> Self {
        let bucket_counts = buckets.iter().map(|_| AtomicU64::new(0)).collect();
        Self {
            name: name.into(),
            help: help.into(),
            buckets,
            bucket_counts,
            sum: Arc::new(RwLock::new(0.0)),
            count: AtomicU64::new(0),
            labels: HashMap::new(),
        }
    }

    pub fn with_labels(mut self, labels: HashMap<String, String>) -> Self {
        self.labels = labels;
        self
    }

    pub fn observe(&self, value: f64) {
        for (i, &bucket) in self.buckets.iter().enumerate() {
            if value <= bucket {
                self.bucket_counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Ok(mut sum) = self.sum.write() {
            *sum += value;
        }
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_duration(&self, duration: Duration) {
        self.observe(duration.as_secs_f64() * 1000.0); // Convert to ms
    }

    pub fn get_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn get_sum(&self) -> f64 {
        self.sum.read().map(|s| *s).unwrap_or(0.0)
    }

    pub fn to_prometheus(&self, global_labels: &HashMap<String, String>) -> String {
        let base_labels = self.format_labels(global_labels);
        let mut output = format!(
            "# HELP {} {}\n# TYPE {} histogram\n",
            self.name, self.help, self.name
        );

        let mut cumulative = 0u64;
        for (i, &bucket) in self.buckets.iter().enumerate() {
            cumulative += self.bucket_counts[i].load(Ordering::Relaxed);
            let bucket_label = if base_labels.is_empty() {
                format!("{{le=\"{}\"}}", bucket)
            } else {
                let inner = &base_labels[1..base_labels.len() - 1];
                format!("{{{},le=\"{}\"}}", inner, bucket)
            };
            output.push_str(&format!(
                "{}_bucket{} {}\n",
                self.name, bucket_label, cumulative
            ));
        }

        // +Inf bucket
        let inf_label = if base_labels.is_empty() {
            "{le=\"+Inf\"}".to_string()
        } else {
            let inner = &base_labels[1..base_labels.len() - 1];
            format!("{{{},le=\"+Inf\"}}", inner)
        };
        output.push_str(&format!(
            "{}_bucket{} {}\n",
            self.name,
            inf_label,
            self.count.load(Ordering::Relaxed)
        ));

        output.push_str(&format!(
            "{}_sum{} {}\n",
            self.name,
            base_labels,
            self.get_sum()
        ));
        output.push_str(&format!(
            "{}_count{} {}\n",
            self.name,
            base_labels,
            self.count.load(Ordering::Relaxed)
        ));

        output
    }

    fn format_labels(&self, global_labels: &HashMap<String, String>) -> String {
        let mut all_labels = global_labels.clone();
        all_labels.extend(self.labels.clone());
        if all_labels.is_empty() {
            String::new()
        } else {
            let pairs: Vec<String> = all_labels
                .iter()
                .map(|(k, v)| format!("{}=\"{}\"", k, v))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

// ============================================================================
// Metrics Collector
// ============================================================================

/// Collects and manages all VAK metrics
pub struct MetricsCollector {
    config: MetricsConfig,
    start_time: Instant,

    // Counters
    /// Total number of policy evaluations
    pub policy_evaluations_total: Counter,
    /// Policy evaluations that allowed the action
    pub policy_evaluations_allowed: Counter,
    /// Policy evaluations that denied the action
    pub policy_evaluations_denied: Counter,
    /// Total audit log entries created
    pub audit_entries_total: Counter,
    /// Total tool executions
    pub tool_executions_total: Counter,
    /// Successful tool executions
    pub tool_executions_success: Counter,
    /// Failed tool executions
    pub tool_executions_failure: Counter,
    /// Total PRM evaluations
    pub prm_evaluations_total: Counter,
    /// PRM backtrack events triggered
    pub prm_backtrack_triggered: Counter,
    /// Total WASM executions
    pub wasm_executions_total: Counter,

    // Gauges
    /// Currently active agents
    pub active_agents: Gauge,
    /// Currently active sessions
    pub active_sessions: Gauge,
    /// Size of audit log in entries
    pub audit_log_size: Gauge,
    /// Current memory usage in bytes
    pub memory_usage_bytes: Gauge,
    /// Number of skills loaded
    pub skills_loaded: Gauge,

    // Histograms
    /// Policy evaluation latency distribution
    pub policy_evaluation_duration: Histogram,
    /// Tool execution latency distribution
    pub tool_execution_duration: Histogram,
    /// PRM scoring latency distribution
    pub prm_scoring_duration: Histogram,
    /// WASM execution latency distribution
    pub wasm_execution_duration: Histogram,
}

impl std::fmt::Debug for MetricsCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsCollector")
            .field("config", &self.config)
            .field("uptime_secs", &self.start_time.elapsed().as_secs())
            .finish_non_exhaustive()
    }
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(config: MetricsConfig) -> Self {
        let buckets = config.latency_buckets_ms.clone();
        Self {
            config,
            start_time: Instant::now(),

            // Counters
            policy_evaluations_total: Counter::new(
                "vak_policy_evaluations_total",
                "Total number of policy evaluations",
            ),
            policy_evaluations_allowed: Counter::new(
                "vak_policy_evaluations_allowed",
                "Number of policy evaluations that resulted in Allow",
            ),
            policy_evaluations_denied: Counter::new(
                "vak_policy_evaluations_denied",
                "Number of policy evaluations that resulted in Deny",
            ),
            audit_entries_total: Counter::new(
                "vak_audit_entries_total",
                "Total number of audit log entries",
            ),
            tool_executions_total: Counter::new(
                "vak_tool_executions_total",
                "Total number of tool executions",
            ),
            tool_executions_success: Counter::new(
                "vak_tool_executions_success",
                "Number of successful tool executions",
            ),
            tool_executions_failure: Counter::new(
                "vak_tool_executions_failure",
                "Number of failed tool executions",
            ),
            prm_evaluations_total: Counter::new(
                "vak_prm_evaluations_total",
                "Total number of PRM evaluations",
            ),
            prm_backtrack_triggered: Counter::new(
                "vak_prm_backtrack_triggered",
                "Number of times PRM triggered backtracking",
            ),
            wasm_executions_total: Counter::new(
                "vak_wasm_executions_total",
                "Total number of WASM skill executions",
            ),

            // Gauges
            active_agents: Gauge::new("vak_active_agents", "Number of currently active agents"),
            active_sessions: Gauge::new(
                "vak_active_sessions",
                "Number of currently active sessions",
            ),
            audit_log_size: Gauge::new("vak_audit_log_size", "Current size of the audit log"),
            memory_usage_bytes: Gauge::new("vak_memory_usage_bytes", "Memory usage in bytes"),
            skills_loaded: Gauge::new("vak_skills_loaded", "Number of loaded WASM skills"),

            // Histograms
            policy_evaluation_duration: Histogram::new(
                "vak_policy_evaluation_duration_ms",
                "Policy evaluation duration in milliseconds",
                buckets.clone(),
            ),
            tool_execution_duration: Histogram::new(
                "vak_tool_execution_duration_ms",
                "Tool execution duration in milliseconds",
                buckets.clone(),
            ),
            prm_scoring_duration: Histogram::new(
                "vak_prm_scoring_duration_ms",
                "PRM scoring duration in milliseconds",
                buckets.clone(),
            ),
            wasm_execution_duration: Histogram::new(
                "vak_wasm_execution_duration_ms",
                "WASM skill execution duration in milliseconds",
                buckets,
            ),
        }
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Export all metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // Add uptime metric
        output.push_str(&format!(
            "# HELP vak_uptime_seconds VAK kernel uptime in seconds\n\
             # TYPE vak_uptime_seconds gauge\n\
             vak_uptime_seconds {}\n\n",
            self.uptime_seconds()
        ));

        // Add build info
        output.push_str(&format!(
            "# HELP vak_build_info VAK build information\n\
             # TYPE vak_build_info gauge\n\
             vak_build_info{{version=\"{}\",rust_version=\"{}\"}} 1\n\n",
            env!("CARGO_PKG_VERSION"),
            "1.75"
        ));

        let labels = &self.config.global_labels;

        // Counters
        output.push_str(&self.policy_evaluations_total.to_prometheus(labels));
        output.push_str(&self.policy_evaluations_allowed.to_prometheus(labels));
        output.push_str(&self.policy_evaluations_denied.to_prometheus(labels));
        output.push_str(&self.audit_entries_total.to_prometheus(labels));
        output.push_str(&self.tool_executions_total.to_prometheus(labels));
        output.push_str(&self.tool_executions_success.to_prometheus(labels));
        output.push_str(&self.tool_executions_failure.to_prometheus(labels));
        output.push_str(&self.prm_evaluations_total.to_prometheus(labels));
        output.push_str(&self.prm_backtrack_triggered.to_prometheus(labels));
        output.push_str(&self.wasm_executions_total.to_prometheus(labels));

        // Gauges
        output.push_str(&self.active_agents.to_prometheus(labels));
        output.push_str(&self.active_sessions.to_prometheus(labels));
        output.push_str(&self.audit_log_size.to_prometheus(labels));
        output.push_str(&self.memory_usage_bytes.to_prometheus(labels));
        output.push_str(&self.skills_loaded.to_prometheus(labels));

        // Histograms
        if self.config.enable_histograms {
            output.push_str(&self.policy_evaluation_duration.to_prometheus(labels));
            output.push_str(&self.tool_execution_duration.to_prometheus(labels));
            output.push_str(&self.prm_scoring_duration.to_prometheus(labels));
            output.push_str(&self.wasm_execution_duration.to_prometheus(labels));
        }

        output
    }

    /// Get a summary of metrics as JSON
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "uptime_seconds": self.uptime_seconds(),
            "counters": {
                "policy_evaluations_total": self.policy_evaluations_total.get(),
                "policy_evaluations_allowed": self.policy_evaluations_allowed.get(),
                "policy_evaluations_denied": self.policy_evaluations_denied.get(),
                "audit_entries_total": self.audit_entries_total.get(),
                "tool_executions_total": self.tool_executions_total.get(),
                "tool_executions_success": self.tool_executions_success.get(),
                "tool_executions_failure": self.tool_executions_failure.get(),
                "prm_evaluations_total": self.prm_evaluations_total.get(),
                "prm_backtrack_triggered": self.prm_backtrack_triggered.get(),
                "wasm_executions_total": self.wasm_executions_total.get(),
            },
            "gauges": {
                "active_agents": self.active_agents.get(),
                "active_sessions": self.active_sessions.get(),
                "audit_log_size": self.audit_log_size.get(),
                "memory_usage_bytes": self.memory_usage_bytes.get(),
                "skills_loaded": self.skills_loaded.get(),
            },
            "histograms": {
                "policy_evaluation_duration_count": self.policy_evaluation_duration.get_count(),
                "policy_evaluation_duration_sum_ms": self.policy_evaluation_duration.get_sum(),
                "tool_execution_duration_count": self.tool_execution_duration.get_count(),
                "tool_execution_duration_sum_ms": self.tool_execution_duration.get_sum(),
            }
        })
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new(MetricsConfig::default())
    }
}

// ============================================================================
// Prometheus Exporter
// ============================================================================

/// Prometheus metrics exporter
pub struct PrometheusExporter {
    collector: Arc<MetricsCollector>,
}

impl std::fmt::Debug for PrometheusExporter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrometheusExporter").finish_non_exhaustive()
    }
}

impl PrometheusExporter {
    pub fn new(collector: Arc<MetricsCollector>) -> Self {
        Self { collector }
    }

    /// Export metrics in Prometheus text format
    pub fn export(&self) -> String {
        self.collector.export_prometheus()
    }

    /// Export metrics as JSON
    pub fn export_json(&self) -> serde_json::Value {
        self.collector.to_json()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_counter_basic() {
        let counter = Counter::new("test_counter", "A test counter");
        assert_eq!(counter.get(), 0);
        counter.inc();
        assert_eq!(counter.get(), 1);
        counter.inc_by(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_gauge_basic() {
        let gauge = Gauge::new("test_gauge", "A test gauge");
        assert_eq!(gauge.get(), 0.0);
        gauge.set(42.5);
        assert_eq!(gauge.get(), 42.5);
        gauge.inc();
        assert_eq!(gauge.get(), 43.5);
        gauge.dec();
        assert_eq!(gauge.get(), 42.5);
    }

    #[test]
    fn test_histogram_basic() {
        let histogram = Histogram::new(
            "test_histogram",
            "A test histogram",
            vec![10.0, 50.0, 100.0],
        );
        histogram.observe(5.0);
        histogram.observe(25.0);
        histogram.observe(75.0);
        histogram.observe(150.0);

        assert_eq!(histogram.get_count(), 4);
        assert_eq!(histogram.get_sum(), 255.0);
    }

    #[test]
    fn test_histogram_duration() {
        let histogram = Histogram::new(
            "test_duration",
            "A test duration histogram",
            vec![1.0, 5.0, 10.0],
        );
        histogram.observe_duration(Duration::from_millis(3));
        assert_eq!(histogram.get_count(), 1);
        assert!(histogram.get_sum() >= 2.9 && histogram.get_sum() <= 3.1);
    }

    #[test]
    fn test_metrics_collector() {
        let collector = MetricsCollector::default();

        collector.policy_evaluations_total.inc();
        collector.policy_evaluations_allowed.inc();
        collector.active_agents.set(5.0);
        collector.policy_evaluation_duration.observe(12.5);

        let json = collector.to_json();
        assert_eq!(json["counters"]["policy_evaluations_total"], 1);
        assert_eq!(json["counters"]["policy_evaluations_allowed"], 1);
        assert_eq!(json["gauges"]["active_agents"], 5.0);
    }

    #[test]
    fn test_prometheus_export() {
        let collector = MetricsCollector::default();
        collector.policy_evaluations_total.inc_by(100);
        collector.active_agents.set(3.0);

        let output = collector.export_prometheus();
        assert!(output.contains("vak_policy_evaluations_total"));
        assert!(output.contains("100"));
        assert!(output.contains("vak_active_agents"));
        assert!(output.contains("3"));
        assert!(output.contains("vak_uptime_seconds"));
    }

    #[test]
    fn test_counter_with_labels() {
        let mut labels = HashMap::new();
        labels.insert("agent".to_string(), "test-agent".to_string());

        let counter = Counter::new("labeled_counter", "Counter with labels").with_labels(labels);
        counter.inc();

        let output = counter.to_prometheus(&HashMap::new());
        assert!(output.contains("agent=\"test-agent\""));
    }

    #[test]
    fn test_global_labels() {
        let config = MetricsConfig::default()
            .with_label("environment", "production")
            .with_label("cluster", "us-west-2");

        let collector = MetricsCollector::new(config);
        collector.policy_evaluations_total.inc();

        let output = collector.export_prometheus();
        assert!(output.contains("environment=\"production\""));
        assert!(output.contains("cluster=\"us-west-2\""));
    }
}
