//! Health Check Endpoints
//!
//! Provides health and readiness checks for Kubernetes-style deployments.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

// ============================================================================
// Health Status
// ============================================================================

/// Overall health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// System is healthy
    Healthy,
    /// System is degraded but operational
    Degraded,
    /// System is unhealthy
    Unhealthy,
}

impl HealthStatus {
    pub fn is_healthy(&self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Degraded)
    }

    pub fn http_status_code(&self) -> u16 {
        match self {
            HealthStatus::Healthy => 200,
            HealthStatus::Degraded => 200,
            HealthStatus::Unhealthy => 503,
        }
    }
}

/// Readiness status for traffic acceptance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadinessStatus {
    /// Ready to accept traffic
    Ready,
    /// Not ready to accept traffic
    NotReady,
}

impl ReadinessStatus {
    pub fn is_ready(&self) -> bool {
        matches!(self, ReadinessStatus::Ready)
    }

    pub fn http_status_code(&self) -> u16 {
        match self {
            ReadinessStatus::Ready => 200,
            ReadinessStatus::NotReady => 503,
        }
    }
}

// ============================================================================
// Component Health
// ============================================================================

/// Health status of an individual component
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub name: String,
    /// Health status
    pub status: HealthStatus,
    /// Optional message
    pub message: Option<String>,
    /// Last check timestamp
    pub last_check: u64,
    /// Response time in milliseconds (if applicable)
    pub response_time_ms: Option<f64>,
}

impl ComponentHealth {
    pub fn healthy(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Healthy,
            message: None,
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            response_time_ms: None,
        }
    }

    pub fn degraded(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Degraded,
            message: Some(message.into()),
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            response_time_ms: None,
        }
    }

    pub fn unhealthy(name: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: HealthStatus::Unhealthy,
            message: Some(message.into()),
            last_check: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            response_time_ms: None,
        }
    }

    pub fn with_response_time(mut self, ms: f64) -> Self {
        self.response_time_ms = Some(ms);
        self
    }
}

// ============================================================================
// Health Response
// ============================================================================

/// Full health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Overall status
    pub status: HealthStatus,
    /// Individual component health
    pub components: HashMap<String, ComponentHealth>,
    /// System uptime in seconds
    pub uptime_seconds: f64,
    /// Version information
    pub version: String,
    /// Timestamp of this check
    pub timestamp: u64,
}

impl HealthResponse {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

/// Readiness check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessResponse {
    /// Readiness status
    pub status: ReadinessStatus,
    /// Reason if not ready
    pub reason: Option<String>,
    /// Components that are not ready
    pub not_ready_components: Vec<String>,
    /// Timestamp
    pub timestamp: u64,
}

impl ReadinessResponse {
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }
}

// ============================================================================
// Health Checker
// ============================================================================

/// Health check function type
pub type HealthCheckFn = Box<dyn Fn() -> ComponentHealth + Send + Sync>;

/// Manages health checks for the VAK kernel
pub struct HealthChecker {
    start_time: Instant,
    checks: RwLock<HashMap<String, HealthCheckFn>>,
    ready: RwLock<bool>,
    ready_checks: RwLock<Vec<String>>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            checks: RwLock::new(HashMap::new()),
            ready: RwLock::new(false),
            ready_checks: RwLock::new(Vec::new()),
        }
    }

    /// Register a health check
    pub fn register_check<F>(&self, name: impl Into<String>, check: F)
    where
        F: Fn() -> ComponentHealth + Send + Sync + 'static,
    {
        let name = name.into();
        self.checks
            .write()
            .unwrap()
            .insert(name, Box::new(check));
    }

    /// Register a component as required for readiness
    pub fn require_for_ready(&self, component: impl Into<String>) {
        self.ready_checks
            .write()
            .unwrap()
            .push(component.into());
    }

    /// Mark the system as ready
    pub fn set_ready(&self, ready: bool) {
        *self.ready.write().unwrap() = ready;
    }

    /// Check if system is ready
    pub fn is_ready(&self) -> bool {
        *self.ready.read().unwrap()
    }

    /// Get uptime in seconds
    pub fn uptime_seconds(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    /// Perform health check
    pub fn check_health(&self) -> HealthResponse {
        let checks = self.checks.read().unwrap();
        let mut components = HashMap::new();
        let mut overall_status = HealthStatus::Healthy;

        for (name, check_fn) in checks.iter() {
            let component_health = check_fn();
            
            // Update overall status based on component health
            match component_health.status {
                HealthStatus::Unhealthy => {
                    overall_status = HealthStatus::Unhealthy;
                }
                HealthStatus::Degraded if overall_status == HealthStatus::Healthy => {
                    overall_status = HealthStatus::Degraded;
                }
                _ => {}
            }

            components.insert(name.clone(), component_health);
        }

        HealthResponse {
            status: overall_status,
            components,
            uptime_seconds: self.uptime_seconds(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Perform readiness check
    pub fn check_readiness(&self) -> ReadinessResponse {
        if !self.is_ready() {
            return ReadinessResponse {
                status: ReadinessStatus::NotReady,
                reason: Some("System initialization not complete".to_string()),
                not_ready_components: vec![],
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };
        }

        let health = self.check_health();
        let required = self.ready_checks.read().unwrap();
        let mut not_ready = Vec::new();

        for component_name in required.iter() {
            if let Some(component) = health.components.get(component_name) {
                if component.status == HealthStatus::Unhealthy {
                    not_ready.push(component_name.clone());
                }
            }
        }

        if not_ready.is_empty() {
            ReadinessResponse {
                status: ReadinessStatus::Ready,
                reason: None,
                not_ready_components: vec![],
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }
        } else {
            ReadinessResponse {
                status: ReadinessStatus::NotReady,
                reason: Some(format!(
                    "Components not ready: {}",
                    not_ready.join(", ")
                )),
                not_ready_components: not_ready,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }
        }
    }

    /// Quick liveness check (always returns healthy if system is running)
    pub fn check_liveness(&self) -> HealthStatus {
        HealthStatus::Healthy
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Default Health Checks
// ============================================================================

/// Create default health checks for VAK components
pub fn create_default_checks(checker: &HealthChecker) {
    // Policy engine check
    checker.register_check("policy_engine", || {
        ComponentHealth::healthy("policy_engine")
    });

    // Audit logger check
    checker.register_check("audit_logger", || {
        ComponentHealth::healthy("audit_logger")
    });

    // Memory system check
    checker.register_check("memory_system", || {
        ComponentHealth::healthy("memory_system")
    });

    // WASM sandbox check
    checker.register_check("wasm_sandbox", || {
        ComponentHealth::healthy("wasm_sandbox")
    });

    // Mark critical components as required for readiness
    checker.require_for_ready("policy_engine");
    checker.require_for_ready("audit_logger");
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_status() {
        assert!(HealthStatus::Healthy.is_healthy());
        assert!(HealthStatus::Degraded.is_healthy());
        assert!(!HealthStatus::Unhealthy.is_healthy());

        assert_eq!(HealthStatus::Healthy.http_status_code(), 200);
        assert_eq!(HealthStatus::Degraded.http_status_code(), 200);
        assert_eq!(HealthStatus::Unhealthy.http_status_code(), 503);
    }

    #[test]
    fn test_readiness_status() {
        assert!(ReadinessStatus::Ready.is_ready());
        assert!(!ReadinessStatus::NotReady.is_ready());

        assert_eq!(ReadinessStatus::Ready.http_status_code(), 200);
        assert_eq!(ReadinessStatus::NotReady.http_status_code(), 503);
    }

    #[test]
    fn test_component_health() {
        let healthy = ComponentHealth::healthy("test");
        assert_eq!(healthy.status, HealthStatus::Healthy);
        assert!(healthy.message.is_none());

        let degraded = ComponentHealth::degraded("test", "slow response");
        assert_eq!(degraded.status, HealthStatus::Degraded);
        assert_eq!(degraded.message, Some("slow response".to_string()));

        let unhealthy = ComponentHealth::unhealthy("test", "connection failed");
        assert_eq!(unhealthy.status, HealthStatus::Unhealthy);
        assert_eq!(unhealthy.message, Some("connection failed".to_string()));
    }

    #[test]
    fn test_health_checker_basic() {
        let checker = HealthChecker::new();
        
        checker.register_check("component_a", || {
            ComponentHealth::healthy("component_a")
        });
        
        checker.register_check("component_b", || {
            ComponentHealth::healthy("component_b")
        });

        let health = checker.check_health();
        assert_eq!(health.status, HealthStatus::Healthy);
        assert_eq!(health.components.len(), 2);
    }

    #[test]
    fn test_health_checker_degraded() {
        let checker = HealthChecker::new();
        
        checker.register_check("healthy", || {
            ComponentHealth::healthy("healthy")
        });
        
        checker.register_check("degraded", || {
            ComponentHealth::degraded("degraded", "slow")
        });

        let health = checker.check_health();
        assert_eq!(health.status, HealthStatus::Degraded);
    }

    #[test]
    fn test_health_checker_unhealthy() {
        let checker = HealthChecker::new();
        
        checker.register_check("healthy", || {
            ComponentHealth::healthy("healthy")
        });
        
        checker.register_check("unhealthy", || {
            ComponentHealth::unhealthy("unhealthy", "down")
        });

        let health = checker.check_health();
        assert_eq!(health.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn test_readiness_not_ready_by_default() {
        let checker = HealthChecker::new();
        let readiness = checker.check_readiness();
        assert_eq!(readiness.status, ReadinessStatus::NotReady);
    }

    #[test]
    fn test_readiness_when_ready() {
        let checker = HealthChecker::new();
        checker.set_ready(true);

        checker.register_check("policy_engine", || {
            ComponentHealth::healthy("policy_engine")
        });
        checker.require_for_ready("policy_engine");

        let readiness = checker.check_readiness();
        assert_eq!(readiness.status, ReadinessStatus::Ready);
    }

    #[test]
    fn test_readiness_with_unhealthy_required() {
        let checker = HealthChecker::new();
        checker.set_ready(true);

        checker.register_check("policy_engine", || {
            ComponentHealth::unhealthy("policy_engine", "error")
        });
        checker.require_for_ready("policy_engine");

        let readiness = checker.check_readiness();
        assert_eq!(readiness.status, ReadinessStatus::NotReady);
        assert!(readiness.not_ready_components.contains(&"policy_engine".to_string()));
    }

    #[test]
    fn test_uptime() {
        let checker = HealthChecker::new();
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(checker.uptime_seconds() >= 0.01);
    }

    #[test]
    fn test_liveness() {
        let checker = HealthChecker::new();
        assert_eq!(checker.check_liveness(), HealthStatus::Healthy);
    }

    #[test]
    fn test_health_response_json() {
        let checker = HealthChecker::new();
        checker.register_check("test", || ComponentHealth::healthy("test"));
        
        let health = checker.check_health();
        let json = health.to_json();
        
        assert!(json.contains("\"status\":"));
        assert!(json.contains("\"components\":"));
        assert!(json.contains("\"uptime_seconds\":"));
    }
}
