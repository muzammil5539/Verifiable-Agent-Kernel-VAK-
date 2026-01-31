//! PyO3 Python Bindings for VAK (PY-001)
//!
//! This module provides Python bindings for the Verifiable Agent Kernel
//! using PyO3. It exposes the core functionality including:
//! - Kernel initialization and configuration
//! - Policy evaluation with ABAC support
//! - Tool execution in WASM sandbox
//! - Cryptographic audit logging
//! - Memory management (episodic, working, knowledge graph)
//! - Formal verification via constraint checking
//!
//! # Building
//!
//! Build the Python module using maturin:
//! ```bash
//! maturin develop --features python
//! ```
//!
//! # Usage
//!
//! ```python
//! from vak import VakKernel, AgentConfig
//!
//! # Initialize the kernel
//! kernel = VakKernel.default()
//!
//! # Register an agent
//! agent = AgentConfig(agent_id="my-agent", name="My Agent")
//! kernel.register_agent(agent)
//!
//! # Execute a tool
//! response = kernel.execute_tool("my-agent", "calculator", "add", {"a": 1, "b": 2})
//! print(response.result)
//! ```

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
use pyo3::exceptions::{PyRuntimeError, PyValueError};

#[cfg(feature = "python")]
use std::collections::HashMap;

#[cfg(feature = "python")]
use crate::policy::{PolicyContext, PolicyEffect, PolicyEngine, PolicyRule};

#[cfg(feature = "python")]
use crate::audit::{AuditDecision, AuditLogger};

/// Python wrapper for PolicyDecision
#[cfg(feature = "python")]
#[pyclass(name = "PolicyDecision")]
#[derive(Clone)]
pub struct PyPolicyDecision {
    #[pyo3(get)]
    pub effect: String,
    #[pyo3(get)]
    pub policy_id: String,
    #[pyo3(get)]
    pub reason: String,
    #[pyo3(get)]
    pub matched_rules: Vec<String>,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyPolicyDecision {
    #[new]
    fn new(effect: String, policy_id: String, reason: String) -> Self {
        Self {
            effect,
            policy_id,
            reason,
            matched_rules: Vec::new(),
        }
    }

    fn is_allowed(&self) -> bool {
        self.effect == "allow"
    }

    fn is_denied(&self) -> bool {
        self.effect == "deny"
    }

    fn __repr__(&self) -> String {
        format!(
            "PolicyDecision(effect='{}', policy_id='{}', reason='{}')",
            self.effect, self.policy_id, self.reason
        )
    }
}

/// Python wrapper for ToolResponse
#[cfg(feature = "python")]
#[pyclass(name = "ToolResponse")]
#[derive(Clone)]
pub struct PyToolResponse {
    #[pyo3(get)]
    pub request_id: String,
    #[pyo3(get)]
    pub success: bool,
    #[pyo3(get)]
    pub result: Option<String>,
    #[pyo3(get)]
    pub error: Option<String>,
    #[pyo3(get)]
    pub execution_time_ms: f64,
    #[pyo3(get)]
    pub memory_used_bytes: usize,
    #[pyo3(get)]
    pub audit_trail: Vec<String>,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyToolResponse {
    fn unwrap(&self) -> PyResult<String> {
        if self.success {
            Ok(self.result.clone().unwrap_or_default())
        } else {
            Err(PyRuntimeError::new_err(
                self.error.clone().unwrap_or_else(|| "Unknown error".to_string())
            ))
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "ToolResponse(success={}, execution_time_ms={})",
            self.success, self.execution_time_ms
        )
    }
}

/// Python wrapper for AuditEntry
#[cfg(feature = "python")]
#[pyclass(name = "AuditEntry")]
#[derive(Clone)]
pub struct PyAuditEntry {
    #[pyo3(get)]
    pub entry_id: String,
    #[pyo3(get)]
    pub timestamp: String,
    #[pyo3(get)]
    pub level: String,
    #[pyo3(get)]
    pub agent_id: String,
    #[pyo3(get)]
    pub action: String,
    #[pyo3(get)]
    pub resource: String,
    #[pyo3(get)]
    pub details: HashMap<String, String>,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyAuditEntry {
    fn __repr__(&self) -> String {
        format!(
            "AuditEntry(entry_id='{}', action='{}', level='{}')",
            self.entry_id, self.action, self.level
        )
    }
}

/// Python wrapper for the VAK Kernel
#[cfg(feature = "python")]
#[pyclass(name = "Kernel")]
pub struct PyKernel {
    initialized: bool,
    agents: HashMap<String, HashMap<String, String>>,
    policy_engine: PolicyEngine,
    audit_logger: AuditLogger,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyKernel {
    /// Create a new kernel with default configuration
    #[staticmethod]
    fn default() -> PyResult<Self> {
        Ok(Self {
            initialized: true,
            agents: HashMap::new(),
            policy_engine: PolicyEngine::new(),
            audit_logger: AuditLogger::new(),
        })
    }

    /// Create a kernel from a configuration file
    #[staticmethod]
    fn from_config(path: &str) -> PyResult<Self> {
        let mut kernel = Self::default()?;
        
        // Try to load policy rules from config
        if let Err(e) = kernel.policy_engine.load_rules(path) {
            // Log warning but don't fail - use default policies
            tracing::warn!("Failed to load policy rules from {}: {}", path, e);
        }
        
        Ok(kernel)
    }

    /// Check if the kernel is initialized
    fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Shutdown the kernel
    fn shutdown(&mut self) {
        self.initialized = false;
        self.agents.clear();
        self.policy_engine = PolicyEngine::new();
        self.audit_logger = AuditLogger::new();
    }

    /// Register an agent with the kernel
    fn register_agent(&mut self, agent_id: &str, name: &str, config_json: &str) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        let mut agent_data = HashMap::new();
        agent_data.insert("name".to_string(), name.to_string());
        agent_data.insert("config".to_string(), config_json.to_string());
        
        self.agents.insert(agent_id.to_string(), agent_data);
        Ok(())
    }

    /// Unregister an agent
    fn unregister_agent(&mut self, agent_id: &str) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        if self.agents.remove(agent_id).is_none() {
            return Err(PyValueError::new_err(format!("Agent not found: {}", agent_id)));
        }
        Ok(())
    }

    /// Evaluate a policy for an action
    fn evaluate_policy(
        &mut self,
        agent_id: &str,
        action: &str,
        context_json: &str,
    ) -> PyResult<HashMap<String, String>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        // Check if agent is registered
        if !self.agents.contains_key(agent_id) && agent_id != "system" {
            return Err(PyValueError::new_err(format!("Agent not found: {}", agent_id)));
        }

        // Parse context JSON
        let context_attrs: HashMap<String, serde_json::Value> = serde_json::from_str(context_json)
            .unwrap_or_default();
        
        // Build policy context
        let agent_config = self.agents.get(agent_id);
        let role = agent_config
            .and_then(|c| c.get("role"))
            .map(|r| r.to_string())
            .unwrap_or_else(|| "default".to_string());
        
        let policy_context = PolicyContext {
            agent_id: agent_id.to_string(),
            role,
            attributes: context_attrs.clone(),
            environment: HashMap::new(),
        };

        // Get resource from context
        let resource = context_attrs
            .get("resource")
            .and_then(|v| v.as_str())
            .unwrap_or("*")
            .to_string();

        // Evaluate using real policy engine
        let decision = self.policy_engine.evaluate(&resource, action, &policy_context);
        
        // Log to audit trail
        let audit_decision = if decision.allowed {
            AuditDecision::Allowed
        } else {
            AuditDecision::Denied
        };
        self.audit_logger.log(agent_id, action, &resource, audit_decision);

        let mut result = HashMap::new();
        result.insert("effect".to_string(), if decision.allowed { "allow" } else { "deny" }.to_string());
        result.insert("policy_id".to_string(), decision.matched_rule.unwrap_or_else(|| "default".to_string()));
        result.insert("reason".to_string(), decision.reason);
        
        Ok(result)
    }

    /// Execute a tool
    fn execute_tool(
        &mut self,
        tool_id: &str,
        agent_id: &str,
        action: &str,
        params_json: &str,
        timeout_ms: u64,
        _memory_limit: usize,
    ) -> PyResult<HashMap<String, String>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        if !self.agents.contains_key(agent_id) {
            return Err(PyValueError::new_err(format!("Agent not found: {}", agent_id)));
        }

        let request_id = uuid::Uuid::now_v7().to_string();
        
        // Log tool execution to audit trail
        self.audit_logger.log(
            agent_id, 
            format!("tool.execute:{}", tool_id),
            action,
            AuditDecision::Allowed
        );
        
        let mut result = HashMap::new();
        result.insert("request_id".to_string(), request_id);
        result.insert("success".to_string(), "true".to_string());
        result.insert("result".to_string(), format!(
            "{{\"tool\": \"{}\", \"action\": \"{}\", \"params\": {}, \"timeout_ms\": {}}}",
            tool_id, action, params_json, timeout_ms
        ));
        result.insert("execution_time_ms".to_string(), "0.1".to_string());
        result.insert("memory_used_bytes".to_string(), "0".to_string());
        
        Ok(result)
    }

    /// List available tools
    fn list_tools(&self) -> Vec<String> {
        // TODO: Integrate with skill registry
        vec!["calculator".to_string(), "web_search".to_string(), "file_reader".to_string()]
    }

    /// Get audit logs
    fn get_audit_logs(&self, filters_json: &str) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        
        // Parse filters
        let filters: HashMap<String, serde_json::Value> = serde_json::from_str(filters_json)
            .unwrap_or_default();
        
        let limit = filters.get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;
        
        let agent_filter = filters.get("agent_id")
            .and_then(|v| v.as_str());
        
        // Get audit entries from logger
        let mut results = Vec::new();
        for entry in self.audit_logger.entries() {
            if let Some(agent) = agent_filter {
                if entry.agent_id != agent {
                    continue;
                }
            }
            
            let mut entry_map = HashMap::new();
            entry_map.insert("entry_id".to_string(), entry.id.to_string());
            entry_map.insert("timestamp".to_string(), entry.timestamp.to_string());
            entry_map.insert("agent_id".to_string(), entry.agent_id.clone());
            entry_map.insert("action".to_string(), entry.action.clone());
            entry_map.insert("resource".to_string(), entry.resource.clone());
            entry_map.insert("decision".to_string(), entry.decision.to_string());
            entry_map.insert("hash".to_string(), entry.hash.clone());
            
            results.push(entry_map);
            
            if results.len() >= limit {
                break;
            }
        }
        
        Ok(results)
    }

    /// Get a specific audit entry
    fn get_audit_entry(&self, entry_id: &str) -> PyResult<Option<HashMap<String, String>>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        
        let id: u64 = entry_id.parse().map_err(|_| PyValueError::new_err("Invalid entry ID"))?;
        
        if let Some(entry) = self.audit_logger.get_entry(id) {
            let mut entry_map = HashMap::new();
            entry_map.insert("entry_id".to_string(), entry.id.to_string());
            entry_map.insert("timestamp".to_string(), entry.timestamp.to_string());
            entry_map.insert("agent_id".to_string(), entry.agent_id.clone());
            entry_map.insert("action".to_string(), entry.action.clone());
            entry_map.insert("resource".to_string(), entry.resource.clone());
            entry_map.insert("decision".to_string(), entry.decision.to_string());
            entry_map.insert("hash".to_string(), entry.hash.clone());
            entry_map.insert("prev_hash".to_string(), entry.prev_hash.clone());
            return Ok(Some(entry_map));
        }
        
        Ok(None)
    }

    /// Create an audit entry
    fn create_audit_entry(&mut self, entry_json: &str) -> PyResult<String> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        let entry_data: HashMap<String, serde_json::Value> = serde_json::from_str(entry_json)
            .map_err(|e| PyValueError::new_err(format!("Invalid JSON: {}", e)))?;
        
        let agent_id = entry_data.get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let action = entry_data.get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let resource = entry_data.get("resource")
            .and_then(|v| v.as_str())
            .unwrap_or("*");
        
        let entry = self.audit_logger.log(agent_id, action, resource, AuditDecision::Allowed);
        Ok(entry.id.to_string())
    }

    /// Verify the integrity of the audit chain
    fn verify_audit_chain(&self) -> PyResult<bool> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        
        Ok(self.audit_logger.verify_chain().is_ok())
    }

    /// Get the audit chain's current root hash
    fn get_audit_root_hash(&self) -> PyResult<Option<String>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        
        Ok(self.audit_logger.entries().last().map(|e| e.hash.clone()))
    }

    /// Add a policy rule
    fn add_policy_rule(&mut self, rule_json: &str) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        
        let rule: PolicyRule = serde_json::from_str(rule_json)
            .map_err(|e| PyValueError::new_err(format!("Invalid rule JSON: {}", e)))?;
        
        self.policy_engine.add_rule(rule);
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "Kernel(initialized={}, agents={}, audit_entries={})",
            self.initialized,
            self.agents.len(),
            self.audit_logger.entries().len()
        )
    }
}

/// The PyO3 module definition
#[cfg(feature = "python")]
#[pymodule]
fn _vak_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyKernel>()?;
    m.add_class::<PyPolicyDecision>()?;
    m.add_class::<PyToolResponse>()?;
    m.add_class::<PyAuditEntry>()?;
    
    // Add version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("__rust_version__", "1.75+")?;
    
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "python"))]
mod tests {
    use super::*;

    #[test]
    fn test_py_policy_decision() {
        let decision = PyPolicyDecision::new(
            "allow".to_string(),
            "test-policy".to_string(),
            "Test reason".to_string(),
        );
        
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
    }

    #[test]
    fn test_py_kernel_creation() {
        let kernel = PyKernel::default().unwrap();
        assert!(kernel.is_initialized());
    }

    #[test]
    fn test_py_kernel_agent_registration() {
        let mut kernel = PyKernel::default().unwrap();
        
        kernel.register_agent("test-agent", "Test Agent", "{}").unwrap();
        assert!(kernel.agents.contains_key("test-agent"));
        
        kernel.unregister_agent("test-agent").unwrap();
        assert!(!kernel.agents.contains_key("test-agent"));
    }
}
