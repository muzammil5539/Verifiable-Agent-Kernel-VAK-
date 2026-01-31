//! PyO3 Python Bindings for VAK (PY-001)
//!
//! This module provides Python bindings for the Verifiable Agent Kernel
//! using PyO3. It exposes the core functionality including:
//! - Kernel initialization and configuration
//! - Policy evaluation
//! - Tool execution
//! - Audit logging
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
        })
    }

    /// Create a kernel from a configuration file
    #[staticmethod]
    fn from_config(_path: &str) -> PyResult<Self> {
        // TODO: Implement config loading
        Self::default()
    }

    /// Check if the kernel is initialized
    fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Shutdown the kernel
    fn shutdown(&mut self) {
        self.initialized = false;
        self.agents.clear();
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
        &self,
        agent_id: &str,
        action: &str,
        _context_json: &str,
    ) -> PyResult<HashMap<String, String>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        // Check if agent is registered
        if !self.agents.contains_key(agent_id) && agent_id != "system" {
            return Err(PyValueError::new_err(format!("Agent not found: {}", agent_id)));
        }

        // Default allow for now - will integrate with Rust policy engine
        let mut result = HashMap::new();
        result.insert("effect".to_string(), "allow".to_string());
        result.insert("policy_id".to_string(), "default".to_string());
        result.insert("reason".to_string(), format!("Action '{}' allowed by default policy", action));
        
        Ok(result)
    }

    /// Execute a tool
    fn execute_tool(
        &self,
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

        let request_id = format!("{}-{}-{}", tool_id, agent_id, action);
        
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
    fn get_audit_logs(&self, _filters_json: &str) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        
        // TODO: Integrate with audit system
        Ok(Vec::new())
    }

    /// Get a specific audit entry
    fn get_audit_entry(&self, _entry_id: &str) -> PyResult<Option<HashMap<String, String>>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        
        Ok(None)
    }

    /// Create an audit entry
    fn create_audit_entry(&self, _entry_json: &str) -> PyResult<String> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        let entry_id = uuid::Uuid::now_v7().to_string();
        Ok(entry_id)
    }

    fn __repr__(&self) -> String {
        format!(
            "Kernel(initialized={}, agents={})",
            self.initialized,
            self.agents.len()
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
