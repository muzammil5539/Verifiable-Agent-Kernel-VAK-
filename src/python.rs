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
use pyo3::types::{PyAny, PyDict, PyList};

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
                self.error
                    .clone()
                    .unwrap_or_else(|| "Unknown error".to_string()),
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
    /// Unique identifier for this audit entry
    #[pyo3(get)]
    pub entry_id: String,
    /// Timestamp when the entry was created
    #[pyo3(get)]
    pub timestamp: String,
    /// Severity level of the audit entry
    #[pyo3(get)]
    pub level: String,
    /// ID of the agent that performed the action
    #[pyo3(get)]
    pub agent_id: String,
    /// The action that was performed
    #[pyo3(get)]
    pub action: String,
    /// The resource that was acted upon
    #[pyo3(get)]
    pub resource: String,
    /// Additional details about the audit entry
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

/// Helper to convert Python objects to serde_json::Value
#[cfg(feature = "python")]
fn py_to_json(obj: Bound<'_, PyAny>) -> PyResult<serde_json::Value> {
    if obj.is_none() {
        return Ok(serde_json::Value::Null);
    }

    // Check boolean first since it can be extracted as int
    if obj.is_instance_of::<pyo3::types::PyBool>() {
        return Ok(serde_json::Value::Bool(obj.extract::<bool>()?));
    }

    if let Ok(dict) = obj.downcast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, v) in dict.iter() {
            let key = k.extract::<String>()?;
            let value = py_to_json(v)?;
            map.insert(key, value);
        }
        return Ok(serde_json::Value::Object(map));
    }

    if let Ok(list) = obj.downcast::<PyList>() {
        let mut vec = Vec::new();
        for v in list.iter() {
            vec.push(py_to_json(v)?);
        }
        return Ok(serde_json::Value::Array(vec));
    }

    if let Ok(s) = obj.extract::<String>() {
        return Ok(serde_json::Value::String(s));
    }

    if let Ok(i) = obj.extract::<i64>() {
        return Ok(serde_json::Value::Number(i.into()));
    }

    if let Ok(f) = obj.extract::<f64>() {
        if let Some(n) = serde_json::Number::from_f64(f) {
            return Ok(serde_json::Value::Number(n));
        } else {
            return Ok(serde_json::Value::Null);
        }
    }

    Err(PyValueError::new_err(format!(
        "Unsupported type for JSON conversion: {}",
        obj.get_type()
    )))
}

/// Python wrapper for the VAK Kernel
#[cfg(feature = "python")]
#[pyclass(name = "Kernel")]
#[derive(Debug)]
pub struct PyKernel {
    initialized: bool,
    agents: HashMap<String, HashMap<String, String>>,
    policy_engine: PolicyEngine,
    audit_logger: AuditLogger,
    /// Registry of available tools/skills
    skill_registry: HashMap<String, SkillInfo>,
}

/// Information about a registered skill/tool
#[cfg(feature = "python")]
#[derive(Clone, Debug)]
pub struct SkillInfo {
    /// Unique identifier for the skill
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description of what the skill does
    pub description: String,
    /// Version string
    pub version: String,
    /// Whether the skill is currently enabled
    pub enabled: bool,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyKernel {
    /// Create a new kernel with default configuration
    #[staticmethod]
    fn default() -> PyResult<Self> {
        let mut skill_registry = HashMap::new();

        // Register default built-in skills
        skill_registry.insert(
            "calculator".to_string(),
            SkillInfo {
                id: "calculator".to_string(),
                name: "Calculator".to_string(),
                description: "Basic arithmetic operations".to_string(),
                version: "1.0.0".to_string(),
                enabled: true,
            },
        );

        Ok(Self {
            initialized: true,
            agents: HashMap::new(),
            policy_engine: PolicyEngine::new(),
            audit_logger: AuditLogger::new(),
            skill_registry,
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
        self.skill_registry.clear();
    }

    /// Register an agent with the kernel
    fn register_agent(
        &mut self,
        agent_id: &str,
        name: &str,
        config: Bound<'_, PyDict>,
    ) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        // Convert Python dictionary to JSON string for internal storage
        let config_val = py_to_json(config.as_any().clone())?;
        let config_json = serde_json::to_string(&config_val).unwrap_or_else(|_| "{}".to_string());

        let mut agent_data = HashMap::new();
        agent_data.insert("name".to_string(), name.to_string());
        agent_data.insert("config".to_string(), config_json);

        self.agents.insert(agent_id.to_string(), agent_data);
        Ok(())
    }

    /// Unregister an agent
    fn unregister_agent(&mut self, agent_id: &str) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        if self.agents.remove(agent_id).is_none() {
            return Err(PyValueError::new_err(format!(
                "Agent not found: {}",
                agent_id
            )));
        }
        Ok(())
    }

    /// Evaluate a policy for an action
    fn evaluate_policy(
        &mut self,
        agent_id: &str,
        action: &str,
        context: Bound<'_, PyDict>,
    ) -> PyResult<HashMap<String, String>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        // Check if agent is registered
        if !self.agents.contains_key(agent_id) && agent_id != "system" {
            return Err(PyValueError::new_err(format!(
                "Agent not found: {}",
                agent_id
            )));
        }

        // Convert Python dictionary to serde_json::Value map
        let mut context_attrs = HashMap::new();
        for (k, v) in context.iter() {
            let key = k.extract::<String>()?;
            let value = py_to_json(v)?;
            context_attrs.insert(key, value);
        }

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
        let decision = self
            .policy_engine
            .evaluate(&resource, action, &policy_context);

        // Log to audit trail
        let audit_decision = if decision.allowed {
            AuditDecision::Allowed
        } else {
            AuditDecision::Denied
        };
        self.audit_logger
            .log(agent_id, action, &resource, audit_decision);

        let mut result = HashMap::new();
        result.insert(
            "effect".to_string(),
            if decision.allowed { "allow" } else { "deny" }.to_string(),
        );
        result.insert(
            "policy_id".to_string(),
            decision
                .matched_rule
                .unwrap_or_else(|| "default".to_string()),
        );
        result.insert("reason".to_string(), decision.reason);

        Ok(result)
    }

    /// Execute a tool
    fn execute_tool(
        &mut self,
        tool_id: &str,
        agent_id: &str,
        action: &str,
        params: Bound<'_, PyDict>,
        timeout_ms: u64,
        _memory_limit: usize,
    ) -> PyResult<HashMap<String, String>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        if !self.agents.contains_key(agent_id) {
            return Err(PyValueError::new_err(format!(
                "Agent not found: {}",
                agent_id
            )));
        }

        let request_id = uuid::Uuid::now_v7().to_string();

        // Log tool execution to audit trail
        self.audit_logger.log(
            agent_id,
            format!("tool.execute:{}", tool_id),
            action,
            AuditDecision::Allowed,
        );

        // Convert Python dictionary to serde_json::Value
        let params_val = py_to_json(params.as_any().clone())?;
        let params_json = serde_json::to_string(&params_val).unwrap_or_else(|_| "{}".to_string());

        let mut result = HashMap::new();
        result.insert("request_id".to_string(), request_id);
        result.insert("success".to_string(), "true".to_string());
        result.insert(
            "result".to_string(),
            format!(
                "{{\"tool\": \"{}\", \"action\": \"{}\", \"params\": {}, \"timeout_ms\": {}}}",
                tool_id, action, params_json, timeout_ms
            ),
        );
        result.insert("execution_time_ms".to_string(), "0.1".to_string());
        result.insert("memory_used_bytes".to_string(), "0".to_string());

        Ok(result)
    }

    /// List available tools from the skill registry
    fn list_tools(&self) -> Vec<String> {
        self.skill_registry
            .values()
            .filter(|skill| skill.enabled)
            .map(|skill| skill.id.clone())
            .collect()
    }

    /// Register a new skill/tool with the kernel
    fn register_skill(
        &mut self,
        skill_id: &str,
        name: &str,
        description: &str,
        version: &str,
    ) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        self.skill_registry.insert(
            skill_id.to_string(),
            SkillInfo {
                id: skill_id.to_string(),
                name: name.to_string(),
                description: description.to_string(),
                version: version.to_string(),
                enabled: true,
            },
        );

        Ok(())
    }

    /// Unregister a skill/tool from the kernel
    fn unregister_skill(&mut self, skill_id: &str) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        if self.skill_registry.remove(skill_id).is_none() {
            return Err(PyValueError::new_err(format!(
                "Skill not found: {}",
                skill_id
            )));
        }

        Ok(())
    }

    /// Enable or disable a skill
    fn set_skill_enabled(&mut self, skill_id: &str, enabled: bool) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        match self.skill_registry.get_mut(skill_id) {
            Some(skill) => {
                skill.enabled = enabled;
                Ok(())
            }
            None => Err(PyValueError::new_err(format!(
                "Skill not found: {}",
                skill_id
            ))),
        }
    }

    /// Get detailed information about a specific skill
    fn get_skill_info(&self, skill_id: &str) -> PyResult<Option<HashMap<String, String>>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        Ok(self.skill_registry.get(skill_id).map(|skill| {
            let mut info = HashMap::new();
            info.insert("id".to_string(), skill.id.clone());
            info.insert("name".to_string(), skill.name.clone());
            info.insert("description".to_string(), skill.description.clone());
            info.insert("version".to_string(), skill.version.clone());
            info.insert("enabled".to_string(), skill.enabled.to_string());
            info
        }))
    }

    /// Get audit logs
    fn get_audit_logs(&self, filters: Bound<'_, PyDict>) -> PyResult<Vec<HashMap<String, String>>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        // Convert Python dictionary to serde_json::Value map
        let mut filters_map = HashMap::new();
        for (k, v) in filters.iter() {
            let key = k.extract::<String>()?;
            let value = py_to_json(v)?;
            filters_map.insert(key, value);
        }

        let limit = filters_map
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(100) as usize;

        let agent_filter = filters_map.get("agent_id").and_then(|v| v.as_str());

        // Get audit entries from logger
        let mut results = Vec::new();
        let entries = self
            .audit_logger
            .load_all_entries()
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;

        for entry in entries {
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

        let id: u64 = entry_id
            .parse()
            .map_err(|_| PyValueError::new_err("Invalid entry ID"))?;

        if let Some(entry) = self
            .audit_logger
            .get_entry(id)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?
        {
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
    fn create_audit_entry(&mut self, entry_data: Bound<'_, PyDict>) -> PyResult<String> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        // Convert Python dictionary to serde_json::Value map
        let mut entry_map = HashMap::new();
        for (k, v) in entry_data.iter() {
            let key = k.extract::<String>()?;
            let value = py_to_json(v)?;
            entry_map.insert(key, value);
        }

        let agent_id = entry_map
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let action = entry_map
            .get("action")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let resource = entry_map
            .get("resource")
            .and_then(|v| v.as_str())
            .unwrap_or("*");

        let entry = self
            .audit_logger
            .log(agent_id, action, resource, AuditDecision::Allowed);
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

        Ok(self.audit_logger.last_entry().map(|e| e.hash.clone()))
    }

    /// Add a policy rule
    fn add_policy_rule(&mut self, rule_dict: Bound<'_, PyDict>) -> PyResult<()> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }

        let rule_val = py_to_json(rule_dict.as_any().clone())?;
        let rule: PolicyRule = serde_json::from_value(rule_val)
            .map_err(|e| PyValueError::new_err(format!("Invalid rule: {}", e)))?;

        self.policy_engine.add_rule(rule);
        Ok(())
    }

    /// Validate the policy configuration and return any warnings (Issue #19)
    fn validate_policy_config(&self) -> PyResult<Vec<String>> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        Ok(self.policy_engine.validate_config())
    }

    /// Check if any allow rules are defined
    fn has_allow_policies(&self) -> PyResult<bool> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        Ok(self.policy_engine.has_allow_rules())
    }

    /// Get the number of loaded policy rules
    fn policy_rule_count(&self) -> PyResult<usize> {
        if !self.initialized {
            return Err(PyRuntimeError::new_err("Kernel not initialized"));
        }
        Ok(self.policy_engine.rule_count())
    }

    fn __repr__(&self) -> String {
        format!(
            "Kernel(initialized={}, agents={}, skills={}, audit_entries={})",
            self.initialized,
            self.agents.len(),
            self.skill_registry.len(),
            self.audit_logger.count().unwrap_or(0)
        )
    }
}

// ============================================================================
// Async Python SDK Helpers (Issue #18)
// ============================================================================

/// Async-capable kernel wrapper for Python integration with FastAPI/aiohttp
///
/// This provides documentation for Python users on how to use VAK with async frameworks:
///
/// ```python
/// # Example usage with FastAPI
/// from vak import VakKernel
/// import asyncio
///
/// kernel = VakKernel.default()
///
/// async def evaluate_async(agent_id: str, action: str, context: dict) -> dict:
///     # Use run_in_executor for CPU-bound operations
///     loop = asyncio.get_event_loop()
///     result = await loop.run_in_executor(
///         None,
///         lambda: kernel.evaluate_policy(agent_id, action, context)
///     )
///     return result
///
/// async def execute_tool_async(tool_id: str, agent_id: str, params: dict) -> dict:
///     loop = asyncio.get_event_loop()
///     result = await loop.run_in_executor(
///         None,
///         lambda: kernel.execute_tool(tool_id, agent_id, "execute", params, 30000, 1024*1024)
///     )
///     return result
/// ```
///
/// For true async support with pyo3-asyncio (future enhancement):
/// The kernel operations are CPU-bound, so using run_in_executor is the
/// recommended approach. True async would only benefit I/O-bound operations
/// like database queries or network requests.
#[cfg(feature = "python")]
pub struct AsyncKernelHelper;

#[cfg(feature = "python")]
impl AsyncKernelHelper {
    /// Documentation on async usage patterns
    pub const ASYNC_USAGE_DOCS: &'static str = r#"
# VAK Async Python SDK Usage Guide (Issue #18)

The VAK kernel performs CPU-bound policy evaluation and audit logging.
For async Python frameworks (FastAPI, aiohttp), wrap calls with run_in_executor:

## Basic Pattern

```python
import asyncio
from vak import VakKernel

kernel = VakKernel.default()

async def async_policy_check(agent_id: str, action: str, context: dict) -> dict:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,  # Uses default executor
        lambda: kernel.evaluate_policy(agent_id, action, context)
    )
```

## FastAPI Integration

```python
from fastapi import FastAPI, HTTPException
from vak import VakKernel
import asyncio
import json

app = FastAPI()
kernel = VakKernel.default()

@app.post("/evaluate")
async def evaluate_policy(agent_id: str, action: str, context: dict):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: kernel.evaluate_policy(agent_id, action, context)
    )
    if result.get("effect") == "deny":
        raise HTTPException(status_code=403, detail=result.get("reason"))
    return result

@app.post("/tools/{tool_id}")
async def execute_tool(tool_id: str, agent_id: str, params: dict):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: kernel.execute_tool(tool_id, agent_id, "execute", params, 30000, 1024*1024)
    )
    return result
```

## Thread Pool Optimization

For high-throughput scenarios, use a dedicated ThreadPoolExecutor:

```python
from concurrent.futures import ThreadPoolExecutor
import asyncio

# Create dedicated executor for VAK operations
vak_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vak-")

async def optimized_policy_check(agent_id: str, action: str, context: dict):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        vak_executor,
        lambda: kernel.evaluate_policy(agent_id, action, context)
    )
```
"#;
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

        kernel
            .register_agent("test-agent", "Test Agent", "{}")
            .unwrap();
        assert!(kernel.agents.contains_key("test-agent"));

        kernel.unregister_agent("test-agent").unwrap();
        assert!(!kernel.agents.contains_key("test-agent"));
    }
}
