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
use pyo3::types::{PyAny, PyDict, PyList, PyTuple};

#[cfg(feature = "python")]
use pyo3::exceptions::{PyPermissionError, PyRuntimeError, PyValueError};

#[cfg(feature = "python")]
use std::collections::HashMap;
#[cfg(feature = "python")]
use std::sync::Arc;

#[cfg(feature = "python")]
use crate::kernel::types::{AgentId, KernelError, PolicyDecision, SessionId, ToolRequest};
#[cfg(feature = "python")]
use crate::kernel::{AgentRecord, Kernel, KernelConfig};

/// Python-visible risk level classification for tools and operations.
///
/// Mirrors the Rust `RiskLevel` enum as a Python class with string constants.
/// Python users compare risk levels with `RiskLevel.LOW`, `RiskLevel.HIGH`, etc.
///
/// # Python Example
///
/// ```python
/// from vak._vak_native import RiskLevel
///
/// if tool_risk == RiskLevel.HIGH:
///     require_human_approval()
/// ```
#[cfg(feature = "python")]
#[pyclass(name = "RiskLevel", skip_from_py_object)]
#[derive(Clone, Debug)]
pub struct PyRiskLevel;

#[cfg(feature = "python")]
#[pymethods]
impl PyRiskLevel {
    /// Read-only, safe operations.
    #[classattr]
    const LOW: &'static str = "low";

    /// May modify state.
    #[classattr]
    const MEDIUM: &'static str = "medium";

    /// Sensitive operations.
    #[classattr]
    const HIGH: &'static str = "high";

    /// Irreversible or security-critical operations.
    #[classattr]
    const CRITICAL: &'static str = "critical";

    fn __repr__(&self) -> String {
        "RiskLevel(LOW | MEDIUM | HIGH | CRITICAL)".to_string()
    }
}

/// Python wrapper for PolicyDecision
#[cfg(feature = "python")]
#[pyclass(name = "PolicyDecision", skip_from_py_object)]
#[derive(Clone)]
pub struct PyPolicyDecision {
    /// The effect of the decision (allow/deny)
    #[pyo3(get)]
    pub effect: String,
    /// The ID of the policy that made the decision
    #[pyo3(get)]
    pub policy_id: String,
    /// The reason for the decision
    #[pyo3(get)]
    pub reason: String,
    /// List of matched rule IDs
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
#[pyclass(name = "ToolResponse", skip_from_py_object)]
#[derive(Clone)]
pub struct PyToolResponse {
    /// Unique request identifier
    #[pyo3(get)]
    pub request_id: String,
    /// Whether execution was successful
    #[pyo3(get)]
    pub success: bool,
    /// The result string (if successful)
    #[pyo3(get)]
    pub result: Option<String>,
    /// The error message (if failed)
    #[pyo3(get)]
    pub error: Option<String>,
    /// Execution time in milliseconds
    #[pyo3(get)]
    pub execution_time_ms: f64,
    /// Memory used in bytes
    #[pyo3(get)]
    pub memory_used_bytes: usize,
    /// Audit trail for this execution
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
#[pyclass(name = "AuditEntry", skip_from_py_object)]
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

    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = serde_json::Map::new();
        for (k, v) in dict.iter() {
            // Mirror Python's json.dumps behavior: coerce dict keys via str(k)
            let key = k
                .str()?
                .to_str()
                .map_err(|e| {
                    PyValueError::new_err(format!(
                        "Dictionary key must be convertible to valid UTF-8 string: {}",
                        e
                    ))
                })?
                .to_owned();
            let value = py_to_json(v)?;
            map.insert(key, value);
        }
        return Ok(serde_json::Value::Object(map));
    }

    if let Ok(list) = obj.cast::<PyList>() {
        let mut vec = Vec::new();
        for v in list.iter() {
            vec.push(py_to_json(v)?);
        }
        return Ok(serde_json::Value::Array(vec));
    }

    // Handle tuples like lists (matching json.dumps behavior)
    if let Ok(tuple) = obj.cast::<PyTuple>() {
        let mut vec = Vec::new();
        for v in tuple.iter() {
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

    // Try u64 for large positive integers before falling back to f64
    if let Ok(u) = obj.extract::<u64>() {
        return Ok(serde_json::Value::Number(u.into()));
    }

    if let Ok(f) = obj.extract::<f64>() {
        if f.is_finite() {
            if let Some(n) = serde_json::Number::from_f64(f) {
                return Ok(serde_json::Value::Number(n));
            } else {
                // This should theoretically never occur for finite floats, but handle it defensively
                return Err(PyValueError::new_err(format!(
                    "Unexpected error: failed to convert finite float ({}) to JSON number",
                    f
                )));
            }
        }
        // Raise error for non-finite floats instead of silently converting to null
        return Err(PyValueError::new_err(format!(
            "Non-finite float value ({}) cannot be converted to JSON",
            f
        )));
    }

    Err(PyValueError::new_err(format!(
        "Unsupported type for JSON conversion: {}",
        obj.get_type()
    )))
}

/// The memory limit, in MiB, [`PyKernel::default`] gives every WASM skill:
/// the Python SDK's default `memory_limit_bytes` for an agent.
///
/// The kernel takes no per-call memory limit, so `execute_tool` refuses a
/// call that asks for less than the kernel enforces rather than run it
/// under a looser limit than asked.
#[cfg(feature = "python")]
pub const NATIVE_SKILL_MEMORY_MB: u64 = 128;

/// An agent registered with the native kernel: the kernel's identity for
/// it, and the session its calls run in.
#[cfg(feature = "python")]
#[derive(Debug, Clone)]
struct NativeAgent {
    id: AgentId,
    session: SessionId,
}

/// Python wrapper for the VAK Kernel.
///
/// Every method that answers with a policy decision, an audit record or a
/// skill answers from one [`Kernel`]: its policy decision point, its audit
/// log and its skill registry (finding I4, ADR 0011). The binding keeps no
/// policy engine, audit log or skill registry of its own.
#[cfg(feature = "python")]
#[pyclass(name = "Kernel")]
#[derive(Debug)]
pub struct PyKernel {
    initialized: bool,
    /// The kernel every method answers from.
    kernel: Arc<Kernel>,
    /// Runs the kernel's async API under Python's synchronous calls.
    runtime: Arc<tokio::runtime::Runtime>,
    /// Agents registered here, by the ID Python knows them by.
    agents: HashMap<String, NativeAgent>,
}

/// Starts a runtime and, on it, a kernel configured by `config`.
#[cfg(feature = "python")]
fn native_kernel(config: KernelConfig) -> PyResult<(Arc<tokio::runtime::Runtime>, Arc<Kernel>)> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("vak-python")
        .enable_all()
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to start the kernel runtime: {e}")))?;
    let kernel = runtime
        .block_on(Kernel::new(config))
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to start the kernel: {e}")))?;
    Ok((Arc::new(runtime), Arc::new(kernel)))
}

/// Converts a JSON value to the Python object `json.loads` would give.
#[cfg(feature = "python")]
fn json_to_py<'py>(py: Python<'py>, value: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    let text = serde_json::to_string(value)
        .map_err(|e| PyValueError::new_err(format!("Failed to serialize result: {e}")))?;
    py.import("json")?.call_method1("loads", (text,))
}

/// A kernel policy decision as the SDK's dict: `effect` ("allow" or
/// "deny"), `policy_id` and `reason`. An allow names the decision point
/// that made it; a denial names the policy it violated, if the decision
/// point said.
#[cfg(feature = "python")]
fn decision_json(decision: &PolicyDecision, decided_by: &str) -> serde_json::Value {
    let (effect, policy_id, reason) = match decision {
        PolicyDecision::Allow { reason, .. } => ("allow", decided_by.to_string(), reason.clone()),
        PolicyDecision::Deny {
            reason,
            violated_policies,
        } => (
            "deny",
            violated_policies
                .as_ref()
                .and_then(|ids| ids.first().cloned())
                .unwrap_or_else(|| decided_by.to_string()),
            reason.clone(),
        ),
        PolicyDecision::Inadmissible { reason } => ("deny", decided_by.to_string(), reason.clone()),
    };
    serde_json::json!({"effect": effect, "policy_id": policy_id, "reason": reason})
}

#[cfg(feature = "python")]
impl PyKernel {
    fn from_kernel(runtime: Arc<tokio::runtime::Runtime>, kernel: Arc<Kernel>) -> Self {
        Self {
            initialized: true,
            kernel,
            runtime,
            agents: HashMap::new(),
        }
    }

    fn ensure_initialized(&self) -> PyResult<()> {
        if self.initialized {
            Ok(())
        } else {
            Err(PyRuntimeError::new_err("Kernel not initialized"))
        }
    }

    fn agent(&self, agent_id: &str) -> PyResult<NativeAgent> {
        self.agents
            .get(agent_id)
            .cloned()
            .ok_or_else(|| PyValueError::new_err(format!("Agent not found: {agent_id}")))
    }

    /// The ID Python knows a kernel agent by, or the kernel's own.
    fn python_agent_id(&self, id: &AgentId) -> String {
        self.agents
            .iter()
            .find(|(_, agent)| agent.id == *id)
            .map_or_else(|| id.to_string(), |(name, _)| name.clone())
    }

    /// A kernel audit entry as the SDK's dict.
    ///
    /// Every entry is a tool call: `action` and `resource` are the tool. A
    /// decision entry has `kind` "decision"; an outcome entry has `kind`
    /// "outcome", its decision's id as `parent_entry_id`, and what happened
    /// in `details.outcome`. `level` is derived: "warning" for a refusal,
    /// "error" for a tool that ran and failed, "info" otherwise.
    fn entry_json(
        &self,
        entries: &[crate::kernel::types::AuditEntry],
        index: usize,
        decided_by: &str,
    ) -> serde_json::Value {
        let entry = &entries[index];
        let (kind, level, parent) = match &entry.outcome {
            Some(outcome) => (
                "outcome",
                if outcome.success { "info" } else { "error" },
                usize::try_from(outcome.decision_leaf)
                    .ok()
                    .and_then(|leaf| entries.get(leaf))
                    .map(|decision| decision.audit_id.to_string()),
            ),
            None => (
                "decision",
                if entry.decision.is_allowed() {
                    "info"
                } else {
                    "warning"
                },
                None,
            ),
        };
        serde_json::json!({
            "entry_id": entry.audit_id.to_string(),
            "timestamp": entry.timestamp.to_rfc3339(),
            "level": level,
            "agent_id": self.python_agent_id(&entry.agent_id),
            "action": entry.action,
            "resource": entry.action,
            "policy_decision": decision_json(&entry.decision, decided_by),
            "details": {
                "kind": kind,
                "leaf_index": index,
                "kernel_agent_id": entry.agent_id.to_string(),
                "session_id": entry.session_id.to_string(),
                "hash": entry.hash,
                "previous_hash": entry.previous_hash,
                "outcome": entry.outcome,
            },
            "parent_entry_id": parent,
        })
    }
}

#[cfg(feature = "python")]
#[pymethods]
impl PyKernel {
    /// A kernel with the default configuration, except that WASM skills get
    /// [`NATIVE_SKILL_MEMORY_MB`] of memory.
    #[staticmethod]
    fn default() -> PyResult<Self> {
        let mut config = KernelConfig::default();
        config.resources.max_memory_mb = NATIVE_SKILL_MEMORY_MB;
        let (runtime, kernel) = native_kernel(config)?;
        Ok(Self::from_kernel(runtime, kernel))
    }

    /// A kernel configured by the file at `path` (YAML or JSON, as
    /// `KernelConfig::from_file` reads): its policies, skills and limits.
    ///
    /// # Errors
    ///
    /// `ValueError` if the file can't be read or parsed. There is no
    /// fallback to the default configuration.
    #[staticmethod]
    fn from_config(path: &str) -> PyResult<Self> {
        let config = KernelConfig::from_file(path).map_err(|e| {
            PyValueError::new_err(format!("Failed to load kernel config '{path}': {e}"))
        })?;
        let (runtime, kernel) = native_kernel(config)?;
        Ok(Self::from_kernel(runtime, kernel))
    }

    /// A kernel with the default configuration and these settings from the
    /// SDK's `KernelConfig`, as a dict. Each key that is present is applied:
    ///
    /// - `name`
    /// - `allowed_tools` (a non-empty list replaces the default allowlist of
    ///   built-in tools), `blocked_tools`
    /// - `default_decision` ("allow" or "deny"), `policy_enabled`,
    ///   `policy_paths` (YAML policy files)
    /// - `enable_sandboxing`, `allow_unsigned_skills`
    /// - `timeout_ms` (the kernel's time limit), `skill_memory_mb`
    /// - `max_requests_per_minute`
    /// - `audit_log_path`
    ///
    /// # Errors
    ///
    /// `ValueError` for an unknown key or a value of the wrong type, so a
    /// setting is never silently dropped.
    #[staticmethod]
    fn from_settings(settings: Bound<'_, PyDict>) -> PyResult<Self> {
        let settings = py_to_json(settings.as_any().clone())?;
        let serde_json::Value::Object(settings) = settings else {
            return Err(PyValueError::new_err("settings must be a dict"));
        };
        let mut config = KernelConfig::default();
        config.resources.max_memory_mb = NATIVE_SKILL_MEMORY_MB;

        let bad = |key: &str, want: &str| {
            PyValueError::new_err(format!("setting '{key}' must be {want}"))
        };
        let strings = |key: &str, value: &serde_json::Value| -> PyResult<Vec<String>> {
            value
                .as_array()
                .and_then(|items| {
                    items
                        .iter()
                        .map(|i| i.as_str().map(str::to_string))
                        .collect()
                })
                .ok_or_else(|| bad(key, "a list of strings"))
        };
        for (key, value) in &settings {
            match key.as_str() {
                "name" => {
                    config.name = value
                        .as_str()
                        .ok_or_else(|| bad(key, "a string"))?
                        .to_string();
                }
                "allowed_tools" => {
                    let tools = strings(key, value)?;
                    if !tools.is_empty() {
                        config.security.allowed_tools = tools;
                    }
                }
                "blocked_tools" => config.security.blocked_tools = strings(key, value)?,
                "default_decision" => {
                    config.policy.default_decision = match value.as_str() {
                        Some("allow") => crate::kernel::DefaultPolicyDecision::Allow,
                        Some("deny") => crate::kernel::DefaultPolicyDecision::Deny,
                        _ => return Err(bad(key, "\"allow\" or \"deny\"")),
                    };
                }
                "policy_enabled" => {
                    config.policy.enabled = value.as_bool().ok_or_else(|| bad(key, "a bool"))?;
                }
                "policy_paths" => {
                    config.policy.policy_paths =
                        strings(key, value)?.into_iter().map(Into::into).collect();
                }
                "enable_sandboxing" => {
                    config.security.enable_sandboxing =
                        value.as_bool().ok_or_else(|| bad(key, "a bool"))?;
                }
                "allow_unsigned_skills" => {
                    config.security.allow_unsigned_skills =
                        value.as_bool().ok_or_else(|| bad(key, "a bool"))?;
                }
                "timeout_ms" => {
                    let ms = value
                        .as_u64()
                        .filter(|ms| *ms > 0)
                        .ok_or_else(|| bad(key, "a positive integer"))?;
                    config.max_execution_time = std::time::Duration::from_millis(ms);
                }
                "skill_memory_mb" => {
                    config.resources.max_memory_mb = value
                        .as_u64()
                        .filter(|mb| *mb > 0)
                        .ok_or_else(|| bad(key, "a positive integer"))?;
                }
                "max_requests_per_minute" => {
                    let rate = value
                        .as_u64()
                        .and_then(|n| u32::try_from(n).ok())
                        .filter(|n| *n > 0)
                        .ok_or_else(|| bad(key, "a positive integer"))?;
                    config.security.enable_rate_limiting = true;
                    config.security.max_requests_per_minute = rate;
                }
                "audit_log_path" => {
                    config.audit.log_path =
                        Some(value.as_str().ok_or_else(|| bad(key, "a string"))?.into());
                }
                other => {
                    return Err(PyValueError::new_err(format!(
                        "unknown kernel setting '{other}'"
                    )));
                }
            }
        }
        let (runtime, kernel) = native_kernel(config)?;
        Ok(Self::from_kernel(runtime, kernel))
    }

    /// Check if the kernel is initialized
    fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Shutdown the kernel
    fn shutdown(&mut self) {
        self.initialized = false;
        for agent in self.agents.drain().map(|(_, agent)| agent) {
            self.runtime
                .block_on(self.kernel.end_session(&agent.session));
        }
    }

    /// Register an agent with the kernel.
    ///
    /// The kernel knows the agent by an ID of its own. From `config`:
    /// `allowed_tools`, if not empty, limits the agent to those tools;
    /// `role` and `attributes` become attributes policy can read
    /// (`principal.role`, `principal.<key>`). Re-registering an agent
    /// replaces it.
    fn register_agent(
        &mut self,
        agent_id: &str,
        name: &str,
        config: Bound<'_, PyDict>,
    ) -> PyResult<()> {
        self.ensure_initialized()?;
        let config = py_to_json(config.as_any().clone())?;

        let mut record = AgentRecord::new(AgentId::new(), name);
        if let Some(tools) = config.get("allowed_tools").and_then(|v| v.as_array()) {
            if !tools.is_empty() {
                let tools: Vec<String> = tools
                    .iter()
                    .map(|t| {
                        t.as_str().map(str::to_string).ok_or_else(|| {
                            PyValueError::new_err("allowed_tools must be a list of strings")
                        })
                    })
                    .collect::<PyResult<_>>()?;
                record = record.with_allowed_tools(tools);
            }
        }
        if let Some(role) = config.get("role").and_then(|v| v.as_str()) {
            record = record.with_attribute("role", role);
        }
        if let Some(attributes) = config.get("attributes").and_then(|v| v.as_object()) {
            for (key, value) in attributes {
                record = record.with_attribute(key.clone(), value.clone());
            }
        }

        let native = NativeAgent {
            id: record.id,
            session: SessionId::new(),
        };
        self.runtime
            .block_on(self.kernel.register_agent(record))
            .map_err(|e| PyRuntimeError::new_err(format!("The kernel refused the agent: {e}")))?;
        if let Some(old) = self.agents.insert(agent_id.to_string(), native) {
            self.runtime.block_on(self.kernel.end_session(&old.session));
        }
        Ok(())
    }

    /// Unregister an agent
    fn unregister_agent(&mut self, agent_id: &str) -> PyResult<()> {
        self.ensure_initialized()?;
        let agent = self
            .agents
            .remove(agent_id)
            .ok_or_else(|| PyValueError::new_err(format!("Agent not found: {agent_id}")))?;
        self.runtime
            .block_on(self.kernel.end_session(&agent.session));
        Ok(())
    }

    /// Ask the kernel whether `agent_id` may call the tool `action` with
    /// `context` as its parameters ([`Kernel::evaluate_policy`]).
    ///
    /// This is the Decide stage of `execute_tool` alone: nothing runs and
    /// nothing is recorded. `execute_tool` sends a tool
    /// `{"action": ..., "params": ...}`, so to ask about exactly that call,
    /// pass those as `context`.
    ///
    /// Returns a dict with `effect` ("allow" or "deny"), `policy_id` and
    /// `reason`.
    fn evaluate_policy<'py>(
        &mut self,
        py: Python<'py>,
        agent_id: &str,
        action: &str,
        context: Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.ensure_initialized()?;
        let agent = self.agent(agent_id)?;
        let request = ToolRequest::new(action, py_to_json(context.as_any().clone())?);
        let decision = self
            .runtime
            .block_on(self.kernel.evaluate_policy(&agent.id, &request));
        json_to_py(
            py,
            &decision_json(&decision, self.kernel.policy_decision_point().name()),
        )
    }

    /// Execute a tool through the kernel ([`Kernel::execute`]).
    ///
    /// The tool gets `{"action": action, "params": params}`, the shape WASM
    /// skills take. The kernel's policy decides, its audit log records the
    /// decision before the tool runs and the outcome after, and the call
    /// stops at `timeout_ms` or the kernel's own limit, whichever is sooner.
    ///
    /// Returns a dict with `request_id`, `success`, `result` (the tool's
    /// output as a Python object), `error`, `execution_time_ms` and `receipt`
    /// (the kernel's audit receipt). A tool that ran and failed has
    /// `success` false and an `error`.
    ///
    /// # Errors
    ///
    /// Nothing runs, and the call raises:
    /// - `PermissionError` with args `(policy_id, reason)` if the kernel's
    ///   policy refuses it;
    /// - `ValueError` if the agent isn't registered, or if `memory_limit` is
    ///   below the memory the kernel gives every skill;
    /// - `RuntimeError` if the kernel refuses it for any other reason, such
    ///   as an unknown tool.
    #[allow(clippy::too_many_arguments)]
    fn execute_tool<'py>(
        &mut self,
        py: Python<'py>,
        tool_id: &str,
        agent_id: &str,
        action: &str,
        params: Bound<'py, PyDict>,
        timeout_ms: u64,
        memory_limit: u64,
    ) -> PyResult<Bound<'py, PyDict>> {
        self.ensure_initialized()?;
        let agent = self.agent(agent_id)?;

        let kernel_mb = self.kernel.config().resources.max_memory_mb;
        if memory_limit < kernel_mb.saturating_mul(1024 * 1024) {
            return Err(PyValueError::new_err(format!(
                "memory_limit of {memory_limit} bytes is below the {kernel_mb} MiB \
                 the kernel gives every skill; it can't run a call under a tighter limit, \
                 so nothing ran"
            )));
        }

        let params_val = py_to_json(params.as_any().clone())?;
        let request = ToolRequest::new(
            tool_id,
            serde_json::json!({"action": action, "params": params_val}),
        )
        .with_timeout(timeout_ms);

        // Release the GIL while the tool runs.
        let (kernel, runtime) = (Arc::clone(&self.kernel), Arc::clone(&self.runtime));
        let outcome =
            py.detach(move || runtime.block_on(kernel.execute(&agent.id, &agent.session, request)));

        let response = match outcome {
            Ok(response) => response,
            Err(KernelError::PolicyViolation { reason, policy_id }) => {
                return Err(PyPermissionError::new_err((policy_id, reason)));
            }
            Err(e) => return Err(PyRuntimeError::new_err(e.to_string())),
        };

        let result = PyDict::new(py);
        result.set_item("request_id", response.request_id.to_string())?;
        result.set_item("success", response.success)?;
        result.set_item(
            "result",
            json_to_py(
                py,
                response.result.as_ref().unwrap_or(&serde_json::Value::Null),
            )?,
        )?;
        result.set_item("error", response.error)?;
        result.set_item("execution_time_ms", response.execution_time_ms)?;
        let receipt = serde_json::to_value(&response.receipt)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize receipt: {e}")))?;
        result.set_item("receipt", json_to_py(py, &receipt)?)?;
        Ok(result)
    }

    /// The kernel's tools: built-ins, registered host handlers and loaded
    /// WASM skills ([`Kernel::list_tools`]).
    fn list_tools(&self) -> PyResult<Vec<String>> {
        self.ensure_initialized()?;
        Ok(self.runtime.block_on(self.kernel.list_tools()))
    }

    /// The loaded WASM skills' names.
    fn list_skills(&self) -> PyResult<Vec<String>> {
        self.ensure_initialized()?;
        #[cfg(feature = "wasm")]
        {
            let kernel = &self.kernel;
            Ok(self.runtime.block_on(async {
                let mut skills = Vec::new();
                for tool in kernel.list_tools().await {
                    if kernel.skill_manifest(&tool).await.is_some() {
                        skills.push(tool);
                    }
                }
                skills
            }))
        }
        #[cfg(not(feature = "wasm"))]
        Ok(Vec::new())
    }

    /// Load a WASM skill from its manifest file ([`Kernel::load_skill`]),
    /// verified as at startup. Returns its name. Loading authorizes no one;
    /// the kernel's policy still decides every call.
    ///
    /// # Errors
    ///
    /// `ValueError` if the manifest or module can't be read or doesn't
    /// verify. Nothing is loaded.
    fn load_skill(&self, manifest_path: &str) -> PyResult<String> {
        self.ensure_initialized()?;
        #[cfg(feature = "wasm")]
        {
            self.runtime
                .block_on(self.kernel.load_skill(std::path::Path::new(manifest_path)))
                .map_err(|e| PyValueError::new_err(e.to_string()))
        }
        #[cfg(not(feature = "wasm"))]
        Err(PyRuntimeError::new_err(format!(
            "cannot load '{manifest_path}': this build has no WASM sandbox (feature `wasm`)"
        )))
    }

    /// The manifest of the loaded skill called `name`, as a dict, or None.
    fn get_skill<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.ensure_initialized()?;
        #[cfg(feature = "wasm")]
        {
            match self.runtime.block_on(self.kernel.skill_manifest(name)) {
                Some(manifest) => {
                    let value = serde_json::to_value(&manifest).map_err(|e| {
                        PyValueError::new_err(format!("Failed to serialize manifest: {e}"))
                    })?;
                    Ok(Some(json_to_py(py, &value)?))
                }
                None => Ok(None),
            }
        }
        #[cfg(not(feature = "wasm"))]
        {
            let _ = (py, name);
            Ok(None)
        }
    }

    /// The kernel's audit log, as dicts, oldest first.
    ///
    /// `filters` may set `agent_id`, `action` (a tool name), `level`,
    /// `limit` (default 100) and `offset`.
    fn get_audit_logs<'py>(
        &self,
        py: Python<'py>,
        filters: Bound<'py, PyDict>,
    ) -> PyResult<Vec<Bound<'py, PyAny>>> {
        self.ensure_initialized()?;
        let filters = py_to_json(filters.as_any().clone())?;
        let wanted = |key: &str| {
            filters
                .get(key)
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };
        let (agent, action, level) = (wanted("agent_id"), wanted("action"), wanted("level"));
        let count = |key: &str, default: usize| {
            filters
                .get(key)
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(default)
        };
        let (limit, offset) = (count("limit", 100), count("offset", 0));

        let entries = self.runtime.block_on(self.kernel.get_audit_log());
        let decided_by = self.kernel.policy_decision_point().name();
        (0..entries.len())
            .map(|i| self.entry_json(&entries, i, decided_by))
            .filter(|e| {
                agent.as_deref().is_none_or(|a| e["agent_id"] == a)
                    && action.as_deref().is_none_or(|a| e["action"] == a)
                    && level.as_deref().is_none_or(|l| e["level"] == l)
            })
            .skip(offset)
            .take(limit)
            .map(|e| json_to_py(py, &e))
            .collect()
    }

    /// The kernel audit entry with this id, as a dict, or None.
    fn get_audit_entry<'py>(
        &self,
        py: Python<'py>,
        entry_id: &str,
    ) -> PyResult<Option<Bound<'py, PyAny>>> {
        self.ensure_initialized()?;
        let entries = self.runtime.block_on(self.kernel.get_audit_log());
        let decided_by = self.kernel.policy_decision_point().name();
        entries
            .iter()
            .position(|e| e.audit_id.to_string() == entry_id)
            .map(|i| json_to_py(py, &self.entry_json(&entries, i, decided_by)))
            .transpose()
    }

    /// Whether the kernel's audit chain verifies: no entry altered,
    /// reordered or spliced in ([`Kernel::verify_audit_chain`]).
    fn verify_audit_chain(&self) -> PyResult<bool> {
        self.ensure_initialized()?;
        Ok(self
            .runtime
            .block_on(self.kernel.verify_audit_chain())
            .is_ok())
    }

    /// The root of the kernel's audit Merkle tree, as hex (RFC 9162; the
    /// SHA-256 of nothing for an empty log).
    fn get_audit_root_hash(&self) -> PyResult<String> {
        self.ensure_initialized()?;
        Ok(self
            .runtime
            .block_on(self.kernel.audit_tree_head())
            .head
            .root
            .to_hex())
    }

    /// The kernel's signed audit tree head, as a dict: the tree's `size`
    /// and `root`, `timestamp_ms`, the Ed25519 `signature` and the
    /// `public_key` that verifies it ([`Kernel::audit_tree_head`]).
    /// Anyone holding one can later demand proof that the log only grew.
    fn export_audit_receipt<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        self.ensure_initialized()?;
        let head = self.runtime.block_on(self.kernel.audit_tree_head());
        let value = serde_json::to_value(&head)
            .map_err(|e| PyValueError::new_err(format!("Failed to serialize tree head: {e}")))?;
        json_to_py(py, &value)
    }

    fn __repr__(&self) -> String {
        format!(
            "Kernel(initialized={}, agents={}, policy={})",
            self.initialized,
            self.agents.len(),
            self.kernel.policy_decision_point().name()
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
///         lambda: kernel.execute_tool(tool_id, agent_id, "execute", params, 30000, 128 * 1024 * 1024)
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
        lambda: kernel.execute_tool(tool_id, agent_id, "execute", params, 30000, 128 * 1024 * 1024)
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
    m.add_class::<PyRiskLevel>()?;

    // Add version info
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add(
        "__rust_version__",
        format!("{}+", env!("CARGO_PKG_RUST_VERSION")),
    )?;

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

    fn get(dict: &Bound<'_, PyAny>, key: &str) -> serde_json::Value {
        py_to_json(dict.get_item(key).unwrap()).unwrap()
    }

    /// A registered agent's call runs through `Kernel::execute`: the tool
    /// runs, and the kernel records the decision and the outcome, which the
    /// audit-log methods then read back.
    #[test]
    fn execute_tool_runs_through_the_kernel() {
        Python::initialize();

        Python::attach(|py| {
            let mut kernel = PyKernel::default().unwrap();
            kernel
                .register_agent("agent-1", "Agent One", PyDict::new(py))
                .unwrap();
            let params = PyDict::new(py);
            params.set_item("text", "hello").unwrap();

            let result = kernel
                .execute_tool(py, "echo", "agent-1", "say", params, 5_000, 128 << 20)
                .unwrap();
            let result = result.as_any();
            assert_eq!(get(result, "success"), serde_json::json!(true));
            assert_eq!(
                get(result, "result"),
                serde_json::json!({"action": "say", "params": {"text": "hello"}})
            );
            assert_eq!(get(result, "receipt")["outcome_leaf"], 1);

            // The audit-log methods read the kernel's log.
            let logs = kernel.get_audit_logs(py, PyDict::new(py)).unwrap();
            assert_eq!(logs.len(), 2, "a decision leaf and an outcome leaf");
            let (decision, outcome) = (
                py_to_json(logs[0].clone()).unwrap(),
                py_to_json(logs[1].clone()).unwrap(),
            );
            assert_eq!(decision["agent_id"], "agent-1");
            assert_eq!(decision["action"], "echo");
            assert_eq!(decision["policy_decision"]["effect"], "allow");
            assert_eq!(outcome["details"]["kind"], "outcome");
            assert_eq!(outcome["parent_entry_id"], decision["entry_id"]);
            let entry_id = decision["entry_id"].as_str().unwrap();
            assert!(kernel.get_audit_entry(py, entry_id).unwrap().is_some());
            assert!(kernel.verify_audit_chain().unwrap());

            // The root and the receipt are the kernel's signed tree head.
            let head = kernel.runtime.block_on(kernel.kernel.audit_tree_head());
            assert_eq!(
                kernel.get_audit_root_hash().unwrap(),
                head.head.root.to_hex()
            );
            let receipt = kernel.export_audit_receipt(py).unwrap();
            assert_eq!(get(&receipt, "head")["size"], 2);
            let native = kernel.agents["agent-1"].clone();
            let log = kernel.runtime.block_on(kernel.kernel.get_audit_log());
            assert!(log.iter().all(|entry| entry.agent_id == native.id));
        });
    }

    /// `evaluate_policy` is the kernel's Decide stage: the same answer
    /// `execute_tool` gets, without running or recording anything.
    #[test]
    fn evaluate_policy_asks_the_kernel() {
        Python::initialize();

        Python::attach(|py| {
            let mut kernel = PyKernel::default().unwrap();
            let config = PyDict::new(py);
            config
                .set_item("allowed_tools", vec!["calculator"])
                .unwrap();
            kernel.register_agent("narrow", "Narrow", config).unwrap();
            kernel
                .register_agent("agent-1", "Agent One", PyDict::new(py))
                .unwrap();
            let ask = |kernel: &mut PyKernel, agent: &str, tool: &str| {
                py_to_json(
                    kernel
                        .evaluate_policy(py, agent, tool, PyDict::new(py))
                        .unwrap(),
                )
                .unwrap()
            };

            assert_eq!(ask(&mut kernel, "agent-1", "echo")["effect"], "allow");
            let unknown = ask(&mut kernel, "agent-1", "no_such_tool");
            assert_eq!(unknown["effect"], "deny");
            assert!(!unknown["reason"].as_str().unwrap().is_empty());
            // allowed_tools reaches the kernel as the agent's scope, which
            // execute_tool enforces at admission.
            let narrowed = kernel
                .execute_tool(
                    py,
                    "echo",
                    "narrow",
                    "say",
                    PyDict::new(py),
                    5_000,
                    128 << 20,
                )
                .unwrap_err();
            assert!(
                narrowed.is_instance_of::<PyPermissionError>(py),
                "{narrowed}"
            );
            assert!(kernel
                .evaluate_policy(py, "nobody", "echo", PyDict::new(py))
                .is_err());

            let log = kernel.runtime.block_on(kernel.kernel.get_audit_log());
            assert_eq!(log.len(), 1, "only the executed call is recorded");
        });
    }

    /// Nothing is reported as run that didn't run.
    #[test]
    fn execute_tool_fails_closed() {
        Python::initialize();

        Python::attach(|py| {
            let mut kernel = PyKernel::default().unwrap();
            kernel
                .register_agent("agent-1", "Agent One", PyDict::new(py))
                .unwrap();
            let run = |kernel: &mut PyKernel, tool: &str, agent: &str, memory: u64| {
                kernel.execute_tool(py, tool, agent, "run", PyDict::new(py), 5_000, memory)
            };

            // A tool the kernel's policy doesn't allow.
            let refused = run(&mut kernel, "no_such_tool", "agent-1", 128 << 20).unwrap_err();
            assert!(refused.is_instance_of::<PyPermissionError>(py), "{refused}");
            // An agent that isn't registered.
            let unknown = run(&mut kernel, "echo", "nobody", 128 << 20).unwrap_err();
            assert!(unknown.is_instance_of::<PyValueError>(py), "{unknown}");
            // A memory limit tighter than the kernel enforces.
            let tight = run(&mut kernel, "echo", "agent-1", 1 << 20).unwrap_err();
            assert!(tight.to_string().contains("nothing ran"), "{tight}");

            // Only the refusal reached the kernel, and nothing ran.
            let log = kernel.runtime.block_on(kernel.kernel.get_audit_log());
            assert_eq!(log.len(), 1);
            assert!(log[0].outcome.is_none());

            // A built-in that ran and failed reports failure.
            let failed = run(&mut kernel, "calculator", "agent-1", 128 << 20).unwrap();
            assert_eq!(get(failed.as_any(), "success"), serde_json::json!(false));
        });
    }

    /// Skills come from the kernel's registry, verified as at startup.
    #[cfg(feature = "wasm")]
    #[test]
    fn skills_are_the_kernels() {
        Python::initialize();

        Python::attach(|py| {
            let kernel = PyKernel::default().unwrap();
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("echo.wat"),
                "(module (memory (export \"memory\") 1))",
            )
            .unwrap();
            let manifest = dir.path().join("skill.yaml");
            std::fs::write(
                &manifest,
                "name: py_skill\nversion: \"1.0.0\"\ndescription: x\n\
                 input_schema: {type: object}\noutput_schema: {type: object}\n\
                 wasm_path: echo.wat\n",
            )
            .unwrap();

            // The default kernel takes signed skills only.
            let rejected = kernel.load_skill(manifest.to_str().unwrap()).unwrap_err();
            assert!(rejected.is_instance_of::<PyValueError>(py), "{rejected}");
            assert!(kernel.get_skill(py, "py_skill").unwrap().is_none());
            assert!(kernel.list_skills().unwrap().is_empty());
            assert!(kernel.list_tools().unwrap().contains(&"echo".to_string()));
        });
    }

    /// The SDK's settings reach the kernel's policy; a setting it can't
    /// apply is an error, not silently dropped.
    #[test]
    fn settings_configure_the_kernel() {
        Python::initialize();

        Python::attach(|py| {
            let settings = PyDict::new(py);
            settings.set_item("allowed_tools", vec!["echo"]).unwrap();
            settings
                .set_item("blocked_tools", vec!["calculator"])
                .unwrap();
            settings.set_item("timeout_ms", 2_000).unwrap();
            let mut kernel = PyKernel::from_settings(settings).unwrap();
            assert_eq!(kernel.kernel.config().max_execution_time.as_millis(), 2_000);
            kernel
                .register_agent("agent-1", "Agent One", PyDict::new(py))
                .unwrap();
            let effect = |kernel: &mut PyKernel, tool: &str| {
                py_to_json(
                    kernel
                        .evaluate_policy(py, "agent-1", tool, PyDict::new(py))
                        .unwrap(),
                )
                .unwrap()["effect"]
                    .clone()
            };
            assert_eq!(effect(&mut kernel, "echo"), "allow");
            assert_eq!(effect(&mut kernel, "calculator"), "deny");
            assert_eq!(
                effect(&mut kernel, "data_processor"),
                "deny",
                "not allowlisted"
            );

            let unknown = PyDict::new(py);
            unknown.set_item("cache_ttl_seconds", 5).unwrap();
            let refused = PyKernel::from_settings(unknown).unwrap_err();
            assert!(
                refused.to_string().contains("unknown kernel setting"),
                "{refused}"
            );
            let wrong = PyDict::new(py);
            wrong.set_item("default_decision", "maybe").unwrap();
            assert!(PyKernel::from_settings(wrong).is_err());
        });
    }

    #[test]
    fn a_config_file_that_does_not_load_is_an_error() {
        Python::initialize();

        Python::attach(|_py| {
            let missing = PyKernel::from_config("/nonexistent/kernel.yaml").unwrap_err();
            assert!(missing.to_string().contains("Failed to load kernel config"));
        });
    }

    #[test]
    fn test_py_kernel_agent_registration() {
        Python::initialize();

        Python::attach(|py| {
            let mut kernel = PyKernel::default().unwrap();
            let empty_dict = PyDict::new(py);

            kernel
                .register_agent("test-agent", "Test Agent", empty_dict.clone())
                .unwrap();
            assert!(kernel.agents.contains_key("test-agent"));

            kernel.unregister_agent("test-agent").unwrap();
            assert!(!kernel.agents.contains_key("test-agent"));
        });
    }
}
