# Python SDK Agent

## Project Overview

**Verifiable Agent Kernel (VAK)** provides Python bindings via PyO3 for ease of integration with ML/AI workflows. This agent manages the Python SDK, type definitions, and integration examples.

## Task Description

Manage the VAK Python SDK including:
- PyO3 bindings implementation
- Python type stubs
- SDK documentation
- Integration examples
- LangChain/AutoGPT adapters

## Available Commands

```bash
# Build Python extension
cd python && maturin develop

# Run Python tests
pytest python/tests/ -v

# Type checking
mypy python/vak/

# Build wheel
maturin build --release

# Install locally
pip install -e ./python
```

## Files This Agent Can Modify

### Python SDK
- `python/vak/__init__.py` - Main module
- `python/vak/types.py` - Type definitions
- `python/vak/kernel.py` - Kernel wrapper
- `python/vak/exceptions.py` - Custom exceptions
- `python/pyproject.toml` - Python project config

### PyO3 Bindings
- `src/python/mod.rs` - PyO3 module
- `src/python/bindings.rs` - Rust bindings

### Tests
- `python/tests/*.py` - Python tests

### Examples
- `examples/python_quickstart.py`
- `examples/langchain_integration.py`

## SDK Structure

### Type Definitions
```python
# python/vak/types.py
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from enum import Enum

@dataclass
class AgentConfig:
    """Configuration for a VAK agent."""
    agent_id: str
    name: str
    description: str = ""
    capabilities: List[str] = None
    allowed_tools: List[str] = None
    memory_limit_bytes: int = 256 * 1024 * 1024
    max_concurrent_requests: int = 5
    trusted: bool = False
    metadata: Dict[str, Any] = None

@dataclass
class ToolRequest:
    """Request to execute a tool."""
    agent_id: str
    tool_name: str
    action: str
    parameters: Dict[str, Any]
    request_id: Optional[str] = None

@dataclass
class ToolResponse:
    """Response from tool execution."""
    request_id: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    audit_hash: Optional[str] = None

class PolicyEffect(Enum):
    ALLOW = "allow"
    DENY = "deny"

@dataclass
class PolicyDecision:
    effect: PolicyEffect
    policy_id: Optional[str] = None
    reason: Optional[str] = None
```

### Kernel Wrapper
```python
# python/vak/__init__.py
from typing import Optional, List
from .types import AgentConfig, ToolRequest, ToolResponse, AuditEntry

class VakKernel:
    """Python interface to the Verifiable Agent Kernel."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize the kernel.
        
        Args:
            config_path: Path to kernel configuration file
        """
        self._inner = _vak_rs.VakKernel(config_path)
    
    @classmethod
    def from_config(cls, config_path: str) -> "VakKernel":
        """Create kernel from configuration file."""
        return cls(config_path)
    
    def register_agent(self, config: AgentConfig) -> str:
        """Register a new agent with the kernel.
        
        Args:
            config: Agent configuration
            
        Returns:
            Agent ID
            
        Raises:
            VakError: If registration fails
        """
        return self._inner.register_agent(config._to_dict())
    
    def execute_tool(
        self,
        agent_id: str,
        tool: str,
        action: str,
        params: dict,
    ) -> ToolResponse:
        """Execute a tool on behalf of an agent.
        
        Args:
            agent_id: ID of the requesting agent
            tool: Name of the tool to execute
            action: Action to perform
            params: Parameters for the action
            
        Returns:
            Tool execution response
            
        Raises:
            PolicyViolationError: If action is not permitted
            ToolExecutionError: If tool execution fails
        """
        request = ToolRequest(
            agent_id=agent_id,
            tool_name=tool,
            action=action,
            parameters=params,
        )
        result = self._inner.execute_tool(request._to_dict())
        return ToolResponse._from_dict(result)
    
    def get_audit_trail(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """Get audit trail entries.
        
        Args:
            agent_id: Filter by agent ID
            limit: Maximum entries to return
            
        Returns:
            List of audit entries
        """
        entries = self._inner.get_audit_trail(agent_id, limit)
        return [AuditEntry._from_dict(e) for e in entries]
```

### Exception Handling
```python
# python/vak/exceptions.py
class VakError(Exception):
    """Base exception for VAK errors."""
    pass

class PolicyViolationError(VakError):
    """Raised when an action violates policy."""
    def __init__(self, message: str, policy_id: str = None):
        super().__init__(message)
        self.policy_id = policy_id

class AgentNotFoundError(VakError):
    """Raised when agent is not registered."""
    pass

class ToolExecutionError(VakError):
    """Raised when tool execution fails."""
    def __init__(self, message: str, tool: str = None):
        super().__init__(message)
        self.tool = tool
```

### PyO3 Bindings
```rust
// src/python/mod.rs
use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

#[pyclass]
struct PyVakKernel {
    inner: Arc<VakKernel>,
}

#[pymethods]
impl PyVakKernel {
    #[new]
    fn new(config_path: Option<String>) -> PyResult<Self> {
        let config = match config_path {
            Some(path) => KernelConfig::from_file(&path)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?,
            None => KernelConfig::default(),
        };
        
        let kernel = VakKernel::new(config)
            .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
        
        Ok(Self { inner: Arc::new(kernel) })
    }
    
    fn register_agent(&self, config: PyObject, py: Python<'_>) -> PyResult<String> {
        let config: AgentConfig = config.extract(py)?;
        
        py.allow_threads(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(self.inner.register_agent(config))
        })
        .map(|id| id.to_string())
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
    }
    
    fn execute_tool(&self, request: PyObject, py: Python<'_>) -> PyResult<PyObject> {
        let request: ToolRequest = request.extract(py)?;
        
        let response = py.allow_threads(|| {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(self.inner.execute_tool(request))
        })
        .map_err(|e| match e {
            VakError::PolicyViolation(msg) => {
                PyErr::new::<PyPolicyViolationError, _>(msg)
            }
            _ => PyRuntimeError::new_err(e.to_string()),
        })?;
        
        response.into_py(py)
    }
}

#[pymodule]
fn _vak_rs(_py: Python<'_>, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyVakKernel>()?;
    Ok(())
}
```

## Guardrails

### DO
- Provide type hints for all public functions
- Include docstrings with examples
- Handle Rust errors gracefully as Python exceptions
- Support async/await patterns
- Test with pytest
- Maintain backwards compatibility

### DON'T
- Expose internal Rust types directly
- Block the Python GIL unnecessarily
- Use bare `except` clauses
- Return raw Rust error strings to users
- Skip input validation
- Break type safety

### Compatibility Requirements
- Python 3.8+
- Type stubs for mypy
- Async support via asyncio
- Integration with common ML frameworks

## Testing Patterns

```python
# python/tests/test_kernel.py
import pytest
from vak import VakKernel, AgentConfig, PolicyViolationError

@pytest.fixture
def kernel():
    return VakKernel()

@pytest.fixture
def registered_agent(kernel):
    config = AgentConfig(
        agent_id="test-agent",
        name="Test Agent",
        capabilities=["compute"],
        allowed_tools=["calculator"],
    )
    kernel.register_agent(config)
    return "test-agent"

def test_register_agent(kernel):
    config = AgentConfig(
        agent_id="new-agent",
        name="New Agent",
    )
    agent_id = kernel.register_agent(config)
    assert agent_id == "new-agent"

def test_execute_tool(kernel, registered_agent):
    response = kernel.execute_tool(
        agent_id=registered_agent,
        tool="calculator",
        action="add",
        params={"a": 1, "b": 2},
    )
    assert response.success
    assert response.result == 3

def test_policy_violation(kernel, registered_agent):
    with pytest.raises(PolicyViolationError):
        kernel.execute_tool(
            agent_id=registered_agent,
            tool="filesystem",
            action="read",
            params={"path": "/etc/passwd"},
        )

@pytest.mark.asyncio
async def test_async_execution(kernel, registered_agent):
    response = await kernel.execute_tool_async(
        agent_id=registered_agent,
        tool="calculator",
        action="add",
        params={"a": 1, "b": 2},
    )
    assert response.success
```

## Related Agents
- [Rust Code Generator Agent](Rust Code Generator Agent.agent.md)
- [Unit Test Agent](Unit Test Agent.agent.md)