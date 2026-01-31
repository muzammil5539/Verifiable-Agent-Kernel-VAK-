"""
Type stubs for the VAK native Rust module.

This file provides type hints for the PyO3-generated _vak_native module.
"""

from typing import Any, Dict, List, Optional

__version__: str
__rust_version__: str

class PolicyDecision:
    """Result of a policy evaluation."""
    
    effect: str
    policy_id: str
    reason: str
    matched_rules: List[str]
    
    def __init__(self, effect: str, policy_id: str, reason: str) -> None: ...
    def is_allowed(self) -> bool: ...
    def is_denied(self) -> bool: ...

class ToolResponse:
    """Result of a tool execution."""
    
    request_id: str
    success: bool
    result: Optional[str]
    error: Optional[str]
    execution_time_ms: float
    memory_used_bytes: int
    audit_trail: List[str]
    
    def unwrap(self) -> str:
        """Get result or raise RuntimeError if execution failed."""
        ...

class AuditEntry:
    """An audit log entry."""
    
    entry_id: str
    timestamp: str
    level: str
    agent_id: str
    action: str
    resource: str
    details: Dict[str, str]

class Kernel:
    """The VAK Kernel native implementation."""
    
    @staticmethod
    def default() -> "Kernel":
        """Create a kernel with default configuration."""
        ...
    
    @staticmethod
    def from_config(path: str) -> "Kernel":
        """Create a kernel from a configuration file."""
        ...
    
    def is_initialized(self) -> bool:
        """Check if the kernel is initialized."""
        ...
    
    def shutdown(self) -> None:
        """Shutdown the kernel."""
        ...
    
    def register_agent(self, agent_id: str, name: str, config_json: str) -> None:
        """Register an agent with the kernel."""
        ...
    
    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent."""
        ...
    
    def evaluate_policy(
        self,
        agent_id: str,
        action: str,
        context_json: str,
    ) -> Dict[str, str]:
        """Evaluate a policy for an action."""
        ...
    
    def execute_tool(
        self,
        tool_id: str,
        agent_id: str,
        action: str,
        params_json: str,
        timeout_ms: int,
        memory_limit: int,
    ) -> Dict[str, str]:
        """Execute a tool."""
        ...
    
    def list_tools(self) -> List[str]:
        """List available tools."""
        ...
    
    def get_audit_logs(self, filters_json: str) -> List[Dict[str, str]]:
        """Get audit logs with optional filtering."""
        ...
    
    def get_audit_entry(self, entry_id: str) -> Optional[Dict[str, str]]:
        """Get a specific audit entry."""
        ...
    
    def create_audit_entry(self, entry_json: str) -> str:
        """Create an audit entry and return its ID."""
        ...
