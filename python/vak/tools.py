"""
VAK Tool Types

Request and response types for tool execution within the VAK sandbox,
plus risk level classification.

Example::

    from vak.tools import ToolRequest, ToolResponse, RiskLevel

    request = ToolRequest(
        tool_id="calculator",
        agent_id="my-agent",
        action="add",
        parameters={"a": 1, "b": 2},
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolRequest:
    """
    A request to execute a tool within the VAK sandbox.

    Attributes:
        tool_id: Unique identifier for the tool to execute.
        agent_id: ID of the agent making the request.
        action: The specific action/method to invoke on the tool.
        parameters: Input parameters for the tool execution.
        timeout_ms: Maximum execution time in milliseconds.
        memory_limit_bytes: Maximum memory allocation for the tool.
        request_id: Optional unique identifier for this request.
    """
    tool_id: str
    agent_id: str
    action: str
    parameters: dict[str, Any] = field(default_factory=dict)
    timeout_ms: int = 5000
    memory_limit_bytes: int = 64 * 1024 * 1024  # 64 MB default
    request_id: str | None = None


@dataclass
class ToolResponse:
    """
    The result of a tool execution.

    Attributes:
        request_id: The ID of the original request.
        success: Whether the tool executed successfully.
        result: The output data from the tool (if successful).
        error: Error message (if execution failed).
        execution_time_ms: Time taken to execute the tool.
        memory_used_bytes: Memory consumed during execution.
        audit_trail: List of audit entry IDs generated during execution.
    """
    request_id: str
    success: bool
    result: Any | None = None
    error: str | None = None
    execution_time_ms: float = 0.0
    memory_used_bytes: int = 0
    audit_trail: list[str] = field(default_factory=list)

    def unwrap(self) -> Any:
        """
        Get the result or raise an exception if execution failed.

        Returns:
            The tool execution result.

        Raises:
            RuntimeError: If the tool execution failed.
        """
        if not self.success:
            raise RuntimeError(f"Tool execution failed: {self.error}")
        return self.result


class RiskLevel:
    """Risk level classification for tools and operations.

    This mirrors the Rust ``RiskLevel`` enum and is used for
    tool registration and policy evaluation.

    Example::

        from vak.tools import RiskLevel

        if tool_risk == RiskLevel.HIGH:
            require_human_approval()
    """

    LOW: str = "low"
    """Tool is read-only and safe."""

    MEDIUM: str = "medium"
    """Tool may modify state."""

    HIGH: str = "high"
    """Tool performs sensitive operations."""

    CRITICAL: str = "critical"
    """Tool performs irreversible or security-critical operations."""
