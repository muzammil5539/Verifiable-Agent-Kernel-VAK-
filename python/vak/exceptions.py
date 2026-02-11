"""
VAK Exception Hierarchy

All exceptions raised by the VAK SDK inherit from :class:`VakError`,
making it easy to catch any VAK-related error.

Example::

    try:
        kernel.execute_tool(...)
    except VakError as e:
        logger.error("VAK operation failed: %s", e)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vak.policy import PolicyDecision


class VakError(Exception):
    """Base exception for all VAK-related errors.

    All exceptions raised by the VAK SDK inherit from this class,
    making it easy to catch any VAK-related error::

        try:
            kernel.execute_tool(...)
        except VakError as e:
            logger.error("VAK operation failed: %s", e)
    """
    pass


class PolicyViolationError(VakError):
    """Raised when an action is denied by the ABAC policy engine.

    Attributes:
        decision: The PolicyDecision that caused the violation.
        policy_id: The ID of the policy rule that denied the action.
        reason: Human-readable explanation.

    Example::

        try:
            kernel.execute_tool(agent_id, "delete", "/sensitive")
        except PolicyViolationError as e:
            print(f"Blocked by policy {e.policy_id}: {e.reason}")
    """

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        self.policy_id = decision.policy_id
        self.reason = decision.reason
        super().__init__(f"Policy violation: {decision.reason}")


class AgentNotFoundError(VakError):
    """Raised when an agent is not registered.

    Attributes:
        agent_id: The ID of the agent that was not found.
    """

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent not found: {agent_id}")


class ToolExecutionError(VakError):
    """Raised when a tool execution fails inside the WASM sandbox.

    Attributes:
        tool_id: The tool that failed.
        error: The error message.
        execution_time_ms: How long the tool ran before failing.

    Example::

        try:
            result = kernel.execute_tool(agent_id, "risky_tool", "run", {})
        except ToolExecutionError as e:
            print(f"Tool {e.tool_id} failed: {e.error}")
    """

    def __init__(
        self, tool_id: str, error: str, execution_time_ms: float = 0.0
    ) -> None:
        self.tool_id = tool_id
        self.error = error
        self.execution_time_ms = execution_time_ms
        super().__init__(f"Tool execution failed for '{tool_id}': {error}")


class AuditError(VakError):
    """Raised when an audit logging operation fails.

    This may indicate a tampered audit chain or a storage backend error.
    """
