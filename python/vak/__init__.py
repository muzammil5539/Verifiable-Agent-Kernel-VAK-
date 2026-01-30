"""
VAK - Verifiable Agent Kernel Python SDK

A Python SDK providing PyO3 bindings to the Rust-based Verifiable Agent Kernel.
Enables secure, policy-enforced agent execution with comprehensive audit logging.

Example:
    >>> from vak import VakKernel, AgentConfig
    >>> kernel = VakKernel.from_config("config/kernel.yaml")
    >>> agent = AgentConfig(agent_id="my-agent", name="My Agent")
    >>> kernel.register_agent(agent)
    >>> response = kernel.execute_tool("my-agent", "calculator", "add", {"a": 1, "b": 2})
    >>> print(response.result)
    3
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from .types import (
    AgentConfig,
    AuditEntry,
    AuditLevel,
    PolicyDecision,
    PolicyEffect,
    ToolRequest,
    ToolResponse,
)

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = [
    "VakKernel",
    "AgentConfig",
    "AuditEntry",
    "AuditLevel",
    "PolicyDecision",
    "PolicyEffect",
    "ToolRequest",
    "ToolResponse",
    "VakError",
    "PolicyViolationError",
    "AgentNotFoundError",
    "ToolExecutionError",
]

__version__ = "0.1.0"


# =============================================================================
# Exceptions
# =============================================================================


class VakError(Exception):
    """Base exception for all VAK-related errors."""
    pass


class PolicyViolationError(VakError):
    """Raised when an action is denied by policy."""

    def __init__(self, decision: PolicyDecision) -> None:
        self.decision = decision
        super().__init__(f"Policy violation: {decision.reason}")


class AgentNotFoundError(VakError):
    """Raised when an agent is not registered."""

    def __init__(self, agent_id: str) -> None:
        self.agent_id = agent_id
        super().__init__(f"Agent not found: {agent_id}")


class ToolExecutionError(VakError):
    """Raised when tool execution fails."""

    def __init__(self, tool_id: str, error: str) -> None:
        self.tool_id = tool_id
        self.error = error
        super().__init__(f"Tool execution failed for '{tool_id}': {error}")


# =============================================================================
# Core Kernel Class
# =============================================================================


class VakKernel:
    """
    Python wrapper for the Rust VAK Kernel.

    Provides a high-level interface to the Verifiable Agent Kernel,
    including policy evaluation, agent management, tool execution,
    and audit logging.

    The kernel enforces security policies on all operations and maintains
    a comprehensive audit trail for compliance and debugging.

    Attributes:
        config_path: Path to the kernel configuration file.
        is_initialized: Whether the kernel has been initialized.
    """

    def __init__(self, config_path: str | Path | None = None) -> None:
        """
        Initialize a new VAK Kernel instance.

        Args:
            config_path: Optional path to a YAML configuration file.
                        If not provided, uses default configuration.
        """
        self._config_path = Path(config_path) if config_path else None
        self._is_initialized = False
        self._native_kernel: Any = None  # PyO3 binding to Rust kernel
        self._registered_agents: dict[str, AgentConfig] = {}
        self._policy_hooks: list[Callable[[str, str, dict[str, Any]], PolicyDecision | None]] = []

    @classmethod
    def from_config(cls, config_path: str | Path) -> VakKernel:
        """
        Create and initialize a kernel from a configuration file.

        Args:
            config_path: Path to the YAML configuration file.

        Returns:
            An initialized VakKernel instance.

        Raises:
            FileNotFoundError: If the configuration file doesn't exist.
            VakError: If kernel initialization fails.
        """
        kernel = cls(config_path)
        kernel.initialize()
        return kernel

    @classmethod
    def default(cls) -> VakKernel:
        """
        Create a kernel with default configuration.

        Returns:
            An initialized VakKernel instance with default settings.
        """
        kernel = cls()
        kernel.initialize()
        return kernel

    @property
    def config_path(self) -> Path | None:
        """Get the configuration file path."""
        return self._config_path

    @property
    def is_initialized(self) -> bool:
        """Check if the kernel has been initialized."""
        return self._is_initialized

    def initialize(self) -> None:
        """
        Initialize the kernel and load configuration.

        This method must be called before using the kernel.
        It loads the Rust native kernel via PyO3 bindings.

        Raises:
            VakError: If initialization fails.
        """
        if self._is_initialized:
            return

        try:
            # Import the native Rust module (compiled via PyO3)
            # This will be available when the Rust crate is built with PyO3
            try:
                from . import _vak_native  # type: ignore[attr-defined]
                
                if self._config_path:
                    self._native_kernel = _vak_native.Kernel.from_config(
                        str(self._config_path)
                    )
                else:
                    self._native_kernel = _vak_native.Kernel.default()
            except ImportError:
                # Native module not available, use stub for development
                self._native_kernel = _StubKernel()

            self._is_initialized = True
        except Exception as e:
            raise VakError(f"Failed to initialize kernel: {e}") from e

    def shutdown(self) -> None:
        """
        Gracefully shutdown the kernel.

        Flushes audit logs, releases resources, and stops any background tasks.
        """
        if not self._is_initialized:
            return

        if self._native_kernel and hasattr(self._native_kernel, "shutdown"):
            self._native_kernel.shutdown()

        self._is_initialized = False
        self._native_kernel = None
        self._registered_agents.clear()

    # =========================================================================
    # Agent Management
    # =========================================================================

    def register_agent(self, config: AgentConfig) -> None:
        """
        Register an agent with the kernel.

        The agent will be subject to all configured policies and can
        execute tools based on its granted permissions.

        Args:
            config: The agent configuration.

        Raises:
            VakError: If registration fails.
            PolicyViolationError: If registration is denied by policy.
        """
        self._ensure_initialized()

        # Evaluate registration policy
        decision = self.evaluate_policy(
            agent_id="system",
            action="agent.register",
            context={
                "target_agent_id": config.agent_id,
                "capabilities": config.capabilities,
                "trusted": config.trusted,
            },
        )

        if decision.is_denied():
            raise PolicyViolationError(decision)

        if self._native_kernel and hasattr(self._native_kernel, "register_agent"):
            self._native_kernel.register_agent(
                config.agent_id,
                config.name,
                json.dumps({
                    "description": config.description,
                    "capabilities": config.capabilities,
                    "allowed_tools": config.allowed_tools,
                    "policy_overrides": config.policy_overrides,
                    "memory_limit_bytes": config.memory_limit_bytes,
                    "max_concurrent_requests": config.max_concurrent_requests,
                    "trusted": config.trusted,
                    "metadata": config.metadata,
                }),
            )

        self._registered_agents[config.agent_id] = config

    def unregister_agent(self, agent_id: str) -> None:
        """
        Unregister an agent from the kernel.

        Args:
            agent_id: The ID of the agent to unregister.

        Raises:
            AgentNotFoundError: If the agent is not registered.
        """
        self._ensure_initialized()

        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)

        if self._native_kernel and hasattr(self._native_kernel, "unregister_agent"):
            self._native_kernel.unregister_agent(agent_id)

        del self._registered_agents[agent_id]

    def get_agent(self, agent_id: str) -> AgentConfig:
        """
        Get the configuration for a registered agent.

        Args:
            agent_id: The ID of the agent.

        Returns:
            The agent's configuration.

        Raises:
            AgentNotFoundError: If the agent is not registered.
        """
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        return self._registered_agents[agent_id]

    def list_agents(self) -> list[str]:
        """
        Get a list of all registered agent IDs.

        Returns:
            List of registered agent IDs.
        """
        return list(self._registered_agents.keys())

    # =========================================================================
    # Policy Evaluation
    # =========================================================================

    def evaluate_policy(
        self,
        agent_id: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Evaluate a policy for a given action.

        Args:
            agent_id: The ID of the agent requesting the action.
            action: The action to evaluate (e.g., "tool.execute", "data.read").
            context: Additional context for policy evaluation.

        Returns:
            The policy decision indicating whether the action is allowed.
        """
        self._ensure_initialized()
        context = context or {}

        # Check custom policy hooks first
        for hook in self._policy_hooks:
            decision = hook(agent_id, action, context)
            if decision is not None:
                return decision

        # Evaluate via native kernel
        if self._native_kernel and hasattr(self._native_kernel, "evaluate_policy"):
            result = self._native_kernel.evaluate_policy(
                agent_id, action, json.dumps(context)
            )
            return PolicyDecision(
                effect=PolicyEffect(result.get("effect", "deny")),
                policy_id=result.get("policy_id", "unknown"),
                reason=result.get("reason", "No reason provided"),
                matched_rules=result.get("matched_rules", []),
                metadata=result.get("metadata", {}),
            )

        # Default allow for stub mode
        return PolicyDecision(
            effect=PolicyEffect.ALLOW,
            policy_id="default",
            reason="Default allow (stub mode)",
        )

    def add_policy_hook(
        self,
        hook: Callable[[str, str, dict[str, Any]], PolicyDecision | None],
    ) -> None:
        """
        Add a custom policy evaluation hook.

        Hooks are evaluated before the native policy engine. If a hook
        returns a PolicyDecision, that decision is used. If it returns
        None, evaluation continues to the next hook or the native engine.

        Args:
            hook: A callable that takes (agent_id, action, context) and
                  returns a PolicyDecision or None.
        """
        self._policy_hooks.append(hook)

    def remove_policy_hook(
        self,
        hook: Callable[[str, str, dict[str, Any]], PolicyDecision | None],
    ) -> None:
        """
        Remove a previously added policy hook.

        Args:
            hook: The hook to remove.
        """
        if hook in self._policy_hooks:
            self._policy_hooks.remove(hook)

    # =========================================================================
    # Tool Execution
    # =========================================================================

    def execute_tool(
        self,
        agent_id: str,
        tool_id: str,
        action: str,
        parameters: dict[str, Any] | None = None,
        *,
        timeout_ms: int = 5000,
        memory_limit_bytes: int | None = None,
    ) -> ToolResponse:
        """
        Execute a tool action on behalf of an agent.

        This method evaluates policies, executes the tool in a sandbox,
        and creates audit log entries.

        Args:
            agent_id: The ID of the agent making the request.
            tool_id: The ID of the tool to execute.
            action: The action/method to invoke on the tool.
            parameters: Input parameters for the tool.
            timeout_ms: Maximum execution time in milliseconds.
            memory_limit_bytes: Maximum memory allocation (uses agent default if None).

        Returns:
            The tool execution response.

        Raises:
            AgentNotFoundError: If the agent is not registered.
            PolicyViolationError: If the action is denied by policy.
            ToolExecutionError: If tool execution fails.
        """
        self._ensure_initialized()

        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)

        agent = self._registered_agents[agent_id]
        parameters = parameters or {}
        memory_limit = memory_limit_bytes or agent.memory_limit_bytes

        # Create the request
        request = ToolRequest(
            tool_id=tool_id,
            agent_id=agent_id,
            action=action,
            parameters=parameters,
            timeout_ms=timeout_ms,
            memory_limit_bytes=memory_limit,
        )

        # Evaluate policy
        decision = self.evaluate_policy(
            agent_id=agent_id,
            action="tool.execute",
            context={
                "tool_id": tool_id,
                "action": action,
                "parameters": parameters,
            },
        )

        if decision.is_denied():
            raise PolicyViolationError(decision)

        # Execute via native kernel
        if self._native_kernel and hasattr(self._native_kernel, "execute_tool"):
            try:
                result = self._native_kernel.execute_tool(
                    tool_id,
                    agent_id,
                    action,
                    json.dumps(parameters),
                    timeout_ms,
                    memory_limit,
                )
                return ToolResponse(
                    request_id=result.get("request_id", ""),
                    success=result.get("success", False),
                    result=result.get("result"),
                    error=result.get("error"),
                    execution_time_ms=result.get("execution_time_ms", 0.0),
                    memory_used_bytes=result.get("memory_used_bytes", 0),
                    audit_trail=result.get("audit_trail", []),
                )
            except Exception as e:
                raise ToolExecutionError(tool_id, str(e)) from e

        # Stub response for development
        return ToolResponse(
            request_id=f"stub-{tool_id}-{action}",
            success=True,
            result={"stub": True, "tool_id": tool_id, "action": action},
            execution_time_ms=0.1,
        )

    def execute_tool_request(self, request: ToolRequest) -> ToolResponse:
        """
        Execute a tool using a ToolRequest object.

        Args:
            request: The tool request to execute.

        Returns:
            The tool execution response.
        """
        return self.execute_tool(
            agent_id=request.agent_id,
            tool_id=request.tool_id,
            action=request.action,
            parameters=request.parameters,
            timeout_ms=request.timeout_ms,
            memory_limit_bytes=request.memory_limit_bytes,
        )

    def list_tools(self) -> list[str]:
        """
        Get a list of all available tool IDs.

        Returns:
            List of tool IDs.
        """
        self._ensure_initialized()

        if self._native_kernel and hasattr(self._native_kernel, "list_tools"):
            return self._native_kernel.list_tools()

        return []

    # =========================================================================
    # Audit Logging
    # =========================================================================

    def get_audit_logs(
        self,
        *,
        agent_id: str | None = None,
        level: AuditLevel | None = None,
        action: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEntry]:
        """
        Retrieve audit log entries with optional filtering.

        Args:
            agent_id: Filter by agent ID.
            level: Filter by minimum audit level.
            action: Filter by action pattern (supports wildcards).
            start_time: Filter entries after this time.
            end_time: Filter entries before this time.
            limit: Maximum number of entries to return.
            offset: Number of entries to skip (for pagination).

        Returns:
            List of matching audit entries.
        """
        self._ensure_initialized()

        filters = {
            "agent_id": agent_id,
            "level": level.value if level else None,
            "action": action,
            "start_time": start_time.isoformat() if start_time else None,
            "end_time": end_time.isoformat() if end_time else None,
            "limit": limit,
            "offset": offset,
        }

        if self._native_kernel and hasattr(self._native_kernel, "get_audit_logs"):
            results = self._native_kernel.get_audit_logs(json.dumps(filters))
            return [self._parse_audit_entry(entry) for entry in results]

        return []

    def get_audit_entry(self, entry_id: str) -> AuditEntry | None:
        """
        Retrieve a specific audit entry by ID.

        Args:
            entry_id: The unique identifier of the audit entry.

        Returns:
            The audit entry, or None if not found.
        """
        self._ensure_initialized()

        if self._native_kernel and hasattr(self._native_kernel, "get_audit_entry"):
            result = self._native_kernel.get_audit_entry(entry_id)
            if result:
                return self._parse_audit_entry(result)

        return None

    def create_audit_entry(
        self,
        agent_id: str,
        action: str,
        resource: str,
        *,
        level: AuditLevel = AuditLevel.INFO,
        details: dict[str, Any] | None = None,
        parent_entry_id: str | None = None,
    ) -> str:
        """
        Create a new audit log entry.

        Args:
            agent_id: The agent associated with this entry.
            action: The action being audited.
            resource: The resource being accessed/modified.
            level: The severity level of the entry.
            details: Additional context about the event.
            parent_entry_id: ID of a parent entry for hierarchical auditing.

        Returns:
            The ID of the created audit entry.
        """
        self._ensure_initialized()

        entry_data = {
            "agent_id": agent_id,
            "action": action,
            "resource": resource,
            "level": level.value,
            "details": details or {},
            "parent_entry_id": parent_entry_id,
        }

        if self._native_kernel and hasattr(self._native_kernel, "create_audit_entry"):
            return self._native_kernel.create_audit_entry(json.dumps(entry_data))

        return f"stub-audit-{datetime.now().timestamp()}"

    # =========================================================================
    # Context Managers
    # =========================================================================

    @contextmanager
    def agent_context(self, agent_id: str) -> Iterator[_AgentContext]:
        """
        Create a context manager for executing operations as an agent.

        Args:
            agent_id: The ID of the agent.

        Yields:
            An AgentContext for executing operations.

        Example:
            >>> with kernel.agent_context("my-agent") as ctx:
            ...     result = ctx.execute_tool("calculator", "add", {"a": 1, "b": 2})
        """
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)

        ctx = _AgentContext(self, agent_id)
        try:
            yield ctx
        finally:
            pass  # Cleanup if needed

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _ensure_initialized(self) -> None:
        """Ensure the kernel is initialized."""
        if not self._is_initialized:
            raise VakError("Kernel not initialized. Call initialize() first.")

    def _parse_audit_entry(self, data: dict[str, Any]) -> AuditEntry:
        """Parse a dictionary into an AuditEntry."""
        policy_data = data.get("policy_decision")
        policy_decision = None
        if policy_data:
            policy_decision = PolicyDecision(
                effect=PolicyEffect(policy_data.get("effect", "deny")),
                policy_id=policy_data.get("policy_id", ""),
                reason=policy_data.get("reason", ""),
                matched_rules=policy_data.get("matched_rules", []),
                metadata=policy_data.get("metadata", {}),
            )

        return AuditEntry(
            entry_id=data.get("entry_id", ""),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now().isoformat())),
            level=AuditLevel(data.get("level", "info")),
            agent_id=data.get("agent_id", ""),
            action=data.get("action", ""),
            resource=data.get("resource", ""),
            policy_decision=policy_decision,
            details=data.get("details", {}),
            parent_entry_id=data.get("parent_entry_id"),
        )


# =============================================================================
# Helper Classes
# =============================================================================


class _AgentContext:
    """Context for executing operations as a specific agent."""

    def __init__(self, kernel: VakKernel, agent_id: str) -> None:
        self._kernel = kernel
        self._agent_id = agent_id

    @property
    def agent_id(self) -> str:
        """Get the agent ID for this context."""
        return self._agent_id

    def execute_tool(
        self,
        tool_id: str,
        action: str,
        parameters: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> ToolResponse:
        """Execute a tool in this agent's context."""
        return self._kernel.execute_tool(
            self._agent_id, tool_id, action, parameters, **kwargs
        )

    def evaluate_policy(
        self,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate a policy in this agent's context."""
        return self._kernel.evaluate_policy(self._agent_id, action, context)

    def create_audit_entry(
        self,
        action: str,
        resource: str,
        **kwargs: Any,
    ) -> str:
        """Create an audit entry in this agent's context."""
        return self._kernel.create_audit_entry(
            self._agent_id, action, resource, **kwargs
        )


class _StubKernel:
    """Stub kernel for development when native module is not available."""

    def shutdown(self) -> None:
        pass
