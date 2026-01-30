"""
VAK Type Definitions

Dataclasses and type definitions for the Verifiable Agent Kernel Python SDK.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class PolicyEffect(Enum):
    """The effect of a policy decision."""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"


class AuditLevel(Enum):
    """Severity level for audit entries."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True)
class PolicyDecision:
    """
    Represents the result of a policy evaluation.

    Attributes:
        effect: The decision effect (allow, deny, or audit).
        policy_id: Identifier of the policy that made this decision.
        reason: Human-readable explanation for the decision.
        matched_rules: List of rule IDs that matched during evaluation.
        metadata: Additional context or data from the evaluation.
    """
    effect: PolicyEffect
    policy_id: str
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_allowed(self) -> bool:
        """Check if the decision permits the action."""
        return self.effect == PolicyEffect.ALLOW

    def is_denied(self) -> bool:
        """Check if the decision denies the action."""
        return self.effect == PolicyEffect.DENY


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


@dataclass(frozen=True)
class AuditEntry:
    """
    An immutable audit log entry.

    Attributes:
        entry_id: Unique identifier for this audit entry.
        timestamp: When the event occurred.
        level: Severity level of the entry.
        agent_id: ID of the agent that triggered this entry.
        action: The action being audited.
        resource: The resource being accessed or modified.
        policy_decision: The policy decision (if applicable).
        details: Additional context about the event.
        parent_entry_id: ID of a parent entry for hierarchical auditing.
    """
    entry_id: str
    timestamp: datetime
    level: AuditLevel
    agent_id: str
    action: str
    resource: str
    policy_decision: PolicyDecision | None = None
    details: dict[str, Any] = field(default_factory=dict)
    parent_entry_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert the audit entry to a dictionary representation."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "policy_decision": {
                "effect": self.policy_decision.effect.value,
                "policy_id": self.policy_decision.policy_id,
                "reason": self.policy_decision.reason,
            } if self.policy_decision else None,
            "details": self.details,
            "parent_entry_id": self.parent_entry_id,
        }


@dataclass
class AgentConfig:
    """
    Configuration for registering an agent with VAK.

    Attributes:
        agent_id: Unique identifier for the agent.
        name: Human-readable name for the agent.
        description: Description of the agent's purpose.
        capabilities: List of capabilities this agent has.
        allowed_tools: List of tool IDs this agent can access.
        policy_overrides: Agent-specific policy configurations.
        memory_limit_bytes: Maximum memory allocation for this agent.
        max_concurrent_requests: Maximum parallel tool executions.
        trusted: Whether this agent has elevated trust level.
        metadata: Additional configuration data.
    """
    agent_id: str
    name: str
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    policy_overrides: dict[str, Any] = field(default_factory=dict)
    memory_limit_bytes: int = 128 * 1024 * 1024  # 128 MB default
    max_concurrent_requests: int = 10
    trusted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_capability(self, capability: str) -> AgentConfig:
        """
        Return a new config with an additional capability.

        Args:
            capability: The capability to add.

        Returns:
            A new AgentConfig with the capability added.
        """
        new_capabilities = self.capabilities.copy()
        if capability not in new_capabilities:
            new_capabilities.append(capability)
        return AgentConfig(
            agent_id=self.agent_id,
            name=self.name,
            description=self.description,
            capabilities=new_capabilities,
            allowed_tools=self.allowed_tools.copy(),
            policy_overrides=self.policy_overrides.copy(),
            memory_limit_bytes=self.memory_limit_bytes,
            max_concurrent_requests=self.max_concurrent_requests,
            trusted=self.trusted,
            metadata=self.metadata.copy(),
        )

    def with_tool_access(self, tool_id: str) -> AgentConfig:
        """
        Return a new config with access to an additional tool.

        Args:
            tool_id: The tool ID to grant access to.

        Returns:
            A new AgentConfig with the tool access added.
        """
        new_tools = self.allowed_tools.copy()
        if tool_id not in new_tools:
            new_tools.append(tool_id)
        return AgentConfig(
            agent_id=self.agent_id,
            name=self.name,
            description=self.description,
            capabilities=self.capabilities.copy(),
            allowed_tools=new_tools,
            policy_overrides=self.policy_overrides.copy(),
            memory_limit_bytes=self.memory_limit_bytes,
            max_concurrent_requests=self.max_concurrent_requests,
            trusted=self.trusted,
            metadata=self.metadata.copy(),
        )
