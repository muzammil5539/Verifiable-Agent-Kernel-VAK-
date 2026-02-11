"""
VAK Agent Configuration

Agent configuration and context types for registering agents
with the VAK kernel.

Example::

    from vak.agent import AgentConfig

    agent = AgentConfig(
        agent_id="code-reviewer",
        name="Code Reviewer",
        role="reviewer",
        capabilities=["code_analysis", "security_audit"],
        allowed_tools=["text-analyzer", "regex-matcher"],
    )

    kernel.register_agent(agent)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from vak.policy import PolicyDecision
from vak.tools import ToolResponse

if TYPE_CHECKING:
    from vak.kernel import VakKernel


@dataclass
class AgentConfig:
    """Configuration for registering an agent with VAK.

    Attributes:
        agent_id: Unique identifier for the agent.
        name: Human-readable name for the agent.
        role: Role for ABAC policy evaluation (e.g. ``"analyst"``, ``"admin"``).
        description: Description of the agent's purpose.
        capabilities: List of capabilities this agent has.
        allowed_tools: List of tool IDs this agent can access.
        policy_overrides: Agent-specific policy configurations.
        memory_limit_bytes: Maximum memory allocation for this agent.
        max_concurrent_requests: Maximum parallel tool executions.
        trusted: Whether this agent has elevated trust level.
        metadata: Additional configuration data.
        attributes: Extra ABAC attributes (department, clearance, etc.).
    """
    agent_id: str
    name: str
    role: str = "default"
    description: str = ""
    capabilities: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    policy_overrides: dict[str, Any] = field(default_factory=dict)
    memory_limit_bytes: int = 128 * 1024 * 1024  # 128 MB default
    max_concurrent_requests: int = 10
    trusted: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    attributes: dict[str, Any] = field(default_factory=dict)

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
