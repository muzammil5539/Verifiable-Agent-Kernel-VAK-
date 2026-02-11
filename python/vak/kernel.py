"""
VAK Kernel

The core ``VakKernel`` class — the main entry point for the
Verifiable Agent Kernel Python SDK.

Example::

    from vak.kernel import VakKernel
    from vak.config import KernelConfig, SecurityConfig
    from vak.policy import PolicyRule
    from vak.reasoner import Constraint

    kernel = VakKernel(config=KernelConfig(
        security=SecurityConfig(default_policy_effect="deny"),
    ))

    kernel.load_policies([
        PolicyRule(id="allow-read", effect="permit", action="data.read", resource="*"),
    ])

    kernel.add_constraint(Constraint(name="max-steps", kind="max_steps", value=50))

    kernel.register_agent(AgentConfig(agent_id="my-agent", name="My Agent"))
    response = kernel.execute_tool("my-agent", "calculator", "add", {"a": 1, "b": 2})
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterator

from vak._stub import _StubKernel
from vak.agent import AgentConfig, _AgentContext
from vak.audit import AuditEntry, AuditLevel
from vak.config import KernelConfig
from vak.exceptions import (
    AgentNotFoundError,
    AuditError,
    PolicyViolationError,
    ToolExecutionError,
    VakError,
)
from vak.policy import PolicyDecision, PolicyEffect, PolicyEngine, PolicyRule
from vak.reasoner import Constraint, ConstraintResult, ReasonerConfig, SafetyRule
from vak.skills import SkillManifest
from vak.tools import ToolRequest, ToolResponse

if TYPE_CHECKING:
    from collections.abc import Callable


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

    def __init__(
        self,
        config_path: str | Path | None = None,
        *,
        config: KernelConfig | None = None,
    ) -> None:
        """
        Initialize a new VAK Kernel instance.

        Args:
            config_path: Optional path to a YAML configuration file.
                        If not provided, uses default configuration.
            config: Optional KernelConfig object for programmatic configuration.
                   Takes precedence over config_path if both are provided.
        """
        if config and config.config_path:
            self._config_path = Path(config.config_path)
        elif config_path:
            self._config_path = Path(config_path)
        else:
            self._config_path = None

        self._config = config or KernelConfig()
        self._is_initialized = False
        self._native_kernel: Any = None  # PyO3 binding to Rust kernel
        self._registered_agents: dict[str, AgentConfig] = {}
        self._policy_hooks: list[Callable[[str, str, dict[str, Any]], PolicyDecision | None]] = []
        self._policy_engine = PolicyEngine(
            default_effect=self._config.security.default_policy_effect
        )
        self._reasoner = ReasonerConfig()
        self._skills: dict[str, SkillManifest] = {}

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
    def config(self) -> KernelConfig:
        """Get the kernel configuration."""
        return self._config

    @property
    def is_initialized(self) -> bool:
        """Check if the kernel has been initialized."""
        return self._is_initialized

    @property
    def policy_engine(self) -> PolicyEngine:
        """Get the local policy engine for direct rule management."""
        return self._policy_engine

    @property
    def reasoner(self) -> ReasonerConfig:
        """Get the reasoner configuration."""
        return self._reasoner

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
            try:
                from vak import _vak_native  # type: ignore[attr-defined]

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

        Args:
            config: The agent configuration.

        Raises:
            VakError: If registration fails.
            PolicyViolationError: If registration is denied by policy.
        """
        self._ensure_initialized()

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
                {
                    "description": config.description,
                    "capabilities": config.capabilities,
                    "allowed_tools": config.allowed_tools,
                    "policy_overrides": config.policy_overrides,
                    "memory_limit_bytes": config.memory_limit_bytes,
                    "max_concurrent_requests": config.max_concurrent_requests,
                    "trusted": config.trusted,
                    "metadata": config.metadata,
                },
            )

        self._registered_agents[config.agent_id] = config

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from the kernel."""
        self._ensure_initialized()
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        if self._native_kernel and hasattr(self._native_kernel, "unregister_agent"):
            self._native_kernel.unregister_agent(agent_id)
        del self._registered_agents[agent_id]

    def get_agent(self, agent_id: str) -> AgentConfig:
        """Get the configuration for a registered agent."""
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        return self._registered_agents[agent_id]

    def list_agents(self) -> list[str]:
        """Get a list of all registered agent IDs."""
        return list(self._registered_agents.keys())

    # =========================================================================
    # Policy Management
    # =========================================================================

    def load_policies(self, rules: list[PolicyRule]) -> None:
        """
        Load policy rules into the kernel's policy engine.

        Users define PolicyRule objects in their own project and pass
        them to the kernel. Rules are evaluated in priority order with
        deny-overrides semantics.

        Args:
            rules: List of PolicyRule objects to load.

        Example::

            from vak.policy import PolicyRule, PolicyCondition

            kernel.load_policies([
                PolicyRule(
                    id="admin-full-access",
                    effect="permit",
                    principal="admin",
                    action="*",
                    resource="*",
                    priority=100,
                ),
                PolicyRule(
                    id="block-untrusted-write",
                    effect="forbid",
                    action="*.write",
                    resource="*",
                    conditions=[PolicyCondition("trusted", "equals", False)],
                    priority=200,
                ),
            ])
        """
        self._policy_engine.add_rules(rules)

        if self._native_kernel and hasattr(self._native_kernel, "add_policy_rule"):
            for rule in rules:
                self._native_kernel.add_policy_rule(
                    rule.id,
                    rule.effect,
                    rule.resource,
                    rule.action,
                    {c.attribute: c.value for c in rule.conditions},
                    rule.priority,
                    rule.description,
                )

    def evaluate_policy(
        self,
        agent_id: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Evaluate a policy for a given action.

        Evaluation order:
        1. Custom policy hooks (Python callbacks)
        2. Local policy engine (PolicyRule objects)
        3. Native Rust policy engine (if available)
        4. Default allow (stub mode)

        Args:
            agent_id: The ID of the agent requesting the action.
            action: The action to evaluate.
            context: Additional context for policy evaluation.

        Returns:
            The policy decision.
        """
        self._ensure_initialized()
        context = context or {}

        # 1. Check custom policy hooks first
        for hook in self._policy_hooks:
            decision = hook(agent_id, action, context)
            if decision is not None:
                return decision

        # 2. Check local policy engine (Python-side rules)
        if self._policy_engine.rules:
            role = "*"
            if agent_id in self._registered_agents:
                role = self._registered_agents[agent_id].role
            resource = context.get("resource", context.get("tool_id", "*"))
            decision = self._policy_engine.evaluate(
                role=role,
                action=action,
                resource=resource,
                context=context,
            )
            # If a concrete rule matched, use its decision immediately.
            if decision.matched_rules:
                return decision
            # No rules matched. For regular agents, return the engine's
            # default decision (typically deny).  For the internal "system"
            # caller (used by register_agent, etc.), fall through so that
            # management operations aren't blocked by the absence of
            # explicit rules covering them.
            if agent_id != "system":
                return decision

        # 3. Evaluate via native kernel
        if self._native_kernel and hasattr(self._native_kernel, "evaluate_policy"):
            result = self._native_kernel.evaluate_policy(
                agent_id, action, context
            )
            return PolicyDecision(
                effect=PolicyEffect(result.get("effect", "deny")),
                policy_id=result.get("policy_id", "unknown"),
                reason=result.get("reason", "No reason provided"),
                matched_rules=result.get("matched_rules", []),
                metadata=result.get("metadata", {}),
            )

        # 4. Default allow for stub mode
        return PolicyDecision(
            effect=PolicyEffect.ALLOW,
            policy_id="default",
            reason="Default allow (stub mode)",
        )

    def add_policy_hook(
        self,
        hook: Callable[[str, str, dict[str, Any]], PolicyDecision | None],
    ) -> None:
        """Add a custom policy evaluation hook."""
        self._policy_hooks.append(hook)

    def remove_policy_hook(
        self,
        hook: Callable[[str, str, dict[str, Any]], PolicyDecision | None],
    ) -> None:
        """Remove a previously added policy hook."""
        if hook in self._policy_hooks:
            self._policy_hooks.remove(hook)

    # =========================================================================
    # Constraints & Safety
    # =========================================================================

    def add_constraint(self, constraint: Constraint) -> None:
        """Add a formal constraint to the reasoner.

        Example::

            kernel.add_constraint(
                Constraint(name="max-steps", kind="max_steps", value=50)
            )
        """
        self._reasoner.add_constraint(constraint)

    def add_safety_rule(self, rule: SafetyRule) -> None:
        """Add a safety rule to the reasoner.

        Example::

            kernel.add_safety_rule(
                SafetyRule(name="no-delete", pattern="file.delete", action="block")
            )
        """
        self._reasoner.add_safety_rule(rule)

    def check_constraints(self, context: dict[str, Any]) -> list[ConstraintResult]:
        """Check all constraints against current execution context."""
        return self._reasoner.check_constraints(context)

    def configure_reasoner(self, config: ReasonerConfig) -> None:
        """Set the full reasoner configuration."""
        self._reasoner = config

    # =========================================================================
    # Skill Registration
    # =========================================================================

    def register_skill(self, manifest: SkillManifest) -> None:
        """Register a WASM skill with the kernel.

        Example::

            kernel.register_skill(SkillManifest(
                id="my-tool", name="My Tool", actions=["analyze"],
            ))
        """
        self._ensure_initialized()
        self._skills[manifest.id] = manifest
        if self._native_kernel and hasattr(self._native_kernel, "register_skill"):
            self._native_kernel.register_skill(
                manifest.id, manifest.wasm_path or "", manifest.to_dict(),
            )

    def list_skills(self) -> list[str]:
        """Get a list of all registered skill IDs."""
        return list(self._skills.keys())

    def get_skill(self, skill_id: str) -> SkillManifest | None:
        """Get a skill manifest by ID."""
        return self._skills.get(skill_id)

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

        Pipeline: constraints -> safety rules -> policy -> sandbox execution -> audit.

        Args:
            agent_id: The ID of the agent making the request.
            tool_id: The ID of the tool to execute.
            action: The action/method to invoke on the tool.
            parameters: Input parameters for the tool.
            timeout_ms: Maximum execution time in milliseconds.
            memory_limit_bytes: Maximum memory allocation.

        Returns:
            The tool execution response.

        Raises:
            AgentNotFoundError: If the agent is not registered.
            PolicyViolationError: If the action is denied by policy or safety rules.
            ToolExecutionError: If tool execution fails.
        """
        self._ensure_initialized()

        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)

        agent = self._registered_agents[agent_id]
        parameters = parameters or {}
        memory_limit = memory_limit_bytes or agent.memory_limit_bytes

        # Check safety rules
        matching_safety = self._reasoner.check_safety(f"tool.{action}")
        for sr in matching_safety:
            if sr.action == "block":
                raise PolicyViolationError(PolicyDecision(
                    effect=PolicyEffect.DENY,
                    policy_id=f"safety:{sr.name}",
                    reason=sr.description or f"Blocked by safety rule '{sr.name}'",
                ))

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
                    tool_id, agent_id, action, parameters, timeout_ms, memory_limit,
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
        """Execute a tool using a ToolRequest object."""
        return self.execute_tool(
            agent_id=request.agent_id,
            tool_id=request.tool_id,
            action=request.action,
            parameters=request.parameters,
            timeout_ms=request.timeout_ms,
            memory_limit_bytes=request.memory_limit_bytes,
        )

    def list_tools(self) -> list[str]:
        """Get a list of all available tool IDs."""
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
        """Retrieve audit log entries with optional filtering."""
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
            results = self._native_kernel.get_audit_logs(filters)
            return [self._parse_audit_entry(entry) for entry in results]
        return []

    def get_audit_entry(self, entry_id: str) -> AuditEntry | None:
        """Retrieve a specific audit entry by ID."""
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
        """Create a new audit log entry."""
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
            return self._native_kernel.create_audit_entry(entry_data)
        return f"stub-audit-{datetime.now().timestamp()}"

    # =========================================================================
    # Context Managers
    # =========================================================================

    @contextmanager
    def agent_context(self, agent_id: str) -> Iterator[_AgentContext]:
        """Create a context manager for executing operations as an agent."""
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        ctx = _AgentContext(self, agent_id)
        try:
            yield ctx
        finally:
            pass

    @contextmanager
    def session(self, agent: AgentConfig) -> Iterator[VakKernel]:
        """Context manager for agent sessions (auto register/unregister)."""
        self.register_agent(agent)
        try:
            yield self
        finally:
            try:
                self.unregister_agent(agent.agent_id)
            except VakError:
                pass

    # =========================================================================
    # Private Methods
    # =========================================================================

    def _ensure_initialized(self) -> None:
        if not self._is_initialized:
            raise VakError("Kernel not initialized. Call initialize() first.")

    def _parse_audit_entry(self, data: dict[str, Any]) -> AuditEntry:
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
