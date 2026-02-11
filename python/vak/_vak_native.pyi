"""
Type stubs for the VAK native Rust module (PyO3 bindings).

This file provides comprehensive type hints for the PyO3-generated
``_vak_native`` module, enabling full IDE IntelliSense/autocomplete
for Python users.

Auto-generated from Rust source: src/python.rs
"""

from typing import Any, Dict, List, Optional, Sequence


__version__: str
"""The VAK crate version (from Cargo.toml)."""

__rust_version__: str
"""The minimum Rust toolchain version required."""


# =============================================================================
# Risk Level Constants
# =============================================================================


class RiskLevel:
    """Risk level classification for tools and operations.

    Use the class-level constants for comparison::

        if tool_risk == RiskLevel.HIGH:
            require_approval()

    Constants:
        LOW: Read-only, safe operations.
        MEDIUM: May modify state.
        HIGH: Sensitive operations.
        CRITICAL: Irreversible or security-critical.
    """

    LOW: str
    MEDIUM: str
    HIGH: str
    CRITICAL: str

    def __repr__(self) -> str: ...


# =============================================================================
# Policy Types
# =============================================================================


class PolicyDecision:
    """Result of a policy evaluation.

    Attributes:
        effect: The policy effect, either ``"allow"`` or ``"deny"``.
        policy_id: Identifier of the policy rule that matched.
        reason: Human-readable explanation of the decision.
        matched_rules: List of rule IDs that contributed to the decision.

    Example::

        decision = kernel.evaluate_policy("agent-1", "read", {"resource": "/data"})
        if decision.is_allowed():
            print("Access granted")
        else:
            print(f"Denied: {decision.reason}")
    """

    effect: str
    policy_id: str
    reason: str
    matched_rules: List[str]

    def __init__(
        self, effect: str, policy_id: str, reason: str
    ) -> None:
        """Create a new PolicyDecision.

        Args:
            effect: The decision effect (``"allow"`` or ``"deny"``).
            policy_id: The ID of the policy that produced this decision.
            reason: Human-readable reason for the decision.
        """
        ...

    def is_allowed(self) -> bool:
        """Return ``True`` if the policy effect is ``"allow"``."""
        ...

    def is_denied(self) -> bool:
        """Return ``True`` if the policy effect is ``"deny"``."""
        ...

    def __repr__(self) -> str: ...


# =============================================================================
# Tool Execution Types
# =============================================================================


class ToolResponse:
    """Result of a tool/skill execution inside the WASM sandbox.

    Attributes:
        request_id: Unique identifier for this execution request.
        success: Whether the tool executed without errors.
        result: The result payload (if successful).
        error: The error message (if failed).
        execution_time_ms: Wall-clock execution time in milliseconds.
        memory_used_bytes: Peak memory consumed by the WASM module.
        audit_trail: Ordered list of audit entry IDs for this execution.

    Example::

        response = kernel.execute_tool(
            "calc", "agent-1", "add", {"a": 1, "b": 2}, 5000, 1048576
        )
        if response.success:
            print(response.result)
        else:
            print(response.error)
    """

    request_id: str
    success: bool
    result: Optional[str]
    error: Optional[str]
    execution_time_ms: float
    memory_used_bytes: int
    audit_trail: List[str]

    def unwrap(self) -> str:
        """Return the result string or raise ``RuntimeError`` on failure.

        Returns:
            The result payload as a string.

        Raises:
            RuntimeError: If ``success`` is ``False``.
        """
        ...

    def __repr__(self) -> str: ...


# =============================================================================
# Audit Types
# =============================================================================


class AuditEntry:
    """An immutable audit log entry in the hash-chained audit trail.

    Each entry is cryptographically linked to its predecessor, forming
    a tamper-evident chain that can be verified with
    :meth:`Kernel.verify_audit_chain`.

    Attributes:
        entry_id: Unique identifier for this audit entry.
        timestamp: ISO-8601 timestamp of when the entry was created.
        level: Severity level (``"info"``, ``"warning"``, ``"error"``, ``"critical"``).
        agent_id: The agent that performed the action.
        action: The action that was performed.
        resource: The resource that was acted upon.
        details: Additional key-value metadata.

    Example::

        entry = kernel.get_audit_entry("42")
        if entry is not None:
            print(f"[{entry.level}] {entry.agent_id} -> {entry.action}")
    """

    entry_id: str
    timestamp: str
    level: str
    agent_id: str
    action: str
    resource: str
    details: Dict[str, str]

    def __repr__(self) -> str: ...


# =============================================================================
# Kernel
# =============================================================================


class Kernel:
    """The VAK Kernel — the central coordinator for policy, audit, and tools.

    The kernel manages agent registration, ABAC policy evaluation,
    WASM-sandboxed tool execution, and cryptographic audit logging.

    Example::

        from vak._vak_native import Kernel

        kernel = Kernel.default()
        assert kernel.is_initialized()

        kernel.register_agent("agent-1", "My Agent", {"role": "analyst"})
        decision = kernel.evaluate_policy("agent-1", "read", {"resource": "/data"})
    """

    # -- Lifecycle --------------------------------------------------------

    @staticmethod
    def default() -> "Kernel":
        """Create a kernel with default configuration.

        Returns:
            A fully initialised ``Kernel`` instance.

        Raises:
            RuntimeError: If kernel initialisation fails.
        """
        ...

    @staticmethod
    def from_config(path: str) -> "Kernel":
        """Create a kernel from a YAML/JSON configuration file.

        Args:
            path: Filesystem path to the configuration file.

        Returns:
            A configured ``Kernel`` instance.

        Raises:
            RuntimeError: If the file cannot be read or parsed.
        """
        ...

    def is_initialized(self) -> bool:
        """Return ``True`` if the kernel has been successfully initialised."""
        ...

    def shutdown(self) -> None:
        """Gracefully shut down the kernel, flushing audit logs.

        After shutdown, the kernel cannot be used until reinitialised.
        """
        ...

    # -- Agent Management -------------------------------------------------

    def register_agent(
        self, agent_id: str, name: str, config: Dict[str, Any]
    ) -> None:
        """Register a new agent with the kernel.

        Args:
            agent_id: Unique identifier for the agent.
            name: Human-readable agent name.
            config: Agent attributes (role, department, clearance, etc.).

        Raises:
            ValueError: If ``agent_id`` is already registered.
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def unregister_agent(self, agent_id: str) -> None:
        """Remove a previously registered agent.

        Args:
            agent_id: The agent to unregister.

        Raises:
            ValueError: If the agent is not found.
            RuntimeError: If the kernel is not initialised.
        """
        ...

    # -- Policy -----------------------------------------------------------

    def evaluate_policy(
        self,
        agent_id: str,
        action: str,
        context: Dict[str, Any],
    ) -> Dict[str, str]:
        """Evaluate an ABAC policy for the given action.

        Args:
            agent_id: The agent requesting the action.
            action: The action to evaluate (e.g. ``"read"``, ``"write"``).
            context: Context attributes including ``"resource"`` key.

        Returns:
            A dict with ``"effect"``, ``"policy_id"``, and ``"reason"`` keys.

        Raises:
            RuntimeError: If the kernel is not initialised.
            ValueError: If the agent is not registered.
        """
        ...

    def add_policy_rule(self, rule_dict: Dict[str, Any]) -> None:
        """Add a new policy rule to the engine.

        Args:
            rule_dict: A dictionary describing the rule (effect, action,
                resource patterns, conditions, etc.).

        Raises:
            ValueError: If the rule dictionary is malformed.
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def validate_policy_config(self) -> List[str]:
        """Validate the current policy configuration.

        Returns:
            A list of warning messages. An empty list means valid.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def has_allow_policies(self) -> bool:
        """Return ``True`` if at least one ``allow`` rule is defined.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def policy_rule_count(self) -> int:
        """Return the number of loaded policy rules.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    # -- Tool / Skill Execution -------------------------------------------

    def execute_tool(
        self,
        tool_id: str,
        agent_id: str,
        action: str,
        params: Dict[str, Any],
        timeout_ms: int,
        memory_limit: int,
    ) -> Dict[str, str]:
        """Execute a tool inside the WASM sandbox.

        Args:
            tool_id: The registered skill/tool identifier.
            agent_id: The agent requesting execution.
            action: The operation to perform (skill-specific).
            params: Input parameters for the tool.
            timeout_ms: Maximum execution time in milliseconds.
            memory_limit: Maximum memory in bytes.

        Returns:
            A dictionary with ``"request_id"``, ``"success"``, ``"result"``,
            ``"execution_time_ms"``, and ``"memory_used_bytes"`` keys.

        Raises:
            RuntimeError: If the kernel is not initialised.
            ValueError: If the agent is not registered.
        """
        ...

    def list_tools(self) -> List[str]:
        """List all enabled tool/skill IDs.

        Returns:
            A list of tool identifier strings.
        """
        ...

    def register_skill(
        self,
        skill_id: str,
        name: str,
        description: str,
        version: str,
    ) -> None:
        """Register a new skill/tool with the kernel.

        Args:
            skill_id: Unique skill identifier.
            name: Human-readable name.
            description: What the skill does.
            version: Semantic version string.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def unregister_skill(self, skill_id: str) -> None:
        """Remove a previously registered skill.

        Args:
            skill_id: The skill to remove.

        Raises:
            ValueError: If the skill is not found.
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def set_skill_enabled(self, skill_id: str, enabled: bool) -> None:
        """Enable or disable a registered skill.

        Args:
            skill_id: The skill to modify.
            enabled: ``True`` to enable, ``False`` to disable.

        Raises:
            ValueError: If the skill is not found.
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def get_skill_info(
        self, skill_id: str
    ) -> Optional[Dict[str, str]]:
        """Return metadata about a skill, or ``None`` if not found.

        Args:
            skill_id: The skill to query.

        Returns:
            A dict with ``"id"``, ``"name"``, ``"description"``,
            ``"version"``, and ``"enabled"`` keys, or ``None``.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    # -- Audit ------------------------------------------------------------

    def get_audit_logs(
        self, filters: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Query audit log entries matching the given filters.

        Args:
            filters: Key-value filter criteria. Supported keys:
                ``"agent_id"``, ``"limit"``.

        Returns:
            A list of matching audit entries as dictionaries.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def get_audit_entry(
        self, entry_id: str
    ) -> Optional[Dict[str, str]]:
        """Retrieve a single audit entry by its ID.

        Args:
            entry_id: The numeric entry ID as a string.

        Returns:
            The entry as a dictionary, or ``None`` if not found.

        Raises:
            RuntimeError: If the kernel is not initialised.
            ValueError: If ``entry_id`` is not a valid ID.
        """
        ...

    def create_audit_entry(
        self, entry_data: Dict[str, Any]
    ) -> str:
        """Create a new audit entry and return its ID.

        Args:
            entry_data: Entry fields including ``"agent_id"``, ``"action"``,
                ``"resource"``.

        Returns:
            The unique ID of the newly created entry.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def verify_audit_chain(self) -> bool:
        """Verify the integrity of the entire audit hash chain.

        Returns:
            ``True`` if the chain is intact and tamper-free.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    def get_audit_root_hash(self) -> Optional[str]:
        """Return the current root hash of the audit chain.

        Returns:
            The hex-encoded hash of the last entry, or ``None``
            if the chain is empty.

        Raises:
            RuntimeError: If the kernel is not initialised.
        """
        ...

    # -- Misc -------------------------------------------------------------

    def __repr__(self) -> str: ...

