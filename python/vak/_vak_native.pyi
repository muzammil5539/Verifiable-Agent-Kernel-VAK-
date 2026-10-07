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
            "calc", "agent-1", "add", {"a": 1, "b": 2}, 5000, 128 * 1024 * 1024
        )
        if response["success"]:
            print(response["result"])
        else:
            print(response["error"])
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
    """The VAK kernel: every method answers from one Rust ``Kernel``, its
    policy decision point, audit log and skill registry (ADR 0011). The
    binding keeps no policy engine, audit log or skill registry of its own.

    Example::

        from vak._vak_native import Kernel

        kernel = Kernel.default()
        kernel.register_agent("agent-1", "My Agent", {"role": "analyst"})
        decision = kernel.evaluate_policy("agent-1", "echo", {})
        result = kernel.execute_tool("echo", "agent-1", "say", {}, 5000, 128 << 20)
    """

    # -- Lifecycle --------------------------------------------------------

    @staticmethod
    def default() -> "Kernel":
        """A kernel with the default configuration, skills getting 128 MiB."""
        ...

    @staticmethod
    def from_config(path: str) -> "Kernel":
        """A kernel configured by the file at ``path`` (YAML, JSON or TOML).

        Raises:
            ValueError: If the file can't be read or parsed. There is no
                fallback to the default configuration.
        """
        ...

    @staticmethod
    def from_settings(settings: Dict[str, Any]) -> "Kernel":
        """A kernel with the default configuration and these settings.

        Keys: ``name``, ``allowed_tools`` (non-empty replaces the default
        allowlist), ``blocked_tools``, ``default_decision`` ("allow" or
        "deny"), ``policy_enabled``, ``policy_paths``, ``enable_sandboxing``,
        ``allow_unsigned_skills``, ``timeout_ms``, ``skill_memory_mb``,
        ``max_requests_per_minute``, ``audit_log_path``.

        Raises:
            ValueError: For an unknown key or a wrong type: no setting is
                silently dropped.
        """
        ...

    def is_initialized(self) -> bool:
        """Return ``True`` until ``shutdown``."""
        ...

    def shutdown(self) -> None:
        """End every registered agent's session and stop answering."""
        ...

    # -- Agents -----------------------------------------------------------

    def register_agent(self, agent_id: str, name: str, config: Dict[str, Any]) -> None:
        """Register an agent. ``config["allowed_tools"]``, if not empty,
        limits it to those tools; ``config["role"]`` and
        ``config["attributes"]`` become attributes policy can read."""
        ...

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent and end its session.

        Raises:
            ValueError: If the agent is not registered.
        """
        ...

    # -- Policy -----------------------------------------------------------

    def evaluate_policy(
        self, agent_id: str, action: str, context: Dict[str, Any]
    ) -> Dict[str, str]:
        """Ask the kernel whether the agent may call the tool ``action`` with
        ``context`` as its parameters. Nothing runs or is recorded.

        Returns:
            ``{"effect": "allow" | "deny", "policy_id": ..., "reason": ...}``.

        Raises:
            ValueError: If the agent is not registered.
        """
        ...

    # -- Tools and skills -------------------------------------------------

    def execute_tool(
        self,
        tool_id: str,
        agent_id: str,
        action: str,
        params: Dict[str, Any],
        timeout_ms: int,
        memory_limit: int,
    ) -> Dict[str, Any]:
        """Execute a tool through the kernel (``Kernel::execute``).

        The tool gets ``{"action": action, "params": params}``, the shape
        WASM skills take. The kernel's policy decides, its audit log records
        the decision before the tool runs and the outcome after, and the
        call stops at ``timeout_ms`` or the kernel's own limit, whichever is
        sooner.

        Returns:
            ``request_id`` (str), ``success`` (bool), ``result`` (the tool's
            output), ``error`` (str or None), ``execution_time_ms`` (int)
            and ``receipt`` (the kernel's audit receipt).

        Raises:
            PermissionError: The kernel's policy refused the call; ``args``
                is ``(policy_id, reason)``. Nothing ran.
            ValueError: The agent is not registered, or ``memory_limit`` is
                below what the kernel gives every skill. Nothing ran.
            RuntimeError: The kernel refused the call for another reason (an
                unknown tool, say). Nothing ran.
        """
        ...

    def list_tools(self) -> List[str]:
        """The kernel's tools: built-ins, host handlers and loaded skills."""
        ...

    def list_skills(self) -> List[str]:
        """The names of the loaded WASM skills."""
        ...

    def load_skill(self, manifest_path: str) -> str:
        """Load a WASM skill from its manifest file, verified as at startup.
        Returns its name. Loading authorizes no one to call it.

        Raises:
            ValueError: If the manifest or module can't be read or doesn't
                verify. Nothing is loaded.
        """
        ...

    def get_skill(self, name: str) -> Optional[Dict[str, Any]]:
        """The manifest of the loaded skill called ``name``, or None."""
        ...

    # -- Audit log --------------------------------------------------------

    def get_audit_logs(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """The kernel's audit entries, oldest first. ``filters`` may set
        ``agent_id``, ``action`` (a tool), ``level``, ``limit`` (default
        100) and ``offset``.

        Each entry has ``entry_id``, ``timestamp``, ``level`` (derived:
        "warning" for a refusal, "error" for a failed run, else "info"),
        ``agent_id``, ``action`` and ``resource`` (the tool),
        ``policy_decision``, ``details`` (``kind`` "decision" or "outcome",
        ``leaf_index``, ``session_id``, ``hash``, ``previous_hash``,
        ``outcome``) and ``parent_entry_id`` (an outcome's decision).
        """
        ...

    def get_audit_entry(self, entry_id: str) -> Optional[Dict[str, Any]]:
        """The audit entry with this id, as in ``get_audit_logs``, or None."""
        ...

    def verify_audit_chain(self) -> bool:
        """Whether no audit entry has been altered, reordered or spliced in."""
        ...

    def get_audit_root_hash(self) -> str:
        """The audit Merkle tree's root, as hex (RFC 9162)."""
        ...

    def export_audit_receipt(self) -> Dict[str, Any]:
        """The kernel's signed audit tree head: ``head`` (``size``, ``root``),
        ``timestamp_ms``, ``signature`` and ``public_key``."""
        ...

    # -- Misc -------------------------------------------------------------

    def __repr__(self) -> str: ...

