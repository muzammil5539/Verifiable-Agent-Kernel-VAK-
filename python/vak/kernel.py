"""
VAK Kernel

The core ``VakKernel`` class — the main entry point for the
Verifiable Agent Kernel Python SDK.

Every answer about policy, the audit log, tools or skills comes from the
Rust kernel in the native module (``vak._vak_native``): its policy
decision point, its audit log, its skill registry (ADR 0011). Without the
native module those methods raise ``VakError``; nothing answers in the
kernel's place. Memory and voting run in Python, in this process
(``vak._local``), with or without it.

Example::

    from vak.kernel import VakKernel
    from vak.config import KernelConfig, SecurityConfig

    kernel = VakKernel(config=KernelConfig(
        security=SecurityConfig(allowed_tools=["echo", "calculator"]),
    ))
    kernel.initialize()

    kernel.register_agent(AgentConfig(agent_id="my-agent", name="My Agent"))
    response = kernel.execute_tool("my-agent", "echo", "say", {"text": "hi"})
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from vak._local import LocalMemory, LocalSwarm
from vak.agent import AgentConfig, _AgentContext
from vak.audit import AuditEntry, AuditLevel
from vak.config import KernelConfig
from vak.exceptions import (
    AgentNotFoundError,
    PolicyViolationError,
    ToolExecutionError,
    VakError,
)
from vak.memory import Episode, MemoryItem
from vak.policy import PolicyDecision, PolicyEffect
from vak.skills import SkillManifest
from vak.tools import ToolRequest, ToolResponse

_NO_KERNEL = (
    "needs the native kernel (vak._vak_native), which is not available; "
    "build it with `maturin develop`"
)


def _load_native() -> Any:
    """The native module, or None if it isn't built."""
    try:
        from vak import _vak_native  # type: ignore[attr-defined]
    except ImportError:
        return None
    return _vak_native


def _kernel_settings(config: KernelConfig) -> dict[str, Any]:
    """The settings in ``config`` that the kernel applies.

    Security and policy settings reach the kernel because they change its
    decisions. ``security.default_policy_effect`` and
    ``policy.default_decision`` both name the default decision; the kernel
    allows by default only if both say "allow". The other settings
    (audit level and rotation, policy caching, resources other than
    per-skill memory, memory tiers) have no kernel equivalent here.
    """
    security, policy = config.security, config.policy
    both_allow = security.default_policy_effect == "allow" and policy.default_decision == "allow"
    settings: dict[str, Any] = {
        "name": config.name,
        "allowed_tools": list(security.allowed_tools),
        "blocked_tools": list(security.blocked_tools),
        "default_decision": "allow" if both_allow else "deny",
        "policy_enabled": policy.enabled,
        "policy_paths": [str(p) for p in policy.policy_paths],
        "enable_sandboxing": security.enable_sandboxing,
        "allow_unsigned_skills": not security.signature_verification,
        "timeout_ms": security.sandbox_timeout_ms,
        "skill_memory_mb": max(1, security.max_memory_bytes // (1024 * 1024)),
        "max_requests_per_minute": security.rate_limit_per_second * 60,
    }
    if config.audit.log_path:
        settings["audit_log_path"] = str(config.audit.log_path)
    return settings


class VakKernel:
    """
    Python wrapper for the Rust VAK Kernel.

    Agent registration, policy decisions, tool execution, skills and the
    audit log all go through the kernel in the native module. Memory and
    voting are Python, in this process.

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
            config_path: Optional path to the kernel's configuration file
                (YAML, JSON or TOML, as the Rust ``KernelConfig`` reads).
            config: Optional KernelConfig for programmatic configuration.
                Its security and policy settings configure the kernel. Give
                either a file or settings: a file together with non-default
                settings is an error, so neither is silently ignored.
        """
        if config and config.config_path:
            self._config_path: Path | None = Path(config.config_path)
        elif config_path:
            self._config_path = Path(config_path)
        else:
            self._config_path = None

        self._config = config or KernelConfig()
        self._is_initialized = False
        self._native_kernel: Any = None
        self._registered_agents: dict[str, AgentConfig] = {}
        self._memory = LocalMemory()
        self._swarm = LocalSwarm()

    @classmethod
    def from_config(cls, config_path: str | Path) -> VakKernel:
        """
        Create and initialize a kernel from a configuration file.

        Args:
            config_path: Path to the kernel's configuration file.

        Returns:
            An initialized VakKernel instance.

        Raises:
            VakError: If the file can't be loaded or the kernel can't start.
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
    def has_native_kernel(self) -> bool:
        """Whether the native kernel is loaded. Without it, the methods that
        answer about policy, tools, skills or the audit log raise."""
        return self._native_kernel is not None

    def initialize(self) -> None:
        """
        Initialize the kernel: start the native kernel, if the module is
        built.

        Raises:
            VakError: If the configuration can't be applied or the kernel
                can't start.
        """
        if self._is_initialized:
            return

        native = _load_native()
        if native is not None:
            settings = _kernel_settings(self._config)
            if self._config_path and settings != _kernel_settings(KernelConfig()):
                raise VakError(
                    "give the kernel either a config file or KernelConfig settings, not both"
                )
            try:
                if self._config_path:
                    self._native_kernel = native.Kernel.from_config(str(self._config_path))
                else:
                    self._native_kernel = native.Kernel.from_settings(settings)
            except Exception as e:
                raise VakError(f"Failed to initialize kernel: {e}") from e

        self._is_initialized = True

    def shutdown(self) -> None:
        """Shut down the kernel and forget registered agents."""
        if not self._is_initialized:
            return

        if self._native_kernel is not None:
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

        The kernel records it with ``allowed_tools`` (if not empty) as its
        own tool scope, and ``role`` and ``attributes`` as attributes its
        policy can read. Registration is not a policy decision; calls are.

        Args:
            config: The agent configuration.

        Raises:
            VakError: If the kernel refuses the agent.
        """
        self._ensure_initialized()
        if self._native_kernel is not None:
            try:
                self._native_kernel.register_agent(
                    config.agent_id,
                    config.name,
                    {
                        "allowed_tools": list(config.allowed_tools),
                        "role": config.role,
                        "attributes": dict(config.attributes),
                    },
                )
            except Exception as e:
                raise VakError(f"Failed to register agent '{config.agent_id}': {e}") from e
        self._registered_agents[config.agent_id] = config

    def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from the kernel."""
        self._ensure_initialized()
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        if self._native_kernel is not None:
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
    # Policy
    # =========================================================================

    def evaluate_policy(
        self,
        agent_id: str,
        action: str,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """
        Ask the kernel whether ``agent_id`` may call the tool ``action``
        with ``context`` as its parameters.

        This is the Decide stage of ``execute_tool`` alone: nothing runs and
        nothing is recorded. ``execute_tool`` sends a tool
        ``{"action": ..., "params": ...}``; to ask about exactly that call,
        pass those as ``context``.

        The kernel's policy comes from its configuration: the
        ``KernelConfig`` security and policy settings, or the config file.

        Args:
            agent_id: The ID of the agent requesting the action.
            action: The tool the agent would call.
            context: The parameters it would call it with.

        Returns:
            The kernel's decision.

        Raises:
            AgentNotFoundError: If the agent is not registered.
            VakError: Without the native kernel.
        """
        native = self._require_kernel("evaluate_policy")
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        result = native.evaluate_policy(agent_id, action, context or {})
        return PolicyDecision(
            effect=PolicyEffect(result["effect"]),
            policy_id=result["policy_id"],
            reason=result["reason"],
        )

    # =========================================================================
    # Skills
    # =========================================================================

    def load_skill(self, manifest_path: str | Path) -> str:
        """Load a WASM skill from its manifest file into the kernel,
        verified as at startup: signed by a trusted publisher unless
        unsigned skills are allowed.

        Loading makes the skill exist; it authorizes no one to call it. The
        kernel's policy still decides every call.

        Returns:
            The skill's name.

        Raises:
            VakError: If the manifest or module can't be read or doesn't
                verify, or without the native kernel.
        """
        native = self._require_kernel("load_skill")
        try:
            return str(native.load_skill(str(manifest_path)))
        except ValueError as e:
            raise VakError(f"Skill rejected: {e}") from e

    def list_skills(self) -> list[str]:
        """The names of the kernel's loaded WASM skills."""
        return list(self._require_kernel("list_skills").list_skills())

    def get_skill(self, skill_id: str) -> SkillManifest | None:
        """The manifest of the kernel's loaded skill called ``skill_id``."""
        manifest = self._require_kernel("get_skill").get_skill(skill_id)
        if manifest is None:
            return None
        return SkillManifest(
            id=manifest["name"],
            name=manifest["name"],
            version=manifest.get("version", ""),
            description=manifest.get("description", ""),
            wasm_path=manifest.get("wasm_path"),
            input_schema=manifest.get("input_schema"),
            output_schema=manifest.get("output_schema"),
            signature=manifest.get("signature"),
            metadata={"signed_by": manifest.get("signed_by")},
        )

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
        Execute a tool action on behalf of an agent, through the kernel.

        The kernel admits the agent, decides by its policy, records the
        decision, runs the tool (a WASM skill in its sandbox), records the
        outcome, and answers with a receipt for both records.

        Args:
            agent_id: The ID of the agent making the request.
            tool_id: The ID of the tool to execute.
            action: The action/method to invoke on the tool.
            parameters: Input parameters for the tool.
            timeout_ms: Time limit; applies when tighter than the kernel's.
            memory_limit_bytes: Memory limit; must be at least what the
                kernel gives every skill, since it takes no per-call limit.

        Returns:
            The tool execution response. A tool that ran and failed has
            ``success`` False.

        Raises:
            AgentNotFoundError: If the agent is not registered.
            PolicyViolationError: If the kernel's policy refuses the call.
            ToolExecutionError: If the kernel refuses it for another reason,
                or there is no kernel to run it. Nothing ran.
        """
        self._ensure_initialized()
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        if self._native_kernel is None:
            raise ToolExecutionError(tool_id, "no kernel is available to run it; nothing ran")

        agent = self._registered_agents[agent_id]
        memory_limit = memory_limit_bytes or agent.memory_limit_bytes
        try:
            result = self._native_kernel.execute_tool(
                tool_id, agent_id, action, parameters or {}, timeout_ms, memory_limit,
            )
        except PermissionError as e:
            # The kernel's policy refused it: args are (policy_id, reason).
            if len(e.args) >= 2:
                policy_id, reason = e.args[0], e.args[1]
            else:
                policy_id, reason = "kernel", str(e)
            raise PolicyViolationError(PolicyDecision(
                effect=PolicyEffect.DENY,
                policy_id=str(policy_id),
                reason=str(reason),
            )) from e
        except Exception as e:
            raise ToolExecutionError(tool_id, str(e)) from e
        return ToolResponse(
            request_id=str(result.get("request_id", "")),
            success=result.get("success") is True,
            result=result.get("result"),
            error=result.get("error"),
            execution_time_ms=float(result.get("execution_time_ms", 0.0)),
            memory_used_bytes=int(result.get("memory_used_bytes", 0)),
            audit_trail=list(result.get("audit_trail", [])),
            receipt=result.get("receipt"),
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
        """The kernel's tools: built-ins, host handlers and loaded skills."""
        return list(self._require_kernel("list_tools").list_tools())

    # =========================================================================
    # Audit Log
    #
    # The kernel's log: every tool call it decided, and every outcome. The
    # SDK cannot write to it; only calls through the kernel are recorded.
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
        The kernel's audit entries, oldest first.

        Each entry is a tool call: ``action`` and ``resource`` are the tool.
        A decision entry has ``details["kind"] == "decision"``; an outcome
        entry has ``"outcome"``, its decision as ``parent_entry_id``, and
        what happened in ``details["outcome"]``. ``level`` is derived:
        WARNING for a refusal, ERROR for a tool that ran and failed, INFO
        otherwise.
        """
        native = self._require_kernel("get_audit_logs")
        filters: dict[str, Any] = {"limit": 1 << 31}
        if agent_id is not None:
            filters["agent_id"] = agent_id
        if level is not None:
            filters["level"] = level.value
        if action is not None:
            filters["action"] = action
        entries = [self._parse_audit_entry(entry) for entry in native.get_audit_logs(filters)]
        # Kernel timestamps are UTC. A naive bound is taken as local time.
        if start_time is not None:
            start = start_time.astimezone()
            entries = [e for e in entries if e.timestamp >= start]
        if end_time is not None:
            end = end_time.astimezone()
            entries = [e for e in entries if e.timestamp <= end]
        return entries[offset : offset + limit]

    def get_audit_entry(self, entry_id: str) -> AuditEntry | None:
        """The kernel's audit entry with this id, if there is one."""
        result = self._require_kernel("get_audit_entry").get_audit_entry(entry_id)
        return self._parse_audit_entry(result) if result else None

    def verify_audit_chain(self) -> bool:
        """
        Whether the kernel's audit chain verifies: no entry altered,
        reordered or spliced in.
        """
        return bool(self._require_kernel("verify_audit_chain").verify_audit_chain())

    def get_audit_root_hash(self) -> str:
        """
        The root of the kernel's audit Merkle tree, as hex (RFC 9162; the
        SHA-256 of nothing for an empty log).
        """
        return str(self._require_kernel("get_audit_root_hash").get_audit_root_hash())

    def export_audit_receipt(self) -> dict[str, Any]:
        """
        The kernel's signed audit tree head: ``head`` (the tree's ``size``
        and ``root``), ``timestamp_ms``, the Ed25519 ``signature`` and the
        ``public_key`` that verifies it. Anyone holding one can later demand
        proof that the log only grew.
        """
        return dict(self._require_kernel("export_audit_receipt").export_audit_receipt())

    # =========================================================================
    # Memory Management
    #
    # Held in this Python process (vak._local), with or without the native
    # module. The kernel doesn't see these calls: they decide no policy,
    # write no audit record and run no tool.
    # =========================================================================

    def store_memory(
        self,
        key: str,
        value: Any,
        priority: str = "normal",
        metadata: dict[str, Any] | None = None,
    ) -> MemoryItem:
        """
        Store an item in working memory, replacing any under ``key``.

        Args:
            key: Unique identifier for the memory item.
            value: The content to store (text, dict, etc.).
            priority: Priority level ("low", "normal", "high", "pinned").
            metadata: Additional metadata to attach.

        Returns:
            The stored MemoryItem.
        """
        self._ensure_initialized()
        item = self._memory.store_memory(key, value, priority, metadata)
        return MemoryItem(
            key=item["key"],
            content=item["content"],
            priority=item["priority"],
            metadata=item["metadata"],
        )

    def retrieve_memory(self, key: str) -> MemoryItem | None:
        """
        Retrieve an item from working memory.

        Args:
            key: The key of the item to retrieve.

        Returns:
            The MemoryItem if found, or None.
        """
        self._ensure_initialized()
        item = self._memory.retrieve_memory(key)
        if item is None:
            return None
        return MemoryItem(
            key=item["key"],
            content=item["content"],
            priority=item["priority"],
            metadata=item["metadata"],
        )

    def store_episode(self, episode: Episode) -> str:
        """
        Append an episode to episodic memory.

        Each episode is linked to the previous one by a SHA-256 hash over
        its id, its content and the previous hash.

        Args:
            episode: The episode to store.

        Returns:
            The hash of the stored episode.
        """
        self._ensure_initialized()
        return self._memory.store_episode(
            {
                "episode_id": episode.episode_id,
                "episode_type": episode.episode_type,
                "content": episode.content,
                "agent_id": episode.agent_id,
                "timestamp": episode.timestamp,
                "metadata": dict(episode.metadata) if episode.metadata else {},
            }
        )

    def retrieve_episodes(self, limit: int = 10) -> list[Episode]:
        """
        Retrieve the most recent episodes from episodic memory.

        Args:
            limit: Maximum number of episodes to return.

        Returns:
            List of Episode objects, most recent first.
        """
        self._ensure_initialized()
        return [
            Episode(
                episode_id=r["episode_id"],
                episode_type=r["episode_type"],
                content=r["content"],
                agent_id=r["agent_id"],
                timestamp=r["timestamp"],
                previous_hash=r["previous_hash"],
                hash=r["hash"],
                metadata=r["metadata"],
            )
            for r in self._memory.retrieve_episodes(limit)
        ]

    def search_semantic(self, query: str, top_k: int = 5) -> list[MemoryItem]:
        """
        Search working memory for items whose key or content contains
        ``query``, ignoring case. This is keyword matching, not vector
        search.

        Args:
            query: The search query.
            top_k: Maximum number of results to return.

        Returns:
            List of matching MemoryItem objects.
        """
        self._ensure_initialized()
        return [
            MemoryItem(
                key=r["key"],
                content=r["content"],
                priority=r["priority"],
                metadata=r["metadata"],
            )
            for r in self._memory.search(query, top_k)
        ]

    # =========================================================================
    # Swarm Coordination
    #
    # Held in this Python process (vak._local), with or without the native
    # module, like memory.
    # =========================================================================

    def create_voting_session(
        self,
        proposal: str,
        config: dict[str, Any] | None = None,
    ) -> str:
        """
        Create a new quadratic voting session.

        Args:
            proposal: The proposal text to vote on.
            config: Optional voting configuration with keys:
                - token_budget (int): Tokens per agent (default 100)
                - quorum_threshold (float): Required voter fraction (default 0.5)
                - quadratic_cost (bool): Use quadratic cost (default True)

        Returns:
            The session ID.
        """
        self._ensure_initialized()
        return self._swarm.create_voting_session(proposal, config)

    def cast_vote(
        self,
        session_id: str,
        agent_id: str,
        direction: str,
        weight: int = 1,
    ) -> dict[str, Any]:
        """
        Cast a vote in a voting session.

        In quadratic voting, the cost of casting N votes is N^2 tokens,
        forcing agents to allocate influence carefully. A vote the agent's
        remaining token budget can't pay for is refused.

        Args:
            session_id: The voting session ID.
            agent_id: The agent casting the vote.
            direction: Vote direction ("for", "against", "abstain").
            weight: Number of votes to cast (cost = weight^2 in quadratic mode).

        Returns:
            Dict with "success", "cost", and "vote" keys, or "success" False
            and an "error".
        """
        self._ensure_initialized()
        return self._swarm.cast_vote(session_id, agent_id, direction, weight)

    def tally_votes(self, session_id: str) -> dict[str, Any]:
        """
        Tally votes and close a voting session.

        Args:
            session_id: The voting session ID.

        Returns:
            Dict with tally results including "winner", "tally", and "unique_voters".
        """
        self._ensure_initialized()
        return self._swarm.tally_votes(session_id)

    def detect_sycophancy(
        self,
        session_history: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Estimate sycophancy from voting history: how often votes agree with
        their session's majority. A heuristic; above 90% is flagged.

        Args:
            session_history: List of session dicts, each containing a "votes" list.

        Returns:
            Dict with "sycophancy_detected" (bool), "agreement_rate" (float),
            "risk_level" (str), and "details" (str).
        """
        self._ensure_initialized()
        return self._swarm.detect_sycophancy(session_history)

    # =========================================================================
    # Context Managers
    # =========================================================================

    @contextmanager
    def agent_context(self, agent_id: str) -> Iterator[_AgentContext]:
        """Create a context manager for executing operations as an agent."""
        if agent_id not in self._registered_agents:
            raise AgentNotFoundError(agent_id)
        yield _AgentContext(self, agent_id)

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

    def _require_kernel(self, method: str) -> Any:
        """The native kernel, or VakError: these answers come from no one
        else."""
        self._ensure_initialized()
        if self._native_kernel is None:
            raise VakError(f"{method} {_NO_KERNEL}")
        return self._native_kernel

    def _parse_audit_entry(self, data: dict[str, Any]) -> AuditEntry:
        policy_data = data.get("policy_decision") or {}
        return AuditEntry(
            entry_id=data["entry_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            level=AuditLevel(data["level"]),
            agent_id=data["agent_id"],
            action=data["action"],
            resource=data["resource"],
            policy_decision=PolicyDecision(
                effect=PolicyEffect(policy_data["effect"]),
                policy_id=policy_data["policy_id"],
                reason=policy_data["reason"],
            )
            if policy_data
            else None,
            details=data.get("details", {}),
            parent_entry_id=data.get("parent_entry_id"),
        )

    def __repr__(self) -> str:
        return (
            f"VakKernel(initialized={self._is_initialized}, "
            f"native={self.has_native_kernel}, agents={len(self._registered_agents)})"
        )
