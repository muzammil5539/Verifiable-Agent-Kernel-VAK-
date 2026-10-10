"""
VAK Configuration

Typed configuration classes for the VAK kernel. Users can define
their own kernel configuration in their projects and pass it to
the kernel on initialization.

Example::

    from vak.config import KernelConfig, SecurityConfig, AuditConfig
    from vak.memory import MemoryConfig, WorkingMemoryConfig

    config = KernelConfig(
        name="my-app-kernel",
        security=SecurityConfig(
            enable_sandboxing=True,
            allowed_tools=["calculator", "text-analyzer"],
        ),
        audit=AuditConfig(
            enabled=True,
            level="info",
        ),
        memory=MemoryConfig(
            working=WorkingMemoryConfig(max_items=200),
        ),
    )

    kernel = VakKernel(config=config)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vak.memory import MemoryConfig


@dataclass
class SecurityConfig:
    """Security configuration for the VAK kernel.

    Attributes:
        enable_sandboxing: Whether to enable WASM sandboxing for tools.
        signature_verification: Whether to verify skill signatures.
        default_policy_effect: Default decision when no rules match ("deny" or
            "allow"). It has no effect through ``KernelConfig``: the kernel's
            allowlist is never empty, and tools outside it are denied first.
        allowed_tools: Tool names agents may call. Empty keeps the kernel's
            built-in tools. Not applied while policy files decide.
        blocked_tools: Tool names agents may not call. With policy files, a
            blocked tool reaches the rules as ``resource.restricted``, and is
            blocked only by rules that check it (ADR 0008).
        max_memory_bytes: Maximum memory per tool execution.
        sandbox_timeout_ms: Default timeout for sandboxed operations.
        rate_limit_per_second: Maximum requests per agent per second.
    """
    enable_sandboxing: bool = True
    signature_verification: bool = True
    default_policy_effect: str = "deny"
    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    max_memory_bytes: int = 128 * 1024 * 1024  # 128 MB
    sandbox_timeout_ms: int = 5000
    rate_limit_per_second: int = 100


@dataclass
class AuditConfig:
    """Audit logging configuration.

    Attributes:
        enabled: Whether audit logging is enabled.
        level: Minimum audit level to log ("debug", "info", "warning", "error", "critical").
        log_path: Path to the audit log file.
        verify_chain: Whether to verify the hash chain on reads.
        max_log_size_mb: Maximum log file size before rotation.
        retention_days: Number of days to retain audit logs.
    """
    enabled: bool = True
    level: str = "info"
    log_path: str | None = None
    verify_chain: bool = True
    max_log_size_mb: int = 100
    retention_days: int = 90


@dataclass
class PolicyConfig:
    """Policy engine configuration.

    Attributes:
        enabled: Whether the kernel reads ``policy_paths``. False ignores them,
            and the allowlist and blocklist decide.
        default_decision: Default decision when no rules match ("deny" or "allow").
            It has no effect through ``KernelConfig``; see
            ``SecurityConfig.default_policy_effect``.
        policy_paths: YAML policy files the kernel reads at startup. They then
            decide in place of ``SecurityConfig.allowed_tools``.
        cache_enabled: Not applied by the kernel (ADR 0011).
        cache_ttl_seconds: Not applied by the kernel (ADR 0011).
        hot_reload: Not applied by the kernel (ADR 0011).
    """
    enabled: bool = True
    default_decision: str = "deny"
    policy_paths: list[str] = field(default_factory=list)
    cache_enabled: bool = True
    cache_ttl_seconds: int = 300
    hot_reload: bool = False


@dataclass
class ResourceConfig:
    """Resource limits configuration.

    Attributes:
        max_memory_mb: Maximum total memory usage.
        max_cpu_time_ms: Maximum CPU time per operation.
        max_concurrent_agents: Maximum number of concurrent agents.
        max_connections: Maximum external connections.
    """
    max_memory_mb: int = 1024
    max_cpu_time_ms: int = 30000
    max_concurrent_agents: int = 100
    max_connections: int = 100


@dataclass
class KernelConfig:
    """Main configuration for the VAK kernel.

    This is the top-level configuration object that aggregates all
    sub-configurations. Pass it to ``VakKernel`` to customize behavior.

    Attributes:
        name: Name for this kernel instance.
        security: Security and sandboxing settings.
        audit: Audit logging settings.
        policy: Policy engine settings.
        resources: Resource limit settings.
        memory: Memory tier configuration (working, episodic, semantic).
        config_path: Optional path to a YAML/JSON config file to merge with.
        extra: Additional configuration key-value pairs.

    Example::

        from vak.config import KernelConfig, SecurityConfig

        config = KernelConfig(
            name="production-kernel",
            security=SecurityConfig(
                enable_sandboxing=True,
                default_policy_effect="deny",
            ),
        )
    """
    name: str = "vak-kernel"
    security: SecurityConfig = field(default_factory=SecurityConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    resources: ResourceConfig = field(default_factory=ResourceConfig)
    memory: MemoryConfig | None = None
    config_path: str | Path | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the configuration to a dictionary for serialization."""
        from dataclasses import asdict
        return asdict(self)
