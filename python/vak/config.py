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
        default_policy_effect: Default policy when no rules match ("deny" or "allow").
        allowed_tools: Whitelist of tool IDs that can be executed.
        blocked_tools: Blacklist of tool IDs that cannot be executed.
        max_memory_bytes: Maximum memory per tool execution.
        sandbox_timeout_ms: Default timeout for sandboxed operations.
        rate_limit_per_second: Maximum requests per agent per second.
    """
    enable_sandboxing: bool = True
    signature_verification: bool = False
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
        enabled: Whether policy enforcement is enabled.
        default_decision: Default decision when no rules match ("deny" or "allow").
        policy_paths: Paths to policy definition files (YAML).
        cache_enabled: Whether to cache policy decisions.
        cache_ttl_seconds: Time-to-live for cached decisions.
        hot_reload: Whether to watch policy files for changes.
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
