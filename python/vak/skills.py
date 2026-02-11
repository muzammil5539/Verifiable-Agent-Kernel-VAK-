"""
VAK Skills (WASM Tools)

Define and register WASM-sandboxed skills (tools) for your agents.
Each skill runs in an isolated WebAssembly sandbox with explicit
permissions, providing security guarantees that host-executed code cannot.

Example::

    from vak.skills import SkillManifest, SkillPermissions

    manifest = SkillManifest(
        id="my-analyzer",
        name="Code Analyzer",
        version="1.0.0",
        description="Analyzes code for security vulnerabilities",
        wasm_path="skills/analyzer.wasm",
        permissions=SkillPermissions(
            allow_read_files=["*.py", "*.js"],
            deny_network=True,
        ),
        actions=["analyze", "lint", "format"],
    )

    kernel.register_skill(manifest)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SkillStatus(Enum):
    """Runtime status of a registered skill."""
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    LOADING = "loading"


@dataclass
class SkillPermissions:
    """Permission manifest for a WASM skill.

    Defines exactly what the sandboxed skill is allowed to do.
    Permissions follow the principle of least privilege — everything
    is denied by default.

    Attributes:
        allow_read_files: File glob patterns the skill can read.
        allow_write_files: File glob patterns the skill can write.
        deny_read_files: File glob patterns explicitly denied for reading.
        deny_write_files: File glob patterns explicitly denied for writing.
        allow_network: Whether the skill can make network requests.
        deny_network: Explicitly deny all network access (overrides allow_network).
        allowed_hosts: Hostnames the skill can connect to (if network allowed).
        max_memory_bytes: Maximum memory the skill can allocate.
        max_execution_ms: Maximum execution time.
        allow_env_vars: Environment variables the skill can read.

    Example::

        # Read-only file access, no network
        SkillPermissions(
            allow_read_files=["*.py", "*.js", "*.ts"],
            deny_write_files=["*"],
            deny_network=True,
            max_memory_bytes=64 * 1024 * 1024,
            max_execution_ms=5000,
        )
    """
    allow_read_files: list[str] = field(default_factory=list)
    allow_write_files: list[str] = field(default_factory=list)
    deny_read_files: list[str] = field(default_factory=list)
    deny_write_files: list[str] = field(default_factory=list)
    allow_network: bool = False
    deny_network: bool = True
    allowed_hosts: list[str] = field(default_factory=list)
    max_memory_bytes: int = 64 * 1024 * 1024  # 64 MB
    max_execution_ms: int = 5000
    allow_env_vars: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        from dataclasses import asdict
        return asdict(self)


@dataclass
class SkillManifest:
    """Manifest describing a WASM skill and its capabilities.

    Skills are the primary way agents interact with the outside world.
    Each skill has a manifest that declares its identity, permissions,
    available actions, and I/O schema.

    Attributes:
        id: Unique identifier for this skill.
        name: Human-readable name.
        version: Semantic version string.
        description: What this skill does.
        wasm_path: Path to the WASM binary (or None for built-in skills).
        permissions: Permission constraints for the sandbox.
        actions: List of actions this skill supports.
        input_schema: JSON Schema for input validation (optional).
        output_schema: JSON Schema for output validation (optional).
        signature: Ed25519 signature for verification (optional).
        risk_level: Risk classification ("low", "medium", "high", "critical").
        metadata: Additional configuration.

    Example::

        from vak.skills import SkillManifest, SkillPermissions

        calculator = SkillManifest(
            id="calculator",
            name="Calculator",
            version="1.0.0",
            description="Arithmetic operations in a sandboxed environment",
            actions=["add", "subtract", "multiply", "divide"],
            risk_level="low",
            permissions=SkillPermissions(
                deny_network=True,
                deny_read_files=["*"],
                deny_write_files=["*"],
                max_memory_bytes=16 * 1024 * 1024,
                max_execution_ms=1000,
            ),
        )
    """
    id: str
    name: str
    version: str = "0.1.0"
    description: str = ""
    wasm_path: str | None = None
    permissions: SkillPermissions = field(default_factory=SkillPermissions)
    actions: list[str] = field(default_factory=list)
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    signature: str | None = None
    risk_level: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "wasm_path": self.wasm_path,
            "permissions": self.permissions.to_dict(),
            "actions": self.actions,
            "input_schema": self.input_schema,
            "output_schema": self.output_schema,
            "risk_level": self.risk_level,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SkillManifest:
        """Deserialize from dictionary.

        Args:
            data: Dictionary with manifest fields.

        Returns:
            A SkillManifest instance.
        """
        perms_data = data.get("permissions", {})
        permissions = SkillPermissions(
            allow_read_files=perms_data.get("allow_read_files", []),
            allow_write_files=perms_data.get("allow_write_files", []),
            deny_read_files=perms_data.get("deny_read_files", []),
            deny_write_files=perms_data.get("deny_write_files", []),
            allow_network=perms_data.get("allow_network", False),
            deny_network=perms_data.get("deny_network", True),
            allowed_hosts=perms_data.get("allowed_hosts", []),
            max_memory_bytes=perms_data.get("max_memory_bytes", 64 * 1024 * 1024),
            max_execution_ms=perms_data.get("max_execution_ms", 5000),
            allow_env_vars=perms_data.get("allow_env_vars", []),
        )
        return cls(
            id=data["id"],
            name=data["name"],
            version=data.get("version", "0.1.0"),
            description=data.get("description", ""),
            wasm_path=data.get("wasm_path"),
            permissions=permissions,
            actions=data.get("actions", []),
            input_schema=data.get("input_schema"),
            output_schema=data.get("output_schema"),
            signature=data.get("signature"),
            risk_level=data.get("risk_level", "medium"),
            metadata=data.get("metadata", {}),
        )
