"""
VAK - Verifiable Agent Kernel Python SDK

A Python SDK providing PyO3 bindings to the Rust-based Verifiable Agent Kernel.
Enables secure, policy-enforced agent execution with comprehensive audit logging.

Quick Start::

    from vak import VakKernel, AgentConfig
    kernel = VakKernel.from_config("config/kernel.yaml")
    agent = AgentConfig(agent_id="my-agent", name="My Agent")
    kernel.register_agent(agent)
    response = kernel.execute_tool("my-agent", "calculator", "add", {"a": 1, "b": 2})

Modular Imports::

    from vak.kernel import VakKernel
    from vak.config import KernelConfig, SecurityConfig
    from vak.policy import PolicyDecision, PolicyEffect, permit, deny
    from vak.agent import AgentConfig
    from vak.audit import AuditEntry, AuditLevel
    from vak.tools import ToolRequest, ToolResponse, RiskLevel
    from vak.exceptions import VakError, PolicyViolationError
"""

from vak._version import __version__
from vak.agent import AgentConfig
from vak.audit import AuditEntry, AuditLevel
from vak.exceptions import (
    AgentNotFoundError,
    AuditError,
    PolicyViolationError,
    ToolExecutionError,
    VakError,
)
from vak.kernel import VakKernel
from vak.policy import PolicyDecision, PolicyEffect, deny, permit
from vak.tools import RiskLevel, ToolRequest, ToolResponse

__all__ = [
    # Version
    "__version__",
    # Core
    "VakKernel",
    # Types
    "AgentConfig",
    "AuditEntry",
    "AuditLevel",
    "PolicyDecision",
    "PolicyEffect",
    "ToolRequest",
    "ToolResponse",
    "RiskLevel",
    # Exceptions
    "VakError",
    "PolicyViolationError",
    "AgentNotFoundError",
    "ToolExecutionError",
    "AuditError",
    # Policy helpers
    "permit",
    "deny",
]
