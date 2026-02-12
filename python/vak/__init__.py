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
    from vak.policy import PolicyRule, PolicyCondition, PolicyEngine, permit, deny
    from vak.agent import AgentConfig
    from vak.audit import AuditEntry, AuditLevel
    from vak.tools import ToolRequest, ToolResponse, RiskLevel
    from vak.reasoner import Constraint, SafetyRule, ReasonerConfig
    from vak.memory import MemoryConfig, WorkingMemoryConfig, EpisodicMemoryConfig, MemoryItem, Episode
    from vak.skills import SkillManifest, SkillPermissions
    from vak.swarm import SwarmConfig, ConsensusProtocol, VotingConfig, SycophancyDetectionConfig
    from vak.exceptions import VakError, PolicyViolationError
"""

from vak._version import __version__
from vak.agent import AgentConfig
from vak.audit import AuditEntry, AuditLevel
from vak.config import KernelConfig
from vak.exceptions import (
    AgentNotFoundError,
    AuditError,
    PolicyViolationError,
    ToolExecutionError,
    VakError,
)
from vak.kernel import VakKernel
from vak.memory import Episode, MemoryConfig, MemoryItem
from vak.policy import (
    PolicyCondition,
    PolicyDecision,
    PolicyEffect,
    PolicyEngine,
    PolicyRule,
    deny,
    permit,
)
from vak.reasoner import Constraint, ReasonerConfig, SafetyRule
from vak.skills import SkillManifest, SkillPermissions
from vak.swarm import ConsensusProtocol, SwarmConfig, SycophancyDetectionConfig, VotingConfig
from vak.tools import RiskLevel, ToolRequest, ToolResponse

__all__ = [
    # Version
    "__version__",
    # Core
    "VakKernel",
    "KernelConfig",
    # Agent
    "AgentConfig",
    # Audit
    "AuditEntry",
    "AuditLevel",
    # Policy
    "PolicyDecision",
    "PolicyEffect",
    "PolicyRule",
    "PolicyCondition",
    "PolicyEngine",
    "permit",
    "deny",
    # Tools
    "ToolRequest",
    "ToolResponse",
    "RiskLevel",
    # Reasoner / Constraints
    "Constraint",
    "SafetyRule",
    "ReasonerConfig",
    # Memory
    "MemoryConfig",
    "MemoryItem",
    "Episode",
    # Skills
    "SkillManifest",
    "SkillPermissions",
    # Swarm
    "SwarmConfig",
    "ConsensusProtocol",
    "VotingConfig",
    "SycophancyDetectionConfig",
    # Exceptions
    "VakError",
    "PolicyViolationError",
    "AgentNotFoundError",
    "ToolExecutionError",
    "AuditError",
]
