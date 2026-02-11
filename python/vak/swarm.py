"""
VAK Swarm Coordination

Configure multi-agent coordination protocols for your agent swarms.
Implements structured consensus mechanisms that avoid the sycophancy
and groupthink problems of free-form agent chat.

Protocols:
    - **Quadratic Voting**: Budget-constrained voting that rewards conviction.
    - **Debate**: Structured argumentation with formal positions.
    - **Hierarchical**: Leader-follower task delegation.

Example::

    from vak.swarm import SwarmConfig, VotingConfig, ConsensusProtocol

    swarm = SwarmConfig(
        protocol=ConsensusProtocol.QUADRATIC_VOTING,
        voting=VotingConfig(
            token_budget=100,
            quorum_threshold=0.6,
        ),
        max_agents=10,
        enable_sycophancy_detection=True,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConsensusProtocol(Enum):
    """Available consensus protocols for multi-agent coordination."""
    MAJORITY = "majority"
    UNANIMOUS = "unanimous"
    WEIGHTED = "weighted"
    QUADRATIC_VOTING = "quadratic_voting"
    DEBATE = "debate"
    HIERARCHICAL = "hierarchical"


class Topology(Enum):
    """Communication topology for agent swarms."""
    STAR = "star"
    MESH = "mesh"
    RING = "ring"
    HIERARCHICAL = "hierarchical"
    BROADCAST = "broadcast"


@dataclass
class VotingConfig:
    """Configuration for quadratic voting in multi-agent consensus.

    In quadratic voting, the cost of casting N votes on a single option
    is N^2 tokens. This forces agents to distribute their influence
    across issues they truly care about, reducing noise and groupthink.

    Attributes:
        token_budget: Number of influence tokens per agent per round.
        quorum_threshold: Fraction of agents that must vote (0.0-1.0).
        max_rounds: Maximum voting rounds before forcing a decision.
        allow_abstention: Whether agents can abstain from voting.
        quadratic_cost: Whether to use quadratic cost (True) or linear (False).

    Example::

        VotingConfig(
            token_budget=100,
            quorum_threshold=0.6,
            quadratic_cost=True,
        )
    """
    token_budget: int = 100
    quorum_threshold: float = 0.5
    max_rounds: int = 3
    allow_abstention: bool = True
    quadratic_cost: bool = True


@dataclass
class DebateConfig:
    """Configuration for structured debate protocol.

    Agents take formal positions and argue with evidence. A moderator
    agent (or the kernel) evaluates arguments and declares a winner.

    Attributes:
        max_turns_per_side: Maximum turns each side gets to argue.
        require_evidence: Whether arguments must cite evidence/sources.
        moderator_agent_id: Agent ID of the debate moderator (optional).
        scoring_criteria: Criteria for evaluating arguments.
    """
    max_turns_per_side: int = 3
    require_evidence: bool = True
    moderator_agent_id: str | None = None
    scoring_criteria: list[str] = field(
        default_factory=lambda: ["logic", "evidence", "relevance"]
    )


@dataclass
class SycophancyDetectionConfig:
    """Configuration for detecting groupthink in multi-agent systems.

    Monitors voting patterns and agreement rates to detect when agents
    are blindly following the majority rather than reasoning independently.

    Attributes:
        enabled: Whether sycophancy detection is active.
        agreement_threshold: Flag if agreement rate exceeds this (0.0-1.0).
        min_samples: Minimum interactions before detecting patterns.
        diversity_weight: How much to weight opinion diversity in scoring.
    """
    enabled: bool = True
    agreement_threshold: float = 0.9
    min_samples: int = 5
    diversity_weight: float = 0.3


@dataclass
class SwarmConfig:
    """Top-level configuration for multi-agent swarm coordination.

    Attributes:
        protocol: The consensus protocol to use.
        topology: Communication topology.
        voting: Voting configuration (for voting protocols).
        debate: Debate configuration (for debate protocol).
        sycophancy: Sycophancy detection configuration.
        max_agents: Maximum agents in the swarm.
        message_timeout_ms: Timeout for inter-agent messages.

    Example::

        from vak.swarm import SwarmConfig, ConsensusProtocol, VotingConfig

        config = SwarmConfig(
            protocol=ConsensusProtocol.QUADRATIC_VOTING,
            voting=VotingConfig(token_budget=100),
            max_agents=10,
            enable_sycophancy_detection=True,
        )
    """
    protocol: ConsensusProtocol = ConsensusProtocol.MAJORITY
    topology: Topology = Topology.MESH
    voting: VotingConfig = field(default_factory=VotingConfig)
    debate: DebateConfig = field(default_factory=DebateConfig)
    sycophancy: SycophancyDetectionConfig = field(default_factory=SycophancyDetectionConfig)
    max_agents: int = 10
    message_timeout_ms: int = 30000
