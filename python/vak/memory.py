"""
VAK Memory Configuration

Configure the hierarchical memory system for your AI agents.
VAK implements a multi-tier memory architecture inspired by the CoALA
framework with cryptographic integrity via Merkle DAGs.

Tiers:
    - **Working Memory** (Hot): Current context window with dynamic pruning.
    - **Episodic Memory** (Warm): Time-ordered hash-chained event log.
    - **Semantic Memory** (Cold): Knowledge graph + vector store for retrieval.

Example::

    from vak.memory import MemoryConfig, WorkingMemoryConfig, EpisodicMemoryConfig

    memory = MemoryConfig(
        working=WorkingMemoryConfig(
            max_items=100,
            summarization_threshold=80,
        ),
        episodic=EpisodicMemoryConfig(
            enable_merkle_chain=True,
            max_episodes=10000,
        ),
    )

    kernel = VakKernel(config=KernelConfig(memory=memory))
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MemoryBackend(Enum):
    """Storage backend for memory persistence."""
    MEMORY = "memory"
    SQLITE = "sqlite"
    FILE = "file"


class ItemPriority(Enum):
    """Priority level for working memory items."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    PINNED = "pinned"


@dataclass
class WorkingMemoryConfig:
    """Configuration for the hot context window.

    Working memory holds the active context that gets fed to the LLM.
    It uses LRU eviction with priority-based pinning and dynamic
    summarization to keep context clean and relevant.

    Attributes:
        max_items: Maximum number of items in working memory.
        summarization_threshold: Trigger summarization when usage exceeds this % (0-100).
        enable_priority_pinning: Whether to allow pinning important items.
        default_priority: Default priority for new items.
        max_token_estimate: Approximate max tokens for context window management.
    """
    max_items: int = 100
    summarization_threshold: int = 80
    enable_priority_pinning: bool = True
    default_priority: str = "normal"
    max_token_estimate: int = 8000


@dataclass
class EpisodicMemoryConfig:
    """Configuration for the time-ordered event log.

    Episodic memory stores a hash-chained sequence of events (observations,
    thoughts, actions) as a Merkle chain. Each entry is linked to the
    previous via SHA-256 hash, creating an unforgeable audit trail.

    Attributes:
        enable_merkle_chain: Whether to hash-chain entries for integrity.
        max_episodes: Maximum stored episodes before oldest are archived.
        backend: Storage backend for persistence.
        db_path: Path to database file (for sqlite/file backends).
        retention_days: How long to retain episodes.
    """
    enable_merkle_chain: bool = True
    max_episodes: int = 10000
    backend: str = "memory"
    db_path: str | None = None
    retention_days: int = 90


@dataclass
class SemanticMemoryConfig:
    """Configuration for the knowledge graph and vector store.

    Semantic memory combines structured knowledge (relationships) with
    unstructured retrieval (vector similarity) to provide grounded,
    hallucination-resistant recall.

    Attributes:
        enable_knowledge_graph: Whether to maintain a relationship graph.
        enable_vector_store: Whether to maintain vector embeddings.
        embedding_dimensions: Dimensionality of vector embeddings.
        similarity_threshold: Minimum cosine similarity for retrieval.
        max_results: Maximum results returned per query.
    """
    enable_knowledge_graph: bool = True
    enable_vector_store: bool = True
    embedding_dimensions: int = 384
    similarity_threshold: float = 0.7
    max_results: int = 10


@dataclass
class MemoryConfig:
    """Top-level memory configuration for the VAK kernel.

    Aggregates configuration for all three memory tiers.

    Attributes:
        working: Working (hot) memory configuration.
        episodic: Episodic (warm) memory configuration.
        semantic: Semantic (cold) memory configuration.
        enable_time_travel: Whether to support state snapshots and rollbacks.
        enable_secret_scrubbing: Whether to automatically redact sensitive data.
        content_addressable: Whether to use content-addressable storage for blobs.

    Example::

        from vak.memory import MemoryConfig

        config = MemoryConfig(
            enable_time_travel=True,
            enable_secret_scrubbing=True,
        )
    """
    working: WorkingMemoryConfig = field(default_factory=WorkingMemoryConfig)
    episodic: EpisodicMemoryConfig = field(default_factory=EpisodicMemoryConfig)
    semantic: SemanticMemoryConfig = field(default_factory=SemanticMemoryConfig)
    enable_time_travel: bool = False
    enable_secret_scrubbing: bool = True
    content_addressable: bool = False


@dataclass
class MemoryItem:
    """An item stored in working memory.

    Attributes:
        key: Unique identifier for this item.
        content: The content stored (text, dict, etc.).
        priority: Priority level for eviction ordering.
        metadata: Additional metadata attached to this item.
    """
    key: str
    content: Any
    priority: str = "normal"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Episode:
    """A single episode in episodic memory.

    Each episode represents an event (observation, thought, action)
    in the agent's execution history.

    Attributes:
        episode_id: Unique identifier.
        episode_type: Type of episode ("observation", "thought", "action", "result").
        content: The episode content.
        agent_id: The agent that generated this episode.
        timestamp: ISO-format timestamp.
        previous_hash: Hash of the previous episode (Merkle chain).
        hash: Hash of this episode.
        metadata: Additional context.
    """
    episode_id: str
    episode_type: str
    content: str
    agent_id: str
    timestamp: str
    previous_hash: str = ""
    hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
