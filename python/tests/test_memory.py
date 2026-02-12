"""
Tests for VAK Memory Management APIs.

Tests working memory, episodic memory, and semantic search functionality.
"""

import pytest

from vak import VakKernel, AgentConfig
from vak.memory import Episode, MemoryItem


class TestWorkingMemory:
    """Tests for working memory store and retrieve."""

    def test_store_memory_returns_item(self):
        """Test storing a memory item returns a MemoryItem."""
        kernel = VakKernel.default()
        item = kernel.store_memory("greeting", "hello world")
        assert isinstance(item, MemoryItem)
        assert item.key == "greeting"
        assert item.content == "hello world"
        assert item.priority == "normal"

    def test_store_memory_with_priority(self):
        """Test storing a memory item with custom priority."""
        kernel = VakKernel.default()
        item = kernel.store_memory("critical-data", {"x": 1}, priority="high")
        assert item.priority == "high"

    def test_store_memory_with_metadata(self):
        """Test storing a memory item with metadata."""
        kernel = VakKernel.default()
        item = kernel.store_memory(
            "tagged", "value", metadata={"source": "test", "version": 2}
        )
        assert item.metadata["source"] == "test"
        assert item.metadata["version"] == 2

    def test_retrieve_memory_existing(self):
        """Test retrieving an existing memory item."""
        kernel = VakKernel.default()
        kernel.store_memory("key1", "value1")
        result = kernel.retrieve_memory("key1")
        assert result is not None
        assert isinstance(result, MemoryItem)
        assert result.key == "key1"
        assert result.content == "value1"

    def test_retrieve_memory_nonexistent(self):
        """Test retrieving a non-existent memory item returns None."""
        kernel = VakKernel.default()
        result = kernel.retrieve_memory("does-not-exist")
        assert result is None

    def test_store_overwrite(self):
        """Test that storing with same key overwrites the value."""
        kernel = VakKernel.default()
        kernel.store_memory("key", "old-value")
        kernel.store_memory("key", "new-value")
        result = kernel.retrieve_memory("key")
        assert result is not None
        assert result.content == "new-value"

    def test_store_complex_content(self):
        """Test storing complex content types."""
        kernel = VakKernel.default()
        kernel.store_memory("dict-item", {"nested": {"a": [1, 2, 3]}})
        result = kernel.retrieve_memory("dict-item")
        assert result is not None
        assert result.content["nested"]["a"] == [1, 2, 3]

    def test_store_requires_initialization(self):
        """Test that storing memory requires initialization."""
        kernel = VakKernel()
        with pytest.raises(Exception, match="not initialized"):
            kernel.store_memory("key", "value")


class TestEpisodicMemory:
    """Tests for episodic memory with Merkle chain linking."""

    def test_store_episode_returns_hash(self):
        """Test storing an episode returns a hash string."""
        kernel = VakKernel.default()
        episode = Episode(
            episode_id="ep-001",
            episode_type="observation",
            content="Agent observed a file change",
            agent_id="agent-1",
            timestamp="2026-01-01T00:00:00Z",
        )
        result = kernel.store_episode(episode)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_store_multiple_episodes_different_hashes(self):
        """Test that different episodes produce different hashes."""
        kernel = VakKernel.default()
        hash1 = kernel.store_episode(Episode(
            episode_id="ep-001",
            episode_type="observation",
            content="First event",
            agent_id="agent-1",
            timestamp="2026-01-01T00:00:00Z",
        ))
        hash2 = kernel.store_episode(Episode(
            episode_id="ep-002",
            episode_type="action",
            content="Second event",
            agent_id="agent-1",
            timestamp="2026-01-01T00:01:00Z",
        ))
        assert hash1 != hash2

    def test_retrieve_episodes_empty(self):
        """Test retrieving episodes when none stored."""
        kernel = VakKernel.default()
        episodes = kernel.retrieve_episodes()
        assert isinstance(episodes, list)
        assert len(episodes) == 0

    def test_retrieve_episodes_after_store(self):
        """Test retrieving episodes after storing them."""
        kernel = VakKernel.default()
        kernel.store_episode(Episode(
            episode_id="ep-001",
            episode_type="observation",
            content="Event A",
            agent_id="agent-1",
            timestamp="2026-01-01T00:00:00Z",
        ))
        kernel.store_episode(Episode(
            episode_id="ep-002",
            episode_type="thought",
            content="Event B",
            agent_id="agent-1",
            timestamp="2026-01-01T00:01:00Z",
        ))

        episodes = kernel.retrieve_episodes(limit=10)
        assert len(episodes) == 2
        assert all(isinstance(e, Episode) for e in episodes)

    def test_retrieve_episodes_respects_limit(self):
        """Test that retrieve_episodes respects the limit parameter."""
        kernel = VakKernel.default()
        for i in range(5):
            kernel.store_episode(Episode(
                episode_id=f"ep-{i:03d}",
                episode_type="observation",
                content=f"Event {i}",
                agent_id="agent-1",
                timestamp=f"2026-01-01T00:{i:02d}:00Z",
            ))

        episodes = kernel.retrieve_episodes(limit=3)
        assert len(episodes) == 3

    def test_episodes_have_hash_chain(self):
        """Test that episodes form a hash chain."""
        kernel = VakKernel.default()
        kernel.store_episode(Episode(
            episode_id="ep-001",
            episode_type="observation",
            content="First",
            agent_id="agent-1",
            timestamp="2026-01-01T00:00:00Z",
        ))
        kernel.store_episode(Episode(
            episode_id="ep-002",
            episode_type="action",
            content="Second",
            agent_id="agent-1",
            timestamp="2026-01-01T00:01:00Z",
        ))

        episodes = kernel.retrieve_episodes(limit=10)
        assert len(episodes) == 2
        # Episodes are returned most-recent-first; second episode's
        # previous_hash should match first episode's hash
        recent = episodes[0]
        older = episodes[1]
        assert recent.previous_hash == older.hash


class TestSemanticSearch:
    """Tests for semantic memory search."""

    def test_search_empty_memory(self):
        """Test searching with no memory items returns empty list."""
        kernel = VakKernel.default()
        results = kernel.search_semantic("anything")
        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_matching_content(self):
        """Test searching matches on content."""
        kernel = VakKernel.default()
        kernel.store_memory("doc1", "Python programming language")
        kernel.store_memory("doc2", "Rust systems programming")
        kernel.store_memory("doc3", "Cooking recipes")

        results = kernel.search_semantic("programming")
        assert len(results) >= 2

    def test_search_matching_key(self):
        """Test searching matches on key."""
        kernel = VakKernel.default()
        kernel.store_memory("python-guide", "A guide about snakes")
        kernel.store_memory("rust-manual", "A manual about oxidation")

        results = kernel.search_semantic("python")
        assert len(results) >= 1

    def test_search_respects_top_k(self):
        """Test that search respects top_k limit."""
        kernel = VakKernel.default()
        for i in range(10):
            kernel.store_memory(f"item-{i}", f"test content {i}")

        results = kernel.search_semantic("test", top_k=3)
        assert len(results) <= 3

    def test_search_no_match(self):
        """Test searching with no matching items."""
        kernel = VakKernel.default()
        kernel.store_memory("key", "completely unrelated content")
        results = kernel.search_semantic("zzz_nonexistent_query")
        assert len(results) == 0


class TestAgentContextMemory:
    """Tests for memory operations via agent context."""

    def test_agent_context_store_memory(self):
        """Test storing memory via agent context."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="mem-agent", name="Memory Agent")
        kernel.register_agent(agent)

        with kernel.agent_context("mem-agent") as ctx:
            item = ctx.store_memory("agent-note", "important data")
            assert isinstance(item, MemoryItem)

    def test_agent_context_retrieve_memory(self):
        """Test retrieving memory via agent context."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="mem-agent", name="Memory Agent")
        kernel.register_agent(agent)

        kernel.store_memory("shared-key", "shared-value")

        with kernel.agent_context("mem-agent") as ctx:
            result = ctx.retrieve_memory("shared-key")
            assert result is not None
            assert result.content == "shared-value"
