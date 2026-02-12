"""
Tests for VAK Swarm Coordination APIs.

Tests quadratic voting, vote tallying, and sycophancy detection.
"""

import pytest

from vak import VakKernel, AgentConfig


class TestVotingSessionCreation:
    """Tests for creating voting sessions."""

    def test_create_voting_session(self):
        """Test creating a basic voting session."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Should we deploy?")
        assert isinstance(session_id, str)
        assert len(session_id) > 0

    def test_create_voting_session_with_config(self):
        """Test creating a session with custom configuration."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session(
            "Approve budget?",
            config={
                "token_budget": 200,
                "quorum_threshold": 0.75,
                "quadratic_cost": False,
            },
        )
        assert isinstance(session_id, str)
        assert len(session_id) > 0

    def test_create_multiple_sessions(self):
        """Test creating multiple independent sessions."""
        kernel = VakKernel.default()
        s1 = kernel.create_voting_session("Proposal A")
        s2 = kernel.create_voting_session("Proposal B")
        assert s1 != s2

    def test_create_session_requires_initialization(self):
        """Test that creating a session requires kernel initialization."""
        kernel = VakKernel()
        with pytest.raises(Exception, match="not initialized"):
            kernel.create_voting_session("test")


class TestCastingVotes:
    """Tests for casting votes in sessions."""

    def test_cast_vote_for(self):
        """Test casting a 'for' vote."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Test proposal")
        result = kernel.cast_vote(session_id, "agent-1", "for")
        assert result["success"] is True

    def test_cast_vote_against(self):
        """Test casting an 'against' vote."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Test proposal")
        result = kernel.cast_vote(session_id, "agent-1", "against")
        assert result["success"] is True

    def test_cast_vote_with_weight(self):
        """Test casting a weighted vote."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Test proposal")
        result = kernel.cast_vote(session_id, "agent-1", "for", weight=3)
        assert result["success"] is True
        # Quadratic cost: 3^2 = 9
        assert result["cost"] == 9

    def test_quadratic_cost_calculation(self):
        """Test that quadratic cost is weight^2."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Test proposal")

        r1 = kernel.cast_vote(session_id, "agent-1", "for", weight=1)
        assert r1["cost"] == 1  # 1^2

        r2 = kernel.cast_vote(session_id, "agent-2", "for", weight=2)
        assert r2["cost"] == 4  # 2^2

        r3 = kernel.cast_vote(session_id, "agent-3", "for", weight=5)
        assert r3["cost"] == 25  # 5^2

    def test_linear_cost_when_configured(self):
        """Test linear cost when quadratic_cost is False."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session(
            "Test proposal", config={"quadratic_cost": False}
        )
        result = kernel.cast_vote(session_id, "agent-1", "for", weight=5)
        assert result["success"] is True
        assert result["cost"] == 5  # Linear cost

    def test_cast_vote_invalid_session(self):
        """Test casting vote on nonexistent session fails."""
        kernel = VakKernel.default()
        result = kernel.cast_vote("nonexistent-session", "agent-1", "for")
        assert result["success"] is False

    def test_multiple_agents_vote(self):
        """Test multiple agents voting on same session."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Multi-vote test")

        agents = ["agent-1", "agent-2", "agent-3"]
        for agent in agents:
            result = kernel.cast_vote(session_id, agent, "for")
            assert result["success"] is True


class TestVoteTallying:
    """Tests for tallying votes."""

    def test_tally_basic(self):
        """Test basic vote tallying."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Tally test")

        kernel.cast_vote(session_id, "agent-1", "for", weight=2)
        kernel.cast_vote(session_id, "agent-2", "against", weight=1)
        kernel.cast_vote(session_id, "agent-3", "for", weight=1)

        tally = kernel.tally_votes(session_id)
        assert tally["success"] is True
        assert tally["winner"] == "for"
        assert tally["tally"]["for"] == 3  # 2 + 1
        assert tally["tally"]["against"] == 1
        assert tally["unique_voters"] == 3
        assert tally["status"] == "closed"

    def test_tally_closes_session(self):
        """Test that tallying closes the session."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Close test")
        kernel.cast_vote(session_id, "agent-1", "for")

        tally = kernel.tally_votes(session_id)
        assert tally["status"] == "closed"

        # Voting on closed session should fail
        result = kernel.cast_vote(session_id, "agent-2", "for")
        assert result["success"] is False

    def test_tally_invalid_session(self):
        """Test tallying nonexistent session fails."""
        kernel = VakKernel.default()
        result = kernel.tally_votes("nonexistent-session")
        assert result["success"] is False

    def test_tally_empty_session(self):
        """Test tallying session with no votes."""
        kernel = VakKernel.default()
        session_id = kernel.create_voting_session("Empty test")
        tally = kernel.tally_votes(session_id)
        assert tally["success"] is True
        assert tally["winner"] is None
        assert tally["unique_voters"] == 0


class TestSycophancyDetection:
    """Tests for sycophancy/groupthink detection."""

    def test_detect_no_sycophancy(self):
        """Test detection with diverse voting patterns."""
        kernel = VakKernel.default()
        session_history = [
            {
                "votes": [
                    {"agent_id": "a1", "direction": "for"},
                    {"agent_id": "a2", "direction": "against"},
                    {"agent_id": "a3", "direction": "for"},
                    {"agent_id": "a4", "direction": "against"},
                ]
            },
        ]
        result = kernel.detect_sycophancy(session_history)
        assert result["sycophancy_detected"] is False
        assert result["risk_level"] == "low"

    def test_detect_high_sycophancy(self):
        """Test detection with unanimous voting patterns."""
        kernel = VakKernel.default()
        session_history = [
            {
                "votes": [
                    {"agent_id": f"a{i}", "direction": "for"}
                    for i in range(20)
                ]
            },
        ]
        result = kernel.detect_sycophancy(session_history)
        assert result["sycophancy_detected"] is True
        assert result["agreement_rate"] == 1.0
        assert result["risk_level"] == "critical"

    def test_detect_sycophancy_empty_history(self):
        """Test detection with empty history."""
        kernel = VakKernel.default()
        result = kernel.detect_sycophancy([])
        assert result["sycophancy_detected"] is False
        assert result["risk_level"] == "low"

    def test_detect_sycophancy_medium_risk(self):
        """Test detection with moderate agreement rates."""
        kernel = VakKernel.default()
        # 8 for, 2 against = 80% agreement
        session_history = [
            {
                "votes": [
                    {"agent_id": f"a{i}", "direction": "for"}
                    for i in range(8)
                ] + [
                    {"agent_id": f"dissent{i}", "direction": "against"}
                    for i in range(2)
                ]
            },
        ]
        result = kernel.detect_sycophancy(session_history)
        assert result["sycophancy_detected"] is False
        assert result["risk_level"] == "medium"

    def test_detect_sycophancy_requires_initialization(self):
        """Test that sycophancy detection requires initialization."""
        kernel = VakKernel()
        with pytest.raises(Exception, match="not initialized"):
            kernel.detect_sycophancy([])


class TestAgentContextSwarm:
    """Tests for swarm operations via agent context."""

    def test_agent_context_create_vote(self):
        """Test creating a vote via agent context."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="voter-1", name="Voter")
        kernel.register_agent(agent)

        with kernel.agent_context("voter-1") as ctx:
            session_id = ctx.create_vote("Should we proceed?")
            assert isinstance(session_id, str)
            assert len(session_id) > 0

    def test_agent_context_cast_vote(self):
        """Test casting a vote via agent context."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="voter-1", name="Voter")
        kernel.register_agent(agent)

        session_id = kernel.create_voting_session("Context vote test")

        with kernel.agent_context("voter-1") as ctx:
            result = ctx.cast_vote(session_id, "for", weight=2)
            assert result["success"] is True
            assert result["cost"] == 4  # 2^2 quadratic
