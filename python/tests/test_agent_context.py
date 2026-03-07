"""
Tests for the internal _AgentContext class in the VAK Python SDK.
"""

import pytest
from unittest.mock import MagicMock
from typing import Any

from vak.agent import _AgentContext
from vak.kernel import VakKernel
from vak.tools import ToolResponse
from vak.policy import PolicyDecision, PolicyEffect


@pytest.fixture
def mock_kernel():
    return MagicMock(spec=VakKernel)


@pytest.fixture
def agent_id():
    return "test-agent-123"


@pytest.fixture
def agent_context(mock_kernel, agent_id):
    return _AgentContext(mock_kernel, agent_id)


class TestAgentContext:
    """Tests for _AgentContext delegation logic."""

    def test_agent_id_property(self, agent_context, agent_id):
        """Test that agent_id property returns the correct ID."""
        assert agent_context.agent_id == agent_id

    def test_execute_tool(self, agent_context, mock_kernel, agent_id):
        """Test that execute_tool delegates correctly to the kernel."""
        # Setup
        tool_id = "calc"
        action = "add"
        parameters = {"a": 1, "b": 2}
        expected_response = ToolResponse(request_id="req-1", success=True, result=3)
        mock_kernel.execute_tool.return_value = expected_response

        # Execute
        result = agent_context.execute_tool(
            tool_id, action, parameters, timeout_ms=1000
        )

        # Verify
        mock_kernel.execute_tool.assert_called_once_with(
            agent_id, tool_id, action, parameters, timeout_ms=1000
        )
        assert result == expected_response

    def test_evaluate_policy(self, agent_context, mock_kernel, agent_id):
        """Test that evaluate_policy delegates correctly to the kernel."""
        # Setup
        action = "file.read"
        context = {"path": "/etc/passwd"}
        expected_decision = PolicyDecision(
            effect=PolicyEffect.DENY, policy_id="p1", reason="blocked"
        )
        mock_kernel.evaluate_policy.return_value = expected_decision

        # Execute
        result = agent_context.evaluate_policy(action, context)

        # Verify
        mock_kernel.evaluate_policy.assert_called_once_with(
            agent_id, action, context
        )
        assert result == expected_decision

    def test_create_audit_entry(self, agent_context, mock_kernel, agent_id):
        """Test that create_audit_entry delegates correctly to the kernel."""
        # Setup
        action = "access"
        resource = "db"
        details = {"key": "val"}
        expected_entry_id = "audit-456"
        mock_kernel.create_audit_entry.return_value = expected_entry_id

        # Execute
        result = agent_context.create_audit_entry(action, resource, details=details)

        # Verify
        mock_kernel.create_audit_entry.assert_called_once_with(
            agent_id, action, resource, details=details
        )
        assert result == expected_entry_id

    def test_store_memory(self, agent_context, mock_kernel):
        """Test that store_memory delegates correctly to the kernel."""
        # Setup
        key = "last_result"
        value = 42
        priority = "high"
        metadata = {"source": "calc"}
        mock_kernel.store_memory.return_value = "item-id"

        # Execute
        result = agent_context.store_memory(key, value, priority, metadata)

        # Verify
        mock_kernel.store_memory.assert_called_once_with(
            key, value, priority, metadata
        )
        assert result == "item-id"

    def test_retrieve_memory(self, agent_context, mock_kernel):
        """Test that retrieve_memory delegates correctly to the kernel."""
        # Setup
        key = "some_key"
        mock_kernel.retrieve_memory.return_value = {"data": "val"}

        # Execute
        result = agent_context.retrieve_memory(key)

        # Verify
        mock_kernel.retrieve_memory.assert_called_once_with(key)
        assert result == {"data": "val"}

    def test_create_vote(self, agent_context, mock_kernel):
        """Test that create_vote delegates correctly to the kernel."""
        # Setup
        proposal = "Should we upgrade?"
        config = {"token_budget": 10}
        mock_kernel.create_voting_session.return_value = "vote-789"

        # Execute
        result = agent_context.create_vote(proposal, config)

        # Verify
        mock_kernel.create_voting_session.assert_called_once_with(proposal, config)
        assert result == "vote-789"

    def test_cast_vote(self, agent_context, mock_kernel, agent_id):
        """Test that cast_vote delegates correctly to the kernel."""
        # Setup
        session_id = "vote-789"
        direction = "for"
        weight = 5
        expected_result = {"success": True}
        mock_kernel.cast_vote.return_value = expected_result

        # Execute
        result = agent_context.cast_vote(session_id, direction, weight)

        # Verify
        mock_kernel.cast_vote.assert_called_once_with(
            session_id, agent_id, direction, weight
        )
        assert result == expected_result
