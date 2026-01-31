"""
Tests for VAK type definitions.

Tests the core data types used throughout the Python SDK.
"""

import pytest
from datetime import datetime

from vak.types import (
    AgentConfig,
    AuditEntry,
    AuditLevel,
    PolicyDecision,
    PolicyEffect,
    ToolRequest,
    ToolResponse,
)


class TestPolicyEffect:
    """Tests for the PolicyEffect enum."""

    def test_allow_value(self):
        """Test ALLOW enum value."""
        assert PolicyEffect.ALLOW.value == "allow"

    def test_deny_value(self):
        """Test DENY enum value."""
        assert PolicyEffect.DENY.value == "deny"

    def test_audit_value(self):
        """Test AUDIT enum value."""
        assert PolicyEffect.AUDIT.value == "audit"


class TestAuditLevel:
    """Tests for the AuditLevel enum."""

    def test_debug_value(self):
        """Test DEBUG level value."""
        assert AuditLevel.DEBUG.value == "debug"

    def test_info_value(self):
        """Test INFO level value."""
        assert AuditLevel.INFO.value == "info"

    def test_warning_value(self):
        """Test WARNING level value."""
        assert AuditLevel.WARNING.value == "warning"

    def test_error_value(self):
        """Test ERROR level value."""
        assert AuditLevel.ERROR.value == "error"

    def test_critical_value(self):
        """Test CRITICAL level value."""
        assert AuditLevel.CRITICAL.value == "critical"


class TestPolicyDecision:
    """Tests for PolicyDecision dataclass."""

    def test_create_allow_decision(self):
        """Test creating an allow decision."""
        decision = PolicyDecision(
            effect=PolicyEffect.ALLOW,
            policy_id="test-policy",
            reason="Test allowed"
        )
        assert decision.is_allowed()
        assert not decision.is_denied()

    def test_create_deny_decision(self):
        """Test creating a deny decision."""
        decision = PolicyDecision(
            effect=PolicyEffect.DENY,
            policy_id="test-policy",
            reason="Test denied"
        )
        assert decision.is_denied()
        assert not decision.is_allowed()

    def test_decision_with_matched_rules(self):
        """Test decision with matched rules."""
        decision = PolicyDecision(
            effect=PolicyEffect.ALLOW,
            policy_id="test-policy",
            reason="Multiple rules",
            matched_rules=["rule1", "rule2"]
        )
        assert decision.matched_rules == ["rule1", "rule2"]

    def test_decision_with_metadata(self):
        """Test decision with metadata."""
        decision = PolicyDecision(
            effect=PolicyEffect.ALLOW,
            policy_id="test-policy",
            reason="With metadata",
            metadata={"key": "value", "count": 42}
        )
        assert decision.metadata == {"key": "value", "count": 42}

    def test_decision_immutability(self):
        """Test that PolicyDecision is immutable (frozen)."""
        decision = PolicyDecision(
            effect=PolicyEffect.ALLOW,
            policy_id="test-policy",
            reason="Test"
        )
        with pytest.raises((TypeError, AttributeError)):
            decision.effect = PolicyEffect.DENY  # type: ignore


class TestToolRequest:
    """Tests for ToolRequest dataclass."""

    def test_create_basic_request(self):
        """Test creating a basic tool request."""
        request = ToolRequest(
            tool_id="calculator",
            agent_id="agent-123",
            action="add"
        )
        assert request.tool_id == "calculator"
        assert request.agent_id == "agent-123"
        assert request.action == "add"
        assert request.parameters == {}

    def test_request_with_parameters(self):
        """Test request with parameters."""
        request = ToolRequest(
            tool_id="calculator",
            agent_id="agent-123",
            action="add",
            parameters={"a": 1, "b": 2}
        )
        assert request.parameters == {"a": 1, "b": 2}

    def test_request_default_timeout(self):
        """Test default timeout value."""
        request = ToolRequest(
            tool_id="test",
            agent_id="agent",
            action="test"
        )
        assert request.timeout_ms == 5000

    def test_request_default_memory_limit(self):
        """Test default memory limit (64 MB)."""
        request = ToolRequest(
            tool_id="test",
            agent_id="agent",
            action="test"
        )
        assert request.memory_limit_bytes == 64 * 1024 * 1024

    def test_request_custom_limits(self):
        """Test custom timeout and memory limits."""
        request = ToolRequest(
            tool_id="test",
            agent_id="agent",
            action="test",
            timeout_ms=10000,
            memory_limit_bytes=128 * 1024 * 1024
        )
        assert request.timeout_ms == 10000
        assert request.memory_limit_bytes == 128 * 1024 * 1024


class TestToolResponse:
    """Tests for ToolResponse dataclass."""

    def test_successful_response(self):
        """Test a successful tool response."""
        response = ToolResponse(
            request_id="req-123",
            success=True,
            result={"answer": 42}
        )
        assert response.success
        assert response.result == {"answer": 42}
        assert response.error is None

    def test_failed_response(self):
        """Test a failed tool response."""
        response = ToolResponse(
            request_id="req-123",
            success=False,
            error="Division by zero"
        )
        assert not response.success
        assert response.error == "Division by zero"
        assert response.result is None

    def test_response_unwrap_success(self):
        """Test unwrap() on successful response."""
        response = ToolResponse(
            request_id="req-123",
            success=True,
            result="Hello, World!"
        )
        assert response.unwrap() == "Hello, World!"

    def test_response_unwrap_failure(self):
        """Test unwrap() on failed response raises exception."""
        response = ToolResponse(
            request_id="req-123",
            success=False,
            error="Something went wrong"
        )
        with pytest.raises(RuntimeError, match="Something went wrong"):
            response.unwrap()

    def test_response_with_execution_metrics(self):
        """Test response with execution metrics."""
        response = ToolResponse(
            request_id="req-123",
            success=True,
            result="OK",
            execution_time_ms=150.5,
            memory_used_bytes=1024000
        )
        assert response.execution_time_ms == 150.5
        assert response.memory_used_bytes == 1024000

    def test_response_with_audit_trail(self):
        """Test response with audit trail."""
        response = ToolResponse(
            request_id="req-123",
            success=True,
            result="OK",
            audit_trail=["audit-1", "audit-2", "audit-3"]
        )
        assert len(response.audit_trail) == 3
        assert "audit-1" in response.audit_trail


class TestAuditEntry:
    """Tests for AuditEntry dataclass."""

    def test_create_basic_entry(self):
        """Test creating a basic audit entry."""
        now = datetime.now()
        entry = AuditEntry(
            entry_id="entry-123",
            timestamp=now,
            level=AuditLevel.INFO,
            agent_id="agent-1",
            action="tool.execute",
            resource="calculator"
        )
        assert entry.entry_id == "entry-123"
        assert entry.timestamp == now
        assert entry.level == AuditLevel.INFO
        assert entry.agent_id == "agent-1"

    def test_entry_with_policy_decision(self):
        """Test entry with associated policy decision."""
        decision = PolicyDecision(
            effect=PolicyEffect.ALLOW,
            policy_id="policy-1",
            reason="Allowed"
        )
        entry = AuditEntry(
            entry_id="entry-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            agent_id="agent-1",
            action="tool.execute",
            resource="calculator",
            policy_decision=decision
        )
        assert entry.policy_decision is not None
        assert entry.policy_decision.is_allowed()

    def test_entry_with_parent(self):
        """Test hierarchical entry with parent."""
        entry = AuditEntry(
            entry_id="child-entry",
            timestamp=datetime.now(),
            level=AuditLevel.DEBUG,
            agent_id="agent-1",
            action="sub-action",
            resource="resource",
            parent_entry_id="parent-entry"
        )
        assert entry.parent_entry_id == "parent-entry"

    def test_entry_to_dict(self):
        """Test converting entry to dictionary."""
        now = datetime.now()
        entry = AuditEntry(
            entry_id="entry-123",
            timestamp=now,
            level=AuditLevel.WARNING,
            agent_id="agent-1",
            action="risky.action",
            resource="sensitive-data",
            details={"note": "Potentially dangerous"}
        )
        d = entry.to_dict()
        assert d["entry_id"] == "entry-123"
        assert d["level"] == "warning"
        assert d["details"]["note"] == "Potentially dangerous"

    def test_entry_immutability(self):
        """Test that AuditEntry is immutable (frozen)."""
        entry = AuditEntry(
            entry_id="entry-123",
            timestamp=datetime.now(),
            level=AuditLevel.INFO,
            agent_id="agent-1",
            action="test",
            resource="test"
        )
        with pytest.raises((TypeError, AttributeError)):
            entry.level = AuditLevel.ERROR  # type: ignore


class TestAgentConfig:
    """Tests for AgentConfig dataclass."""

    def test_create_minimal_config(self):
        """Test creating minimal agent config."""
        config = AgentConfig(
            agent_id="agent-1",
            name="Test Agent"
        )
        assert config.agent_id == "agent-1"
        assert config.name == "Test Agent"
        assert config.description == ""
        assert config.capabilities == []
        assert config.allowed_tools == []

    def test_create_full_config(self):
        """Test creating agent config with all fields."""
        config = AgentConfig(
            agent_id="agent-1",
            name="Test Agent",
            description="A test agent",
            capabilities=["code_review", "testing"],
            allowed_tools=["calculator", "web_search"],
            policy_overrides={"max_requests": 100},
            memory_limit_bytes=256 * 1024 * 1024,
            max_concurrent_requests=5,
            trusted=True,
            metadata={"version": "1.0"}
        )
        assert config.description == "A test agent"
        assert "code_review" in config.capabilities
        assert "calculator" in config.allowed_tools
        assert config.trusted

    def test_with_capability(self):
        """Test adding a capability."""
        config = AgentConfig(
            agent_id="agent-1",
            name="Test Agent",
            capabilities=["existing"]
        )
        new_config = config.with_capability("new_capability")
        
        # Original unchanged
        assert "new_capability" not in config.capabilities
        # New config has the capability
        assert "new_capability" in new_config.capabilities
        assert "existing" in new_config.capabilities

    def test_with_capability_no_duplicate(self):
        """Test that with_capability doesn't add duplicates."""
        config = AgentConfig(
            agent_id="agent-1",
            name="Test Agent",
            capabilities=["existing"]
        )
        new_config = config.with_capability("existing")
        assert new_config.capabilities.count("existing") == 1

    def test_with_tool_access(self):
        """Test adding tool access."""
        config = AgentConfig(
            agent_id="agent-1",
            name="Test Agent",
            allowed_tools=["calculator"]
        )
        new_config = config.with_tool_access("web_search")
        
        # Original unchanged
        assert "web_search" not in config.allowed_tools
        # New config has the tool
        assert "web_search" in new_config.allowed_tools
        assert "calculator" in new_config.allowed_tools

    def test_with_tool_access_no_duplicate(self):
        """Test that with_tool_access doesn't add duplicates."""
        config = AgentConfig(
            agent_id="agent-1",
            name="Test Agent",
            allowed_tools=["calculator"]
        )
        new_config = config.with_tool_access("calculator")
        assert new_config.allowed_tools.count("calculator") == 1

    def test_default_memory_limit(self):
        """Test default memory limit is 128 MB."""
        config = AgentConfig(agent_id="agent-1", name="Test")
        assert config.memory_limit_bytes == 128 * 1024 * 1024

    def test_default_max_concurrent_requests(self):
        """Test default max concurrent requests."""
        config = AgentConfig(agent_id="agent-1", name="Test")
        assert config.max_concurrent_requests == 10

    def test_default_trusted_is_false(self):
        """Test default trusted is False."""
        config = AgentConfig(agent_id="agent-1", name="Test")
        assert config.trusted is False
