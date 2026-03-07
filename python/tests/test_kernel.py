"""
Tests for VAK Kernel functionality.

Tests the core kernel class and its operations.
"""

import pytest
from datetime import datetime

from vak import (
    VakKernel,
    AgentConfig,
    AuditLevel,
    PolicyDecision,
    PolicyEffect,
    ToolRequest,
    ToolResponse,
    VakError,
    PolicyViolationError,
    AgentNotFoundError,
    ToolExecutionError,
)


class TestVakKernelCreation:
    """Tests for kernel creation and initialization."""

    def test_create_default_kernel(self):
        """Test creating kernel with default configuration."""
        kernel = VakKernel.default()
        assert kernel.is_initialized

    def test_create_kernel_not_initialized(self):
        """Test that kernel is not initialized before initialize() call."""
        kernel = VakKernel()
        assert not kernel.is_initialized

    def test_initialize_kernel(self):
        """Test explicit initialization."""
        kernel = VakKernel()
        kernel.initialize()
        assert kernel.is_initialized

    def test_double_initialize_is_idempotent(self):
        """Test that calling initialize() twice is safe."""
        kernel = VakKernel()
        kernel.initialize()
        kernel.initialize()  # Should not raise
        assert kernel.is_initialized

    def test_shutdown_kernel(self):
        """Test kernel shutdown."""
        kernel = VakKernel.default()
        kernel.shutdown()
        assert not kernel.is_initialized

    def test_shutdown_clears_agents(self):
        """Test that shutdown clears registered agents."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        kernel.shutdown()
        
        # Re-initialize and verify agent is gone
        kernel.initialize()
        assert "test-agent" not in kernel.list_agents()


class TestAgentManagement:
    """Tests for agent registration and management."""

    def test_register_agent(self):
        """Test registering an agent."""
        kernel = VakKernel.default()
        agent = AgentConfig(
            agent_id="test-agent",
            name="Test Agent",
            description="A test agent"
        )
        kernel.register_agent(agent)
        assert "test-agent" in kernel.list_agents()

    def test_get_registered_agent(self):
        """Test retrieving a registered agent."""
        kernel = VakKernel.default()
        agent = AgentConfig(
            agent_id="test-agent",
            name="Test Agent",
            capabilities=["testing"]
        )
        kernel.register_agent(agent)
        
        retrieved = kernel.get_agent("test-agent")
        assert retrieved.agent_id == "test-agent"
        assert retrieved.name == "Test Agent"
        assert "testing" in retrieved.capabilities

    def test_get_unregistered_agent_raises(self):
        """Test that getting an unregistered agent raises."""
        kernel = VakKernel.default()
        with pytest.raises(AgentNotFoundError) as exc_info:
            kernel.get_agent("nonexistent")
        assert exc_info.value.agent_id == "nonexistent"

    def test_unregister_agent(self):
        """Test unregistering an agent."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        kernel.unregister_agent("test-agent")
        assert "test-agent" not in kernel.list_agents()

    def test_unregister_nonexistent_agent_raises(self):
        """Test that unregistering nonexistent agent raises."""
        kernel = VakKernel.default()
        with pytest.raises(AgentNotFoundError):
            kernel.unregister_agent("nonexistent")

    def test_list_agents_empty(self):
        """Test listing agents when none registered."""
        kernel = VakKernel.default()
        assert kernel.list_agents() == []

    def test_list_agents_multiple(self):
        """Test listing multiple registered agents."""
        kernel = VakKernel.default()
        for i in range(3):
            agent = AgentConfig(agent_id=f"agent-{i}", name=f"Agent {i}")
            kernel.register_agent(agent)
        
        agents = kernel.list_agents()
        assert len(agents) == 3
        assert "agent-0" in agents
        assert "agent-1" in agents
        assert "agent-2" in agents


class TestPolicyEvaluation:
    """Tests for policy evaluation."""

    def test_evaluate_policy_default_allow(self):
        """Test that default policy allows actions (stub mode)."""
        kernel = VakKernel.default()
        decision = kernel.evaluate_policy(
            agent_id="system",
            action="test.action"
        )
        # In stub mode, default is allow
        assert decision.is_allowed()

    def test_evaluate_policy_with_context(self):
        """Test policy evaluation with context."""
        kernel = VakKernel.default()
        decision = kernel.evaluate_policy(
            agent_id="system",
            action="tool.execute",
            context={"tool_id": "calculator", "amount": 500}
        )
        assert isinstance(decision, PolicyDecision)

    def test_custom_policy_hook_deny(self):
        """Test custom policy hook that denies."""
        kernel = VakKernel.default()
        
        def deny_dangerous(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            if action.startswith("dangerous."):
                return PolicyDecision(
                    effect=PolicyEffect.DENY,
                    policy_id="custom-deny",
                    reason="Dangerous action blocked"
                )
            return None
        
        kernel.add_policy_hook(deny_dangerous)
        
        # Normal action allowed
        normal_decision = kernel.evaluate_policy("agent", "normal.action")
        assert normal_decision.is_allowed()
        
        # Dangerous action denied
        dangerous_decision = kernel.evaluate_policy("agent", "dangerous.delete")
        assert dangerous_decision.is_denied()

    def test_remove_policy_hook(self):
        """Test removing a policy hook."""
        kernel = VakKernel.default()
        
        def deny_all(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                policy_id="deny-all",
                reason="All denied"
            )
        
        kernel.add_policy_hook(deny_all)
        
        # Should be denied
        decision1 = kernel.evaluate_policy("agent", "test")
        assert decision1.is_denied()
        
        # Remove hook
        kernel.remove_policy_hook(deny_all)
        
        # Should be allowed now
        decision2 = kernel.evaluate_policy("agent", "test")
        assert decision2.is_allowed()


class TestToolExecution:
    """Tests for tool execution."""

    def test_execute_tool_basic(self):
        """Test basic tool execution."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        
        response = kernel.execute_tool(
            agent_id="test-agent",
            tool_id="calculator",
            action="add",
            parameters={"a": 1, "b": 2}
        )
        
        assert isinstance(response, ToolResponse)
        assert response.success

    def test_execute_tool_unregistered_agent(self):
        """Test that executing for unregistered agent raises."""
        kernel = VakKernel.default()
        
        with pytest.raises(AgentNotFoundError):
            kernel.execute_tool(
                agent_id="nonexistent",
                tool_id="calculator",
                action="add"
            )

    def test_execute_tool_custom_timeout(self):
        """Test tool execution with custom timeout."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        
        response = kernel.execute_tool(
            agent_id="test-agent",
            tool_id="slow_tool",
            action="process",
            timeout_ms=30000
        )
        
        assert response.success

    def test_execute_tool_request_object(self):
        """Test executing with ToolRequest object."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        
        request = ToolRequest(
            tool_id="calculator",
            agent_id="test-agent",
            action="multiply",
            parameters={"a": 3, "b": 4}
        )
        
        response = kernel.execute_tool_request(request)
        assert response.success

    def test_list_tools(self):
        """Test listing available tools."""
        kernel = VakKernel.default()
        tools = kernel.list_tools()
        # In stub mode, may return empty or predefined tools
        assert isinstance(tools, list)


class TestAuditLogging:
    """Tests for audit logging functionality."""

    def test_create_audit_entry(self):
        """Test creating an audit entry."""
        kernel = VakKernel.default()
        
        entry_id = kernel.create_audit_entry(
            agent_id="test-agent",
            action="test.action",
            resource="test-resource"
        )
        
        assert entry_id is not None
        assert len(entry_id) > 0

    def test_create_audit_entry_with_level(self):
        """Test creating audit entry with specific level."""
        kernel = VakKernel.default()
        
        entry_id = kernel.create_audit_entry(
            agent_id="test-agent",
            action="dangerous.action",
            resource="sensitive-resource",
            level=AuditLevel.WARNING
        )
        
        assert entry_id is not None

    def test_create_audit_entry_with_details(self):
        """Test creating audit entry with details."""
        kernel = VakKernel.default()
        
        entry_id = kernel.create_audit_entry(
            agent_id="test-agent",
            action="data.modify",
            resource="database",
            details={"rows_affected": 5, "table": "users"}
        )
        
        assert entry_id is not None

    def test_create_hierarchical_audit_entry(self):
        """Test creating a child audit entry."""
        kernel = VakKernel.default()
        
        parent_id = kernel.create_audit_entry(
            agent_id="test-agent",
            action="workflow.start",
            resource="workflow-1"
        )
        
        child_id = kernel.create_audit_entry(
            agent_id="test-agent",
            action="workflow.step",
            resource="workflow-1",
            parent_entry_id=parent_id
        )
        
        assert child_id != parent_id

    def test_get_audit_logs_empty(self):
        """Test getting audit logs when empty."""
        kernel = VakKernel.default()
        logs = kernel.get_audit_logs()
        # May return empty in stub mode
        assert isinstance(logs, list)

    def test_get_audit_logs_with_filters(self):
        """Test getting audit logs with filters."""
        kernel = VakKernel.default()
        logs = kernel.get_audit_logs(
            agent_id="specific-agent",
            level=AuditLevel.WARNING,
            limit=10
        )
        assert isinstance(logs, list)


class TestAgentContext:
    """Tests for agent context manager."""

    def test_agent_context_basic(self):
        """Test using agent context manager."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        
        with kernel.agent_context("test-agent") as ctx:
            assert ctx.agent_id == "test-agent"

    def test_agent_context_execute_tool(self):
        """Test executing tool within agent context."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        
        with kernel.agent_context("test-agent") as ctx:
            response = ctx.execute_tool(
                tool_id="calculator",
                action="add",
                parameters={"a": 1, "b": 2}
            )
            assert response.success

    def test_agent_context_evaluate_policy(self):
        """Test evaluating policy within agent context."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        
        with kernel.agent_context("test-agent") as ctx:
            decision = ctx.evaluate_policy("test.action")
            assert isinstance(decision, PolicyDecision)

    def test_agent_context_create_audit_entry(self):
        """Test creating audit entry within agent context."""
        kernel = VakKernel.default()
        agent = AgentConfig(agent_id="test-agent", name="Test")
        kernel.register_agent(agent)
        
        with kernel.agent_context("test-agent") as ctx:
            entry_id = ctx.create_audit_entry(
                action="test.action",
                resource="test-resource"
            )
            assert entry_id is not None

    def test_agent_context_unregistered_raises(self):
        """Test that context for unregistered agent raises."""
        kernel = VakKernel.default()
        
        with pytest.raises(AgentNotFoundError):
            with kernel.agent_context("nonexistent"):
                pass


class TestErrorHandling:
    """Tests for error handling."""

    def test_operation_without_initialization_raises(self):
        """Test that operations without initialization raise."""
        kernel = VakKernel()
        # Don't call initialize()
        
        with pytest.raises(VakError, match="not initialized"):
            kernel.register_agent(AgentConfig(agent_id="a", name="A"))

    def test_vak_error_base_class(self):
        """Test VakError as base exception."""
        error = VakError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_policy_violation_error(self):
        """Test PolicyViolationError contains decision."""
        decision = PolicyDecision(
            effect=PolicyEffect.DENY,
            policy_id="strict-policy",
            reason="Action not permitted"
        )
        error = PolicyViolationError(decision)
        
        assert error.decision == decision
        assert "Action not permitted" in str(error)

    def test_agent_not_found_error(self):
        """Test AgentNotFoundError contains agent_id."""
        error = AgentNotFoundError("missing-agent")
        
        assert error.agent_id == "missing-agent"
        assert "missing-agent" in str(error)

    def test_tool_execution_error(self):
        """Test ToolExecutionError contains tool_id and error."""
        error = ToolExecutionError("broken-tool", "Internal error")
        
        assert error.tool_id == "broken-tool"
        assert error.error == "Internal error"
        assert "broken-tool" in str(error)


class TestKernelRepr:
    """Tests for kernel string representations."""

    def test_kernel_has_config_path(self):
        """Test kernel stores config path."""
        kernel = VakKernel("/path/to/config.yaml")
        assert kernel.config_path is not None


class TestPolicyHookChain:
    """Tests for policy hook chaining."""

    def test_multiple_hooks_first_wins(self):
        """Test that first returning hook wins."""
        kernel = VakKernel.default()
        
        def hook1(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            if action == "test":
                return PolicyDecision(
                    effect=PolicyEffect.ALLOW,
                    policy_id="hook1",
                    reason="Hook 1 allowed"
                )
            return None
        
        def hook2(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                policy_id="hook2",
                reason="Hook 2 denied"
            )
        
        kernel.add_policy_hook(hook1)
        kernel.add_policy_hook(hook2)
        
        # First hook should win for "test" action
        decision = kernel.evaluate_policy("agent", "test")
        assert decision.policy_id == "hook1"
        
        # Second hook wins for other actions
        decision = kernel.evaluate_policy("agent", "other")
        assert decision.policy_id == "hook2"

    def test_hook_returns_none_continues_chain(self):
        """Test that returning None continues to next hook."""
        kernel = VakKernel.default()
        
        call_count = {"hook1": 0, "hook2": 0}
        
        def hook1(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            call_count["hook1"] += 1
            return None  # Pass to next
        
        def hook2(agent_id: str, action: str, context: dict) -> PolicyDecision | None:
            call_count["hook2"] += 1
            return PolicyDecision(
                effect=PolicyEffect.ALLOW,
                policy_id="hook2",
                reason="Hook 2"
            )
        
        kernel.add_policy_hook(hook1)
        kernel.add_policy_hook(hook2)
        
        kernel.evaluate_policy("agent", "action")
        
        assert call_count["hook1"] == 1
        assert call_count["hook2"] == 1
