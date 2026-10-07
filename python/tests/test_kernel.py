"""
Tests for VakKernel.

Policy decisions, tool results, skills and audit records come from the
Rust kernel (ADR 0011). Tests of those use the ``native`` fixture; tests
of what happens without the native module use ``no_native``. Agent
bookkeeping and the error types work either way.
"""

import pytest

from vak import (
    AgentConfig,
    AgentNotFoundError,
    KernelConfig,
    PolicyDecision,
    PolicyEffect,
    PolicyViolationError,
    ToolExecutionError,
    ToolRequest,
    ToolResponse,
    VakError,
    VakKernel,
)
from vak.config import SecurityConfig


def kernel_with(*agents, config=None):
    """An initialized kernel with ``agents`` (ids) registered."""
    kernel = VakKernel(config=config)
    kernel.initialize()
    for agent_id in agents:
        kernel.register_agent(AgentConfig(agent_id=agent_id, name=agent_id))
    return kernel


class TestVakKernelCreation:
    """Kernel creation and lifecycle."""

    def test_create_default_kernel(self):
        kernel = VakKernel.default()
        assert kernel.is_initialized

    def test_create_kernel_not_initialized(self):
        kernel = VakKernel()
        assert not kernel.is_initialized

    def test_initialize_kernel(self):
        kernel = VakKernel()
        kernel.initialize()
        assert kernel.is_initialized

    def test_double_initialize_is_idempotent(self):
        kernel = VakKernel()
        kernel.initialize()
        kernel.initialize()
        assert kernel.is_initialized

    def test_shutdown_kernel(self):
        kernel = VakKernel.default()
        kernel.shutdown()
        assert not kernel.is_initialized

    def test_shutdown_clears_agents(self):
        kernel = kernel_with("test-agent")
        kernel.shutdown()
        kernel.initialize()
        assert "test-agent" not in kernel.list_agents()

    def test_kernel_has_config_path(self):
        kernel = VakKernel("/path/to/config.yaml")
        assert kernel.config_path is not None

    def test_a_config_file_that_does_not_load_is_an_error(self, native):
        with pytest.raises(VakError, match="Failed to initialize kernel"):
            VakKernel.from_config("/nonexistent/kernel.yaml")

    def test_a_config_file_and_settings_together_are_an_error(self, native):
        config = KernelConfig(security=SecurityConfig(blocked_tools=["echo"]))
        kernel = VakKernel("/some/kernel.yaml", config=config)
        with pytest.raises(VakError, match="not both"):
            kernel.initialize()


class TestAgentManagement:
    """Agent registration and bookkeeping."""

    def test_register_agent(self):
        kernel = kernel_with("test-agent")
        assert "test-agent" in kernel.list_agents()

    def test_get_registered_agent(self):
        kernel = VakKernel.default()
        kernel.register_agent(
            AgentConfig(agent_id="test-agent", name="Test Agent", capabilities=["testing"])
        )
        retrieved = kernel.get_agent("test-agent")
        assert retrieved.agent_id == "test-agent"
        assert retrieved.name == "Test Agent"
        assert "testing" in retrieved.capabilities

    def test_get_unregistered_agent_raises(self):
        kernel = VakKernel.default()
        with pytest.raises(AgentNotFoundError) as exc_info:
            kernel.get_agent("nonexistent")
        assert exc_info.value.agent_id == "nonexistent"

    def test_unregister_agent(self):
        kernel = kernel_with("test-agent")
        kernel.unregister_agent("test-agent")
        assert "test-agent" not in kernel.list_agents()

    def test_unregister_nonexistent_agent_raises(self):
        kernel = VakKernel.default()
        with pytest.raises(AgentNotFoundError):
            kernel.unregister_agent("nonexistent")

    def test_list_agents_empty(self):
        assert VakKernel.default().list_agents() == []

    def test_list_agents_multiple(self):
        kernel = kernel_with("agent-0", "agent-1", "agent-2")
        assert sorted(kernel.list_agents()) == ["agent-0", "agent-1", "agent-2"]


@pytest.mark.usefixtures("no_native")
class TestWithoutTheNativeKernel:
    """Without the native module nothing answers in the kernel's place:
    nothing runs, nothing is decided, and there is no audit log."""

    def test_execute_tool_fails_closed(self):
        kernel = kernel_with("test-agent")
        assert not kernel.has_native_kernel
        with pytest.raises(ToolExecutionError, match="nothing ran"):
            kernel.execute_tool("test-agent", "echo", "say", {"text": "hi"})

    @pytest.mark.parametrize(
        "call",
        [
            lambda k: k.evaluate_policy("test-agent", "echo"),
            lambda k: k.list_tools(),
            lambda k: k.list_skills(),
            lambda k: k.get_skill("anything"),
            lambda k: k.load_skill("skill.yaml"),
            lambda k: k.get_audit_logs(),
            lambda k: k.get_audit_entry("anything"),
            lambda k: k.verify_audit_chain(),
            lambda k: k.get_audit_root_hash(),
            lambda k: k.export_audit_receipt(),
        ],
    )
    def test_kernel_answers_raise(self, call):
        kernel = kernel_with("test-agent")
        with pytest.raises(VakError, match="needs the native kernel"):
            call(kernel)


class TestPolicyEvaluation:
    """evaluate_policy is the kernel's Decide stage."""

    def test_a_builtin_tool_is_allowed_by_default(self, native):
        decision = kernel_with("agent").evaluate_policy("agent", "echo")
        assert isinstance(decision, PolicyDecision)
        assert decision.is_allowed()

    def test_an_unknown_tool_is_denied_by_default(self, native):
        decision = kernel_with("agent").evaluate_policy("agent", "no_such_tool")
        assert decision.is_denied()
        assert decision.reason

    def test_settings_reach_the_kernel(self, native):
        config = KernelConfig(security=SecurityConfig(blocked_tools=["calculator"]))
        kernel = kernel_with("agent", config=config)
        assert kernel.evaluate_policy("agent", "echo").is_allowed()
        assert kernel.evaluate_policy("agent", "calculator").is_denied()

    def test_an_unregistered_agent_raises(self, native):
        with pytest.raises(AgentNotFoundError):
            kernel_with().evaluate_policy("nobody", "echo")

    def test_evaluating_records_nothing(self, native):
        kernel = kernel_with("agent")
        kernel.evaluate_policy("agent", "echo")
        assert kernel.get_audit_logs() == []


class TestToolExecution:
    """execute_tool runs through Kernel::execute."""

    def test_execute_tool_basic(self, native):
        kernel = kernel_with("test-agent")
        response = kernel.execute_tool("test-agent", "echo", "say", {"text": "hi"})
        assert isinstance(response, ToolResponse)
        assert response.success is True
        assert response.result == {"action": "say", "params": {"text": "hi"}}
        assert response.receipt["decision_leaf"] == 0
        assert response.receipt["outcome_leaf"] == 1

    def test_execute_tool_unregistered_agent(self, native):
        with pytest.raises(AgentNotFoundError):
            kernel_with().execute_tool("nonexistent", "echo", "say")

    def test_a_kernel_refusal_is_a_policy_violation(self, native):
        kernel = kernel_with("test-agent")
        with pytest.raises(PolicyViolationError) as refused:
            kernel.execute_tool("test-agent", "no_such_tool", "run")
        assert refused.value.decision.is_denied()
        assert refused.value.decision.reason

    def test_an_agents_own_scope_is_enforced(self, native):
        kernel = VakKernel.default()
        kernel.register_agent(
            AgentConfig(agent_id="narrow", name="Narrow", allowed_tools=["calculator"])
        )
        with pytest.raises(PolicyViolationError) as refused:
            kernel.execute_tool("narrow", "echo", "say")
        assert refused.value.decision.policy_id == "agent.scope"

    def test_a_failed_tool_is_not_a_success(self, native):
        # The built-in calculator wants "operation" and "operands".
        response = kernel_with("test-agent").execute_tool("test-agent", "calculator", "add")
        assert response.success is False
        assert response.error

    def test_a_memory_limit_below_the_kernels_is_refused(self, native):
        kernel = kernel_with("test-agent")
        with pytest.raises(ToolExecutionError, match="nothing ran"):
            kernel.execute_tool("test-agent", "echo", "say", memory_limit_bytes=1024 * 1024)

    def test_execute_tool_custom_timeout(self, native):
        response = kernel_with("test-agent").execute_tool(
            "test-agent", "echo", "say", timeout_ms=30000
        )
        assert response.success

    def test_execute_tool_request_object(self, native):
        kernel = kernel_with("test-agent")
        request = ToolRequest(
            tool_id="echo", agent_id="test-agent", action="say", parameters={"n": 1}
        )
        response = kernel.execute_tool_request(request)
        assert response.success
        assert response.result == {"action": "say", "params": {"n": 1}}

    def test_list_tools(self, native):
        tools = kernel_with().list_tools()
        assert {"echo", "calculator", "data_processor", "system_info"} <= set(tools)


class TestAgentContext:
    """The agent context acts as its agent."""

    def test_agent_context_basic(self):
        kernel = kernel_with("test-agent")
        with kernel.agent_context("test-agent") as ctx:
            assert ctx.agent_id == "test-agent"

    def test_agent_context_execute_tool(self, native):
        kernel = kernel_with("test-agent")
        with kernel.agent_context("test-agent") as ctx:
            assert ctx.execute_tool("echo", "say", {"a": 1}).success

    def test_agent_context_evaluate_policy(self, native):
        kernel = kernel_with("test-agent")
        with kernel.agent_context("test-agent") as ctx:
            assert ctx.evaluate_policy("echo").is_allowed()

    def test_agent_context_unregistered_raises(self):
        kernel = VakKernel.default()
        with pytest.raises(AgentNotFoundError):
            with kernel.agent_context("nonexistent"):
                pass


class TestErrorHandling:
    """Error types."""

    def test_operation_without_initialization_raises(self):
        kernel = VakKernel()
        with pytest.raises(VakError, match="not initialized"):
            kernel.register_agent(AgentConfig(agent_id="a", name="A"))

    def test_vak_error_base_class(self):
        error = VakError("Test error")
        assert str(error) == "Test error"
        assert isinstance(error, Exception)

    def test_policy_violation_error(self):
        decision = PolicyDecision(
            effect=PolicyEffect.DENY, policy_id="strict-policy", reason="Action not permitted"
        )
        error = PolicyViolationError(decision)
        assert error.decision == decision
        assert "Action not permitted" in str(error)

    def test_agent_not_found_error(self):
        error = AgentNotFoundError("missing-agent")
        assert error.agent_id == "missing-agent"
        assert "missing-agent" in str(error)

    def test_tool_execution_error(self):
        error = ToolExecutionError("broken-tool", "Internal error")
        assert error.tool_id == "broken-tool"
        assert error.error == "Internal error"
        assert "broken-tool" in str(error)


class TestRemovedMethods:
    """Methods that answered from an engine other than the kernel are gone
    (ADR 0011): a missing method is honest, a wrong answer is not."""

    @pytest.mark.parametrize(
        "name",
        [
            "create_audit_entry",
            "add_policy_hook",
            "remove_policy_hook",
            "load_policies",
            "policy_engine",
            "add_safety_rule",
            "add_constraint",
            "check_constraints",
            "configure_reasoner",
            "reasoner",
            "register_skill",
        ],
    )
    def test_is_not_on_the_kernel(self, name):
        assert not hasattr(VakKernel, name)
