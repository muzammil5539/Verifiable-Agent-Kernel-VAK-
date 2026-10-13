"""
End-to-end tests of the SDK on the kernel (ADR 0011).

Each test drives calls through ``Kernel::execute`` and checks what the
kernel decided, ran and recorded.
"""

import textwrap

import pytest

from vak import (
    AgentConfig,
    KernelConfig,
    PolicyViolationError,
    VakError,
    VakKernel,
)
from vak.config import SecurityConfig

# Echoes its input (the kernel's skill ABI).
ECHO_WAT = textwrap.dedent(
    """
    (module
      (memory (export "memory") 1)
      (global $next (mut i32) (i32.const 1024))
      (func (export "alloc") (param $len i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $next))
        (global.set $next (i32.add (global.get $next) (local.get $len)))
        (local.get $p))
      (func (export "execute") (param $ptr i32) (param $len i32) (result i32)
        (i32.store (i32.const 0) (local.get $len))
        (memory.copy (i32.const 4) (local.get $ptr) (local.get $len))
        (i32.const 0)))
    """
)


def write_skill(directory, name="py_echo"):
    (directory / "echo.wat").write_text(ECHO_WAT)
    manifest = directory / "skill.yaml"
    manifest.write_text(
        f"name: {name}\nversion: \"1.0.0\"\ndescription: Echoes its input\n"
        "input_schema: {type: object}\noutput_schema: {type: object}\n"
        "wasm_path: echo.wat\n"
    )
    return manifest


class TestEndToEnd:
    def test_complete_agent_workflow(self, native):
        kernel = VakKernel.default()
        kernel.register_agent(
            AgentConfig(agent_id="auditor", name="Code Auditor", capabilities=["review"])
        )

        assert kernel.evaluate_policy("auditor", "echo").is_allowed()
        response = kernel.execute_tool("auditor", "echo", "review", {"file": "main.py"})
        assert response.success
        assert response.result == {"action": "review", "params": {"file": "main.py"}}

        entries = kernel.get_audit_logs(agent_id="auditor")
        assert [e.details["kind"] for e in entries] == ["decision", "outcome"]
        assert kernel.verify_audit_chain()
        assert kernel.export_audit_receipt()["head"]["size"] == 2

        kernel.shutdown()
        assert not kernel.is_initialized

    def test_multi_agent_records_are_attributed(self, native):
        kernel = VakKernel.default()
        for agent_id in ["analyst", "reviewer"]:
            kernel.register_agent(AgentConfig(agent_id=agent_id, name=agent_id))
        kernel.execute_tool("analyst", "echo", "analyze", {})
        kernel.execute_tool("reviewer", "echo", "review", {})
        kernel.execute_tool("reviewer", "system_info", "info", {})

        assert len(kernel.get_audit_logs(agent_id="analyst")) == 2
        assert len(kernel.get_audit_logs(agent_id="reviewer")) == 4

    def test_multiple_kernel_instances_are_separate(self, native):
        first, second = VakKernel.default(), VakKernel.default()
        first.register_agent(AgentConfig(agent_id="agent", name="agent"))
        second.register_agent(AgentConfig(agent_id="agent", name="agent"))
        first.execute_tool("agent", "echo", "say", {})
        assert len(first.get_audit_logs()) == 2
        assert second.get_audit_logs() == []


class TestSecurityScenarios:
    def test_an_agent_cannot_call_outside_its_own_scope(self, native):
        kernel = VakKernel.default()
        kernel.register_agent(
            AgentConfig(agent_id="reader", name="Reader", allowed_tools=["echo"])
        )
        assert kernel.execute_tool("reader", "echo", "read", {}).success
        with pytest.raises(PolicyViolationError):
            kernel.execute_tool("reader", "system_info", "info", {})
        refusal = kernel.get_audit_logs(action="system_info")
        assert len(refusal) == 1 and refusal[0].policy_decision.is_denied()

    def test_blocked_tools_never_run(self, native):
        config = KernelConfig(security=SecurityConfig(blocked_tools=["system_info"]))
        kernel = VakKernel(config=config)
        kernel.initialize()
        kernel.register_agent(AgentConfig(agent_id="agent", name="agent"))
        with pytest.raises(PolicyViolationError):
            kernel.execute_tool("agent", "system_info", "info", {})
        assert all(e.details["kind"] == "decision" for e in kernel.get_audit_logs())

    def test_unknown_tools_are_denied(self, native):
        kernel = VakKernel.default()
        kernel.register_agent(AgentConfig(agent_id="agent", name="agent"))
        with pytest.raises(PolicyViolationError):
            kernel.execute_tool("agent", "file_reader", "read", {"path": ".env"})

    def test_a_kernel_config_file_configures_the_kernel(self, native, tmp_path):
        config = tmp_path / "kernel.yaml"
        config.write_text(
            "security:\n  allowed_tools: [echo, calculator]\n  blocked_tools: [echo]\n"
        )
        kernel = VakKernel.from_config(config)
        kernel.register_agent(AgentConfig(agent_id="agent", name="agent"))
        assert kernel.evaluate_policy("agent", "echo").is_denied()
        assert kernel.evaluate_policy("agent", "calculator").is_allowed()


class TestSkills:
    def test_unsigned_skills_are_refused_by_default(self, native, tmp_path):
        kernel = VakKernel.default()
        with pytest.raises(VakError, match="Skill rejected"):
            kernel.load_skill(write_skill(tmp_path))
        assert kernel.list_skills() == []
        assert kernel.get_skill("py_echo") is None

    def test_a_loaded_skill_runs_in_the_sandbox(self, native, tmp_path):
        config = KernelConfig(
            security=SecurityConfig(
                signature_verification=False,
                allowed_tools=["echo", "py_echo"],
            )
        )
        kernel = VakKernel(config=config)
        kernel.initialize()
        kernel.register_agent(AgentConfig(agent_id="agent", name="agent"))

        assert kernel.load_skill(write_skill(tmp_path)) == "py_echo"
        assert kernel.list_skills() == ["py_echo"]
        assert "py_echo" in kernel.list_tools()
        assert kernel.get_skill("py_echo").version == "1.0.0"

        response = kernel.execute_tool("agent", "py_echo", "say", {"text": "hi"})
        assert response.success
        assert response.result == {"action": "say", "params": {"text": "hi"}}
        outcome = kernel.get_audit_logs(action="py_echo")[-1]
        assert outcome.details["outcome"]["module_sha256"]

    def test_loading_a_skill_authorizes_no_one(self, native, tmp_path):
        config = KernelConfig(security=SecurityConfig(signature_verification=False))
        kernel = VakKernel(config=config)
        kernel.initialize()
        kernel.register_agent(AgentConfig(agent_id="agent", name="agent"))
        kernel.load_skill(write_skill(tmp_path))
        # Not in the allowlist, so policy refuses it.
        with pytest.raises(PolicyViolationError):
            kernel.execute_tool("agent", "py_echo", "say", {})
