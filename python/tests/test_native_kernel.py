"""The SDK on the native kernel (finding I4).

``execute_tool`` runs through ``Kernel::execute``: the kernel's policy
decides, its audit log records the call, and a refusal or failure is
never reported as a success. Skipped unless the native module is built
(``maturin develop``), except where ``VAK_REQUIRE_NATIVE`` is set.
"""

import os

import pytest

if os.environ.get("VAK_REQUIRE_NATIVE"):
    # CI builds the module first: a missing module is a failure there.
    from vak import _vak_native
else:
    _vak_native = pytest.importorskip("vak._vak_native")


@pytest.fixture
def native():
    kernel = _vak_native.Kernel.default()
    kernel.register_agent("agent-1", "Agent One", {})
    return kernel


def test_a_tool_runs_through_the_kernel(native):
    result = native.execute_tool(
        "echo", "agent-1", "say", {"text": "hello"}, 5000, 128 * 1024 * 1024
    )
    assert result["success"] is True
    assert result["result"] == {"action": "say", "params": {"text": "hello"}}
    # The kernel's receipt: the decision leaf and the outcome leaf.
    assert result["receipt"]["decision_leaf"] == 0
    assert result["receipt"]["outcome_leaf"] == 1


def test_a_tool_the_kernel_refuses_raises(native):
    with pytest.raises(PermissionError) as refused:
        native.execute_tool("no_such_tool", "agent-1", "run", {}, 5000, 128 * 1024 * 1024)
    policy_id, reason = refused.value.args
    assert policy_id and reason


def test_a_tool_that_fails_reports_failure(native):
    # The built-in calculator wants "operation" and "operands".
    result = native.execute_tool(
        "calculator", "agent-1", "add", {"a": 1, "b": 2}, 5000, 128 * 1024 * 1024
    )
    assert result["success"] is False
    assert result["error"]


def test_a_tighter_memory_limit_than_the_kernel_enforces_is_refused(native):
    with pytest.raises(ValueError, match="nothing ran"):
        native.execute_tool("echo", "agent-1", "say", {}, 5000, 1024 * 1024)
