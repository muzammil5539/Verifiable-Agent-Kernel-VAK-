"""Shared test fixtures.

The SDK runs tools only through the native kernel (``vak._vak_native``).
Without it, ``execute_tool`` fails: nothing is reported as run that
didn't run. Tests of the SDK's own logic around a call (policy hooks,
safety rules, the audit trail) use the ``fake_tools`` fixture, which
swaps in an explicit test double that "runs" every tool by echoing the
call back. It exists only here, in the tests.
"""

from __future__ import annotations

import sys
from typing import Any

import pytest

import vak
import vak.kernel
from vak._stub import _StubKernel


class FakeToolKernel(_StubKernel):
    """A test double for the native kernel that answers every tool call
    with an echo of the call, and records it."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[dict[str, Any]] = []

    def execute_tool(
        self,
        tool_id: str,
        agent_id: str,
        action: str,
        parameters: dict[str, Any],
        timeout_ms: int,
        memory_limit: int,
    ) -> dict[str, Any]:
        call = {
            "tool_id": tool_id,
            "agent_id": agent_id,
            "action": action,
            "parameters": parameters,
            "timeout_ms": timeout_ms,
            "memory_limit": memory_limit,
        }
        self.calls.append(call)
        return {
            "request_id": f"fake-{len(self.calls)}",
            "success": True,
            "result": {"fake": True, **call},
            "error": None,
            "execution_time_ms": 0.0,
        }


def _without_native(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "vak._vak_native", None)
    monkeypatch.delattr(vak, "_vak_native", raising=False)


@pytest.fixture
def fake_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kernels initialized in the test run tools on ``FakeToolKernel``."""
    _without_native(monkeypatch)
    monkeypatch.setattr(vak.kernel, "_StubKernel", FakeToolKernel)


@pytest.fixture
def no_native(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kernels initialized in the test have no native kernel."""
    _without_native(monkeypatch)
