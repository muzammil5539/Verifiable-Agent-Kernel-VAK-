"""Shared test fixtures.

Policy, tools, skills and the audit log come from the native kernel
(``vak._vak_native``), so tests of them use the ``native`` fixture: they
are skipped when the module isn't built, and fail instead when
``VAK_REQUIRE_NATIVE`` is set, as CI sets it after building the module.
Tests of what happens without the native module use ``no_native``.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

import vak.kernel


def _native_module() -> Any:
    if os.environ.get("VAK_REQUIRE_NATIVE"):
        from vak import _vak_native  # noqa: F401  (a missing module fails here)

        return _vak_native
    return pytest.importorskip("vak._vak_native")


@pytest.fixture
def native() -> Any:
    """The native module. Kernels initialized in the test use it."""
    return _native_module()


@pytest.fixture
def no_native(monkeypatch: pytest.MonkeyPatch) -> None:
    """Kernels initialized in the test have no native kernel."""
    monkeypatch.setattr(vak.kernel, "_load_native", lambda: None)
