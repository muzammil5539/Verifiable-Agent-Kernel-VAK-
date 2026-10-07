"""Stub kernel for development when native module is not available.

All methods return sensible defaults so the Python SDK can be
used for development and testing without compiling the Rust
native module.  Build the real module with::

    maturin develop --features python

The stub keeps the agent registry and an in-memory audit chain for local
development. Memory and swarm coordination live in ``vak._local`` and
work the same with or without the native module.
It cannot run tools: ``execute_tool`` raises, because a tool that
didn't run must never be reported as a success.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any


class _StubKernel:
    """Stub kernel for development when native module is not available.

    Keeps the agent registry and an in-memory audit chain. It cannot run
    tools.
    """

    def __init__(self) -> None:
        self._agents: dict[str, dict[str, Any]] = {}
        self._audit_entries: list[dict[str, Any]] = []
        self._audit_chain_hash: str = "genesis"
        self._skills: dict[str, dict[str, Any]] = {}

    def shutdown(self) -> None:
        """Gracefully shutdown the stub kernel."""
        self._agents.clear()
        self._audit_entries.clear()
        self._skills.clear()

    # =========================================================================
    # Agent Management
    # =========================================================================

    def register_agent(
        self, agent_id: str, name: str, metadata: dict[str, Any]
    ) -> None:
        self._agents[agent_id] = {"name": name, **metadata}

    def unregister_agent(self, agent_id: str) -> None:
        self._agents.pop(agent_id, None)

    def evaluate_policy(
        self, agent_id: str, action: str, context: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "effect": "allow",
            "policy_id": "stub-default",
            "reason": "Default allow (stub mode)",
            "matched_rules": [],
            "metadata": {},
        }

    def execute_tool(
        self,
        tool_id: str,
        agent_id: str,
        action: str,
        parameters: dict[str, Any],
        timeout_ms: int,
        memory_limit: int,
    ) -> dict[str, Any]:
        # The stub can't run tools, and must not say it did.
        raise RuntimeError(
            f"cannot run '{tool_id}': the native kernel (vak._vak_native) is not "
            "available, so nothing ran. Build it with `maturin develop`."
        )

    def list_tools(self) -> list[str]:
        return list(self._skills.keys())

    def register_skill(
        self, skill_id: str, wasm_path: str, manifest: dict[str, Any]
    ) -> None:
        self._skills[skill_id] = {"wasm_path": wasm_path, **manifest}

    # =========================================================================
    # Audit Logging
    # =========================================================================

    def get_audit_logs(self, filters: dict[str, Any]) -> list[dict[str, Any]]:
        results = list(self._audit_entries)
        agent_id = filters.get("agent_id")
        if agent_id:
            results = [e for e in results if e.get("agent_id") == agent_id]
        action = filters.get("action")
        if action:
            results = [e for e in results if e.get("action") == action]
        limit = filters.get("limit", 100)
        offset = filters.get("offset", 0)
        return results[offset : offset + limit]

    def get_audit_entry(self, entry_id: str) -> dict[str, Any] | None:
        for entry in self._audit_entries:
            if entry.get("entry_id") == entry_id:
                return entry
        return None

    def create_audit_entry(self, entry_data: dict[str, Any]) -> str:
        entry_id = f"audit-{uuid.uuid4().hex[:12]}"
        previous_hash = self._audit_chain_hash

        entry_content = f"{entry_id}:{entry_data}:{previous_hash}"
        entry_hash = hashlib.sha256(entry_content.encode()).hexdigest()

        entry = {
            "entry_id": entry_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": previous_hash,
            "hash": entry_hash,
            **entry_data,
        }
        self._audit_entries.append(entry)
        self._audit_chain_hash = entry_hash
        return entry_id

    def verify_audit_chain(self) -> dict[str, Any]:
        """Verify the integrity of the audit chain."""
        if not self._audit_entries:
            return {"valid": True, "entries_checked": 0, "errors": []}

        errors: list[str] = []
        expected_prev = "genesis"

        for i, entry in enumerate(self._audit_entries):
            if entry.get("previous_hash") != expected_prev:
                errors.append(
                    f"Entry {i} ({entry.get('entry_id')}): "
                    f"expected previous_hash={expected_prev!r}, "
                    f"got {entry.get('previous_hash')!r}"
                )
            expected_prev = entry.get("hash", "")

        return {
            "valid": len(errors) == 0,
            "entries_checked": len(self._audit_entries),
            "errors": errors,
        }

    def get_audit_root_hash(self) -> str:
        """Return the current root hash of the audit chain."""
        return self._audit_chain_hash

    def export_audit_receipt(self) -> dict[str, Any]:
        """Export a cryptographic receipt for the current audit state."""
        return {
            "receipt_id": f"receipt-{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "root_hash": self._audit_chain_hash,
            "entry_count": len(self._audit_entries),
            "first_entry": (
                self._audit_entries[0].get("entry_id") if self._audit_entries else None
            ),
            "last_entry": (
                self._audit_entries[-1].get("entry_id") if self._audit_entries else None
            ),
        }
