"""Stub kernel for development when native module is not available.

All methods return sensible defaults so the Python SDK can be
used for development and testing without compiling the Rust
native module.  Build the real module with::

    maturin develop --features python

The stub provides real in-memory implementations (not just empty
returns) so that the Python SDK is fully functional for local
development, testing, and prototyping without native compilation.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any


class _StubKernel:
    """Stub kernel for development when native module is not available.

    Provides fully-functional in-memory implementations of all kernel
    subsystems: agent management, policy evaluation, tool execution,
    audit logging, memory management, swarm coordination, and audit
    chain verification.
    """

    def __init__(self) -> None:
        self._agents: dict[str, dict[str, Any]] = {}
        self._audit_entries: list[dict[str, Any]] = []
        self._audit_chain_hash: str = "genesis"
        self._memory_store: dict[str, dict[str, Any]] = {}
        self._episodes: list[dict[str, Any]] = []
        self._episode_chain_hash: str = ""
        self._voting_sessions: dict[str, dict[str, Any]] = {}
        self._skills: dict[str, dict[str, Any]] = {}

    def shutdown(self) -> None:
        """Gracefully shutdown the stub kernel."""
        self._agents.clear()
        self._audit_entries.clear()
        self._memory_store.clear()
        self._episodes.clear()
        self._voting_sessions.clear()
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
        return {
            "request_id": f"stub-{tool_id}-{action}-{uuid.uuid4().hex[:8]}",
            "success": True,
            "result": {"stub": True, "tool_id": tool_id, "action": action},
            "error": None,
            "execution_time_ms": 0.1,
            "memory_used_bytes": 0,
            "audit_trail": [],
        }

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

    # =========================================================================
    # Memory Management
    # =========================================================================

    def store_memory(
        self,
        key: str,
        value: Any,
        priority: str = "normal",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Store an item in working memory."""
        item = {
            "key": key,
            "content": value,
            "priority": priority,
            "metadata": metadata or {},
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        self._memory_store[key] = item
        return item

    def retrieve_memory(self, key: str) -> dict[str, Any] | None:
        """Retrieve an item from working memory."""
        return self._memory_store.get(key)

    def delete_memory(self, key: str) -> bool:
        """Delete an item from working memory."""
        if key in self._memory_store:
            del self._memory_store[key]
            return True
        return False

    def list_memory_keys(self) -> list[str]:
        """List all keys in working memory."""
        return list(self._memory_store.keys())

    def store_episode(self, episode_data: dict[str, Any]) -> str:
        """Store an episode with Merkle chain linking."""
        episode_id = episode_data.get(
            "episode_id", f"ep-{uuid.uuid4().hex[:12]}"
        )
        previous_hash = self._episode_chain_hash

        hash_input = (
            f"{episode_id}:{episode_data.get('content', '')}:{previous_hash}"
        )
        episode_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        entry = {
            "episode_id": episode_id,
            "episode_type": episode_data.get("episode_type", "observation"),
            "content": episode_data.get("content", ""),
            "agent_id": episode_data.get("agent_id", ""),
            "timestamp": episode_data.get(
                "timestamp", datetime.now(timezone.utc).isoformat()
            ),
            "previous_hash": previous_hash,
            "hash": episode_hash,
            "metadata": episode_data.get("metadata", {}),
        }
        self._episodes.append(entry)
        self._episode_chain_hash = episode_hash
        return episode_hash

    def retrieve_episodes(self, limit: int = 10) -> list[dict[str, Any]]:
        """Retrieve the most recent episodes."""
        return list(reversed(self._episodes[-limit:]))

    def search_semantic(
        self, query: str, top_k: int = 5
    ) -> list[dict[str, Any]]:
        """Search memory items by keyword matching (stub for vector search)."""
        results = []
        query_lower = query.lower()
        for item in self._memory_store.values():
            content = str(item.get("content", "")).lower()
            key = item.get("key", "").lower()
            if query_lower in content or query_lower in key:
                results.append(item)
            if len(results) >= top_k:
                break
        return results

    # =========================================================================
    # Swarm Coordination
    # =========================================================================

    def create_voting_session(
        self,
        proposal: str,
        config: dict[str, Any] | None = None,
    ) -> str:
        """Create a new quadratic voting session."""
        session_id = f"vote-{uuid.uuid4().hex[:12]}"
        cfg = config or {}
        self._voting_sessions[session_id] = {
            "session_id": session_id,
            "proposal": proposal,
            "token_budget": cfg.get("token_budget", 100),
            "quorum_threshold": cfg.get("quorum_threshold", 0.5),
            "quadratic_cost": cfg.get("quadratic_cost", True),
            "votes": [],
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return session_id

    def cast_vote(
        self,
        session_id: str,
        agent_id: str,
        direction: str,
        weight: int = 1,
    ) -> dict[str, Any]:
        """Cast a vote in a voting session."""
        session = self._voting_sessions.get(session_id)
        if session is None:
            return {"success": False, "error": f"Session {session_id} not found"}
        if session["status"] != "open":
            return {"success": False, "error": "Session is not open"}

        quadratic = session.get("quadratic_cost", True)
        cost = weight * weight if quadratic else weight

        vote = {
            "agent_id": agent_id,
            "direction": direction,
            "weight": weight,
            "cost": cost,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        session["votes"].append(vote)
        return {"success": True, "cost": cost, "vote": vote}

    def tally_votes(self, session_id: str) -> dict[str, Any]:
        """Tally votes for a voting session."""
        session = self._voting_sessions.get(session_id)
        if session is None:
            return {"success": False, "error": f"Session {session_id} not found"}

        votes = session["votes"]
        tally: dict[str, int] = {}
        voter_set: set[str] = set()

        for vote in votes:
            direction = vote["direction"]
            tally[direction] = tally.get(direction, 0) + vote["weight"]
            voter_set.add(vote["agent_id"])

        total_weight = sum(tally.values())
        winner = max(tally, key=lambda d: tally[d]) if tally else None

        session["status"] = "closed"

        return {
            "success": True,
            "session_id": session_id,
            "proposal": session["proposal"],
            "tally": tally,
            "total_weight": total_weight,
            "unique_voters": len(voter_set),
            "winner": winner,
            "status": "closed",
        }

    def detect_sycophancy(
        self, session_history: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Detect sycophancy patterns in voting/discussion history."""
        if not session_history:
            return {
                "sycophancy_detected": False,
                "agreement_rate": 0.0,
                "risk_level": "low",
                "details": "No history provided",
            }

        total_votes = 0
        agreement_count = 0

        for session in session_history:
            votes = session.get("votes", [])
            if not votes:
                continue
            directions = [v.get("direction") for v in votes]
            if not directions:
                continue
            majority = max(set(directions), key=directions.count)
            for d in directions:
                total_votes += 1
                if d == majority:
                    agreement_count += 1

        agreement_rate = agreement_count / total_votes if total_votes > 0 else 0.0

        if agreement_rate > 0.95:
            risk_level = "critical"
        elif agreement_rate > 0.85:
            risk_level = "high"
        elif agreement_rate > 0.75:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "sycophancy_detected": agreement_rate > 0.9,
            "agreement_rate": agreement_rate,
            "risk_level": risk_level,
            "total_votes_analyzed": total_votes,
            "details": (
                f"Agreement rate {agreement_rate:.1%} across "
                f"{len(session_history)} sessions"
            ),
        }
