"""Memory and swarm coordination that run in this Python process.

These back ``VakKernel``'s memory and voting methods, the same way whether
or not the native module is built. They are plain Python: the native
module doesn't expose the Rust ``memory`` or ``swarm`` modules, and these
neither go through the kernel nor claim to. Nothing here decides policy,
writes the kernel's audit log, or runs a tool.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any


class LocalMemory:
    """Working memory in a dict, episodes in a SHA-256 hash chain, and
    keyword search over working memory."""

    def __init__(self) -> None:
        self._items: dict[str, dict[str, Any]] = {}
        self._episodes: list[dict[str, Any]] = []
        self._episode_chain_hash: str = ""

    def store_memory(
        self,
        key: str,
        value: Any,
        priority: str = "normal",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Store an item in working memory, replacing any under ``key``."""
        item = {
            "key": key,
            "content": value,
            "priority": priority,
            "metadata": metadata or {},
            "stored_at": datetime.now(timezone.utc).isoformat(),
        }
        self._items[key] = item
        return item

    def retrieve_memory(self, key: str) -> dict[str, Any] | None:
        """The item stored under ``key``, if any."""
        return self._items.get(key)

    def store_episode(self, episode_data: dict[str, Any]) -> str:
        """Append an episode, linked to the previous one by SHA-256 over its
        id, content and the previous hash. Returns its hash."""
        episode_id = episode_data.get("episode_id") or f"ep-{uuid.uuid4().hex[:12]}"
        previous_hash = self._episode_chain_hash
        hash_input = f"{episode_id}:{episode_data.get('content', '')}:{previous_hash}"
        episode_hash = hashlib.sha256(hash_input.encode()).hexdigest()

        self._episodes.append(
            {
                "episode_id": episode_id,
                "episode_type": episode_data.get("episode_type", "observation"),
                "content": episode_data.get("content", ""),
                "agent_id": episode_data.get("agent_id", ""),
                "timestamp": episode_data.get("timestamp")
                or datetime.now(timezone.utc).isoformat(),
                "previous_hash": previous_hash,
                "hash": episode_hash,
                "metadata": episode_data.get("metadata", {}),
            }
        )
        self._episode_chain_hash = episode_hash
        return episode_hash

    def retrieve_episodes(self, limit: int = 10) -> list[dict[str, Any]]:
        """The most recent episodes, newest first."""
        return list(reversed(self._episodes[-limit:])) if limit > 0 else []

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Items whose key or content contains ``query``, ignoring case.
        Keyword matching, not vector search."""
        query_lower = query.lower()
        results = []
        for item in self._items.values():
            if query_lower in str(item.get("content", "")).lower() or query_lower in str(
                item.get("key", "")
            ).lower():
                results.append(item)
            if len(results) >= top_k:
                break
        return results


class LocalSwarm:
    """Quadratic voting sessions and a sycophancy heuristic."""

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}

    def create_voting_session(self, proposal: str, config: dict[str, Any] | None = None) -> str:
        """Open a session. ``config`` may set ``token_budget`` (per agent,
        default 100), ``quorum_threshold`` (default 0.5) and
        ``quadratic_cost`` (default True)."""
        session_id = f"vote-{uuid.uuid4().hex[:12]}"
        cfg = config or {}
        self._sessions[session_id] = {
            "session_id": session_id,
            "proposal": proposal,
            "token_budget": cfg.get("token_budget", 100),
            "quorum_threshold": cfg.get("quorum_threshold", 0.5),
            "quadratic_cost": cfg.get("quadratic_cost", True),
            "votes": [],
            "spent": {},
            "status": "open",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        return session_id

    def cast_vote(
        self, session_id: str, agent_id: str, direction: str, weight: int = 1
    ) -> dict[str, Any]:
        """Cast ``weight`` votes, costing ``weight**2`` tokens (or
        ``weight`` when costs are linear). A vote the agent's remaining
        budget can't pay for is refused."""
        session = self._sessions.get(session_id)
        if session is None:
            return {"success": False, "error": f"Session {session_id} not found"}
        if session["status"] != "open":
            return {"success": False, "error": "Session is not open"}
        if weight < 1:
            return {"success": False, "error": "weight must be at least 1"}

        cost = weight * weight if session["quadratic_cost"] else weight
        spent = session["spent"].get(agent_id, 0)
        if spent + cost > session["token_budget"]:
            return {
                "success": False,
                "error": (
                    f"{agent_id} has {session['token_budget'] - spent} tokens left; "
                    f"this vote costs {cost}"
                ),
                "cost": cost,
            }

        vote = {
            "agent_id": agent_id,
            "direction": direction,
            "weight": weight,
            "cost": cost,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        session["votes"].append(vote)
        session["spent"][agent_id] = spent + cost
        return {"success": True, "cost": cost, "vote": vote}

    def tally_votes(self, session_id: str) -> dict[str, Any]:
        """Close the session and count votes by direction."""
        session = self._sessions.get(session_id)
        if session is None:
            return {"success": False, "error": f"Session {session_id} not found"}

        tally: dict[str, int] = {}
        voters: set[str] = set()
        for vote in session["votes"]:
            tally[vote["direction"]] = tally.get(vote["direction"], 0) + vote["weight"]
            voters.add(vote["agent_id"])
        session["status"] = "closed"
        return {
            "success": True,
            "session_id": session_id,
            "proposal": session["proposal"],
            "tally": tally,
            "total_weight": sum(tally.values()),
            "unique_voters": len(voters),
            "winner": max(tally, key=lambda d: tally[d]) if tally else None,
            "status": "closed",
        }

    @staticmethod
    def detect_sycophancy(session_history: list[dict[str, Any]]) -> dict[str, Any]:
        """How often votes agree with their session's majority. A heuristic:
        above 90% is flagged."""
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
            directions = [v.get("direction") for v in session.get("votes", [])]
            if not directions:
                continue
            majority = max(set(directions), key=directions.count)
            total_votes += len(directions)
            agreement_count += sum(1 for d in directions if d == majority)

        agreement_rate = agreement_count / total_votes if total_votes else 0.0
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
                f"Agreement rate {agreement_rate:.1%} across {len(session_history)} sessions"
            ),
        }
