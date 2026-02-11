"""
VAK Audit Types

Audit logging types for the VAK kernel's cryptographic audit trail.

Example::

    from vak.audit import AuditLevel, AuditEntry

    # Query audit logs
    logs = kernel.get_audit_logs(
        agent_id="my-agent",
        level=AuditLevel.WARNING,
        limit=50,
    )

    for entry in logs:
        print(f"[{entry.level.value}] {entry.action}: {entry.resource}")
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from vak.policy import PolicyDecision


class AuditLevel(Enum):
    """Severity level for audit entries."""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AuditEntry:
    """
    An immutable audit log entry.

    Attributes:
        entry_id: Unique identifier for this audit entry.
        timestamp: When the event occurred.
        level: Severity level of the entry.
        agent_id: ID of the agent that triggered this entry.
        action: The action being audited.
        resource: The resource being accessed or modified.
        policy_decision: The policy decision (if applicable).
        details: Additional context about the event.
        parent_entry_id: ID of a parent entry for hierarchical auditing.
    """
    entry_id: str
    timestamp: datetime
    level: AuditLevel
    agent_id: str
    action: str
    resource: str
    policy_decision: PolicyDecision | None = None
    details: dict[str, Any] = field(default_factory=dict)
    parent_entry_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert the audit entry to a dictionary representation."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "agent_id": self.agent_id,
            "action": self.action,
            "resource": self.resource,
            "policy_decision": {
                "effect": self.policy_decision.effect.value,
                "policy_id": self.policy_decision.policy_id,
                "reason": self.policy_decision.reason,
            } if self.policy_decision else None,
            "details": self.details,
            "parent_entry_id": self.parent_entry_id,
        }
