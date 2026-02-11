"""
VAK Policy Types and Helpers

Policy evaluation types and convenience builders for defining
access control policies in your own project.

Example::

    from vak.policy import PolicyEffect, PolicyDecision, permit, deny

    # In a policy hook
    def my_hook(agent_id, action, context):
        if action.startswith("dangerous."):
            return deny(policy_id="safety", reason="Blocked dangerous action")
        return None
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PolicyEffect(Enum):
    """The effect of a policy decision."""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"


@dataclass(frozen=True)
class PolicyDecision:
    """
    Represents the result of a policy evaluation.

    Attributes:
        effect: The decision effect (allow, deny, or audit).
        policy_id: Identifier of the policy that made this decision.
        reason: Human-readable explanation for the decision.
        matched_rules: List of rule IDs that matched during evaluation.
        metadata: Additional context or data from the evaluation.
    """
    effect: PolicyEffect
    policy_id: str
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def is_allowed(self) -> bool:
        """Check if the decision permits the action."""
        return self.effect == PolicyEffect.ALLOW

    def is_denied(self) -> bool:
        """Check if the decision denies the action."""
        return self.effect == PolicyEffect.DENY


def permit(
    policy_id: str = "custom",
    reason: str = "Explicitly permitted",
    matched_rules: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicyDecision:
    """Create an ALLOW policy decision.

    Convenience factory for use in policy hooks and custom evaluators.

    Args:
        policy_id: Identifier for this policy rule.
        reason: Human-readable explanation.
        matched_rules: List of matched rule IDs.
        metadata: Additional context.

    Returns:
        A PolicyDecision with ALLOW effect.

    Example::

        from vak.policy import permit

        def allow_admins(agent_id, action, context):
            if context.get("role") == "admin":
                return permit(policy_id="admin-override", reason="Admin access")
            return None
    """
    return PolicyDecision(
        effect=PolicyEffect.ALLOW,
        policy_id=policy_id,
        reason=reason,
        matched_rules=matched_rules or [],
        metadata=metadata or {},
    )


def deny(
    policy_id: str = "custom",
    reason: str = "Explicitly denied",
    matched_rules: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> PolicyDecision:
    """Create a DENY policy decision.

    Convenience factory for use in policy hooks and custom evaluators.

    Args:
        policy_id: Identifier for this policy rule.
        reason: Human-readable explanation.
        matched_rules: List of matched rule IDs.
        metadata: Additional context.

    Returns:
        A PolicyDecision with DENY effect.

    Example::

        from vak.policy import deny

        def block_dangerous(agent_id, action, context):
            if action.startswith("system."):
                return deny(policy_id="safety", reason="System actions blocked")
            return None
    """
    return PolicyDecision(
        effect=PolicyEffect.DENY,
        policy_id=policy_id,
        reason=reason,
        matched_rules=matched_rules or [],
        metadata=metadata or {},
    )
