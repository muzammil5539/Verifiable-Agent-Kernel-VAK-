"""
VAK Policy Engine

Define access control policies for your AI agents. Supports Cedar-style
ABAC (Attribute-Based Access Control) with permit/forbid rules, glob pattern
matching, and conditional evaluation.

Users define policies in their own project and load them into the kernel::

    from vak.policy import PolicyRule, PolicyCondition, permit, deny

    # Define rules declaratively
    rules = [
        PolicyRule(
            id="allow-analysts-read",
            effect="permit",
            principal="analyst",
            action="data.read",
            resource="reports/*",
        ),
        PolicyRule(
            id="block-untrusted-delete",
            effect="forbid",
            action="*.delete",
            resource="*",
            conditions=[
                PolicyCondition("trusted", "equals", False),
            ],
        ),
    ]

    kernel.load_policies(rules)
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# =============================================================================
# Core Enums
# =============================================================================


class PolicyEffect(Enum):
    """The effect of a policy decision."""
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"


class ConditionOperator(Enum):
    """Operators for policy condition evaluation."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    REGEX = "regex"


# =============================================================================
# Policy Data Structures
# =============================================================================


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


@dataclass
class PolicyCondition:
    """A condition that must be satisfied for a policy rule to match.

    Conditions are evaluated against the request context attributes.

    Attributes:
        attribute: The context attribute to check (e.g., "role", "trusted", "department").
        operator: The comparison operator.
        value: The value to compare against.

    Example::

        # Only match if agent role is "admin"
        PolicyCondition("role", "equals", "admin")

        # Only match if trust score is above threshold
        PolicyCondition("trust_score", "greater_than", 0.8)

        # Only match if department is in allowed list
        PolicyCondition("department", "in", ["engineering", "security"])
    """
    attribute: str
    operator: str
    value: Any

    def evaluate(self, context: dict[str, Any]) -> bool:
        """Evaluate this condition against a context dictionary.

        Args:
            context: The request context with attribute values.

        Returns:
            True if the condition is satisfied.
        """
        actual = context.get(self.attribute)
        op = self.operator

        if op == "exists":
            return self.attribute in context
        if actual is None:
            return False

        if op == "equals":
            return actual == self.value
        if op == "not_equals":
            return actual != self.value
        if op == "contains":
            return self.value in actual if isinstance(actual, (str, list)) else False
        if op == "not_contains":
            return self.value not in actual if isinstance(actual, (str, list)) else True
        if op == "starts_with":
            return str(actual).startswith(str(self.value))
        if op == "ends_with":
            return str(actual).endswith(str(self.value))
        if op == "greater_than":
            return actual > self.value
        if op == "less_than":
            return actual < self.value
        if op == "in":
            return actual in self.value if isinstance(self.value, (list, set, tuple)) else False
        if op == "not_in":
            return actual not in self.value if isinstance(self.value, (list, set, tuple)) else True
        if op == "regex":
            import re
            return bool(re.search(str(self.value), str(actual)))

        return False


@dataclass
class PolicyRule:
    """A single access control rule in the policy engine.

    Rules are evaluated in priority order. Forbid rules override permit rules
    at the same priority level (deny-overrides).

    Attributes:
        id: Unique identifier for this rule.
        effect: "permit" or "forbid".
        principal: Glob pattern matching agent roles (e.g., "admin", "analyst*", "*").
        action: Glob pattern matching actions (e.g., "data.read", "tool.*", "*").
        resource: Glob pattern matching resources (e.g., "reports/*", "*.py", "*").
        conditions: Additional conditions that must all be true for the rule to match.
        priority: Higher priority rules are evaluated first (default 0).
        description: Human-readable description of this rule's purpose.

    Example::

        from vak.policy import PolicyRule, PolicyCondition

        # Permit analysts to read reports
        PolicyRule(
            id="analyst-read-reports",
            effect="permit",
            principal="analyst",
            action="data.read",
            resource="reports/*",
            description="Allow analysts to read report files",
        )

        # Forbid untrusted agents from deleting anything
        PolicyRule(
            id="block-untrusted-delete",
            effect="forbid",
            action="*.delete",
            resource="*",
            conditions=[PolicyCondition("trusted", "equals", False)],
            priority=100,
            description="Block all delete operations from untrusted agents",
        )
    """
    id: str
    effect: str  # "permit" or "forbid"
    principal: str = "*"
    action: str = "*"
    resource: str = "*"
    conditions: list[PolicyCondition] = field(default_factory=list)
    priority: int = 0
    description: str = ""

    def matches(
        self,
        role: str,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> bool:
        """Check if this rule matches the given request parameters.

        Args:
            role: The agent's role.
            action: The requested action.
            resource: The target resource.
            context: Additional context for condition evaluation.

        Returns:
            True if all patterns and conditions match.
        """
        context = context or {}

        if not fnmatch.fnmatch(role, self.principal):
            return False
        if not fnmatch.fnmatch(action, self.action):
            return False
        if not fnmatch.fnmatch(resource, self.resource):
            return False

        return all(cond.evaluate(context) for cond in self.conditions)

    def to_dict(self) -> dict[str, Any]:
        """Serialize this rule to a dictionary."""
        return {
            "id": self.id,
            "effect": self.effect,
            "principal": self.principal,
            "action": self.action,
            "resource": self.resource,
            "conditions": [
                {"attribute": c.attribute, "operator": c.operator, "value": c.value}
                for c in self.conditions
            ],
            "priority": self.priority,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyRule:
        """Deserialize a rule from a dictionary.

        Args:
            data: Dictionary with rule fields.

        Returns:
            A PolicyRule instance.
        """
        conditions = [
            PolicyCondition(
                attribute=c["attribute"],
                operator=c["operator"],
                value=c["value"],
            )
            for c in data.get("conditions", [])
        ]
        return cls(
            id=data["id"],
            effect=data["effect"],
            principal=data.get("principal", "*"),
            action=data.get("action", "*"),
            resource=data.get("resource", "*"),
            conditions=conditions,
            priority=data.get("priority", 0),
            description=data.get("description", ""),
        )


# =============================================================================
# Policy Engine (Pure Python, evaluates rules locally)
# =============================================================================


class PolicyEngine:
    """Local policy engine for evaluating rules in pure Python.

    Use this when you want to define and evaluate policies entirely in
    Python without the Rust native module. The kernel also delegates to
    this engine for Python-side rule evaluation.

    Example::

        from vak.policy import PolicyEngine, PolicyRule

        engine = PolicyEngine(default_effect="deny")

        engine.add_rule(PolicyRule(
            id="allow-read",
            effect="permit",
            action="data.read",
            resource="*",
        ))

        decision = engine.evaluate(
            role="analyst",
            action="data.read",
            resource="report.csv",
        )
        assert decision.is_allowed()
    """

    def __init__(self, default_effect: str = "deny") -> None:
        """Initialize the policy engine.

        Args:
            default_effect: Default decision when no rules match ("deny" or "allow").
        """
        self._rules: list[PolicyRule] = []
        self._default_effect = default_effect

    @property
    def rules(self) -> list[PolicyRule]:
        """Get all loaded rules."""
        return list(self._rules)

    def add_rule(self, rule: PolicyRule) -> None:
        """Add a policy rule.

        Args:
            rule: The rule to add.
        """
        self._rules.append(rule)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def add_rules(self, rules: list[PolicyRule]) -> None:
        """Add multiple policy rules.

        Args:
            rules: List of rules to add.
        """
        self._rules.extend(rules)
        self._rules.sort(key=lambda r: r.priority, reverse=True)

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID.

        Args:
            rule_id: The ID of the rule to remove.

        Returns:
            True if a rule was removed.
        """
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def clear_rules(self) -> None:
        """Remove all rules."""
        self._rules.clear()

    def evaluate(
        self,
        role: str = "*",
        action: str = "*",
        resource: str = "*",
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        """Evaluate all rules against the given request.

        Uses deny-overrides: if any matching forbid rule exists, the request
        is denied regardless of permit rules at the same or lower priority.

        Args:
            role: The agent's role.
            action: The requested action.
            resource: The target resource.
            context: Additional context for condition evaluation.

        Returns:
            A PolicyDecision with the evaluation result.
        """
        context = context or {}
        matched_permits: list[PolicyRule] = []
        matched_forbids: list[PolicyRule] = []

        for rule in self._rules:
            if rule.matches(role, action, resource, context):
                if rule.effect == "forbid":
                    matched_forbids.append(rule)
                elif rule.effect == "permit":
                    matched_permits.append(rule)

        # Deny-overrides: any forbid rule wins
        if matched_forbids:
            top = matched_forbids[0]
            return PolicyDecision(
                effect=PolicyEffect.DENY,
                policy_id=top.id,
                reason=top.description or f"Denied by rule '{top.id}'",
                matched_rules=[r.id for r in matched_forbids],
            )

        if matched_permits:
            top = matched_permits[0]
            return PolicyDecision(
                effect=PolicyEffect.ALLOW,
                policy_id=top.id,
                reason=top.description or f"Permitted by rule '{top.id}'",
                matched_rules=[r.id for r in matched_permits],
            )

        # Default decision
        if self._default_effect == "allow":
            return PolicyDecision(
                effect=PolicyEffect.ALLOW,
                policy_id="default",
                reason="No matching rules; default allow",
            )

        return PolicyDecision(
            effect=PolicyEffect.DENY,
            policy_id="default-deny",
            reason="No matching rules; default deny",
        )

    def load_rules_from_list(self, rules_data: list[dict[str, Any]]) -> None:
        """Load rules from a list of dictionaries (e.g., parsed from YAML/JSON).

        Args:
            rules_data: List of rule dictionaries.

        Example::

            import yaml

            with open("policies.yaml") as f:
                data = yaml.safe_load(f)

            engine.load_rules_from_list(data["rules"])
        """
        for rule_data in rules_data:
            self.add_rule(PolicyRule.from_dict(rule_data))


# =============================================================================
# Convenience Factory Functions
# =============================================================================


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
