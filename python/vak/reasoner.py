"""
VAK Neuro-Symbolic Reasoner

Configure the verification and safety layer for your AI agents.
The reasoner mediates between the LLM (neural) and execution (symbolic),
enforcing formal constraints and scoring reasoning quality.

Components:
    - **Constraints**: Formal rules that actions must satisfy (max steps, forbidden files, etc.).
    - **Safety Rules**: Datalog-style safety invariants checked before execution.
    - **PRM Config**: Process Reward Model scoring for step-by-step reasoning validation.

Example::

    from vak.reasoner import Constraint, SafetyRule, ReasonerConfig

    config = ReasonerConfig(
        constraints=[
            Constraint(name="max-steps", kind="max_steps", value=50),
            Constraint(name="no-secrets", kind="forbidden_files", value=[".env", "secrets.json"]),
            Constraint(name="budget-limit", kind="max_budget", value=100.0),
        ],
        safety_rules=[
            SafetyRule(
                name="no-pii-in-logs",
                description="PII must never appear in public logs",
                pattern="pii_detected",
                action="block",
            ),
        ],
        enable_prm=True,
        prm_threshold=0.6,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ConstraintKind(Enum):
    """Types of formal constraints the reasoner can enforce."""
    MAX_STEPS = "max_steps"
    FORBIDDEN_FILES = "forbidden_files"
    ALLOWED_ACTIONS = "allowed_actions"
    BLOCKED_ACTIONS = "blocked_actions"
    MAX_BUDGET = "max_budget"
    MAX_TOKENS = "max_tokens"
    REQUIRE_APPROVAL = "require_approval"
    CUSTOM = "custom"


class SafetyAction(Enum):
    """Action to take when a safety rule is violated."""
    BLOCK = "block"
    WARN = "warn"
    AUDIT = "audit"
    REQUIRE_APPROVAL = "require_approval"


@dataclass
class Constraint:
    """A formal constraint that limits agent behavior.

    Constraints are checked by the neuro-symbolic reasoner before
    actions are executed. If a constraint is violated, the action
    is blocked and the agent is prompted with the violation details.

    Attributes:
        name: Human-readable name for this constraint.
        kind: The type of constraint (see ConstraintKind).
        value: The constraint value (type depends on kind).
        description: Optional description of why this constraint exists.

    Example::

        from vak.reasoner import Constraint

        constraints = [
            # Limit agent to 50 reasoning steps
            Constraint(name="max-steps", kind="max_steps", value=50),

            # Prevent access to sensitive files
            Constraint(
                name="no-secrets",
                kind="forbidden_files",
                value=[".env", "secrets.json", "credentials.yaml"],
                description="Protect sensitive configuration files",
            ),

            # Cap spending budget
            Constraint(name="budget-limit", kind="max_budget", value=100.0),

            # Only allow specific actions
            Constraint(
                name="read-only",
                kind="allowed_actions",
                value=["read", "list", "search"],
            ),
        ]
    """
    name: str
    kind: str
    value: Any
    description: str = ""

    def check(self, context: dict[str, Any]) -> ConstraintResult:
        """Check this constraint against execution context.

        Args:
            context: Current execution context with relevant state.

        Returns:
            A ConstraintResult indicating pass/fail.
        """
        if self.kind == "max_steps":
            current = context.get("step_count", 0)
            passed = current < self.value
            return ConstraintResult(
                constraint_name=self.name,
                passed=passed,
                message=f"Step {current}/{self.value}" if not passed else "",
            )

        if self.kind == "forbidden_files":
            target = context.get("target_file", "")
            forbidden = self.value if isinstance(self.value, list) else [self.value]
            violated = target in forbidden
            return ConstraintResult(
                constraint_name=self.name,
                passed=not violated,
                message=f"Access to '{target}' is forbidden" if violated else "",
            )

        if self.kind == "allowed_actions":
            action = context.get("action", "")
            allowed = self.value if isinstance(self.value, list) else [self.value]
            passed = action in allowed
            return ConstraintResult(
                constraint_name=self.name,
                passed=passed,
                message=f"Action '{action}' not in allowed list" if not passed else "",
            )

        if self.kind == "blocked_actions":
            action = context.get("action", "")
            blocked = self.value if isinstance(self.value, list) else [self.value]
            violated = action in blocked
            return ConstraintResult(
                constraint_name=self.name,
                passed=not violated,
                message=f"Action '{action}' is blocked" if violated else "",
            )

        if self.kind == "max_budget":
            spent = context.get("budget_spent", 0.0)
            passed = spent < self.value
            return ConstraintResult(
                constraint_name=self.name,
                passed=passed,
                message=f"Budget exceeded: {spent}/{self.value}" if not passed else "",
            )

        if self.kind == "max_tokens":
            used = context.get("tokens_used", 0)
            passed = used < self.value
            return ConstraintResult(
                constraint_name=self.name,
                passed=passed,
                message=f"Token limit exceeded: {used}/{self.value}" if not passed else "",
            )

        # Custom constraints always pass (user implements logic externally)
        return ConstraintResult(constraint_name=self.name, passed=True)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "kind": self.kind,
            "value": self.value,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Constraint:
        """Deserialize from dictionary."""
        return cls(
            name=data["name"],
            kind=data["kind"],
            value=data["value"],
            description=data.get("description", ""),
        )


@dataclass(frozen=True)
class ConstraintResult:
    """Result of a constraint check.

    Attributes:
        constraint_name: Name of the constraint that was checked.
        passed: Whether the constraint was satisfied.
        message: Explanation if the constraint failed.
    """
    constraint_name: str
    passed: bool
    message: str = ""


@dataclass
class SafetyRule:
    """A safety invariant enforced by the reasoner.

    Safety rules use pattern matching to detect violations and take
    specified actions (block, warn, audit, require approval).

    Attributes:
        name: Unique name for this safety rule.
        description: Human-readable description.
        pattern: Pattern to match against (action names, content patterns, etc.).
        action: What to do when the pattern matches ("block", "warn", "audit").
        severity: Severity level ("low", "medium", "high", "critical").
        metadata: Additional rule configuration.

    Example::

        from vak.reasoner import SafetyRule

        rules = [
            SafetyRule(
                name="no-pii-in-logs",
                description="PII must never appear in public logs",
                pattern="pii_detected",
                action="block",
                severity="critical",
            ),
            SafetyRule(
                name="warn-external-api",
                description="Warn when calling external APIs",
                pattern="network.request",
                action="warn",
                severity="medium",
            ),
        ]
    """
    name: str
    description: str = ""
    pattern: str = "*"
    action: str = "block"
    severity: str = "medium"
    metadata: dict[str, Any] = field(default_factory=dict)

    def matches(self, action: str, context: dict[str, Any] | None = None) -> bool:
        """Check if this safety rule matches the given action.

        Args:
            action: The action being performed.
            context: Additional context for matching.

        Returns:
            True if the pattern matches.
        """
        import fnmatch
        return fnmatch.fnmatch(action, self.pattern)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "pattern": self.pattern,
            "action": self.action,
            "severity": self.severity,
            "metadata": self.metadata,
        }


@dataclass
class PRMConfig:
    """Configuration for the Process Reward Model.

    The PRM scores each step of the agent's reasoning before execution.
    Low-scoring steps trigger backtracking (Tree of Thoughts), preventing
    the agent from committing to flawed reasoning paths.

    Attributes:
        enabled: Whether PRM scoring is active.
        threshold: Minimum score (0.0-1.0) for a step to proceed.
        model: PRM model identifier (for external model routing).
        max_backtrack_depth: Maximum number of backtrack levels.
        score_components: Which aspects to score ("logic", "safety", "relevance").

    Example::

        from vak.reasoner import PRMConfig

        prm = PRMConfig(
            enabled=True,
            threshold=0.7,
            score_components=["logic", "safety", "relevance"],
        )
    """
    enabled: bool = False
    threshold: float = 0.6
    model: str = ""
    max_backtrack_depth: int = 3
    score_components: list[str] = field(
        default_factory=lambda: ["logic", "safety", "relevance"]
    )


@dataclass
class ReasonerConfig:
    """Top-level configuration for the neuro-symbolic reasoner.

    Aggregates constraints, safety rules, and PRM settings into
    a single configuration that users define in their own project.

    Attributes:
        constraints: Formal constraints to enforce.
        safety_rules: Safety invariants to check.
        prm: Process Reward Model configuration.
        enable_formal_verification: Whether to use Z3/Datalog verification.
        enable_tree_search: Whether to use Tree of Thoughts search.

    Example::

        from vak.reasoner import ReasonerConfig, Constraint, SafetyRule, PRMConfig

        reasoner = ReasonerConfig(
            constraints=[
                Constraint(name="max-steps", kind="max_steps", value=100),
                Constraint(name="no-env", kind="forbidden_files", value=[".env"]),
            ],
            safety_rules=[
                SafetyRule(name="block-rm", pattern="file.delete", action="block"),
            ],
            prm=PRMConfig(enabled=True, threshold=0.7),
            enable_formal_verification=True,
        )
    """
    constraints: list[Constraint] = field(default_factory=list)
    safety_rules: list[SafetyRule] = field(default_factory=list)
    prm: PRMConfig = field(default_factory=PRMConfig)
    enable_formal_verification: bool = False
    enable_tree_search: bool = False

    def check_constraints(self, context: dict[str, Any]) -> list[ConstraintResult]:
        """Check all constraints against current context.

        Args:
            context: Execution context with relevant state.

        Returns:
            List of constraint results (only failures if any).
        """
        return [c.check(context) for c in self.constraints]

    def check_safety(self, action: str, context: dict[str, Any] | None = None) -> list[SafetyRule]:
        """Find all safety rules that match the given action.

        Args:
            action: The action being performed.
            context: Additional context.

        Returns:
            List of matching safety rules.
        """
        return [r for r in self.safety_rules if r.matches(action, context)]

    def add_constraint(self, constraint: Constraint) -> None:
        """Add a constraint."""
        self.constraints.append(constraint)

    def add_safety_rule(self, rule: SafetyRule) -> None:
        """Add a safety rule."""
        self.safety_rules.append(rule)
