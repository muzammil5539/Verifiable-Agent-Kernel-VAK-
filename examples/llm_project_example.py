#!/usr/bin/env python3
"""
VAK — Full LLM Project Integration Example

Shows how to build a secure, policy-enforced LLM application using
the VAK Python SDK. This is what a user's own project looks like
when they ``pip install vak`` and define their own policies,
constraints, skills, and agent configurations.

Sections:
    1. Kernel configuration: the security settings the kernel enforces
    2. Policy rules evaluated in Python with the standalone PolicyEngine
    3. Constraints and safety rules, checked in Python (the kernel doesn't
       enforce them)
    4. WASM skills, loaded into the kernel from signed manifests
    5. Agent registration and tool execution through the kernel
    6. Swarm configuration (multi-agent consensus)
    7. Audit trail querying

Policy decisions, tool runs and audit records come from the Rust kernel in
the native module (ADR 0011). Build it first with ``maturin develop``.

Run with:
    python examples/llm_project_example.py
"""

from __future__ import annotations

# =============================================================================
# 1. Configuration — define how the kernel behaves in YOUR project
# =============================================================================

from vak.config import KernelConfig, SecurityConfig, AuditConfig
from vak.memory import (
    MemoryConfig,
    WorkingMemoryConfig,
    EpisodicMemoryConfig,
    SemanticMemoryConfig,
)

# Build a custom kernel configuration
config = KernelConfig(
    name="my-llm-app",
    security=SecurityConfig(
        enable_sandboxing=True,
        default_policy_effect="deny",       # deny by default — explicit allow
        signature_verification=True,         # enabled by default for security
        # Memory per skill. The kernel takes no per-call limit, so agents
        # must not ask for less than this (AgentConfig defaults to 128 MiB).
        max_memory_bytes=128 * 1024 * 1024,
        sandbox_timeout_ms=10000,            # 10 s per tool call
        blocked_tools=["system_info"],       # the kernel refuses these
    ),
    audit=AuditConfig(
        enabled=True,
        level="info",
        retention_days=90,
    ),
    memory=MemoryConfig(
        working=WorkingMemoryConfig(
            max_items=200,
            summarization_threshold=80,      # summarize at 80 % capacity
            max_token_estimate=16000,
        ),
        episodic=EpisodicMemoryConfig(
            enable_merkle_chain=True,         # hash-chain for integrity
            max_episodes=50000,
            retention_days=180,
        ),
        semantic=SemanticMemoryConfig(
            enable_knowledge_graph=True,
            enable_vector_store=True,
            embedding_dimensions=384,
            similarity_threshold=0.75,
        ),
    ),
)

# =============================================================================
# 2. Initialize the kernel
# =============================================================================

from vak.kernel import VakKernel

kernel = VakKernel(config=config)
kernel.initialize()
print(f"Kernel '{config.name}' initialized: {kernel.is_initialized}")

# =============================================================================
# 3. Define policies — Cedar-style ABAC rules
# =============================================================================

from vak.policy import PolicyRule, PolicyCondition

rules = [
    # Admins can do anything
    PolicyRule(
        id="admin-full-access",
        effect="permit",
        principal="admin",
        action="*",
        resource="*",
        priority=100,
        description="Full access for admin role",
    ),

    # Analysts may read reports
    PolicyRule(
        id="analyst-read-reports",
        effect="permit",
        principal="analyst",
        action="data.read",
        resource="reports/*",
        description="Analysts can read report files",
    ),

    # Any agent can use the calculator
    PolicyRule(
        id="allow-calculator",
        effect="permit",
        action="tool.execute",
        resource="calculator",
        description="Everyone may use the calculator",
    ),

    # Block untrusted agents from writing
    PolicyRule(
        id="block-untrusted-write",
        effect="forbid",
        action="*.write",
        resource="*",
        conditions=[
            PolicyCondition("trusted", "equals", False),
        ],
        priority=200,
        description="Untrusted agents cannot write",
    ),

    # Block access to secrets
    PolicyRule(
        id="block-secret-access",
        effect="forbid",
        action="data.read",
        resource="secrets/*",
        priority=300,
        description="No agent may read secrets",
    ),
]

# The kernel's own policy comes from its configuration: the allowed and
# blocked tools above, or YAML/Cedar policy files (policy.policy_paths).
# These Python rules are evaluated with the standalone PolicyEngine in
# section 8; the kernel doesn't consult them.
print(f"Defined {len(rules)} policy rules for the standalone engine")

# =============================================================================
# 4. Define constraints and safety rules (reasoner)
# =============================================================================

from vak.reasoner import Constraint, SafetyRule, ReasonerConfig, PRMConfig

# Constraints and safety rules live in a ReasonerConfig and are checked in
# Python when you ask. The kernel doesn't enforce them.
reasoner = ReasonerConfig(
    prm=PRMConfig(
        enabled=True,
        threshold=0.7,
        score_components=["logic", "safety", "relevance"],
    ),
    enable_formal_verification=True,
    enable_tree_search=False,
)

reasoner.add_constraint(
    Constraint(
        name="max-steps",
        kind="max_steps",
        value=100,
        description="Limit agent to 100 reasoning steps",
    )
)

reasoner.add_constraint(
    Constraint(
        name="no-secrets",
        kind="forbidden_files",
        value=[".env", "secrets.json", "credentials.yaml"],
        description="Protect sensitive configuration files",
    )
)

reasoner.add_constraint(
    Constraint(
        name="budget-cap",
        kind="max_budget",
        value=50.0,
        description="Cap API spending at $50",
    )
)

# Add safety rules
reasoner.add_safety_rule(
    SafetyRule(
        name="no-delete",
        description="Block all file deletion operations",
        pattern="file.delete",
        action="block",
        severity="critical",
    )
)

reasoner.add_safety_rule(
    SafetyRule(
        name="warn-external-api",
        description="Warn when calling external APIs",
        pattern="network.*",
        action="warn",
        severity="medium",
    )
)

print(f"Configured reasoner: {len(reasoner.constraints)} constraints, "
      f"{len(reasoner.safety_rules)} safety rules, PRM={'on' if reasoner.prm.enabled else 'off'}")

# =============================================================================
# 5. Register WASM skills (sandboxed tools)
# =============================================================================

# Skills are loaded into the kernel from their manifest files, verified as at
# startup: signed by a trusted publisher unless signature_verification is
# off. Loading authorizes no one; the kernel's policy still decides each call.
from pathlib import Path

manifest = Path("skills/calculator/skill.yaml")
if manifest.exists():
    print(f"Loaded skill: {kernel.load_skill(manifest)}")
print(f"Kernel skills: {kernel.list_skills()}")

# =============================================================================
# 6. Register agents and execute tools
# =============================================================================

from vak.agent import AgentConfig
from vak.exceptions import PolicyViolationError

# Register a trusted admin agent
admin_agent = AgentConfig(
    agent_id="admin-bot",
    name="Admin Bot",
    role="admin",
    trusted=True,
    capabilities=["*"],
    allowed_tools=["echo", "calculator", "code-analyzer", "system_info"],
)
kernel.register_agent(admin_agent)

# Register an analyst agent (limited)
analyst_agent = AgentConfig(
    agent_id="analyst-bot",
    name="Analyst Bot",
    role="analyst",
    trusted=False,
    capabilities=["data.read", "compute.basic"],
    allowed_tools=["echo"],
)
kernel.register_agent(analyst_agent)

print(f"Registered agents: {kernel.list_agents()}")

# Execute a tool as the admin. The tool gets {"action": ..., "params": ...}.
response = kernel.execute_tool(
    agent_id="admin-bot",
    tool_id="echo",
    action="summarize",
    parameters={"report": "q4"},
)
print(f"\nAdmin echo: success={response.success}, result={response.result}")
print(f"Receipt: decision leaf {response.receipt['decision_leaf']}, "
      f"outcome leaf {response.receipt['outcome_leaf']}")

# The analyst's own scope is ["echo"]: the kernel refuses anything else.
print("\nAnalyst calling a tool outside its scope:")
try:
    kernel.execute_tool("analyst-bot", "calculator", "multiply", {"a": 7, "b": 6})
except PolicyViolationError as exc:
    print(f"  Refused by the kernel [{exc.decision.policy_id}]: {exc.decision.reason}")

# system_info is blocked in the kernel's configuration.
try:
    kernel.execute_tool("admin-bot", "system_info", "read", {})
except PolicyViolationError as exc:
    print(f"  Refused by the kernel [{exc.decision.policy_id}]: {exc.decision.reason}")

# =============================================================================
# 7. Check constraints
# =============================================================================

# Simulate checking constraints against current execution state
results = reasoner.check_constraints({
    "step_count": 42,
    "budget_spent": 12.50,
    "target_file": "app.py",
})

print("\nConstraint check results:")
for r in results:
    status = "PASS" if r.passed else "FAIL"
    msg = f" — {r.message}" if r.message else ""
    print(f"  [{status}] {r.constraint_name}{msg}")

# Check with a violation
results = reasoner.check_constraints({
    "step_count": 150,        # exceeds max_steps=100
    "budget_spent": 75.0,     # exceeds budget_cap=50
    "target_file": ".env",    # forbidden file
})

print("\nConstraint check with violations:")
for r in results:
    status = "PASS" if r.passed else "FAIL"
    msg = f" — {r.message}" if r.message else ""
    print(f"  [{status}] {r.constraint_name}{msg}")

# =============================================================================
# 8. Policy evaluation directly
# =============================================================================

from vak.policy import PolicyEngine, permit, deny

# You can also use the PolicyEngine standalone (without the kernel)
engine = PolicyEngine(default_effect="deny")
engine.add_rules(rules)

decision = engine.evaluate(
    role="analyst",
    action="data.read",
    resource="reports/q4-summary.csv",
)
print(f"\nStandalone policy check: {decision.effect.value} — {decision.reason}")

decision = engine.evaluate(
    role="analyst",
    action="data.read",
    resource="secrets/api-key.txt",
)
print(f"Secrets access check:   {decision.effect.value} — {decision.reason}")

# =============================================================================
# 9. Context manager for sessions
# =============================================================================

temp_agent = AgentConfig(
    agent_id="temp-worker",
    name="Temporary Worker",
    capabilities=["compute.basic"],
    allowed_tools=["echo"],
)

with kernel.session(temp_agent) as k:
    resp = k.execute_tool("temp-worker", "echo", "add", {"a": 1, "b": 1})
    print(f"\nSession tool call: {resp.result}")
# temp-worker is automatically unregistered here

print(f"Agents after session: {kernel.list_agents()}")

# =============================================================================
# 10. Swarm configuration (for multi-agent setups)
# =============================================================================

from vak.swarm import (
    SwarmConfig,
    ConsensusProtocol,
    VotingConfig,
    DebateConfig,
    SycophancyDetectionConfig,
)

swarm = SwarmConfig(
    protocol=ConsensusProtocol.QUADRATIC_VOTING,
    voting=VotingConfig(
        token_budget=100,
        quorum_threshold=0.6,
        quadratic_cost=True,
    ),
    debate=DebateConfig(
        max_turns_per_side=3,
        require_evidence=True,
        scoring_criteria=["logic", "evidence", "relevance"],
    ),
    sycophancy=SycophancyDetectionConfig(
        enabled=True,
        agreement_threshold=0.9,
        diversity_weight=0.3,
    ),
    max_agents=10,
)

print(f"\nSwarm config: protocol={swarm.protocol.value}, "
      f"max_agents={swarm.max_agents}, "
      f"token_budget={swarm.voting.token_budget}")

# =============================================================================
# 11. Audit trail
# =============================================================================

# Every call above, refused or run, is in the kernel's hash-chained log.
for entry in kernel.get_audit_logs(agent_id="analyst-bot"):
    print(f"  {entry.level.value:7} {entry.action}: {entry.policy_decision.effect.value}")
print(f"Audit chain verifies: {kernel.verify_audit_chain()}")
print(f"Signed tree head: {kernel.export_audit_receipt()['head']}")

# =============================================================================
# Cleanup
# =============================================================================

kernel.shutdown()
print(f"\nKernel shut down. initialized={kernel.is_initialized}")
print("\nDone — all VAK modules demonstrated.")
