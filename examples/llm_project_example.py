#!/usr/bin/env python3
"""
VAK — Full LLM Project Integration Example

Shows how to build a secure, policy-enforced LLM application using
the VAK Python SDK. This is what a user's own project looks like
when they ``pip install vak`` and define their own policies,
constraints, skills, and agent configurations.

Sections:
    1. Kernel configuration with memory and security settings
    2. Policy rules (Cedar-style ABAC)
    3. Constraints and safety rules (neuro-symbolic reasoner)
    4. Skill registration (WASM sandboxed tools)
    5. Agent registration and tool execution
    6. Swarm configuration (multi-agent consensus)
    7. Audit trail querying

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
        signature_verification=False,        # enable in production
        max_memory_bytes=256 * 1024 * 1024,  # 256 MB per tool
        sandbox_timeout_ms=10000,            # 10 s per tool call
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

kernel.load_policies(rules)
print(f"Loaded {len(rules)} policy rules")

# =============================================================================
# 4. Define constraints and safety rules (reasoner)
# =============================================================================

from vak.reasoner import Constraint, SafetyRule, ReasonerConfig, PRMConfig

# Add individual constraints
kernel.add_constraint(
    Constraint(
        name="max-steps",
        kind="max_steps",
        value=100,
        description="Limit agent to 100 reasoning steps",
    )
)

kernel.add_constraint(
    Constraint(
        name="no-secrets",
        kind="forbidden_files",
        value=[".env", "secrets.json", "credentials.yaml"],
        description="Protect sensitive configuration files",
    )
)

kernel.add_constraint(
    Constraint(
        name="budget-cap",
        kind="max_budget",
        value=50.0,
        description="Cap API spending at $50",
    )
)

# Add safety rules
kernel.add_safety_rule(
    SafetyRule(
        name="no-delete",
        description="Block all file deletion operations",
        pattern="file.delete",
        action="block",
        severity="critical",
    )
)

kernel.add_safety_rule(
    SafetyRule(
        name="warn-external-api",
        description="Warn when calling external APIs",
        pattern="network.*",
        action="warn",
        severity="medium",
    )
)

# Or configure the whole reasoner at once
reasoner = ReasonerConfig(
    constraints=kernel.reasoner.constraints,       # keep what we added
    safety_rules=kernel.reasoner.safety_rules,     # keep what we added
    prm=PRMConfig(
        enabled=True,
        threshold=0.7,
        score_components=["logic", "safety", "relevance"],
    ),
    enable_formal_verification=True,
    enable_tree_search=False,
)
kernel.configure_reasoner(reasoner)

print(f"Configured reasoner: {len(reasoner.constraints)} constraints, "
      f"{len(reasoner.safety_rules)} safety rules, PRM={'on' if reasoner.prm.enabled else 'off'}")

# =============================================================================
# 5. Register WASM skills (sandboxed tools)
# =============================================================================

from vak.skills import SkillManifest, SkillPermissions

# A calculator skill — low risk, no file/network access
calculator_skill = SkillManifest(
    id="calculator",
    name="Calculator",
    version="1.0.0",
    description="Arithmetic operations in a sandboxed environment",
    actions=["add", "subtract", "multiply", "divide"],
    risk_level="low",
    permissions=SkillPermissions(
        deny_network=True,
        deny_read_files=["*"],
        deny_write_files=["*"],
        max_memory_bytes=16 * 1024 * 1024,   # 16 MB
        max_execution_ms=1000,
    ),
)

# A code analyzer skill — can read source files
analyzer_skill = SkillManifest(
    id="code-analyzer",
    name="Code Analyzer",
    version="2.1.0",
    description="Static analysis of source code for vulnerabilities",
    wasm_path="skills/code_analyzer.wasm",
    actions=["analyze", "lint", "format"],
    risk_level="medium",
    permissions=SkillPermissions(
        allow_read_files=["*.py", "*.js", "*.ts", "*.rs"],
        deny_write_files=["*"],
        deny_network=True,
        max_memory_bytes=64 * 1024 * 1024,   # 64 MB
        max_execution_ms=30000,
    ),
    input_schema={
        "type": "object",
        "properties": {
            "file_path": {"type": "string"},
            "language": {"type": "string", "enum": ["python", "javascript", "typescript", "rust"]},
        },
        "required": ["file_path"],
    },
)

kernel.register_skill(calculator_skill)
kernel.register_skill(analyzer_skill)
print(f"Registered skills: {kernel.list_skills()}")

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
    allowed_tools=["calculator", "code-analyzer"],
)
kernel.register_agent(admin_agent)

# Register an analyst agent (limited)
analyst_agent = AgentConfig(
    agent_id="analyst-bot",
    name="Analyst Bot",
    role="analyst",
    trusted=False,
    capabilities=["data.read", "compute.basic"],
    allowed_tools=["calculator"],
)
kernel.register_agent(analyst_agent)

print(f"Registered agents: {kernel.list_agents()}")

# Execute a tool as the admin
response = kernel.execute_tool(
    agent_id="admin-bot",
    tool_id="calculator",
    action="add",
    parameters={"a": 42, "b": 58},
)
print(f"\nAdmin calculator: success={response.success}, result={response.result}")

# Execute a tool as the analyst
response = kernel.execute_tool(
    agent_id="analyst-bot",
    tool_id="calculator",
    action="multiply",
    parameters={"a": 7, "b": 6},
)
print(f"Analyst calculator: success={response.success}, result={response.result}")

# Demonstrate safety rule blocking
print("\nTesting safety rule (file.delete should be blocked):")
try:
    kernel.execute_tool(
        agent_id="admin-bot",
        tool_id="code-analyzer",
        action="delete",     # matches "file.delete" pattern? No, but "tool.delete"
        parameters={"file": "important.py"},
    )
    print("  Tool executed (action didn't match safety pattern)")
except PolicyViolationError as exc:
    print(f"  Blocked by safety rule: {exc.decision.reason}")

# =============================================================================
# 7. Check constraints
# =============================================================================

# Simulate checking constraints against current execution state
results = kernel.check_constraints({
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
results = kernel.check_constraints({
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
    allowed_tools=["calculator"],
)

with kernel.session(temp_agent) as k:
    resp = k.execute_tool("temp-worker", "calculator", "add", {"a": 1, "b": 1})
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
# 11. Custom policy hooks (Python callbacks)
# =============================================================================

def rate_limit_hook(agent_id: str, action: str, context: dict) -> None:
    """
    Return a PolicyDecision to override, or None to fall through to rules.

    This hook could check Redis, a rate limiter, an external auth service, etc.
    """
    if context.get("request_count", 0) > 1000:
        return deny(
            policy_id="rate-limit",
            reason=f"Agent {agent_id} exceeded 1000 requests",
        )
    return None

kernel.add_policy_hook(rate_limit_hook)

# =============================================================================
# Cleanup
# =============================================================================

kernel.shutdown()
print(f"\nKernel shut down. initialized={kernel.is_initialized}")
print("\nDone — all VAK modules demonstrated.")
