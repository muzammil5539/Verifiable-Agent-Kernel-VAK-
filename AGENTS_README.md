# VAK Project Structure
# Overview of custom agents, instructions, and prompts

## Directory Structure

```
VAK/
├── agents/
│   ├── development/           # Development-time code generation agents
│   │   ├── kernel_core_agent.yaml
│   │   ├── crypto_memory_agent.yaml
│   │   ├── neurosymbolic_agent.yaml
│   │   ├── wasm_sandbox_agent.yaml
│   │   ├── policy_engine_agent.yaml
│   │   ├── python_sdk_agent.yaml
│   │   └── testing_agent.yaml
│   │
│   └── runtime/               # Runtime enforcement agents
│       ├── policy_enforcement_agent.yaml
│       ├── audit_logging_agent.yaml
│       ├── prm_scoring_agent.yaml
│       ├── formal_verification_agent.yaml
│       ├── swarm_consensus_agent.yaml
│       └── state_manager_agent.yaml
│
├── instructions/              # System instructions for agents
│   ├── global.instructions.yaml       # Core principles (all agents)
│   ├── safety.instructions.yaml       # Safety rules (all agents)
│   ├── code_generation.instructions.yaml  # Dev agent standards
│   └── policy_authoring.instructions.yaml # Policy writing guide
│
├── prompts/                   # Prompt templates
│   ├── code_generation.prompts.yaml   # Code gen prompts
│   ├── reasoning_verification.prompts.yaml  # PRM/verification
│   ├── policy_audit.prompts.yaml      # Policy & audit prompts
│   └── multi_agent.prompts.yaml       # Consensus/debate prompts
│
├── protocols/                 # Communication protocols
│   ├── inter_agent_protocol.yaml      # Agent-to-agent comms
│   └── kernel_api.yaml               # Kernel API spec
│
└── config/
    └── agent_registry.yaml    # Central agent registry
```

## Agent Summary

### Development Agents (7)

| Agent | Purpose | Key Capabilities |
|-------|---------|-----------------|
| **Kernel Core** | Build Rust kernel | Async, policy engine, tool orchestration |
| **Crypto Memory** | Merkle DAG memory | Hash chains, state snapshots, rollback |
| **Neuro-Symbolic** | Verification layer | PRM scoring, Z3 integration, ToT |
| **WASM Sandbox** | Secure execution | Wasmtime, skill signing, isolation |
| **Policy Engine** | ABAC system | Rule parsing, condition evaluation |
| **Python SDK** | Developer interface | PyO3 bindings, LangChain integration |
| **Testing** | Quality assurance | Adversarial tests, fuzzing, benchmarks |

### Runtime Agents (6)

| Agent | Purpose | Key Responsibilities |
|-------|---------|---------------------|
| **Policy Enforcement** | Gatekeeper | Intercept actions, check policies, route |
| **Audit Logging** | Historian | Append-only logs, hash chains, receipts |
| **PRM Scoring** | Critic | Score reasoning steps, trigger backtrack |
| **Formal Verification** | Prover | Z3 checks, invariant validation |
| **Swarm Consensus** | Coordinator | Quadratic voting, debate protocols |
| **State Manager** | Memory keeper | Context windows, snapshots, rollback |

## Instruction Files

### global.instructions.yaml
Core principles all agents must follow:
- Safety First (inadmissible = undefined)
- Cryptographic Integrity (hash everything)
- Deterministic Control (LLMs propose, kernel disposes)
- Isolation Principle (WASM sandboxing)
- Auditability (every decision logged)

### safety.instructions.yaml
- Inadmissibility doctrine
- Escalation protocols (4 levels)
- Prompt injection defense
- Data protection (PII handling)
- Security boundaries (trust levels)

### code_generation.instructions.yaml
- Rust standards (error handling, async patterns)
- Python standards (typing, async)
- Testing requirements (coverage, adversarial)
- Security requirements (secrets, input validation)

### policy_authoring.instructions.yaml
- Policy JSON structure
- Rule authoring principles
- Condition operators (eq, lt, in, contains, etc.)
- Common patterns (time-based, approval workflow)
- Testing policies

## Prompt Libraries

### code_generation.prompts.yaml (5 prompts)
- `implement_kernel_module` - Generate new kernel modules
- `implement_policy_evaluator` - Build ABAC evaluation
- `implement_audit_logger` - Create audit system
- `implement_wasm_sandbox` - Build WASM runtime
- `implement_python_binding` - Generate PyO3 bindings

### reasoning_verification.prompts.yaml (5 prompts)
- `evaluate_reasoning_step` - PRM scoring
- `detect_reasoning_loop` - Loop detection
- `generate_backtrack_suggestion` - Alternative approaches
- `translate_to_formal_spec` - NL → SMT-LIB2
- `explain_verification_failure` - Human-readable errors

### policy_audit.prompts.yaml (5 prompts)
- `explain_policy_decision` - Decision explanation
- `generate_policy_from_description` - NL → JSON policy
- `suggest_policy_improvements` - Security analysis
- `analyze_audit_trail` - Pattern/anomaly detection
- `generate_compliance_report` - Formal reports

### multi_agent.prompts.yaml (6 prompts)
- `quadratic_vote_decision` - Voting guidance
- `debate_proposer_turn` - Debate FOR
- `debate_opponent_turn` - Debate AGAINST
- `debate_judge_decision` - Judge evaluation
- `devils_advocate_challenge` - Challenge majority
- `ensemble_aggregation` - Aggregate results

## Communication Flow

```
┌──────────────┐     tool_request     ┌─────────────────────┐
│   Any Agent  │ ───────────────────► │ Policy Enforcement  │
└──────────────┘                      └──────────┬──────────┘
                                                 │
                           ┌─────────────────────┼─────────────────────┐
                           │                     │                     │
                           ▼                     ▼                     ▼
                   ┌───────────────┐     ┌───────────────┐     ┌───────────────┐
                   │ Formal Verif  │     │ Tool Executor │     │ Audit Logger  │
                   │ (high-stakes) │     │    (WASM)     │     │  (all actions)│
                   └───────────────┘     └───────────────┘     └───────────────┘
```

## Getting Started

1. **Load Agent Registry**: Start with `config/agent_registry.yaml`
2. **Apply Instructions**: Load relevant instructions per agent category
3. **Assign Prompts**: Map prompts to agents based on their functions
4. **Initialize Runtime**: Start runtime agents (Policy → Audit → others)
5. **Register Dev Agents**: Start development agents as needed

## Key Design Decisions

1. **Kernel-Mediated Communication**: All messages route through kernel
2. **Deny by Default**: No policy = inadmissible (not allowed)
3. **Hash Everything**: State changes produce Merkle hashes
4. **WASM Isolation**: Tools run in sandboxes
5. **Quadratic Voting**: Prevents sycophancy in multi-agent systems
6. **PRM at Every Step**: Reasoning evaluated before execution

## GitHub Copilot Agent Skills

VAK provides a set of skills that enable GitHub Copilot to interact with the kernel. These are located in `.github/skills/` and can be used by Copilot to perform verifiable actions.

### Available Skills

| Skill | Description | Usage |
|-------|-------------|-------|
| `vak-audit` | Query audit logs | "Show me the audit trail for agent X" |
| `vak-execute` | Execute tools | "Run the calculator tool" |
| `vak-policy` | Check policies | "Can I read this file?" |
| `vak-manage` | Manage agents | "List registered agents" |
| `vak-sdk-gen` | Generate SDK code | "Generate Python wrapper for Struct" |

These skills automatically handle the VAK Python SDK installation and configuration, providing a seamless experience for Copilot users.
