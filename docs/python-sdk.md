# VAK Python SDK — Getting Started

The **Verifiable Agent Kernel (VAK)** Python SDK provides a native, Pythonic
interface to the Rust-based kernel via [PyO3](https://pyo3.rs) bindings.
Every tool call is policy-checked, sandboxed in WASM, and recorded in a
tamper-evident audit chain.

---

## Prerequisites

| Requirement | Version |
|-------------|---------|
| Python      | 3.9+    |
| Rust        | 1.96+   |
| maturin     | 1.4+    |

```bash
# Install maturin (the PyO3 build tool)
pip install maturin
```

---

## Installation

### From source (development)

```bash
git clone https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-.git
cd Verifiable-Agent-Kernel-VAK-

# Build and install in development mode
maturin develop --features python

# Verify
python -c "from vak import VakKernel; print(VakKernel())"
```

### From PyPI (when published)

```bash
pip install vak
```

---

## Quick Start

```python
from vak import VakKernel, AgentConfig, PolicyEffect

# 1. Create and initialise the kernel
kernel = VakKernel()
kernel.initialize()

# 2. Register an agent
agent = AgentConfig(
    agent_id="analyst-001",
    name="Data Analyst Bot",
    description="Analyzes quarterly reports",
    capabilities=["read", "compute"],
    metadata={"department": "research", "clearance": "level-2"},
)
kernel.register_agent(agent)

# 3. Ask the kernel whether the agent may call a tool (nothing runs)
decision = kernel.evaluate_policy(
    agent_id="analyst-001",
    action="echo",
    context={"action": "say", "params": {"text": "hello"}},
)
print(f"Policy: {decision.effect}")  # PolicyEffect.ALLOW or .DENY

# 4. Execute a tool through the kernel
response = kernel.execute_tool(
    agent_id="analyst-001",
    tool_id="echo",
    action="say",
    parameters={"text": "hello"},
)
print(f"Result: {response.result}")  # {"action": "say", "params": {"text": "hello"}}
print(f"Receipt: {response.receipt}")  # the kernel's audit receipt

# 5. Audit trail
logs = kernel.get_audit_logs(agent_id="analyst-001")
for entry in logs:
    print(entry)

# 6. Shutdown
kernel.shutdown()
```

### Where answers come from

Policy decisions, tool results, skills and audit records come from the Rust
kernel in the native module (ADR 0011). Without the module, those methods
raise `VakError` (`execute_tool` raises `ToolExecutionError`); nothing answers
in the kernel's place.

- **Policy** comes from the kernel's configuration: `KernelConfig`'s security
  and policy settings, or a kernel config file passed to
  `VakKernel.from_config`. Without policy files, the kernel's allowlist (its
  built-in tools, unless `allowed_tools` names others) and blocklist decide.
  With policy files (`policy_paths`), the files decide; see
  [Policy files](#policy-files). Through `KernelConfig` the default decision
  has no effect: the allowlist is never empty, and tools outside it are
  denied before the default is read.
- **Not on the kernel.** There are no Python policy hooks, Python policy rules
  (`load_policies`) or safety rules on the kernel. `PolicyEngine` and
  `ReasonerConfig` remain as standalone Python evaluators that the kernel
  doesn't consult.
- **Skills** are loaded with `load_skill(manifest_path)`, verified as the
  kernel verifies them at startup.
- **Memory and voting** are Python, in this process, with or without the native
  module.

### How `execute_tool` runs a tool

`execute_tool` runs through the Rust kernel's `Kernel::execute` (ADR 0011):

- **The tool's input.** The tool gets `{"action": action, "params": parameters}`, the
  shape WASM skills take.
- **Who decides and records.** The kernel's policy decides, and its audit log records
  the decision before the tool runs and the outcome after. The response carries the
  kernel's `receipt`.
- **Refusals.** If the kernel refuses a call, it raises `PolicyViolationError` and
  nothing runs. Any other refusal, such as an unknown tool, raises
  `ToolExecutionError`.
- **Failures.** A tool that ran and failed returns `success=False` with an `error`.
- **Time limit.** `timeout_ms` applies when it is tighter than the kernel's limit.
- **Memory limit.** The kernel gives every skill 128 MiB and takes no per-call limit,
  so it refuses a `memory_limit_bytes` below that rather than run looser than asked.

Without the native module (`maturin develop`), `execute_tool` raises
`ToolExecutionError`. The SDK never reports that a tool ran when nothing ran it.

---

## Migrating the Python package from 0.1 to 1.0

This is the version of the `vak` Python package (`pyproject.toml`), not the
Rust crate's. Version 1.0 removes the methods that answered from engines the
kernel never consulted, and changes what some remaining methods answer
(ADR 0011). Each removed method has a kernel equivalent below, or there is
none. `CHANGELOG.md` says why each was removed.

### Removed from `VakKernel` and `agent_context()`

| Removed | Use instead |
|---|---|
| `create_audit_entry` | No equivalent; no longer supported. The kernel records each call made through `execute_tool`. |
| `create_audit_entry` on the context from `kernel.agent_context(...)` | No equivalent; no longer supported. |
| `add_policy_hook` | No equivalent; no longer supported. |
| `remove_policy_hook` | No equivalent; no longer supported. |
| `load_policies(rules)` | A YAML policy file in `PolicyConfig(policy_paths=[...])`, or in a kernel config file passed to `VakKernel.from_config`. The kernel reads it when it starts. See [Policy files](#policy-files) before you switch. |
| `policy_engine` | No equivalent; no longer supported. `vak.policy.PolicyEngine` remains as a standalone evaluator that the kernel doesn't consult. |
| `add_safety_rule` | A rule with action `"block"` stopped `execute_tool`. In the kernel, block the call with a forbid rule in a policy file, or a narrower `AgentConfig.allowed_tools`. Without policy files, `SecurityConfig(blocked_tools=[...])` also blocks it. A safety rule matched `tool.<action>`; the kernel matches the tool's name. |
| `add_constraint` | No equivalent; no longer supported. `ReasonerConfig.add_constraint` remains as a standalone evaluator that the kernel doesn't consult. |
| `check_constraints` | No equivalent; no longer supported. `ReasonerConfig.check_constraints` remains as a standalone evaluator that the kernel doesn't consult. |
| `configure_reasoner` | No equivalent; no longer supported. Its safety rules with action `"block"` stopped `execute_tool`: block those calls as for `add_safety_rule`. |
| `reasoner` | No equivalent; no longer supported. Safety rules added through it: as `add_safety_rule`. |
| `register_skill(manifest)` | `load_skill(manifest_path)`. It takes the path of a manifest file, and the kernel verifies the skill as it does at startup. A signed skill loads only if its key is in `security.trusted_skill_keys` in a kernel config file (`VakKernel.from_config`); `KernelConfig` can't name trusted keys. An unsigned skill loads only with `signature_verification=False`. |

### Removed from the native module (`vak._vak_native.Kernel`)

| Removed | Use instead |
|---|---|
| `add_policy_rule` | As `load_policies`: a YAML policy file in `policy_paths`, read when the kernel starts. |
| `validate_policy_config` | No equivalent; no longer supported. |
| `has_allow_policies` | No equivalent; no longer supported. |
| `policy_rule_count` | No equivalent; no longer supported. |
| `register_skill` | `load_skill(manifest_path)` |
| `get_skill_info` | `get_skill(name)` |
| `unregister_skill` | No equivalent; no longer supported. In 0.1 it changed only the binding's own map (what `list_tools` and `get_skill_info` reported). To keep the kernel from running a skill, block it when the kernel starts. |
| `set_skill_enabled` | No equivalent; no longer supported. As `unregister_skill`. |
| `create_audit_entry` | No equivalent; no longer supported. |

### Changed in 1.0

These methods remain, but answer differently. Code written for 0.1 can keep
running and get answers to a different question.

| Method | 0.1 | 1.0 |
|---|---|---|
| `VakKernel(config_path=...)`, `from_config(path)` | Read the file as policy rules for the binding's own engine, and ignored a file that didn't load. | Reads a kernel configuration file (YAML or JSON) and, with the native module, raises `VakError` if it can't. Policy files go in its `policy.policy_paths`. |
| `VakKernel(config=..., config_path=...)` | The file was read as policy rules. Of `config`, only the Python engine's default effect was used. | With the native module, raises `VakError` when any setting the SDK passes to the kernel is not the default: the name, the security and policy settings other than caching, or the audit log path. |
| `evaluate_policy(agent_id, action, context)` | `action` was any action string, `context` held a `"resource"`, the agent `"system"` was accepted unregistered, and the call wrote an audit entry. | `action` is a tool name and `context` the parameters it would be called with. An unregistered agent raises `AgentNotFoundError`. Nothing is recorded. |
| `register_agent` | Asked policy about `"agent.register"` and could raise `PolicyViolationError`. | Registers the agent with the kernel without a policy check. |
| `get_audit_logs`, `get_audit_entry` | The binding's own log. Native dicts had `decision` and `hash`; `get_audit_entry`'s also had `prev_hash`. | The kernel's log: a decision entry for each call and, if it ran, an outcome entry (`details["kind"]`). Native dicts have `policy_decision`, `details["hash"]` and `details["previous_hash"]`. |
| `verify_audit_chain` | Checked the binding's own log, or the stub's. | Checks the kernel's log. |
| `get_audit_root_hash` | The last entry's hash (native: `None` for an empty log). | The root of the kernel's RFC 9162 Merkle tree. |
| `export_audit_receipt` | Without the native module, the stub's `receipt_id`, `timestamp`, `root_hash`, `entry_count`, `first_entry` and `last_entry`. With it, an empty dict. | The kernel's signed tree head: `head` (`size`, `root`), `timestamp_ms`, `signature`, `public_key`. `root_hash` is now `head["root"]`, and `entry_count` is `head["size"]`. |
| `list_tools` | The binding's own map (`calculator` by default). | The tools the kernel can run: its built-ins, host handlers and loaded skills. |
| `list_skills` | The ids passed to `register_skill`. | The skills the kernel has loaded. |
| `get_skill(skill_id)` | A manifest registered with the SDK, by id. | A skill the kernel has loaded, by name. |
| `ToolRequest.memory_limit_bytes` | Defaulted to 64 MiB. | Defaults to 128 MiB, the limit the kernel enforces. |

### Without the native module

The `vak._stub` fallback is removed. Methods that need the kernel raise
`VakError`, and `execute_tool` raises `ToolExecutionError`. In 0.1 the stub
answered in the kernel's place and allowed every policy question.

### Policy files

Rules that went through `load_policies` go in a YAML policy file. A tool call
reaches a rule as the action `Action::"Tool::execute"` on the resource
`Tool::"<tool name>"`. Conditions are expressions over the agent's attributes
(`principal.*`) and the tool's (`resource.*`). `policies/default_policies.yaml`
is a complete example.

Once `policy_paths` is set (and `PolicyConfig.enabled` is true), the files
decide in place of the kernel-wide settings:

- **`SecurityConfig.allowed_tools` stops applying.** An allowlist has to be
  written as permit rules in the file. An agent's own
  `AgentConfig.allowed_tools` still limits `execute_tool`, though not
  `evaluate_policy`.
- **`blocked_tools` doesn't block by itself.** It reaches the rules as
  `resource.restricted`, so a permit that doesn't check
  `resource.restricted == false` can allow a blocked tool (ADR 0008).
- **A file that doesn't load leaves the kernel denying every call.**

With `PolicyConfig(enabled=False)` the files aren't read, and the allowlist
and blocklist decide.

```yaml
# policies/agents.yaml
version: "1.0"
rules:
  - id: "analysts-may-echo"
    effect: "permit"
    principal: "*"
    action: "Action::\"Tool::execute\""
    resource: "Tool::\"echo\""
    conditions:
      - "principal.role == \"analyst\""
      - "resource.restricted == false"
```

```python
from vak import AgentConfig, VakKernel
from vak.config import KernelConfig, PolicyConfig

kernel = VakKernel(config=KernelConfig(
    policy=PolicyConfig(policy_paths=["policies/agents.yaml"]),
))
kernel.initialize()
kernel.register_agent(AgentConfig(agent_id="a1", name="Analyst", role="analyst"))
assert kernel.evaluate_policy("a1", "echo").is_allowed()
assert kernel.evaluate_policy("a1", "calculator").is_denied()  # no rule permits it
```

---

## Context Manager Sessions

The `session()` context manager registers an agent on entry and
automatically unregisters it on exit:

```python
from vak import VakKernel, AgentConfig

kernel = VakKernel()
kernel.initialize()

agent = AgentConfig(agent_id="temp", name="Temp Agent")

with kernel.session(agent) as k:
    response = k.execute_tool("temp", "calculator", "multiply", {"a": 6, "b": 7})
    print(response.result)
# Agent automatically unregistered here
```

The `agent_context()` method gives a scoped context for an already-registered agent:

```python
kernel.register_agent(AgentConfig(agent_id="bot", name="Bot"))

with kernel.agent_context("bot") as ctx:
    decision = ctx.evaluate_policy("echo")
    result = ctx.execute_tool("echo", "add", {"a": 1, "b": 2})
```

---

## Exception Handling

VAK provides a hierarchy of exceptions for precise error handling:

```python
from vak import (
    VakKernel,
    VakError,
    PolicyViolationError,
    AgentNotFoundError,
    ToolExecutionError,
    AuditError,
)

kernel = VakKernel()
kernel.initialize()

try:
    kernel.execute_tool("unregistered-agent", "risky_tool", "delete", {})
except AgentNotFoundError as e:
    print(f"Agent not found: {e.agent_id}")
except PolicyViolationError as e:
    print(f"Blocked by {e.policy_id}: {e.reason}")
except ToolExecutionError as e:
    print(f"Tool {e.tool_id} failed: {e.error}")
except AuditError as e:
    print(f"Audit system error: {e}")
except VakError as e:
    print(f"General VAK error: {e}")
```

### Exception Hierarchy

```
VakError (base)
├── PolicyViolationError   — action denied by ABAC policy
├── AgentNotFoundError     — agent ID not registered
├── ToolExecutionError     — WASM tool execution failed
└── AuditError             — audit logging/verification failed
```

---

## Risk Levels

Tools can be classified by risk level for policy evaluation:

```python
from vak import RiskLevel

print(RiskLevel.LOW)       # "low"
print(RiskLevel.MEDIUM)    # "medium"
print(RiskLevel.HIGH)      # "high"
print(RiskLevel.CRITICAL)  # "critical"
```

---

## Memory Management

VAK provides a multi-tier memory system. The Python SDK exposes a working
memory store, an episodic memory chain, and a semantic search interface.

### Working Memory

```python
from vak import VakKernel
from vak.memory import MemoryItem

kernel = VakKernel.default()

# Store an item
item = kernel.store_memory("api-key-hash", "abc123", priority="high", metadata={"source": "env"})
assert isinstance(item, MemoryItem)

# Retrieve by key
result = kernel.retrieve_memory("api-key-hash")
print(result.content)  # "abc123"

# Search by keyword (key or content contains the query; not vector search)
results = kernel.search_semantic("api", top_k=5)
```

### Episodic Memory (Merkle-Chained)

Each episode is hash-chained to the previous, creating an unforgeable event log.

```python
from vak.memory import Episode

episode = Episode(
    episode_id="ep-001",
    episode_type="observation",
    content="Agent observed a config change",
    agent_id="agent-1",
    timestamp="2026-01-15T10:30:00Z",
)
hash_str = kernel.store_episode(episode)  # Returns SHA-256 hash

episodes = kernel.retrieve_episodes(limit=10)  # Most recent first
for ep in episodes:
    print(f"{ep.episode_id}: {ep.content} (hash={ep.hash[:8]}...)")
```

---

## Swarm Coordination

Multi-agent consensus using quadratic voting with sycophancy detection.

### Quadratic Voting

```python
kernel = VakKernel.default()

# Create a voting session
session_id = kernel.create_voting_session(
    "Should we deploy v2.0?",
    config={"token_budget": 100, "quorum_threshold": 0.6, "quadratic_cost": True},
)

# Agents cast votes (cost = weight^2 tokens)
kernel.cast_vote(session_id, "agent-1", "for", weight=3)   # cost: 9
kernel.cast_vote(session_id, "agent-2", "against", weight=1)  # cost: 1
kernel.cast_vote(session_id, "agent-3", "for", weight=2)   # cost: 4

# Tally and close
result = kernel.tally_votes(session_id)
print(f"Winner: {result['winner']}")       # "for"
print(f"Voters: {result['unique_voters']}") # 3
```

### Sycophancy Detection

```python
# Analyze voting history for groupthink patterns
history = [
    {"votes": [{"agent_id": "a1", "direction": "for"}, {"agent_id": "a2", "direction": "for"}]},
    {"votes": [{"agent_id": "a1", "direction": "for"}, {"agent_id": "a2", "direction": "for"}]},
]
analysis = kernel.detect_sycophancy(history)
print(f"Sycophancy: {analysis['sycophancy_detected']}")  # True if agreement > 90%
print(f"Risk level: {analysis['risk_level']}")            # "critical", "high", "medium", "low"
```

---

## Audit Chain Verification

The audit log is the kernel's: an RFC 9162 Merkle tree with a hash chain,
written only by calls the kernel mediates. Each call leaves a decision entry
and, if it ran, an outcome entry. The SDK cannot add entries of its own
(ADR 0011).

```python
kernel = VakKernel.default()
kernel.register_agent(AgentConfig(agent_id="agent-1", name="Agent One"))

# Calls through the kernel are recorded: decision, then outcome
kernel.execute_tool("agent-1", "echo", "read", {"path": "/data/report.csv"})

for entry in kernel.get_audit_logs(agent_id="agent-1"):
    print(entry.details["kind"], entry.action, entry.policy_decision.effect.value)

# Verify chain integrity
assert kernel.verify_audit_chain()  # True if no tampering

# The Merkle tree's root
root = kernel.get_audit_root_hash()
print(f"Root hash: {root}")  # SHA-256 hex string

# The kernel's signed tree head
receipt = kernel.export_audit_receipt()
print(f"Entries: {receipt['head']['size']}, signed by {receipt['public_key']}")
```

---

## Using with Async Frameworks

VAK kernel operations are CPU-bound. Use `run_in_executor` for
non-blocking integration with FastAPI, aiohttp, etc.

```python
import asyncio
from vak import VakKernel

kernel = VakKernel()
kernel.initialize()


async def evaluate_async(agent_id: str, action: str, context: dict):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        None,
        lambda: kernel.evaluate_policy(agent_id, action, context),
    )
```

### FastAPI Example

```python
from fastapi import FastAPI, HTTPException
from vak import VakKernel, AgentConfig, PolicyEffect

app = FastAPI()
kernel = VakKernel()
kernel.initialize()


@app.post("/evaluate")
async def evaluate(agent_id: str, action: str, resource: str):
    import asyncio

    loop = asyncio.get_event_loop()
    decision = await loop.run_in_executor(
        None,
        lambda: kernel.evaluate_policy(
            agent_id, action, {"resource": resource}
        ),
    )
    if decision.is_denied():
        raise HTTPException(403, detail=decision.reason)
    return {"effect": decision.effect.value, "policy_id": decision.policy_id}
```

### Thread Pool Optimisation

For high-throughput scenarios, use a dedicated `ThreadPoolExecutor`:

```python
from concurrent.futures import ThreadPoolExecutor

vak_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="vak-")


async def optimized_policy_check(agent_id: str, action: str, context: dict):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        vak_executor,
        lambda: kernel.evaluate_policy(agent_id, action, context),
    )
```

---

## Type Checking

The SDK ships with full type stubs (`.pyi`) and a `py.typed` marker (PEP 561).
All major type checkers are supported:

```bash
# mypy
mypy --strict your_script.py

# pyright / Pylance (VS Code)
# Automatically picks up type stubs
```

---

## Architecture

```
Python Application
        │
        ▼
┌─────────────────────┐
│  vak (Python SDK)   │  ← VakKernel, AgentConfig, exceptions
│  python/vak/        │
└────────┬────────────┘
         │ PyO3 FFI
         ▼
┌─────────────────────┐
│  _vak_native (Rust) │  ← PyKernel, PyPolicyDecision, PyRiskLevel, ...
│  src/python.rs      │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  VAK Kernel (Rust)  │  ← Kernel::execute: policy, audit log, WASM sandbox
│  src/               │
└─────────────────────┘
```

---

## Running Tests

```bash
# Python tests
pytest python/tests/ -v

# With coverage
pytest python/tests/ --cov=vak --cov-report=term-missing

# Type checking
mypy python/vak/ --strict

# Rust-side tests (includes PyO3 tests)
cargo test --features python
```

---

## Building for Release

```bash
# Build optimised wheel
maturin build --release --features python

# The wheel is in target/wheels/
pip install target/wheels/vak-*.whl
```

---

## Project Structure

```
VAK/
├── Cargo.toml              # Rust workspace + optional "python" feature
├── pyproject.toml           # maturin build config
├── README_PYTHON.md         # This file
├── TODO_BINDINGS.md         # Binding status tracker
├── src/
│   ├── python.rs            # PyO3 bindings (#[pyclass], #[pyfunction])
│   ├── lib.rs               # #[cfg(feature = "python")] pub mod python
│   ├── policy/              # ABAC policy engine
│   ├── audit/               # Cryptographic audit logging
│   ├── sandbox/             # WASM sandbox
│   ├── reasoner/            # PRM scoring & verification
│   └── ...                  # Other core modules
└── python/
    ├── vak/
    │   ├── __init__.py      # VakKernel wrapper + exceptions
    │   ├── types.py         # Dataclasses (AgentConfig, ToolRequest, etc.)
    │   ├── _vak_native.pyi  # Type stubs for PyO3 module
    │   └── py.typed         # PEP 561 marker
    └── tests/
        ├── test_kernel.py
        ├── test_types.py
        ├── test_integration.py
        ├── test_memory.py
        ├── test_swarm.py
        └── test_audit_chain.py
```

---

## Further Reading

- [Main README](../README.md) -- Full project documentation
- [Architecture Documentation](../ARCHITECTURE.md) -- System design and module reference
- [API Reference](../API.md) -- Complete API reference (Rust & Python)
- [Production Deployment Guide](production-deployment.md) -- Docker, Kubernetes, Helm deployment
- [Troubleshooting Guide](troubleshooting.md) -- Common issues and solutions
- [CONTRIBUTING.md](../CONTRIBUTING.md) -- Contribution guidelines
- [CHANGELOG.md](../CHANGELOG.md) -- Version history
- [examples/](../examples/) -- Usage examples (Rust and Python)
