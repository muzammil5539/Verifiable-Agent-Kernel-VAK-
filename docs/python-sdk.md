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
| Rust        | 1.75+   |
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

# 3. Evaluate a policy
decision = kernel.evaluate_policy(
    agent_id="analyst-001",
    action="read",
    context={"resource": "/data/reports/q4.csv"},
)
print(f"Policy: {decision.effect}")  # PolicyEffect.ALLOW or .DENY

# 4. Execute a tool (WASM-sandboxed)
response = kernel.execute_tool(
    agent_id="analyst-001",
    tool_id="calculator",
    action="add",
    parameters={"a": 42, "b": 58},
)
print(f"Result: {response.result}")  # {"tool": "calculator", ...}

# 5. Audit trail
logs = kernel.get_audit_logs(agent_id="analyst-001")
for entry in logs:
    print(entry)

# 6. Shutdown
kernel.shutdown()
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
    decision = ctx.evaluate_policy("read", {"resource": "/data"})
    result = ctx.execute_tool("calculator", "add", {"a": 1, "b": 2})
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
│  VAK Kernel (Rust)  │  ← PolicyEngine, AuditLogger, WASM Sandbox
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
        └── test_integration.py
```

---

## Further Reading

- [Main README](../README.md) -- Full project documentation
- [Architecture Documentation](../ARCHITECTURE.md) -- System design and module reference
- [API Reference](../API.md) -- Complete API reference (Rust & Python)
- [CONTRIBUTING.md](../CONTRIBUTING.md) -- Contribution guidelines
- [CHANGELOG.md](../CHANGELOG.md) -- Version history
- [examples/](../examples/) -- Usage examples (Rust and Python)
