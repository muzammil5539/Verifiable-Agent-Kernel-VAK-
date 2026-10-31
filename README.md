# Verifiable Agent Kernel (VAK)

A Rust library that sits between an LLM-driven agent and the outside world. For every tool call an agent proposes, VAK checks it against policy, writes the decision to a tamper-evident log before the call runs, and returns a receipt that anyone can verify without trusting the kernel.

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org/)

Think of it as the checkpoint at a building's door. The agent can ask for anything, but every request is checked against the guest list, written in a ledger that can't be edited, and only then let through.

## What it does

Every request passes through one function, `Kernel::execute`, in this order:

1. **Admit**: is the agent known and active, and is the tool inside its own scope?
2. **Budget**: has the agent used up its rate limit?
3. **Decide**: does policy (Cedar or YAML ABAC, default deny) permit the call?
4. **Guard**: do any registered extra checks object?
5. **Record**: append the decision to the audit log. If this fails, the tool does not run.
6. **Execute**: run a built-in tool, a host handler, or a signed WASM skill in the sandbox.
7. **Record outcome**: append the result's hash, linked to the decision.
8. **Respond**: return the result with a receipt (both log positions and a signed tree head).

The audit log is an RFC 9162 Merkle tree with Ed25519-signed heads, so a third party can check that a decision was made and that nothing was removed or rewritten afterwards. Details are in [ARCHITECTURE.md](ARCHITECTURE.md).

The rules the kernel never relaxes: deny by default, fail closed, record before acting, no fake success (a tool that didn't run is an error), untrusted code only in the sandbox, no `unsafe`.

## Status

The core request path is built and tested. The research modules around it are not all sound, and the design doc says which. [docs/architecture-v2.md](docs/architecture-v2.md) is the source of truth, with each claim checked against code.

| Area | State |
|---|---|
| Mediation pipeline, agent registry, rate limits, guards | Built |
| Policy: Cedar (with SymCC property proofs) and YAML ABAC | Built |
| Audit log: memory, JSONL and SQLite adapters, receipts, proofs | Built |
| WASM sandbox: Wasmtime 49, fuel and epoch limits, Ed25519-signed skills | Built |
| Python SDK, MCP `execute_skill` | Built, both through `Kernel::execute` |
| Datalog safety rules, PRM scoring, Z3, tree search | Heuristic: useful signals, not guarantees |
| Zero-knowledge proofs | Not a proof system. Behind `experimental-zk`, off by default |
| Sparse Merkle tree, swarm voting | Known unsound (findings V4 and S1) |
| Constitution, reasoner as guards | Not on the request path yet |

## Install

Requires Rust 1.96 or later.

```bash
git clone https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-.git
cd Verifiable-Agent-Kernel-VAK-
cargo build --release                 # core, WASM sandbox and memory
cargo build --no-default-features     # the trusted core alone, no Wasmtime
cargo build --features full           # everything except the Python bindings
```

Features outside the core are opt-in: `reasoner`, `swarm`, `integrations`, `dashboard`, `cedar`, `cedar-analysis`, `experimental-zk`, `python`. See [ARCHITECTURE.md](ARCHITECTURE.md) for what each enables.

The Python SDK is built with maturin: `pip install -e ./python`. See [docs/python-sdk.md](docs/python-sdk.md).

## Quick start

```rust
use vak::kernel::config::KernelConfig;
use vak::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kernel = Kernel::new(KernelConfig::default()).await?;

    let agent_id = AgentId::new();
    let session_id = SessionId::new();

    let request = ToolRequest::new(
        "calculator",
        serde_json::json!({ "operation": "add", "operands": [42, 58] }),
    );
    let response = kernel.execute(&agent_id, &session_id, request).await?;
    println!("success: {}, result: {:?}", response.success, response.result);

    for entry in kernel.get_audit_log().await {
        println!("{} {} {:?}", entry.agent_id, entry.action, entry.decision);
    }
    Ok(())
}
```

More in `examples/`: `basic_agent.rs`, `policy_demo.rs`, `sign_skill.rs`, `cedar_check.rs`, and the Python scripts.

A YAML policy looks like this. A call with no matching rule is denied.

```yaml
id: "refund_approval"
effect: Allow
patterns:
  actions: ["refund_user"]
  resources: ["payments/*"]
conditions:
  - field: "amount"
    operator: LessThan
    value: 1000
priority: 100
```

Operators: `Equals`, `NotEquals`, `LessThan`, `GreaterThan`, `In`, `Contains`, `StartsWith`, `EndsWith`, `Matches`. Example policies are in `policies/`. Cedar policies and their schema are in `policies/cedar/`.

## Writing a skill

Skills are WASM modules the kernel runs in the sandbox. A skill is signed with Ed25519 over its module hash and manifest, and the kernel only loads skills signed by a key in `security.trusted_skill_keys`. See [.github/skills/README.md](.github/skills/README.md) and `cargo run --example sign_skill`.

```bash
cargo build -p calculator --target wasm32-unknown-unknown --release
```

## Repository layout

| Path | Contents |
|---|---|
| `src/kernel`, `policy`, `audit`, `secrets` | The trusted core |
| `src/sandbox` | Wasmtime sandbox and skill registry |
| `src/memory`, `reasoner`, `swarm`, `integrations`, `llm` | Modules outside the core |
| `python/` | Python SDK over the native module |
| `policies/` | Example YAML and Cedar policies |
| `agents/`, `instructions/`, `prompts/`, `protocols/` | Agent definitions used to develop VAK and to run its runtime agents |
| `docs/` | Design, ADRs, deployment, security and tuning guides |
| `k8s/`, `helm/`, `scripts/` | Deployment manifests and tooling |
| `.github/skills/` | WASM skill crates and contributor skills |

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): module reference, data flow, deployment
- [API.md](API.md): API reference for Rust and Python
- [docs/architecture-v2.md](docs/architecture-v2.md): audit of claims against code, and the migration plan
- [docs/adr/](docs/adr/): decision records
- [docs/python-sdk.md](docs/python-sdk.md), [docs/production-deployment.md](docs/production-deployment.md), [docs/security-hardening.md](docs/security-hardening.md), [docs/performance-tuning.md](docs/performance-tuning.md), [docs/troubleshooting.md](docs/troubleshooting.md), [docs/migration-guide.md](docs/migration-guide.md)
- [CONTRIBUTING.md](CONTRIBUTING.md), [CHANGELOG.md](CHANGELOG.md), [TODO.md](TODO.md)

## Development

```bash
cargo test --features full            # all Rust tests
cargo test --no-default-features      # the core alone
python -m pytest python/tests/ -v     # Python SDK tests
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
make coverage-check                   # fails under 80% line coverage
make security                         # cargo audit and cargo deny
```

Commit messages follow Conventional Commits ([CONTRIBUTING.md](CONTRIBUTING.md)).

## License

MIT or Apache-2.0, at your option, as declared in `Cargo.toml`.

## Prior work

VAK draws on CoALA (cognitive architectures for language agents), Imran Siddique's Agent Control Plane, David Mc's Sovereign Kernel, process reward models, and Yao et al.'s Tree of Thoughts.
