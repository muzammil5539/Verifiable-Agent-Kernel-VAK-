# VAK Migration Guide

> **Verifiable Agent Kernel (VAK)** -- Upgrading from v0.x to v1.0

---

## Table of Contents

- [Overview](#overview)
- [Migration from v0.3 to v1.0](#migration-from-v03-to-v10)
- [Migration from v0.2 to v1.0](#migration-from-v02-to-v10)
- [Migration from v0.1 to v1.0](#migration-from-v01-to-v10)
- [Configuration Changes](#configuration-changes)
- [API Compatibility](#api-compatibility)
- [Python SDK Migration](#python-sdk-migration)
- [Helm Chart Migration](#helm-chart-migration)
- [Audit Log Migration](#audit-log-migration)
- [Verification Steps](#verification-steps)

---

## Overview

VAK v1.0 is the first production-ready release. This guide covers upgrading from any v0.x version.

### Version History

| Version | Release | Description |
|---------|---------|-------------|
| v0.1 (Alpha) | 2026-02-10 | Core kernel, policy engine, audit logging, neuro-symbolic layer |
| v0.2 (Stable) | 2026-02-13 | Complete ecosystem integrations, Python SDK stable |
| v0.3 (Beta) | 2026-02-13 | Full test coverage, infrastructure tooling, CI/CD pipeline |
| **v1.0 (Production)** | **2026-02-13** | **Production-ready with full documentation** |

### Key Changes in v1.0

- **Version bump**: `0.1.0` -> `1.0.0` in `Cargo.toml`, Helm chart, and Docker labels
- **New documentation**: Production deployment guide, security hardening guide, performance tuning guide, troubleshooting guide, and this migration guide
- **No breaking API changes**: All public Rust and Python APIs remain backward compatible
- **Documentation links**: README and other docs updated with new documentation pointers

---

## Migration from v0.3 to v1.0

This is the simplest migration path. v1.0 builds directly on v0.3 with documentation additions and version bump.

### Steps

1. **Update dependencies**:
   ```bash
   git pull origin main
   cargo update
   ```

2. **Rebuild**:
   ```bash
   cargo build --release
   ```

3. **Update container images** (if using Docker):
   ```bash
   docker build -t vak/kernel:1.0.0 .
   ```

4. **Update Helm release** (if using Kubernetes):
   ```bash
   helm upgrade vak helm/vak/ --namespace vak --set image.tag="1.0.0"
   ```

5. **Verify**:
   ```bash
   cargo test
   ```

### Breaking Changes

None. v0.3 to v1.0 has no breaking changes.

---

## Migration from v0.2 to v1.0

v0.2 to v1.0 includes all v0.3 additions (test infrastructure, CI/CD, profiling tooling).

### Steps

1. **Update source**:
   ```bash
   git pull origin main
   cargo update
   ```

2. **Review new infrastructure files** (optional, for development):
   - `tarpaulin.toml` -- Code coverage configuration
   - `Makefile` -- Development automation targets
   - `scripts/perf-profile.sh` -- Performance profiling
   - `.github/workflows/ci.yml` -- CI/CD pipeline

3. **Rebuild and test**:
   ```bash
   cargo build --release
   cargo test
   ```

### New Features Available

- Cross-module integration tests (`cargo test --test integration_root`)
- Stress & load testing (`cargo test --test integration_root test_stress`)
- Code coverage enforcement (`make coverage-check`)
- Performance profiling (`make perf`)
- 30+ Makefile development targets (`make help`)

---

## Migration from v0.1 to v1.0

v0.1 to v1.0 includes all features added in v0.2 and v0.3. This is the largest migration.

### Steps

1. **Update source and rebuild**:
   ```bash
   git pull origin main
   cargo update
   cargo build --release
   ```

2. **Update Python SDK** (if using):
   ```bash
   maturin develop --features python
   ```

3. **Review new policy features**:
   - Policy hot-reloading is now supported -- policies can be updated at runtime
   - Policy evaluation caching (LRU) for improved performance
   - Audit log rotation with configurable max entries

4. **Update integration code** (if using adapters):
   - LangChain adapter now includes LLM call interception
   - AutoGPT adapter includes PRM scoring
   - MCP server has real Datalog-based safety verification

5. **Deploy new infrastructure** (optional):
   - Kubernetes manifests in `k8s/base/`
   - Helm charts in `helm/vak/`
   - Docker multi-stage builds with dev and production targets

6. **Run full test suite**:
   ```bash
   make test-all
   ```

### New APIs Available Since v0.1

**Rust:**
- `VakRuntime` / `VakAgent` -- High-level integration API
- `ConstitutionalEngine` -- Immutable safety principles
- `ZkProver` / `ZkVerifier` -- Zero-knowledge proofs
- `PrmToolkit` -- PRM fine-tuning utilities
- `SkillMarketplace` -- Verified skill publishing
- `AgentCardDiscovery` -- A2A agent discovery
- `SecretProvider` -- Pluggable secrets management

**Python:**
- `store_memory()` / `retrieve_memory()` -- Working memory
- `store_episode()` / `retrieve_episodes()` -- Episodic memory
- `search_semantic()` -- Vector search
- `create_voting_session()` / `cast_vote()` / `tally_votes()` -- Swarm voting
- `detect_sycophancy()` -- Groupthink detection
- `verify_audit_chain()` / `get_audit_root_hash()` / `export_audit_receipt()` -- Audit verification

---

## Configuration Changes

### Environment Variables

No environment variables were removed. New optional variables in v1.0:

| Variable | Since | Default | Description |
|----------|-------|---------|-------------|
| `VAK_MAX_CONCURRENT_AGENTS` | v0.1 | 10 | Max concurrent agents |
| `VAK_MAX_EXECUTION_TIME_SECS` | v0.1 | 30 | Max WASM execution time |
| `VAK_RATE_LIMIT_RPM` | v0.1 | 60 | Rate limit per agent |

### Cargo.toml

The workspace version is updated from `0.1.0` to `1.0.0`. If you have the `vak` crate as a dependency, update your `Cargo.toml`:

```toml
[dependencies]
vak = "1.0"
```

---

## API Compatibility

### Rust API

All public APIs from v0.1, v0.2, and v0.3 remain available and unchanged in v1.0. No deprecations.

### Python SDK API

All Python SDK APIs remain backward compatible. The `VakKernel`, `AgentConfig`, policy evaluation, tool execution, memory, swarm, and audit APIs are all stable.

---

## Python SDK Migration

### From v0.1

The Python SDK gained significant features in v0.2. To access them:

```bash
# Reinstall the SDK
maturin develop --features python

# Or build a wheel
maturin build --release --features python
pip install target/wheels/vak-*.whl
```

New imports available:

```python
# Memory management (v0.2+)
from vak import VakKernel
kernel = VakKernel.default()
kernel.store_memory("key", "value")
kernel.retrieve_memory("key")

# Swarm coordination (v0.2+)
session_id = kernel.create_voting_session("Question?", config={...})
kernel.cast_vote(session_id, "agent-1", "for", weight=2)

# Audit verification (v0.2+)
assert kernel.verify_audit_chain()
```

---

## Helm Chart Migration

### From v0.2/v0.3

Update the chart version:

```bash
helm upgrade vak helm/vak/ \
  --namespace vak \
  --set image.tag="1.0.0"
```

### Values Changes

No values were removed. The chart is backward compatible with existing `values.yaml` files.

---

## Audit Log Migration

### Log Compatibility

Audit logs created by v0.1, v0.2, and v0.3 are fully compatible with v1.0. The hash-chain format has not changed.

### Verification After Upgrade

After upgrading, verify audit chain integrity:

```python
from vak import VakKernel

kernel = VakKernel.default()
assert kernel.verify_audit_chain(), "Audit chain integrity check passed"
```

---

## Verification Steps

After migration, run through this checklist:

### Build Verification

```bash
# Build succeeds
cargo build --release

# All tests pass
cargo test

# Python SDK builds
maturin develop --features python

# Python tests pass
pytest python/tests/ -v
```

### Runtime Verification

```bash
# Start the kernel
docker compose up -d vak

# Health check passes
curl http://localhost:8080/health

# Metrics are exposed
curl http://localhost:8080/metrics
```

### Functional Verification

```python
from vak import VakKernel, AgentConfig

kernel = VakKernel()
kernel.initialize()

# Agent registration works
kernel.register_agent(AgentConfig(
    agent_id="test",
    name="Migration Test",
))

# Policy evaluation works
decision = kernel.evaluate_policy("test", "read", {"resource": "/data"})

# Audit chain is valid
assert kernel.verify_audit_chain()

kernel.shutdown()
print("Migration verification passed!")
```

---

## Further Reading

- [Production Deployment Guide](production-deployment.md) -- Deploy v1.0 in production
- [Security Hardening Guide](security-hardening.md) -- Secure your deployment
- [Performance Tuning Guide](performance-tuning.md) -- Optimize performance
- [Troubleshooting Guide](troubleshooting.md) -- Resolve issues
- [CHANGELOG](../CHANGELOG.md) -- Complete version history
