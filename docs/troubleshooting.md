# VAK Troubleshooting Guide

> **Verifiable Agent Kernel (VAK) v1.0** -- Common Issues and Solutions

---

## Table of Contents

- [Diagnostic Tools](#diagnostic-tools)
- [Build Issues](#build-issues)
- [Runtime Issues](#runtime-issues)
- [Policy Engine Issues](#policy-engine-issues)
- [WASM Sandbox Issues](#wasm-sandbox-issues)
- [Audit Log Issues](#audit-log-issues)
- [Memory System Issues](#memory-system-issues)
- [Python SDK Issues](#python-sdk-issues)
- [Docker and Kubernetes Issues](#docker-and-kubernetes-issues)
- [Performance Issues](#performance-issues)
- [Getting Help](#getting-help)

---

## Diagnostic Tools

### Enable Debug Logging

```bash
# Full debug output
RUST_LOG=vak=debug cargo run

# Module-specific debug
RUST_LOG=vak::policy=debug,vak::audit=trace cargo run

# In Docker
docker run -e RUST_LOG=vak=debug vak/kernel
```

### Health Check

```bash
# HTTP health endpoint
curl -v http://localhost:8080/health

# Readiness check
curl -v http://localhost:8080/ready

# Metrics endpoint
curl http://localhost:8080/metrics
```

### Audit Chain Verification

```python
from vak import VakKernel

kernel = VakKernel.default()
is_valid = kernel.verify_audit_chain()
print(f"Audit chain valid: {is_valid}")
```

---

## Build Issues

### `error[E0463]: can't find crate for wasmtime`

**Cause**: The `wasmtime` crate requires a compatible Rust version.

**Solution**:
```bash
# Ensure MSRV 1.75+
rustup update stable
rustc --version   # Should show 1.75.0 or later
```

### `error: failed to run custom build command for rusqlite`

**Cause**: Missing SQLite build dependencies.

**Solution**:
```bash
# Ubuntu/Debian
sudo apt-get install pkg-config libsqlite3-dev

# macOS
brew install sqlite3

# Or use bundled SQLite (already configured in Cargo.toml)
cargo build --release
```

### WASM target not installed

**Cause**: The `wasm32-unknown-unknown` target is required for building skills.

**Solution**:
```bash
rustup target add wasm32-unknown-unknown
cargo build -p calculator --target wasm32-unknown-unknown --release
```

### Python SDK build fails with `maturin`

**Cause**: Missing maturin or incompatible Python version.

**Solution**:
```bash
pip install maturin>=1.4
python --version   # Requires 3.9+
maturin develop --features python
```

---

## Runtime Issues

### `Policy evaluation returned Deny for all requests`

**Cause**: Default-deny policy with no matching allow rules.

**Solution**:
1. Check that policy files exist in the configured path:
   ```bash
   ls $VAK_POLICY_PATH
   ```
2. Verify agent attributes match policy conditions:
   ```yaml
   # Ensure the agent's role matches
   conditions:
     - field: "agent_role"
       operator: Equals
       value: "admin"   # Agent must have this role
   ```
3. Check policy priorities -- deny rules with higher priority override allow rules
4. Use debug logging to see policy evaluation:
   ```bash
   RUST_LOG=vak::policy=debug cargo run
   ```

### `Agent not found` error

**Cause**: Attempting to use an agent that hasn't been registered.

**Solution**:
```python
# Register the agent before use
kernel.register_agent(AgentConfig(
    agent_id="my-agent",
    name="My Agent",
    capabilities=["read", "compute"],
))
```

### `Rate limit exceeded`

**Cause**: Agent exceeded the configured requests-per-minute limit.

**Solution**:
- Wait for the rate limit window to reset
- Increase the rate limit if appropriate:
  ```yaml
  vak:
    security:
      maxRequestsPerMinute: 120
  ```
- Distribute requests across multiple agents if load is legitimate

### Kernel fails to start

**Cause**: Invalid configuration or missing required files.

**Solution**:
1. Verify environment variables are set:
   ```bash
   echo $VAK_POLICY_PATH
   echo $VAK_AUDIT_PATH
   echo $VAK_SKILLS_PATH
   ```
2. Ensure directories exist and are accessible:
   ```bash
   ls -la $VAK_POLICY_PATH
   ls -la $VAK_AUDIT_PATH
   ```
3. Check file permissions (the process needs read access to policies, write access to audit directory)

---

## Policy Engine Issues

### Policies not reloading

**Cause**: Hot-reload may not detect changes if the file system doesn't emit events.

**Solution**:
- Verify the policy file was actually modified (check timestamps)
- On NFS or CIFS mounts, file system events may not propagate -- restart the kernel
- Check logs for hot-reload events:
  ```bash
  RUST_LOG=vak::policy::hot_reload=debug cargo run
  ```

### Policy conflicts

**Cause**: Multiple policies matching the same request with different effects.

**Solution**:
- Use the `PolicyAnalyzer` to detect conflicts:
  ```rust
  let analyzer = PolicyAnalyzer::new(&policies);
  let conflicts = analyzer.detect_conflicts();
  ```
- Higher priority values take precedence -- ensure deny rules have higher priority than allow rules for sensitive resources
- Review policies with debug logging to see evaluation order

### Condition matching failures

**Cause**: Type mismatch between condition value and request context.

**Solution**:
- Ensure numeric values are numbers, not strings:
  ```yaml
  # Correct
  value: 1000

  # Incorrect (string comparison)
  value: "1000"
  ```
- Check operator compatibility with the field type
- Available operators: `Equals`, `NotEquals`, `LessThan`, `GreaterThan`, `In`, `Contains`, `StartsWith`, `EndsWith`, `Matches`

---

## WASM Sandbox Issues

### `Fuel exhausted` error

**Cause**: The WASM module exceeded its CPU execution quota.

**Solution**:
- Increase the fuel limit for compute-intensive skills:
  ```rust
  let config = SandboxConfig {
      max_fuel: 10_000_000,  // Increase from default
      ..Default::default()
  };
  ```
- Optimize the WASM module to use fewer instructions
- Check for infinite loops or excessive recursion in the skill code

### `Memory limit exceeded` error

**Cause**: The WASM module attempted to allocate more memory than allowed.

**Solution**:
- Increase memory pages:
  ```rust
  let config = SandboxConfig {
      max_memory_pages: 64,  // 64 pages = 4 MB
      ..Default::default()
  };
  ```
- Optimize the skill to use less memory (avoid large allocations)
- Consider splitting complex operations across multiple skill invocations

### `Skill signature verification failed`

**Cause**: The WASM module's Ed25519 signature doesn't match.

**Solution**:
1. Re-sign the skill with the correct key:
   ```bash
   vak-skill-sign sign --key private.key --module my_skill.wasm
   ```
2. Ensure the public key matches the one configured in the kernel
3. Verify the WASM file hasn't been modified after signing:
   ```bash
   vak-skill-sign verify --pubkey public.key --module my_skill.wasm
   ```

### `Epoch deadline exceeded`

**Cause**: The WASM module hit the wall-clock timeout.

**Solution**:
- Increase the execution time limit:
  ```yaml
  vak:
    maxExecutionTimeSecs: 60
  ```
- Optimize the skill for faster execution
- Consider breaking long operations into smaller steps

---

## Audit Log Issues

### `Audit chain integrity check failed`

**Cause**: An audit log entry has been modified or corrupted.

**Solution**:
1. Identify the corrupted entry:
   ```python
   # The verification will indicate where the chain breaks
   kernel.verify_audit_chain()
   ```
2. Restore from backup if available
3. If running multiple instances, check for concurrent write issues
4. Ensure the audit storage is not being modified externally

### Audit logs growing too large

**Cause**: High request volume without log rotation configured.

**Solution**:
- Configure audit log rotation:
  ```rust
  let logger = AuditLogger::new(AuditConfig {
      max_entries: 100_000,  // Rotate after this many entries
      ..Default::default()
  });
  ```
- Archive old logs to S3 or external storage
- Set up a scheduled backup job (see [Production Deployment Guide](production-deployment.md))

### `Failed to write audit entry`

**Cause**: Disk full, permission error, or I/O failure.

**Solution**:
1. Check available disk space:
   ```bash
   df -h $VAK_AUDIT_PATH
   ```
2. Verify write permissions:
   ```bash
   ls -la $VAK_AUDIT_PATH
   ```
3. Check for disk I/O errors in system logs

---

## Memory System Issues

### Time travel rollback fails

**Cause**: The target hash doesn't exist in the Merkle DAG.

**Solution**:
- Verify the hash exists:
  ```rust
  let exists = merkle_dag.contains(&target_hash);
  ```
- Hashes are case-sensitive -- ensure exact match
- Check if the state was pruned or archived

### Vector store returns no results

**Cause**: No matching embeddings above the similarity threshold.

**Solution**:
- Lower the similarity threshold
- Verify data was indexed:
  ```python
  results = kernel.search_semantic("test query", top_k=10)
  print(f"Found {len(results)} results")
  ```
- Check that the embedding model is configured and accessible

---

## Python SDK Issues

### `ModuleNotFoundError: No module named '_vak_native'`

**Cause**: The native Rust extension wasn't built.

**Solution**:
```bash
# Build with maturin
maturin develop --features python

# Or install from wheel
maturin build --release --features python
pip install target/wheels/vak-*.whl
```

### `ImportError: libvak.so: cannot open shared object file`

**Cause**: The shared library isn't on the library path.

**Solution**:
```bash
# Add to library path
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Or install system-wide
sudo cp target/release/libvak.so /usr/local/lib/
sudo ldconfig
```

### Type checking errors with `mypy`

**Cause**: Missing type stubs.

**Solution**:
```bash
# The SDK includes py.typed and .pyi stubs
# Ensure the package is installed properly
pip install -e ./python
mypy --strict your_script.py
```

---

## Docker and Kubernetes Issues

### Container fails health check

**Cause**: Application not ready or port misconfigured.

**Solution**:
1. Check container logs:
   ```bash
   docker logs vak
   kubectl logs -n vak deploy/vak
   ```
2. Verify the health endpoint responds:
   ```bash
   kubectl exec -n vak deploy/vak -- curl -s http://localhost:8080/health
   ```
3. Check that port 8080 is exposed and not blocked
4. Increase `start_period` if the application needs more time to initialize

### OOMKilled in Kubernetes

**Cause**: Memory usage exceeded the container's memory limit.

**Solution**:
- Increase memory limits:
  ```yaml
  resources:
    limits:
      memory: 4Gi
  ```
- Reduce `maxConcurrentAgents` to lower memory usage
- Profile memory usage with the performance tools (see [Performance Tuning Guide](performance-tuning.md))

### Pod stuck in `CrashLoopBackOff`

**Cause**: Application is crashing during startup.

**Solution**:
1. Check logs for the crash reason:
   ```bash
   kubectl logs -n vak deploy/vak --previous
   ```
2. Common causes:
   - Missing configuration (policy path, audit path)
   - Insufficient permissions on volumes
   - Invalid Helm values
3. Try running the container interactively:
   ```bash
   kubectl run vak-debug --image=vak/kernel:1.0.0 -n vak -it --rm -- /bin/bash
   ```

### Persistent volume not mounting

**Cause**: Storage class unavailable or PVC binding issues.

**Solution**:
```bash
# Check PVC status
kubectl get pvc -n vak

# Check events
kubectl describe pvc -n vak

# Ensure the storage class exists
kubectl get storageclass
```

---

## Performance Issues

### High latency on policy evaluation

**Cause**: Large number of policies or complex conditions.

**Solution**:
- Enable policy evaluation caching (built-in LRU cache)
- Reduce the number of active policies
- Use more specific patterns to short-circuit evaluation
- Profile with:
  ```bash
  RUST_LOG=vak::policy=trace cargo run
  ```

### WASM execution slower than expected

**Cause**: Suboptimal WASM compilation or insufficient resources.

**Solution**:
- Build skills with optimizations:
  ```bash
  cargo build -p my_skill --target wasm32-unknown-unknown --profile wasm-release
  ```
- Increase resources if running in containers
- Use the benchmark suite to establish baselines:
  ```bash
  cargo bench -- sandbox
  ```

### Memory usage growing over time

**Cause**: Possible memory leak in long-running sessions.

**Solution**:
- Unregister agents when no longer needed
- Prune old audit log entries with rotation
- Monitor memory with Prometheus metrics
- Profile with the provided tooling:
  ```bash
  make perf
  ```

For detailed performance optimization, see the [Performance Tuning Guide](performance-tuning.md).

---

## Getting Help

If your issue isn't covered here:

1. **Search existing issues**: [GitHub Issues](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/issues)
2. **Enable debug logging**: `RUST_LOG=vak=debug` often reveals the root cause
3. **Check metrics**: The `/metrics` endpoint provides runtime diagnostics
4. **Open a new issue**: Include debug logs, configuration, and steps to reproduce
5. **Community discussions**: [GitHub Discussions](https://github.com/muzammil5539/Verifiable-Agent-Kernel-VAK-/discussions)

---

## Further Reading

- [Production Deployment Guide](production-deployment.md) -- Deployment procedures
- [Security Hardening Guide](security-hardening.md) -- Security configuration
- [Performance Tuning Guide](performance-tuning.md) -- Optimization
- [Migration Guide](migration-guide.md) -- Upgrading to v1.0
- [API Reference](../API.md) -- Complete API reference
