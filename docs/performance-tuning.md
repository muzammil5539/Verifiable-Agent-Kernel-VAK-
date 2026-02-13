# VAK Performance Tuning Guide

> **Verifiable Agent Kernel (VAK) v1.0** -- Optimization and Profiling Reference

---

## Table of Contents

- [Performance Characteristics](#performance-characteristics)
- [Benchmarking](#benchmarking)
- [Kernel Tuning](#kernel-tuning)
- [Policy Engine Optimization](#policy-engine-optimization)
- [WASM Sandbox Optimization](#wasm-sandbox-optimization)
- [Audit Logging Optimization](#audit-logging-optimization)
- [Memory System Optimization](#memory-system-optimization)
- [Python SDK Performance](#python-sdk-performance)
- [Profiling Tools](#profiling-tools)
- [Resource Sizing](#resource-sizing)
- [Production Performance Monitoring](#production-performance-monitoring)

---

## Performance Characteristics

VAK is designed for low-latency policy enforcement and sandboxed execution. Key performance properties:

| Operation | Typical Latency | Throughput |
|-----------|----------------|------------|
| Policy evaluation (cached) | < 1 ms | 50,000+ ops/sec |
| Policy evaluation (uncached) | 1-5 ms | 10,000+ ops/sec |
| WASM skill execution (simple) | 1-10 ms | 5,000+ ops/sec |
| Audit log entry | < 1 ms | 20,000+ ops/sec |
| Memory store/retrieve | < 1 ms | 30,000+ ops/sec |

These numbers are from the benchmark suite running on a 4-core system. Actual performance depends on hardware, configuration, and workload.

---

## Benchmarking

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark groups
cargo bench -- kernel
cargo bench -- policy
cargo bench -- audit
cargo bench -- sandbox
cargo bench -- memory

# Using Makefile
make bench

# Full profiling suite (benchmarks + flamegraph + binary analysis)
make perf
```

### Benchmark Groups (25 total)

| Group | Module | What it measures |
|-------|--------|-----------------|
| `kernel_create_session` | Kernel | Session creation overhead |
| `kernel_tool_dispatch` | Kernel | End-to-end tool dispatch |
| `policy_eval_*` | Policy | Rule evaluation latency |
| `policy_cache_*` | Policy | LRU cache hit/miss performance |
| `audit_log_*` | Audit | Entry creation and chain verification |
| `audit_signed_*` | Audit | Ed25519 signed entry overhead |
| `memory_merkle_*` | Memory | Merkle DAG operations |
| `memory_kgraph_*` | Memory | Knowledge graph queries |
| `sandbox_execute_*` | Sandbox | WASM skill execution |
| `secrets_*` | Secrets | Secret store/retrieve latency |

### Establishing Baselines

Before tuning, establish performance baselines:

```bash
# Save baseline results
cargo bench -- --save-baseline before

# After changes, compare
cargo bench -- --baseline before
```

### Performance Profiling Script

Use the included profiling script for comprehensive analysis:

```bash
# Full profiling suite
./scripts/perf-profile.sh all

# Individual analyses
./scripts/perf-profile.sh benchmark    # Run benchmarks
./scripts/perf-profile.sh flamegraph   # Generate flamegraphs
./scripts/perf-profile.sh compile      # Compilation timing
./scripts/perf-profile.sh binary-size  # Binary size analysis
```

---

## Kernel Tuning

### Concurrent Agent Limit

The `maxConcurrentAgents` setting controls how many agents can be active simultaneously:

```yaml
vak:
  maxConcurrentAgents: 50    # Increase for high-throughput workloads
```

**Guidelines:**
- Each agent consumes memory for its session state
- Start with 10 agents and increase based on monitoring
- Monitor `vak_active_agents` metric to understand utilization

### Async Pipeline

VAK uses Tokio for async execution. For high-throughput scenarios, tune the Tokio runtime:

```bash
# Increase worker threads (default = number of CPU cores)
TOKIO_WORKER_THREADS=8

# Adjust blocking thread pool
TOKIO_MAX_BLOCKING_THREADS=128
```

### Execution Timeout

Balance between allowing long operations and preventing resource waste:

```yaml
vak:
  maxExecutionTimeSecs: 30   # Default; increase for complex skills
```

---

## Policy Engine Optimization

### Evaluation Caching

Policy evaluation results are cached using an LRU cache with TTL:

- **Cache hit**: Sub-microsecond policy decisions
- **Cache miss**: Full rule evaluation (~1-5 ms depending on rule count)

The cache is automatically enabled. Key tuning parameters:

- Cache size: Proportional to the number of unique request patterns
- TTL: How quickly policy changes take effect (trade-off between freshness and performance)

### Policy Rule Ordering

Policies are evaluated by priority. Optimization tips:

1. **Put deny rules first** (higher priority): Short-circuits evaluation early for blocked requests
2. **Use specific patterns**: `file_read` is faster to match than `file_*`
3. **Minimize condition count**: Each condition adds evaluation overhead
4. **Group related policies**: Reduces the number of rules the engine scans

### Hot-Reload Performance

Policy hot-reload uses lock-free atomic pointer swapping (`arc-swap`):

- Reload of policy files: ~10 ms for 100 policies
- No request blocking during reload
- Reader threads see the new policy set atomically

---

## WASM Sandbox Optimization

### Skill Compilation

Build WASM skills with the size-optimized profile:

```bash
# Use the wasm-release profile for production skills
cargo build -p my_skill --target wasm32-unknown-unknown --profile wasm-release
```

The `wasm-release` profile (`Cargo.toml`):
```toml
[profile.wasm-release]
inherits = "release"
opt-level = "s"      # Optimize for size
lto = true           # Link-time optimization
codegen-units = 1    # Single codegen unit for better optimization
strip = true         # Strip debug info
panic = "abort"      # Smaller panic handling
```

### Fuel Allocation

Set fuel budgets based on skill complexity:

| Skill Type | Recommended Fuel | Description |
|-----------|-----------------|-------------|
| Simple computation | 100,000 | Arithmetic, string ops |
| Data processing | 1,000,000 | JSON parsing, transformations |
| Complex analysis | 10,000,000 | Text analysis, pattern matching |
| Heavy computation | 100,000,000 | Cryptographic operations |

### Memory Pooling

The pooling allocator reduces per-invocation overhead by pre-allocating memory:

- Pre-allocated memory pools reduce allocation latency
- Memory is recycled between invocations
- Configure pool size based on concurrent skill executions expected

### Epoch-Based Preemption

Epoch ticking provides cooperative preemption for long-running WASM modules:

- The epoch ticker runs in a background thread
- Lower tick intervals = more responsive preemption but higher overhead
- Default interval is sufficient for most workloads

---

## Audit Logging Optimization

### Log Rotation

Configure audit log rotation to prevent unbounded growth:

```rust
let config = AuditConfig {
    max_entries: 100_000,     // Entries per log file
    ..Default::default()
};
```

### Storage Backend Selection

| Backend | Latency | Throughput | Use Case |
|---------|---------|------------|----------|
| In-memory | ~1 us | 100K+ ops/sec | Testing, development |
| File | ~10 us | 20K+ ops/sec | Single instance production |
| SQLite | ~50 us | 10K+ ops/sec | Queryable audit trail |
| S3 | ~50 ms | 500 ops/sec | Archival, compliance |

For production: Use File or SQLite as the primary backend, with S3 for archival.

### Batch Writing

For high-throughput scenarios, audit entries are buffered and written in batches. The batch size is automatically tuned based on request rate.

---

## Memory System Optimization

### Merkle DAG

The Merkle DAG uses content-addressable storage with SHA-256 hashing:

- **Read performance**: O(1) lookup by hash
- **Write performance**: O(log n) for tree updates
- **Space optimization**: Deduplication via content addressing

### Vector Store

For semantic search performance:

- Index size scales linearly with stored items
- Search performance depends on `top_k` and total items
- For large datasets (>100K items), consider external vector stores

### Knowledge Graph

The knowledge graph uses `petgraph` for in-memory graph operations:

- Node lookup: O(1)
- Edge traversal: O(degree)
- For large graphs (>1M edges), monitor memory usage

### Working Memory

Working memory uses content-aware token estimation:

- Code blocks: Higher token density
- CJK text: Adjusted character-to-token ratio
- Whitespace: Optimized handling

---

## Python SDK Performance

### Thread Pool for Async

VAK kernel operations are CPU-bound. Use a dedicated thread pool for non-blocking async integration:

```python
from concurrent.futures import ThreadPoolExecutor

# Dedicated VAK thread pool
vak_executor = ThreadPoolExecutor(
    max_workers=4,
    thread_name_prefix="vak-"
)

async def evaluate_async(agent_id, action, context):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        vak_executor,
        lambda: kernel.evaluate_policy(agent_id, action, context),
    )
```

### Batch Operations

When processing multiple requests, batch them rather than making individual calls:

```python
# Process multiple evaluations concurrently
import asyncio

async def batch_evaluate(requests):
    tasks = [
        evaluate_async(r.agent_id, r.action, r.context)
        for r in requests
    ]
    return await asyncio.gather(*tasks)
```

---

## Profiling Tools

### Flamegraph

Generate flamegraphs to identify CPU hotspots:

```bash
# Using the Makefile
make perf-flamegraph

# Manual generation
cargo flamegraph --bench kernel_benchmarks -- --bench
```

### Compilation Timing

Analyze build time to optimize development iteration:

```bash
# Using the profiling script
./scripts/perf-profile.sh compile

# Manual
cargo build --release --timings
# Opens target/cargo-timings/cargo-timing.html
```

### Binary Size Analysis

Understand binary size breakdown by dependency:

```bash
# Using the profiling script
./scripts/perf-profile.sh binary-size

# Manual (requires cargo-bloat)
cargo bloat --release -n 20
```

### Memory Profiling

For memory analysis in long-running deployments:

```bash
# Use Valgrind/DHAT for detailed heap profiling
valgrind --tool=dhat target/release/your_app

# Monitor via Prometheus metrics
curl http://localhost:8080/metrics | grep vak_memory
```

---

## Resource Sizing

### CPU Sizing

| Agents | Requests/sec | Recommended CPU |
|--------|-------------|-----------------|
| 1-10 | < 100 | 1 core |
| 10-50 | 100-1,000 | 2 cores |
| 50-200 | 1,000-10,000 | 4 cores |
| 200+ | 10,000+ | 8+ cores |

### Memory Sizing

| Component | Memory per Instance |
|-----------|-------------------|
| Kernel base | ~50 MB |
| Per active agent | ~5 MB |
| Policy cache | ~10 MB |
| Audit buffer | ~20 MB |
| WASM pool (per slot) | 1-4 MB |

**Formula**: `Base (50 MB) + Agents * 5 MB + WASM_slots * 4 MB + Buffer (50 MB)`

Example: 50 agents with 10 WASM slots = 50 + 250 + 40 + 50 = **390 MB** minimum

---

## Production Performance Monitoring

### Key Metrics to Watch

| Metric | Threshold | Action |
|--------|-----------|--------|
| `vak_requests_total` rate | Baseline dependent | Scale if increasing |
| Policy evaluation p99 | > 10 ms | Review policy rules |
| WASM execution p99 | > 100 ms | Optimize skills |
| `vak_active_agents` | > 80% of max | Increase limit |
| Memory usage | > 80% of limit | Scale up or optimize |
| CPU usage | > 70% sustained | Scale out |

### Prometheus Alert Examples

```yaml
groups:
  - name: vak-performance
    rules:
      - alert: HighPolicyLatency
        expr: histogram_quantile(0.99, vak_policy_eval_duration_seconds_bucket) > 0.01
        for: 5m
        annotations:
          summary: "Policy evaluation p99 latency above 10ms"

      - alert: HighAgentUtilization
        expr: vak_active_agents / vak_max_agents > 0.8
        for: 10m
        annotations:
          summary: "Agent utilization above 80%"
```

---

## Further Reading

- [Production Deployment Guide](production-deployment.md) -- Deployment and scaling
- [Security Hardening Guide](security-hardening.md) -- Security without sacrificing performance
- [Troubleshooting Guide](troubleshooting.md) -- Diagnosing performance issues
- [Architecture Documentation](../ARCHITECTURE.md) -- System design details
