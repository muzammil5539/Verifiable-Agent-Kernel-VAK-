# VAK Security Hardening Guide

> **Verifiable Agent Kernel (VAK) v1.0** -- Production Security Best Practices

---

## Table of Contents

- [Security Model Overview](#security-model-overview)
- [Defense in Depth](#defense-in-depth)
- [Policy Engine Hardening](#policy-engine-hardening)
- [WASM Sandbox Security](#wasm-sandbox-security)
- [Audit Log Integrity](#audit-log-integrity)
- [Cryptographic Configuration](#cryptographic-configuration)
- [Container Security](#container-security)
- [Network Security](#network-security)
- [Secrets Management](#secrets-management)
- [Supply Chain Security](#supply-chain-security)
- [Prompt Injection Protection](#prompt-injection-protection)
- [Rate Limiting and DoS Prevention](#rate-limiting-and-dos-prevention)
- [Compliance Considerations](#compliance-considerations)
- [Security Checklist](#security-checklist)

---

## Security Model Overview

VAK implements a defense-in-depth security model with multiple layers:

```
Agent Request
     │
     ▼
┌─────────────────────┐
│ Rate Limiter         │ ── Per-agent token bucket
├─────────────────────┤
│ Prompt Injection     │ ── Multi-category detection
│ Detection            │
├─────────────────────┤
│ Constitution Check   │ ── Immutable safety principles
├─────────────────────┤
│ Policy Engine (ABAC) │ ── Attribute-based access control
├─────────────────────┤
│ WASM Sandbox         │ ── Isolated execution with fuel metering
├─────────────────────┤
│ Audit Logger         │ ── Hash-chained, signed records
└─────────────────────┘
```

---

## Defense in Depth

### Layer 1: Rate Limiting

Prevents resource exhaustion and brute-force attempts.

```yaml
vak:
  security:
    enableRateLimiting: true
    maxRequestsPerMinute: 60    # Per agent
```

### Layer 2: Prompt Injection Detection

The neuro-symbolic reasoner includes multi-category prompt injection analysis that detects:

- Direct injection attempts
- Indirect injection via tool parameters
- Instruction override patterns
- Data exfiltration attempts

### Layer 3: Constitution Protocol

Immutable safety rules that cannot be overridden by policies:

- **No Harm**: Actions that could cause physical or financial harm are blocked
- **Transparency**: All decisions must be auditable
- **Least Privilege**: Agents receive minimum necessary permissions
- **Data Protection**: Sensitive data is never exposed unnecessarily
- **Human Override**: Human operators can always intervene

### Layer 4: Policy Engine (ABAC)

Attribute-Based Access Control with deny-by-default enforcement:

```yaml
# Default-deny: if no policy matches, the request is denied
vak:
  policy:
    enabled: true
    defaultDecision: "deny"
```

### Layer 5: WASM Sandbox

All skill execution happens in isolated WebAssembly sandboxes with:

- Memory limits (bounded pages)
- CPU execution quotas (fuel metering)
- Epoch-based preemption (timeouts)
- No direct host access

### Layer 6: Audit Logging

Every action is recorded in a hash-chained, Ed25519-signed audit log that provides:

- Non-repudiation
- Tamper detection
- Cryptographic replay capability

---

## Policy Engine Hardening

### Default-Deny Configuration

Always use default-deny in production:

```yaml
vak:
  policy:
    defaultDecision: "deny"
```

### Policy Best Practices

1. **Principle of least privilege**: Grant only the minimum permissions needed
2. **Explicit deny rules**: Use high-priority deny rules for sensitive resources
3. **Pattern specificity**: Use specific patterns over broad wildcards

```yaml
# Good: Specific resource patterns
id: "allow_read_reports"
effect: Allow
patterns:
  actions: ["file_read"]
  resources: ["/data/reports/*.csv"]
conditions:
  - field: "agent_role"
    operator: Equals
    value: "analyst"
priority: 100

# Always include explicit deny for sensitive paths
id: "deny_system_files"
effect: Deny
patterns:
  actions: ["file_*"]
  resources: ["/etc/*", "/sys/*", "/proc/*", "/app/config/*"]
conditions: []
priority: 200     # Higher priority = evaluated first
```

### Policy Hot-Reloading

Policies can be updated at runtime without restart. In production:

- Store policies in a ConfigMap or mounted volume
- Use read-only mounts for policy directories
- Monitor policy changes via audit logs

---

## WASM Sandbox Security

### Fuel Limits

Set appropriate fuel limits to prevent runaway execution:

```rust
let config = SandboxConfig {
    max_fuel: 1_000_000,          // CPU execution quota
    max_memory_pages: 16,          // 16 pages = 1 MB
    max_execution_time_ms: 5_000,  // 5-second timeout
};
```

### Skill Signing

All production WASM skills must be signed with Ed25519 keys:

```bash
# Sign a skill
vak-skill-sign sign --key private.key --module my_skill.wasm

# Verify a skill
vak-skill-sign verify --pubkey public.key --module my_skill.wasm
```

**Configuration for strict verification:**

In production, always enable strict signature verification. The kernel rejects unsigned or incorrectly signed skills by default. Dev-mode opt-out should never be used in production.

### Skill Marketplace Trust Levels

| Level | Description | Requirements |
|-------|-------------|--------------|
| Official | VAK team-maintained skills | Core team verification |
| Trusted | Verified organizations | GitHub org + GPG key |
| Verified | Identity-verified publishers | Domain or email verification |
| Basic | Registered publishers | Account registration |
| Unverified | Unknown publishers | Not recommended for production |

For production, only use skills at **Verified** trust level or above.

---

## Audit Log Integrity

### Chain Verification

Periodically verify the audit chain integrity:

```python
from vak import VakKernel

kernel = VakKernel.default()
assert kernel.verify_audit_chain()  # Returns True if no tampering
```

### Audit Log Protection

- Store audit logs on append-only storage when possible
- Use separate persistent volumes for audit data
- Implement regular backup procedures
- Monitor chain integrity with automated checks

### Cryptographic Receipts

Export receipts for external verification:

```python
receipt = kernel.export_audit_receipt()
# Store receipt externally for independent verification
```

---

## Cryptographic Configuration

### Algorithms Used

| Purpose | Algorithm | Key Size |
|---------|-----------|----------|
| Audit chain hashing | SHA-256 | 256-bit |
| Audit entry signing | Ed25519 | 256-bit |
| Skill signature | Ed25519 | 256-bit |
| Content addressing | SHA-256 | 256-bit |
| ZK proofs | Fiat-Shamir heuristic | 256-bit |
| Constitution tamper detection | SHA-256 | 256-bit |

### Key Management

- Store signing keys in a dedicated secrets management system (Vault, AWS KMS, etc.)
- Rotate keys periodically
- Never embed keys in container images or source code
- Use Kubernetes Secrets (encrypted at rest) or external secret operators

---

## Container Security

### Production Image

The production Docker image follows security best practices:

- **Non-root user**: Runs as user `vak` (UID 1000)
- **Minimal base image**: `debian:bookworm-slim`
- **Dropped capabilities**: All Linux capabilities dropped
- **No privilege escalation**: `allowPrivilegeEscalation: false`
- **Multi-stage build**: Build tools not included in production image

### Pod Security Context

```yaml
podSecurityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  fsGroup: 1000

securityContext:
  readOnlyRootFilesystem: false    # Audit logs require write access
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

### Image Scanning

Include container image scanning in your CI/CD pipeline:

```bash
# Scan with Trivy
trivy image vak/kernel:1.0.0

# Scan with Grype
grype vak/kernel:1.0.0
```

---

## Network Security

### Network Policies

The Helm chart includes a NetworkPolicy that restricts traffic:

```yaml
networkPolicy:
  enabled: true
```

### Recommended Egress Rules

Restrict outbound traffic to only necessary services:

- LLM API endpoints (OpenAI, Anthropic, etc.)
- S3 endpoints (for audit log archival)
- DNS resolution

### Internal Communications

- Use mTLS between services if deploying alongside other microservices
- Keep VAK in a dedicated namespace with restricted access

---

## Secrets Management

VAK includes a pluggable secrets management system with support for:

- **Environment variables**: Simple but less secure
- **File-based secrets**: Mounted as volumes
- **Vault integration**: For production use

### Best Practices

1. Never store secrets in policy files, source code, or container images
2. Use Kubernetes Secrets with encryption at rest
3. Consider external secret operators (External Secrets Operator, Vault Agent)
4. Enable secret rotation where supported
5. The kernel's built-in `SecretScrubber` automatically redacts sensitive data from memory and logs

---

## Supply Chain Security

### Dependency Auditing

The CI pipeline includes comprehensive supply chain checks:

```bash
# Check for known vulnerabilities
cargo audit

# Verify license compliance
cargo deny check

# Check for unsafe code
cargo geiger --all-features

# Check dependency freshness
cargo outdated
```

### SBOM Generation

Generate a Software Bill of Materials for compliance:

```bash
# Using cargo-sbom
cargo sbom > sbom.json
```

### Build Reproducibility

Use the locked dependency versions in `Cargo.lock` for reproducible builds. The multi-stage Dockerfile ensures consistent build environments.

---

## Prompt Injection Protection

VAK's neuro-symbolic reasoner includes built-in prompt injection detection:

- **Multi-category analysis**: Detects direct injection, indirect injection, instruction override, and data exfiltration
- **Configurable thresholds**: Adjust sensitivity based on your risk tolerance
- **Integration with PRM**: Process Reward Model validates reasoning chains

### Best Practices

1. Always validate agent inputs before processing
2. Use the Policy Engine to restrict agent capabilities to minimum required
3. Enable the Constitution Protocol for immutable safety constraints
4. Monitor audit logs for suspicious patterns

---

## Rate Limiting and DoS Prevention

### Per-Agent Rate Limiting

```yaml
vak:
  security:
    enableRateLimiting: true
    maxRequestsPerMinute: 60
```

### Resource Limits

Prevent resource exhaustion with container resource limits:

```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: "2"
    memory: 2Gi
```

### WASM Execution Limits

```yaml
vak:
  maxExecutionTimeSecs: 30
  resources:
    maxMemoryMb: 256
```

---

## Compliance Considerations

### Audit Trail Requirements

VAK's hash-chained audit log supports compliance requirements for:

- **SOC 2**: Immutable audit trail with non-repudiation
- **GDPR**: Audit logs can track data access (pair with data classification policies)
- **HIPAA**: Access logging for all agent actions on protected data
- **PCI DSS**: Policy enforcement for financial data access

### Data Residency

For data residency requirements:

- Deploy VAK in the required region
- Use region-specific storage classes for audit logs
- Configure egress policies to prevent data leaving the region
- The multi-region audit replication module supports cross-region setups with controlled replication

---

## Security Checklist

### Pre-Deployment

- [ ] Default-deny policy configured
- [ ] All WASM skills signed with Ed25519 keys
- [ ] Strict skill signature verification enabled (no dev-mode opt-out)
- [ ] Rate limiting enabled
- [ ] Constitution Protocol active with appropriate safety principles
- [ ] Container runs as non-root user
- [ ] All Linux capabilities dropped
- [ ] Resource limits configured (CPU, memory)
- [ ] Network policies enabled
- [ ] Secrets stored in a secret management system (not env vars)

### Ongoing

- [ ] Audit chain integrity verified regularly
- [ ] Dependencies audited for vulnerabilities (`cargo audit`)
- [ ] Container images scanned for CVEs
- [ ] Audit logs backed up to external storage
- [ ] Access patterns reviewed for anomalies
- [ ] Policy rules reviewed and updated as needed
- [ ] Keys rotated on schedule

---

## Further Reading

- [Production Deployment Guide](production-deployment.md) -- Deployment procedures
- [Performance Tuning Guide](performance-tuning.md) -- Optimization
- [Troubleshooting Guide](troubleshooting.md) -- Common issues
- [Architecture Documentation](../ARCHITECTURE.md) -- Security architecture details
- [API Reference](../API.md) -- Security-related APIs
