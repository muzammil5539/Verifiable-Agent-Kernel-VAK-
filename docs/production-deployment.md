# VAK Production Deployment Guide

> **Verifiable Agent Kernel (VAK) v1.0** -- Production Deployment Reference

---

## Table of Contents

- [Prerequisites](#prerequisites)
- [Deployment Options](#deployment-options)
  - [Docker Compose](#docker-compose)
  - [Kubernetes with Kustomize](#kubernetes-with-kustomize)
  - [Helm Chart](#helm-chart)
- [Configuration Reference](#configuration-reference)
  - [Environment Variables](#environment-variables)
  - [Helm Values](#helm-values)
- [Storage and Persistence](#storage-and-persistence)
- [Networking](#networking)
- [Scaling](#scaling)
- [Monitoring and Observability](#monitoring-and-observability)
- [Backup and Recovery](#backup-and-recovery)
- [Upgrade Procedures](#upgrade-procedures)
- [Production Checklist](#production-checklist)

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| Memory | 512 MB | 2 GB+ |
| Disk (audit logs) | 10 GB | 50 GB+ (depending on retention) |
| Docker | 24.0+ | Latest stable |
| Kubernetes | 1.27+ | 1.29+ |
| Helm | 3.12+ | 3.14+ |

---

## Deployment Options

### Docker Compose

The simplest way to deploy VAK for single-node production use.

```bash
# Build and start the production container
docker compose up -d vak

# Verify health
curl http://localhost:8080/health
```

**Production `docker-compose.yml` overrides:**

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  vak:
    build:
      context: .
      dockerfile: Dockerfile
      target: production
    ports:
      - "8080:8080"
    environment:
      - VAK_POLICY_PATH=/app/policies
      - VAK_AUDIT_PATH=/app/audit
      - VAK_SKILLS_PATH=/app/skills
      - VAK_LOG_LEVEL=info
      - RUST_LOG=vak=info
    volumes:
      - ./policies:/app/policies:ro
      - ./prompts:/app/prompts:ro
      - vak-audit:/app/audit
      - vak-data:/app/data
    restart: unless-stopped
    deploy:
      resources:
        limits:
          memory: 2G
          cpus: '2.0'
        reservations:
          memory: 512M
          cpus: '0.5'

volumes:
  vak-audit:
    driver: local
  vak-data:
    driver: local
```

```bash
# Deploy with production overrides
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### Kubernetes with Kustomize

For Kubernetes deployments using the base manifests:

```bash
# Review the manifests
ls k8s/base/

# Apply with kustomize
kubectl apply -k k8s/base/

# Verify deployment
kubectl get pods -l app=vak
kubectl get svc vak
```

**Manifests included in `k8s/base/`:**

| Manifest | Purpose |
|----------|---------|
| `namespace.yaml` | Dedicated `vak` namespace |
| `deployment.yaml` | Main deployment with resource limits |
| `service.yaml` | ClusterIP service on port 8080 |
| `hpa.yaml` | Horizontal Pod Autoscaler |
| `pdb.yaml` | Pod Disruption Budget (minAvailable: 1) |
| `networkpolicy.yaml` | Network isolation rules |
| `configmap.yaml` | Runtime configuration |
| `pvc.yaml` | Persistent storage for audit logs |
| `serviceaccount.yaml` | Dedicated service account |

**Creating environment-specific overlays:**

```bash
# Create a production overlay
mkdir -p k8s/overlays/production
```

```yaml
# k8s/overlays/production/kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
patchesStrategicMerge:
  - deployment-patch.yaml
```

```yaml
# k8s/overlays/production/deployment-patch.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vak
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: vak
          resources:
            requests:
              cpu: "1"
              memory: 1Gi
            limits:
              cpu: "4"
              memory: 4Gi
```

### Helm Chart

The recommended approach for production Kubernetes deployments.

```bash
# Install with default values
helm install vak helm/vak/ --namespace vak --create-namespace

# Install with custom values
helm install vak helm/vak/ \
  --namespace vak \
  --create-namespace \
  --values my-values.yaml

# Verify
helm status vak -n vak
kubectl get pods -n vak
```

**Example production `values.yaml`:**

```yaml
replicaCount: 3

image:
  repository: vak/kernel
  pullPolicy: IfNotPresent
  tag: "1.0.0"

resources:
  requests:
    cpu: "1"
    memory: 1Gi
  limits:
    cpu: "4"
    memory: 4Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

vak:
  logLevel: "info"
  maxConcurrentAgents: 50
  maxExecutionTimeSecs: 30
  security:
    enableSandboxing: true
    enableRateLimiting: true
    maxRequestsPerMinute: 120
  audit:
    enabled: true
  policy:
    enabled: true
    defaultDecision: "deny"

persistence:
  audit:
    enabled: true
    storageClass: "gp3"
    size: 50Gi

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: vak.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vak-tls
      hosts:
        - vak.example.com
```

---

## Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAK_POLICY_PATH` | `/app/policies` | Directory containing ABAC policy YAML files |
| `VAK_AUDIT_PATH` | `/app/audit` | Directory for hash-chained audit logs |
| `VAK_SKILLS_PATH` | `/app/skills` | Directory for WASM skill modules |
| `VAK_LOG_LEVEL` | `info` | Application log level (`trace`, `debug`, `info`, `warn`, `error`) |
| `RUST_LOG` | `vak=info` | Rust tracing filter directive |
| `VAK_MAX_CONCURRENT_AGENTS` | `10` | Maximum concurrent agent sessions |
| `VAK_MAX_EXECUTION_TIME_SECS` | `30` | Maximum WASM execution time per request |
| `VAK_RATE_LIMIT_RPM` | `60` | Maximum requests per minute per agent |

### Helm Values

See `helm/vak/values.yaml` for the complete list of configurable values with descriptions.

---

## Storage and Persistence

### Audit Log Storage

Audit logs are append-only, hash-chained records. They require persistent storage for production use.

**Docker volumes:**
```bash
# Create a named volume with a specific driver
docker volume create --driver local \
  --opt type=none \
  --opt device=/mnt/vak-audit \
  --opt o=bind \
  vak-audit-prod
```

**Kubernetes PVC:**
```yaml
persistence:
  audit:
    enabled: true
    storageClass: "gp3"          # Use appropriate storage class
    accessMode: ReadWriteOnce
    size: 50Gi                   # Size based on retention needs
```

### Storage Sizing Guidelines

| Agents | Requests/Day | Monthly Storage | Recommended Size |
|--------|-------------|-----------------|------------------|
| 1-10 | ~10,000 | ~500 MB | 10 Gi |
| 10-50 | ~100,000 | ~5 GB | 50 Gi |
| 50-200 | ~1,000,000 | ~50 GB | 200 Gi |

---

## Networking

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP | API, health checks, metrics |

### Network Policies

The Helm chart and Kustomize base include network policies that restrict pod-to-pod communication. In production, ensure:

- Ingress is only allowed from your API gateway or load balancer
- Egress is restricted to necessary external services (LLM APIs, S3 for audit archival)
- Inter-pod communication within the namespace is allowed for replicated deployments

### TLS Termination

TLS should be terminated at the ingress controller or load balancer level:

```yaml
# Helm ingress with TLS
ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
  tls:
    - secretName: vak-tls
      hosts:
        - vak.example.com
```

---

## Scaling

### Horizontal Scaling

VAK supports horizontal scaling via Kubernetes HPA:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80
```

### Pod Disruption Budget

Ensure availability during rolling updates:

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

### Resource Recommendations

| Workload | CPU Request | Memory Request | CPU Limit | Memory Limit |
|----------|-------------|----------------|-----------|--------------|
| Light (dev/staging) | 250m | 256Mi | 1 | 1Gi |
| Medium (production) | 500m | 512Mi | 2 | 2Gi |
| Heavy (high-throughput) | 1 | 1Gi | 4 | 4Gi |

---

## Monitoring and Observability

### Prometheus Metrics

VAK exposes Prometheus metrics at `/metrics` on port 8080.

**Key metrics:**

| Metric | Type | Description |
|--------|------|-------------|
| `vak_requests_total` | Counter | Total tool requests processed |
| `vak_policy_decisions_total` | Counter | Policy decisions by effect (allow/deny) |
| `vak_audit_entries_total` | Counter | Audit log entries created |
| `vak_wasm_execution_duration_seconds` | Histogram | WASM skill execution duration |
| `vak_active_agents` | Gauge | Currently active agent sessions |

**Prometheus scrape config:**

```yaml
# Automatically scraped via pod annotations
podAnnotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8080"
  prometheus.io/path: "/metrics"
```

### Health Checks

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Liveness probe -- returns 200 if the kernel is running |
| `GET /ready` | Readiness probe -- returns 200 when ready to accept traffic |

**Kubernetes probe configuration (included in Helm chart):**

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
```

### Logging

VAK uses structured JSON logging via the `tracing` crate. Configure log levels with:

```bash
# Application-level
VAK_LOG_LEVEL=info

# Fine-grained Rust tracing
RUST_LOG=vak=info,vak::audit=debug,vak::policy=warn
```

---

## Backup and Recovery

### Audit Log Backup

Audit logs are the most critical data to back up. They form a hash-chained, cryptographic trail.

```bash
# Docker: Copy audit volume
docker run --rm -v vak-audit:/data -v $(pwd)/backup:/backup \
  alpine tar czf /backup/vak-audit-$(date +%Y%m%d).tar.gz -C /data .

# Kubernetes: Create a snapshot
kubectl exec -n vak deploy/vak -- tar czf - /app/audit | \
  gzip > vak-audit-backup-$(date +%Y%m%d).tar.gz
```

### Recovery

```bash
# Docker: Restore from backup
docker run --rm -v vak-audit:/data -v $(pwd)/backup:/backup \
  alpine tar xzf /backup/vak-audit-20260213.tar.gz -C /data

# Verify chain integrity after recovery
# (use the audit chain verification API)
```

---

## Upgrade Procedures

### Rolling Update (Kubernetes)

```bash
# Update the image tag
helm upgrade vak helm/vak/ \
  --namespace vak \
  --set image.tag="1.0.1" \
  --wait

# Verify rollout
kubectl rollout status deployment/vak -n vak
```

### Rollback

```bash
# Helm rollback
helm rollback vak 1 -n vak

# Kubernetes rollback
kubectl rollout undo deployment/vak -n vak
```

---

## Production Checklist

Before going live, verify each item:

### Security
- [ ] TLS termination configured at ingress/load balancer
- [ ] Network policies enabled and reviewed
- [ ] Pod security context set (non-root user, read-only filesystem where possible)
- [ ] WASM sandboxing enabled (`vak.security.enableSandboxing: true`)
- [ ] Rate limiting enabled (`vak.security.enableRateLimiting: true`)
- [ ] Default-deny policy enforcement (`vak.policy.defaultDecision: deny`)
- [ ] All WASM skills signed with Ed25519 keys
- [ ] Secrets not stored in environment variables (use Kubernetes secrets or a vault)

### Reliability
- [ ] Minimum 2 replicas configured
- [ ] Pod Disruption Budget enabled
- [ ] Horizontal Pod Autoscaler configured
- [ ] Resource requests and limits set appropriately
- [ ] Health check endpoints verified (`/health`, `/ready`)
- [ ] Restart policy configured (`unless-stopped` or `Always`)

### Observability
- [ ] Prometheus scraping configured
- [ ] Log aggregation pipeline in place (e.g., Fluentd, Loki)
- [ ] Alerting rules defined for key metrics
- [ ] Audit log integrity verification scheduled

### Data
- [ ] Persistent storage provisioned for audit logs
- [ ] Backup strategy implemented and tested
- [ ] Storage sizing reviewed based on expected throughput
- [ ] Audit log archival/rotation configured

### Operations
- [ ] Runbook documented for common operational tasks
- [ ] Rollback procedure tested
- [ ] Load testing completed against production-like environment
- [ ] Upgrade procedure documented and tested

---

## Further Reading

- [Security Hardening Guide](security-hardening.md) -- Production security best practices
- [Performance Tuning Guide](performance-tuning.md) -- Optimization and profiling
- [Troubleshooting Guide](troubleshooting.md) -- Common issues and solutions
- [Migration Guide](migration-guide.md) -- Upgrading from v0.x to v1.0
- [Architecture Documentation](../ARCHITECTURE.md) -- System design and module reference
- [API Reference](../API.md) -- Complete API reference
