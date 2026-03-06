# Bridge - Infrastructure & Resilience

## Design Principles

1. **No single point of failure.** Every component has redundancy.
2. **Graceful degradation.** If a relay dies, clients seamlessly migrate. If the control plane is down, cached policies keep working.
3. **Zero-downtime deployments.** Rolling updates with automatic rollback.
4. **Geographic distribution.** Relays near users for low latency. Control plane replicated across regions.

---

## Architecture Overview

```
                        ┌─────────────────────────────────┐
                        │  Global Load Balancer (Anycast)  │
                        │  (Cloudflare / AWS Global Accel) │
                        └────────┬────────────────────────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
     ┌────────▼──────┐ ┌────────▼──────┐ ┌────────▼──────┐
     │  Region: US    │ │  Region: EU   │ │  Region: APAC │
     │                │ │               │ │               │
     │  ┌──────────┐  │ │ ┌──────────┐  │ │ ┌──────────┐  │
     │  │ Relay x3 │  │ │ │ Relay x3 │  │ │ │ Relay x3 │  │
     │  └──────────┘  │ │ └──────────┘  │ │ └──────────┘  │
     │                │ │               │ │               │
     │  ┌──────────┐  │ │ ┌──────────┐  │ │ ┌──────────┐  │
     │  │ CP Node  │  │ │ │ CP Node  │  │ │ │ CP Node  │  │
     │  │ (active) │  │ │ │ (active) │  │ │ │ (active) │  │
     │  └──────────┘  │ │ └──────────┘  │ │ └──────────┘  │
     │                │ │               │ │               │
     │  ┌──────────┐  │ │ ┌──────────┐  │ │ ┌──────────┐  │
     │  │ PG Primary│ │ │ │ PG Replica│ │ │ │ PG Replica│ │
     │  └──────────┘  │ │ └──────────┘  │ │ └──────────┘  │
     └────────────────┘ └───────────────┘ └───────────────┘
```

---

## Component: Bridge Relay (Data Plane)

### Relay Resilience

Relays are **stateless** - they receive tunnel config from the control plane and process packets. No local database, no persistent state. This makes them trivially replaceable.

**Redundancy model:**
```
Client connects to relay.bridge.io (Anycast IP)
        │
        ▼
  DNS returns multiple relay IPs (or Anycast routes to nearest)
        │
        ▼
  Client establishes WireGuard tunnel to Relay A
        │
        ├── Relay A healthy → traffic flows normally
        │
        └── Relay A dies →
              │
              ├── Client detects: WireGuard keepalive timeout (25s)
              ├── Client reconnects to relay.bridge.io
              ├── DNS/Anycast routes to Relay B (next nearest healthy relay)
              ├── New WireGuard handshake with Relay B (~100ms)
              ├── Relay B fetches tunnel policy from control plane
              └── Traffic resumes on Relay B
                  Total disruption: ~30 seconds
```

**How failover works:**

| Layer | Mechanism | Failover Time |
|---|---|---|
| DNS | Multiple A/AAAA records with health checks. Unhealthy relays removed from DNS within 30s. | 30-60s (DNS TTL) |
| Anycast | BGP anycast routes traffic to nearest healthy relay. Failed relay withdraws BGP route. | 5-15s (BGP convergence) |
| Client | WireGuard keepalive timer (25s). On timeout, client reconnects to DNS-resolved endpoint. | 25-30s |
| Load balancer | L4 health checks every 5s. Failed relay removed from pool after 3 consecutive failures (15s). | 15s |

**Recommended deployment:** Anycast for production (fastest failover). DNS round-robin for smaller deployments.

### Relay Horizontal Scaling

```
                    ┌─────────────────────────────┐
                    │  Kubernetes Cluster          │
                    │                              │
                    │  ┌────────┐ ┌────────┐      │
                    │  │Relay-0 │ │Relay-1 │ ...  │
                    │  └────────┘ └────────┘      │
                    │                              │
                    │  HPA (Horizontal Pod         │
                    │  Autoscaler):                │
                    │  - Scale on: active_tunnels  │
                    │  - Min: 3 pods               │
                    │  - Max: 50 pods              │
                    │  - Target: 5000 tunnels/pod  │
                    └─────────────────────────────┘
```

**Scaling metrics:**
- Each relay pod handles ~5,000 concurrent WireGuard tunnels
- Scale trigger: when average tunnels/pod exceeds 4,000 (80% capacity)
- Scale-down delay: 10 minutes (avoid flapping)
- Pod disruption budget: max 1 pod unavailable at a time (rolling updates)

**Key design:** New relay pods register with the control plane on startup. The control plane assigns new tunnels to the least-loaded relay. Existing tunnels are NOT migrated (they naturally rebalance as clients reconnect).

### Relay Health Checks

Each relay exposes:
```
GET /health           → 200 OK (basic liveness)
GET /health/ready     → 200 OK (ready to accept tunnels)
GET /health/deep      → 200 OK + JSON metrics (for monitoring)

{
  "status": "healthy",
  "active_tunnels": 3421,
  "capacity_percent": 68,
  "uptime_seconds": 86400,
  "last_policy_sync": "2026-03-05T10:30:00Z",
  "cpu_percent": 12,
  "memory_mb": 256,
  "packets_per_second": 150000
}
```

---

## Component: Bridge Control Plane

### Control Plane Resilience

The control plane is **stateful** (PostgreSQL database) and requires more careful failover design.

**Architecture:**

```
                    ┌──────────────────────────────┐
                    │  Load Balancer (L7)           │
                    │  (AWS ALB / GCP LB / nginx)   │
                    └──────────┬───────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐ ┌──────▼────────┐ ┌─────▼───────┐
     │  CP Node 1    │ │  CP Node 2    │ │  CP Node 3  │
     │  (Axum)       │ │  (Axum)       │ │  (Axum)     │
     │  Active       │ │  Active       │ │  Active     │
     └────────┬──────┘ └──────┬────────┘ └─────┬───────┘
              │                │                │
              └────────────────┼────────────────┘
                               │
                    ┌──────────▼───────────────┐
                    │  PostgreSQL (HA)          │
                    │                           │
                    │  Primary (writes)         │
                    │  ├── Sync replica (same AZ)│
                    │  └── Async replica (other) │
                    └───────────────────────────┘
```

**All CP nodes are active-active** (stateless Axum servers reading from PostgreSQL). Any node can handle any request. Load balancer distributes across healthy nodes.

### PostgreSQL High Availability

```
                    ┌───────────────────┐
                    │  PG Primary       │
                    │  (us-east-1a)     │
                    │  Writes + Reads   │
                    └────────┬──────────┘
                             │ streaming replication
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼─────┐ ┌─────▼──────┐ ┌────▼───────┐
     │ Sync Replica │ │ Async Rep  │ │ Async Rep  │
     │ (us-east-1b) │ │ (eu-west-1)│ │ (ap-se-1)  │
     │ Reads        │ │ Reads      │ │ Reads      │
     └──────────────┘ └────────────┘ └────────────┘
```

**Failover scenarios:**

| Scenario | What Happens | Recovery Time |
|---|---|---|
| CP node crash | LB detects failure (health check), routes to remaining nodes | 5-15s |
| PG primary crash | Patroni/pg_auto_failover promotes sync replica to primary | 10-30s |
| AZ failure | All traffic routes to other AZ's CP nodes + PG replica promoted | 30-60s |
| Region failure | DNS failover to other region's control plane + PG async replica promoted | 1-5 min |

**Tools:**
- **Patroni** or **pg_auto_failover** for PostgreSQL automatic failover
- **PgBouncer** for connection pooling (reduce PG connection overhead)
- **WAL-G** for continuous backup to S3/GCS (point-in-time recovery)

### Control Plane Offline Tolerance

**Critical design:** The client MUST continue working even if the control plane is completely down.

```
Control Plane Status     │  Client Behavior
─────────────────────────┼─────────────────────────────────────
Online                   │  Normal: policy sync, posture reports, heartbeats
Degraded (slow)          │  Increase heartbeat interval, batch uploads
Unreachable (< 1 hour)  │  Use cached policy, cached posture tier, tunnels stay active
Unreachable (> 1 hour)  │  Use cached policy, warn user, alert admin when back
Unreachable (> 24 hours) │  Configurable: keep tunnels active OR graceful shutdown
```

**What's cached on the client:**
- Last-known policy (signed by control plane, tamper-evident)
- WireGuard tunnel configurations (relay endpoints, keys)
- DNS blocklists (updated periodically)
- Posture check definitions (osquery queries)
- Access tier assignment
- Session token (with offline grace period)

**Cache invalidation:** When control plane comes back, client immediately syncs:
1. Check policy_version → if changed, fetch new policy
2. Submit queued posture reports and heartbeats
3. Upload any staged shadow copies
4. Re-validate session token

---

## Component: Audit Storage

### Shadow Copy & Log Storage Resilience

```
                    ┌────────────────────────────┐
                    │  Object Storage (S3/GCS)    │
                    │                              │
                    │  ┌─────────────────────────┐ │
                    │  │ Primary Region           │ │
                    │  │ bridge-audit-org123/     │ │
                    │  │  ├── shadow-copies/      │ │
                    │  │  ├── events/             │ │
                    │  │  └── posture-reports/    │ │
                    │  └───────────┬─────────────┘ │
                    │              │ CRR            │
                    │  ┌───────────▼─────────────┐ │
                    │  │ Backup Region            │ │
                    │  │ bridge-audit-org123-dr/  │ │
                    │  └─────────────────────────┘ │
                    └────────────────────────────┘
```

- **S3 Cross-Region Replication (CRR)** for automatic backup
- **S3 Versioning** enabled (protection against accidental deletion)
- **S3 Object Lock** in compliance mode (for legal hold / eDiscovery)
- **Lifecycle policies:** Hot (30 days) → IA (90 days) → Glacier (365 days) → delete

---

## Deployment Topologies

### Small (1-100 devices)

```
Single Region:
  - 2 relay pods (active-active behind LB)
  - 2 CP nodes (active-active behind LB)
  - 1 PG primary + 1 sync replica (same region)
  - S3 bucket for audit storage

Cost: ~$500/month (AWS/GCP)
```

### Medium (100-5,000 devices)

```
Two Regions:
  - 3 relay pods per region (6 total, autoscaling to 20)
  - 2 CP nodes per region (4 total)
  - PG primary in Region A, async replica in Region B
  - S3 with CRR between regions
  - Anycast or Geo-DNS for relay routing

Cost: ~$2,000-5,000/month
```

### Large (5,000-50,000 devices)

```
Three+ Regions:
  - 5-20 relay pods per region (autoscaling to 50)
  - 3 CP nodes per region
  - PG primary + sync replica in primary region
  - PG async replicas in all other regions
  - Anycast for relays
  - Geo-DNS for control plane
  - Dedicated audit storage per region (data sovereignty)

Cost: ~$10,000-30,000/month
```

### On-Premises

```
Customer Kubernetes Cluster:
  - Helm chart deploys: relay (3+ pods), CP (2+ pods), PG (operator-managed)
  - Customer provides: Kubernetes, object storage (MinIO for S3-compat), DNS
  - Bridge provides: container images, Helm chart, operator, runbooks
  - HA: same patterns as cloud, just on customer infra
```

---

## Disaster Recovery

### RPO/RTO Targets

| Component | RPO (max data loss) | RTO (max downtime) | Strategy |
|---|---|---|---|
| Relay | 0 (stateless) | 30s | Anycast failover + client reconnect |
| Control Plane API | 0 (PG sync replication) | 30s | Active-active + LB |
| PostgreSQL | 0 (sync replica) | 30s (auto-failover) | Patroni + sync replication |
| PostgreSQL (cross-region) | <1 min (async lag) | 5 min (manual promotion) | Async replica + WAL-G backups |
| Audit Storage | 0 (S3 durability) | 0 (always available) | S3 11-nines durability + CRR |
| Client functionality | N/A | 0 (cached policy) | Offline-capable design |

### Recovery Procedures

**Relay failure:**
1. Kubernetes restarts pod (automatic, ~10s)
2. New pod registers with control plane
3. Clients reconnect (WireGuard keepalive timeout → DNS re-resolve)
4. No data loss (relays are stateless)

**Control plane node failure:**
1. LB health check detects failure (5s)
2. Traffic routes to remaining nodes (automatic)
3. Kubernetes restarts failed pod
4. No data loss (all state in PostgreSQL)

**PostgreSQL primary failure:**
1. Patroni detects primary failure (10s)
2. Sync replica promoted to primary (automatic, ~5s)
3. CP nodes reconnect to new primary (PgBouncer handles transparently)
4. Old primary fenced (STONITH) to prevent split-brain
5. New sync replica provisioned from remaining async replicas

**Full region failure:**
1. DNS failover routes CP traffic to secondary region (1-5 min depending on TTL)
2. Async PG replica in secondary region promoted to primary (manual or automated decision)
3. Relay traffic routes via Anycast to next-nearest region (automatic, ~15s)
4. Potential data loss: up to PG async replication lag (typically <1 second)

---

## Monitoring & Alerting

### Key Metrics

| Metric | Warning | Critical | Source |
|---|---|---|---|
| Relay active tunnels | >80% capacity | >95% capacity | Relay /health/deep |
| Relay packet loss | >0.1% | >1% | Relay metrics |
| CP API latency (p99) | >200ms | >1s | LB metrics |
| CP error rate | >1% | >5% | LB metrics |
| PG replication lag | >100ms | >1s | PG metrics |
| PG connection pool | >80% used | >95% used | PgBouncer |
| Client heartbeat miss rate | >1% fleet | >5% fleet | CP metrics |
| Posture report queue depth | >1000 | >10000 | CP metrics |

### Observability Stack

```
Metrics:    Prometheus → Grafana (or Datadog/New Relic)
Logs:       Structured JSON → Loki (or Elasticsearch)
Traces:     OpenTelemetry → Jaeger (or Honeycomb)
Alerts:     Alertmanager → PagerDuty / Opsgenie
Uptime:     External probes (Pingdom / Better Uptime)
```

### Runbooks

Each alert has an associated runbook in the ops wiki:
- `relay-capacity-critical.md` - Scale up relay pods
- `pg-replication-lag.md` - Investigate network, check WAL sender
- `cp-error-rate.md` - Check logs, recent deployments, PG connectivity
- `region-failover.md` - Step-by-step region failover procedure

---

## Zero-Downtime Deployments

### Relay Deployment

```
Rolling update (Kubernetes):
  1. New relay pod starts with new version
  2. New pod passes health checks, joins relay pool
  3. Old pod marked for draining
  4. Existing tunnels on old pod: clients reconnect to new pod on next keepalive
  5. Old pod terminates after drain timeout (60s)
  6. Repeat for next pod (PDB: max 1 unavailable)
```

### Control Plane Deployment

```
Rolling update:
  1. New CP pod starts with new version
  2. New pod passes health checks, added to LB pool
  3. Old pod removed from LB pool (stops receiving new requests)
  4. Old pod finishes in-flight requests (graceful shutdown, 30s timeout)
  5. Old pod terminates
  6. Repeat for next pod
```

### Database Migrations

```
Forward-compatible migrations only:
  1. Add new columns/tables (backward compatible)
  2. Deploy new CP version that uses new schema
  3. Backfill data if needed
  4. In next release: drop old columns/tables

Never: rename columns, change types, drop used columns in the same release
```

---

## Security of Infrastructure

- **Network:** VPC with private subnets. Relays in public subnet (UDP ingress only). CP and PG in private subnet.
- **Secrets:** All secrets in AWS Secrets Manager / GCP Secret Manager / Vault. Never in environment variables or config files.
- **Access:** Zero standing access to production. Break-glass procedure for emergency access, fully audited.
- **TLS:** All internal communication over mTLS. No plaintext, even within VPC.
- **Encryption at rest:** PG encrypted (AWS RDS encryption). S3 server-side encryption (SSE-S3 or SSE-KMS).
- **Immutable infrastructure:** Container images are signed and immutable. No SSH to production pods.
