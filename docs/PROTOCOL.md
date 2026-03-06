# Bridge - Protocol Specification

## Overview

Bridge uses three communication channels:

1. **Client <-> Control Plane:** HTTPS + mTLS for device registration, policy sync, posture reporting
2. **Client <-> Relay:** WireGuard (UDP) for encrypted traffic tunneling
3. **Relay <-> Control Plane:** HTTPS + mTLS for tunnel authorization and policy distribution

---

## 1. Device Registration & Authentication

### Initial Registration

```
Client                          Control Plane
  │                                   │
  │  1. Generate device keypair       │
  │     (Secure Enclave / TPM)        │
  │                                   │
  ├──── POST /api/v1/devices/register │
  │     {                             │
  │       public_key: "...",          │
  │       platform: "macos",         │
  │       os_version: "15.2",        │
  │       hardware_id: "...",        │
  │       enrollment_token: "..."    │
  │     }                            │
  │                                   │
  │◄─── 201 Created                   │
  │     {                             │
  │       device_id: "dev_...",      │
  │       device_certificate: "...", │
  │       ca_certificate: "...",     │
  │       control_plane_fingerprint  │
  │     }                            │
  │                                   │
  │  2. Store device cert in keychain │
  │     Configure mTLS for all       │
  │     future API calls             │
  │                                   │
```

### User Authentication (layered on top of device auth)

```
Client                          Control Plane              IdP (Okta/Azure AD/etc.)
  │                                   │                         │
  ├──── GET /api/v1/auth/sso          │                         │
  │     (mTLS with device cert)       │                         │
  │                                   │                         │
  │◄─── 302 Redirect to IdP ─────────┼────────────────────────►│
  │                                   │                         │
  │  (User authenticates with IdP)    │                         │
  │                                   │                         │
  │◄──────────────────────────────────┼──── OIDC callback ──────┤
  │                                   │     with id_token       │
  │                                   │                         │
  │◄─── 200 OK                        │
  │     {                             │
  │       session_token: "...",      │
  │       user_id: "usr_...",        │
  │       groups: ["engineering"],   │
  │       expires_at: "..."          │
  │     }                            │
```

---

## 2. Posture Reporting & Tiered Access

### Posture Report Structure

```json
{
  "device_id": "dev_abc123",
  "timestamp": "2026-03-05T10:30:00Z",
  "signature": "...",  // Signed with device hardware key

  "native_checks": {
    "os_version": "15.2",
    "disk_encryption": true,
    "firewall_enabled": true,
    "screen_lock_enabled": true,
    "jailbroken": false,
    "agent_integrity_hash": "sha256:..."
  },

  "osquery_results": {
    "unsigned_binaries": {
      "query": "SELECT path FROM signature WHERE signed = 0 AND path LIKE '/Applications/%'",
      "rows": [],
      "status": "pass"
    },
    "browser_extensions": {
      "query": "SELECT name, identifier FROM chrome_extensions",
      "rows": [
        {"name": "uBlock Origin", "identifier": "cjpalhdlnbpafiamejdnhcphjbkeiagm"}
      ],
      "status": "pass"
    },
    "listening_ports": {
      "query": "SELECT port, protocol, path FROM listening_ports WHERE port < 1024",
      "rows": [],
      "status": "pass"
    }
  }
}
```

### Posture-Based Tiered Access

The control plane evaluates posture reports against policies and assigns an **access tier** to each device. Different tiers grant access to different resource groups.

```
Posture Score Calculation:
  ┌─────────────────────────────────────────────┐
  │  Native Checks                              │
  │  ├── OS version current?          +20 pts   │
  │  ├── Disk encryption on?          +20 pts   │
  │  ├── Firewall enabled?            +15 pts   │
  │  ├── Screen lock enabled?         +10 pts   │
  │  └── Not jailbroken?              +15 pts   │
  │                                             │
  │  osquery Checks                             │
  │  ├── No unsigned apps?            +5 pts    │
  │  ├── No malicious extensions?     +5 pts    │
  │  ├── No unexpected listeners?     +5 pts    │
  │  └── Custom checks (configurable) +5 pts    │
  │                                    ────────  │
  │                              Total: 0-100   │
  └─────────────────────────────────────────────┘
```

### Access Tiers

```yaml
# Example tiered access policy
access_tiers:
  - name: "full_access"
    min_posture_score: 90
    allowed_resources:
      - "*.salesforce.com"       # CRM with customer data
      - "*.aws.amazon.com"       # Production infrastructure
      - "*.github.com"           # Source code
      - "*.slack.com"            # Communication
      - "*.jira.atlassian.com"   # Project management
      - "internal.*"             # All internal services

  - name: "standard_access"
    min_posture_score: 70
    allowed_resources:
      - "*.slack.com"            # Communication still works
      - "*.jira.atlassian.com"   # Can still manage tasks
      - "*.google.com"           # Workspace (email, docs)
      - "*.github.com"           # Source code (read-only enforced separately)
    blocked_resources:
      - "*.salesforce.com"       # No CRM access - customer data at risk
      - "*.aws.amazon.com"       # No prod access - device isn't secure enough

  - name: "restricted_access"
    min_posture_score: 40
    allowed_resources:
      - "*.slack.com"            # Can ask for help
      - "it-help.internal.com"   # Can access IT help desk
    blocked_resources:
      - "*"                      # Everything else blocked
    user_message: "Your device needs attention. Contact IT or update your OS."

  - name: "quarantined"
    min_posture_score: 0
    allowed_resources: []        # Nothing accessible
    user_message: "Your device has been quarantined. Contact security@company.com."
    admin_alert: true
```

### Posture-to-Tunnel Mapping

When posture changes, tunnels are dynamically reconfigured:

```
Client                          Control Plane                   Relay
  │                                   │                          │
  ├── POST /posture                   │                          │
  │   { score: 65, details: ... }     │                          │
  │                                   │                          │
  │   Control plane evaluates:        │                          │
  │   Score 65 = "standard_access"    │                          │
  │   Previously was "full_access"    │                          │
  │                                   │                          │
  │◄── 200 OK                         │                          │
  │   {                               │                          │
  │     tier: "standard_access",      │                          │
  │     tunnels: [                    │                          │
  │       { id: "tun_1",             │                          │
  │         status: "active",        │                          │
  │         allowed: ["*.slack.com"] │                          │
  │       },                          │                          │
  │       { id: "tun_2",             │                          │
  │         status: "revoked",       │── REVOKE tun_2 ────────►│
  │         reason: "posture_downgrade"│                         │
  │       }                           │                          │
  │     ],                            │                          │
  │     message: "OS update needed"   │                          │
  │   }                               │                          │
  │                                   │                          │
  │  Client tears down tun_2          │                          │
  │  Shows user notification          │                          │
  │  "Salesforce access restricted    │                          │
  │   until OS is updated"            │                          │
```

### osquery-Driven Posture Policies

Admins define posture checks as osquery queries in the policy DSL:

```yaml
posture_checks:
  - name: "os_up_to_date"
    weight: 20
    platform: [macos, windows]
    query: |
      SELECT CASE
        WHEN major >= 15 THEN 'pass'
        WHEN major = 14 AND minor >= 5 THEN 'pass'
        ELSE 'fail'
      END AS status
      FROM os_version
    expected: "pass"
    remediation: "Update your OS to macOS 15+ or 14.5+"

  - name: "no_unauthorized_remote_access"
    weight: 15
    platform: [macos]
    query: |
      SELECT name, path FROM launchd
      WHERE name LIKE '%vnc%' OR name LIKE '%teamviewer%' OR name LIKE '%anydesk%'
    expected_rows: 0
    remediation: "Remove unauthorized remote access software"

  - name: "disk_encryption_enabled"
    weight: 20
    platform: [macos]
    query: |
      SELECT de.encrypted FROM disk_encryption de
      JOIN mounts m ON de.name = m.device
      WHERE m.path = '/'
    expected: [{"encrypted": "1"}]

  - name: "no_known_vulnerable_software"
    weight: 10
    platform: [macos, windows]
    query: |
      SELECT name, version FROM programs
      WHERE (name = 'OpenSSL' AND version < '3.0.0')
         OR (name = 'log4j' AND version < '2.17.0')
    expected_rows: 0
    remediation: "Update vulnerable software detected on your device"

  - name: "approved_browser_extensions_only"
    weight: 5
    platform: [macos, windows]
    query: |
      SELECT ce.name, ce.identifier FROM chrome_extensions ce
      WHERE ce.identifier NOT IN (
        'cjpalhdlnbpafiamejdnhcphjbkeiagm',  -- uBlock
        'nkbihfbeogaeaoehlefnkodbefgpgknn'   -- MetaMask (if approved)
      )
      AND ce.from_webstore = '0'
    expected_rows: 0
    remediation: "Remove unapproved browser extensions"
```

---

## 3. Tunnel Management

### Tunnel Configuration

```
Client                          Control Plane
  │                                   │
  ├──── GET /api/v1/tunnels/config    │
  │     (mTLS + session token)        │
  │                                   │
  │◄─── 200 OK                        │
  │     {                             │
  │       tunnels: [                  │
  │         {                         │
  │           tunnel_id: "tun_...",   │
  │           relay_endpoint:         │
  │             "relay1.bridge.io:51820", │
  │           relay_public_key: "...",│
  │           client_private_key:     │
  │             "..." (encrypted),    │
  │           client_address:         │
  │             "10.0.1.42/32",      │
  │           dns: ["10.0.0.1"],     │
  │           allowed_ips:            │
  │             ["10.0.0.0/16"],     │
  │           app_filter: [           │
  │             "com.tinyspeck.slackmacgap", │
  │             "com.google.Chrome"   │
  │           ],                      │
  │           keepalive: 25,         │
  │           policy_hash: "sha256:..." │
  │         }                         │
  │       ],                          │
  │       policy_version: 42,        │
  │       next_sync: 300             │
  │     }                            │
```

### Tunnel Lifecycle

```
State Machine:

  ┌──────────┐    register    ┌──────────┐   posture OK   ┌──────────┐
  │  CREATED ├───────────────►│ PENDING  ├───────────────►│  ACTIVE  │
  └──────────┘                └──────────┘                └────┬─────┘
                                                              │
                              ┌──────────┐   posture fail  ┌──▼───────┐
                              │ REVOKED  │◄────────────────┤ DEGRADED │
                              └────┬─────┘                 └──────────┘
                                   │
                              ┌────▼─────┐
                              │ DELETED  │
                              └──────────┘

  ACTIVE:   Tunnel operational, full policy applied
  DEGRADED: Tunnel active but with restricted policy (posture score dropped)
  REVOKED:  Tunnel torn down by control plane (tamper, posture fail, admin action)
  DELETED:  Tunnel permanently removed (device deregistered)
```

---

## 4. Policy Sync

### Policy Distribution

Policies flow from Control Plane to both Client and Relay:

```
Control Plane
      │
      ├──► Client: "Route these apps through tunnel X, DNS filter rules, posture query schedule"
      │
      └──► Relay:  "Tunnel X allows *.slack.com, inspect TLS on *, DLP rules for uploads"
```

The client and relay each get a **different view** of the same policy - the client gets routing/app rules, the relay gets inspection/filtering rules. Neither gets the full picture.

### Policy Format

```json
{
  "version": 42,
  "hash": "sha256:...",
  "signature": "...",

  "client_policy": {
    "app_tunnel_map": {
      "com.tinyspeck.slackmacgap": "tun_slack",
      "com.google.Chrome": "tun_browser",
      "com.apple.Terminal": "tun_dev"
    },
    "dns_blocklists": ["malware", "ads", "tracking"],
    "dns_allowlists": ["*.company.com"],
    "split_tunnel_exclude": ["*.zoom.us"],
    "posture_check_interval": 300,
    "posture_queries": [ ... ]
  },

  "relay_policy": {
    "tun_slack": {
      "allowed_destinations": ["*.slack.com", "*.slack-edge.com"],
      "inspect_tls": false,
      "dlp_rules": ["block_file_upload_over_50mb"]
    },
    "tun_browser": {
      "allowed_destinations": ["*"],
      "inspect_tls": true,
      "tls_exclude": ["*.bank.com", "*.health.gov"],
      "dlp_rules": ["block_pii", "block_source_code", "shadow_copy_personal_uploads"],
      "shadow_copy": {
        "trigger": ["personal_account_upload", "unsanctioned_saas"],
        "storage": "s3://bridge-audit-org123"
      }
    }
  }
}
```

---

## 5. Heartbeat & Health

### Client Heartbeat

Every 30 seconds:

```json
POST /api/v1/devices/{id}/heartbeat
{
  "timestamp": "2026-03-05T10:30:00Z",
  "agent_integrity": "sha256:...",
  "active_tunnels": ["tun_slack", "tun_browser"],
  "posture_snapshot": { ... },
  "signature": "..."
}
```

### Control Plane Response

```json
{
  "status": "ok",
  "policy_version": 42,
  "policy_changed": false,
  "next_heartbeat": 30,
  "commands": []  // or: ["rotate_keys", "update_policy", "collect_diagnostics"]
}
```

---

## 6. Audit Events

### Event Types

```json
{
  "event_type": "dlp_violation",
  "tunnel_id": "tun_browser",
  "timestamp": "2026-03-05T10:31:00Z",
  "details": {
    "rule": "block_pii",
    "destination": "docs.google.com",
    "session_context": "personal_account",
    "pattern_matched": "credit_card",
    "action_taken": "blocked",
    "shadow_copy_id": "sc_xyz789"
  }
}
```

Events are sent from the relay to the control plane. The control plane correlates tunnel_id to device/user for the admin dashboard. This correlation requires explicit admin authorization and is itself audited.

---

## 7. Wire Format Summary

| Channel | Transport | Auth | Format |
|---|---|---|---|
| Client <-> Control Plane | HTTPS (TLS 1.3) | mTLS (device cert) + session token | JSON |
| Client <-> Relay | WireGuard (Noise protocol, UDP) | WireGuard keypair | Raw IP packets |
| Relay <-> Control Plane | HTTPS (TLS 1.3) | mTLS (relay cert) | JSON |
| Client daemon <-> UI | gRPC (localhost) | Unix socket permissions | Protobuf |
| Client <-> osquery | Thrift (localhost) | Unix socket permissions | Thrift |

---

## 8. Security Considerations

- **Forward secrecy:** WireGuard provides forward secrecy via Noise_IKpsk2. Control plane uses TLS 1.3 (forward secret by default).
- **Key rotation:** WireGuard keys rotate every 24h. Device certificates rotate every 90 days. Session tokens expire after 8h.
- **Replay protection:** WireGuard has built-in replay protection. API calls include monotonic timestamps + nonces.
- **Quantum readiness:** WireGuard's Noise protocol can be extended with post-quantum KEMs (e.g., Kyber) when standardized.
- **Supply chain:** All binaries are reproducibly built and signed. Update checks use certificate transparency logs.
