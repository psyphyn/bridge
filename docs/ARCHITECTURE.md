# Bridge - Technical Architecture

## System Overview

Bridge is a three-component system with a strict separation between data handling and identity management.

```
                         ┌─────────────────────┐
                         │   Bridge Control     │
                         │   Plane (API)        │
                         │                      │
                         │ - Auth & Identity    │
                         │ - Policy Engine      │
                         │ - Device Registry    │
                         │ - Admin Dashboard    │
                         │ - Audit Logs         │
                         └──────┬───────────────┘
                                │ policy sync
                    ┌───────────┼───────────────┐
                    │           │               │
              ┌─────▼─────┐    │         ┌─────▼─────┐
              │  Bridge    │   │         │  Bridge    │
              │  Client    │◄──┘         │  Relay     │
              │            │◄═══════════►│            │
              │ macOS/iOS  │  WireGuard  │ Data Plane │
              │ Android    │  Tunnels    │            │
              │ Windows    │             │ - Inspect  │
              └────────────┘             │ - DLP      │
                                         │ - Filter   │
                                         └────────────┘
```

**Key invariant:** The control plane handles identity and policy but never touches traffic. The relay handles traffic but never knows user identity - it only sees opaque tunnel IDs.

---

## Component 1: Bridge Client

The client runs on end-user devices. It consists of a **platform-native UI shell** and a **Rust core daemon** connected via gRPC IPC.

### Client Internal Architecture

```
┌──────────────────────────────────────────────────────┐
│  Platform UI Shell (Swift / Kotlin / C#)             │
│  - Connection status, settings, per-app visibility   │
└──────────────────┬───────────────────────────────────┘
                   │ gRPC IPC (localhost)
┌──────────────────▼───────────────────────────────────┐
│  Bridge Daemon (Rust)                                │
│                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ Tunnel Mgr  │  │ DNS Proxy    │  │ Posture    │  │
│  │ (boringtun) │  │ (filtering)  │  │ Agent      │  │
│  └──────┬──────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                │                │          │
│  ┌──────▼────────────────▼────────────────▼──────┐   │
│  │              Policy Engine                     │   │
│  │  - Per-app routing decisions                   │   │
│  │  - Posture-based access control                │   │
│  │  - Cached policy (works offline)               │   │
│  └────────────────────────────────────────────────┘   │
│                                                      │
│  ┌────────────────────────────────────────────────┐   │
│  │           Traffic Inspector                     │   │
│  │  - Selective TLS interception                   │   │
│  │  - Protocol detection (HTTP, DNS, etc.)         │   │
│  │  - Local DLP evaluation                         │   │
│  └────────────────────────────────────────────────┘   │
│                                                      │
│  ┌────────────────────────────────────────────────┐   │
│  │         Cryptographic Identity                  │   │
│  │  - Hardware-bound keys (TPM / Secure Enclave)   │   │
│  │  - Device attestation                           │   │
│  │  - Mutual TLS with control plane                │   │
│  └────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

### Per-App Micro-Tunnels

Traditional VPNs create one tunnel and route all traffic through it. Bridge creates **multiple WireGuard tunnels**, each with its own keypair and policy:

```
App A (Slack)     ──► Tunnel 1 ──► Relay (policy: allow *.slack.com, block file uploads > 10MB)
App B (Browser)   ──► Tunnel 2 ──► Relay (policy: block known malware domains, inspect TLS)
App C (Terminal)  ──► Tunnel 3 ──► Relay (policy: allow SSH to corp servers only)
App D (Personal)  ──► No tunnel   (split-tunnel: goes direct to internet)
```

**How per-app routing works by platform:**

| Platform | Mechanism |
|---|---|
| macOS | `NEPacketTunnelProvider` + `NEFilterDataProvider`. The Network Extension sees which app owns each flow via `NEFilterFlow.sourceAppIdentifier`. |
| iOS | `NEPacketTunnelProvider` with per-app VPN profiles (`NEVPNProtocol.appRules`). |
| Android | `VpnService.Builder.addAllowedApplication()` / `addDisallowedApplication()` per tunnel instance. |
| Windows | WFP (Windows Filtering Platform) callout driver associates flows with process IDs. `GetExtendedTcpTable` / `GetExtendedUdpTable` maps connections to PIDs. |
| ChromeOS | Android `VpnService` via ARC++ (Android runtime). Bridge's Android app runs natively on Chromebooks. Per-app filtering works for both Android and ChromeOS system apps. |
| Linux | `nftables` + cgroups for per-app routing. Or eBPF-based socket attribution. |

### ChromeOS / Chromebook Support

Chromebooks are supported via three tiers:

**Tier 1: Android App (Recommended)**
- Bridge's Android client runs on ChromeOS via ARC++ (Android Runtime for Chrome)
- `VpnService` API works on ChromeOS - routes ALL device traffic (not just Android apps) through Bridge
- Per-app filtering: `addAllowedApplication()` works for Android apps; system ChromeOS traffic routes through the default tunnel
- Deployed via Managed Google Play (Google Workspace admin console)
- Posture: ChromeOS device attributes available via Android APIs + `Build.VERSION`
- This is how Tailscale, Cloudflare WARP, and Zscaler all support Chromebooks today

**Tier 2: Chrome Extension (Browser-Only)**
- For managed Chromebooks where Android apps are disabled or for browser-only coverage
- Chrome extension uses `chrome.proxy` API to route browser traffic through Bridge relay via HTTPS CONNECT proxy
- Extension can inspect/filter web requests via `chrome.webRequest` API
- DLP for browser uploads (file inputs, drag-and-drop, paste events)
- Deployed silently via Google Workspace admin console (force-install extension)
- Limitations: browser traffic only, no system-level VPN, no per-app tunneling for non-browser apps

**Tier 3: Linux Container (Crostini)**
- For developer Chromebooks with Linux (Crostini) enabled
- Bridge Linux daemon runs inside the Linux VM
- WireGuard tunnel covers Linux container traffic
- Limitations: only covers traffic from the Linux VM, not ChromeOS or Android apps

**Recommended deployment:**
```
Managed Chromebook (Enterprise)
  ├── Android Bridge app (Tier 1) → Covers all traffic via VpnService
  └── Chrome Extension (Tier 2)   → Additional browser-level DLP and visibility

Unmanaged Chromebook (BYOD)
  └── Chrome Extension (Tier 2)   → Browser-only coverage via extension
```

### Local Traffic Inspection (Non-Tunneled Traffic)

Bridge can inspect ALL device traffic, not just traffic routed through WireGuard tunnels. This is critical for:
- Split-tunnel scenarios where some apps go direct to internet
- Monitoring personal app activity on managed devices
- DLP enforcement even when the relay is bypassed
- Detecting threats in traffic that doesn't need to be tunneled

```
                    ┌─────────────────────────────┐
                    │  All Device Traffic          │
                    └──────────┬──────────────────┘
                               │
                    ┌──────────▼──────────────────┐
                    │  Bridge Content Filter       │
                    │  (System Extension / WFP)    │
                    │                              │
                    │  Sees ALL packets regardless │
                    │  of tunnel routing           │
                    └──────────┬──────────────────┘
                               │
                 ┌─────────────┼─────────────────┐
                 │             │                 │
          ┌──────▼──────┐ ┌───▼────────┐  ┌─────▼─────┐
          │  Tunneled   │ │ Inspected  │  │  Direct   │
          │  (to relay) │ │  Locally   │  │ (passthru)│
          │             │ │            │  │           │
          │ Full relay  │ │ On-device  │  │ No inspect│
          │ inspection  │ │ DLP/filter │  │ (trusted) │
          └─────────────┘ └────────────┘  └───────────┘
```

**How it works per platform:**

| Platform | Mechanism | Scope |
|---|---|---|
| macOS | `NEFilterDataProvider` (Content Filter System Extension) | Sees all TCP/UDP flows with app attribution. Runs independently of VPN tunnel. |
| iOS | `NEFilterDataProvider` (Content Filter Network Extension) | Same as macOS. Apple requires MDM supervision for content filtering. |
| Windows | WFP (Windows Filtering Platform) callout driver | Kernel-level packet inspection. Sees all flows with PID attribution. |
| Android | `VpnService` in full-tunnel mode | All traffic routes through Bridge's TUN interface, even non-tunneled flows are visible for inspection. |

**Local inspection capabilities:**
- DNS query logging and filtering (all apps, not just tunneled ones)
- TLS fingerprinting (JA3/JA4) to detect unusual clients without decryption
- Destination reputation checking against local blocklists
- DLP pattern scanning on non-encrypted traffic (HTTP, FTP, SMTP)
- Upload detection and shadow copy for non-tunneled uploads
- Flow metadata collection for anomaly detection
- App-level bandwidth monitoring and throttling

**Policy example - inspect non-tunneled traffic:**
```yaml
local_inspection:
  enabled: true
  scope: "all_traffic"  # or "non_tunneled_only" or "specific_apps"

  dns_filtering:
    blocklists: ["malware", "phishing", "ads"]
    log_all_queries: true

  tls_fingerprinting:
    enabled: true
    alert_on_unknown_ja3: true

  upload_monitoring:
    inspect_non_tunneled: true
    shadow_copy_trigger: ["personal_cloud", "unsanctioned_saas"]

  flow_metadata:
    collect: true
    anomaly_detection: true
    report_to_control_plane: true
```

### Local DNS Proxy

The client runs a local DNS resolver on 127.0.0.1:53 that:

1. Intercepts all DNS queries from the device
2. Checks the query against policy (blocklists, allowlists)
3. Routes the query through the appropriate tunnel based on the requesting app
4. Caches responses with TTL awareness
5. Supports DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) to upstream resolvers
6. Detects DNS tunneling attempts (unusually long subdomains, high query entropy)

### Posture Agent

Continuously collects device health signals using a combination of native APIs and **osquery** for deep, SQL-queryable endpoint telemetry.

#### Native Posture Checks

| Signal | macOS | iOS | Android | Windows |
|---|---|---|---|---|
| OS version | `ProcessInfo.operatingSystemVersion` | Same | `Build.VERSION` | `RtlGetVersion` |
| Disk encryption | `fdesetup status` | Always on | `DevicePolicyManager` | `BitLocker WMI` |
| Firewall | `socketfilterfw --getglobalstate` | N/A | `iptables` | `netsh advfirewall` |
| Screen lock | `sysadminctl` | `LAContext` | `KeyguardManager` | `SystemParametersInfo` |
| Jailbreak/root | SIP check | File-based detection | `su` binary check, SafetyNet | N/A |
| Antivirus | N/A | N/A | N/A | `WSC_SECURITY_PROVIDER` |

#### osquery Integration

Bridge embeds osquery (Apache 2.0, cross-platform) as a posture data source on macOS, Windows, and Linux. This gives admins SQL-queryable access to hundreds of OS tables:

```sql
-- Example posture queries that Bridge runs continuously

-- Check for unauthorized browser extensions
SELECT * FROM chrome_extensions WHERE name NOT IN (SELECT name FROM policy_allowed_extensions);

-- Detect unsigned or tampered binaries
SELECT path, authority FROM signature WHERE signed = 0 AND path LIKE '/Applications/%';

-- Monitor listening ports for unexpected services
SELECT pid, port, protocol, path FROM listening_ports JOIN processes USING (pid);

-- Check for outdated software with known CVEs
SELECT name, version FROM programs WHERE name IN ('OpenSSL', 'curl', 'python3');

-- Detect USB storage devices
SELECT vendor, model, serial FROM usb_devices WHERE class = 'Mass Storage';
```

**How osquery fits in:**
- Bridge ships with a bundled osquery binary (no separate install needed)
- The Bridge daemon communicates with osquery via its Thrift API or extension socket
- Admins define "posture queries" in the policy DSL - these are osquery SQL statements
- Query results are evaluated against expected values to produce pass/fail posture signals
- Results are signed with the device key and sent to the control plane
- On mobile (iOS/Android), where osquery doesn't run, Bridge uses equivalent native APIs

**Why osquery over custom checks:**
- 300+ tables covering processes, users, hardware, network, browser state, certificates, etc.
- Battle-tested at scale (used by Meta, Kolide/Fleet, Uptycs)
- Admins can write custom queries without Bridge code changes
- Community-maintained table definitions stay current with OS updates
- Differential queries: only report changes, reducing bandwidth and noise

Posture is evaluated locally and sent as a signed attestation to the control plane. The relay never sees posture data directly - it only sees "this tunnel is authorized" or "this tunnel is revoked."

---

## Component 2: Bridge Relay (Data Plane)

The relay is a server-side component that terminates WireGuard tunnels and performs traffic inspection.

### Relay Architecture

```
┌──────────────────────────────────────────────────────┐
│  Bridge Relay                                        │
│                                                      │
│  ┌────────────────────────────────────────────────┐   │
│  │  WireGuard Endpoint (boringtun)                │   │
│  │  - Multi-tenant: thousands of tunnels          │   │
│  │  - Each tunnel has an opaque ID (no user info) │   │
│  └──────────────────┬─────────────────────────────┘   │
│                     │                                │
│  ┌──────────────────▼─────────────────────────────┐   │
│  │  Traffic Router                                │   │
│  │  - Reads tunnel-attached policy                │   │
│  │  - Routes to inspection pipeline or direct     │   │
│  │  - Enforces network-level ACLs                 │   │
│  └──────────────────┬─────────────────────────────┘   │
│                     │                                │
│  ┌──────────────────▼─────────────────────────────┐   │
│  │  Inspection Pipeline                           │   │
│  │                                                │   │
│  │  Stage 1: Protocol Detection                   │   │
│  │  - Identify HTTP, TLS, DNS, SSH, etc.          │   │
│  │                                                │   │
│  │  Stage 2: TLS Interception (if policy allows)  │   │
│  │  - Generate per-domain certificates on the fly │   │
│  │  - Respect certificate pinning lists           │   │
│  │                                                │   │
│  │  Stage 3: Content Analysis                     │   │
│  │  - DLP pattern matching (PII, secrets, etc.)   │   │
│  │  - Malware URL/hash checking                   │   │
│  │  - File type detection and policy              │   │
│  │                                                │   │
│  │  Stage 4: Metadata Analysis (no decryption)    │   │
│  │  - Flow size, timing, destination patterns     │   │
│  │  - Anomaly scoring via ML model                │   │
│  │  - C2 beacon pattern detection                 │   │
│  └──────────────────┬─────────────────────────────┘   │
│                     │                                │
│  ┌──────────────────▼─────────────────────────────┐   │
│  │  Egress                                        │   │
│  │  - Forward to destination (internet or corp)   │   │
│  │  - NAT with relay's IP                         │   │
│  │  - Log metadata (not content) for audit        │   │
│  └────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

### Split-Knowledge Privacy Model

The relay operates under strict constraints:

- **It knows:** Tunnel ID, traffic content (if inspecting), destination IPs
- **It does NOT know:** Which user or device owns the tunnel, why this policy was applied, posture state
- **Policy attachment:** The control plane sends "tunnel X gets policy Y" - the relay applies Y without knowing who X is
- **Audit logs:** The relay logs "tunnel abc123 sent 5MB to 1.2.3.4" - the control plane can correlate abc123 to a user, but only an authorized admin with access to BOTH systems can make that connection

This means a compromised relay cannot identify users, and a compromised control plane cannot see traffic.

### Inspection Engine Design (mitmproxy-Inspired)

The inspection engine follows mitmproxy's architecture but is implemented in Rust:

```
Connection Lifecycle:

  Client ──► [TCP Accept] ──► [Protocol Detect] ──► [TLS?] ──► [Intercept?] ──► [Parse] ──► [Rules] ──► [Forward]
                                     │                 │             │              │            │
                                     │                 │             │              │            │
                                   HTTP?             Yes/No    Yes: MITM CA     HTTP?      DLP/Block?
                                   DNS?                         No: passthru    DNS?        Allow?
                                   TLS?                                         Raw?        Log?
                                   Other?
```

Key concepts borrowed from mitmproxy:
- **Flows:** Each connection is a "flow" object with request/response lifecycle
- **Hooks:** Inspection rules can hook into `request`, `response`, `tcp_message`, `dns_query` events
- **Addons:** DLP, threat detection, logging are all "addons" that subscribe to flow events
- **Transparent mode:** The proxy is invisible to the client (works at the packet level via WireGuard)

---

## Component 3: Bridge Control Plane

### Control Plane Architecture

```
┌──────────────────────────────────────────────────────┐
│  Bridge Control Plane                                │
│                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────┐  │
│  │ Auth Service │  │ Policy       │  │ Device     │  │
│  │ - OIDC/SAML │  │ Engine       │  │ Registry   │  │
│  │ - API keys  │  │ - Rules DSL  │  │ - Posture  │  │
│  │ - mTLS      │  │ - Evaluation │  │ - Identity │  │
│  └──────┬──────┘  └──────┬───────┘  └─────┬──────┘  │
│         │                │                │          │
│  ┌──────▼────────────────▼────────────────▼──────┐   │
│  │                 Axum API Server                │   │
│  │                                                │   │
│  │  POST /api/v1/devices/register                 │   │
│  │  POST /api/v1/devices/{id}/attest              │   │
│  │  GET  /api/v1/tunnels/config                   │   │
│  │  POST /api/v1/tunnels/sync                     │   │
│  │  GET  /api/v1/policies                         │   │
│  │  POST /api/v1/policies                         │   │
│  │  GET  /api/v1/posture/{device_id}              │   │
│  │  POST /api/v1/events                           │   │
│  └────────────────────┬──────────────────────────┘   │
│                       │                              │
│  ┌────────────────────▼──────────────────────────┐   │
│  │              PostgreSQL                        │   │
│  │  - devices, users, policies, audit_events     │   │
│  │  - tunnel_assignments (tunnel_id <-> device)  │   │
│  │  - posture_reports                            │   │
│  └───────────────────────────────────────────────┘   │
│                                                      │
│  ┌───────────────────────────────────────────────┐   │
│  │         Admin Dashboard (Next.js)             │   │
│  │  - Device inventory & status                  │   │
│  │  - Policy editor                              │   │
│  │  - Audit log viewer                           │   │
│  │  - Threat/DLP event dashboard                 │   │
│  └───────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

### Identity, SSO & IdP Integration

Bridge integrates deeply with identity providers - not just consuming identity for auth, but **feeding posture signals back** so the IdP can make better access decisions across ALL apps, not just those behind Bridge.

#### Supported SSO Providers

| Provider | Protocol | User/Group Sync | Posture Signal Back | Notes |
|---|---|---|---|---|
| **Okta** | OIDC + SAML 2.0 | SCIM 2.0 | Okta Device Trust API + Shared Signals (SSF) | Primary integration target |
| **Azure AD / Entra ID** | OIDC + SAML 2.0 | Microsoft Graph API (SCIM) | Conditional Access external auth | Intune compliance signal |
| **Google Workspace** | OIDC | Google Directory API | Context-Aware Access API | BeyondCorp integration |
| **Ping Identity** | OIDC + SAML 2.0 | SCIM 2.0 | PingOne Risk API | |
| **OneLogin** | OIDC + SAML 2.0 | SCIM 2.0 | Webhooks | |
| **JumpCloud** | OIDC + SAML 2.0 | JumpCloud Directory API | Device Trust API | |
| **Custom / Self-Hosted** | OIDC (any provider) | SCIM 2.0 or LDAP | Webhook / API callback | Keycloak, Authentik, etc. |

#### SSO Authentication Flow

```
User opens Bridge (or Bridge auto-starts via MDM)
     │
     ▼
Bridge daemon checks for existing session
     │
     ├── Valid session? → Skip auth, resume tunnels
     │
     └── No session? → Trigger SSO
           │
           ▼
     Open system browser to Bridge control plane /auth/sso
           │
           ▼
     Control plane redirects to IdP (Okta, Azure AD, etc.)
           │
           ▼
     User authenticates with IdP (MFA, passwordless, etc.)
           │
           ▼
     IdP returns OIDC id_token + access_token to control plane
           │
           ▼
     Control plane extracts: user_id, email, groups, roles
           │
           ▼
     Control plane returns Bridge session to daemon
     {
       user_id: "usr_...",
       email: "will@company.com",
       groups: ["engineering", "platform-team"],
       roles: ["developer"],
       session_expires: "2026-03-05T18:00:00Z",
       refresh_token: "..."
     }
           │
           ▼
     Daemon stores session in OS keychain (encrypted)
     Tunnels established based on group policies
```

**Key auth properties:**
- SSO is the ONLY way to authenticate users (no local passwords)
- Device cert (mTLS) + SSO token required together (device AND user identity)
- Session refresh happens silently via refresh tokens (no re-auth interruption)
- MFA is delegated entirely to the IdP (Bridge never handles MFA directly)
- On mobile: uses ASWebAuthenticationSession (iOS) / Chrome Custom Tab (Android) for secure SSO

#### User Groups & Conditional Policies

Groups are synced from the IdP and used as the primary policy targeting mechanism:

```yaml
# Groups synced from Okta via SCIM
groups:
  - id: "grp_eng"
    name: "engineering"
    source: "okta"
    members: 45

  - id: "grp_sales"
    name: "sales"
    source: "okta"
    members: 120

  - id: "grp_exec"
    name: "executives"
    source: "okta"
    members: 8

  - id: "grp_contractors"
    name: "contractors"
    source: "okta"
    members: 30
```

**Conditional policy engine** - policies can target combinations of user properties, group membership, device attributes, and environmental context:

```yaml
# Policy: Engineering team - full access with DLP
name: "engineering-full-access"
conditions:
  match_all:
    - group: "engineering"
    - device_type: ["macos", "linux"]
    - posture_tier: ["full_access", "standard_access"]
rules:
  - allow: ["*.github.com", "*.aws.amazon.com", "internal.*"]
  - inspect_tls: ["*"]
  - dlp: ["block_source_code_to_personal"]

---
# Policy: Contractors - restricted, heavy monitoring
name: "contractor-restricted"
conditions:
  match_all:
    - group: "contractors"
  match_any:
    - device_managed: false          # BYOD
    - posture_tier: "restricted"
rules:
  - allow: ["*.slack.com", "*.jira.atlassian.com"]
  - block: ["*.github.com", "internal.*"]     # No source code, no internal tools
  - shadow_copy: all_uploads
  - inspect_tls: ["*"]

---
# Policy: Executives on travel - extra protection
name: "exec-travel-mode"
conditions:
  match_all:
    - group: "executives"
    - network_type: "untrusted"       # Not corporate WiFi
    - country_not: ["US", "AU"]       # Outside home countries
rules:
  - tunnel_all_traffic: true          # No split tunnel
  - inspect_tls: ["*"]
  - block: ["*.wetransfer.com", "*.mega.nz"]
  - alert_on: ["unusual_login_location"]

---
# Policy: User-level override (specific person)
name: "cfo-salesforce-readonly"
conditions:
  match_all:
    - user_email: "cfo@company.com"
    - app: "*.salesforce.com"
    - time_outside: "09:00-18:00 AEST"  # After hours
rules:
  - allow: ["*.salesforce.com"]
  - block_action: ["export", "download", "print"]  # Read-only after hours
  - shadow_copy: all_downloads
```

**Condition properties available for policy targeting:**

| Property | Source | Examples |
|---|---|---|
| `group` | IdP (SCIM sync) | "engineering", "sales", "contractors" |
| `role` | IdP (OIDC claims) | "admin", "developer", "viewer" |
| `user_email` | IdP | "will@company.com" |
| `department` | IdP (SCIM attribute) | "Engineering", "Finance" |
| `device_type` | Bridge agent | "macos", "ios", "windows", "chromeos" |
| `device_managed` | Bridge agent | true (MDM-enrolled) / false (BYOD) |
| `posture_tier` | Bridge posture engine | "full_access", "standard", "restricted" |
| `posture_score` | Bridge posture engine | 0-100 numeric |
| `network_type` | Bridge agent | "corporate", "home", "untrusted", "cellular" |
| `country` | GeoIP of client IP | "US", "AU", "DE" |
| `time` | Current time in user's timezone | Time ranges, business hours |
| `app` | Per-app tunnel attribution | Bundle ID or domain |
| `os_version` | Bridge agent / osquery | "15.2", "14.5" |
| `custom_osquery` | osquery result | Any boolean from a custom query |

#### Bidirectional Posture Signaling (Bridge → IdP)

This is where Bridge goes beyond competitors. Bridge doesn't just consume identity from Okta - it **feeds device posture back to Okta** so that Okta's own access policies (for apps NOT behind Bridge) can use Bridge's posture data.

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  Bridge      │ posture │  Okta /      │ access  │  SaaS Apps   │
│  Agent       ├────────►│  Azure AD    ├────────►│  (all of them)│
│              │ signal  │              │ decision│              │
│  "Device is  │         │  "Bridge says│         │  Salesforce  │
│   healthy,   │         │   device is  │         │  Workday     │
│   score: 95" │         │   compliant" │         │  GitHub      │
└──────────────┘         └──────────────┘         └──────────────┘

Without Bridge signal:  Okta can only check "is user authenticated?"
With Bridge signal:     Okta can check "is user authenticated AND is device healthy?"
```

**How it works with Okta specifically:**

1. **Okta Device Trust / Device Assurance API**
   - Bridge registers as a device management signal provider
   - When a device's posture changes, Bridge pushes the update to Okta via the Device Assurance API
   - Okta admins create Device Assurance Policies that require Bridge posture signals
   - If Bridge reports "device unhealthy", Okta blocks the user from ALL Okta-protected apps (not just Bridge-tunneled ones)

2. **Shared Signals Framework (SSF/CAEP)**
   - OpenID Foundation standard for continuous access evaluation
   - Bridge implements the SSF Transmitter role
   - Sends CAEP events: `device-compliance-change`, `session-revoked`, `credential-compromise`
   - Okta (or any SSF Receiver) consumes these events in real-time
   - Enables: "Bridge detected malware → Okta revokes all sessions in <30 seconds"

3. **SCEP/SCIM Bidirectional Sync**
   - Bridge syncs user/group data FROM Okta (SCIM provisioning)
   - Bridge syncs posture/compliance data TO Okta (Device Trust API)
   - Two-way: Okta can also push "user deactivated" → Bridge revokes all tunnels

```
Bridge Control Plane                    Okta
       │                                  │
       │  ◄── SCIM Provisioning ────────  │  (users, groups → Bridge)
       │                                  │
       │  ──► Device Assurance API ────►  │  (posture score → Okta)
       │                                  │
       │  ──► SSF/CAEP Events ─────────►  │  (real-time security events)
       │                                  │
       │  ◄── SSF/CAEP Events ─────────  │  (user deactivated, MFA reset)
       │                                  │
```

**Posture signals sent to IdP:**

```json
// Signal sent to Okta Device Assurance API
{
  "device_id": "dev_abc123",
  "platform": "macos",
  "os_version": "15.2",
  "compliant": true,
  "posture_score": 95,
  "signals": {
    "disk_encryption": true,
    "firewall_enabled": true,
    "os_up_to_date": true,
    "screen_lock": true,
    "agent_healthy": true,
    "no_malware_detected": true,
    "last_posture_check": "2026-03-05T10:30:00Z"
  }
}

// CAEP event when posture degrades
{
  "type": "device-compliance-change",
  "subject": { "device_id": "dev_abc123", "user": "will@company.com" },
  "previous_status": "compliant",
  "current_status": "non-compliant",
  "reason": "os_outdated",
  "timestamp": "2026-03-05T10:31:00Z"
}
```

**Why this matters:**
- Without Bridge: Okta protects apps at login time only. Once logged in, a compromised device has access until the session expires.
- With Bridge: Okta can enforce continuous device compliance across ALL apps. Bridge detects the problem → signals Okta → Okta revokes sessions everywhere → all apps are protected, even ones not behind Bridge's tunnel.

**Azure AD / Entra ID equivalent:**
- Bridge registers as a Compliance Partner via Microsoft Graph API
- Pushes device compliance state to Intune compliance policies
- Azure AD Conditional Access policies can require "Bridge reports compliant"
- Works alongside Intune (Bridge handles posture, Intune handles MDM)

**Google Workspace equivalent:**
- Bridge integrates with Context-Aware Access via the BeyondCorp Enterprise API
- Pushes device signals as custom access levels
- Google Workspace admins can require Bridge compliance for Gmail, Drive, etc.

### Policy DSL

Policies are defined in a declarative format:

```yaml
# Example policy
name: "engineering-browser-policy"
applies_to:
  groups: ["engineering"]
  apps: ["com.google.Chrome", "org.mozilla.firefox"]

rules:
  - action: allow
    destinations: ["*.github.com", "*.stackoverflow.com", "*.docs.rs"]

  - action: inspect_tls
    destinations: ["*"]
    exclude: ["*.bank.com", "*.health.gov"]  # Never inspect sensitive sites

  - action: block
    conditions:
      - dlp_match: ["credit_card", "ssn", "api_key"]
      - direction: egress
    alert: high

  - action: block
    destinations_from: "threat_feed:malware_domains"
    alert: critical

  - action: allow
    destinations: ["*"]  # Default allow for everything else

posture_requirements:
  min_os_version: "14.0"
  disk_encryption: required
  firewall: enabled
  max_posture_age: 300  # Re-evaluate posture every 5 minutes
```

### Tunnel Assignment Flow

```
1. Client boots → generates hardware-bound keypair (Secure Enclave / TPM)
2. Client → Control Plane: POST /devices/register { public_key, platform, os_version }
3. Control Plane: creates device record, evaluates initial posture
4. Client → Control Plane: POST /devices/{id}/attest { posture_report, signature }
5. Control Plane: validates attestation, determines which apps need tunnels
6. Control Plane → Client: { tunnels: [{ id, wg_config, relay_endpoint, policy_hash }] }
7. Client: establishes WireGuard tunnels to relay(s)
8. Control Plane → Relay: { tunnel_id: "abc123", policy: { ... } }  (no user identity)
9. Client periodically re-attests posture; control plane can revoke/modify tunnels
```

---

## Cryptographic Identity

### Device Identity Chain

```
Hardware Root of Trust (TPM/Secure Enclave)
    │
    ├── Device Key (asymmetric, never leaves hardware)
    │       │
    │       ├── Device Certificate (signed by Bridge CA at registration)
    │       │       │
    │       │       └── Used for mTLS with control plane
    │       │
    │       └── Attestation Signatures (posture reports)
    │
    └── WireGuard Keys (per-tunnel, derived/rotated frequently)
            │
            └── Tunnel-specific keypairs (rotated every 24h or on policy change)
```

### Key Properties
- **Hardware binding:** The device key is generated inside the Secure Enclave (Apple) or TPM 2.0 (Windows/Android). It cannot be exported.
- **Stolen credentials aren't enough:** Even with a user's password + MFA, an attacker can't impersonate the device without the hardware key.
- **Key rotation:** WireGuard tunnel keys rotate automatically. Compromise of one tunnel key doesn't affect others.
- **Attestation:** Posture reports are signed with the device key, preventing spoofing.

---

## Traffic Inspection Architecture

### Selective TLS Inspection

Bridge does NOT blindly MITM all traffic. The inspection is:

1. **Policy-driven:** Admin configures which domains/apps get inspected
2. **Pinning-aware:** If an app uses certificate pinning, Bridge detects it and bypasses inspection (rather than breaking the app)
3. **Consent-transparent:** Users see which apps are being inspected in the Bridge client UI
4. **Exclusion lists:** Sensitive categories (banking, health) can be permanently excluded

### Certificate Management

```
Bridge Root CA (generated per organization)
    │
    ├── Inspection Sub-CA (deployed to managed devices)
    │       │
    │       └── Per-domain ephemeral certs (generated on the fly)
    │           e.g., *.example.com cert valid for 24h
    │
    └── Control Plane mTLS CA
            │
            └── Device certificates (one per registered device)
```

The Root CA is generated during org setup. The Sub-CA is installed on managed devices via MDM (macOS/iOS) or device admin (Android) or Group Policy (Windows).

### DLP Engine

The DLP engine runs as an inspection pipeline addon with **session-aware, identity-aware, and upload-aware** capabilities.

#### Pattern Detection

| Pattern | Detection Method | Action |
|---|---|---|
| Credit card numbers | Luhn-validated regex | Block + alert |
| SSN / Tax IDs | Format regex + context analysis | Block + alert |
| API keys / secrets | Entropy analysis + known formats (AWS, GitHub, etc.) | Block + alert |
| Source code | File extension + language detection | Warn or block |
| PII (names, emails, phones) | NER model + regex | Configurable |
| Custom patterns | Admin-defined regex/keywords | Configurable |

#### Session & Identity Awareness

Bridge correlates traffic inspection with user identity context to answer **who** is doing **what**:

- **SaaS session detection:** When TLS inspection is active, Bridge extracts session tokens and OAuth claims from HTTP traffic to determine which user account is logged into which SaaS app (Google Workspace, Slack, Salesforce, etc.)
- **Personal vs. corporate account detection:** Distinguish between a user logged into their corporate Google account vs. their personal Gmail - apply different DLP policies to each
- **Shadow IT detection:** Identify when users are logged into unsanctioned SaaS apps and alert or block
- **Session anomalies:** Detect impossible travel (same account active from two locations), session hijacking (token reuse from different device fingerprints), or privilege escalation

```yaml
# Example: identity-aware DLP policy
name: "salesforce-dlp"
rules:
  - action: inspect_session
    app_domains: ["*.salesforce.com", "*.force.com"]
    extract: ["user_email", "org_id", "role"]

  - action: block
    conditions:
      - logged_in_as: "personal_account"    # Not a corporate account
      - destination: "*.salesforce.com"
    message: "Personal accounts cannot access corporate Salesforce"

  - action: alert
    conditions:
      - logged_in_as: "*@company.com"
      - uploading_to: ["*.dropbox.com", "*.wetransfer.com", "drive.google.com"]
      - file_contains: ["confidential", "internal only"]
    severity: high
```

#### Upload Monitoring & Control

Bridge inspects file uploads across all protocols with content-aware policies:

| Upload Vector | Detection Method | Capabilities |
|---|---|---|
| HTTP multipart uploads | Parse `multipart/form-data` boundaries | File type, size, content scanning |
| HTTP PUT/POST body | Content-Type + magic byte detection | Block by type, scan for DLP patterns |
| WebSocket binary frames | Frame inspection | Detect file transfers over WebSocket |
| Cloud storage APIs | API-specific parsers (S3, GCS, Azure Blob) | Intercept SDK uploads |
| Email attachments (SMTP/API) | SMTP inspection or API-level (Gmail, O365 API) | Scan attachments before send |
| Clipboard/paste | Browser paste events (via TLS inspection of web apps) | Detect bulk paste of sensitive data |

**Upload policy examples:**
- Block uploads of `.zip`, `.7z` files larger than 50MB to any non-corporate domain
- Alert when source code files (`.py`, `.rs`, `.ts`) are uploaded to personal cloud storage
- Block any upload containing credit card numbers or SSNs
- Allow uploads to sanctioned apps (company Slack, Jira) but block to personal accounts on the same platform
- Quarantine suspicious uploads for admin review before delivery

#### Shadow Copy & Audit Trail

When a user uploads content to an unsanctioned or personal service, Bridge can **seamlessly capture a copy** of the uploaded data without disrupting the user's workflow:

```
User uploads file to personal Google Docs
        │
        ▼
  Bridge TLS Inspection intercepts the upload
        │
        ├──► File continues to Google Docs (user experience unchanged)
        │
        └──► Shadow copy is:
             1. Stored in encrypted audit storage (S3-compatible, customer-controlled)
             2. Tagged with metadata: timestamp, user identity, destination, app, device
             3. DLP-scanned asynchronously for sensitive content
             4. Admin alerted if policy violations detected
             5. Available for forensic review in the admin dashboard
```

**How it works technically:**
- During TLS inspection, Bridge reconstructs the full HTTP request including multipart file data
- The inspection pipeline forks the upload stream: one copy goes to the destination, one to audit storage
- The shadow copy happens inline (zero added latency to the user) - the data is buffered and written to audit storage asynchronously
- For large files, Bridge streams the copy rather than buffering the entire file in memory
- Copies are encrypted at rest with a key managed by the customer (not Bridge)

**Policy controls:**
```yaml
shadow_copy:
  enabled: true
  trigger:
    - destination_type: "personal_account"    # Personal Google, Dropbox, etc.
    - destination_type: "unsanctioned_saas"   # Apps not in the approved list
    - dlp_match: ["confidential", "pii"]      # Any upload with sensitive content
  storage:
    backend: "s3"
    bucket: "bridge-audit-{org_id}"
    encryption: "aes-256-gcm"
    retention_days: 90
  notification:
    admin_alert: true
    user_notify: false  # Configurable: some orgs want users to know
```

**Privacy & compliance considerations:**
- Shadow copy is opt-in per policy, not default behavior
- Customer controls storage location (data sovereignty)
- Retention policies are configurable and auto-enforced
- Access to shadow copies requires admin + auditor role (dual authorization)
- All access to shadow copies is itself logged (audit of audits)
- For regulated industries: meets requirements for eDiscovery and litigation hold

### Anomaly Detection (Metadata-Only)

For traffic that is NOT TLS-inspected, Bridge can still detect threats using metadata:

- **Flow timing:** Regular beacon intervals suggest C2 communication
- **Payload sizes:** Unusual upload volumes suggest data exfiltration
- **Destination reputation:** IP/domain reputation scoring
- **DNS patterns:** High entropy subdomains suggest DNS tunneling
- **Protocol anomalies:** TLS fingerprinting (JA3/JA4) to detect unusual clients
- **Connection graphs:** Unusual destination patterns for a given app

This runs as a lightweight ML model (ONNX runtime) on both client and relay.

---

## Performance Engineering

### Target Resource Budgets

Bridge must be invisible to the user. These are hard performance ceilings, not aspirational goals:

| Resource | Budget | Comparable To |
|---|---|---|
| Idle CPU | < 0.5% | CrowdStrike Falcon sensor (~0.3%), Tailscale (~0.1%) |
| Active CPU (during inspection) | < 3% | Cloudflare WARP under load (~2%), Zscaler (~3%) |
| Memory (RSS) | < 50 MB | Tailscale (~30MB), CrowdStrike (~45MB), Falcon Go agent |
| Disk (installed) | < 100 MB | Including bundled osquery (~25MB) and ML models (~10MB) |
| Battery impact (mobile) | < 2% per day | Comparable to Tailscale/WARP on iOS |
| Tunnel latency overhead | < 2ms | WireGuard itself adds ~0.5ms; inspection adds ~1ms |
| Bandwidth overhead | < 1% | Heartbeats, posture reports, policy sync - not user traffic |

### What Major Companies Do (And What We Steal)

**CrowdStrike Falcon:**
- Tiny kernel sensor (~45MB RSS) does event capture only
- ALL analysis happens cloud-side - the agent is a dumb forwarder
- Uses ring buffers for event collection - never blocks the kernel
- Key lesson: **Move heavy processing off-device. The agent captures and forwards.**

**Tailscale:**
- Written in Go, ~30MB RSS
- Uses kernel WireGuard (`wireguard-go` → kernel module) when available, falls back to userspace
- Control plane is polling-based (DERP), not persistent WebSocket - saves battery
- Key lesson: **Use kernel offloading when possible. Poll, don't push.**

**Cloudflare WARP (1.1.1.1):**
- Uses BoringTun (same Rust WireGuard we're using)
- Minimal inspection on-device - routing decisions are simple and fast
- DNS filtering happens at resolver, not in the agent
- Key lesson: **Keep the fast path fast. Only inspect what policy requires.**

**Zscaler ZPA / ZIA:**
- Lightweight tunnel forwarder on device
- All DLP, threat detection, sandboxing happens in Zscaler's cloud
- Device sends traffic to nearest Zscaler edge node
- Key lesson: **The relay should do the heavy lifting, not the client.**

**SentinelOne:**
- On-device ML models are quantized (INT8) and tiny (<5MB)
- Uses event-driven architecture - only wakes on relevant system events
- Batches telemetry uploads to reduce network calls
- Key lesson: **Quantize ML models. Batch uploads. Event-driven, not polling.**

**Apple Endpoint Security Framework (used by Jamf Protect):**
- OS provides efficient event streams - no polling
- Mach message-based IPC (zero-copy)
- Framework handles deduplication and rate limiting
- Key lesson: **Use OS-native event APIs, not polling or raw packet capture.**

### Shadow Copy: Local Staging + Async Upload

Shadow copies are the heaviest operation Bridge performs. Here's how we keep them lightweight:

```
Upload Detected
      │
      ▼
┌─────────────────────────────────────────────────┐
│  Stage 1: Inline Capture (zero added latency)   │
│                                                  │
│  - Fork the upload stream using io::copy + tee  │
│  - Write to memory-mapped temp file (mmap)      │
│  - If file < 1MB: keep in memory ring buffer    │
│  - If file > 1MB: spill to tmpdir immediately   │
│  - User's upload continues unimpeded             │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│  Stage 2: Local Staging                          │
│                                                  │
│  - Compress with zstd (level 3: fast, ~3:1)     │
│  - Encrypt with AES-256-GCM (org key)           │
│  - Write to staging directory:                   │
│    ~/Library/Caches/Bridge/staging/              │
│    (or %TEMP%\Bridge\staging\ on Windows)        │
│  - Staging budget: max 500MB, LRU eviction       │
│  - Each staged file tagged with metadata JSON    │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│  Stage 3: Smart Upload Queue                     │
│                                                  │
│  Upload scheduler considers:                     │
│  - Network type: WiFi preferred over cellular    │
│  - Bandwidth utilization: upload when < 50% used │
│  - Battery state: defer on low battery (< 20%)   │
│  - Time of day: prefer off-peak hours            │
│  - Priority: DLP-flagged files upload first      │
│  - Power state: plugged in = upload immediately  │
│                                                  │
│  Upload method:                                  │
│  - Chunked upload (1MB chunks)                   │
│  - Resumable (if interrupted, resume from chunk) │
│  - Bandwidth throttled (max 10% of available)    │
│  - Parallel uploads: max 2 concurrent            │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│  Stage 4: Cleanup                                │
│                                                  │
│  - Delete local staging file after confirmed     │
│    upload (server ACK with checksum)             │
│  - If upload fails 3x: keep staged, alert admin  │
│  - If staging dir > 500MB: LRU evict oldest      │
│  - If device offline > 24h: compress staging dir │
└─────────────────────────────────────────────────┘
```

### CPU Optimization Techniques

**1. Zero-Copy Packet Processing**
```
Kernel packet buffer ──► mmap'd ring buffer ──► inspection ──► WireGuard
                         (no memcpy)            (in-place)     (zero-copy sendmsg)
```
- Use `AF_XDP` (Linux), `kqueue` (macOS), or `IOCP` (Windows) for zero-copy packet I/O
- Inspect packets in-place in the ring buffer without copying to heap
- smoltcp userspace TCP/IP stack operates on borrowed slices

**2. Fast-Path / Slow-Path Split**
```
All Packets
    │
    ├── 95% ──► Fast Path (no inspection needed)
    │           - Destination not in inspection list
    │           - Known-good flow (cached verdict)
    │           - Just forward through WireGuard
    │           - Cost: ~50ns per packet (hash lookup)
    │
    └── 5% ──► Slow Path (needs inspection)
                - First packet of new flow → classify
                - TLS inspection target → decrypt + inspect
                - Upload detected → DLP scan
                - Cost: ~500μs per flow (amortized)
```
- Cache flow verdicts: once a flow is classified, subsequent packets take the fast path
- Use `HashMap` with flow 5-tuple as key for O(1) lookup
- Flow cache eviction: LRU with 60-second TTL

**3. Efficient String/Pattern Matching**
- Use Aho-Corasick (via `aho-corasick` crate) for multi-pattern DLP scanning
- Compile all DLP patterns into a single automaton at policy load time
- Single pass through content matches ALL patterns simultaneously
- This is what CrowdStrike and Snort/Suricata use for signature matching

**4. Lazy TLS Interception**
- Don't decrypt until there's a reason to
- First check: is the destination on the inspection list? (fast hash lookup)
- Second check: does the SNI match a DLP-relevant domain? (Aho-Corasick)
- Only then set up the MITM certificate and decrypt
- Most TLS connections are never decrypted

### Memory Optimization Techniques

**1. Arena Allocation for Packets**
- Pre-allocate a fixed-size arena (e.g., 8MB) for packet processing
- All packet buffers come from the arena, not the heap
- Reset the arena per batch (no individual frees, no fragmentation)
- Rust's `bumpalo` crate provides this pattern

**2. Memory-Mapped I/O for Large Data**
- Shadow copy files: `mmap` to tmpdir, not `Vec<u8>` in heap
- Policy files: `mmap` read-only, shared across threads
- osquery result cache: `mmap` backed by temp file
- This keeps RSS low even when handling large files

**3. Streaming Inspection (No Buffering)**
- DLP scanning operates on streaming chunks, not buffered files
- Upload inspection reads 64KB at a time through the pattern matcher
- No need to hold the entire upload in memory
- Only the shadow copy (if triggered) touches disk

**4. Bounded Data Structures**
- Flow cache: max 10,000 entries (LRU eviction) ≈ 2MB
- DNS cache: max 5,000 entries ≈ 500KB
- Event queue: ring buffer, fixed 1MB
- Session cache: max 1,000 SaaS sessions ≈ 200KB

**5. Jemalloc / mimalloc**
- Use `mimalloc` as the global allocator (used by Tailscale's Go runtime, ClickHouse)
- Better performance and lower fragmentation than system malloc
- ~10-20% memory reduction in long-running services

### Battery & Mobile Optimization

**1. Adaptive Polling**
```
Device State          │  Behavior
──────────────────────┼─────────────────────────────────
Screen on, active     │  Full inspection, real-time posture
Screen on, idle       │  Reduce posture checks to every 5 min
Screen off, plugged   │  Background processing, upload staged copies
Screen off, battery   │  Minimal: heartbeat only, cache verdicts
Low battery (< 20%)   │  Suspend non-critical: ML inference, shadow copy upload
Airplane mode         │  Cache everything locally, sync when connected
```

**2. Coalesced Network Operations**
- Batch heartbeat + posture report + event upload into single HTTPS request
- Use HTTP/2 multiplexing to the control plane (one TCP connection, multiple streams)
- Compress all uploads with zstd (typically 3-5x reduction)

**3. Kernel Offloading (Where Available)**
- macOS/iOS: Use `NEFilterDataProvider` instead of raw packet capture (OS handles scheduling)
- Linux relay: Use kernel WireGuard module instead of boringtun userspace (saves context switches)
- Windows: WFP callout runs in kernel, only sends verdicts to userspace (not full packets)

**4. CPU Frequency Awareness**
- On mobile: detect when device is in low-power mode
- Defer ML inference and heavy DLP scanning until CPU is back to full speed
- Use `dispatch_queue_attr_make_with_qos_class(.utility)` on Apple platforms
- Use `THREAD_PRIORITY_BELOW_NORMAL` on Windows

### Bandwidth Optimization

| Data Type | Strategy | Expected Volume |
|---|---|---|
| Heartbeats | 30s interval, ~200 bytes each | ~580 KB/day |
| Posture reports | Every 5 min, ~2KB each | ~576 KB/day |
| Policy sync | On-change only (hash comparison), ~5KB | < 50 KB/day |
| Flow metadata | Batched every 60s, compressed, ~1KB/batch | ~1.4 MB/day |
| DLP events | On-detection only, ~500 bytes each | Variable |
| Shadow copies | Staged + async, bandwidth-throttled | Variable |
| **Total overhead** | | **< 3 MB/day typical** |

### Monitoring & Profiling

Bridge includes a built-in performance monitor (disabled by default, enabled via admin policy):

```
GET /debug/perf (localhost IPC only)

{
  "cpu_percent": 0.3,
  "memory_rss_mb": 42,
  "memory_heap_mb": 18,
  "flow_cache_entries": 3421,
  "flow_cache_hit_rate": 0.97,
  "packets_fast_path": 98423,
  "packets_slow_path": 1577,
  "active_tunnels": 3,
  "inspection_queue_depth": 0,
  "staging_dir_mb": 12.3,
  "pending_uploads": 2,
  "last_heartbeat_ms": 14,
  "osquery_last_run_ms": 230
}
```

Admin dashboard shows fleet-wide performance metrics to catch regressions before users notice.

---

## SIEM / SOAR Integration & Logging

Bridge exports structured security events and telemetry to external security platforms. This is critical for SOC teams who need Bridge data alongside other security signals.

### Supported SIEM/SOAR Platforms

| Platform | Transport | Format | Notes |
|---|---|---|---|
| **Splunk** | HEC (HTTP Event Collector) | JSON, CIM-compliant | Native Splunk app with pre-built dashboards |
| **Google SecOps (Chronicle)** | Ingestion API / Syslog | UDM (Unified Data Model) | Maps Bridge events to Chronicle's entity model |
| **Wazuh** | Syslog (TCP/UDP/TLS) + API | JSON (Wazuh decoder) | Custom decoder + rules for Bridge events |
| **Elastic Security** | Elasticsearch API / Filebeat | ECS (Elastic Common Schema) | Pre-built Kibana dashboards |
| **Microsoft Sentinel** | Data Collector API / Syslog | CEF / custom JSON | Logic App connectors for automated response |
| **Sumo Logic** | HTTP Source | JSON | |
| **IBM QRadar** | Syslog (LEEF format) | LEEF | DSM for Bridge events |
| **Any Syslog** | Syslog (RFC 5424, TLS) | CEF or JSON | Universal fallback |
| **Webhook** | HTTPS POST | JSON | For custom integrations, SOAR platforms |
| **S3 / GCS / Azure Blob** | Object storage | JSON Lines (JSONL) | Batch export for data lake / cold storage |

### Event Taxonomy

All Bridge events follow a consistent schema with a `bridge.event_type` classification:

```json
{
  "timestamp": "2026-03-05T10:31:00.123Z",
  "bridge": {
    "event_type": "dlp.violation",
    "severity": "high",
    "event_id": "evt_abc123",
    "org_id": "org_xyz"
  },
  "device": {
    "id": "dev_abc123",
    "platform": "macos",
    "os_version": "15.2",
    "hostname": "will-mbp",
    "posture_score": 85,
    "posture_tier": "standard_access"
  },
  "user": {
    "id": "usr_will",
    "email": "will@company.com",
    "groups": ["engineering"]
  },
  "network": {
    "tunnel_id": "tun_browser",
    "source_app": "com.google.Chrome",
    "destination": "docs.google.com",
    "destination_ip": "142.250.70.46",
    "protocol": "https",
    "bytes_sent": 524288,
    "bytes_received": 1024
  },
  "dlp": {
    "rule_name": "block_pii_to_personal",
    "pattern_matched": "credit_card",
    "action_taken": "blocked",
    "session_context": "personal_google_account",
    "shadow_copy_id": "sc_xyz789"
  }
}
```

### Event Types

| Category | Event Type | Severity | Description |
|---|---|---|---|
| **DLP** | `dlp.violation` | high/critical | DLP pattern matched, upload blocked or shadowed |
| **DLP** | `dlp.shadow_copy` | info | Upload shadow-copied to audit storage |
| **DLP** | `dlp.session_detected` | info | Personal/corporate account session identified |
| **Threat** | `threat.malware_domain` | critical | Connection to known malware domain blocked |
| **Threat** | `threat.c2_beacon` | critical | C2 beacon pattern detected |
| **Threat** | `threat.dns_tunnel` | high | DNS tunneling attempt detected |
| **Threat** | `threat.anomaly` | medium | ML-based traffic anomaly score exceeded threshold |
| **Posture** | `posture.score_change` | info/warning | Device posture score changed |
| **Posture** | `posture.tier_change` | warning | Device moved to a different access tier |
| **Posture** | `posture.check_failed` | warning | Specific posture check failed (e.g., OS outdated) |
| **Access** | `access.tunnel_created` | info | New WireGuard tunnel established |
| **Access** | `access.tunnel_revoked` | warning | Tunnel revoked (posture, tamper, admin) |
| **Access** | `access.resource_blocked` | warning | Access to resource denied by policy |
| **Tamper** | `tamper.heartbeat_missed` | warning | Device missed heartbeat threshold |
| **Tamper** | `tamper.integrity_failed` | critical | Agent binary integrity check failed |
| **Tamper** | `tamper.config_modified` | high | Local config tampered with |
| **Auth** | `auth.login` | info | User SSO login successful |
| **Auth** | `auth.login_failed` | warning | SSO login failed |
| **Auth** | `auth.session_expired` | info | User session expired, re-auth needed |
| **Device** | `device.registered` | info | New device enrolled |
| **Device** | `device.deregistered` | warning | Device removed from fleet |
| **Shadow IT** | `shadow_it.app_detected` | warning | Unsanctioned SaaS app usage detected |

### SIEM Configuration

Admins configure SIEM exports in the Bridge control plane dashboard or via API:

```yaml
# Example: Multi-destination logging config
logging:
  destinations:
    - name: "splunk-prod"
      type: "splunk_hec"
      endpoint: "https://splunk.company.com:8088"
      token: "${SPLUNK_HEC_TOKEN}"
      index: "bridge_security"
      source_type: "bridge:events"
      tls_verify: true
      events: ["dlp.*", "threat.*", "tamper.*"]   # Only high-value events
      batch_size: 100
      flush_interval: 10s

    - name: "chronicle"
      type: "google_secops"
      customer_id: "${CHRONICLE_CUSTOMER_ID}"
      credentials: "${CHRONICLE_SA_KEY}"
      events: ["*"]                                # All events
      batch_size: 500
      flush_interval: 30s

    - name: "wazuh-manager"
      type: "syslog"
      endpoint: "wazuh.company.com:1514"
      protocol: "tcp_tls"
      format: "json"                               # or "cef"
      ca_cert: "/etc/bridge/wazuh-ca.pem"
      events: ["*"]

    - name: "cold-storage"
      type: "s3"
      bucket: "bridge-logs-${ORG_ID}"
      region: "us-east-1"
      prefix: "events/"
      format: "jsonl"
      compression: "gzip"
      partition_by: "date"                         # s3://bucket/events/2026/03/05/*.jsonl.gz
      events: ["*"]
      flush_interval: 300s

    - name: "soar-webhook"
      type: "webhook"
      endpoint: "https://soar.company.com/api/v1/bridge/events"
      auth:
        type: "bearer"
        token: "${SOAR_API_TOKEN}"
      events: ["threat.*", "tamper.*"]             # Only actionable events
      retry: { max_attempts: 3, backoff: "exponential" }
```

### SOAR Playbook Integration

Bridge events can trigger automated response workflows in SOAR platforms:

```
Bridge Event                     SOAR Action
─────────────────────────────────────────────────────────────
threat.c2_beacon          →  Isolate device, create incident ticket,
                             notify security team, revoke Okta sessions

tamper.integrity_failed   →  Quarantine device, lock user account,
                             create P1 incident, page on-call

dlp.violation (critical)  →  Block user's upload capabilities,
                             notify user's manager, create case

posture.tier_change       →  If downgrade: notify user with remediation
                             steps, create IT ticket if unresolved in 24h

shadow_it.app_detected    →  Log for monthly shadow IT report,
                             notify IT admin if repeated
```

### Wazuh-Specific Integration

For Wazuh users, Bridge provides:

1. **Custom decoder** (`/var/ossec/etc/decoders/bridge_decoder.xml`):
```xml
<decoder name="bridge">
  <prematch>\"bridge\":{\"event_type\":</prematch>
  <regex>\"event_type\":\"(\S+)\".*\"severity\":\"(\S+)\"</regex>
  <order>bridge.event_type, bridge.severity</order>
</decoder>
```

2. **Custom rules** (`/var/ossec/etc/rules/bridge_rules.xml`):
```xml
<group name="bridge,">
  <rule id="100100" level="10">
    <decoded_as>bridge</decoded_as>
    <field name="bridge.event_type">^threat\.</field>
    <description>Bridge: Threat detected - $(bridge.event_type)</description>
  </rule>

  <rule id="100101" level="14">
    <decoded_as>bridge</decoded_as>
    <field name="bridge.event_type">^tamper\.</field>
    <description>Bridge: Tamper detected - $(bridge.event_type)</description>
  </rule>

  <rule id="100102" level="8">
    <decoded_as>bridge</decoded_as>
    <field name="bridge.event_type">^dlp\.violation</field>
    <description>Bridge: DLP violation - $(bridge.event_type)</description>
  </rule>
</group>
```

3. **Pre-built Wazuh dashboard** (JSON import) for Bridge event visualization

### Google SecOps (Chronicle) Integration

Bridge maps events to Chronicle's Unified Data Model (UDM):

| Bridge Field | UDM Field | Notes |
|---|---|---|
| `user.email` | `principal.user.email_addresses` | |
| `device.hostname` | `principal.hostname` | |
| `network.destination` | `target.hostname` | |
| `network.destination_ip` | `target.ip` | |
| `network.protocol` | `network.application_protocol` | |
| `bridge.event_type` | `metadata.event_type` | Mapped to UDM event types |
| `dlp.rule_name` | `security_result.rule_name` | |
| `dlp.action_taken` | `security_result.action` | ALLOW/BLOCK |

Bridge ships a Chronicle parser configuration that handles this mapping automatically.

### Log Volume Estimates

| Fleet Size | Events/Day (Typical) | Storage/Day | Notes |
|---|---|---|---|
| 100 devices | ~50,000 | ~50 MB | Mostly flow metadata + posture |
| 1,000 devices | ~500,000 | ~500 MB | Standard enterprise |
| 10,000 devices | ~5,000,000 | ~5 GB | Large enterprise, consider S3 tiering |

Events are compressed (zstd, ~5:1) before transmission. Admins can filter which event types are sent to each destination to control volume.

---

## Tamper Resistance & Agent-as-Gatekeeper

### Core Principle: No Agent = No Access

Bridge enforces a fundamental invariant: **the agent IS the access gate**. Users cannot bypass, disable, or tamper with Bridge because doing so revokes their access to all corporate resources. This is not punitive - it's structural.

```
Bridge Agent Running + Healthy    ──►  WireGuard tunnels active  ──►  Access to corporate apps
Bridge Agent Tampered/Stopped     ──►  Tunnels torn down         ──►  No access to anything
Bridge Agent Uninstalled          ──►  Device deregistered       ──►  Zero access
```

### How It Works

**1. Heartbeat & Liveness**
- The Bridge daemon sends signed heartbeats to the control plane every 30 seconds
- Heartbeats include: process integrity hash, posture snapshot signature, timestamp
- If the control plane misses 3 heartbeats (90s), it revokes all tunnel authorizations for that device
- The relay tears down WireGuard sessions for revoked tunnels immediately

**2. Agent Integrity Verification**
- On macOS: Bridge runs as a System Extension (kernel-level protection). Users cannot kill it without admin privileges + SIP bypass.
- On iOS: The Network Extension lifecycle is managed by the OS. If the app is removed, the VPN profile is automatically removed.
- On Android: Bridge uses Device Admin / Android Enterprise APIs. The VPN profile is enforced by MDM policy.
- On Windows: Bridge installs as a Windows Service with SYSTEM privileges. The WFP callout driver requires kernel-mode signing.

**3. Self-Attestation**
- The daemon continuously hashes its own binary, configuration, and loaded libraries
- These hashes are compared against known-good values from the control plane
- If the binary has been modified, patched, or injected into, the attestation fails
- Failed attestation = heartbeat rejected = tunnels revoked

**4. Configuration Tamper Detection**
- All local policy/config files are signed by the control plane
- The daemon verifies signatures before applying any configuration
- Local modification of config files is detected and reported
- The daemon fetches authoritative config from the control plane on startup

**5. Network-Level Enforcement**
- Corporate resources (SaaS apps, internal services) are ONLY accessible through Bridge relays
- Direct access is blocked at the network/firewall level (IP allowlisting, mTLS requirements)
- Even if a user disables Bridge and connects directly, the destination services reject connections without the Bridge relay's IP or mTLS certificate
- DNS for corporate domains resolves to Bridge relay IPs only

### Anti-Tamper Escalation Model

| Level | What Happened | Response |
|---|---|---|
| 0 - Normal | Agent healthy, posture passing | Full access |
| 1 - Degraded | Posture check failing (e.g., OS outdated) | Limited access, user notified to remediate |
| 2 - Suspicious | Heartbeat delayed, config modified | Restricted to essential services only, admin alerted |
| 3 - Tampered | Binary modified, heartbeat missing | All tunnels revoked, device quarantined, security team alerted |
| 4 - Deregistered | Agent uninstalled or device wiped | Device removed from registry, all keys rotated |

### Why Users Won't Tamper

The incentive structure makes tampering irrational:
- **Tampering = losing access to work tools** (email, Slack, Jira, internal apps)
- **The agent is lightweight** - minimal battery/performance impact, no reason to disable
- **Transparent operation** - users can see exactly what Bridge is doing (which apps are routed, what's inspected)
- **Graceful degradation** - if the agent has issues, it self-heals or alerts IT rather than blocking the user silently

---

## Deployment & Installation

### Design Principle: Zero-Touch Deployment

Bridge must be deployable at scale through MDM without requiring end-user interaction beyond opening the app. The install should:
- Be a single package (no multi-step installers)
- Pre-configure enrollment token and control plane URL
- Auto-approve System Extension / Network Extension permissions via MDM profiles
- Start the daemon automatically on first launch
- Complete device registration silently

### macOS Deployment (Jamf Pro / Jamf Now)

```
Jamf Admin Console
  │
  ├── 1. Upload Bridge.pkg to Jamf
  │      - Signed + notarized .pkg containing:
  │        - Bridge.app (SwiftUI UI)
  │        - BridgeSystemExtension.systemextension
  │        - bridge-daemon (Rust binary)
  │        - Bundled osquery binary
  │        - LaunchDaemon plist (auto-start)
  │
  ├── 2. Create Configuration Profile
  │      - System Extension Policy:
  │        - Allow team ID for Bridge system extension
  │        - Allow network extension (content filter + packet tunnel)
  │      - VPN Profile:
  │        - VPN type: Custom SSL (NEPacketTunnelProvider)
  │        - Provider bundle ID: com.bridge.tunnel
  │        - On-demand rules (always connected)
  │      - Certificate Payload:
  │        - Bridge inspection CA certificate (for TLS inspection)
  │        - Installed to System keychain as trusted
  │      - Custom Settings (Bridge config):
  │        - control_plane_url: "https://control.bridge.io"
  │        - enrollment_token: "org_xxxxx"
  │        - auto_connect: true
  │
  ├── 3. Scope to device groups / smart groups
  │
  └── 4. Deploy
         - .pkg installs silently
         - Configuration profile auto-approves extensions
         - LaunchDaemon starts bridge-daemon
         - Daemon registers with control plane using enrollment token
         - User opens Bridge.app, sees "Connected" immediately
```

**Key Jamf MDM profile payloads:**

```xml
<!-- System Extension Policy -->
<key>PayloadType</key>
<string>com.apple.system-extension-policy</string>
<key>AllowedSystemExtensions</key>
<dict>
  <key>TEAM_ID_HERE</key>
  <array>
    <string>com.bridge.tunnel.extension</string>
    <string>com.bridge.filter.extension</string>
  </array>
</dict>

<!-- Network Extension / Content Filter -->
<key>PayloadType</key>
<string>com.apple.webcontent-filter</string>
<key>FilterType</key>
<string>Plugin</string>
<key>PluginBundleID</key>
<string>com.bridge.app</string>
<key>FilterDataProviderBundleIdentifier</key>
<string>com.bridge.filter.extension</string>

<!-- VPN Always-On -->
<key>PayloadType</key>
<string>com.apple.vpn.managed</string>
<key>VPNType</key>
<string>VPN</string>
<key>VPNSubType</key>
<string>com.bridge.tunnel.extension</string>
<key>OnDemandEnabled</key>
<integer>1</integer>
<key>OnDemandRules</key>
<array>
  <dict>
    <key>Action</key>
    <string>Connect</string>
  </dict>
</array>
```

### iOS Deployment (Jamf / Intune / ABM)

```
1. Distribute Bridge via Apple Business Manager (ABM) / VPP
   - App is assigned to devices (no Apple ID needed for managed distribution)
   - MDM pushes install command

2. MDM Configuration Profile:
   - VPN Profile (per-app VPN):
     - Associates specific managed apps with Bridge tunnel
     - e.g., Salesforce, Slack, corporate browser all route through Bridge
   - Certificate payload for inspection CA
   - App Config (Managed App Configuration):
     - control_plane_url, enrollment_token via AppConfig XML

3. On first launch:
   - Network Extension activates automatically (MDM pre-approved)
   - Device registers with control plane
   - Per-app VPN rules take effect immediately
```

### Windows Deployment (Intune / SCCM / Group Policy)

```
1. Package: Bridge.msix (or .msi for legacy)
   - Contains:
     - Bridge UI (WinUI 3)
     - Bridge Windows Service (Rust daemon)
     - Wintun driver (WireGuard tunnel adapter)
     - WFP callout driver (per-app filtering)
     - Bundled osquery
   - Signed with EV code signing certificate

2. Intune deployment:
   - Upload .msix as Win32 app or LOB app
   - Detection rule: Check for Bridge Windows Service running
   - Assignment: Required for device groups

3. Group Policy / Registry pre-configuration:
   HKLM\SOFTWARE\Bridge\
     ControlPlaneURL = "https://control.bridge.io"
     EnrollmentToken = "org_xxxxx"
     AutoConnect = 1

4. Silent install:
   bridge-installer.exe /S /CONTROL_PLANE=https://control.bridge.io /TOKEN=org_xxxxx

5. Post-install:
   - Windows Service starts automatically
   - WFP driver loads
   - Wintun adapter created
   - Device registers with control plane
```

### Android Deployment (Intune / VMware WS1 / Android Enterprise)

```
1. Distribute via Managed Google Play (Android Enterprise)
   - App published as private app or uploaded as APK
   - EMM pushes install

2. Managed Configuration (AppConfig):
   {
     "control_plane_url": "https://control.bridge.io",
     "enrollment_token": "org_xxxxx",
     "always_on_vpn": true
   }

3. Android Enterprise policies:
   - Set Bridge as Always-On VPN provider
   - Block connections without VPN (lockdown mode)
   - Per-app VPN via work profile app association

4. On first launch:
   - VPN permission auto-granted (Android Enterprise managed)
   - Device registers
   - Tunnels establish
```

### Zero-Interaction Install Guarantee

All deployment methods must achieve **zero user interaction** after the MDM pushes the package:

- **No prompts:** System Extension, VPN, and certificate trust are all pre-approved via MDM profiles
- **No clicks:** The daemon starts via LaunchDaemon/Windows Service/init.d automatically
- **No app launch needed:** Registration happens at the daemon level, not the UI level. The UI is optional (for status visibility only)
- **No UAC/admin prompts:** Installers run in SYSTEM/root context via MDM
- **Enrollment is automatic:** Token is embedded in the package or delivered via MDM AppConfig

The user's only experience is: their device now has Bridge running. Corporate resources work. No action required.

### Self-Service Install (Smaller Orgs Without MDM)

For orgs without MDM, Bridge provides a streamlined self-service flow. This is the ONE scenario where minimal user interaction is unavoidable (OS requires user consent for VPN/extensions when no MDM is present):

```
1. Admin generates enrollment link in Bridge dashboard
   https://bridge.io/enroll/org_xxxxx

2. User opens link on their device
   - Downloads platform-appropriate installer with embedded enrollment token

3. Install flow:
   macOS: Open .pkg → one "Allow" for System Extension → auto-connects
   Windows: Run installer → one UAC prompt → auto-connects
   iOS: App Store → open → one "Allow VPN" → auto-connects
   Android: Play Store → open → one "Allow VPN" → auto-connects

4. After initial approval, everything is automatic
```

### Package Signing & Notarization Requirements

| Platform | Requirement | How |
|---|---|---|
| macOS | Developer ID + Notarization + Hardened Runtime | Apple Developer Enterprise Program |
| iOS | App Store or Enterprise Distribution cert | Apple Developer Enterprise Program |
| Windows | EV Code Signing Certificate (for driver signing) | DigiCert / Sectigo |
| Android | Play Store signing or enterprise APK signing | Google Play Console |

---

## Deployment Models

### SaaS (Default)
- Bridge-managed relays in multiple regions
- Bridge-managed control plane
- Customer data never stored (pass-through inspection)

### Hybrid
- Customer-managed control plane (for policy sovereignty)
- Bridge-managed relays (for global coverage)

### On-Premises
- Everything on customer infrastructure
- Kubernetes-based deployment
- Air-gapped support for regulated environments

---

## Technology Choices & Rationale

| Decision | Choice | Rationale |
|---|---|---|
| Core language | Rust | Memory safety for security product, cross-compiles to all platforms, great FFI, matches boringtun |
| WireGuard impl | boringtun | Cloudflare's userspace WireGuard in Rust, BSD-3 license, production-proven |
| TLS library | rustls | Pure Rust, no OpenSSL dependency, MIT licensed, audited |
| HTTP parsing | httparse | Zero-copy HTTP parser, used by hyper/reqwest |
| DNS | trust-dns / hickory-dns | Full DNS library in Rust, supports DoH/DoT |
| Async runtime | tokio | De facto standard for async Rust |
| API framework | axum | Built on tokio/hyper, tower middleware ecosystem |
| Database | PostgreSQL | Reliable, good tooling (sqlx for Rust), JSONB for flexible policy storage |
| IPC | tonic (gRPC) | Type-safe IPC between daemon and UI, code generation from protobuf |
| ML inference | ort (ONNX Runtime) | Lightweight, cross-platform ML inference for anomaly detection |
| Packet handling | smoltcp | Userspace TCP/IP stack for packet-level manipulation |
| Dashboard | Next.js + TypeScript | Fast iteration, good component ecosystem, SSR for admin UIs |

### Why NOT mitmproxy directly?
- Python is too heavy for mobile clients (battery, memory)
- mitmproxy's core is GPL-licensed (the library/addons), complicating commercialization
- We need packet-level integration with WireGuard, not a standalone proxy
- Rust implementation gives us single-binary deployment and C-level performance
- We adopt mitmproxy's **design patterns** (flows, hooks, addons) without its codebase

### Why NOT wireguard-go?
- boringtun (Rust) integrates naturally with our Rust core
- No CGo cross-compilation complexity
- Same language means shared types, error handling, and tooling
- boringtun is used in production by Cloudflare (1.1.1.1 WARP)
