# Bridge - Epics & Development Stages

## Overview

Bridge development is organized into **6 stages**, each containing multiple **epics**. Each stage builds on the previous one and ends with a usable milestone. Stages are sequential, but epics within a stage can be parallelized across team members.

**Notation:**
- Each epic has a unique ID (e.g., `E1.1`)
- Dependencies are listed explicitly
- Estimated effort is in engineer-weeks (one person, full-time)
- "MVP" marks the minimum viable scope within an epic
- "Full" marks the complete scope

---

## Stage 1: Foundation
**Goal:** A single WireGuard tunnel on macOS that connects through a relay, authenticated by a control plane.
**Milestone:** `bridge connect` works. Device registers, gets config, establishes tunnel, traffic flows through relay.

### E1.1 - Rust Workspace & Build System
**Effort:** 1 week
**Dependencies:** None

- [ ] Initialize Cargo workspace with crates: `bridge-core`, `bridge-daemon`, `bridge-relay`, `bridge-api`, `bridge-ffi`
- [ ] Set up cross-compilation targets (macOS aarch64/x86_64, Linux x86_64)
- [ ] CI pipeline: `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt`
- [ ] Protobuf code generation (tonic-build) for IPC and API definitions
- [ ] Shared error types, logging (tracing crate), and configuration loading

### E1.2 - WireGuard Tunnel Core
**Effort:** 3 weeks
**Dependencies:** E1.1

- [ ] Integrate boringtun as userspace WireGuard implementation
- [ ] Tunnel lifecycle: create, configure, handshake, data transfer, teardown
- [ ] Key generation and management (ephemeral keypairs)
- [ ] Keepalive and reconnection logic
- [ ] TUN device creation (utun on macOS, tun on Linux)
- [ ] Unit tests: tunnel establishment, packet forwarding, key rotation
- [ ] **MVP:** Single tunnel, single peer, packets flow bidirectionally

### E1.3 - Control Plane API (Basic)
**Effort:** 3 weeks
**Dependencies:** E1.1

- [ ] Axum HTTP server with health check endpoint
- [ ] PostgreSQL schema: devices, users, tunnels, policies
- [ ] Database migrations (sqlx-migrate or refinery)
- [ ] `POST /api/v1/devices/register` - device registration with enrollment token
- [ ] `GET /api/v1/tunnels/config` - return WireGuard config for registered device
- [ ] `POST /api/v1/devices/{id}/heartbeat` - basic heartbeat
- [ ] Enrollment token generation and validation (admin API)
- [ ] Basic API authentication (enrollment token → device cert exchange)
- [ ] Docker Compose for local development (API + PostgreSQL)
- [ ] **MVP:** Device registers, receives WireGuard config, heartbeat accepted

### E1.4 - Bridge Relay (Basic)
**Effort:** 2 weeks
**Dependencies:** E1.2

- [ ] Relay server binary using boringtun
- [ ] Multi-peer WireGuard endpoint (listen on UDP, handle multiple tunnels)
- [ ] Tunnel provisioning API (control plane tells relay about new tunnels)
- [ ] NAT/forwarding: traffic egresses through relay's IP
- [ ] Basic ACL: allowed destination IPs/CIDRs per tunnel
- [ ] **MVP:** Relay accepts tunnel from client, forwards traffic to internet

### E1.5 - macOS Network Extension (Shell)
**Effort:** 3 weeks
**Dependencies:** E1.2

- [ ] Xcode project with NEPacketTunnelProvider system extension
- [ ] FFI bridge: Swift calls Rust core via C ABI (bridge-ffi crate)
- [ ] Packet tunnel provider: read/write packets to/from WireGuard tunnel
- [ ] VPN configuration: programmatic NEVPNManager setup
- [ ] Connect/disconnect lifecycle
- [ ] System Extension signing and entitlements
- [ ] **MVP:** macOS system extension establishes WireGuard tunnel through relay

### E1.6 - macOS Client UI (Minimal)
**Effort:** 1 week
**Dependencies:** E1.5

- [ ] SwiftUI menu bar app
- [ ] Connection status (connected/disconnected/connecting)
- [ ] Connect/disconnect button
- [ ] gRPC IPC to bridge-daemon for status and control
- [ ] **MVP:** User can see status and toggle connection

---

## Stage 2: Identity & Posture
**Goal:** SSO authentication, osquery posture checks, tiered access based on device health.
**Milestone:** Users authenticate via Okta/Azure AD. Posture score determines which resources are accessible.

### E2.1 - SSO Integration
**Effort:** 3 weeks
**Dependencies:** E1.3

- [ ] OIDC client implementation in control plane (authorization code flow + PKCE)
- [ ] Okta integration (primary target): app registration, callback handling, token validation
- [ ] Azure AD / Entra ID integration
- [ ] Google Workspace OIDC integration
- [ ] Generic OIDC provider support (any compliant provider)
- [ ] SAML 2.0 SP implementation (for enterprises that require it)
- [ ] Session management: token storage, refresh, expiry
- [ ] Device cert + SSO token dual authentication enforcement
- [ ] Client-side: system browser SSO flow (ASWebAuthenticationSession on macOS)
- [ ] **MVP:** Okta SSO login, session stored in keychain, tunnels gated on valid session

### E2.2 - SCIM User & Group Sync
**Effort:** 2 weeks
**Dependencies:** E2.1

- [ ] SCIM 2.0 server endpoint in control plane
- [ ] User provisioning: create, update, deactivate from IdP
- [ ] Group provisioning: create, update, member add/remove
- [ ] Okta SCIM integration (auto-provision on group assignment)
- [ ] Azure AD SCIM integration (Microsoft Graph)
- [ ] Google Directory API sync (alternative to SCIM for Google Workspace)
- [ ] PostgreSQL schema: users, groups, group_memberships
- [ ] Admin dashboard: user/group inventory view
- [ ] **MVP:** Groups sync from Okta, visible in dashboard, usable in policies

### E2.3 - Cryptographic Device Identity
**Effort:** 2 weeks
**Dependencies:** E1.2, E1.5

- [ ] macOS: Secure Enclave key generation (kSecAttrTokenIDSecureEnclave)
- [ ] Device certificate signing (control plane CA)
- [ ] mTLS configuration for all control plane API calls
- [ ] Attestation: sign posture reports with device hardware key
- [ ] Certificate rotation (90-day lifecycle)
- [ ] **MVP:** Device key in Secure Enclave, mTLS to control plane, signed heartbeats

### E2.4 - osquery Integration
**Effort:** 2 weeks
**Dependencies:** E1.1

- [ ] Bundle osquery binary in Bridge installer
- [ ] Launch and manage osquery process from bridge-daemon
- [ ] Communication via osquery Thrift extension interface
- [ ] Execute posture queries defined in policy
- [ ] Parse and evaluate query results against expected values
- [ ] Differential mode: only report changes between runs
- [ ] **MVP:** Bridge runs osquery, executes 5 default posture queries, reports results

### E2.5 - Posture Engine & Tiered Access
**Effort:** 3 weeks
**Dependencies:** E2.3, E2.4, E1.3

- [ ] Posture score calculation: weighted sum of native checks + osquery results
- [ ] Access tier assignment based on posture score thresholds
- [ ] Tier-to-resource mapping (which tiers can access which destinations)
- [ ] Dynamic tunnel reconfiguration on tier change (add/revoke tunnels)
- [ ] Posture report endpoint: `POST /api/v1/devices/{id}/posture`
- [ ] Admin dashboard: per-device posture score, tier, check history
- [ ] Client UI: show current posture score and any failing checks with remediation guidance
- [ ] Posture policy DSL: admin-defined osquery checks with weights and remediation text
- [ ] **MVP:** Posture score calculated, tier assigned, Salesforce blocked when OS outdated

### E2.6 - Policy Engine (Groups & Conditions)
**Effort:** 3 weeks
**Dependencies:** E2.2, E2.5

- [ ] Policy DSL parser and evaluator (YAML-based)
- [ ] Condition matching: group, role, device_type, posture_tier, network_type, time, country
- [ ] Policy priority and conflict resolution (most specific wins)
- [ ] Policy versioning and hash-based sync (client only fetches on change)
- [ ] Split policy delivery: client_policy vs relay_policy views
- [ ] Policy editor in admin dashboard (YAML editor with validation)
- [ ] Policy simulation: "what would happen if device X had posture Y?"
- [ ] **MVP:** Policies target groups with conditions, different groups get different access

---

## Stage 3: Traffic Intelligence
**Goal:** DNS filtering, TLS inspection, DLP, and shadow copy on macOS.
**Milestone:** Bridge blocks malware domains, inspects TLS selectively, catches credit card uploads, shadow copies to personal cloud.

### E3.1 - Local DNS Proxy
**Effort:** 2 weeks
**Dependencies:** E1.5

- [ ] DNS resolver on 127.0.0.1:53 (hickory-dns/trust-dns)
- [ ] Query interception via Network Extension DNS settings
- [ ] Blocklist matching: malware, phishing, ads/tracking (bundled lists + admin custom)
- [ ] Allowlist support (corporate domains always resolve)
- [ ] Per-app DNS routing (different upstream resolvers per tunnel)
- [ ] DoH/DoT upstream support
- [ ] DNS query logging (app, domain, result, timestamp)
- [ ] DNS cache with TTL awareness
- [ ] DNS tunneling detection (entropy analysis on query names)
- [ ] **MVP:** DNS queries filtered against blocklists, logged with app attribution

### E3.2 - Content Filter (Non-Tunneled Inspection)
**Effort:** 3 weeks
**Dependencies:** E1.5

- [ ] macOS NEFilterDataProvider system extension
- [ ] Flow classification: identify app, destination, protocol for all traffic
- [ ] Fast-path/slow-path split (hash-based flow cache)
- [ ] TLS fingerprinting (JA3/JA4 extraction) without decryption
- [ ] Destination reputation checking (local blocklist)
- [ ] Flow metadata collection: source app, destination, bytes, duration
- [ ] Integration with policy engine for per-app filtering decisions
- [ ] **MVP:** All traffic visible with app attribution, malware domains blocked even without tunnel

### E3.3 - TLS Inspection Engine
**Effort:** 4 weeks
**Dependencies:** E3.2

- [ ] CA certificate generation (per-org root CA, inspection sub-CA)
- [ ] On-the-fly certificate generation for inspected domains (rustls)
- [ ] MITM proxy: terminate TLS from client, new TLS to destination
- [ ] Certificate pinning detection and bypass (don't break pinned apps)
- [ ] Selective inspection: only decrypt domains on the inspection list
- [ ] Exclusion lists: banking, health, and admin-defined sensitive domains
- [ ] HTTP request/response parsing (httparse) from decrypted stream
- [ ] Flow/hook architecture: request_hook, response_hook, tcp_message_hook
- [ ] CA distribution: MDM profile for trust, client UI for self-service
- [ ] **MVP:** TLS decrypted for configured domains, HTTP requests visible, exclusions work

### E3.4 - DLP Engine
**Effort:** 3 weeks
**Dependencies:** E3.3

- [ ] Pattern engine: Aho-Corasick automaton compiled from all DLP rules
- [ ] Built-in detectors: credit card (Luhn), SSN, API keys (entropy + format), email, phone
- [ ] Custom pattern support (admin-defined regex/keywords)
- [ ] Streaming inspection: scan 64KB chunks, no full-file buffering
- [ ] Upload detection: multipart/form-data parsing, PUT/POST body, WebSocket frames
- [ ] Actions: block, alert, allow-and-log
- [ ] DLP event generation with matched pattern, destination, app context
- [ ] **MVP:** Credit cards and API keys detected in uploads, blocked per policy

### E3.5 - Session & Identity-Aware DLP
**Effort:** 3 weeks
**Dependencies:** E3.3, E3.4

- [ ] SaaS session detection: extract OAuth tokens, cookies, claims from inspected HTTP
- [ ] Account classification: corporate vs personal (based on email domain in session)
- [ ] SaaS-specific parsers: Google (accounts.google.com), Slack, Salesforce, Microsoft
- [ ] Shadow IT detection: flag traffic to unsanctioned SaaS apps
- [ ] Session context injected into DLP events and policy evaluation
- [ ] Policy conditions: `logged_in_as`, `session_type`, `uploading_to`
- [ ] **MVP:** Personal vs corporate Google detected, different DLP rules applied per session

### E3.6 - Shadow Copy
**Effort:** 3 weeks
**Dependencies:** E3.4, E3.5

- [ ] Upload stream forking: tee data to both destination and local staging
- [ ] Local staging: write to mmap'd temp file, compress (zstd level 3), encrypt (AES-256-GCM)
- [ ] Staging directory management: 500MB budget, LRU eviction
- [ ] Smart upload queue: bandwidth-aware, battery-aware, priority-based scheduling
- [ ] Chunked resumable upload to audit storage (S3-compatible)
- [ ] Metadata tagging: timestamp, user, device, destination, app, DLP scan result
- [ ] Admin dashboard: shadow copy browser with search/filter
- [ ] Policy controls: trigger conditions (personal account, unsanctioned SaaS, DLP match)
- [ ] Dual-authorization access (admin + auditor role required to view copies)
- [ ] **MVP:** Uploads to personal Google Docs shadow-copied, viewable in dashboard

---

## Stage 4: Enterprise Integration
**Goal:** SSO posture signaling, SIEM export, MDM deployment, tamper resistance.
**Milestone:** Bridge deploys silently via Jamf/Intune, feeds posture to Okta, exports events to Splunk/Wazuh.

### E4.1 - Bidirectional IdP Posture Signaling
**Effort:** 3 weeks
**Dependencies:** E2.5, E2.1

- [ ] Okta Device Trust / Device Assurance API integration
  - [ ] Register Bridge as signal provider
  - [ ] Push posture score + compliance signals on posture change
  - [ ] Okta Device Assurance Policy creation guide
- [ ] Shared Signals Framework (SSF/CAEP) transmitter
  - [ ] SSF stream configuration endpoint
  - [ ] CAEP events: device-compliance-change, session-revoked
  - [ ] SSF receiver: consume events from IdP (user deactivated, MFA reset)
- [ ] Azure AD compliance partner integration (Microsoft Graph)
- [ ] Google Context-Aware Access integration (BeyondCorp API)
- [ ] **MVP:** Posture changes push to Okta, Okta blocks non-compliant users from all apps

### E4.2 - SIEM Integration
**Effort:** 3 weeks
**Dependencies:** E1.3

- [ ] Event pipeline: structured events from relay + control plane → output adapters
- [ ] Splunk HEC adapter (HTTP Event Collector, CIM-compliant JSON)
- [ ] Syslog adapter (RFC 5424, TCP/TLS, CEF and JSON formats)
- [ ] Webhook adapter (HTTPS POST with retry/backoff)
- [ ] S3/GCS batch export adapter (JSONL, gzip, date-partitioned)
- [ ] Google SecOps (Chronicle) adapter with UDM mapping
- [ ] Wazuh decoder + rules XML (shipped as integration package)
- [ ] Elastic adapter with ECS mapping
- [ ] Event filtering per destination (e.g., only threat events to SOAR webhook)
- [ ] Admin dashboard: SIEM configuration UI, test connection, event preview
- [ ] **MVP:** Events flowing to Splunk HEC and Syslog, Wazuh decoder working

### E4.3 - Tamper Resistance
**Effort:** 2 weeks
**Dependencies:** E2.3, E1.5

- [ ] Agent self-attestation: continuous binary hash verification
- [ ] Configuration tamper detection: signed policy files, signature verification
- [ ] Heartbeat-based liveness: 3 missed = tunnel revocation
- [ ] Anti-tamper escalation model: normal → degraded → suspicious → tampered → quarantined
- [ ] Network-level enforcement: corporate resources only reachable via relay
- [ ] macOS System Extension protections (can't be killed without SIP bypass)
- [ ] Admin alerts on tamper events
- [ ] **MVP:** Tampered agent detected, tunnels revoked, admin alerted

### E4.4 - MDM Deployment (macOS)
**Effort:** 2 weeks
**Dependencies:** E1.5, E3.3

- [ ] Signed + notarized .pkg installer
- [ ] LaunchDaemon plist for auto-start
- [ ] Jamf Pro deployment guide and configuration profiles
  - [ ] System Extension policy payload
  - [ ] VPN always-on payload
  - [ ] Certificate trust payload (inspection CA)
  - [ ] Custom settings payload (control plane URL, enrollment token)
- [ ] Zero-interaction install: no prompts with MDM profiles
- [ ] Intune macOS deployment guide
- [ ] **MVP:** .pkg deploys via Jamf, zero user interaction, auto-connects

### E4.5 - Admin Dashboard (Full)
**Effort:** 4 weeks
**Dependencies:** E2.2, E2.5, E3.6, E4.2

- [ ] Next.js app with authentication (control plane session)
- [ ] Device inventory: list, search, filter by platform/posture/group
- [ ] Device detail: posture history, tunnel status, recent events
- [ ] User management: SSO-linked users, group memberships
- [ ] Policy editor: YAML editor with syntax highlighting, validation, simulation
- [ ] DLP events: timeline view, filter by severity/type/user
- [ ] Shadow copy browser: search, preview metadata, download (dual-auth gated)
- [ ] Audit log: all admin actions, shadow copy access, policy changes
- [ ] SIEM configuration: add/edit/test destinations
- [ ] Fleet overview: posture distribution chart, threat count, active devices
- [ ] **MVP:** Device list, posture view, policy editor, DLP event timeline

---

## Stage 5: Cross-Platform
**Goal:** iOS, Android, Windows, ChromeOS clients with full feature parity.
**Milestone:** All platforms connect, authenticate, report posture, and enforce DLP.

### E5.1 - iOS Client
**Effort:** 3 weeks
**Dependencies:** E1.5 (shares code with macOS)

- [ ] iOS app target in Xcode project (shared SwiftUI with macOS)
- [ ] iOS NEPacketTunnelProvider (nearly identical to macOS)
- [ ] Per-app VPN via NEVPNProtocol.appRules
- [ ] SSO via ASWebAuthenticationSession
- [ ] Native posture checks (jailbreak detection, OS version, passcode)
- [ ] Background processing: heartbeat, posture reporting
- [ ] MDM deployment: ABM/VPP, managed app configuration
- [ ] **MVP:** iOS connects, authenticates via SSO, posture reported, per-app VPN active

### E5.2 - Android Client
**Effort:** 4 weeks
**Dependencies:** E1.2

- [ ] Android Studio project (Jetpack Compose UI)
- [ ] Rust core integration via JNI (bridge-ffi jni.rs)
- [ ] VpnService implementation with WireGuard tunnel
- [ ] Per-app VPN: addAllowedApplication() / addDisallowedApplication()
- [ ] SSO via Chrome Custom Tab
- [ ] Native posture checks (root detection, SafetyNet/Play Integrity, OS version)
- [ ] Always-On VPN support (Android Enterprise)
- [ ] Managed Configuration for MDM deployment
- [ ] ChromeOS compatibility testing (ARC++)
- [ ] **MVP:** Android connects, SSO, posture, per-app VPN, deployable via Managed Google Play

### E5.3 - Windows Client
**Effort:** 5 weeks
**Dependencies:** E1.2

- [ ] WinUI 3 app (C# UI shell)
- [ ] Rust core integration via C# P/Invoke (bridge-ffi csharp.rs)
- [ ] Windows Service for bridge-daemon
- [ ] Wintun driver integration for WireGuard tunnel adapter
- [ ] WFP callout driver for per-app traffic filtering and PID attribution
- [ ] SSO via system browser (default browser OAuth redirect)
- [ ] Native posture checks (BitLocker, Windows Defender, firewall, OS version)
- [ ] osquery integration (Windows build)
- [ ] Intune deployment: .msix package, detection rules, registry pre-config
- [ ] SCCM/Group Policy deployment alternative
- [ ] EV code signing for kernel-mode driver
- [ ] **MVP:** Windows connects, SSO, posture with osquery, per-app WFP filtering

### E5.4 - ChromeOS Client
**Effort:** 2 weeks
**Dependencies:** E5.2

- [ ] Verify Android client works on ChromeOS via ARC++
- [ ] Chrome extension for browser-level DLP (chrome.webRequest, chrome.proxy)
- [ ] Extension deployment via Google Workspace admin console (force-install)
- [ ] Upload monitoring in Chrome (file input, drag-and-drop interception)
- [ ] **MVP:** Android app works on Chromebook, Chrome extension adds browser DLP

### E5.5 - Linux Client
**Effort:** 2 weeks
**Dependencies:** E1.2

- [ ] CLI client (bridge-cli) for headless/server use
- [ ] Optional GTK4 UI for desktop Linux
- [ ] nftables-based routing for per-app tunneling (cgroup matching)
- [ ] Kernel WireGuard module support (preferred over boringtun userspace)
- [ ] osquery integration (Linux build)
- [ ] Systemd service unit
- [ ] .deb and .rpm packaging
- [ ] **MVP:** CLI connects, routes traffic, reports posture

---

## Stage 6: Intelligence & Scale
**Goal:** ML-based threat detection, multi-relay mesh, on-prem deployment, compliance certifications.
**Milestone:** Production-ready for enterprise with advanced threat detection and geographic relay distribution.

### E6.1 - Anomaly Detection (ML)
**Effort:** 4 weeks
**Dependencies:** E3.2

- [ ] Training pipeline: collect flow metadata from relay, train anomaly model
- [ ] Model: lightweight autoencoder on flow features (size, timing, destination patterns)
- [ ] Quantize to INT8 ONNX model (< 5MB)
- [ ] On-device inference via ort (ONNX Runtime) crate
- [ ] C2 beacon detection: regular interval patterns in flow timing
- [ ] DNS tunneling scoring: entropy + query length features
- [ ] Data exfiltration scoring: unusual upload volume per app
- [ ] Anomaly threshold configuration per policy
- [ ] **MVP:** ML model flags C2 beacons and unusual upload patterns

### E6.2 - Multi-Relay Mesh
**Effort:** 4 weeks
**Dependencies:** E1.4

- [ ] Relay discovery and health checking from control plane
- [ ] Geographic relay assignment (client → nearest healthy relay)
- [ ] Relay failover: automatic migration to next-closest relay
- [ ] Relay-to-relay forwarding (for internal traffic across regions)
- [ ] Relay autoscaling (Kubernetes HPA based on tunnel count)
- [ ] Anycast IP for relay endpoints (BGP-based)
- [ ] **MVP:** 3 relays in different regions, clients auto-assigned, failover works

### E6.3 - On-Premises Deployment
**Effort:** 3 weeks
**Dependencies:** E1.3, E1.4

- [ ] Helm chart for control plane + relay deployment
- [ ] Air-gapped installation support (offline bundles)
- [ ] Customer-managed PostgreSQL configuration
- [ ] Customer-managed CA (bring your own root CA)
- [ ] Backup and restore procedures
- [ ] Upgrade/migration tooling
- [ ] **MVP:** Control plane + relay deployable on customer Kubernetes cluster

### E6.4 - Compliance & Audit
**Effort:** 4 weeks (ongoing)
**Dependencies:** E4.5

- [ ] SOC 2 Type II preparation: controls documentation, evidence collection
- [ ] HIPAA compliance mapping: BAA template, PHI handling documentation
- [ ] GDPR data processing documentation
- [ ] Audit log completeness: every admin action, data access, policy change logged
- [ ] Data retention automation: configurable retention, auto-purge
- [ ] Penetration testing (third-party)
- [ ] Security architecture review (third-party)
- [ ] **MVP:** SOC 2 Type II audit-ready

### E6.5 - Performance Optimization
**Effort:** 3 weeks (ongoing)
**Dependencies:** E3.2, E3.3

- [ ] Zero-copy packet processing (AF_XDP on relay, kqueue on macOS)
- [ ] Arena allocation for packet buffers (bumpalo)
- [ ] mimalloc global allocator
- [ ] Flow cache optimization (10K entries, 97%+ hit rate target)
- [ ] Battery profiling on iOS/Android (Energy Diagnostics, Battery Historian)
- [ ] Load testing: 10K concurrent tunnels per relay
- [ ] Latency benchmarking: <2ms overhead target
- [ ] Memory profiling: <50MB RSS target on all platforms
- [ ] **MVP:** Meet all resource budget targets from architecture doc

### E6.6 - Auto-Update & Fleet Management
**Effort:** 2 weeks
**Dependencies:** E4.4

- [ ] Signed update packages per platform
- [ ] Control plane update distribution (staged rollout by group/percentage)
- [ ] Client self-update: download, verify signature, apply
- [ ] Rollback capability on update failure
- [ ] Version pinning per group (e.g., keep beta group on canary)
- [ ] Fleet version dashboard
- [ ] **MVP:** macOS auto-updates via control plane, staged rollout

---

## Dependency Graph

```
Stage 1: Foundation
  E1.1 ──► E1.2 ──► E1.4 (relay)
  E1.1 ──► E1.3 (API)
  E1.2 ──► E1.5 (macOS NE) ──► E1.6 (UI)

Stage 2: Identity & Posture
  E1.3 ──► E2.1 (SSO) ──► E2.2 (SCIM)
  E1.2 + E1.5 ──► E2.3 (device identity)
  E1.1 ──► E2.4 (osquery)
  E2.3 + E2.4 + E1.3 ──► E2.5 (posture engine)
  E2.2 + E2.5 ──► E2.6 (policy engine)

Stage 3: Traffic Intelligence
  E1.5 ──► E3.1 (DNS) + E3.2 (content filter)
  E3.2 ──► E3.3 (TLS inspection)
  E3.3 ──► E3.4 (DLP)
  E3.3 + E3.4 ──► E3.5 (session-aware DLP)
  E3.4 + E3.5 ──► E3.6 (shadow copy)

Stage 4: Enterprise
  E2.5 + E2.1 ──► E4.1 (IdP signaling)
  E1.3 ──► E4.2 (SIEM)
  E2.3 + E1.5 ──► E4.3 (tamper resistance)
  E1.5 + E3.3 ──► E4.4 (MDM deployment)
  E2.2 + E2.5 + E3.6 + E4.2 ──► E4.5 (dashboard)

Stage 5: Cross-Platform
  E1.5 ──► E5.1 (iOS)
  E1.2 ──► E5.2 (Android) ──► E5.4 (ChromeOS)
  E1.2 ──► E5.3 (Windows)
  E1.2 ──► E5.5 (Linux)

Stage 6: Intelligence & Scale
  E3.2 ──► E6.1 (ML)
  E1.4 ──► E6.2 (multi-relay)
  E1.3 + E1.4 ──► E6.3 (on-prem)
  E4.5 ──► E6.4 (compliance)
  E3.2 + E3.3 ──► E6.5 (performance)
  E4.4 ──► E6.6 (auto-update)
```

---

## Timeline Summary

| Stage | Duration | Team Size | End State |
|---|---|---|---|
| **1. Foundation** | 6 weeks | 2-3 engineers | macOS tunnel works through relay |
| **2. Identity & Posture** | 8 weeks | 3-4 engineers | SSO, osquery posture, tiered access |
| **3. Traffic Intelligence** | 10 weeks | 3-4 engineers | DNS filtering, TLS inspection, DLP, shadow copy |
| **4. Enterprise** | 8 weeks | 3-4 engineers | IdP signaling, SIEM, MDM, admin dashboard |
| **5. Cross-Platform** | 10 weeks | 4-5 engineers | iOS, Android, Windows, ChromeOS, Linux |
| **6. Intelligence & Scale** | 12 weeks | 4-5 engineers | ML detection, multi-relay, on-prem, compliance |

**Total estimated effort:** ~54 weeks with parallel execution across team.
**Solo developer realistic timeline:** Stage 1-3 achievable in ~6 months. Full product in ~18 months.

---

## Critical Path

The fastest path to a demonstrable product:

```
E1.1 → E1.2 → E1.5 → E1.6        macOS client with WireGuard tunnel
       E1.3                        Control plane API (parallel with E1.2)
       E1.4                        Relay (parallel with E1.5)
              → E2.1               SSO (after E1.3)
              → E2.4 → E2.5       osquery + posture (parallel with SSO)
                     → E3.1       DNS filtering (after E1.5)
                     → E3.2 → E3.3 → E3.4   TLS inspection + DLP
```

**Weeks 1-6:** Working tunnel (Stage 1)
**Weeks 7-14:** SSO + posture gating (Stage 2)
**Weeks 15-24:** Traffic inspection + DLP (Stage 3)

At week 24 (~6 months), you have a compelling macOS product demo: SSO-authenticated, posture-gated, DLP-enforced, per-app tunneling with shadow copy.

---

## MVP Feature Matrix (What Ships First)

| Feature | Stage 1 | Stage 2 | Stage 3 | Stage 4 |
|---|---|---|---|---|
| WireGuard tunnel | Single tunnel | Multi-tunnel | Multi-tunnel | Multi-tunnel |
| Platform | macOS only | macOS only | macOS only | macOS + MDM |
| Auth | Enrollment token | SSO (Okta) | SSO | SSO + SCIM |
| Posture | None | Score + tiers | Score + tiers | Score + IdP signal |
| DLP | None | None | Pattern + session-aware | + shadow copy |
| DNS | None | None | Filtered + logged | Filtered + logged |
| TLS inspection | None | None | Selective MITM | Selective MITM |
| Admin UI | None | Basic | Full | Full + SIEM config |
| SIEM | None | None | None | Splunk + Syslog |
