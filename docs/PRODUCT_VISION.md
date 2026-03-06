# Bridge - Product Vision

## What is Bridge?

Bridge is a zero-trust network security platform that combines WireGuard tunneling with intelligent traffic inspection to provide per-app, identity-aware network security for enterprises and individuals.

## The Problem

Current solutions force a tradeoff:
- **Traditional VPNs** (Cisco AnyConnect, OpenVPN): Route all traffic through a central gateway. Slow, fragile, no granular policy.
- **Zero-trust proxies** (Zscaler, Cloudflare WARP): Better routing but limited to HTTP/S. Can't inspect or control arbitrary protocols.
- **Endpoint protection** (Jamf Protect, CrowdStrike): Great device posture but weak network-layer controls.
- **Mesh VPNs** (Tailscale, Nebula): Excellent connectivity but no traffic inspection or threat detection.

Nobody does all four well: **fast tunneling + deep inspection + device posture + per-app policy**.

## What Bridge Does Differently

### 1. Per-App Micro-Tunnels
Instead of routing all device traffic through a VPN, Bridge creates isolated WireGuard tunnels per application. Slack gets its own tunnel with its own policy. A browser gets a different one. A compromised app can't pivot to other network paths.

### 2. Inline Traffic Intelligence
Bridge runs a lightweight inspection engine (built on mitmproxy's core) that can:
- Selectively decrypt TLS for managed apps (with user/admin consent and certificate pinning awareness)
- Detect data exfiltration patterns (DLP) in real-time
- Block C2 callbacks, DNS tunneling, and suspicious protocol usage
- Apply ML-based anomaly detection on traffic metadata without full decryption

### 3. Identity-Aware DLP & Shadow Copy
Bridge goes beyond pattern matching - it understands **who** is logged in and **where** data is going:
- Detect personal vs. corporate account sessions on the same SaaS platform
- Shadow copy uploads to personal/unsanctioned services (e.g., personal Google Docs) seamlessly without disrupting the user
- Upload monitoring across HTTP, WebSocket, cloud storage APIs, and email
- Shadow copies are encrypted, customer-controlled, and available for forensic review
- Shadow IT detection: alert on unsanctioned SaaS usage

### 4. Cryptographic Device Identity
Every device gets a hardware-bound identity (TPM/Secure Enclave). Authentication isn't just "user + password" - it's "this specific device, in this posture state, running this app, for this user." Compromised credentials alone aren't enough.

### 5. Continuous Posture Assessment (with osquery)
Bridge continuously evaluates device health using native APIs and **osquery** (Apache 2.0):
- OS patch level, disk encryption status, firewall state
- Running process integrity (is the endpoint agent tampered with?)
- Network environment risk (public WiFi vs corporate LAN)
- Jailbreak/root detection on mobile
- **osquery-powered deep checks:** browser extensions, unsigned binaries, USB devices, listening ports, installed software CVEs
- Admins write posture checks as SQL queries - no code changes needed
- 300+ osquery tables for processes, hardware, network, certificates, and more

Policy decisions happen continuously, not just at connection time.

### 6. Split-Knowledge Architecture
The control plane never sees user traffic. The data plane never sees policy decisions. No single component (or employee) can both see traffic AND know who it belongs to. This is a structural privacy guarantee, not a policy promise.

### 7. SSO with Bidirectional Posture Signals
Bridge doesn't just consume identity from Okta/Azure AD/Google - it **feeds posture back**:
- SSO via OIDC/SAML with any major IdP (Okta, Azure AD, Google, Ping, JumpCloud)
- SCIM user/group sync for policy targeting
- **Posture signals sent TO the IdP** via Okta Device Trust API, Azure Conditional Access, Google Context-Aware Access
- Bridge detects unhealthy device → signals Okta → Okta revokes access to ALL apps (not just Bridge-tunneled ones)
- Shared Signals Framework (SSF/CAEP) for real-time security event exchange

### 8. SIEM/SOAR Integration
Every security event is exportable to your SOC's tools:
- Native integrations: Splunk (HEC), Google SecOps (Chronicle), Wazuh, Elastic, Microsoft Sentinel
- Universal: Syslog (CEF/JSON), webhooks, S3/GCS batch export
- Pre-built decoders, dashboards, and SOAR playbooks
- Structured event taxonomy with consistent schema across all event types

## Target Users

### Phase 1: SMB & Startups (1-500 employees)
- Replaces VPN + basic endpoint protection
- Self-serve deployment, no hardware required
- Pricing: per-device/month SaaS

### Phase 2: Enterprise (500+ employees)
- Compliance features (SOC2, HIPAA, FedRAMP)
- On-prem control plane option
- SIEM/SOAR integrations
- Custom policy engine

### Phase 3: Consumer Privacy
- Personal privacy product (like Mullvad meets Little Snitch)
- Per-app firewall with traffic visibility
- Ad/tracker blocking at the network level

## Competitive Positioning

| Feature | Tailscale | Cloudflare WARP | Jamf Protect | **Bridge** |
|---|---|---|---|---|
| WireGuard tunneling | Yes | Yes | No | **Yes** |
| Per-app tunnels | No | No | No | **Yes** |
| Traffic inspection | No | HTTP only | Limited | **Full stack** |
| Device posture | Basic | Basic | Yes | **Yes** |
| DLP | No | Add-on | No | **Built-in** |
| Split-knowledge privacy | No | No | N/A | **Yes** |
| Posture → IdP signaling | No | No | No | **Yes (Okta, Azure, Google)** |
| SIEM integration | Basic | Basic | Jamf Pro only | **Splunk, Wazuh, Chronicle, Elastic, Sentinel** |
| Self-hosted option | Yes (Headscale) | No | No | **Yes** |
| Cross-platform | Yes | Yes | Apple only | **Yes (incl. ChromeOS, Linux)** |
