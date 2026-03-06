# Bridge

**Zero-trust network security with per-app micro-tunnels, inline traffic intelligence, and continuous device posture.**

Bridge combines WireGuard tunneling with intelligent traffic inspection to provide identity-aware, application-level network security across macOS, iOS, Android, Windows, ChromeOS, and Linux.

---

## What Makes Bridge Different

| Capability | How It Works |
|---|---|
| **Per-App Micro-Tunnels** | Each application gets its own isolated WireGuard tunnel with its own policy. A compromised app can't pivot to other network paths. |
| **Inline Traffic Intelligence** | Selective TLS inspection, DLP, C2 detection, and anomaly scoring - built into the tunnel, not bolted on. |
| **Identity-Aware DLP** | Detects personal vs. corporate account sessions. Shadow copies uploads to unsanctioned services for audit. |
| **Continuous Posture (osquery)** | SQL-queryable device health checks. Admins write posture policies as osquery queries. Posture score determines access tier. |
| **Tiered Access** | Device posture score controls which resources are accessible. Outdated OS? You keep Slack but lose Salesforce. |
| **Tamper Resistance** | The agent IS the access gate. Disable it = lose access to everything. No incentive to tamper. |
| **Split-Knowledge Privacy** | Control plane never sees traffic. Data plane never sees identity. No single component can correlate both. |
| **Cryptographic Device Identity** | Hardware-bound keys (TPM/Secure Enclave). Stolen credentials alone can't impersonate a device. |
| **SSO + Bidirectional IdP Signals** | Okta/Azure AD/Google SSO with posture signals fed BACK to the IdP. Bridge posture protects ALL apps, not just tunneled ones. |
| **SIEM/SOAR Integration** | Structured events to Splunk, Wazuh, Google SecOps, Elastic, Sentinel. Pre-built decoders, dashboards, and SOAR playbooks. |

## Architecture

```
┌────────────────┐       ┌──────────────┐       ┌─────────────────┐
│  Bridge Client │◄═════►│ Bridge Relay  │       │ Bridge Control  │
│                │  WG   │ (Data Plane)  │◄─────►│ Plane (API)     │
│ - Per-app VPN  │Tunnels│ - Inspection  │Policy │ - Auth/Identity │
│ - DNS proxy    │       │ - DLP engine  │ Sync  │ - Policy engine │
│ - Posture agent│       │ - Threat det. │       │ - Device registry│
│ - osquery      │       │ - Shadow copy │       │ - Admin dashboard│
└────────────────┘       └──────────────┘       └─────────────────┘
```

## Tech Stack

- **Core:** Rust (cross-platform, memory-safe, high-performance)
- **WireGuard:** boringtun (Cloudflare's userspace WireGuard, BSD-3)
- **TLS Inspection:** rustls + custom MITM layer (inspired by mitmproxy's architecture)
- **Endpoint Telemetry:** osquery (Apache 2.0, 300+ OS tables)
- **API Server:** Rust + Axum
- **Database:** PostgreSQL
- **Dashboard:** Next.js + TypeScript
- **IPC:** gRPC (tonic) with protobuf
- **ML Inference:** ONNX Runtime (anomaly detection)

## Platform Support

| Platform | UI | VPN API | Posture |
|---|---|---|---|
| macOS | SwiftUI | NEPacketTunnelProvider | osquery + native |
| iOS | SwiftUI | NEPacketTunnelProvider | Native APIs |
| Android | Jetpack Compose | VpnService | Native APIs |
| Windows | WinUI 3 | WFP + Wintun | osquery + native |
| ChromeOS | Android app + Chrome extension | VpnService (via ARC++) | Android APIs |
| Linux | GTK4 / CLI | nftables + eBPF | osquery + native |

## Documentation

- [Product Vision](docs/PRODUCT_VISION.md) - What we're building and why
- [Architecture](docs/ARCHITECTURE.md) - Technical architecture and design decisions
- [Protocol Specification](docs/PROTOCOL.md) - Wire protocols, API contracts, and security model
- [Epics & Stages](docs/EPICS.md) - Development epics, stages, dependencies, and timeline
- [Cutting-Edge Tech](docs/CUTTING_EDGE.md) - Post-quantum crypto, eBPF, confidential computing, WASM extensions
- [Infrastructure & Resilience](docs/INFRASTRUCTURE.md) - Server architecture, failover, disaster recovery
- [Brand Identity](docs/BRAND.md) - Logo concept (card bridge), colors, voice

## Project Status

Pre-development. Architecture, protocol, and epic planning complete. Ready to scaffold code.