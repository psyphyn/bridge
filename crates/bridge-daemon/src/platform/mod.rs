//! Platform-specific implementations.
//!
//! Each platform has different VPN APIs:
//! - macOS/iOS: NEPacketTunnelProvider
//! - Android: VpnService
//! - Windows: WFP + Wintun
//! - Linux: nftables + eBPF
