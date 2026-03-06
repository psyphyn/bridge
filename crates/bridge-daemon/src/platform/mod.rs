//! Platform-specific implementations.
//!
//! Each platform has different VPN APIs:
//! - macOS/iOS: NEPacketTunnelProvider
//! - Android: VpnService
//! - Windows: WFP + Wintun
//! - Linux: nftables + eBPF

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

/// Configure the system to use Bridge's local DNS proxy.
pub async fn configure_dns(proxy_addr: &str) -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::configure_dns(proxy_addr).await
    }
    #[cfg(target_os = "linux")]
    {
        linux::configure_dns(proxy_addr).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = proxy_addr;
        tracing::warn!("DNS configuration not implemented for this platform");
        Ok(())
    }
}

/// Restore the system DNS to its original configuration.
pub async fn restore_dns() -> anyhow::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::restore_dns().await
    }
    #[cfg(target_os = "linux")]
    {
        linux::restore_dns().await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        tracing::warn!("DNS restoration not implemented for this platform");
        Ok(())
    }
}

/// Get the primary network service name (macOS-specific, used for DNS config).
#[cfg(target_os = "macos")]
pub fn primary_network_service() -> Option<String> {
    macos::primary_network_service()
}
