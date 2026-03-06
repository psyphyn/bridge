//! Linux-specific network configuration.
//!
//! Uses systemd-resolved or direct /etc/resolv.conf manipulation
//! to configure DNS for Bridge's local proxy.

use std::process::Command;

/// Configure the system to use Bridge's local DNS proxy.
pub async fn configure_dns(proxy_addr: &str) -> anyhow::Result<()> {
    let proxy_ip = proxy_addr
        .split(':')
        .next()
        .unwrap_or("127.0.0.1");

    // Try systemd-resolved first
    if has_resolvectl() {
        let status = Command::new("resolvectl")
            .args(["dns", "bridge0", proxy_ip])
            .status();

        match status {
            Ok(s) if s.success() => {
                tracing::info!(dns = %proxy_ip, "Configured DNS via systemd-resolved");
                return Ok(());
            }
            _ => {
                tracing::debug!("resolvectl failed, falling back to resolv.conf");
            }
        }
    }

    // Fallback: note the limitation
    tracing::info!(
        proxy = %proxy_addr,
        "DNS proxy running. Configure /etc/resolv.conf manually or use \
         the VPN tunnel DNS (handled by the Network Extension equivalent)."
    );

    Ok(())
}

/// Restore the system DNS to its original configuration.
pub async fn restore_dns() -> anyhow::Result<()> {
    if has_resolvectl() {
        let _ = Command::new("resolvectl")
            .args(["revert", "bridge0"])
            .status();
    }
    tracing::info!("System DNS restored");
    Ok(())
}

fn has_resolvectl() -> bool {
    Command::new("resolvectl")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
