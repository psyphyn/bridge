//! macOS-specific network configuration.
//!
//! Uses `networksetup` to configure the system DNS resolver
//! to point at Bridge's local DNS proxy. This allows us to
//! intercept DNS queries for domain-based routing and filtering.

use std::process::Command;
use std::sync::OnceLock;

/// Stores the original DNS servers so we can restore them on shutdown.
static ORIGINAL_DNS: OnceLock<(String, Vec<String>)> = OnceLock::new();

/// Get the primary network service name (e.g., "Wi-Fi", "Ethernet").
pub fn primary_network_service() -> Option<String> {
    // Get the default route interface
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let interface = stdout
        .lines()
        .find(|l| l.contains("interface:"))?
        .split(':')
        .nth(1)?
        .trim()
        .to_string();

    // Map interface to network service name
    let output = Command::new("networksetup")
        .args(["-listallhardwareports"])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut current_service = None;

    for line in stdout.lines() {
        if let Some(name) = line.strip_prefix("Hardware Port: ") {
            current_service = Some(name.to_string());
        } else if let Some(dev) = line.strip_prefix("Device: ") {
            if dev.trim() == interface {
                return current_service;
            }
        }
    }

    None
}

/// Get the current DNS servers for a network service.
fn get_dns_servers(service: &str) -> Vec<String> {
    let output = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("There aren't any DNS Servers") {
                vec![] // Using DHCP DNS
            } else {
                stdout
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect()
            }
        }
        Err(_) => vec![],
    }
}

/// Configure the system to use Bridge's local DNS proxy.
pub async fn configure_dns(proxy_addr: &str) -> anyhow::Result<()> {
    let service = primary_network_service()
        .ok_or_else(|| anyhow::anyhow!("Could not determine primary network service"))?;

    // Save original DNS before overwriting
    let original = get_dns_servers(&service);
    let _ = ORIGINAL_DNS.set((service.clone(), original.clone()));

    tracing::info!(
        service = %service,
        original_dns = ?original,
        proxy = %proxy_addr,
        "Configuring system DNS"
    );

    // Extract just the IP from "127.0.0.1:5353" -> "127.0.0.1"
    let proxy_ip = proxy_addr
        .split(':')
        .next()
        .unwrap_or("127.0.0.1");

    // Set the DNS server to our proxy
    // Note: macOS networksetup only sets port 53 DNS. For non-standard ports,
    // we'd need to use a local resolver that listens on 53 and forwards to 5353.
    // For now, log a note about this limitation.
    if proxy_addr.contains(":53") && !proxy_addr.contains(":5353") {
        // Standard port 53 — can use networksetup directly
        let status = Command::new("networksetup")
            .args(["-setdnsservers", &service, proxy_ip])
            .status()?;

        if !status.success() {
            anyhow::bail!("Failed to set DNS servers via networksetup");
        }

        tracing::info!(service = %service, dns = %proxy_ip, "System DNS configured");
    } else {
        // Non-standard port — can't use networksetup directly
        // The daemon's DNS proxy runs on 5353, which requires apps to be configured
        // individually or a local resolver on port 53 that forwards to 5353.
        tracing::info!(
            proxy = %proxy_addr,
            "DNS proxy running on non-standard port. \
             Apps using the VPN tunnel will have DNS intercepted via the Network Extension. \
             System-wide DNS interception requires running the proxy on port 53 (needs root)."
        );
    }

    Ok(())
}

/// Restore the system DNS to its original configuration.
pub async fn restore_dns() -> anyhow::Result<()> {
    let (service, original) = match ORIGINAL_DNS.get() {
        Some(o) => o,
        None => {
            tracing::debug!("No original DNS to restore");
            return Ok(());
        }
    };

    if original.is_empty() {
        // Was using DHCP DNS — clear manual DNS
        let status = Command::new("networksetup")
            .args(["-setdnsservers", service, "empty"])
            .status()?;

        if !status.success() {
            tracing::warn!("Failed to clear DNS servers");
        }
    } else {
        // Restore original DNS servers
        let mut args = vec!["-setdnsservers".to_string(), service.clone()];
        args.extend(original.iter().cloned());

        let str_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let status = Command::new("networksetup")
            .args(&str_args)
            .status()?;

        if !status.success() {
            tracing::warn!("Failed to restore DNS servers");
        }
    }

    tracing::info!(service = %service, "System DNS restored");
    Ok(())
}
