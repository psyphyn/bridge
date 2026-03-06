//! Bridge daemon - background service that manages tunnels, posture, and IPC.
//!
//! On startup:
//! 1. Generates a device keypair
//! 2. Registers with the control plane
//! 3. Receives tunnel configuration
//! 4. Establishes WireGuard tunnels
//! 5. Runs heartbeat and posture reporting loops

use std::time::Instant;

use bridge_core::api_types::DeviceRegistrationRequest;
use bridge_core::tunnel::{TunnelConfig, TunnelManager};
use tracing_subscriber::EnvFilter;

mod control_plane;
mod platform;

use control_plane::ControlPlaneClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Bridge daemon v{} starting", bridge_core::VERSION);

    let api_url = std::env::var("BRIDGE_API_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    // Generate device keypair
    let (device_private_key, device_public_key) = bridge_core::tunnel::generate_keypair();
    tracing::info!(public_key = %device_public_key, "Device keypair generated");

    // Collect device info
    let platform = std::env::consts::OS.to_string();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Register with control plane
    let mut cp_client = ControlPlaneClient::new(&api_url);

    let registration = cp_client
        .register(DeviceRegistrationRequest {
            device_public_key: device_public_key.clone(),
            platform: platform.clone(),
            os_version: os_version(),
            hardware_model: hardware_model(),
            hostname,
        })
        .await?;

    tracing::info!(
        device_id = %registration.device_id,
        tunnels = registration.tunnels.len(),
        "Registration complete"
    );

    // Initialize tunnel manager
    let mut tunnel_mgr = TunnelManager::new();
    let mut event_rx = tunnel_mgr.take_event_receiver().unwrap();

    // Set up tunnels from registration response
    for assignment in &registration.tunnels {
        let config = TunnelConfig {
            id: assignment.tunnel_id,
            private_key: device_private_key.clone(),
            peer_public_key: assignment.server_public_key.clone(),
            peer_endpoint: assignment.server_endpoint.parse()?,
            allowed_ips: assignment.allowed_ips.clone(),
            dns: assignment.dns.clone(),
            keepalive_secs: assignment.keepalive_secs,
        };

        tunnel_mgr.add_tunnel(config).await;
        tunnel_mgr.connect(assignment.tunnel_id).await?;
    }

    let start_time = Instant::now();

    // Spawn event logger
    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            match event {
                bridge_core::tunnel::TunnelEvent::StateChanged { tunnel_id, new_state, .. } => {
                    tracing::info!(%tunnel_id, %new_state, "Tunnel state changed");
                }
                bridge_core::tunnel::TunnelEvent::HandshakeComplete { tunnel_id } => {
                    tracing::info!(%tunnel_id, "WireGuard handshake complete");
                }
                bridge_core::tunnel::TunnelEvent::PacketReceived { tunnel_id, bytes } => {
                    tracing::debug!(%tunnel_id, bytes, "Packet received");
                }
                bridge_core::tunnel::TunnelEvent::Error { tunnel_id, error } => {
                    tracing::error!(%tunnel_id, %error, "Tunnel error");
                }
            }
        }
    });

    // Spawn heartbeat loop
    let cp_heartbeat = ControlPlaneClient::new(&api_url);
    // Re-register to get the device_id set (simple approach for now)
    let _device_id = registration.device_id;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let uptime = start_time.elapsed().as_secs();
            match cp_heartbeat.heartbeat(0, uptime).await {
                Ok(_) => tracing::debug!("Heartbeat sent"),
                Err(e) => tracing::warn!(%e, "Heartbeat failed"),
            }
        }
    });

    tracing::info!("Bridge daemon running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");

    // Disconnect all tunnels
    for (id, _state) in tunnel_mgr.list_tunnels().await {
        let _ = tunnel_mgr.disconnect(id).await;
    }

    Ok(())
}

fn os_version() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::env::consts::OS.to_string()
    }
}

fn hardware_model() -> String {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.model"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(target_os = "macos"))]
    {
        "unknown".to_string()
    }
}
