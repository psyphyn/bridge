//! Bridge daemon - background service that manages tunnels, posture, and IPC.
//!
//! On startup:
//! 1. Generates cryptographic device identity (Ed25519)
//! 2. Generates WireGuard keypair
//! 3. Creates attestation token with posture score
//! 4. Registers with the control plane
//! 5. Establishes WireGuard tunnels
//! 6. Runs heartbeat and posture reporting loops

use std::sync::Arc;
use std::time::Instant;

use base64::Engine;
use bridge_core::api_types::DeviceRegistrationRequest;
use bridge_core::identity::{
    self, DeviceAttestation,
};
use bridge_core::posture::{self, AccessTier};
use bridge_core::routing::{AppRouter, RouterConfig, TunnelGroup, DefaultRoute};
use bridge_core::tunnel::{TunnelConfig, TunnelManager};
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

mod control_plane;

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

    // ── Step 1: Generate cryptographic device identity ──
    let (identity_private_key, identity_public_key) =
        identity::generate_identity_keypair()
            .map_err(|e| anyhow::anyhow!("Identity key generation failed: {}", e))?;

    let identity_pub_b64 =
        base64::engine::general_purpose::STANDARD.encode(&identity_public_key);
    let device_id = identity::device_id_from_public_key(&identity_public_key);
    tracing::info!(%device_id, "Device identity established");

    // Collect device info
    let platform = std::env::consts::OS.to_string();
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // ── Step 2: Generate WireGuard keypair ──
    let (device_private_key, device_public_key) = bridge_core::tunnel::generate_keypair();
    tracing::info!(wg_public_key = %device_public_key, "WireGuard keypair generated");

    // ── Step 3: Create attestation token ──
    let attestation = DeviceAttestation::new(
        identity_private_key.clone(),
        identity_public_key.clone(),
        &platform,
    );

    // Initial posture: assume standard until we run checks
    let initial_score = 75;
    let initial_tier = AccessTier::from_score(initial_score);

    let token = attestation
        .attest(initial_score, initial_tier, 3600)
        .map_err(|e| anyhow::anyhow!("Attestation failed: {}", e))?;

    tracing::info!(
        posture_score = initial_score,
        access_tier = %initial_tier,
        "Initial attestation token created"
    );

    // ── Step 4: Register with control plane ──
    let mut cp_client = ControlPlaneClient::new(&api_url);

    let registration = cp_client
        .register(DeviceRegistrationRequest {
            device_public_key: device_public_key.clone(),
            identity_public_key: Some(identity_pub_b64.clone()),
            attestation_token: Some(token.to_compact()),
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

    // ── Step 5: Establish WireGuard tunnels ──
    let mut tunnel_mgr = TunnelManager::new();
    let mut event_rx = tunnel_mgr.take_event_receiver().unwrap();

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

    // ── Step 5b: Initialize per-app router ──
    let default_tunnel_id = registration.tunnels.first().map(|t| t.tunnel_id);

    let router_config = RouterConfig {
        groups: vec![
            TunnelGroup {
                name: "browsers".to_string(),
                tunnel_id: default_tunnel_id.unwrap_or_default(),
                applications: vec![
                    "com.apple.Safari".to_string(),
                    "com.google.Chrome".to_string(),
                    "org.mozilla.firefox".to_string(),
                    "com.microsoft.edgemac".to_string(),
                ],
                domains: vec![],
                ip_ranges: vec![],
                priority: 1,
            },
            TunnelGroup {
                name: "dev-tools".to_string(),
                tunnel_id: default_tunnel_id.unwrap_or_default(),
                applications: vec![
                    "com.apple.Terminal".to_string(),
                    "com.microsoft.VSCode".to_string(),
                    "com.todesktop.230313mzl4w4u92".to_string(), // Cursor
                ],
                domains: vec!["*.github.com".to_string(), "*.gitlab.com".to_string()],
                ip_ranges: vec![],
                priority: 2,
            },
        ],
        default_tunnel: default_tunnel_id,
        bypass_apps: vec![
            "com.apple.Music".to_string(),
            "com.apple.TV".to_string(),
        ],
        bypass_domains: vec![
            "*.apple.com".to_string(),
            "*.icloud.com".to_string(),
        ],
        default_route: DefaultRoute::TunnelAll,
    };

    let router = Arc::new(tokio::sync::RwLock::new(AppRouter::new(router_config)));
    tracing::info!(
        groups = router.read().await.groups().len(),
        default_tunnel = ?default_tunnel_id,
        "Per-app router initialized"
    );

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

    // ── Step 6: Heartbeat + posture loop ──
    let attestation = Arc::new(Mutex::new(attestation));
    let cp_heartbeat = ControlPlaneClient::new(&api_url);

    let attestation_clone = attestation.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let uptime = start_time.elapsed().as_secs();

            // Run posture checks and create fresh attestation
            let posture_score = run_posture_checks().await;
            let access_tier = AccessTier::from_score(posture_score);

            let token = {
                let att = attestation_clone.lock().await;
                att.attest(posture_score, access_tier, 300) // 5 min TTL for heartbeat tokens
            };

            let attestation_compact = match token {
                Ok(t) => Some(t.to_compact()),
                Err(e) => {
                    tracing::warn!(%e, "Failed to create attestation token");
                    None
                }
            };

            match cp_heartbeat
                .heartbeat_with_attestation(
                    registration.device_id,
                    1, // active tunnels
                    uptime,
                    attestation_compact,
                )
                .await
            {
                Ok(_) => tracing::debug!(
                    posture_score,
                    %access_tier,
                    "Heartbeat sent with attestation"
                ),
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

/// Run local posture checks and return a score.
async fn run_posture_checks() -> u8 {
    // Build posture checks from available system state
    let checks = vec![
        posture::PostureCheck {
            name: "os_current".to_string(),
            passed: true, // TODO: check actual OS version freshness
            weight: 30,
            detail: None,
        },
        posture::PostureCheck {
            name: "disk_encryption".to_string(),
            passed: check_disk_encryption(),
            weight: 25,
            detail: None,
        },
        posture::PostureCheck {
            name: "firewall_enabled".to_string(),
            passed: check_firewall(),
            weight: 15,
            detail: None,
        },
        posture::PostureCheck {
            name: "screen_lock".to_string(),
            passed: true, // TODO: check actual screen lock
            weight: 10,
            detail: None,
        },
        posture::PostureCheck {
            name: "sip_enabled".to_string(),
            passed: check_sip(),
            weight: 20,
            detail: None,
        },
    ];

    posture::calculate_score(&checks)
}

fn check_disk_encryption() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("fdesetup")
            .arg("isactive")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        true // Assume OK on non-macOS for now
    }
}

fn check_firewall() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
            .arg("--getglobalstate")
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("enabled")
            })
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

fn check_sip() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("csrutil")
            .arg("status")
            .output()
            .map(|o| {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("enabled")
            })
            .unwrap_or(false)
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
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
