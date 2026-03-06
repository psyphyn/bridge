//! Shared API types used by both the control plane (bridge-api) and clients (bridge-daemon).
//!
//! These types define the REST API contract between client and server.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Device Registration ──────────────────────────────────────────────

/// Request to register a new device with the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    /// Base64-encoded device public key (x25519).
    pub device_public_key: String,
    /// Platform identifier (macos, ios, android, windows, linux, chromeos).
    pub platform: String,
    /// OS version string.
    pub os_version: String,
    /// Hardware model (e.g., "MacBookPro18,1").
    pub hardware_model: String,
    /// Hostname of the device.
    pub hostname: String,
}

/// Response after successful device registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationResponse {
    /// Unique device ID assigned by the control plane.
    pub device_id: Uuid,
    /// Tunnel configurations assigned to this device.
    pub tunnels: Vec<TunnelAssignment>,
}

/// A tunnel configuration assigned to a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelAssignment {
    /// Tunnel ID.
    pub tunnel_id: Uuid,
    /// Server (relay) public key for this tunnel.
    pub server_public_key: String,
    /// Relay endpoint (host:port).
    pub server_endpoint: String,
    /// Allowed IP ranges routed through this tunnel.
    pub allowed_ips: Vec<String>,
    /// DNS servers for this tunnel.
    pub dns: Vec<String>,
    /// Keepalive interval in seconds.
    pub keepalive_secs: Option<u16>,
}

// ─── Posture ──────────────────────────────────────────────────────────

/// Posture report submitted by the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReportRequest {
    pub device_id: Uuid,
    pub os_patch_age_days: u32,
    pub disk_encrypted: bool,
    pub firewall_enabled: bool,
    pub screen_lock_enabled: bool,
    pub osquery_results: Vec<OsqueryCheckResult>,
}

/// Result of an individual osquery posture check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsqueryCheckResult {
    pub query_name: String,
    pub passed: bool,
    pub raw_json: Option<String>,
}

/// Response to a posture report with updated access tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureReportResponse {
    pub posture_score: u8,
    pub access_tier: String,
    /// Updated tunnel assignments (may change based on posture).
    pub tunnels: Vec<TunnelAssignment>,
}

// ─── Heartbeat ────────────────────────────────────────────────────────

/// Periodic heartbeat from client to control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub device_id: Uuid,
    pub active_tunnels: u32,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatResponse {
    /// If true, client should re-fetch tunnel config.
    pub config_changed: bool,
}
