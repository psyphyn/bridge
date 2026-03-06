//! Device registration and management endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use chrono::Utc;
use uuid::Uuid;

use bridge_core::api_types::{
    DeviceRegistrationRequest, DeviceRegistrationResponse, HeartbeatRequest, HeartbeatResponse,
    PostureReportRequest, PostureReportResponse, TunnelAssignment,
};
use bridge_core::posture::AccessTier;

use crate::models::Device;
use crate::state::AppState;

/// POST /api/v1/devices/register
///
/// Register a new device. Returns device ID and initial tunnel configuration.
pub async fn register_device(
    State(state): State<AppState>,
    Json(req): Json<DeviceRegistrationRequest>,
) -> Result<Json<DeviceRegistrationResponse>, StatusCode> {
    let device_id = Uuid::new_v4();
    let now = Utc::now();

    let device = Device {
        id: device_id,
        device_public_key: req.device_public_key.clone(),
        platform: req.platform.clone(),
        os_version: req.os_version,
        hardware_model: req.hardware_model,
        hostname: req.hostname,
        registered_at: now,
        last_seen: now,
        posture_score: 100, // Full access until first posture check
        access_tier: "full_access".to_string(),
    };

    tracing::info!(
        device_id = %device_id,
        platform = %req.platform,
        "Device registered"
    );

    state.devices.write().await.insert(device_id, device);

    // Assign default tunnel to the new device
    let tunnel = TunnelAssignment {
        tunnel_id: Uuid::new_v4(),
        server_public_key: state.relay.public_key.clone(),
        server_endpoint: state.relay.endpoint.clone(),
        allowed_ips: vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        dns: vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
        keepalive_secs: Some(25),
    };

    Ok(Json(DeviceRegistrationResponse {
        device_id,
        tunnels: vec![tunnel],
    }))
}

/// POST /api/v1/devices/posture
///
/// Submit a posture report. Returns updated posture score and access tier.
pub async fn report_posture(
    State(state): State<AppState>,
    Json(req): Json<PostureReportRequest>,
) -> Result<Json<PostureReportResponse>, StatusCode> {
    let mut devices = state.devices.write().await;
    let device = devices
        .get_mut(&req.device_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    // Calculate posture score
    let mut score: u8 = 100;

    if req.os_patch_age_days > 90 {
        score = score.saturating_sub(40);
    } else if req.os_patch_age_days > 30 {
        score = score.saturating_sub(15);
    }

    if !req.disk_encrypted {
        score = score.saturating_sub(25);
    }

    if !req.firewall_enabled {
        score = score.saturating_sub(15);
    }

    if !req.screen_lock_enabled {
        score = score.saturating_sub(10);
    }

    // Deduct for failed osquery checks
    for check in &req.osquery_results {
        if !check.passed {
            score = score.saturating_sub(10);
        }
    }

    let tier = AccessTier::from_score(score);
    let tier_name = format!("{:?}", tier).to_lowercase();

    device.posture_score = score;
    device.access_tier = tier_name.clone();
    device.last_seen = Utc::now();

    tracing::info!(
        device_id = %req.device_id,
        score = score,
        tier = %tier_name,
        "Posture updated"
    );

    // Return tunnel config based on access tier
    let tunnels = match tier {
        AccessTier::Quarantined => vec![], // No tunnels in quarantine
        _ => vec![TunnelAssignment {
            tunnel_id: Uuid::new_v4(),
            server_public_key: state.relay.public_key.clone(),
            server_endpoint: state.relay.endpoint.clone(),
            allowed_ips: match tier {
                AccessTier::FullAccess => vec!["0.0.0.0/0".to_string()],
                AccessTier::Standard => vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
                AccessTier::Restricted => vec!["10.0.1.0/24".to_string()], // Only essential
                AccessTier::Quarantined => unreachable!(),
            },
            dns: vec!["1.1.1.1".to_string()],
            keepalive_secs: Some(25),
        }],
    };

    Ok(Json(PostureReportResponse {
        posture_score: score,
        access_tier: tier_name,
        tunnels,
    }))
}

/// POST /api/v1/devices/heartbeat
///
/// Periodic heartbeat from client.
pub async fn heartbeat(
    State(state): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, StatusCode> {
    let mut devices = state.devices.write().await;
    let device = devices
        .get_mut(&req.device_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    device.last_seen = Utc::now();

    Ok(Json(HeartbeatResponse {
        config_changed: false,
    }))
}

/// GET /api/v1/devices
///
/// List all registered devices (admin endpoint).
pub async fn list_devices(
    State(state): State<AppState>,
) -> Json<Vec<Device>> {
    let devices = state.devices.read().await;
    Json(devices.values().cloned().collect())
}
