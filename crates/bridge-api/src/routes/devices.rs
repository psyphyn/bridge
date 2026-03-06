//! Device registration and management endpoints.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use chrono::Utc;
use uuid::Uuid;

use bridge_core::api_types::{
    DeviceRegistrationRequest, DeviceRegistrationResponse, HeartbeatRequest, HeartbeatResponse,
    PostureReportRequest, PostureReportResponse, TunnelAssignment,
};
use bridge_core::identity::AttestationToken;
use bridge_core::posture::AccessTier;

use crate::models::Device;
use crate::state::AppState;

/// Verify an attestation token against the provided identity public key.
///
/// Returns Ok(claims) if the token is valid, Err(reason) if not.
fn verify_attestation(
    token_compact: &str,
    identity_public_key_b64: &str,
) -> Result<bridge_core::identity::AttestationClaims, String> {
    let token = AttestationToken::from_compact(token_compact)
        .map_err(|e| format!("Invalid token format: {e}"))?;

    let public_key_bytes = base64::engine::general_purpose::STANDARD
        .decode(identity_public_key_b64)
        .map_err(|e| format!("Invalid public key base64: {e}"))?;

    let claims = token
        .verify_and_decode(&public_key_bytes)
        .map_err(|e| format!("Token verification failed: {e}"))?;

    // Verify the public key in the claims matches what was provided
    let claims_pk_bytes = base64::engine::general_purpose::STANDARD
        .decode(&claims.public_key)
        .map_err(|e| format!("Invalid claims public key: {e}"))?;

    if claims_pk_bytes != public_key_bytes {
        return Err("Public key in token doesn't match provided key".to_string());
    }

    Ok(claims)
}

/// POST /api/v1/devices/register
///
/// Register a new device. Returns device ID and initial tunnel configuration.
///
/// If an attestation token is provided with an identity public key, the server
/// verifies the token signature. This proves the device possesses the private key
/// corresponding to the identity. With hardware-backed keys (Secure Enclave/TPM),
/// this is cryptographic proof of device identity.
pub async fn register_device(
    State(state): State<AppState>,
    Json(req): Json<DeviceRegistrationRequest>,
) -> Result<Json<DeviceRegistrationResponse>, StatusCode> {
    let device_id = Uuid::new_v4();
    let now = Utc::now();

    // Verify attestation if both token and identity key are provided
    let mut verified_posture: Option<u8> = None;
    let mut verified_tier: Option<String> = None;
    let mut attestation_verified = false;

    if let (Some(ref token), Some(ref identity_pk)) =
        (&req.attestation_token, &req.identity_public_key)
    {
        match verify_attestation(token, identity_pk) {
            Ok(claims) => {
                attestation_verified = true;
                verified_posture = Some(claims.posture_score);
                verified_tier = Some(format!("{:?}", claims.access_tier).to_lowercase());

                tracing::info!(
                    device_id = %device_id,
                    claimed_posture = claims.posture_score,
                    claimed_tier = %format!("{:?}", claims.access_tier),
                    token_device_id = %claims.device_id,
                    platform = %claims.platform,
                    "Attestation verified successfully"
                );
            }
            Err(reason) => {
                tracing::warn!(
                    device_id = %device_id,
                    reason = %reason,
                    "Attestation verification failed — registering without attestation"
                );
                // Don't reject the registration — allow it with reduced trust.
                // The device will be treated as unverified.
            }
        }
    }

    let initial_score = verified_posture.unwrap_or(50); // Unverified devices start at 50
    let initial_tier = verified_tier.unwrap_or_else(|| {
        format!("{:?}", AccessTier::from_score(initial_score)).to_lowercase()
    });

    let device = Device {
        id: device_id,
        device_public_key: req.device_public_key.clone(),
        identity_public_key: req.identity_public_key.clone(),
        platform: req.platform.clone(),
        os_version: req.os_version,
        hardware_model: req.hardware_model,
        hostname: req.hostname,
        registered_at: now,
        last_seen: now,
        posture_score: initial_score,
        access_tier: initial_tier,
        attestation_verified,
    };

    tracing::info!(
        device_id = %device_id,
        platform = %req.platform,
        has_identity = req.identity_public_key.is_some(),
        attestation_verified,
        initial_score,
        "Device registered"
    );

    state.devices.write().await.insert(device_id, device);

    // Assign tunnel based on verification status
    let allowed_ips = if attestation_verified {
        vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
    } else {
        // Unverified devices get restricted access
        vec!["10.0.0.0/8".to_string()]
    };

    let tunnel = TunnelAssignment {
        tunnel_id: Uuid::new_v4(),
        server_public_key: state.relay.public_key.clone(),
        server_endpoint: state.relay.endpoint.clone(),
        allowed_ips,
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
                AccessTier::Standard => {
                    vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()]
                }
                AccessTier::Restricted => vec!["10.0.1.0/24".to_string()],
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
/// Periodic heartbeat from client. Verifies attestation token if provided.
pub async fn heartbeat(
    State(state): State<AppState>,
    Json(req): Json<HeartbeatRequest>,
) -> Result<Json<HeartbeatResponse>, StatusCode> {
    let mut devices = state.devices.write().await;
    let device = devices
        .get_mut(&req.device_id)
        .ok_or(StatusCode::NOT_FOUND)?;

    device.last_seen = Utc::now();

    // Verify heartbeat attestation if provided
    if let (Some(ref token), Some(ref identity_pk)) =
        (&req.attestation_token, &device.identity_public_key)
    {
        match verify_attestation(token, identity_pk) {
            Ok(claims) => {
                // Update posture from verified attestation
                device.posture_score = claims.posture_score;
                device.access_tier =
                    format!("{:?}", claims.access_tier).to_lowercase();
                device.attestation_verified = true;

                tracing::debug!(
                    device_id = %req.device_id,
                    posture = claims.posture_score,
                    tier = %format!("{:?}", claims.access_tier),
                    "Heartbeat attestation verified"
                );
            }
            Err(reason) => {
                tracing::warn!(
                    device_id = %req.device_id,
                    reason = %reason,
                    "Heartbeat attestation verification failed"
                );
                // Don't fail the heartbeat, but mark attestation as unverified
                device.attestation_verified = false;
            }
        }
    }

    Ok(Json(HeartbeatResponse {
        config_changed: false,
    }))
}

/// GET /api/v1/devices
///
/// List all registered devices (admin endpoint).
pub async fn list_devices(State(state): State<AppState>) -> Json<Vec<Device>> {
    let devices = state.devices.read().await;
    Json(devices.values().cloned().collect())
}
