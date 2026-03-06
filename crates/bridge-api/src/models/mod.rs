//! Data models for the control plane.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A registered device in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub device_public_key: String,
    /// Ed25519 identity public key (for attestation verification).
    pub identity_public_key: Option<String>,
    pub platform: String,
    pub os_version: String,
    pub hardware_model: String,
    pub hostname: String,
    pub registered_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub posture_score: u8,
    pub access_tier: String,
}
