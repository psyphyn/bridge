//! Shared application state for the API server.
//!
//! Uses in-memory storage for now. Will migrate to PostgreSQL later.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use uuid::Uuid;

use bridge_core::policy::PolicySet;
use bridge_core::siem::SecurityEvent;
use crate::models::Device;
use crate::routes::attest::AttestedDevice;

/// The relay's WireGuard keypair and endpoint.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Base64-encoded relay private key.
    pub private_key: String,
    /// Base64-encoded relay public key.
    pub public_key: String,
    /// Relay endpoint for clients to connect to.
    pub endpoint: String,
}

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub devices: Arc<RwLock<HashMap<Uuid, Device>>>,
    pub relay: RelayConfig,
    /// Pending attestation challenges (challenge_b64 -> expiry).
    pub pending_challenges: Arc<RwLock<HashMap<String, DateTime<Utc>>>>,
    /// Devices that have completed App Attest (key_id -> attestation record).
    pub attested_devices: Arc<RwLock<HashMap<String, AttestedDevice>>>,
    /// Named policy sets (name -> policy).
    pub policies: Arc<RwLock<HashMap<String, PolicySet>>>,
    /// Security events buffer (ring buffer, most recent last).
    pub events: Arc<RwLock<Vec<SecurityEvent>>>,
}

impl AppState {
    pub fn new(relay: RelayConfig) -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            relay,
            pending_challenges: Arc::new(RwLock::new(HashMap::new())),
            attested_devices: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            events: Arc::new(RwLock::new(Vec::new())),
        }
    }
}
