//! Shared application state for the API server.
//!
//! Uses in-memory storage for now. Will migrate to PostgreSQL later.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::models::Device;

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
}

impl AppState {
    pub fn new(relay: RelayConfig) -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            relay,
        }
    }
}
