//! WireGuard tunnel management using boringtun.
//!
//! Handles creation, configuration, and lifecycle of per-app micro-tunnels.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique identifier for a tunnel instance.
pub type TunnelId = Uuid;

/// Tunnel state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelState {
    Disconnected,
    Connecting,
    Connected,
    Reconnecting,
    Disconnecting,
}

/// Configuration for a single WireGuard tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub id: TunnelId,
    pub private_key: String,
    pub peer_public_key: String,
    pub peer_endpoint: String,
    pub allowed_ips: Vec<String>,
    pub dns: Vec<String>,
    pub keepalive_secs: Option<u16>,
}

/// Manages the lifecycle of WireGuard tunnels.
pub struct TunnelManager {
    tunnels: std::collections::HashMap<TunnelId, TunnelState>,
}

impl TunnelManager {
    pub fn new() -> Self {
        Self {
            tunnels: std::collections::HashMap::new(),
        }
    }

    pub fn tunnel_count(&self) -> usize {
        self.tunnels.len()
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_manager_starts_empty() {
        let mgr = TunnelManager::new();
        assert_eq!(mgr.tunnel_count(), 0);
    }
}
