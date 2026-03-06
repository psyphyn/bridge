//! WireGuard tunnel management using boringtun.
//!
//! Handles creation, configuration, and lifecycle of per-app micro-tunnels.
//! Each tunnel wraps a boringtun `Tunn` instance with async UDP transport.

mod peer;
mod transport;

pub use peer::{WgPeer, PeerStats};
pub use transport::UdpTransport;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

use crate::tunnel::peer::PeerHandle;

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

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Reconnecting => write!(f, "reconnecting"),
            Self::Disconnecting => write!(f, "disconnecting"),
        }
    }
}

/// Configuration for a single WireGuard tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub id: TunnelId,
    /// Base64-encoded WireGuard private key.
    pub private_key: String,
    /// Base64-encoded peer public key.
    pub peer_public_key: String,
    /// Peer endpoint as "host:port".
    pub peer_endpoint: SocketAddr,
    /// Allowed IP ranges (CIDR notation).
    pub allowed_ips: Vec<String>,
    /// DNS servers for this tunnel.
    pub dns: Vec<String>,
    /// Persistent keepalive interval in seconds.
    pub keepalive_secs: Option<u16>,
}

/// Events emitted by the tunnel manager.
#[derive(Debug, Clone)]
pub enum TunnelEvent {
    StateChanged {
        tunnel_id: TunnelId,
        old_state: TunnelState,
        new_state: TunnelState,
    },
    PacketReceived {
        tunnel_id: TunnelId,
        bytes: usize,
    },
    HandshakeComplete {
        tunnel_id: TunnelId,
    },
    Error {
        tunnel_id: TunnelId,
        error: String,
    },
}

/// Manages the lifecycle of WireGuard tunnels.
pub struct TunnelManager {
    tunnels: Arc<RwLock<HashMap<TunnelId, TunnelEntry>>>,
    event_tx: mpsc::Sender<TunnelEvent>,
    event_rx: Option<mpsc::Receiver<TunnelEvent>>,
}

struct TunnelEntry {
    config: TunnelConfig,
    state: TunnelState,
    handle: Option<PeerHandle>,
}

impl TunnelManager {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(256);
        Self {
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            event_rx: Some(event_rx),
        }
    }

    /// Take the event receiver (can only be called once).
    pub fn take_event_receiver(&mut self) -> Option<mpsc::Receiver<TunnelEvent>> {
        self.event_rx.take()
    }

    /// Register a tunnel configuration without connecting.
    pub async fn add_tunnel(&self, config: TunnelConfig) {
        let id = config.id;
        let entry = TunnelEntry {
            config,
            state: TunnelState::Disconnected,
            handle: None,
        };
        self.tunnels.write().await.insert(id, entry);
        tracing::info!(%id, "Tunnel registered");
    }

    /// Connect a registered tunnel. Starts the WireGuard handshake and UDP transport.
    pub async fn connect(&self, tunnel_id: TunnelId) -> Result<(), TunnelError> {
        let mut tunnels = self.tunnels.write().await;
        let entry = tunnels
            .get_mut(&tunnel_id)
            .ok_or(TunnelError::NotFound(tunnel_id))?;

        if entry.state == TunnelState::Connected || entry.state == TunnelState::Connecting {
            return Ok(());
        }

        let old_state = entry.state;
        entry.state = TunnelState::Connecting;

        let _ = self.event_tx.send(TunnelEvent::StateChanged {
            tunnel_id,
            old_state,
            new_state: TunnelState::Connecting,
        }).await;

        let config = entry.config.clone();
        let event_tx = self.event_tx.clone();
        let tunnels_ref = self.tunnels.clone();

        // Decode keys
        let private_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &config.private_key,
        )
        .map_err(|_| TunnelError::InvalidKey("invalid base64 private key".into()))?;

        let peer_public_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &config.peer_public_key,
        )
        .map_err(|_| TunnelError::InvalidKey("invalid base64 peer public key".into()))?;

        let private_key_arr: [u8; 32] = private_key_bytes
            .try_into()
            .map_err(|_| TunnelError::InvalidKey("private key must be 32 bytes".into()))?;

        let peer_public_key_arr: [u8; 32] = peer_public_key_bytes
            .try_into()
            .map_err(|_| TunnelError::InvalidKey("peer public key must be 32 bytes".into()))?;

        // Create the boringtun peer
        let wg_peer = WgPeer::new(
            private_key_arr,
            peer_public_key_arr,
            config.keepalive_secs,
        )?;

        // Bind UDP socket
        let transport = UdpTransport::bind("0.0.0.0:0").await
            .map_err(|e| TunnelError::Transport(e.to_string()))?;

        transport.connect(config.peer_endpoint).await
            .map_err(|e| TunnelError::Transport(e.to_string()))?;

        // Start the async tunnel loop
        let handle = PeerHandle::spawn(
            tunnel_id,
            wg_peer,
            transport,
            event_tx,
            tunnels_ref,
        );

        entry.handle = Some(handle);

        Ok(())
    }

    /// Disconnect a tunnel.
    pub async fn disconnect(&self, tunnel_id: TunnelId) -> Result<(), TunnelError> {
        let mut tunnels = self.tunnels.write().await;
        let entry = tunnels
            .get_mut(&tunnel_id)
            .ok_or(TunnelError::NotFound(tunnel_id))?;

        let old_state = entry.state;
        entry.state = TunnelState::Disconnecting;

        // Drop the handle to cancel the background task
        if let Some(handle) = entry.handle.take() {
            handle.shutdown();
        }

        entry.state = TunnelState::Disconnected;

        let _ = self.event_tx.send(TunnelEvent::StateChanged {
            tunnel_id,
            old_state,
            new_state: TunnelState::Disconnected,
        }).await;

        tracing::info!(%tunnel_id, "Tunnel disconnected");
        Ok(())
    }

    /// Remove a tunnel entirely.
    pub async fn remove_tunnel(&self, tunnel_id: TunnelId) -> Result<(), TunnelError> {
        self.disconnect(tunnel_id).await.ok(); // Ignore if already disconnected
        self.tunnels.write().await.remove(&tunnel_id);
        tracing::info!(%tunnel_id, "Tunnel removed");
        Ok(())
    }

    /// Get the state of a specific tunnel.
    pub async fn tunnel_state(&self, tunnel_id: TunnelId) -> Option<TunnelState> {
        self.tunnels.read().await.get(&tunnel_id).map(|e| e.state)
    }

    /// Get stats for a specific tunnel.
    pub async fn tunnel_stats(&self, tunnel_id: TunnelId) -> Option<PeerStats> {
        let tunnels = self.tunnels.read().await;
        let entry = tunnels.get(&tunnel_id)?;
        entry.handle.as_ref().map(|h| h.stats())
    }

    /// Number of registered tunnels.
    pub async fn tunnel_count(&self) -> usize {
        self.tunnels.read().await.len()
    }

    /// List all tunnel IDs and their states.
    pub async fn list_tunnels(&self) -> Vec<(TunnelId, TunnelState)> {
        self.tunnels
            .read()
            .await
            .iter()
            .map(|(id, entry)| (*id, entry.state))
            .collect()
    }

    /// Send an IP packet into a specific tunnel (from the tunnel interface).
    pub async fn send_packet(&self, tunnel_id: TunnelId, packet: &[u8]) -> Result<(), TunnelError> {
        let tunnels = self.tunnels.read().await;
        let entry = tunnels
            .get(&tunnel_id)
            .ok_or(TunnelError::NotFound(tunnel_id))?;

        let handle = entry
            .handle
            .as_ref()
            .ok_or(TunnelError::NotConnected(tunnel_id))?;

        handle.send_packet(packet).await
            .map_err(|e| TunnelError::Transport(e.to_string()))
    }
}

impl Default for TunnelManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Tunnel errors.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("tunnel {0} not found")]
    NotFound(TunnelId),

    #[error("tunnel {0} not connected")]
    NotConnected(TunnelId),

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("WireGuard error: {0}")]
    WireGuard(String),

    #[error("transport error: {0}")]
    Transport(String),
}

use base64::Engine as _;

/// Helper to generate a new WireGuard keypair, returned as base64 strings.
pub fn generate_keypair() -> (String, String) {
    let secret = boringtun::x25519::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = boringtun::x25519::PublicKey::from(&secret);

    let secret_b64 = base64::engine::general_purpose::STANDARD.encode(secret.to_bytes());
    let public_b64 = base64::engine::general_purpose::STANDARD.encode(public.to_bytes());

    (secret_b64, public_b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_produces_valid_keys() {
        let (secret, public) = generate_keypair();
        // Keys should be 32 bytes = 44 chars in base64
        assert_eq!(secret.len(), 44);
        assert_eq!(public.len(), 44);

        // Should decode successfully
        let secret_bytes = base64::engine::general_purpose::STANDARD.decode(&secret).unwrap();
        let public_bytes = base64::engine::general_purpose::STANDARD.decode(&public).unwrap();
        assert_eq!(secret_bytes.len(), 32);
        assert_eq!(public_bytes.len(), 32);
    }

    #[test]
    fn keypair_public_derives_from_private() {
        let (secret_b64, public_b64) = generate_keypair();

        let secret_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&secret_b64)
            .unwrap()
            .try_into()
            .unwrap();

        let secret = boringtun::x25519::StaticSecret::from(secret_bytes);
        let derived_public = boringtun::x25519::PublicKey::from(&secret);
        let derived_b64 = base64::engine::general_purpose::STANDARD.encode(derived_public.to_bytes());

        assert_eq!(public_b64, derived_b64);
    }

    #[test]
    fn wg_peer_handshake_between_two_peers() {
        // Generate two keypairs
        let (client_secret_b64, client_public_b64) = generate_keypair();
        let (server_secret_b64, server_public_b64) = generate_keypair();

        let client_secret: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&client_secret_b64).unwrap().try_into().unwrap();
        let server_secret: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&server_secret_b64).unwrap().try_into().unwrap();
        let client_public: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&client_public_b64).unwrap().try_into().unwrap();
        let server_public: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&server_public_b64).unwrap().try_into().unwrap();

        // Client knows server's public key, server knows client's public key
        let mut client = WgPeer::new(client_secret, server_public, Some(25)).unwrap();
        let mut server = WgPeer::new(server_secret, client_public, None).unwrap();

        let mut buf = vec![0u8; 65536];

        // Step 1: Client initiates handshake
        let result = client.encapsulate(&[], &mut buf);
        let handshake_init = match result {
            boringtun::noise::TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("Expected WriteToNetwork, got {:?}", other),
        };

        // Step 2: Server receives handshake init, produces response
        let result = server.decapsulate(&handshake_init, &mut buf);
        let handshake_resp = match result {
            boringtun::noise::TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("Expected WriteToNetwork for handshake response, got {:?}", other),
        };

        // Step 3: Client receives response, produces keepalive
        let result = client.decapsulate(&handshake_resp, &mut buf);
        let keepalive = match result {
            boringtun::noise::TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("Expected WriteToNetwork for keepalive, got {:?}", other),
        };

        // Step 4: Server processes keepalive
        let result = server.decapsulate(&keepalive, &mut buf);
        match result {
            boringtun::noise::TunnResult::Done => {} // Keepalive processed
            other => panic!("Expected Done for keepalive, got {:?}", other),
        }

        // Now the tunnel is established! Test data transfer.
        // Create a minimal IPv4 UDP packet (src: 10.0.0.1, dst: 10.0.0.2)
        let test_packet = build_test_ipv4_packet();

        // Client sends data through the tunnel
        let result = client.encapsulate(&test_packet, &mut buf);
        let encrypted_data = match result {
            boringtun::noise::TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("Expected WriteToNetwork for data, got {:?}", other),
        };

        // Server decrypts data
        let mut recv_buf = vec![0u8; 65536];
        let result = server.decapsulate(&encrypted_data, &mut recv_buf);
        match result {
            boringtun::noise::TunnResult::WriteToTunnelV4(data, _addr) => {
                assert_eq!(data, &test_packet[..]);
            }
            other => panic!("Expected WriteToTunnelV4, got {:?}", other),
        }
    }

    /// Build a minimal valid IPv4/UDP packet for testing.
    fn build_test_ipv4_packet() -> Vec<u8> {
        let mut pkt = vec![0u8; 28]; // 20 byte IP header + 8 byte UDP header

        // IP version (4) + IHL (5 = 20 bytes)
        pkt[0] = 0x45;
        // Total length = 28
        pkt[2] = 0;
        pkt[3] = 28;
        // TTL
        pkt[8] = 64;
        // Protocol: UDP (17)
        pkt[9] = 17;
        // Source IP: 10.0.0.1
        pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1;
        // Dest IP: 10.0.0.2
        pkt[16] = 10; pkt[17] = 0; pkt[18] = 0; pkt[19] = 2;

        // UDP header (ports don't matter for this test)
        pkt[20] = 0x13; pkt[21] = 0x88; // src port 5000
        pkt[22] = 0x13; pkt[23] = 0x89; // dst port 5001
        pkt[24] = 0; pkt[25] = 8; // UDP length = 8

        // Compute IP checksum
        let checksum = ip_checksum(&pkt[..20]);
        pkt[10] = (checksum >> 8) as u8;
        pkt[11] = (checksum & 0xff) as u8;

        pkt
    }

    fn ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for i in (0..header.len()).step_by(2) {
            let word = if i + 1 < header.len() {
                ((header[i] as u32) << 8) | (header[i + 1] as u32)
            } else {
                (header[i] as u32) << 8
            };
            sum += word;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !sum as u16
    }

    #[tokio::test]
    async fn tunnel_manager_add_and_list() {
        let mgr = TunnelManager::new();
        assert_eq!(mgr.tunnel_count().await, 0);

        let (secret, _) = generate_keypair();
        let (_, peer_pub) = generate_keypair();

        let config = TunnelConfig {
            id: Uuid::new_v4(),
            private_key: secret,
            peer_public_key: peer_pub,
            peer_endpoint: "127.0.0.1:51820".parse().unwrap(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            dns: vec!["1.1.1.1".to_string()],
            keepalive_secs: Some(25),
        };

        mgr.add_tunnel(config.clone()).await;
        assert_eq!(mgr.tunnel_count().await, 1);

        let state = mgr.tunnel_state(config.id).await.unwrap();
        assert_eq!(state, TunnelState::Disconnected);

        mgr.remove_tunnel(config.id).await.unwrap();
        assert_eq!(mgr.tunnel_count().await, 0);
    }
}
