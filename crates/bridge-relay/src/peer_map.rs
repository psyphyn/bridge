//! Peer management for the relay.
//!
//! Maps client endpoints to their WireGuard tunnel state.
//! The relay is the "server side" of each WireGuard tunnel.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use boringtun::noise::{Tunn, TunnResult};
use tokio::sync::Mutex;

/// A connected WireGuard peer (client) on the relay.
pub struct RelayPeer {
    pub tunn: Tunn,
    pub endpoint: SocketAddr,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Manages all connected peers on the relay.
pub struct PeerMap {
    /// Map from client endpoint to their tunnel state.
    peers: HashMap<SocketAddr, Arc<Mutex<RelayPeer>>>,
    /// The relay's private key (used for all peer tunnels).
    relay_private_key: [u8; 32],
}

impl PeerMap {
    pub fn new(relay_private_key: [u8; 32]) -> Self {
        Self {
            peers: HashMap::new(),
            relay_private_key,
        }
    }

    /// Get or create a peer for the given endpoint.
    /// On first contact (handshake init), we create a new Tunn for the peer.
    pub fn get_or_create_peer(
        &mut self,
        endpoint: SocketAddr,
        peer_public_key: Option<[u8; 32]>,
    ) -> Option<Arc<Mutex<RelayPeer>>> {
        if let Some(peer) = self.peers.get(&endpoint) {
            return Some(peer.clone());
        }

        // Need the peer's public key to create a tunnel
        let peer_public_key = peer_public_key?;

        let static_secret =
            boringtun::x25519::StaticSecret::from(self.relay_private_key);
        let peer_public = boringtun::x25519::PublicKey::from(peer_public_key);

        let tunn = Tunn::new(static_secret, peer_public, None, None, 0, None).ok()?;

        let peer = Arc::new(Mutex::new(RelayPeer {
            tunn,
            endpoint,
            tx_bytes: 0,
            rx_bytes: 0,
        }));

        self.peers.insert(endpoint, peer.clone());
        tracing::info!(%endpoint, "New peer connected");

        Some(peer)
    }

    /// Get an existing peer by endpoint.
    pub fn get_peer(&self, endpoint: &SocketAddr) -> Option<Arc<Mutex<RelayPeer>>> {
        self.peers.get(endpoint).cloned()
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, endpoint: &SocketAddr) {
        self.peers.remove(endpoint);
    }

    /// Number of connected peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
}
