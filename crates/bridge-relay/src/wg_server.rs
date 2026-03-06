//! WireGuard server for the relay.
//!
//! Accepts incoming WireGuard connections from clients, performs handshakes,
//! and handles encrypted packet forwarding.

use std::net::SocketAddr;
use std::sync::Arc;

use boringtun::noise::TunnResult;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use bridge_core::inspect::Verdict;

use crate::inspector::SharedInspector;
use crate::peer_map::PeerMap;

/// Max WireGuard packet size.
const MAX_PACKET: usize = 65536;

/// The WireGuard server that listens for client tunnels.
pub struct WgServer {
    socket: Arc<UdpSocket>,
    peers: Arc<Mutex<PeerMap>>,
    inspector: SharedInspector,
}

impl WgServer {
    /// Bind the WireGuard server to the given address.
    pub async fn bind(
        addr: &str,
        relay_private_key: [u8; 32],
        inspector: SharedInspector,
    ) -> anyhow::Result<Self> {
        let socket = UdpSocket::bind(addr).await?;
        tracing::info!(addr = %socket.local_addr()?, "WireGuard server listening");

        Ok(Self {
            socket: Arc::new(socket),
            peers: Arc::new(Mutex::new(PeerMap::new(relay_private_key))),
            inspector,
        })
    }

    /// Get the local address the server is bound to.
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Run the WireGuard server main loop.
    pub async fn run(&self) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_PACKET];

        loop {
            let (len, peer_addr) = self.socket.recv_from(&mut buf).await?;
            let packet = &buf[..len];

            self.handle_packet(packet, peer_addr).await;
        }
    }

    async fn handle_packet(&self, packet: &[u8], peer_addr: SocketAddr) {
        let mut dst = vec![0u8; MAX_PACKET];
        let mut peers = self.peers.lock().await;

        // Try to find existing peer, or create one for handshake init
        let peer = if let Some(p) = peers.get_peer(&peer_addr) {
            p
        } else {
            // For a new peer, we need to try decapsulating as a handshake init
            // We'll create the peer with a placeholder and handle the first packet
            // In production, we'd validate the peer's public key against the control plane
            // For now, accept all handshake initiations

            // Try to parse as handshake init to extract the peer's static key
            // boringtun handles this internally, so we create a peer with a known key
            // In the real system, allowed peer keys come from the control plane
            match peers.get_or_create_peer(peer_addr, None) {
                Some(p) => p,
                None => {
                    tracing::debug!(%peer_addr, "Unknown peer, no public key available");
                    return;
                }
            }
        };

        let mut peer_lock = peer.lock().await;
        let result = peer_lock.tunn.decapsulate(None, packet, &mut dst);

        match result {
            TunnResult::WriteToNetwork(data) => {
                // Handshake response or keepalive — send back to peer
                let _ = self.socket.send_to(data, peer_addr).await;

                // Drain queued packets
                loop {
                    let result = peer_lock.tunn.decapsulate(None, &[], &mut dst);
                    match result {
                        TunnResult::WriteToNetwork(data) => {
                            let _ = self.socket.send_to(data, peer_addr).await;
                        }
                        TunnResult::Done => break,
                        _ => break,
                    }
                }
            }
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                let len = data.len();
                peer_lock.rx_bytes += len as u64;

                // Run through inspection pipeline
                let verdict = {
                    let mut inspector = self.inspector.lock().await;
                    inspector.inspect_packet(peer_addr, data)
                };

                match &verdict {
                    Verdict::Block { reason } => {
                        tracing::warn!(
                            %peer_addr,
                            bytes = len,
                            %reason,
                            "Packet blocked by inspection"
                        );
                        // Drop the packet — don't forward
                    }
                    Verdict::Alert { severity, message } => {
                        tracing::info!(
                            %peer_addr,
                            bytes = len,
                            ?severity,
                            %message,
                            "Inspection alert"
                        );
                        // TODO: Forward to destination (alert doesn't block)
                        tracing::debug!(
                            %peer_addr,
                            bytes = len,
                            "Forwarding packet (alert)"
                        );
                    }
                    Verdict::ShadowCopy => {
                        // TODO: Copy packet to shadow store for audit
                        tracing::debug!(
                            %peer_addr,
                            bytes = len,
                            "Shadow copy + forward"
                        );
                    }
                    Verdict::Allow => {
                        // TODO: Forward to destination or route to another tunnel
                        tracing::debug!(
                            %peer_addr,
                            bytes = len,
                            "Decapsulated packet from client"
                        );
                    }
                }
            }
            TunnResult::Done => {}
            TunnResult::Err(e) => {
                tracing::debug!(%peer_addr, ?e, "WireGuard error");
            }
        }
    }

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.peer_count()
    }
}
