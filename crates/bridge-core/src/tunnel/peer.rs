//! WireGuard peer wrapper around boringtun's `Tunn`.
//!
//! Provides a safe, async-friendly interface over boringtun's synchronous API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use tokio::sync::{mpsc, Mutex, RwLock};

use super::transport::UdpTransport;
use super::{TunnelEvent, TunnelState, TunnelId};

/// Max WireGuard packet size (standard MTU).
const MAX_PACKET: usize = 65536;

/// Interval for timer ticks (WireGuard keepalive/rekey).
const TIMER_TICK_INTERVAL: Duration = Duration::from_millis(250);

/// Statistics for a WireGuard peer.
#[derive(Debug, Clone, Default)]
pub struct PeerStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub handshakes: u64,
    pub last_handshake_secs: Option<u64>,
}

/// Wraps boringtun's `Tunn` with key management.
pub struct WgPeer {
    tunn: Tunn,
}

impl WgPeer {
    /// Create a new WireGuard peer from raw key bytes.
    pub fn new(
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
        keepalive_secs: Option<u16>,
    ) -> Result<Self, super::TunnelError> {
        let static_secret = boringtun::x25519::StaticSecret::from(private_key);
        let peer_public = boringtun::x25519::PublicKey::from(peer_public_key);

        let tunn = Tunn::new(
            static_secret,
            peer_public,
            None, // No preshared key for now
            keepalive_secs,
            0, // Tunnel index
            None, // Use default rate limiter
        )
        .map_err(|e| super::TunnelError::WireGuard(e.to_string()))?;

        Ok(Self { tunn })
    }

    /// Encapsulate an IP packet for sending over the WireGuard tunnel.
    /// Returns the encrypted WireGuard packet to send via UDP.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.encapsulate(src, dst)
    }

    /// Decapsulate a received UDP packet.
    /// Returns the decrypted IP packet (or handshake response to send).
    pub fn decapsulate<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        self.tunn.decapsulate(None, src, dst)
    }

    /// Tick internal WireGuard timers (keepalive, rekey).
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.update_timers(dst)
    }

    /// Get tunnel stats.
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        self.tunn.stats()
    }
}

/// Handle to a running tunnel peer task.
pub struct PeerHandle {
    /// Channel to send outbound IP packets into the tunnel.
    outbound_tx: mpsc::Sender<Vec<u8>>,
    /// Shared stats.
    stats: Arc<PeerStatsInner>,
    /// Handle to the background task (dropped = cancelled).
    _task: tokio::task::JoinHandle<()>,
}

struct PeerStatsInner {
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
}

impl PeerHandle {
    /// Spawn the async tunnel I/O loop.
    pub fn spawn(
        tunnel_id: TunnelId,
        peer: WgPeer,
        transport: UdpTransport,
        event_tx: mpsc::Sender<TunnelEvent>,
        tunnels: Arc<RwLock<HashMap<TunnelId, super::TunnelEntry>>>,
    ) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(256);
        let stats = Arc::new(PeerStatsInner {
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
        });

        let stats_clone = stats.clone();
        let task = tokio::spawn(async move {
            tunnel_loop(
                tunnel_id,
                peer,
                transport,
                outbound_rx,
                event_tx,
                tunnels,
                stats_clone,
            )
            .await;
        });

        Self {
            outbound_tx,
            stats,
            _task: task,
        }
    }

    /// Send an IP packet into the tunnel.
    pub async fn send_packet(&self, packet: &[u8]) -> Result<(), String> {
        self.outbound_tx
            .send(packet.to_vec())
            .await
            .map_err(|_| "tunnel closed".to_string())
    }

    /// Get current stats snapshot.
    pub fn stats(&self) -> PeerStats {
        PeerStats {
            tx_bytes: self.stats.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Ordering::Relaxed),
            tx_packets: self.stats.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.stats.rx_packets.load(Ordering::Relaxed),
            ..Default::default()
        }
    }

    /// Signal the background task to stop.
    pub fn shutdown(self) {
        // Dropping self aborts the task via _task JoinHandle drop
        self._task.abort();
    }
}

/// The main async I/O loop for a WireGuard tunnel.
///
/// Handles:
/// 1. Sending outbound IP packets (encapsulate → UDP send)
/// 2. Receiving inbound UDP packets (UDP recv → decapsulate)
/// 3. Timer ticks for keepalive and rekey
/// 4. Initiating the handshake on startup
async fn tunnel_loop(
    tunnel_id: TunnelId,
    peer: WgPeer,
    transport: UdpTransport,
    mut outbound_rx: mpsc::Receiver<Vec<u8>>,
    event_tx: mpsc::Sender<TunnelEvent>,
    tunnels: Arc<RwLock<HashMap<TunnelId, super::TunnelEntry>>>,
    stats: Arc<PeerStatsInner>,
) {
    let peer = Arc::new(Mutex::new(peer));
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut timer_interval = tokio::time::interval(TIMER_TICK_INTERVAL);

    // Initiate handshake
    {
        let mut dst = vec![0u8; MAX_PACKET];
        let mut peer_lock = peer.lock().await;
        let result = peer_lock.encapsulate(&[], &mut dst);
        if let TunnResult::WriteToNetwork(data) = result {
            let _ = transport.send(data).await;
        }
    }

    let mut connected = false;

    loop {
        tokio::select! {
            // Outbound: IP packet from the tunnel interface → encapsulate → UDP
            Some(packet) = outbound_rx.recv() => {
                let mut dst = vec![0u8; MAX_PACKET];
                let mut peer_lock = peer.lock().await;
                let result = peer_lock.encapsulate(&packet, &mut dst);
                match result {
                    TunnResult::WriteToNetwork(data) => {
                        if transport.send(data).await.is_ok() {
                            stats.tx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                            stats.tx_packets.fetch_add(1, Ordering::Relaxed);
                        }
                        // Check if there are queued packets to flush
                        loop {
                            let result = peer_lock.decapsulate(&[], &mut dst);
                            match result {
                                TunnResult::WriteToNetwork(data) => {
                                    let _ = transport.send(data).await;
                                }
                                TunnResult::Done => break,
                                _ => break,
                            }
                        }
                    }
                    TunnResult::Err(e) => {
                        tracing::warn!(%tunnel_id, ?e, "Encapsulate error");
                    }
                    _ => {}
                }
            }

            // Inbound: UDP packet from network → decapsulate → IP packet
            result = transport.recv(&mut recv_buf) => {
                match result {
                    Ok(n) => {
                        let mut dst = vec![0u8; MAX_PACKET];
                        let mut peer_lock = peer.lock().await;
                        let result = peer_lock.decapsulate(&recv_buf[..n], &mut dst);

                        match result {
                            TunnResult::WriteToNetwork(data) => {
                                // Handshake response or keepalive — send it back
                                let _ = transport.send(data).await;

                                // Drain any queued packets
                                loop {
                                    let result = peer_lock.decapsulate(&[], &mut dst);
                                    match result {
                                        TunnResult::WriteToNetwork(data) => {
                                            let _ = transport.send(data).await;
                                        }
                                        TunnResult::Done => break,
                                        _ => break,
                                    }
                                }

                                // If we weren't connected before, we are now
                                if !connected {
                                    connected = true;
                                    update_tunnel_state(&tunnels, tunnel_id, TunnelState::Connected).await;
                                    let _ = event_tx.send(TunnelEvent::HandshakeComplete { tunnel_id }).await;
                                    let _ = event_tx.send(TunnelEvent::StateChanged {
                                        tunnel_id,
                                        old_state: TunnelState::Connecting,
                                        new_state: TunnelState::Connected,
                                    }).await;
                                    tracing::info!(%tunnel_id, "Handshake complete, tunnel connected");
                                }
                            }
                            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                                let len = data.len();
                                stats.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                                stats.rx_packets.fetch_add(1, Ordering::Relaxed);

                                let _ = event_tx.send(TunnelEvent::PacketReceived {
                                    tunnel_id,
                                    bytes: len,
                                }).await;

                                // TODO: Route decapsulated packet to the virtual interface
                                // For now we just count it

                                if !connected {
                                    connected = true;
                                    update_tunnel_state(&tunnels, tunnel_id, TunnelState::Connected).await;
                                    let _ = event_tx.send(TunnelEvent::StateChanged {
                                        tunnel_id,
                                        old_state: TunnelState::Connecting,
                                        new_state: TunnelState::Connected,
                                    }).await;
                                }
                            }
                            TunnResult::Done => {}
                            TunnResult::Err(e) => {
                                tracing::debug!(%tunnel_id, ?e, "Decapsulate error");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%tunnel_id, %e, "UDP recv error");
                    }
                }
            }

            // Timer tick: keepalive, rekey
            _ = timer_interval.tick() => {
                let mut dst = vec![0u8; MAX_PACKET];
                let mut peer_lock = peer.lock().await;
                let result = peer_lock.update_timers(&mut dst);
                match result {
                    TunnResult::WriteToNetwork(data) => {
                        let _ = transport.send(data).await;
                    }
                    TunnResult::Err(e) => {
                        tracing::debug!(%tunnel_id, ?e, "Timer error");
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn update_tunnel_state(
    tunnels: &Arc<RwLock<HashMap<TunnelId, super::TunnelEntry>>>,
    tunnel_id: TunnelId,
    new_state: TunnelState,
) {
    if let Some(entry) = tunnels.write().await.get_mut(&tunnel_id) {
        entry.state = new_state;
    }
}
