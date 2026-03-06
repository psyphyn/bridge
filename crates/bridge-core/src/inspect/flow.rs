//! Flow tracking for connections.
//!
//! A flow represents a single network connection or request/response.
//! Flows are the unit of inspection — each flow passes through the
//! inspection pipeline.

use std::net::SocketAddr;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique flow identifier.
pub type FlowId = Uuid;

/// Direction of traffic in a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowDirection {
    /// Client → server (upload).
    Outbound,
    /// Server → client (download).
    Inbound,
}

/// Flow lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowState {
    /// Connection initiated.
    New,
    /// TLS handshake in progress.
    TlsHandshake,
    /// Data transfer active.
    Active,
    /// Connection closed normally.
    Closed,
    /// Connection blocked by policy.
    Blocked,
}

/// Metadata extracted from a flow for inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowMetadata {
    /// Destination domain (from SNI or DNS correlation).
    pub domain: Option<String>,
    /// Content type (from HTTP headers).
    pub content_type: Option<String>,
    /// HTTP method (GET, POST, PUT, etc).
    pub http_method: Option<String>,
    /// HTTP path.
    pub http_path: Option<String>,
    /// Whether the connection uses TLS.
    pub is_tls: bool,
    /// TLS SNI (Server Name Indication).
    pub tls_sni: Option<String>,
    /// Source application (process name/bundle ID, if known).
    pub application: Option<String>,
    /// JA3/JA4 fingerprint of the TLS client.
    pub tls_fingerprint: Option<String>,
}

impl Default for FlowMetadata {
    fn default() -> Self {
        Self {
            domain: None,
            content_type: None,
            http_method: None,
            http_path: None,
            is_tls: false,
            tls_sni: None,
            application: None,
            tls_fingerprint: None,
        }
    }
}

/// A tracked network flow.
#[derive(Debug)]
pub struct Flow {
    pub id: FlowId,
    pub state: FlowState,
    pub src: Option<SocketAddr>,
    pub dst: Option<SocketAddr>,
    pub metadata: FlowMetadata,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub started_at: Instant,
    /// Buffered data for inspection (cleared after inspection).
    pub inspect_buffer: Vec<u8>,
}

impl Flow {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            state: FlowState::New,
            src: None,
            dst: None,
            metadata: FlowMetadata::default(),
            tx_bytes: 0,
            rx_bytes: 0,
            started_at: Instant::now(),
            inspect_buffer: Vec::new(),
        }
    }

    pub fn with_endpoints(src: SocketAddr, dst: SocketAddr) -> Self {
        let mut flow = Self::new();
        flow.src = Some(src);
        flow.dst = Some(dst);
        flow
    }

    /// Record outbound bytes.
    pub fn record_tx(&mut self, bytes: usize) {
        self.tx_bytes += bytes as u64;
    }

    /// Record inbound bytes.
    pub fn record_rx(&mut self, bytes: usize) {
        self.rx_bytes += bytes as u64;
    }

    /// Duration since flow started.
    pub fn duration(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Total bytes transferred.
    pub fn total_bytes(&self) -> u64 {
        self.tx_bytes + self.rx_bytes
    }
}

impl Default for Flow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_tracks_bytes() {
        let mut flow = Flow::new();
        flow.record_tx(100);
        flow.record_rx(200);
        assert_eq!(flow.total_bytes(), 300);
    }
}
