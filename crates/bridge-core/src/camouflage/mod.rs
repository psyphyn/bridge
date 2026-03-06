//! Traffic camouflage and pluggable transports.
//!
//! Inspired by Tor's "collateral freedom" concept: make Bridge traffic
//! indistinguishable from legitimate high-value services. Blocking Bridge
//! means blocking services the censor can't afford to lose.
//!
//! Transports:
//! - HTTPS tunnel (looks like normal web traffic via CDN domain fronting)
//! - WebSocket tunnel (persistent connection disguised as web app)
//! - QUIC/HTTP3 (blends with modern web traffic)
//! - DNS-over-HTTPS (fallback when other transports are blocked)
//!
//! Domain fronting:
//! - TLS SNI shows a high-value domain (e.g., CDN endpoint)
//! - HTTP Host header routes to the actual Bridge relay
//! - Censor must block the entire CDN to block Bridge

mod transport;
mod fronting;

pub use transport::{
    Transport, TransportConfig, TransportType,
    HttpsTransport, WebSocketTransport, DohTransport,
};
pub use fronting::{
    FrontingConfig, FrontDomain, DomainStrategy,
};

use serde::{Deserialize, Serialize};

/// Overall camouflage configuration for a client connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CamouflageConfig {
    /// Which transport to use.
    pub transport: TransportType,
    /// Domain fronting configuration (if applicable).
    pub fronting: Option<FrontingConfig>,
    /// Traffic shaping: add padding to match expected patterns.
    pub padding: PaddingConfig,
    /// Timing jitter to avoid traffic analysis fingerprinting.
    pub timing_jitter_ms: u32,
}

/// Configuration for traffic padding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingConfig {
    /// Whether padding is enabled.
    pub enabled: bool,
    /// Target packet size to pad to (bytes).
    pub target_size: usize,
    /// Send dummy packets during idle periods.
    pub send_chaff: bool,
    /// Interval for chaff packets (milliseconds).
    pub chaff_interval_ms: u64,
}

impl Default for PaddingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            target_size: 1200, // Match typical HTTPS packet size
            send_chaff: false,
            chaff_interval_ms: 5000,
        }
    }
}

impl Default for CamouflageConfig {
    fn default() -> Self {
        Self {
            transport: TransportType::Direct,
            fronting: None,
            padding: PaddingConfig::default(),
            timing_jitter_ms: 0,
        }
    }
}

/// Pad data to a target size to resist traffic analysis.
pub fn pad_packet(data: &[u8], target_size: usize) -> Vec<u8> {
    if data.len() >= target_size {
        return data.to_vec();
    }

    // Format: [2-byte original length][data][random padding]
    let mut padded = Vec::with_capacity(target_size);
    let len = data.len() as u16;
    padded.extend_from_slice(&len.to_be_bytes());
    padded.extend_from_slice(data);

    // Fill remaining space with random-looking bytes
    let remaining = target_size - padded.len();
    padded.resize(padded.len() + remaining, 0);

    // Use simple PRNG for padding (not crypto - just looks random to analysis)
    let mut seed: u32 = data.len() as u32 ^ 0xDEAD_BEEF;
    for byte in padded[2 + data.len()..].iter_mut() {
        seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
        *byte = (seed >> 16) as u8;
    }

    padded
}

/// Remove padding and extract original data.
pub fn unpad_packet(padded: &[u8]) -> Option<Vec<u8>> {
    if padded.len() < 2 {
        return None;
    }

    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if padded.len() < 2 + len {
        return None;
    }

    Some(padded[2..2 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_and_unpad_roundtrip() {
        let data = b"Hello, Bridge!";
        let padded = pad_packet(data, 1200);
        assert_eq!(padded.len(), 1200);

        let recovered = unpad_packet(&padded).unwrap();
        assert_eq!(recovered, data);
    }

    #[test]
    fn pad_preserves_large_packets() {
        let data = vec![42u8; 2000];
        let padded = pad_packet(&data, 1200);
        assert_eq!(padded, data); // No padding needed, returned as-is
    }

    #[test]
    fn unpad_rejects_truncated() {
        assert!(unpad_packet(&[]).is_none());
        assert!(unpad_packet(&[0]).is_none());
        // Length says 100 but only 2 bytes of data
        assert!(unpad_packet(&[0, 100, 1, 2]).is_none());
    }

    #[test]
    fn default_config() {
        let config = CamouflageConfig::default();
        assert!(matches!(config.transport, TransportType::Direct));
        assert!(config.fronting.is_none());
        assert!(config.padding.enabled);
    }
}
