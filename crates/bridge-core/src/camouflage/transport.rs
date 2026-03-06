//! Pluggable transports for traffic camouflage.
//!
//! Each transport wraps WireGuard packets in a different protocol to evade
//! detection. Inspired by Tor's pluggable transport framework.

use serde::{Deserialize, Serialize};

/// Available transport types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    /// Direct WireGuard UDP (no camouflage).
    Direct,
    /// WireGuard over HTTPS (looks like web browsing).
    Https,
    /// WireGuard over WebSocket (looks like a web app connection).
    WebSocket,
    /// WireGuard over DNS-over-HTTPS (ultimate fallback).
    Doh,
}

/// Transport configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    pub transport_type: TransportType,
    /// Relay endpoint for this transport.
    pub endpoint: String,
    /// TLS SNI to use (for domain fronting).
    pub sni: Option<String>,
    /// HTTP Host header (real destination, hidden by fronting).
    pub host: Option<String>,
    /// Path for HTTPS/WebSocket connections.
    pub path: String,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            transport_type: TransportType::Direct,
            endpoint: String::new(),
            sni: None,
            host: None,
            path: "/bridge/v1/tunnel".to_string(),
        }
    }
}

/// Trait for pluggable transports.
///
/// A transport wraps raw WireGuard packets for transmission over
/// a different protocol that's harder to detect/block.
pub trait Transport: Send + Sync {
    /// Name of this transport (for logging).
    fn name(&self) -> &str;

    /// Wrap a WireGuard packet for transmission.
    fn wrap(&self, wg_packet: &[u8]) -> Vec<u8>;

    /// Unwrap a received packet to extract the WireGuard data.
    fn unwrap(&self, transport_packet: &[u8]) -> Option<Vec<u8>>;
}

/// HTTPS transport — encapsulates WireGuard packets in HTTP POST bodies.
///
/// To a network observer, this looks like a client making HTTPS requests
/// to a CDN. Combined with domain fronting, the censor can't determine
/// the actual destination without blocking the entire CDN.
pub struct HttpsTransport {
    config: TransportConfig,
}

impl HttpsTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }
}

impl Transport for HttpsTransport {
    fn name(&self) -> &str {
        "https"
    }

    fn wrap(&self, wg_packet: &[u8]) -> Vec<u8> {
        // Encode WireGuard packet as base64 in an HTTP POST body.
        // The actual HTTP framing happens at the connection layer;
        // here we just prepare the body payload.
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(wg_packet);

        // Wrap in a JSON body that looks like a normal API call
        let body = format!(
            r#"{{"data":"{}","ts":{}}}"#,
            encoded,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );

        body.into_bytes()
    }

    fn unwrap(&self, transport_packet: &[u8]) -> Option<Vec<u8>> {
        use base64::Engine;

        let text = std::str::from_utf8(transport_packet).ok()?;
        let json: serde_json::Value = serde_json::from_str(text).ok()?;
        let data = json.get("data")?.as_str()?;
        base64::engine::general_purpose::STANDARD.decode(data).ok()
    }
}

/// WebSocket transport — encapsulates WireGuard packets in WebSocket frames.
///
/// Looks like a persistent WebSocket connection to a web application.
/// Many censors allow WebSocket traffic since it's used by real-time apps.
pub struct WebSocketTransport {
    config: TransportConfig,
}

impl WebSocketTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }
}

impl Transport for WebSocketTransport {
    fn name(&self) -> &str {
        "websocket"
    }

    fn wrap(&self, wg_packet: &[u8]) -> Vec<u8> {
        // Simple binary WebSocket frame wrapping.
        // In production, we'd use a proper WebSocket library.
        // For now, prepend a minimal binary frame header.
        let len = wg_packet.len();
        let mut frame = Vec::with_capacity(10 + len);

        // WebSocket binary frame opcode
        frame.push(0x82); // FIN + binary opcode

        if len <= 125 {
            frame.push(len as u8);
        } else if len <= 65535 {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }

        frame.extend_from_slice(wg_packet);
        frame
    }

    fn unwrap(&self, transport_packet: &[u8]) -> Option<Vec<u8>> {
        if transport_packet.len() < 2 {
            return None;
        }

        let opcode = transport_packet[0] & 0x0F;
        if opcode != 2 {
            return None; // Not a binary frame
        }

        let len_byte = transport_packet[1] & 0x7F;
        let (payload_len, header_len) = if len_byte <= 125 {
            (len_byte as usize, 2)
        } else if len_byte == 126 {
            if transport_packet.len() < 4 {
                return None;
            }
            let len = u16::from_be_bytes([transport_packet[2], transport_packet[3]]) as usize;
            (len, 4)
        } else {
            if transport_packet.len() < 10 {
                return None;
            }
            let len = u64::from_be_bytes(
                transport_packet[2..10].try_into().ok()?,
            ) as usize;
            (len, 10)
        };

        if transport_packet.len() < header_len + payload_len {
            return None;
        }

        Some(transport_packet[header_len..header_len + payload_len].to_vec())
    }
}

/// DNS-over-HTTPS transport — ultimate fallback.
///
/// Encodes WireGuard packets as DNS TXT record queries over HTTPS.
/// Even the most restrictive networks usually allow DNS-over-HTTPS.
/// Lower bandwidth but extremely hard to block without breaking the internet.
pub struct DohTransport {
    config: TransportConfig,
}

impl DohTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }
}

impl Transport for DohTransport {
    fn name(&self) -> &str {
        "doh"
    }

    fn wrap(&self, wg_packet: &[u8]) -> Vec<u8> {
        use base64::Engine;

        // Encode the WireGuard packet as a DNS TXT query.
        // Split into 63-byte labels (DNS label limit) encoded as base32.
        // The domain looks like: <encoded-data>.t.bridge-relay.example.com
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wg_packet);

        // For the transport layer, we just return the encoded payload.
        // The actual DNS framing happens in the DoH HTTP request.
        encoded.into_bytes()
    }

    fn unwrap(&self, transport_packet: &[u8]) -> Option<Vec<u8>> {
        use base64::Engine;

        let text = std::str::from_utf8(transport_packet).ok()?;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(text).ok()
    }
}

/// Select the best transport based on network conditions.
pub fn select_transport(config: &TransportConfig) -> Box<dyn Transport> {
    match config.transport_type {
        TransportType::Direct => {
            // Direct mode returns packets unchanged
            Box::new(DirectTransport)
        }
        TransportType::Https => Box::new(HttpsTransport::new(config.clone())),
        TransportType::WebSocket => Box::new(WebSocketTransport::new(config.clone())),
        TransportType::Doh => Box::new(DohTransport::new(config.clone())),
    }
}

/// Passthrough transport for direct WireGuard UDP.
struct DirectTransport;

impl Transport for DirectTransport {
    fn name(&self) -> &str {
        "direct"
    }

    fn wrap(&self, wg_packet: &[u8]) -> Vec<u8> {
        wg_packet.to_vec()
    }

    fn unwrap(&self, transport_packet: &[u8]) -> Option<Vec<u8>> {
        Some(transport_packet.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_transport_passthrough() {
        let transport = DirectTransport;
        let data = b"raw wireguard packet data";
        let wrapped = transport.wrap(data);
        let unwrapped = transport.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn https_transport_roundtrip() {
        let config = TransportConfig {
            transport_type: TransportType::Https,
            endpoint: "https://cdn.example.com".to_string(),
            sni: Some("cdn.example.com".to_string()),
            host: Some("bridge-relay.internal".to_string()),
            path: "/api/v1/data".to_string(),
        };

        let transport = HttpsTransport::new(config);
        let data = b"wireguard handshake init packet here";
        let wrapped = transport.wrap(data);

        // Should be valid JSON
        let json: serde_json::Value = serde_json::from_slice(&wrapped).unwrap();
        assert!(json.get("data").is_some());
        assert!(json.get("ts").is_some());

        let unwrapped = transport.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn websocket_transport_roundtrip() {
        let config = TransportConfig::default();
        let transport = WebSocketTransport::new(config);

        // Small packet
        let data = b"small wg packet";
        let wrapped = transport.wrap(data);
        let unwrapped = transport.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, data);

        // Medium packet (>125 bytes)
        let medium = vec![0xAB; 500];
        let wrapped = transport.wrap(&medium);
        let unwrapped = transport.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, medium);
    }

    #[test]
    fn websocket_rejects_invalid_frame() {
        let config = TransportConfig::default();
        let transport = WebSocketTransport::new(config);

        assert!(transport.unwrap(&[]).is_none());
        assert!(transport.unwrap(&[0x81, 5, 1, 2, 3, 4, 5]).is_none()); // text frame, not binary
    }

    #[test]
    fn doh_transport_roundtrip() {
        let config = TransportConfig::default();
        let transport = DohTransport::new(config);

        let data = b"wireguard packet via dns";
        let wrapped = transport.wrap(data);
        let unwrapped = transport.unwrap(&wrapped).unwrap();
        assert_eq!(unwrapped, data);
    }

    #[test]
    fn select_transport_creates_correct_type() {
        let config = TransportConfig {
            transport_type: TransportType::Https,
            ..TransportConfig::default()
        };
        let transport = select_transport(&config);
        assert_eq!(transport.name(), "https");

        let config = TransportConfig {
            transport_type: TransportType::Direct,
            ..TransportConfig::default()
        };
        let transport = select_transport(&config);
        assert_eq!(transport.name(), "direct");
    }
}
