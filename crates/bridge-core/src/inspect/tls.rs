//! TLS inspection engine — selective MITM for managed traffic.
//!
//! Inspired by mitmproxy's approach to TLS interception:
//! 1. Bridge CA generates a root certificate (installed on managed devices)
//! 2. When intercepting, Bridge generates per-domain leaf certificates signed by the CA
//! 3. Traffic is decrypted, inspected, then re-encrypted to the destination
//!
//! Key difference from mitmproxy: selective interception per-domain and per-app,
//! controlled by admin policy. Personal traffic can be left encrypted.

use std::collections::HashMap;

use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair,
    BasicConstraints, IsCa,
};
use serde::{Deserialize, Serialize};

/// Configuration for TLS inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInspectConfig {
    /// Domains to intercept (supports * wildcard prefix).
    pub intercept_domains: Vec<String>,
    /// Domains to NEVER intercept (banking, health, etc).
    pub bypass_domains: Vec<String>,
    /// Whether to intercept by default (true = intercept unless bypassed).
    pub default_intercept: bool,
}

impl Default for TlsInspectConfig {
    fn default() -> Self {
        Self {
            intercept_domains: Vec::new(),
            bypass_domains: vec![
                // Never intercept sensitive services
                "*.banking.com".to_string(),
                "*.health.gov".to_string(),
                "*.1password.com".to_string(),
                "*.bitwarden.com".to_string(),
            ],
            default_intercept: false,
        }
    }
}

impl TlsInspectConfig {
    /// Check if a domain should be intercepted.
    pub fn should_intercept(&self, domain: &str) -> bool {
        // Bypass list always wins
        if self.bypass_domains.iter().any(|p| domain_matches(domain, p)) {
            return false;
        }

        // Check intercept list
        if self.intercept_domains.iter().any(|p| domain_matches(domain, p)) {
            return true;
        }

        self.default_intercept
    }
}

/// Bridge Certificate Authority for TLS inspection.
///
/// Generates a self-signed root CA certificate. Managed devices install
/// this CA to trust Bridge's inspection certificates.
pub struct BridgeCA {
    /// PEM-encoded CA certificate.
    ca_cert_pem: String,
    /// PEM-encoded CA private key.
    ca_key_pem: String,
    /// Cached leaf certificates per domain.
    cert_cache: HashMap<String, CachedCert>,
}

/// A cached leaf certificate for a domain.
struct CachedCert {
    cert_pem: String,
    key_pem: String,
}

impl BridgeCA {
    /// Generate a new Bridge CA with a self-signed root certificate.
    pub fn generate() -> Result<Self, String> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "Bridge Inspection CA");
        params.distinguished_name.push(DnType::OrganizationName, "Bridge Security");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let key_pair = KeyPair::generate()
            .map_err(|e| format!("Failed to generate CA key: {}", e))?;

        let ca_cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("Failed to create CA cert: {}", e))?;

        let ca_cert_pem = ca_cert.pem();
        let ca_key_pem = key_pair.serialize_pem();

        tracing::info!("Bridge CA certificate generated");

        Ok(Self {
            ca_cert_pem,
            ca_key_pem,
            cert_cache: HashMap::new(),
        })
    }

    /// Load an existing CA from PEM-encoded certificate and key.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, String> {
        // Validate by parsing
        let _key = KeyPair::from_pem(key_pem)
            .map_err(|e| format!("Invalid CA key: {}", e))?;

        Ok(Self {
            ca_cert_pem: cert_pem.to_string(),
            ca_key_pem: key_pem.to_string(),
            cert_cache: HashMap::new(),
        })
    }

    /// Get the CA certificate in PEM format (for installation on devices).
    pub fn ca_cert_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Generate a leaf certificate for a domain, signed by this CA.
    ///
    /// This certificate is presented to the client during MITM interception.
    /// The client trusts it because they have the Bridge CA installed.
    pub fn generate_leaf_cert(&mut self, domain: &str) -> Result<(&str, &str), String> {
        // Return cached cert if available
        if self.cert_cache.contains_key(domain) {
            let cached = &self.cert_cache[domain];
            return Ok((&cached.cert_pem, &cached.key_pem));
        }

        // Reconstruct CA for signing
        let ca_key = KeyPair::from_pem(&self.ca_key_pem)
            .map_err(|e| format!("Failed to load CA key: {}", e))?;

        let mut ca_params = CertificateParams::default();
        ca_params.distinguished_name = DistinguishedName::new();
        ca_params.distinguished_name.push(DnType::CommonName, "Bridge Inspection CA");
        ca_params.distinguished_name.push(DnType::OrganizationName, "Bridge Security");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        let ca_cert = ca_params
            .self_signed(&ca_key)
            .map_err(|e| format!("Failed to reconstruct CA: {}", e))?;

        // Generate leaf certificate
        let leaf_params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| format!("Invalid domain: {}", e))?;

        let leaf_key = KeyPair::generate()
            .map_err(|e| format!("Failed to generate leaf key: {}", e))?;

        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .map_err(|e| format!("Failed to sign leaf cert: {}", e))?;

        let cert_pem = leaf_cert.pem();
        let key_pem = leaf_key.serialize_pem();

        self.cert_cache.insert(
            domain.to_string(),
            CachedCert {
                cert_pem: cert_pem.clone(),
                key_pem: key_pem.clone(),
            },
        );

        let cached = &self.cert_cache[domain];
        Ok((&cached.cert_pem, &cached.key_pem))
    }

    /// Number of cached leaf certificates.
    pub fn cache_size(&self) -> usize {
        self.cert_cache.len()
    }

    /// Clear the certificate cache.
    pub fn clear_cache(&mut self) {
        self.cert_cache.clear();
    }
}

/// Match a domain against a pattern (supports * wildcard prefix).
fn domain_matches(domain: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        domain.ends_with(suffix) || domain == &pattern[2..]
    } else {
        domain == pattern
    }
}

/// Extract the SNI (Server Name Indication) from a TLS ClientHello.
///
/// This is used to determine the target domain before interception.
/// Returns None if the packet is not a TLS ClientHello or has no SNI.
pub fn extract_sni(data: &[u8]) -> Option<String> {
    // TLS record: type(1) + version(2) + length(2) + data
    if data.len() < 5 || data[0] != 0x16 {
        return None; // Not a TLS handshake record
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return None;
    }

    let hs = &data[5..];
    if hs.is_empty() || hs[0] != 0x01 {
        return None; // Not a ClientHello
    }

    // ClientHello: type(1) + length(3) + version(2) + random(32) + session_id_len(1)
    if hs.len() < 38 {
        return None;
    }

    let session_id_len = hs[38] as usize;
    let mut offset = 39 + session_id_len;

    // Skip cipher suites
    if offset + 2 > hs.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;

    // Skip compression methods
    if offset + 1 > hs.len() {
        return None;
    }
    let comp_methods_len = hs[offset] as usize;
    offset += 1 + comp_methods_len;

    // Extensions
    if offset + 2 > hs.len() {
        return None;
    }
    let extensions_len = u16::from_be_bytes([hs[offset], hs[offset + 1]]) as usize;
    offset += 2;

    let extensions_end = offset + extensions_len;
    while offset + 4 <= extensions_end && offset + 4 <= hs.len() {
        let ext_type = u16::from_be_bytes([hs[offset], hs[offset + 1]]);
        let ext_len = u16::from_be_bytes([hs[offset + 2], hs[offset + 3]]) as usize;
        offset += 4;

        if ext_type == 0x0000 {
            // SNI extension
            if offset + ext_len <= hs.len() && ext_len > 5 {
                // server_name_list_length(2) + server_name_type(1) + name_length(2) + name
                let name_len = u16::from_be_bytes([hs[offset + 3], hs[offset + 4]]) as usize;
                if offset + 5 + name_len <= hs.len() {
                    let sni_bytes = &hs[offset + 5..offset + 5 + name_len];
                    return String::from_utf8(sni_bytes.to_vec()).ok();
                }
            }
            return None;
        }

        offset += ext_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_default_no_intercept() {
        let config = TlsInspectConfig::default();
        assert!(!config.should_intercept("www.example.com"));
    }

    #[test]
    fn config_intercept_specific_domain() {
        let config = TlsInspectConfig {
            intercept_domains: vec!["*.example.com".to_string()],
            bypass_domains: vec![],
            default_intercept: false,
        };

        assert!(config.should_intercept("www.example.com"));
        assert!(config.should_intercept("api.example.com"));
        assert!(!config.should_intercept("www.other.com"));
    }

    #[test]
    fn config_bypass_overrides_intercept() {
        let config = TlsInspectConfig {
            intercept_domains: vec![],
            bypass_domains: vec!["*.banking.com".to_string()],
            default_intercept: true, // Intercept everything by default
        };

        assert!(!config.should_intercept("secure.banking.com"));
        assert!(config.should_intercept("www.example.com"));
    }

    #[test]
    fn config_bypass_overrides_specific_intercept() {
        let config = TlsInspectConfig {
            intercept_domains: vec!["*.example.com".to_string()],
            bypass_domains: vec!["secure.example.com".to_string()],
            default_intercept: false,
        };

        assert!(config.should_intercept("www.example.com"));
        assert!(!config.should_intercept("secure.example.com"));
    }

    #[test]
    fn generate_ca_certificate() {
        let ca = BridgeCA::generate().unwrap();
        let pem = ca.ca_cert_pem();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.contains("-----END CERTIFICATE-----"));
    }

    #[test]
    fn generate_leaf_certificate() {
        let mut ca = BridgeCA::generate().unwrap();
        let (cert_pem, key_pem) = ca.generate_leaf_cert("www.example.com").unwrap();

        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn leaf_cert_is_cached() {
        let mut ca = BridgeCA::generate().unwrap();
        assert_eq!(ca.cache_size(), 0);

        ca.generate_leaf_cert("www.example.com").unwrap();
        assert_eq!(ca.cache_size(), 1);

        // Second call should use cache
        ca.generate_leaf_cert("www.example.com").unwrap();
        assert_eq!(ca.cache_size(), 1);

        // Different domain creates new entry
        ca.generate_leaf_cert("api.example.com").unwrap();
        assert_eq!(ca.cache_size(), 2);
    }

    #[test]
    fn extract_sni_from_client_hello() {
        // Minimal TLS 1.2 ClientHello with SNI = "example.com"
        // This is a hand-crafted minimal packet for testing
        let domain = "example.com";
        let domain_bytes = domain.as_bytes();

        let mut packet = Vec::new();

        // TLS Record Header
        packet.push(0x16); // Handshake
        packet.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 (record layer)

        // Build the ClientHello first
        let mut client_hello = Vec::new();
        client_hello.push(0x01); // ClientHello
        // Length placeholder (3 bytes) - will fill later
        let ch_len_pos = client_hello.len();
        client_hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        client_hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        client_hello.extend_from_slice(&[0u8; 32]); // Random
        client_hello.push(0x00); // Session ID length = 0

        // Cipher suites (2 bytes length + one cipher)
        client_hello.extend_from_slice(&[0x00, 0x02]); // 2 bytes of ciphers
        client_hello.extend_from_slice(&[0x00, 0xFF]); // one cipher suite

        // Compression methods
        client_hello.push(0x01); // 1 method
        client_hello.push(0x00); // null compression

        // Extensions
        let mut extensions = Vec::new();

        // SNI extension (type 0x0000)
        extensions.extend_from_slice(&[0x00, 0x00]); // Extension type: SNI
        let sni_list_len = 3 + domain_bytes.len(); // type(1) + len(2) + name
        let ext_data_len = 2 + sni_list_len; // list_len(2) + sni_list
        extensions.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
        extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        extensions.push(0x00); // Host name type
        extensions.extend_from_slice(&(domain_bytes.len() as u16).to_be_bytes());
        extensions.extend_from_slice(domain_bytes);

        // Extensions length
        client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        client_hello.extend_from_slice(&extensions);

        // Fill ClientHello length (3 bytes, excluding the type byte and length itself)
        let ch_body_len = client_hello.len() - 4; // subtract type(1) + length(3)
        client_hello[ch_len_pos] = ((ch_body_len >> 16) & 0xFF) as u8;
        client_hello[ch_len_pos + 1] = ((ch_body_len >> 8) & 0xFF) as u8;
        client_hello[ch_len_pos + 2] = (ch_body_len & 0xFF) as u8;

        // TLS record length
        packet.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
        packet.extend_from_slice(&client_hello);

        let sni = extract_sni(&packet);
        assert_eq!(sni, Some("example.com".to_string()));
    }

    #[test]
    fn extract_sni_rejects_non_tls() {
        assert!(extract_sni(b"Hello").is_none());
        assert!(extract_sni(&[]).is_none());
        assert!(extract_sni(&[0x16, 0x03, 0x01]).is_none()); // Too short
    }

    #[test]
    fn domain_matching_exact() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("other.com", "example.com"));
    }

    #[test]
    fn domain_matching_wildcard() {
        assert!(domain_matches("sub.example.com", "*.example.com"));
        assert!(domain_matches("example.com", "*.example.com"));
        assert!(!domain_matches("notexample.com", "*.example.com"));
    }
}
