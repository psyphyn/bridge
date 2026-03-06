//! Cryptographic device identity using hardware-bound keys.
//!
//! Manages device keypairs and handles device registration,
//! attestation tokens, and mTLS certificate management.
//!
//! Architecture:
//! - Each device generates an Ed25519 signing keypair at first launch
//! - The public key becomes the device's cryptographic identity
//! - Attestation tokens prove device identity + posture to the control plane
//! - In production, keys are bound to TPM/Secure Enclave (platform-specific)

mod attestation;

pub use attestation::{AttestationToken, AttestationClaims, DeviceAttestation};

use base64::Engine;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A device's cryptographic identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Unique device identifier (derived from public key).
    pub device_id: Uuid,
    /// Ed25519 public key (base64-encoded).
    pub public_key: String,
    /// Human-readable device name.
    pub hostname: String,
    /// Platform (macos, ios, android, windows, linux).
    pub platform: String,
    /// When this identity was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Errors from identity operations.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Key generation failed: {0}")]
    KeyGeneration(String),
    #[error("Signing failed: {0}")]
    Signing(String),
    #[error("Verification failed: {0}")]
    Verification(String),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
}

/// Generate a new Ed25519 keypair for device identity.
///
/// Returns (PKCS8 private key bytes, public key bytes).
/// In production, the private key would be stored in TPM/Secure Enclave.
pub fn generate_identity_keypair() -> Result<(Vec<u8>, Vec<u8>), IdentityError> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|e| IdentityError::KeyGeneration(e.to_string()))?;

    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|e| IdentityError::KeyGeneration(e.to_string()))?;

    let public_key = key_pair.public_key().as_ref().to_vec();

    Ok((pkcs8.as_ref().to_vec(), public_key))
}

/// Derive a deterministic device ID from a public key.
///
/// Uses the first 16 bytes of the public key as a UUID v4-like identifier.
pub fn device_id_from_public_key(public_key: &[u8]) -> Uuid {
    if public_key.len() < 16 {
        return Uuid::nil();
    }
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&public_key[..16]);
    // Set version (4) and variant (RFC 4122) bits
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    Uuid::from_bytes(bytes)
}

/// Create a DeviceIdentity from a keypair.
pub fn create_identity(
    public_key: &[u8],
    hostname: &str,
    platform: &str,
) -> DeviceIdentity {
    let device_id = device_id_from_public_key(public_key);
    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(public_key);

    DeviceIdentity {
        device_id,
        public_key: public_key_b64,
        hostname: hostname.to_string(),
        platform: platform.to_string(),
        created_at: chrono::Utc::now(),
    }
}

/// Sign a message with an Ed25519 private key (PKCS8 format).
pub fn sign(pkcs8_private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, IdentityError> {
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_private_key)
        .map_err(|e| IdentityError::Signing(e.to_string()))?;
    let sig = key_pair.sign(message);
    Ok(sig.as_ref().to_vec())
}

/// Verify a signature against a public key.
pub fn verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, IdentityError> {
    use ring::signature;

    let peer_public_key = signature::UnparsedPublicKey::new(
        &signature::ED25519,
        public_key,
    );

    match peer_public_key.verify(message, signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_keypair_succeeds() {
        let (private_key, public_key) = generate_identity_keypair().unwrap();
        assert_eq!(public_key.len(), 32); // Ed25519 public key is 32 bytes
        assert!(!private_key.is_empty());
    }

    #[test]
    fn device_id_is_deterministic() {
        let (_, public_key) = generate_identity_keypair().unwrap();
        let id1 = device_id_from_public_key(&public_key);
        let id2 = device_id_from_public_key(&public_key);
        assert_eq!(id1, id2);
        assert!(!id1.is_nil());
    }

    #[test]
    fn different_keys_different_ids() {
        let (_, pk1) = generate_identity_keypair().unwrap();
        let (_, pk2) = generate_identity_keypair().unwrap();
        assert_ne!(device_id_from_public_key(&pk1), device_id_from_public_key(&pk2));
    }

    #[test]
    fn sign_and_verify() {
        let (private_key, public_key) = generate_identity_keypair().unwrap();
        let message = b"Bridge device attestation payload";

        let signature = sign(&private_key, message).unwrap();
        assert!(verify(&public_key, message, &signature).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let (private_key, public_key) = generate_identity_keypair().unwrap();
        let signature = sign(&private_key, b"original message").unwrap();
        assert!(!verify(&public_key, b"tampered message", &signature).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (private_key, _) = generate_identity_keypair().unwrap();
        let (_, wrong_public_key) = generate_identity_keypair().unwrap();
        let message = b"test message";
        let signature = sign(&private_key, message).unwrap();
        assert!(!verify(&wrong_public_key, message, &signature).unwrap());
    }

    #[test]
    fn create_identity_from_keypair() {
        let (_, public_key) = generate_identity_keypair().unwrap();
        let identity = create_identity(&public_key, "test-machine", "macos");
        assert!(!identity.device_id.is_nil());
        assert_eq!(identity.hostname, "test-machine");
        assert_eq!(identity.platform, "macos");
    }
}
