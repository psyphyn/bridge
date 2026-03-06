//! Device attestation tokens.
//!
//! Attestation tokens are signed claims that prove:
//! 1. The device has a valid cryptographic identity
//! 2. The device's posture meets minimum requirements
//! 3. The token was generated recently (not replayed)
//!
//! The control plane verifies these tokens to make access decisions.
//! Similar to JWT but purpose-built for device attestation.

use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{sign, verify, IdentityError};
use crate::posture::AccessTier;

/// Claims in an attestation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationClaims {
    /// Device ID (from public key).
    pub device_id: Uuid,
    /// Device public key (base64).
    pub public_key: String,
    /// Current posture score (0-100).
    pub posture_score: u8,
    /// Access tier based on posture.
    pub access_tier: AccessTier,
    /// Platform identifier.
    pub platform: String,
    /// Token issue time (Unix timestamp).
    pub issued_at: i64,
    /// Token expiry time (Unix timestamp).
    pub expires_at: i64,
    /// Nonce to prevent replay.
    pub nonce: String,
}

/// A signed attestation token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationToken {
    /// Base64-encoded serialized claims.
    pub claims: String,
    /// Base64-encoded Ed25519 signature over the claims.
    pub signature: String,
}

impl AttestationToken {
    /// Create and sign an attestation token.
    pub fn create(
        pkcs8_private_key: &[u8],
        claims: AttestationClaims,
    ) -> Result<Self, IdentityError> {
        let claims_json = serde_json::to_vec(&claims)
            .map_err(|e| IdentityError::Signing(e.to_string()))?;

        let claims_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&claims_json);
        let signature = sign(pkcs8_private_key, claims_b64.as_bytes())?;
        let signature_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature);

        Ok(Self {
            claims: claims_b64,
            signature: signature_b64,
        })
    }

    /// Verify the token signature and decode claims.
    pub fn verify_and_decode(
        &self,
        public_key: &[u8],
    ) -> Result<AttestationClaims, IdentityError> {
        let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.signature)
            .map_err(|e| IdentityError::Verification(e.to_string()))?;

        let valid = verify(public_key, self.claims.as_bytes(), &signature)?;
        if !valid {
            return Err(IdentityError::Verification("Invalid signature".to_string()));
        }

        let claims_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&self.claims)
            .map_err(|e| IdentityError::Verification(e.to_string()))?;

        let claims: AttestationClaims = serde_json::from_slice(&claims_json)
            .map_err(|e| IdentityError::Verification(e.to_string()))?;

        // Check expiry
        let now = chrono::Utc::now().timestamp();
        if claims.expires_at < now {
            return Err(IdentityError::Verification("Token expired".to_string()));
        }

        Ok(claims)
    }

    /// Compact string representation (claims.signature).
    pub fn to_compact(&self) -> String {
        format!("{}.{}", self.claims, self.signature)
    }

    /// Parse from compact string representation.
    pub fn from_compact(compact: &str) -> Result<Self, IdentityError> {
        let parts: Vec<&str> = compact.splitn(2, '.').collect();
        if parts.len() != 2 {
            return Err(IdentityError::InvalidKey("Invalid compact token format".to_string()));
        }

        Ok(Self {
            claims: parts[0].to_string(),
            signature: parts[1].to_string(),
        })
    }
}

/// Helper to build attestation tokens.
pub struct DeviceAttestation {
    pkcs8_private_key: Vec<u8>,
    public_key: Vec<u8>,
    device_id: Uuid,
    platform: String,
}

impl DeviceAttestation {
    pub fn new(
        pkcs8_private_key: Vec<u8>,
        public_key: Vec<u8>,
        platform: &str,
    ) -> Self {
        let device_id = super::device_id_from_public_key(&public_key);

        Self {
            pkcs8_private_key,
            public_key,
            device_id,
            platform: platform.to_string(),
        }
    }

    /// Create a fresh attestation token with the given posture score.
    pub fn attest(
        &self,
        posture_score: u8,
        access_tier: AccessTier,
        ttl_secs: i64,
    ) -> Result<AttestationToken, IdentityError> {
        let now = chrono::Utc::now().timestamp();
        let nonce = Uuid::new_v4().to_string();
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&self.public_key);

        let claims = AttestationClaims {
            device_id: self.device_id,
            public_key: public_key_b64,
            posture_score,
            access_tier,
            platform: self.platform.clone(),
            issued_at: now,
            expires_at: now + ttl_secs,
            nonce,
        };

        AttestationToken::create(&self.pkcs8_private_key, claims)
    }

    pub fn device_id(&self) -> Uuid {
        self.device_id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_identity_keypair;

    fn create_test_attestation() -> (DeviceAttestation, Vec<u8>) {
        let (private_key, public_key) = generate_identity_keypair().unwrap();
        let attestation = DeviceAttestation::new(
            private_key,
            public_key.clone(),
            "macos",
        );
        (attestation, public_key)
    }

    #[test]
    fn create_and_verify_token() {
        let (attestation, public_key) = create_test_attestation();

        let token = attestation.attest(85, AccessTier::Standard, 3600).unwrap();
        let claims = token.verify_and_decode(&public_key).unwrap();

        assert_eq!(claims.posture_score, 85);
        assert_eq!(claims.access_tier, AccessTier::Standard);
        assert_eq!(claims.platform, "macos");
        assert_eq!(claims.device_id, attestation.device_id());
    }

    #[test]
    fn token_rejects_wrong_key() {
        let (attestation, _) = create_test_attestation();
        let (_, wrong_public_key) = generate_identity_keypair().unwrap();

        let token = attestation.attest(85, AccessTier::Standard, 3600).unwrap();
        let result = token.verify_and_decode(&wrong_public_key);
        assert!(result.is_err());
    }

    #[test]
    fn expired_token_rejected() {
        let (attestation, public_key) = create_test_attestation();

        // Create a token that expired 1 second ago
        let token = attestation.attest(85, AccessTier::Standard, -1).unwrap();
        let result = token.verify_and_decode(&public_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expired"));
    }

    #[test]
    fn compact_format_roundtrip() {
        let (attestation, public_key) = create_test_attestation();
        let token = attestation.attest(90, AccessTier::FullAccess, 3600).unwrap();

        let compact = token.to_compact();
        assert!(compact.contains('.'));

        let parsed = AttestationToken::from_compact(&compact).unwrap();
        let claims = parsed.verify_and_decode(&public_key).unwrap();
        assert_eq!(claims.posture_score, 90);
    }

    #[test]
    fn token_contains_nonce() {
        let (attestation, public_key) = create_test_attestation();

        let token1 = attestation.attest(85, AccessTier::Standard, 3600).unwrap();
        let token2 = attestation.attest(85, AccessTier::Standard, 3600).unwrap();

        let claims1 = token1.verify_and_decode(&public_key).unwrap();
        let claims2 = token2.verify_and_decode(&public_key).unwrap();

        // Each token should have a unique nonce
        assert_ne!(claims1.nonce, claims2.nonce);
    }

    #[test]
    fn token_serializes_to_json() {
        let (attestation, _) = create_test_attestation();
        let token = attestation.attest(85, AccessTier::Standard, 3600).unwrap();

        let json = serde_json::to_string(&token).unwrap();
        let parsed: AttestationToken = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.claims, token.claims);
        assert_eq!(parsed.signature, token.signature);
    }
}
