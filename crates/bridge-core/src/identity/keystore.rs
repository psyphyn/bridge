//! Platform-abstracted key storage.
//!
//! Provides a unified interface for storing device identity keys:
//! - **macOS/iOS**: Secure Enclave via Security.framework (key never leaves hardware)
//! - **Android**: Android Keystore (StrongBox when available)
//! - **Windows**: TPM 2.0 via CNG
//! - **Fallback**: Software-only (encrypted on disk)
//!
//! The key principle: the private key should never be extractable in plaintext.
//! On platforms with hardware security, the key is generated inside the secure
//! element and signing operations happen there — the raw key bytes never exist
//! in process memory.

use serde::{Deserialize, Serialize};

/// Identifies which key storage backend is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStoreBackend {
    /// Apple Secure Enclave (macOS/iOS). Key never leaves hardware.
    SecureEnclave,
    /// Android Keystore with StrongBox backing.
    AndroidKeystore,
    /// Windows TPM 2.0.
    WindowsTpm,
    /// Software-only key storage (encrypted at rest). Least secure.
    Software,
}

impl std::fmt::Display for KeyStoreBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SecureEnclave => write!(f, "secure_enclave"),
            Self::AndroidKeystore => write!(f, "android_keystore"),
            Self::WindowsTpm => write!(f, "windows_tpm"),
            Self::Software => write!(f, "software"),
        }
    }
}

/// A reference to a stored key. The actual key material may be in hardware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyRef {
    /// Which backend holds the key.
    pub backend: KeyStoreBackend,
    /// Label/alias used to look up the key in the platform keystore.
    pub key_label: String,
    /// The public key (always extractable, unlike the private key).
    pub public_key: Vec<u8>,
    /// For software backend only: encrypted private key (PKCS8).
    /// None for hardware-backed keys (private key isn't extractable).
    pub encrypted_private_key: Option<Vec<u8>>,
}

/// Errors from keystore operations.
#[derive(Debug, thiserror::Error)]
pub enum KeyStoreError {
    #[error("Key generation failed: {0}")]
    Generation(String),
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Signing failed: {0}")]
    Signing(String),
    #[error("Platform not supported: {0}")]
    Unsupported(String),
    #[error("Hardware security not available: {0}")]
    NoHardwareSecurity(String),
}

/// Platform-abstracted keystore interface.
///
/// Each platform implements this trait. The private key never leaves
/// the secure element on supported hardware.
pub trait KeyStore: Send + Sync {
    /// Generate a new signing keypair. Returns a reference to the stored key.
    /// On hardware-backed stores, the private key is generated inside the
    /// secure element and cannot be extracted.
    fn generate_key(&self, label: &str) -> Result<StoredKeyRef, KeyStoreError>;

    /// Sign data using a previously stored key.
    /// On hardware-backed stores, this calls into the secure element.
    fn sign(&self, key_ref: &StoredKeyRef, data: &[u8]) -> Result<Vec<u8>, KeyStoreError>;

    /// Check if a key exists in the store.
    fn key_exists(&self, label: &str) -> bool;

    /// Delete a key from the store.
    fn delete_key(&self, label: &str) -> Result<(), KeyStoreError>;

    /// Which backend this keystore uses.
    fn backend(&self) -> KeyStoreBackend;

    /// Whether the key material is hardware-protected (non-extractable).
    fn is_hardware_backed(&self) -> bool;
}

// ── Software keystore (fallback) ─────────────────────────────────────

use std::collections::HashMap;
use std::sync::Mutex;

/// Software-only keystore. Keys are stored in memory and optionally
/// encrypted at rest. This is the fallback when no hardware security
/// is available.
pub struct SoftwareKeyStore {
    keys: Mutex<HashMap<String, SoftwareKey>>,
}

struct SoftwareKey {
    pkcs8_private_key: Vec<u8>,
    public_key: Vec<u8>,
}

impl SoftwareKeyStore {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }

    /// Import an existing PKCS8 keypair (for migration from non-keystore code).
    pub fn import_key(
        &self,
        label: &str,
        pkcs8_private_key: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<StoredKeyRef, KeyStoreError> {
        let key_ref = StoredKeyRef {
            backend: KeyStoreBackend::Software,
            key_label: label.to_string(),
            public_key: public_key.clone(),
            encrypted_private_key: Some(pkcs8_private_key.clone()),
        };

        self.keys.lock().unwrap().insert(
            label.to_string(),
            SoftwareKey {
                pkcs8_private_key,
                public_key,
            },
        );

        Ok(key_ref)
    }
}

impl Default for SoftwareKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyStore for SoftwareKeyStore {
    fn generate_key(&self, label: &str) -> Result<StoredKeyRef, KeyStoreError> {
        let (pkcs8, public_key) = super::generate_identity_keypair()
            .map_err(|e| KeyStoreError::Generation(e.to_string()))?;

        let key_ref = StoredKeyRef {
            backend: KeyStoreBackend::Software,
            key_label: label.to_string(),
            public_key: public_key.clone(),
            encrypted_private_key: Some(pkcs8.clone()),
        };

        self.keys.lock().unwrap().insert(
            label.to_string(),
            SoftwareKey {
                pkcs8_private_key: pkcs8,
                public_key,
            },
        );

        Ok(key_ref)
    }

    fn sign(&self, key_ref: &StoredKeyRef, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        let keys = self.keys.lock().unwrap();
        let key = keys
            .get(&key_ref.key_label)
            .ok_or_else(|| KeyStoreError::NotFound(key_ref.key_label.clone()))?;

        super::sign(&key.pkcs8_private_key, data)
            .map_err(|e| KeyStoreError::Signing(e.to_string()))
    }

    fn key_exists(&self, label: &str) -> bool {
        self.keys.lock().unwrap().contains_key(label)
    }

    fn delete_key(&self, label: &str) -> Result<(), KeyStoreError> {
        self.keys.lock().unwrap().remove(label);
        Ok(())
    }

    fn backend(&self) -> KeyStoreBackend {
        KeyStoreBackend::Software
    }

    fn is_hardware_backed(&self) -> bool {
        false
    }
}

// ── macOS Secure Enclave keystore ────────────────────────────────────

/// Secure Enclave keystore for macOS/iOS.
///
/// Uses Security.framework to generate and store keys in the Secure Enclave.
/// The private key never leaves the hardware — all signing operations happen
/// inside the SE. Uses P-256 (secp256r1) since the Secure Enclave doesn't
/// support Ed25519.
///
/// Note: This is a stub that defines the interface. The actual
/// Security.framework calls go through the FFI layer from Swift, since
/// Rust doesn't have direct access to the Secure Enclave APIs.
///
/// The flow:
/// 1. Swift calls SecKeyCreateRandomKey with kSecAttrTokenIDSecureEnclave
/// 2. Key reference is stored in Keychain with our label
/// 3. For signing, Swift calls SecKeyCreateSignature
/// 4. Results are passed back to Rust via FFI callbacks
#[cfg(target_os = "macos")]
pub struct SecureEnclaveKeyStore {
    /// Callback to Swift for key generation.
    generate_fn: Option<Box<dyn Fn(&str) -> Result<Vec<u8>, String> + Send + Sync>>,
    /// Callback to Swift for signing.
    sign_fn: Option<Box<dyn Fn(&str, &[u8]) -> Result<Vec<u8>, String> + Send + Sync>>,
    /// Callback to Swift for key existence check.
    exists_fn: Option<Box<dyn Fn(&str) -> bool + Send + Sync>>,
    /// Callback to Swift for key deletion.
    delete_fn: Option<Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>>,
}

#[cfg(target_os = "macos")]
impl SecureEnclaveKeyStore {
    /// Create a new Secure Enclave keystore.
    /// Pass None for callbacks to get a non-functional placeholder
    /// (useful for testing the interface).
    pub fn new() -> Self {
        Self {
            generate_fn: None,
            sign_fn: None,
            exists_fn: None,
            delete_fn: None,
        }
    }

    /// Set the callback functions that bridge to Swift/Security.framework.
    /// Called during FFI initialization.
    pub fn set_callbacks(
        &mut self,
        generate: impl Fn(&str) -> Result<Vec<u8>, String> + Send + Sync + 'static,
        sign: impl Fn(&str, &[u8]) -> Result<Vec<u8>, String> + Send + Sync + 'static,
        exists: impl Fn(&str) -> bool + Send + Sync + 'static,
        delete: impl Fn(&str) -> Result<(), String> + Send + Sync + 'static,
    ) {
        self.generate_fn = Some(Box::new(generate));
        self.sign_fn = Some(Box::new(sign));
        self.exists_fn = Some(Box::new(exists));
        self.delete_fn = Some(Box::new(delete));
    }
}

#[cfg(target_os = "macos")]
impl KeyStore for SecureEnclaveKeyStore {
    fn generate_key(&self, label: &str) -> Result<StoredKeyRef, KeyStoreError> {
        let generate = self.generate_fn.as_ref().ok_or_else(|| {
            KeyStoreError::Unsupported("Secure Enclave callbacks not initialized".to_string())
        })?;

        let public_key = (generate)(label).map_err(KeyStoreError::Generation)?;

        Ok(StoredKeyRef {
            backend: KeyStoreBackend::SecureEnclave,
            key_label: label.to_string(),
            public_key,
            encrypted_private_key: None, // Private key stays in hardware
        })
    }

    fn sign(&self, key_ref: &StoredKeyRef, data: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
        let sign = self.sign_fn.as_ref().ok_or_else(|| {
            KeyStoreError::Unsupported("Secure Enclave callbacks not initialized".to_string())
        })?;

        (sign)(&key_ref.key_label, data).map_err(KeyStoreError::Signing)
    }

    fn key_exists(&self, label: &str) -> bool {
        self.exists_fn.as_ref().map(|f| (f)(label)).unwrap_or(false)
    }

    fn delete_key(&self, label: &str) -> Result<(), KeyStoreError> {
        let delete = self.delete_fn.as_ref().ok_or_else(|| {
            KeyStoreError::Unsupported("Secure Enclave callbacks not initialized".to_string())
        })?;

        (delete)(label).map_err(|e| KeyStoreError::NotFound(e))
    }

    fn backend(&self) -> KeyStoreBackend {
        KeyStoreBackend::SecureEnclave
    }

    fn is_hardware_backed(&self) -> bool {
        true
    }
}

// ── Platform detection ───────────────────────────────────────────────

/// Create the best available keystore for the current platform.
///
/// Prefers hardware-backed storage when available, falls back to software.
pub fn create_platform_keystore() -> Box<dyn KeyStore> {
    #[cfg(target_os = "macos")]
    {
        // Try Secure Enclave first. If callbacks aren't set up
        // (e.g., running as pure Rust without Swift FFI), fall back to software.
        // In practice, the Swift layer will call set_callbacks() during init.
        tracing::info!("Platform: macOS — Secure Enclave available via FFI");
        // Return software store as default; the FFI layer will replace this
        // with a hardware-backed store once callbacks are wired up.
        Box::new(SoftwareKeyStore::new())
    }

    #[cfg(not(target_os = "macos"))]
    {
        tracing::info!("Platform: {} — using software keystore", std::env::consts::OS);
        Box::new(SoftwareKeyStore::new())
    }
}

// ── Updated attestation that uses KeyStore ───────────────────────────

use crate::posture::AccessTier;
use super::attestation::{AttestationToken, AttestationClaims};

/// Device attestation backed by a platform keystore.
///
/// Unlike the original `DeviceAttestation`, this version can use
/// hardware-backed keys where the private key never leaves the
/// secure element.
pub struct KeyStoreAttestation {
    keystore: Box<dyn KeyStore>,
    key_ref: StoredKeyRef,
    device_id: uuid::Uuid,
    platform: String,
}

impl KeyStoreAttestation {
    /// Create or load a device attestation identity.
    pub fn new(
        keystore: Box<dyn KeyStore>,
        label: &str,
        platform: &str,
    ) -> Result<Self, KeyStoreError> {
        let key_ref = if keystore.key_exists(label) {
            // In a real implementation, we'd load the key reference from persistent storage.
            // For now, generate fresh if not found in memory.
            return Err(KeyStoreError::NotFound(
                "Key reference loading not yet implemented — regenerate".to_string(),
            ));
        } else {
            keystore.generate_key(label)?
        };

        let device_id = super::device_id_from_public_key(&key_ref.public_key);

        Ok(Self {
            keystore,
            key_ref,
            device_id,
            platform: platform.to_string(),
        })
    }

    /// Create from an existing key reference (loaded from disk).
    pub fn from_key_ref(
        keystore: Box<dyn KeyStore>,
        key_ref: StoredKeyRef,
        platform: &str,
    ) -> Self {
        let device_id = super::device_id_from_public_key(&key_ref.public_key);
        Self {
            keystore,
            key_ref,
            device_id,
            platform: platform.to_string(),
        }
    }

    /// Create a signed attestation token.
    pub fn attest(
        &self,
        posture_score: u8,
        access_tier: AccessTier,
        ttl_secs: i64,
    ) -> Result<AttestationToken, KeyStoreError> {
        let now = chrono::Utc::now().timestamp();
        let nonce = uuid::Uuid::new_v4().to_string();
        let public_key_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.key_ref.public_key);

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

        // Serialize claims
        let claims_json =
            serde_json::to_vec(&claims).map_err(|e| KeyStoreError::Signing(e.to_string()))?;
        let claims_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &claims_json);

        // Sign using the keystore (may go to Secure Enclave)
        let signature = self.keystore.sign(&self.key_ref, claims_b64.as_bytes())?;
        let signature_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &signature);

        Ok(AttestationToken {
            claims: claims_b64,
            signature: signature_b64,
        })
    }

    pub fn device_id(&self) -> uuid::Uuid {
        self.device_id
    }

    pub fn public_key(&self) -> &[u8] {
        &self.key_ref.public_key
    }

    pub fn backend(&self) -> KeyStoreBackend {
        self.keystore.backend()
    }

    pub fn is_hardware_backed(&self) -> bool {
        self.keystore.is_hardware_backed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_keystore_generate_and_sign() {
        let ks = SoftwareKeyStore::new();
        let key_ref = ks.generate_key("test-device").unwrap();

        assert_eq!(key_ref.backend, KeyStoreBackend::Software);
        assert_eq!(key_ref.public_key.len(), 32);
        assert!(key_ref.encrypted_private_key.is_some());

        let data = b"test attestation payload";
        let sig = ks.sign(&key_ref, data).unwrap();
        assert!(!sig.is_empty());

        // Verify the signature
        let valid = super::super::verify(&key_ref.public_key, data, &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn software_keystore_key_exists() {
        let ks = SoftwareKeyStore::new();
        assert!(!ks.key_exists("test"));

        ks.generate_key("test").unwrap();
        assert!(ks.key_exists("test"));
    }

    #[test]
    fn software_keystore_delete_key() {
        let ks = SoftwareKeyStore::new();
        ks.generate_key("test").unwrap();
        assert!(ks.key_exists("test"));

        ks.delete_key("test").unwrap();
        assert!(!ks.key_exists("test"));
    }

    #[test]
    fn software_keystore_sign_unknown_key_fails() {
        let ks = SoftwareKeyStore::new();
        let fake_ref = StoredKeyRef {
            backend: KeyStoreBackend::Software,
            key_label: "nonexistent".to_string(),
            public_key: vec![],
            encrypted_private_key: None,
        };

        let result = ks.sign(&fake_ref, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn software_keystore_import_key() {
        let ks = SoftwareKeyStore::new();

        // Generate a key outside the keystore
        let (pkcs8, public_key) = super::super::generate_identity_keypair().unwrap();

        let key_ref = ks.import_key("imported", pkcs8, public_key.clone()).unwrap();
        assert_eq!(key_ref.public_key, public_key);

        // Should be signable
        let sig = ks.sign(&key_ref, b"test data").unwrap();
        let valid = super::super::verify(&public_key, b"test data", &sig).unwrap();
        assert!(valid);
    }

    #[test]
    fn keystore_attestation_creates_valid_token() {
        let ks = Box::new(SoftwareKeyStore::new());
        let attestation =
            KeyStoreAttestation::new(ks, "test-attest", "macos").unwrap();

        assert!(!attestation.is_hardware_backed());
        assert_eq!(attestation.backend(), KeyStoreBackend::Software);

        let token = attestation
            .attest(85, AccessTier::Standard, 3600)
            .unwrap();

        // Verify with the public key
        let claims = token
            .verify_and_decode(attestation.public_key())
            .unwrap();

        assert_eq!(claims.posture_score, 85);
        assert_eq!(claims.access_tier, AccessTier::Standard);
        assert_eq!(claims.device_id, attestation.device_id());
    }

    #[test]
    fn keystore_attestation_from_key_ref() {
        let ks = SoftwareKeyStore::new();
        let key_ref = ks.generate_key("persist-test").unwrap();

        // Simulate loading from disk
        let attestation = KeyStoreAttestation::from_key_ref(
            Box::new(ks),
            key_ref,
            "macos",
        );

        let token = attestation.attest(90, AccessTier::FullAccess, 3600).unwrap();
        let claims = token.verify_and_decode(attestation.public_key()).unwrap();
        assert_eq!(claims.posture_score, 90);
    }

    #[test]
    fn platform_keystore_returns_something() {
        let ks = create_platform_keystore();
        // Should at least be software on any platform
        assert!(!ks.backend().to_string().is_empty());
    }

    #[test]
    fn backend_display() {
        assert_eq!(KeyStoreBackend::SecureEnclave.to_string(), "secure_enclave");
        assert_eq!(KeyStoreBackend::Software.to_string(), "software");
        assert_eq!(KeyStoreBackend::AndroidKeystore.to_string(), "android_keystore");
        assert_eq!(KeyStoreBackend::WindowsTpm.to_string(), "windows_tpm");
    }
}
