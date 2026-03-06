// SecureEnclaveKeyStore.swift - Hardware-bound key storage via Secure Enclave
//
// Generates and stores signing keys in the Apple Secure Enclave.
// The private key never leaves the hardware — all signing happens inside the SE.
//
// Uses P-256 (secp256r1) since Secure Enclave doesn't support Ed25519.
// The control plane must accept both Ed25519 (software) and P-256 (hardware) signatures.

import Foundation
import Security
import CryptoKit
import LocalAuthentication

/// Manages cryptographic keys in the Apple Secure Enclave.
///
/// Key properties:
/// - Keys are bound to the device hardware and cannot be extracted
/// - Keys survive app reinstalls if stored in Keychain with appropriate flags
/// - Biometric or passcode can be required for key use (optional)
/// - Uses NIST P-256 (the only curve Secure Enclave supports)
public final class SecureEnclaveKeyStore {
    public static let shared = SecureEnclaveKeyStore()

    /// Service identifier for Keychain storage
    private let service = "com.bridge.vpn.identity"

    /// Check if Secure Enclave is available on this device.
    public var isAvailable: Bool {
        if #available(macOS 10.15, iOS 13.0, *) {
            return SecureEnclave.isAvailable
        }
        return false
    }

    // MARK: - Key Generation

    /// Generate a new P-256 signing key in the Secure Enclave.
    /// Returns the public key bytes (65 bytes uncompressed, or 33 compressed).
    public func generateKey(label: String) throws -> Data {
        guard isAvailable else {
            throw SecureEnclaveError.notAvailable
        }

        // Delete any existing key with this label first
        deleteKey(label: label)

        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            nil
        )

        guard let accessControl = access else {
            throw SecureEnclaveError.accessControlFailed
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData(for: label),
                kSecAttrAccessControl as String: accessControl,
                kSecAttrLabel as String: label,
            ] as [String: Any],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw SecureEnclaveError.keyGenerationFailed(desc)
        }

        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw SecureEnclaveError.keyGenerationFailed("Failed to extract public key")
        }

        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw SecureEnclaveError.keyGenerationFailed(desc)
        }

        return publicKeyData
    }

    // MARK: - Signing

    /// Sign data using a Secure Enclave key.
    /// The signing operation happens entirely inside the Secure Enclave hardware.
    public func sign(label: String, data: Data) throws -> Data {
        guard let privateKey = loadPrivateKey(label: label) else {
            throw SecureEnclaveError.keyNotFound(label)
        }

        let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw SecureEnclaveError.algorithmNotSupported
        }

        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            algorithm,
            data as CFData,
            &error
        ) as Data? else {
            let desc = error?.takeRetainedValue().localizedDescription ?? "unknown"
            throw SecureEnclaveError.signingFailed(desc)
        }

        return signature
    }

    // MARK: - Key Lookup

    /// Check if a key exists in the Secure Enclave.
    public func keyExists(label: String) -> Bool {
        return loadPrivateKey(label: label) != nil
    }

    /// Delete a key from the Secure Enclave.
    @discardableResult
    public func deleteKey(label: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData(for: label),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }

    /// Get the public key for a stored key.
    public func publicKey(label: String) -> Data? {
        guard let privateKey = loadPrivateKey(label: label) else { return nil }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }

        var error: Unmanaged<CFError>?
        return SecKeyCopyExternalRepresentation(publicKey, &error) as Data?
    }

    // MARK: - Private Helpers

    private func loadPrivateKey(label: String) -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData(for: label),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        guard status == errSecSuccess else { return nil }
        return (item as! SecKey)
    }

    private func tagData(for label: String) -> Data {
        "\(service).\(label)".data(using: .utf8)!
    }
}

// MARK: - Errors

public enum SecureEnclaveError: Error, LocalizedError {
    case notAvailable
    case accessControlFailed
    case keyGenerationFailed(String)
    case keyNotFound(String)
    case signingFailed(String)
    case algorithmNotSupported

    public var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Secure Enclave is not available on this device"
        case .accessControlFailed:
            return "Failed to create access control for Secure Enclave key"
        case .keyGenerationFailed(let detail):
            return "Key generation failed: \(detail)"
        case .keyNotFound(let label):
            return "Key '\(label)' not found in Secure Enclave"
        case .signingFailed(let detail):
            return "Signing failed: \(detail)"
        case .algorithmNotSupported:
            return "ECDSA P-256 not supported by this key"
        }
    }
}
