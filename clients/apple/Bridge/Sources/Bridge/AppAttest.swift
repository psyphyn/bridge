// AppAttest.swift - Apple App Attest integration
//
// Uses DCAppAttestService to get Apple-signed attestation that proves:
// 1. This is a genuine Apple device (not a simulator/emulator)
// 2. This specific app generated the key (not a modified binary)
// 3. The device has not been compromised (jailbreak detection)
//
// Flow:
// 1. Generate a key in App Attest (device-bound, non-extractable)
// 2. Attest the key with Apple — Apple signs a certificate chain
// 3. Send the attestation to our control plane for verification
// 4. For subsequent requests, create assertions (signed challenges)

import DeviceCheck
import CryptoKit
import Foundation

/// Manages Apple App Attest for device integrity verification.
@available(macOS 14.0, iOS 14.0, *)
public final class AppAttestManager {
    public static let shared = AppAttestManager()

    private let service = DCAppAttestService.shared
    private var keyId: String?

    /// Whether App Attest is supported on this device.
    public var isSupported: Bool {
        service.isSupported
    }

    // MARK: - Key Generation

    /// Generate a new App Attest key.
    /// The key is stored in the Secure Enclave by Apple's framework.
    public func generateKey() async throws -> String {
        guard isSupported else {
            throw AppAttestError.notSupported
        }

        let keyId = try await service.generateKey()
        self.keyId = keyId
        return keyId
    }

    // MARK: - Attestation

    /// Attest the key with Apple's servers.
    ///
    /// The server challenge should be a random value from your control plane.
    /// Apple returns an attestation object containing:
    /// - A certificate chain rooted at Apple's App Attest CA
    /// - The app's App ID and team ID
    /// - A receipt for future assertion verification
    ///
    /// Returns the raw attestation object to send to the control plane.
    public func attestKey(challenge: Data) async throws -> Data {
        guard let keyId = keyId else {
            throw AppAttestError.noKey
        }

        // Hash the challenge (App Attest expects SHA-256 of the client data)
        let challengeHash = Data(SHA256.hash(data: challenge))

        let attestation = try await service.attestKey(keyId, clientDataHash: challengeHash)
        return attestation
    }

    // MARK: - Assertions

    /// Create a signed assertion for an ongoing request.
    ///
    /// Unlike attestation (one-time), assertions are used for every
    /// authenticated request. They prove the same device that attested
    /// is making this specific request.
    ///
    /// `payload` is the request data to sign (e.g., JSON body hash).
    public func createAssertion(payload: Data) async throws -> Data {
        guard let keyId = keyId else {
            throw AppAttestError.noKey
        }

        let payloadHash = Data(SHA256.hash(data: payload))
        let assertion = try await service.generateAssertion(keyId, clientDataHash: payloadHash)
        return assertion
    }

    // MARK: - Integration with Bridge

    /// Full attestation flow for Bridge device registration.
    ///
    /// 1. Generates an App Attest key
    /// 2. Requests a challenge from the control plane
    /// 3. Attests the key with Apple
    /// 4. Sends attestation to control plane for verification
    ///
    /// Returns the verified device token from the control plane.
    public func performAttestation(
        controlPlaneURL: URL
    ) async throws -> AttestationResult {
        // Step 1: Generate key
        let keyId = try await generateKey()

        // Step 2: Get challenge from control plane
        let challenge = try await fetchChallenge(from: controlPlaneURL)

        // Step 3: Attest with Apple
        let attestationObject = try await attestKey(challenge: challenge)

        // Step 4: Send to control plane for verification
        let result = try await submitAttestation(
            to: controlPlaneURL,
            keyId: keyId,
            attestation: attestationObject,
            challenge: challenge
        )

        return result
    }

    // MARK: - Control Plane Communication

    private func fetchChallenge(from baseURL: URL) async throws -> Data {
        let url = baseURL.appendingPathComponent("api/v1/attest/challenge")
        let (data, response) = try await URLSession.shared.data(from: url)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw AppAttestError.serverError("Failed to fetch challenge")
        }

        let challengeResponse = try JSONDecoder().decode(ChallengeResponse.self, from: data)
        guard let challengeData = Data(base64Encoded: challengeResponse.challenge) else {
            throw AppAttestError.serverError("Invalid challenge format")
        }

        return challengeData
    }

    private func submitAttestation(
        to baseURL: URL,
        keyId: String,
        attestation: Data,
        challenge: Data
    ) async throws -> AttestationResult {
        let url = baseURL.appendingPathComponent("api/v1/attest/verify")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let body = AttestationSubmission(
            keyId: keyId,
            attestation: attestation.base64EncodedString(),
            challenge: challenge.base64EncodedString()
        )
        request.httpBody = try JSONEncoder().encode(body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw AppAttestError.serverError("Attestation verification failed")
        }

        return try JSONDecoder().decode(AttestationResult.self, from: data)
    }
}

// MARK: - Types

public struct AttestationResult: Codable {
    public let verified: Bool
    public let deviceToken: String?
    public let trustLevel: String // "hardware", "software", "unknown"
}

struct ChallengeResponse: Codable {
    let challenge: String // base64
    let expiresAt: String
}

struct AttestationSubmission: Codable {
    let keyId: String
    let attestation: String // base64
    let challenge: String   // base64
}

// MARK: - Errors

public enum AppAttestError: Error, LocalizedError {
    case notSupported
    case noKey
    case serverError(String)
    case verificationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .notSupported:
            return "App Attest is not supported on this device"
        case .noKey:
            return "No App Attest key generated. Call generateKey() first."
        case .serverError(let detail):
            return "Server error: \(detail)"
        case .verificationFailed(let detail):
            return "Verification failed: \(detail)"
        }
    }
}
