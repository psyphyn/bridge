// BridgeEngine.swift - Swift wrapper around the Bridge Rust FFI
//
// Provides a safe, idiomatic Swift API over the C bridge_ffi functions.

import Foundation
import BridgeCore

// MARK: - Tunnel State

public enum TunnelState: Int {
    case disconnected = 0
    case connecting = 1
    case connected = 2
    case reconnecting = 3
    case disconnecting = 4
    case unknown = 5

    init(ffi: BridgeTunnelState) {
        self = TunnelState(rawValue: Int(ffi.rawValue)) ?? .unknown
    }
}

// MARK: - Tunnel Stats

public struct TunnelStats {
    public let bytesSent: UInt64
    public let bytesReceived: UInt64
    public let packetsSent: UInt64
    public let packetsReceived: UInt64
    public let lastHandshakeSecsAgo: UInt64
}

// MARK: - Tunnel Assignment (from control plane)

public struct TunnelAssignment {
    public let tunnelId: UUID
    public let serverPublicKey: String
    public let serverEndpoint: String
    public let allowedIPs: [String]
    public let dns: [String]
    public let keepaliveSecs: UInt16

    public init(
        tunnelId: UUID,
        serverPublicKey: String,
        serverEndpoint: String,
        allowedIPs: [String] = ["0.0.0.0/0"],
        dns: [String] = ["1.1.1.1"],
        keepaliveSecs: UInt16 = 25
    ) {
        self.tunnelId = tunnelId
        self.serverPublicKey = serverPublicKey
        self.serverEndpoint = serverEndpoint
        self.allowedIPs = allowedIPs
        self.dns = dns
        self.keepaliveSecs = keepaliveSecs
    }
}

// MARK: - Bridge Engine Error

public enum BridgeError: Error, LocalizedError {
    case invalidArgument
    case tunnelNotFound
    case tunnelNotConnected
    case connectionFailed
    case internalError

    init?(result: BridgeResult) {
        switch result {
        case BridgeResultOk:
            return nil
        case BridgeResultInvalidArgument:
            self = .invalidArgument
        case BridgeResultTunnelNotFound:
            self = .tunnelNotFound
        case BridgeResultTunnelNotConnected:
            self = .tunnelNotConnected
        case BridgeResultConnectionFailed:
            self = .connectionFailed
        default:
            self = .internalError
        }
    }

    public var errorDescription: String? {
        switch self {
        case .invalidArgument: return "Invalid argument"
        case .tunnelNotFound: return "Tunnel not found"
        case .tunnelNotConnected: return "Tunnel not connected"
        case .connectionFailed: return "Connection failed"
        case .internalError: return "Internal error"
        }
    }
}

// MARK: - Bridge Engine

/// Main entry point for the Bridge VPN engine.
///
/// Wraps the Rust FFI layer and provides tunnel management for
/// both the main app UI and the Network Extension.
public final class BridgeEngine {
    public static let shared = BridgeEngine()

    /// Bridge core version string.
    public var version: String {
        guard let cStr = bridge_version() else { return "unknown" }
        return String(cString: cStr)
    }

    private init() {
        // Initialize logging
        bridge_init_logging(nil, nil)
    }

    // MARK: - Keypair Generation

    /// Generate a new WireGuard keypair.
    public func generateWireGuardKeypair() -> (privateKey: String, publicKey: String) {
        let kp = bridge_generate_keypair()
        defer {
            bridge_free_string(kp.private_key)
            bridge_free_string(kp.public_key)
        }
        let privateKey = String(cString: kp.private_key)
        let publicKey = String(cString: kp.public_key)
        return (privateKey, publicKey)
    }

    /// Generate a new Ed25519 device identity.
    public func generateIdentity() -> (privateKey: String, publicKey: String, deviceId: String)? {
        let kp = bridge_generate_identity()
        guard kp.private_key != nil else { return nil }
        defer {
            bridge_free_string(kp.private_key)
            bridge_free_string(kp.public_key)
            bridge_free_string(kp.device_id)
        }
        return (
            String(cString: kp.private_key),
            String(cString: kp.public_key),
            String(cString: kp.device_id)
        )
    }

    // MARK: - Tunnel Management

    /// Add a tunnel from a control plane assignment.
    public func addTunnel(
        privateKey: String,
        assignment: TunnelAssignment
    ) throws {
        let tunnelIdStr = assignment.tunnelId.uuidString.lowercased()
        let allowedIPs = assignment.allowedIPs.joined(separator: ",")
        let dns = assignment.dns.joined(separator: ",")

        let result = tunnelIdStr.withCString { tidPtr in
            privateKey.withCString { pkPtr in
                assignment.serverPublicKey.withCString { spkPtr in
                    assignment.serverEndpoint.withCString { epPtr in
                        allowedIPs.withCString { aipPtr in
                            dns.withCString { dnsPtr in
                                var config = BridgeTunnelConfig(
                                    tunnel_id: tidPtr,
                                    private_key: pkPtr,
                                    peer_public_key: spkPtr,
                                    peer_endpoint: epPtr,
                                    allowed_ips: aipPtr,
                                    dns: dnsPtr,
                                    keepalive_secs: assignment.keepaliveSecs
                                )
                                return bridge_add_tunnel(&config)
                            }
                        }
                    }
                }
            }
        }

        if let error = BridgeError(result: result) {
            throw error
        }
    }

    /// Connect a registered tunnel.
    public func connectTunnel(_ tunnelId: UUID) throws {
        let result = tunnelId.uuidString.lowercased().withCString { ptr in
            bridge_connect_tunnel(ptr)
        }
        if let error = BridgeError(result: result) {
            throw error
        }
    }

    /// Disconnect a tunnel.
    public func disconnectTunnel(_ tunnelId: UUID) throws {
        let result = tunnelId.uuidString.lowercased().withCString { ptr in
            bridge_disconnect_tunnel(ptr)
        }
        if let error = BridgeError(result: result) {
            throw error
        }
    }

    /// Remove a tunnel.
    public func removeTunnel(_ tunnelId: UUID) throws {
        let result = tunnelId.uuidString.lowercased().withCString { ptr in
            bridge_remove_tunnel(ptr)
        }
        if let error = BridgeError(result: result) {
            throw error
        }
    }

    /// Get tunnel state.
    public func tunnelState(_ tunnelId: UUID) -> TunnelState {
        let state = tunnelId.uuidString.lowercased().withCString { ptr in
            bridge_tunnel_state(ptr)
        }
        return TunnelState(ffi: state)
    }

    /// Get tunnel statistics.
    public func tunnelStats(_ tunnelId: UUID) -> TunnelStats? {
        var stats = BridgeTunnelStats()
        let found = tunnelId.uuidString.lowercased().withCString { ptr in
            bridge_tunnel_stats(ptr, &stats)
        }
        guard found else { return nil }
        return TunnelStats(
            bytesSent: stats.bytes_sent,
            bytesReceived: stats.bytes_received,
            packetsSent: stats.packets_sent,
            packetsReceived: stats.packets_received,
            lastHandshakeSecsAgo: stats.last_handshake_secs_ago
        )
    }

    /// Number of registered tunnels.
    public var tunnelCount: Int {
        Int(bridge_tunnel_count())
    }

    // MARK: - Packet I/O

    /// Send an IP packet through a tunnel.
    public func sendPacket(_ tunnelId: UUID, data: Data) throws {
        let result = data.withUnsafeBytes { rawBuf in
            guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                return BridgeResultInvalidArgument
            }
            return tunnelId.uuidString.lowercased().withCString { tidPtr in
                bridge_send_packet(tidPtr, ptr, rawBuf.count)
            }
        }
        if let error = BridgeError(result: result) {
            throw error
        }
    }
}
