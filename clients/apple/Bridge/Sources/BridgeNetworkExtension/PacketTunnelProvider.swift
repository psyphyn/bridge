// PacketTunnelProvider.swift - NEPacketTunnelProvider for Bridge VPN
//
// This is the core Network Extension that manages the VPN tunnel on Apple platforms.
// It runs as a separate process managed by the OS, receiving all network traffic
// when the VPN is active.

import NetworkExtension
import os.log
import BridgeCore

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = OSLog(subsystem: "com.bridge.vpn.tunnel", category: "PacketTunnel")
    private var activeTunnelId: String?

    // MARK: - Tunnel Lifecycle

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        os_log(.info, log: log, "Starting Bridge tunnel (core v%{public}@)",
               String(cString: bridge_version()))

        // Extract configuration from the NETunnelProviderProtocol
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let config = proto.providerConfiguration else {
            os_log(.error, log: log, "Missing provider configuration")
            completionHandler(BridgeExtensionError.missingConfiguration)
            return
        }

        guard let serverEndpoint = config["serverEndpoint"] as? String,
              let serverPublicKey = config["serverPublicKey"] as? String,
              let privateKey = config["privateKey"] as? String,
              let tunnelIdStr = config["tunnelId"] as? String else {
            os_log(.error, log: log, "Incomplete tunnel configuration")
            completionHandler(BridgeExtensionError.missingConfiguration)
            return
        }

        let allowedIPs = (config["allowedIPs"] as? String) ?? "0.0.0.0/0"
        let dnsServers = (config["dns"] as? String) ?? "1.1.1.1"
        let keepalive = UInt16(config["keepaliveSecs"] as? Int ?? 25)

        // Configure the tunnel through FFI
        let result = tunnelIdStr.withCString { tidPtr in
            privateKey.withCString { pkPtr in
                serverPublicKey.withCString { spkPtr in
                    serverEndpoint.withCString { epPtr in
                        allowedIPs.withCString { aipPtr in
                            dnsServers.withCString { dnsPtr in
                                var tunnelConfig = BridgeTunnelConfig(
                                    tunnel_id: tidPtr,
                                    private_key: pkPtr,
                                    peer_public_key: spkPtr,
                                    peer_endpoint: epPtr,
                                    allowed_ips: aipPtr,
                                    dns: dnsPtr,
                                    keepalive_secs: keepalive
                                )
                                return bridge_add_tunnel(&tunnelConfig)
                            }
                        }
                    }
                }
            }
        }

        guard result == BridgeResultOk else {
            os_log(.error, log: log, "Failed to add tunnel: %d", result.rawValue)
            completionHandler(BridgeExtensionError.tunnelSetupFailed)
            return
        }

        // Connect the tunnel
        let connectResult = tunnelIdStr.withCString { ptr in
            bridge_connect_tunnel(ptr)
        }

        guard connectResult == BridgeResultOk else {
            os_log(.error, log: log, "Failed to connect tunnel: %d", connectResult.rawValue)
            completionHandler(BridgeExtensionError.connectionFailed)
            return
        }

        activeTunnelId = tunnelIdStr

        // Configure the virtual network interface
        let networkSettings = buildNetworkSettings(
            tunnelAddress: "10.0.0.2",
            subnetMask: "255.255.255.0",
            dns: dnsServers.components(separatedBy: ",").map { $0.trimmingCharacters(in: .whitespaces) },
            mtu: 1420
        )

        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            if let error = error {
                os_log(.error, log: self?.log ?? .default, "Failed to set network settings: %{public}@",
                       error.localizedDescription)
                completionHandler(error)
                return
            }

            os_log(.info, log: self?.log ?? .default, "Tunnel started successfully")

            // Start reading packets from the virtual interface
            self?.startPacketForwarding()

            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        os_log(.info, log: log, "Stopping Bridge tunnel (reason: %d)", reason.rawValue)

        if let tunnelId = activeTunnelId {
            tunnelId.withCString { ptr in
                _ = bridge_disconnect_tunnel(ptr)
                _ = bridge_remove_tunnel(ptr)
            }
            activeTunnelId = nil
        }

        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle IPC messages from the main app (status queries, etc.)
        guard let message = try? JSONDecoder().decode(AppMessage.self, from: messageData) else {
            completionHandler?(nil)
            return
        }

        switch message.type {
        case .status:
            let response = buildStatusResponse()
            let data = try? JSONEncoder().encode(response)
            completionHandler?(data)

        case .stats:
            let response = buildStatsResponse()
            let data = try? JSONEncoder().encode(response)
            completionHandler?(data)
        }
    }

    // MARK: - Packet Forwarding

    /// Read IP packets from the virtual TUN interface and forward them through WireGuard.
    private func startPacketForwarding() {
        guard let tunnelId = activeTunnelId else { return }

        packetFlow.readPackets { [weak self] packets, protocols in
            for (i, packet) in packets.enumerated() {
                self?.forwardPacket(packet, tunnelId: tunnelId)
            }
            // Continue reading
            self?.startPacketForwarding()
        }
    }

    private func forwardPacket(_ packet: Data, tunnelId: String) {
        packet.withUnsafeBytes { rawBuf in
            guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            tunnelId.withCString { tidPtr in
                _ = bridge_send_packet(tidPtr, ptr, rawBuf.count)
            }
        }
    }

    // MARK: - Network Settings

    private func buildNetworkSettings(
        tunnelAddress: String,
        subnetMask: String,
        dns: [String],
        mtu: Int
    ) -> NEPacketTunnelNetworkSettings {
        let remoteAddress = "10.0.0.1" // Gateway
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)

        // IPv4 settings
        let ipv4 = NEIPv4Settings(addresses: [tunnelAddress], subnetMasks: [subnetMask])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4

        // DNS
        let dnsSettings = NEDNSSettings(servers: dns)
        dnsSettings.matchDomains = [""] // Match all domains
        settings.dnsSettings = dnsSettings

        // MTU
        settings.mtu = NSNumber(value: mtu)

        return settings
    }

    // MARK: - IPC Message Types

    private struct AppMessage: Codable {
        enum MessageType: String, Codable {
            case status
            case stats
        }
        let type: MessageType
    }

    private struct StatusResponse: Codable {
        let connected: Bool
        let tunnelId: String?
        let version: String
    }

    private struct StatsResponse: Codable {
        let bytesSent: UInt64
        let bytesReceived: UInt64
        let packetsSent: UInt64
        let packetsReceived: UInt64
    }

    private func buildStatusResponse() -> StatusResponse {
        let connected: Bool
        if let tid = activeTunnelId {
            let state = tid.withCString { ptr in bridge_tunnel_state(ptr) }
            connected = state == BridgeTunnelStateConnected
        } else {
            connected = false
        }

        return StatusResponse(
            connected: connected,
            tunnelId: activeTunnelId,
            version: String(cString: bridge_version())
        )
    }

    private func buildStatsResponse() -> StatsResponse {
        guard let tid = activeTunnelId else {
            return StatsResponse(bytesSent: 0, bytesReceived: 0, packetsSent: 0, packetsReceived: 0)
        }

        var stats = BridgeTunnelStats()
        let found = tid.withCString { ptr in bridge_tunnel_stats(ptr, &stats) }

        if found {
            return StatsResponse(
                bytesSent: stats.bytes_sent,
                bytesReceived: stats.bytes_received,
                packetsSent: stats.packets_sent,
                packetsReceived: stats.packets_received
            )
        } else {
            return StatsResponse(bytesSent: 0, bytesReceived: 0, packetsSent: 0, packetsReceived: 0)
        }
    }
}

// MARK: - Errors

enum BridgeExtensionError: Error, LocalizedError {
    case missingConfiguration
    case tunnelSetupFailed
    case connectionFailed

    var errorDescription: String? {
        switch self {
        case .missingConfiguration: return "Missing VPN configuration"
        case .tunnelSetupFailed: return "Failed to set up tunnel"
        case .connectionFailed: return "Failed to connect tunnel"
        }
    }
}
