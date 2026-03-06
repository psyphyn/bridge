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

        // Initialize per-app router
        initializeRouter(defaultTunnelId: tunnelIdStr, config: config)

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

    // MARK: - Per-App Router

    /// Initialize the per-app router from provider config.
    private func initializeRouter(defaultTunnelId: String, config: [String: Any]) {
        // Init router: mode 0 = TunnelAll
        let mode: UInt8 = (config["splitTunnel"] as? Bool == true) ? 1 : 0
        defaultTunnelId.withCString { ptr in
            _ = bridge_router_init(ptr, mode)
        }

        // Add router groups from config if present
        if let groups = config["routerGroups"] as? [[String: Any]] {
            for group in groups {
                guard let name = group["name"] as? String,
                      let tid = group["tunnelId"] as? String else { continue }
                let apps = (group["applications"] as? String) ?? ""
                let domains = (group["domains"] as? String) ?? ""
                let ipRanges = (group["ipRanges"] as? String) ?? ""
                let priority = UInt32(group["priority"] as? Int ?? 10)

                name.withCString { nPtr in
                    tid.withCString { tPtr in
                        apps.withCString { aPtr in
                            domains.withCString { dPtr in
                                ipRanges.withCString { iPtr in
                                    _ = bridge_router_add_group(nPtr, tPtr, aPtr, dPtr, iPtr, priority)
                                }
                            }
                        }
                    }
                }
            }
        }

        // Set bypass apps
        if let bypass = config["bypassApps"] as? String {
            bypass.withCString { ptr in
                _ = bridge_router_set_bypass_apps(ptr)
            }
        }

        // Set bypass domains
        if let bypass = config["bypassDomains"] as? String {
            bypass.withCString { ptr in
                _ = bridge_router_set_bypass_domains(ptr)
            }
        }

        os_log(.info, log: log, "Router initialized with %d groups", bridge_router_group_count())
    }

    // MARK: - Packet Forwarding

    /// Read IP packets from the virtual TUN interface and route them through the appropriate tunnel.
    private func startPacketForwarding() {
        guard let defaultTunnelId = activeTunnelId else { return }

        packetFlow.readPackets { [weak self] packets, protocols in
            for packet in packets {
                self?.routeAndForwardPacket(packet, defaultTunnelId: defaultTunnelId)
            }
            // Continue reading
            self?.startPacketForwarding()
        }
    }

    /// Route a packet through the per-app router, then forward to the chosen tunnel.
    private func routeAndForwardPacket(_ packet: Data, defaultTunnelId: String) {
        packet.withUnsafeBytes { rawBuf in
            guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }

            // Ask the router which tunnel this packet should go to
            let routeResult = bridge_router_route_packet(nil, ptr, rawBuf.count)

            switch routeResult.decision {
            case BridgeRoutingDecisionTunnel:
                // Route through the specified tunnel
                if let tidPtr = routeResult.tunnel_id {
                    let tunnelId = String(cString: tidPtr)
                    tunnelId.withCString { tidCStr in
                        _ = bridge_send_packet(tidCStr, ptr, rawBuf.count)
                    }
                    bridge_free_string(tidPtr)
                } else {
                    // Fallback to default tunnel
                    defaultTunnelId.withCString { tidPtr in
                        _ = bridge_send_packet(tidPtr, ptr, rawBuf.count)
                    }
                }

            case BridgeRoutingDecisionDirect:
                // Bypass: write packet back to the system network stack
                // In a Network Extension, bypassed traffic is handled by not
                // capturing it (via excludedRoutes), but if we get it here,
                // we just pass it through the default tunnel.
                defaultTunnelId.withCString { tidPtr in
                    _ = bridge_send_packet(tidPtr, ptr, rawBuf.count)
                }

            case BridgeRoutingDecisionDrop:
                // Silently drop the packet (blocked by policy)
                break

            default:
                break
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
