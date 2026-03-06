// VPNManager.swift - Manages NETunnelProviderManager for the Bridge VPN

import Foundation
import NetworkExtension
import Combine

@MainActor
class VPNManager: ObservableObject {
    @Published var status: VPNStatus = .disconnected
    @Published var stats: ConnectionStats = .zero
    @Published var errorMessage: String?

    private var tunnelManager: NETunnelProviderManager?
    private var statusObserver: Any?
    private var statsTimer: Timer?

    enum VPNStatus: String {
        case disconnected = "Disconnected"
        case connecting = "Connecting..."
        case connected = "Connected"
        case disconnecting = "Disconnecting..."
        case reasserting = "Reconnecting..."
    }

    struct ConnectionStats {
        var bytesSent: UInt64 = 0
        var bytesReceived: UInt64 = 0
        var duration: TimeInterval = 0

        static let zero = ConnectionStats()

        var formattedBytesSent: String { Self.formatBytes(bytesSent) }
        var formattedBytesReceived: String { Self.formatBytes(bytesReceived) }
        var formattedDuration: String { Self.formatDuration(duration) }

        private static func formatBytes(_ bytes: UInt64) -> String {
            let formatter = ByteCountFormatter()
            formatter.countStyle = .binary
            return formatter.string(fromByteCount: Int64(bytes))
        }

        private static func formatDuration(_ seconds: TimeInterval) -> String {
            let hours = Int(seconds) / 3600
            let minutes = (Int(seconds) % 3600) / 60
            let secs = Int(seconds) % 60
            if hours > 0 {
                return String(format: "%d:%02d:%02d", hours, minutes, secs)
            }
            return String(format: "%d:%02d", minutes, secs)
        }
    }

    init() {
        loadTunnelManager()
    }

    // MARK: - Tunnel Manager

    private func loadTunnelManager() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            Task { @MainActor in
                if let error = error {
                    self?.errorMessage = "Failed to load VPN config: \(error.localizedDescription)"
                    return
                }

                if let existing = managers?.first {
                    self?.tunnelManager = existing
                    self?.observeStatus()
                    self?.syncStatus()
                }
            }
        }
    }

    private func createTunnelManager(
        serverEndpoint: String,
        serverPublicKey: String,
        privateKey: String,
        tunnelId: String
    ) async throws -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        manager.localizedDescription = "Bridge VPN"

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.bridge.vpn.tunnel"
        proto.serverAddress = serverEndpoint
        proto.providerConfiguration = [
            "serverEndpoint": serverEndpoint,
            "serverPublicKey": serverPublicKey,
            "privateKey": privateKey,
            "tunnelId": tunnelId,
            "allowedIPs": "0.0.0.0/0",
            "dns": "1.1.1.1,8.8.8.8",
            "keepaliveSecs": 25,
        ]

        manager.protocolConfiguration = proto
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        return manager
    }

    // MARK: - Connect / Disconnect

    func connect(
        serverEndpoint: String,
        serverPublicKey: String,
        privateKey: String,
        tunnelId: String
    ) async {
        do {
            if tunnelManager == nil {
                tunnelManager = try await createTunnelManager(
                    serverEndpoint: serverEndpoint,
                    serverPublicKey: serverPublicKey,
                    privateKey: privateKey,
                    tunnelId: tunnelId
                )
                observeStatus()
            }

            guard let manager = tunnelManager else { return }

            let session = manager.connection as? NETunnelProviderSession
            try session?.startTunnel(options: nil)
            status = .connecting

        } catch {
            errorMessage = "Connect failed: \(error.localizedDescription)"
        }
    }

    func disconnect() {
        guard let session = tunnelManager?.connection as? NETunnelProviderSession else { return }
        session.stopTunnel()
        status = .disconnecting
    }

    // MARK: - Status Observation

    private func observeStatus() {
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: tunnelManager?.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.syncStatus()
            }
        }
    }

    private func syncStatus() {
        guard let connection = tunnelManager?.connection else {
            status = .disconnected
            return
        }

        switch connection.status {
        case .invalid, .disconnected:
            status = .disconnected
            stopStatsPolling()
        case .connecting:
            status = .connecting
        case .connected:
            status = .connected
            startStatsPolling()
        case .reasserting:
            status = .reasserting
        case .disconnecting:
            status = .disconnecting
        @unknown default:
            status = .disconnected
        }
    }

    // MARK: - Stats Polling

    private func startStatsPolling() {
        statsTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.pollStats()
            }
        }
    }

    private func stopStatsPolling() {
        statsTimer?.invalidate()
        statsTimer = nil
        stats = .zero
    }

    private func pollStats() {
        guard let session = tunnelManager?.connection as? NETunnelProviderSession else { return }

        let message = try? JSONEncoder().encode(["type": "stats"])
        guard let data = message else { return }

        try? session.sendProviderMessage(data) { [weak self] response in
            guard let response = response,
                  let stats = try? JSONDecoder().decode(StatsMessage.self, from: response) else { return }
            Task { @MainActor in
                self?.stats = ConnectionStats(
                    bytesSent: stats.bytesSent,
                    bytesReceived: stats.bytesReceived
                )
            }
        }
    }

    private struct StatsMessage: Codable {
        let bytesSent: UInt64
        let bytesReceived: UInt64
        let packetsSent: UInt64
        let packetsReceived: UInt64
    }

    deinit {
        if let observer = statusObserver {
            NotificationCenter.default.removeObserver(observer)
        }
        statsTimer?.invalidate()
    }
}
