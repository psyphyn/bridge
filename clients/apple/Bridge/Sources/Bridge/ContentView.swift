// ContentView.swift - Main UI for Bridge VPN

import SwiftUI

struct ContentView: View {
    @EnvironmentObject var vpnManager: VPNManager

    var body: some View {
        VStack(spacing: 24) {
            // Header
            VStack(spacing: 4) {
                Image(systemName: "shield.checkered")
                    .font(.system(size: 48))
                    .foregroundStyle(statusColor)

                Text("Bridge")
                    .font(.title.bold())

                Text("v\(BridgeEngine.shared.version)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 32)

            // Status
            VStack(spacing: 8) {
                Text(vpnManager.status.rawValue)
                    .font(.headline)
                    .foregroundStyle(statusColor)

                if vpnManager.status == .connected {
                    StatsView(stats: vpnManager.stats)
                }
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))

            // Connect button
            Button(action: toggleConnection) {
                HStack {
                    Image(systemName: buttonIcon)
                    Text(buttonTitle)
                }
                .font(.headline)
                .foregroundStyle(.white)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
                .background(buttonColor, in: RoundedRectangle(cornerRadius: 12))
            }
            .buttonStyle(.plain)
            .disabled(isTransitioning)

            // Error message
            if let error = vpnManager.errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }

            Spacer()
        }
        .padding(.horizontal, 24)
        .frame(minWidth: 320, minHeight: 480)
    }

    // MARK: - Computed Properties

    private var statusColor: Color {
        switch vpnManager.status {
        case .connected: return .green
        case .connecting, .reconnecting: return .orange
        case .disconnecting: return .yellow
        case .disconnected: return .secondary
        }
    }

    private var buttonIcon: String {
        vpnManager.status == .connected ? "stop.fill" : "play.fill"
    }

    private var buttonTitle: String {
        vpnManager.status == .connected ? "Disconnect" : "Connect"
    }

    private var buttonColor: Color {
        vpnManager.status == .connected ? .red : .blue
    }

    private var isTransitioning: Bool {
        vpnManager.status == .connecting || vpnManager.status == .disconnecting
    }

    // MARK: - Actions

    private func toggleConnection() {
        if vpnManager.status == .connected {
            vpnManager.disconnect()
        } else {
            // In a real app, these would come from the control plane registration
            Task {
                let keypair = BridgeEngine.shared.generateWireGuardKeypair()
                await vpnManager.connect(
                    serverEndpoint: "relay.bridge.example:51820",
                    serverPublicKey: "placeholder",
                    privateKey: keypair.privateKey,
                    tunnelId: UUID().uuidString.lowercased()
                )
            }
        }
    }
}

// MARK: - Stats View

struct StatsView: View {
    let stats: VPNManager.ConnectionStats

    var body: some View {
        HStack(spacing: 24) {
            StatItem(
                icon: "arrow.up.circle.fill",
                label: "Sent",
                value: stats.formattedBytesSent
            )
            StatItem(
                icon: "arrow.down.circle.fill",
                label: "Received",
                value: stats.formattedBytesReceived
            )
        }
    }
}

struct StatItem: View {
    let icon: String
    let label: String
    let value: String

    var body: some View {
        VStack(spacing: 4) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.subheadline.monospacedDigit())
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(VPNManager())
}
