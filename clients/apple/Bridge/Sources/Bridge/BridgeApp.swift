// BridgeApp.swift - Main SwiftUI application entry point

import SwiftUI

@main
struct BridgeApp: App {
    @StateObject private var vpnManager = VPNManager()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(vpnManager)
        }
        #if os(macOS)
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 360, height: 520)
        #endif
    }
}
