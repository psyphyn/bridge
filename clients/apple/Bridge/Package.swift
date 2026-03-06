// swift-tools-version: 5.9
// Bridge VPN - Apple client package

import PackageDescription

let package = Package(
    name: "Bridge",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "Bridge", targets: ["Bridge"]),
        .library(name: "BridgeNetworkExtension", targets: ["BridgeNetworkExtension"]),
    ],
    targets: [
        // C module wrapping the Rust FFI static library
        .systemLibrary(
            name: "BridgeCore",
            path: "Sources/BridgeCore"
        ),
        // Swift wrapper around the FFI
        .target(
            name: "Bridge",
            dependencies: ["BridgeCore"],
            path: "Sources/Bridge"
        ),
        // Network Extension provider
        .target(
            name: "BridgeNetworkExtension",
            dependencies: ["BridgeCore"],
            path: "Sources/BridgeNetworkExtension"
        ),
    ]
)
