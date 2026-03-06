// bridge_ffi.h - C header for Bridge FFI bindings
// Auto-maintained to match crates/bridge-ffi/src/lib.rs

#ifndef BRIDGE_FFI_H
#define BRIDGE_FFI_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ── Version ──────────────────────────────────────────────────────────

const char* bridge_version(void);

// ── Keypair generation ───────────────────────────────────────────────

typedef struct {
    char* private_key;
    char* public_key;
} BridgeKeypair;

BridgeKeypair bridge_generate_keypair(void);

// ── Identity ─────────────────────────────────────────────────────────

typedef struct {
    char* private_key;
    char* public_key;
    char* device_id;
} BridgeIdentityKeypair;

BridgeIdentityKeypair bridge_generate_identity(void);

// ── Tunnel configuration ─────────────────────────────────────────────

typedef struct {
    const char* tunnel_id;
    const char* private_key;
    const char* peer_public_key;
    const char* peer_endpoint;
    const char* allowed_ips;     // Comma-separated CIDRs
    const char* dns;             // Comma-separated DNS servers
    uint16_t keepalive_secs;     // 0 = disabled
} BridgeTunnelConfig;

typedef enum {
    BridgeResultOk = 0,
    BridgeResultInvalidArgument = 1,
    BridgeResultTunnelNotFound = 2,
    BridgeResultTunnelNotConnected = 3,
    BridgeResultConnectionFailed = 4,
    BridgeResultInternalError = 5,
} BridgeResult;

typedef enum {
    BridgeTunnelStateDisconnected = 0,
    BridgeTunnelStateConnecting = 1,
    BridgeTunnelStateConnected = 2,
    BridgeTunnelStateReconnecting = 3,
    BridgeTunnelStateDisconnecting = 4,
    BridgeTunnelStateUnknown = 5,
} BridgeTunnelState;

typedef struct {
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t last_handshake_secs_ago;
} BridgeTunnelStats;

// ── Tunnel lifecycle ─────────────────────────────────────────────────

BridgeResult bridge_add_tunnel(const BridgeTunnelConfig* config);
BridgeResult bridge_connect_tunnel(const char* tunnel_id);
BridgeResult bridge_disconnect_tunnel(const char* tunnel_id);
BridgeResult bridge_remove_tunnel(const char* tunnel_id);
BridgeTunnelState bridge_tunnel_state(const char* tunnel_id);
bool bridge_tunnel_stats(const char* tunnel_id, BridgeTunnelStats* out_stats);
uint32_t bridge_tunnel_count(void);

// ── Packet I/O ───────────────────────────────────────────────────────

BridgeResult bridge_send_packet(
    const char* tunnel_id,
    const uint8_t* packet_data,
    size_t packet_len
);

typedef void (*BridgePacketCallback)(void* context, const uint8_t* packet_data, size_t packet_len);

// ── Logging ──────────────────────────────────────────────────────────

typedef void (*BridgeLogCallback)(void* context, uint8_t level, const char* message);
void bridge_init_logging(BridgeLogCallback callback, void* context);

// ── Memory management ────────────────────────────────────────────────

void bridge_free_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // BRIDGE_FFI_H
