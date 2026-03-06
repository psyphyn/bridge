//! FFI bindings for platform-native clients.
//!
//! Exposes bridge-core functionality via C-compatible functions for:
//! - Swift/Objective-C (Apple platforms)
//! - JNI (Android/Kotlin)
//! - C#/P/Invoke (Windows)
//!
//! All functions use C-compatible types and conventions:
//! - Strings are passed as `*const c_char` (null-terminated UTF-8)
//! - Callbacks use `extern "C"` function pointers
//! - Memory ownership is explicit: caller frees what caller allocates

use std::ffi::{c_char, c_void, CStr, CString};
use std::net::IpAddr;
use std::sync::OnceLock;

use bridge_core::routing::{AppIdentity, AppRouter, DefaultRoute, RouterConfig, RoutingDecision, TunnelGroup};
use bridge_core::tunnel::{TunnelConfig, TunnelManager, TunnelState};
use tokio::runtime::Runtime;
use tokio::sync::RwLock;
use uuid::Uuid;

// ── Global runtime and tunnel manager ────────────────────────────────

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static TUNNEL_MANAGER: OnceLock<TunnelManager> = OnceLock::new();
static ROUTER: OnceLock<RwLock<AppRouter>> = OnceLock::new();

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create tokio runtime")
    })
}

fn tunnel_manager() -> &'static TunnelManager {
    TUNNEL_MANAGER.get_or_init(TunnelManager::new)
}

// ── Version ──────────────────────────────────────────────────────────

/// Returns the Bridge core version as a C string.
///
/// # Safety
/// The returned pointer is valid for the lifetime of the program.
/// Do NOT free this pointer.
#[no_mangle]
pub extern "C" fn bridge_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

// ── Keypair generation ───────────────────────────────────────────────

/// Result of keypair generation. Caller must free both strings with `bridge_free_string`.
#[repr(C)]
pub struct BridgeKeypair {
    pub private_key: *mut c_char,
    pub public_key: *mut c_char,
}

/// Generate a new WireGuard keypair. Returns base64-encoded keys.
///
/// # Safety
/// Caller must free both `private_key` and `public_key` with `bridge_free_string`.
#[no_mangle]
pub extern "C" fn bridge_generate_keypair() -> BridgeKeypair {
    let (private_key, public_key) = bridge_core::tunnel::generate_keypair();
    BridgeKeypair {
        private_key: CString::new(private_key).unwrap().into_raw(),
        public_key: CString::new(public_key).unwrap().into_raw(),
    }
}

// ── Tunnel configuration ─────────────────────────────────────────────

/// C-compatible tunnel configuration.
#[repr(C)]
pub struct BridgeTunnelConfig {
    /// UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000")
    pub tunnel_id: *const c_char,
    /// Base64-encoded WireGuard private key
    pub private_key: *const c_char,
    /// Base64-encoded peer public key
    pub peer_public_key: *const c_char,
    /// Peer endpoint as "host:port"
    pub peer_endpoint: *const c_char,
    /// Comma-separated CIDR ranges (e.g., "0.0.0.0/0,10.0.0.0/8")
    pub allowed_ips: *const c_char,
    /// Comma-separated DNS servers (e.g., "1.1.1.1,8.8.8.8")
    pub dns: *const c_char,
    /// Keepalive interval in seconds. 0 means disabled.
    pub keepalive_secs: u16,
}

/// Result code for FFI operations.
#[repr(C)]
pub enum BridgeResult {
    Ok = 0,
    InvalidArgument = 1,
    TunnelNotFound = 2,
    TunnelNotConnected = 3,
    ConnectionFailed = 4,
    InternalError = 5,
}

/// Tunnel state visible to FFI callers.
#[repr(C)]
pub enum BridgeTunnelState {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Reconnecting = 3,
    Disconnecting = 4,
    Unknown = 5,
}

impl From<TunnelState> for BridgeTunnelState {
    fn from(state: TunnelState) -> Self {
        match state {
            TunnelState::Disconnected => BridgeTunnelState::Disconnected,
            TunnelState::Connecting => BridgeTunnelState::Connecting,
            TunnelState::Connected => BridgeTunnelState::Connected,
            TunnelState::Reconnecting => BridgeTunnelState::Reconnecting,
            TunnelState::Disconnecting => BridgeTunnelState::Disconnecting,
        }
    }
}

/// Tunnel statistics.
#[repr(C)]
pub struct BridgeTunnelStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub last_handshake_secs_ago: u64,
}

// ── Tunnel lifecycle ─────────────────────────────────────────────────

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_string())
}

fn parse_comma_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Add a tunnel configuration. Does not connect.
///
/// # Safety
/// All string pointers in `config` must be valid null-terminated UTF-8.
#[no_mangle]
pub unsafe extern "C" fn bridge_add_tunnel(config: *const BridgeTunnelConfig) -> BridgeResult {
    let config = match config.as_ref() {
        Some(c) => c,
        None => return BridgeResult::InvalidArgument,
    };

    let tunnel_id = match cstr_to_string(config.tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return BridgeResult::InvalidArgument,
    };

    let private_key = match cstr_to_string(config.private_key) {
        Some(k) => k,
        None => return BridgeResult::InvalidArgument,
    };

    let peer_public_key = match cstr_to_string(config.peer_public_key) {
        Some(k) => k,
        None => return BridgeResult::InvalidArgument,
    };

    let peer_endpoint = match cstr_to_string(config.peer_endpoint)
        .and_then(|s| s.parse().ok())
    {
        Some(ep) => ep,
        None => return BridgeResult::InvalidArgument,
    };

    let allowed_ips = cstr_to_string(config.allowed_ips)
        .map(|s| parse_comma_list(&s))
        .unwrap_or_default();

    let dns = cstr_to_string(config.dns)
        .map(|s| parse_comma_list(&s))
        .unwrap_or_default();

    let keepalive = if config.keepalive_secs > 0 {
        Some(config.keepalive_secs)
    } else {
        None
    };

    let tc = TunnelConfig {
        id: tunnel_id,
        private_key,
        peer_public_key,
        peer_endpoint,
        allowed_ips,
        dns,
        keepalive_secs: keepalive,
    };

    runtime().block_on(tunnel_manager().add_tunnel(tc));
    BridgeResult::Ok
}

/// Connect a registered tunnel.
#[no_mangle]
pub unsafe extern "C" fn bridge_connect_tunnel(tunnel_id: *const c_char) -> BridgeResult {
    let id = match cstr_to_string(tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return BridgeResult::InvalidArgument,
    };

    match runtime().block_on(tunnel_manager().connect(id)) {
        Ok(()) => BridgeResult::Ok,
        Err(bridge_core::tunnel::TunnelError::NotFound(_)) => BridgeResult::TunnelNotFound,
        Err(_) => BridgeResult::ConnectionFailed,
    }
}

/// Disconnect a tunnel.
#[no_mangle]
pub unsafe extern "C" fn bridge_disconnect_tunnel(tunnel_id: *const c_char) -> BridgeResult {
    let id = match cstr_to_string(tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return BridgeResult::InvalidArgument,
    };

    match runtime().block_on(tunnel_manager().disconnect(id)) {
        Ok(()) => BridgeResult::Ok,
        Err(bridge_core::tunnel::TunnelError::NotFound(_)) => BridgeResult::TunnelNotFound,
        Err(_) => BridgeResult::InternalError,
    }
}

/// Remove a tunnel entirely.
#[no_mangle]
pub unsafe extern "C" fn bridge_remove_tunnel(tunnel_id: *const c_char) -> BridgeResult {
    let id = match cstr_to_string(tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return BridgeResult::InvalidArgument,
    };

    match runtime().block_on(tunnel_manager().remove_tunnel(id)) {
        Ok(()) => BridgeResult::Ok,
        Err(_) => BridgeResult::InternalError,
    }
}

/// Get the state of a tunnel.
#[no_mangle]
pub unsafe extern "C" fn bridge_tunnel_state(tunnel_id: *const c_char) -> BridgeTunnelState {
    let id = match cstr_to_string(tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return BridgeTunnelState::Unknown,
    };

    match runtime().block_on(tunnel_manager().tunnel_state(id)) {
        Some(state) => state.into(),
        None => BridgeTunnelState::Unknown,
    }
}

/// Get tunnel statistics. Returns false if tunnel not found.
#[no_mangle]
pub unsafe extern "C" fn bridge_tunnel_stats(
    tunnel_id: *const c_char,
    out_stats: *mut BridgeTunnelStats,
) -> bool {
    let id = match cstr_to_string(tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return false,
    };

    let out = match out_stats.as_mut() {
        Some(o) => o,
        None => return false,
    };

    match runtime().block_on(tunnel_manager().tunnel_stats(id)) {
        Some(stats) => {
            out.bytes_sent = stats.tx_bytes;
            out.bytes_received = stats.rx_bytes;
            out.packets_sent = stats.tx_packets;
            out.packets_received = stats.rx_packets;
            out.last_handshake_secs_ago = stats.last_handshake_secs.unwrap_or(0);
            true
        }
        None => false,
    }
}

/// Get the number of registered tunnels.
#[no_mangle]
pub extern "C" fn bridge_tunnel_count() -> u32 {
    runtime().block_on(tunnel_manager().tunnel_count()) as u32
}

// ── Packet I/O (for Network Extension) ───────────────────────────────

/// Send an IP packet into a specific tunnel.
///
/// # Safety
/// `packet_data` must point to `packet_len` valid bytes.
#[no_mangle]
pub unsafe extern "C" fn bridge_send_packet(
    tunnel_id: *const c_char,
    packet_data: *const u8,
    packet_len: usize,
) -> BridgeResult {
    let id = match cstr_to_string(tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return BridgeResult::InvalidArgument,
    };

    if packet_data.is_null() || packet_len == 0 {
        return BridgeResult::InvalidArgument;
    }

    let packet = std::slice::from_raw_parts(packet_data, packet_len);

    match runtime().block_on(tunnel_manager().send_packet(id, packet)) {
        Ok(()) => BridgeResult::Ok,
        Err(bridge_core::tunnel::TunnelError::NotFound(_)) => BridgeResult::TunnelNotFound,
        Err(bridge_core::tunnel::TunnelError::NotConnected(_)) => BridgeResult::TunnelNotConnected,
        Err(_) => BridgeResult::InternalError,
    }
}

/// Callback type for receiving decrypted packets from a tunnel.
pub type BridgePacketCallback =
    unsafe extern "C" fn(context: *mut c_void, packet_data: *const u8, packet_len: usize);

// ── Device identity ──────────────────────────────────────────────────

/// Generate an Ed25519 identity keypair. Returns base64-encoded keys.
///
/// # Safety
/// Caller must free both strings with `bridge_free_string`.
#[repr(C)]
pub struct BridgeIdentityKeypair {
    pub private_key: *mut c_char,
    pub public_key: *mut c_char,
    pub device_id: *mut c_char,
}

#[no_mangle]
pub extern "C" fn bridge_generate_identity() -> BridgeIdentityKeypair {
    use base64::Engine;

    match bridge_core::identity::generate_identity_keypair() {
        Ok((private_key, public_key)) => {
            let device_id = bridge_core::identity::device_id_from_public_key(&public_key);
            let priv_b64 = base64::engine::general_purpose::STANDARD.encode(&private_key);
            let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key);

            BridgeIdentityKeypair {
                private_key: CString::new(priv_b64).unwrap().into_raw(),
                public_key: CString::new(pub_b64).unwrap().into_raw(),
                device_id: CString::new(device_id.to_string()).unwrap().into_raw(),
            }
        }
        Err(_) => BridgeIdentityKeypair {
            private_key: std::ptr::null_mut(),
            public_key: std::ptr::null_mut(),
            device_id: std::ptr::null_mut(),
        },
    }
}

// ── Keystore-backed attestation ──────────────────────────────────────

use std::sync::Mutex;
use bridge_core::identity::{SoftwareKeyStore, KeyStore, KeyStoreAttestation, KeyStoreBackend};

static KEYSTORE: OnceLock<Mutex<Option<Box<dyn KeyStore>>>> = OnceLock::new();
static ATTESTATION: OnceLock<Mutex<Option<KeyStoreAttestation>>> = OnceLock::new();

fn keystore_mutex() -> &'static Mutex<Option<Box<dyn KeyStore>>> {
    KEYSTORE.get_or_init(|| Mutex::new(None))
}

fn attestation_mutex() -> &'static Mutex<Option<KeyStoreAttestation>> {
    ATTESTATION.get_or_init(|| Mutex::new(None))
}

/// Attestation info returned to the caller.
#[repr(C)]
pub struct BridgeAttestationInfo {
    /// "secure_enclave", "software", etc.
    pub backend: *mut c_char,
    /// Whether the key is hardware-backed (non-extractable).
    pub hardware_backed: bool,
    /// Device UUID string.
    pub device_id: *mut c_char,
    /// Base64-encoded public key.
    pub public_key: *mut c_char,
}

/// Initialize the keystore with a software backend and generate a device identity.
/// Returns attestation info. Caller must free strings with `bridge_free_string`.
///
/// Use this as the default. On macOS with Secure Enclave, call
/// `bridge_init_keystore_se` instead (from Swift, after wiring SE callbacks).
#[no_mangle]
pub extern "C" fn bridge_init_keystore_software(
    label: *const c_char,
) -> BridgeAttestationInfo {
    use base64::Engine;

    let label = unsafe {
        match cstr_to_string(label) {
            Some(l) => l,
            None => return null_attestation_info(),
        }
    };

    let ks = Box::new(SoftwareKeyStore::new());
    let platform = std::env::consts::OS.to_string();

    let attestation = match KeyStoreAttestation::new(ks, &label, &platform) {
        Ok(a) => a,
        Err(_) => return null_attestation_info(),
    };

    let info = BridgeAttestationInfo {
        backend: CString::new(attestation.backend().to_string()).unwrap().into_raw(),
        hardware_backed: attestation.is_hardware_backed(),
        device_id: CString::new(attestation.device_id().to_string()).unwrap().into_raw(),
        public_key: CString::new(
            base64::engine::general_purpose::STANDARD.encode(attestation.public_key()),
        )
        .unwrap()
        .into_raw(),
    };

    *attestation_mutex().lock().unwrap() = Some(attestation);

    info
}

/// Create an attestation token using the current keystore identity.
/// Returns a compact token string (claims.signature). Caller must free with `bridge_free_string`.
///
/// `posture_score`: 0-100
/// `access_tier`: 0=Quarantined, 1=Restricted, 2=Standard, 3=FullAccess
/// `ttl_secs`: token validity in seconds
#[no_mangle]
pub extern "C" fn bridge_create_attestation_token(
    posture_score: u8,
    access_tier: u8,
    ttl_secs: i64,
) -> *mut c_char {
    use bridge_core::posture::AccessTier;

    let tier = match access_tier {
        0 => AccessTier::Quarantined,
        1 => AccessTier::Restricted,
        2 => AccessTier::Standard,
        3 => AccessTier::FullAccess,
        _ => AccessTier::Standard,
    };

    let guard = attestation_mutex().lock().unwrap();
    let attestation = match guard.as_ref() {
        Some(a) => a,
        None => return std::ptr::null_mut(),
    };

    match attestation.attest(posture_score, tier, ttl_secs) {
        Ok(token) => CString::new(token.to_compact()).unwrap().into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Query the current keystore backend info.
#[no_mangle]
pub extern "C" fn bridge_keystore_is_hardware_backed() -> bool {
    attestation_mutex()
        .lock()
        .unwrap()
        .as_ref()
        .map(|a| a.is_hardware_backed())
        .unwrap_or(false)
}

fn null_attestation_info() -> BridgeAttestationInfo {
    BridgeAttestationInfo {
        backend: std::ptr::null_mut(),
        hardware_backed: false,
        device_id: std::ptr::null_mut(),
        public_key: std::ptr::null_mut(),
    }
}

// ── Per-app routing ──────────────────────────────────────────────────

/// Routing decision returned to FFI callers.
#[repr(C)]
pub enum BridgeRoutingDecision {
    /// Route through the tunnel whose UUID is in `tunnel_id`.
    Tunnel = 0,
    /// Bypass VPN, route directly.
    Direct = 1,
    /// Drop the packet.
    Drop = 2,
}

/// Full routing result with tunnel ID (if Tunnel decision).
#[repr(C)]
pub struct BridgeRouteResult {
    pub decision: BridgeRoutingDecision,
    /// Tunnel UUID string (only valid when decision == Tunnel). Free with `bridge_free_string`.
    pub tunnel_id: *mut c_char,
}

/// Initialize the per-app router with a default config.
/// `default_tunnel_id`: UUID string for the default tunnel (nullable).
/// `mode`: 0 = TunnelAll, 1 = SplitTunnel.
///
/// # Safety
/// `default_tunnel_id` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn bridge_router_init(
    default_tunnel_id: *const c_char,
    mode: u8,
) -> BridgeResult {
    let default_tunnel = cstr_to_string(default_tunnel_id)
        .and_then(|s| s.parse::<Uuid>().ok());

    let default_route = if mode == 1 {
        DefaultRoute::SplitTunnel
    } else {
        DefaultRoute::TunnelAll
    };

    let config = RouterConfig {
        groups: vec![],
        default_tunnel,
        bypass_apps: vec![],
        bypass_domains: vec![],
        default_route,
    };

    let router = AppRouter::new(config);
    // Replace or init the global router
    match ROUTER.get() {
        Some(lock) => {
            *runtime().block_on(lock.write()) = router;
        }
        None => {
            let _ = ROUTER.set(RwLock::new(router));
        }
    }
    BridgeResult::Ok
}

/// Add a tunnel group to the router.
///
/// # Safety
/// All string pointers must be valid null-terminated UTF-8 or null.
#[no_mangle]
pub unsafe extern "C" fn bridge_router_add_group(
    name: *const c_char,
    tunnel_id: *const c_char,
    applications: *const c_char,
    domains: *const c_char,
    ip_ranges: *const c_char,
    priority: u32,
) -> BridgeResult {
    let name = match cstr_to_string(name) {
        Some(n) => n,
        None => return BridgeResult::InvalidArgument,
    };
    let tunnel_id = match cstr_to_string(tunnel_id).and_then(|s| s.parse::<Uuid>().ok()) {
        Some(id) => id,
        None => return BridgeResult::InvalidArgument,
    };
    let apps = cstr_to_string(applications)
        .map(|s| parse_comma_list(&s))
        .unwrap_or_default();
    let doms = cstr_to_string(domains)
        .map(|s| parse_comma_list(&s))
        .unwrap_or_default();
    let ips = cstr_to_string(ip_ranges)
        .map(|s| parse_comma_list(&s))
        .unwrap_or_default();

    let group = TunnelGroup {
        name,
        tunnel_id,
        applications: apps,
        domains: doms,
        ip_ranges: ips,
        priority,
    };

    let lock = match ROUTER.get() {
        Some(l) => l,
        None => return BridgeResult::InternalError,
    };

    // Re-create router with the new group added to config
    let mut router = runtime().block_on(lock.write());
    let mut config = router_config_snapshot(&router);
    config.groups.push(group);
    *router = AppRouter::new(config);

    BridgeResult::Ok
}

/// Set bypass apps (comma-separated bundle IDs).
///
/// # Safety
/// `apps` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn bridge_router_set_bypass_apps(apps: *const c_char) -> BridgeResult {
    let apps_list = cstr_to_string(apps)
        .map(|s| parse_comma_list(&s))
        .unwrap_or_default();

    let lock = match ROUTER.get() {
        Some(l) => l,
        None => return BridgeResult::InternalError,
    };

    let mut router = runtime().block_on(lock.write());
    let mut config = router_config_snapshot(&router);
    config.bypass_apps = apps_list;
    *router = AppRouter::new(config);

    BridgeResult::Ok
}

/// Set bypass domains (comma-separated, supports wildcards like "*.apple.com").
///
/// # Safety
/// `domains` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn bridge_router_set_bypass_domains(domains: *const c_char) -> BridgeResult {
    let domains_list = cstr_to_string(domains)
        .map(|s| parse_comma_list(&s))
        .unwrap_or_default();

    let lock = match ROUTER.get() {
        Some(l) => l,
        None => return BridgeResult::InternalError,
    };

    let mut router = runtime().block_on(lock.write());
    let mut config = router_config_snapshot(&router);
    config.bypass_domains = domains_list;
    *router = AppRouter::new(config);

    BridgeResult::Ok
}

/// Record a DNS resolution for domain-based routing.
///
/// # Safety
/// `domain` and `ip` must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn bridge_router_record_dns(
    domain: *const c_char,
    ip: *const c_char,
) -> BridgeResult {
    let domain = match cstr_to_string(domain) {
        Some(d) => d,
        None => return BridgeResult::InvalidArgument,
    };
    let ip: IpAddr = match cstr_to_string(ip).and_then(|s| s.parse().ok()) {
        Some(ip) => ip,
        None => return BridgeResult::InvalidArgument,
    };

    let lock = match ROUTER.get() {
        Some(l) => l,
        None => return BridgeResult::InternalError,
    };

    runtime().block_on(lock.write()).record_dns_resolution(&domain, ip);
    BridgeResult::Ok
}

/// Route a packet based on the source app and destination.
/// Returns a `BridgeRouteResult`. Caller must free `tunnel_id` with `bridge_free_string`.
///
/// # Safety
/// `bundle_id` must be a valid C string or null.
/// `dest_ip` must be a valid C string (e.g., "10.0.0.1").
/// `protocol` must be a valid C string (e.g., "tcp", "udp").
#[no_mangle]
pub unsafe extern "C" fn bridge_router_route(
    bundle_id: *const c_char,
    dest_ip: *const c_char,
    dest_port: u16,
    protocol: *const c_char,
) -> BridgeRouteResult {
    let no_route = BridgeRouteResult {
        decision: BridgeRoutingDecision::Direct,
        tunnel_id: std::ptr::null_mut(),
    };

    let app_id = cstr_to_string(bundle_id).unwrap_or_default();
    let dest: IpAddr = match cstr_to_string(dest_ip).and_then(|s| s.parse().ok()) {
        Some(ip) => ip,
        None => return no_route,
    };
    let proto = cstr_to_string(protocol).unwrap_or_else(|| "tcp".to_string());

    let lock = match ROUTER.get() {
        Some(l) => l,
        None => return no_route,
    };

    let app = if app_id.is_empty() {
        AppIdentity::from_process_name("unknown")
    } else {
        AppIdentity::from_bundle_id(&app_id)
    };

    let decision = runtime().block_on(lock.read()).route(&app, dest, dest_port, &proto);

    match decision {
        RoutingDecision::Tunnel(id) => BridgeRouteResult {
            decision: BridgeRoutingDecision::Tunnel,
            tunnel_id: CString::new(id.to_string()).unwrap().into_raw(),
        },
        RoutingDecision::Direct => BridgeRouteResult {
            decision: BridgeRoutingDecision::Direct,
            tunnel_id: std::ptr::null_mut(),
        },
        RoutingDecision::Drop { .. } => BridgeRouteResult {
            decision: BridgeRoutingDecision::Drop,
            tunnel_id: std::ptr::null_mut(),
        },
    }
}

/// Route a raw IP packet by parsing its headers.
/// Returns a `BridgeRouteResult`. Caller must free `tunnel_id` with `bridge_free_string`.
///
/// # Safety
/// `packet_data` must point to `packet_len` valid bytes.
/// `bundle_id` must be a valid C string or null.
#[no_mangle]
pub unsafe extern "C" fn bridge_router_route_packet(
    bundle_id: *const c_char,
    packet_data: *const u8,
    packet_len: usize,
) -> BridgeRouteResult {
    let no_route = BridgeRouteResult {
        decision: BridgeRoutingDecision::Direct,
        tunnel_id: std::ptr::null_mut(),
    };

    if packet_data.is_null() || packet_len == 0 {
        return no_route;
    }

    let packet = std::slice::from_raw_parts(packet_data, packet_len);

    let (_src, dst, dst_port, proto_num) =
        match bridge_core::routing::parse_packet_endpoints(packet) {
            Some(ep) => ep,
            None => return no_route,
        };

    let proto = match proto_num {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        _ => "other",
    };

    let app_id = cstr_to_string(bundle_id).unwrap_or_default();
    let app = if app_id.is_empty() {
        AppIdentity::from_process_name("unknown")
    } else {
        AppIdentity::from_bundle_id(&app_id)
    };

    let lock = match ROUTER.get() {
        Some(l) => l,
        None => return no_route,
    };

    let decision = runtime().block_on(lock.read()).route(&app, dst, dst_port, proto);

    match decision {
        RoutingDecision::Tunnel(id) => BridgeRouteResult {
            decision: BridgeRoutingDecision::Tunnel,
            tunnel_id: CString::new(id.to_string()).unwrap().into_raw(),
        },
        RoutingDecision::Direct => no_route,
        RoutingDecision::Drop { .. } => BridgeRouteResult {
            decision: BridgeRoutingDecision::Drop,
            tunnel_id: std::ptr::null_mut(),
        },
    }
}

/// Get the number of tunnel groups in the router.
#[no_mangle]
pub extern "C" fn bridge_router_group_count() -> u32 {
    match ROUTER.get() {
        Some(lock) => runtime().block_on(lock.read()).groups().len() as u32,
        None => 0,
    }
}

/// Helper: snapshot the current router config for mutation.
fn router_config_snapshot(router: &AppRouter) -> RouterConfig {
    router.config().clone()
}

// ── Memory management ────────────────────────────────────────────────

/// Free a string previously returned by a `bridge_*` function.
///
/// # Safety
/// `ptr` must have been allocated by a `bridge_*` function, or be null.
#[no_mangle]
pub unsafe extern "C" fn bridge_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// ── Logging ──────────────────────────────────────────────────────────

/// Log callback type.
pub type BridgeLogCallback =
    unsafe extern "C" fn(context: *mut c_void, level: u8, message: *const c_char);

/// Initialize logging. Pass a callback to receive log messages.
/// Levels: 0=error, 1=warn, 2=info, 3=debug, 4=trace
///
/// # Safety
/// `callback` and `context` must remain valid for the lifetime of the program.
#[no_mangle]
pub unsafe extern "C" fn bridge_init_logging(
    _callback: BridgeLogCallback,
    _context: *mut c_void,
) {
    // Initialize tracing subscriber that forwards to the callback.
    // For now, just initialize basic tracing.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}
