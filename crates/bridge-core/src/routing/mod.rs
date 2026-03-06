//! Per-app micro-tunnel routing.
//!
//! Maps applications to specific WireGuard tunnels, enabling isolated
//! network paths per application. A compromised app cannot pivot to
//! another app's tunnel.
//!
//! Routing decisions are made based on:
//! - Application identity (bundle ID, process name, PID)
//! - Destination domain/IP
//! - Policy rules
//! - Access tier

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::policy::{self, Action, PolicyContext, PolicySet};
use crate::posture::AccessTier;
use crate::tunnel::TunnelId;

/// Identifies an application making a network request.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppIdentity {
    /// macOS/iOS bundle identifier (e.g., "com.apple.Safari")
    pub bundle_id: Option<String>,
    /// Process name (e.g., "Safari")
    pub process_name: Option<String>,
    /// Process ID (transient, not persisted)
    #[serde(skip)]
    pub pid: Option<u32>,
}

impl AppIdentity {
    pub fn from_bundle_id(bundle_id: &str) -> Self {
        Self {
            bundle_id: Some(bundle_id.to_string()),
            process_name: None,
            pid: None,
        }
    }

    pub fn from_process_name(name: &str) -> Self {
        Self {
            bundle_id: None,
            process_name: Some(name.to_string()),
            pid: None,
        }
    }

    /// Best identifier string for matching.
    pub fn identifier(&self) -> &str {
        self.bundle_id
            .as_deref()
            .or(self.process_name.as_deref())
            .unwrap_or("unknown")
    }
}

/// A group of tunnels assigned to a set of applications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelGroup {
    /// Unique name for this group (e.g., "corporate", "personal", "engineering").
    pub name: String,
    /// The tunnel ID assigned to this group.
    pub tunnel_id: TunnelId,
    /// Applications assigned to this group (bundle IDs or process names).
    pub applications: Vec<String>,
    /// Domains routed through this group (optional domain-based routing).
    pub domains: Vec<String>,
    /// CIDR ranges routed through this group.
    pub ip_ranges: Vec<String>,
    /// Priority (lower = higher priority, for overlapping rules).
    pub priority: u32,
}

/// Routing decision: which tunnel should handle a packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Route through a specific tunnel.
    Tunnel(TunnelId),
    /// Route directly (bypass VPN / split tunnel).
    Direct,
    /// Drop the packet (blocked by policy).
    Drop { reason: String },
}

/// Configuration for the per-app router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Tunnel groups defining app-to-tunnel mappings.
    pub groups: Vec<TunnelGroup>,
    /// Default tunnel for traffic that doesn't match any group.
    pub default_tunnel: Option<TunnelId>,
    /// Apps that should always bypass the VPN.
    pub bypass_apps: Vec<String>,
    /// Domains that should always bypass the VPN.
    pub bypass_domains: Vec<String>,
    /// Whether to route unmatched traffic through VPN or direct.
    pub default_route: DefaultRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DefaultRoute {
    /// All traffic goes through VPN by default.
    TunnelAll,
    /// Only matched traffic goes through VPN (split tunnel).
    SplitTunnel,
}

/// The per-app packet router.
pub struct AppRouter {
    config: RouterConfig,
    /// Cached app → tunnel group lookup.
    app_cache: HashMap<String, usize>,
    /// DNS domain → IP mapping (from DNS proxy).
    domain_ip_cache: HashMap<IpAddr, String>,
    /// Policy set for additional filtering.
    policy: Option<PolicySet>,
    /// Current device access tier.
    access_tier: AccessTier,
}

impl AppRouter {
    pub fn new(config: RouterConfig) -> Self {
        let mut app_cache = HashMap::new();

        // Build app → group index cache
        for (i, group) in config.groups.iter().enumerate() {
            for app in &group.applications {
                app_cache.insert(app.clone(), i);
            }
        }

        Self {
            config,
            app_cache,
            domain_ip_cache: HashMap::new(),
            policy: None,
            access_tier: AccessTier::Standard,
        }
    }

    /// Set the policy to apply on top of routing.
    pub fn set_policy(&mut self, policy: PolicySet) {
        self.policy = Some(policy);
    }

    /// Update the device access tier.
    pub fn set_access_tier(&mut self, tier: AccessTier) {
        self.access_tier = tier;
    }

    /// Record a DNS resolution (domain → IP) for domain-based routing.
    pub fn record_dns_resolution(&mut self, domain: &str, ip: IpAddr) {
        self.domain_ip_cache.insert(ip, domain.to_string());
    }

    /// Clear stale DNS cache entries (call periodically).
    pub fn clear_dns_cache(&mut self) {
        self.domain_ip_cache.clear();
    }

    /// Route a packet based on source app and destination.
    pub fn route(
        &self,
        app: &AppIdentity,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: &str,
    ) -> RoutingDecision {
        let app_id = app.identifier();

        // Check bypass list first
        if self.config.bypass_apps.iter().any(|a| a == app_id) {
            return RoutingDecision::Direct;
        }

        // Look up domain from DNS cache
        let domain = self.domain_ip_cache.get(&dest_ip).cloned();

        // Check bypass domains
        if let Some(ref domain) = domain {
            if self.config.bypass_domains.iter().any(|d| domain_matches(domain, d)) {
                return RoutingDecision::Direct;
            }
        }

        // Check policy first (may block the traffic)
        if let Some(ref policy_set) = self.policy {
            let ctx = PolicyContext {
                access_tier: self.access_tier.clone(),
                application: Some(app_id.to_string()),
                domain: domain.clone(),
                dest_ip: Some(dest_ip.to_string()),
                dest_port: Some(dest_port),
                protocol: Some(protocol.to_string()),
                user_groups: Vec::new(),
                platform: Some(std::env::consts::OS.to_string()),
            };

            let decision = policy::evaluate(policy_set, &ctx);
            if let Action::Block { reason } = decision.action {
                return RoutingDecision::Drop { reason };
            }
        }

        // Match by application → tunnel group
        if let Some(&group_idx) = self.app_cache.get(app_id) {
            return RoutingDecision::Tunnel(self.config.groups[group_idx].tunnel_id);
        }

        // Match by domain → tunnel group
        if let Some(ref domain) = domain {
            for group in &self.config.groups {
                if group.domains.iter().any(|d| domain_matches(domain, d)) {
                    return RoutingDecision::Tunnel(group.tunnel_id);
                }
            }
        }

        // Match by IP range → tunnel group
        let dest_str = dest_ip.to_string();
        for group in &self.config.groups {
            if group.ip_ranges.iter().any(|r| ip_in_cidr(&dest_str, r)) {
                return RoutingDecision::Tunnel(group.tunnel_id);
            }
        }

        // Default routing
        match self.config.default_route {
            DefaultRoute::TunnelAll => {
                if let Some(default_id) = self.config.default_tunnel {
                    RoutingDecision::Tunnel(default_id)
                } else {
                    RoutingDecision::Direct
                }
            }
            DefaultRoute::SplitTunnel => RoutingDecision::Direct,
        }
    }

    /// Get the tunnel group for an app (if any).
    pub fn app_tunnel_group(&self, app_id: &str) -> Option<&TunnelGroup> {
        self.app_cache
            .get(app_id)
            .map(|&idx| &self.config.groups[idx])
    }

    /// List all tunnel groups.
    pub fn groups(&self) -> &[TunnelGroup] {
        &self.config.groups
    }

    /// Get the current router configuration.
    pub fn config(&self) -> &RouterConfig {
        &self.config
    }
}

/// Domain matching with wildcard support.
fn domain_matches(domain: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..];
        domain.ends_with(suffix) || domain == &pattern[2..]
    } else {
        domain == pattern
    }
}

/// Simple CIDR matching (v4 only for now).
fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }
    let network: IpAddr = match parts[0].parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };
    let prefix_len: u32 = match parts[1].parse() {
        Ok(p) => p,
        Err(_) => return false,
    };
    let target: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => return false,
    };

    match (target, network) {
        (IpAddr::V4(t), IpAddr::V4(n)) => {
            if prefix_len == 0 {
                return true;
            }
            if prefix_len > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix_len);
            (u32::from(t) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(t), IpAddr::V6(n)) => {
            if prefix_len == 0 {
                return true;
            }
            if prefix_len > 128 {
                return false;
            }
            let t_bits = u128::from(t);
            let n_bits = u128::from(n);
            let mask = u128::MAX << (128 - prefix_len);
            (t_bits & mask) == (n_bits & mask)
        }
        _ => false, // Mismatched IP versions
    }
}

/// Extract source app identity from a raw IP packet (platform-specific).
///
/// On macOS, NEPacketTunnelProvider gives us the process info.
/// This function parses the IP header to get src/dst for correlation.
pub fn parse_packet_endpoints(packet: &[u8]) -> Option<(IpAddr, IpAddr, u16, u8)> {
    if packet.len() < 20 {
        return None;
    }

    let version = packet[0] >> 4;
    match version {
        4 => {
            let ihl = ((packet[0] & 0x0f) as usize) * 4;
            if packet.len() < ihl + 4 {
                return None;
            }
            let protocol = packet[9];
            let src = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            ));
            let dst = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));
            let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
            Some((src, dst, dst_port, protocol))
        }
        6 => {
            if packet.len() < 40 + 4 {
                return None;
            }
            let protocol = packet[6]; // Next header
            let src = IpAddr::V6(std::net::Ipv6Addr::from({
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&packet[8..24]);
                buf
            }));
            let dst = IpAddr::V6(std::net::Ipv6Addr::from({
                let mut buf = [0u8; 16];
                buf.copy_from_slice(&packet[24..40]);
                buf
            }));
            let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
            Some((src, dst, dst_port, protocol))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RouterConfig {
        let corporate_tunnel = Uuid::new_v4();
        let engineering_tunnel = Uuid::new_v4();
        let default_tunnel = Uuid::new_v4();

        RouterConfig {
            groups: vec![
                TunnelGroup {
                    name: "corporate".to_string(),
                    tunnel_id: corporate_tunnel,
                    applications: vec![
                        "com.apple.Safari".to_string(),
                        "com.google.Chrome".to_string(),
                    ],
                    domains: vec!["*.corp.example.com".to_string()],
                    ip_ranges: vec!["10.0.0.0/8".to_string()],
                    priority: 1,
                },
                TunnelGroup {
                    name: "engineering".to_string(),
                    tunnel_id: engineering_tunnel,
                    applications: vec![
                        "com.apple.Terminal".to_string(),
                        "com.microsoft.VSCode".to_string(),
                    ],
                    domains: vec!["*.github.com".to_string()],
                    ip_ranges: vec![],
                    priority: 2,
                },
            ],
            default_tunnel: Some(default_tunnel),
            bypass_apps: vec!["com.apple.Music".to_string()],
            bypass_domains: vec!["*.apple.com".to_string()],
            default_route: DefaultRoute::TunnelAll,
        }
    }

    #[test]
    fn route_by_app() {
        let config = test_config();
        let corporate_id = config.groups[0].tunnel_id;
        let router = AppRouter::new(config);

        let app = AppIdentity::from_bundle_id("com.apple.Safari");
        let decision = router.route(
            &app,
            "1.2.3.4".parse().unwrap(),
            443,
            "tcp",
        );

        assert_eq!(decision, RoutingDecision::Tunnel(corporate_id));
    }

    #[test]
    fn route_by_domain() {
        let config = test_config();
        let corporate_id = config.groups[0].tunnel_id;
        let mut router = AppRouter::new(config);

        // Record DNS resolution
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        router.record_dns_resolution("internal.corp.example.com", ip);

        let app = AppIdentity::from_bundle_id("com.unknown.app");
        let decision = router.route(&app, ip, 443, "tcp");

        assert_eq!(decision, RoutingDecision::Tunnel(corporate_id));
    }

    #[test]
    fn route_by_ip_range() {
        let config = test_config();
        let corporate_id = config.groups[0].tunnel_id;
        let router = AppRouter::new(config);

        let app = AppIdentity::from_bundle_id("com.unknown.app");
        let decision = router.route(
            &app,
            "10.5.3.1".parse().unwrap(),
            8080,
            "tcp",
        );

        assert_eq!(decision, RoutingDecision::Tunnel(corporate_id));
    }

    #[test]
    fn bypass_app() {
        let config = test_config();
        let router = AppRouter::new(config);

        let app = AppIdentity::from_bundle_id("com.apple.Music");
        let decision = router.route(
            &app,
            "1.2.3.4".parse().unwrap(),
            443,
            "tcp",
        );

        assert_eq!(decision, RoutingDecision::Direct);
    }

    #[test]
    fn bypass_domain() {
        let config = test_config();
        let mut router = AppRouter::new(config);

        let ip: IpAddr = "17.253.144.10".parse().unwrap();
        router.record_dns_resolution("updates.apple.com", ip);

        let app = AppIdentity::from_bundle_id("com.unknown.app");
        let decision = router.route(&app, ip, 443, "tcp");

        assert_eq!(decision, RoutingDecision::Direct);
    }

    #[test]
    fn default_tunnel_all() {
        let config = test_config();
        let default_id = config.default_tunnel.unwrap();
        let router = AppRouter::new(config);

        let app = AppIdentity::from_bundle_id("com.unknown.app");
        let decision = router.route(
            &app,
            "8.8.8.8".parse().unwrap(),
            53,
            "udp",
        );

        assert_eq!(decision, RoutingDecision::Tunnel(default_id));
    }

    #[test]
    fn split_tunnel_mode() {
        let mut config = test_config();
        config.default_route = DefaultRoute::SplitTunnel;
        let router = AppRouter::new(config);

        let app = AppIdentity::from_bundle_id("com.unknown.app");
        let decision = router.route(
            &app,
            "8.8.8.8".parse().unwrap(),
            53,
            "udp",
        );

        assert_eq!(decision, RoutingDecision::Direct);
    }

    #[test]
    fn policy_blocks_traffic() {
        let config = test_config();
        let mut router = AppRouter::new(config);

        // Add a policy that blocks malware domains
        let policy = PolicySet {
            name: "test".to_string(),
            default_action: Action::Allow,
            rules: vec![policy::PolicyRule {
                name: "block-malware".to_string(),
                conditions: vec![policy::Condition::DomainMatches(vec![
                    "malware.com".to_string(),
                ])],
                action: Action::Block {
                    reason: "Malware".to_string(),
                },
            }],
        };
        router.set_policy(policy);

        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        router.record_dns_resolution("malware.com", ip);

        let app = AppIdentity::from_bundle_id("com.apple.Safari");
        let decision = router.route(&app, ip, 80, "tcp");

        assert_eq!(
            decision,
            RoutingDecision::Drop {
                reason: "Malware".to_string()
            }
        );
    }

    #[test]
    fn cidr_matching_v4() {
        assert!(ip_in_cidr("10.0.1.5", "10.0.0.0/8"));
        assert!(ip_in_cidr("10.255.255.255", "10.0.0.0/8"));
        assert!(!ip_in_cidr("11.0.0.1", "10.0.0.0/8"));

        assert!(ip_in_cidr("192.168.1.100", "192.168.1.0/24"));
        assert!(!ip_in_cidr("192.168.2.1", "192.168.1.0/24"));

        assert!(ip_in_cidr("1.2.3.4", "0.0.0.0/0")); // Match all
    }

    #[test]
    fn cidr_matching_v6() {
        assert!(ip_in_cidr("fd00::1", "fd00::/8"));
        assert!(ip_in_cidr("fd00:1234::5678", "fd00::/8"));
        assert!(!ip_in_cidr("fe80::1", "fd00::/8"));
    }

    #[test]
    fn parse_ipv4_packet() {
        // Build a minimal IPv4/TCP packet
        let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP
        pkt[0] = 0x45; // v4, IHL=5
        pkt[2] = 0; pkt[3] = 40; // total len
        pkt[9] = 6; // TCP
        pkt[12] = 10; pkt[13] = 0; pkt[14] = 0; pkt[15] = 1; // src
        pkt[16] = 172; pkt[17] = 16; pkt[18] = 0; pkt[19] = 1; // dst
        pkt[22] = 0x01; pkt[23] = 0xBB; // dst port 443

        let (src, dst, port, proto) = parse_packet_endpoints(&pkt).unwrap();
        assert_eq!(src, IpAddr::V4("10.0.0.1".parse().unwrap()));
        assert_eq!(dst, IpAddr::V4("172.16.0.1".parse().unwrap()));
        assert_eq!(port, 443);
        assert_eq!(proto, 6); // TCP
    }
}
