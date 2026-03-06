//! DNS threat intelligence and categorized blocklists.
//!
//! Provides categorized domain blocking with different actions:
//! - Malware C2 domains → block + alert
//! - Phishing domains → block + alert
//! - Ad/tracking networks → block (optional)
//! - DNS tunneling detection → block + alert
//!
//! Categories allow per-policy control (e.g., allow ads for marketing team).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

/// Threat category for a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThreatCategory {
    /// Known malware command & control servers.
    MalwareC2,
    /// Phishing / credential harvesting domains.
    Phishing,
    /// Advertising and tracking networks.
    AdTracking,
    /// Cryptojacking / cryptomining pools.
    Cryptomining,
    /// Newly registered domains (high risk).
    NewlyRegistered,
    /// DNS tunneling / data exfiltration.
    DnsTunneling,
    /// Parked / suspicious domains.
    Suspicious,
    /// Custom admin-defined category.
    Custom,
}

/// Action to take when a threat is detected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatAction {
    /// Block the DNS query (NXDOMAIN).
    Block,
    /// Block and generate a security alert.
    BlockAndAlert,
    /// Allow but log for monitoring.
    Monitor,
    /// Redirect to a warning page.
    Redirect { target_ip: String },
}

/// A threat intelligence entry for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatEntry {
    pub domain: String,
    pub category: ThreatCategory,
    pub action: ThreatAction,
    pub source: String,
}

/// Threat intelligence database for DNS filtering.
pub struct ThreatIntel {
    /// Domain → threat entries (exact match).
    exact: HashMap<String, ThreatEntry>,
    /// Suffix patterns for wildcard matching.
    suffixes: Vec<ThreatEntry>,
    /// Categories that are enabled for blocking.
    enabled_categories: HashSet<ThreatCategory>,
    /// DNS tunneling detection state.
    tunneling_detector: TunnelingDetector,
}

impl ThreatIntel {
    pub fn new() -> Self {
        let mut enabled = HashSet::new();
        // Enable security-critical categories by default
        enabled.insert(ThreatCategory::MalwareC2);
        enabled.insert(ThreatCategory::Phishing);
        enabled.insert(ThreatCategory::DnsTunneling);

        Self {
            exact: HashMap::new(),
            suffixes: Vec::new(),
            enabled_categories: enabled,
            tunneling_detector: TunnelingDetector::new(),
        }
    }

    /// Create with all categories enabled (strict mode).
    pub fn strict() -> Self {
        let mut intel = Self::new();
        intel.enabled_categories.insert(ThreatCategory::AdTracking);
        intel.enabled_categories.insert(ThreatCategory::Cryptomining);
        intel.enabled_categories.insert(ThreatCategory::NewlyRegistered);
        intel.enabled_categories.insert(ThreatCategory::Suspicious);
        intel.enabled_categories.insert(ThreatCategory::Custom);
        intel
    }

    /// Enable a threat category.
    pub fn enable_category(&mut self, category: ThreatCategory) {
        self.enabled_categories.insert(category);
    }

    /// Disable a threat category.
    pub fn disable_category(&mut self, category: ThreatCategory) {
        self.enabled_categories.remove(&category);
    }

    /// Add a domain to the threat database.
    pub fn add_domain(&mut self, domain: &str, category: ThreatCategory, source: &str) {
        let action = default_action_for_category(category);
        let entry = ThreatEntry {
            domain: domain.to_string(),
            category,
            action,
            source: source.to_string(),
        };

        if domain.starts_with("*.") {
            self.suffixes.push(entry);
        } else {
            self.exact.insert(domain.to_string(), entry);
        }
    }

    /// Load domains in bulk for a category.
    pub fn load_domains(&mut self, domains: &[&str], category: ThreatCategory, source: &str) {
        for domain in domains {
            self.add_domain(domain, category, source);
        }
    }

    /// Check if a domain is a threat. Returns the threat entry if found and the
    /// category is enabled.
    pub fn check_domain(&mut self, domain: &str) -> Option<&ThreatEntry> {
        // Check DNS tunneling first
        if self.enabled_categories.contains(&ThreatCategory::DnsTunneling)
            && self.tunneling_detector.is_suspicious(domain)
        {
            // Add a dynamic entry for the tunneling domain
            let entry = ThreatEntry {
                domain: domain.to_string(),
                category: ThreatCategory::DnsTunneling,
                action: ThreatAction::BlockAndAlert,
                source: "dns-tunneling-detector".to_string(),
            };
            self.exact.insert(domain.to_string(), entry);
        }

        // Check exact match
        if let Some(entry) = self.exact.get(domain) {
            if self.enabled_categories.contains(&entry.category) {
                return Some(entry);
            }
        }

        // Check suffix match
        for entry in &self.suffixes {
            let suffix = &entry.domain[1..]; // Remove leading '*'
            if domain.ends_with(suffix) || domain == &entry.domain[2..] {
                if self.enabled_categories.contains(&entry.category) {
                    return Some(entry);
                }
            }
        }

        None
    }

    /// Number of entries in the threat database.
    pub fn entry_count(&self) -> usize {
        self.exact.len() + self.suffixes.len()
    }
}

impl Default for ThreatIntel {
    fn default() -> Self {
        Self::new()
    }
}

/// Default action based on threat category.
fn default_action_for_category(category: ThreatCategory) -> ThreatAction {
    match category {
        ThreatCategory::MalwareC2 => ThreatAction::BlockAndAlert,
        ThreatCategory::Phishing => ThreatAction::BlockAndAlert,
        ThreatCategory::DnsTunneling => ThreatAction::BlockAndAlert,
        ThreatCategory::Cryptomining => ThreatAction::Block,
        ThreatCategory::AdTracking => ThreatAction::Block,
        ThreatCategory::NewlyRegistered => ThreatAction::Monitor,
        ThreatCategory::Suspicious => ThreatAction::Monitor,
        ThreatCategory::Custom => ThreatAction::Block,
    }
}

/// DNS tunneling detection heuristics.
///
/// Detects potential DNS tunneling by looking for:
/// - Unusually long domain names (encoded data in labels)
/// - High entropy in subdomain labels (random-looking characters)
/// - Excessive query frequency to the same base domain
struct TunnelingDetector {
    /// Recent queries per base domain for frequency detection.
    query_counts: HashMap<String, u32>,
}

impl TunnelingDetector {
    fn new() -> Self {
        Self {
            query_counts: HashMap::new(),
        }
    }

    /// Check if a domain query looks like DNS tunneling.
    fn is_suspicious(&mut self, domain: &str) -> bool {
        // Heuristic 1: Very long domain names (data encoded in labels)
        if domain.len() > 100 {
            return true;
        }

        // Heuristic 2: High entropy in the subdomain portion
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() >= 3 {
            // Check the leftmost label (likely encoded data)
            let subdomain = parts[0];
            if subdomain.len() > 30 && Self::shannon_entropy(subdomain) > 3.5 {
                return true;
            }
        }

        // Heuristic 3: Excessive query rate to same base domain
        if parts.len() >= 2 {
            let base = format!(
                "{}.{}",
                parts[parts.len() - 2],
                parts[parts.len() - 1]
            );
            let count = self.query_counts.entry(base).or_insert(0);
            *count += 1;
            if *count > 50 {
                return true;
            }
        }

        false
    }

    /// Calculate Shannon entropy of a string (measure of randomness).
    fn shannon_entropy(s: &str) -> f64 {
        let len = s.len() as f64;
        if len == 0.0 {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &b in s.as_bytes() {
            freq[b as usize] += 1;
        }

        let mut entropy = 0.0;
        for &count in &freq {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }
}

/// Built-in threat feeds with common known-bad domains.
pub fn builtin_malware_domains() -> Vec<&'static str> {
    vec![
        "malware-c2.example.com",
        "evil-botnet.example.net",
        "*.coinhive.com",
        "*.cryptoloot.pro",
    ]
}

pub fn builtin_phishing_domains() -> Vec<&'static str> {
    vec![
        "login-secure-update.example.com",
        "paypal-verify.example.net",
    ]
}

pub fn builtin_ad_domains() -> Vec<&'static str> {
    vec![
        "*.doubleclick.net",
        "*.googlesyndication.com",
        "*.moatads.com",
        "*.outbrain.com",
        "*.taboola.com",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_match() {
        let mut intel = ThreatIntel::new();
        intel.add_domain("malware.example.com", ThreatCategory::MalwareC2, "test");

        assert!(intel.check_domain("malware.example.com").is_some());
        assert!(intel.check_domain("safe.example.com").is_none());
    }

    #[test]
    fn wildcard_domain_match() {
        let mut intel = ThreatIntel::new();
        intel.add_domain("*.coinhive.com", ThreatCategory::Cryptomining, "test");
        intel.enable_category(ThreatCategory::Cryptomining);

        assert!(intel.check_domain("ws.coinhive.com").is_some());
        assert!(intel.check_domain("coinhive.com").is_some());
        assert!(intel.check_domain("notcoinhive.com").is_none());
    }

    #[test]
    fn disabled_category_allows() {
        let mut intel = ThreatIntel::new();
        intel.add_domain("ads.example.com", ThreatCategory::AdTracking, "test");

        // AdTracking is not enabled by default
        assert!(intel.check_domain("ads.example.com").is_none());

        // Enable it
        intel.enable_category(ThreatCategory::AdTracking);
        assert!(intel.check_domain("ads.example.com").is_some());
    }

    #[test]
    fn malware_always_blocked() {
        let mut intel = ThreatIntel::new();
        intel.add_domain("c2.evil.com", ThreatCategory::MalwareC2, "test");

        let entry = intel.check_domain("c2.evil.com").unwrap();
        assert_eq!(entry.category, ThreatCategory::MalwareC2);
        assert_eq!(entry.action, ThreatAction::BlockAndAlert);
    }

    #[test]
    fn dns_tunneling_detection_long_domain() {
        let mut intel = ThreatIntel::new();

        // A very long domain name (typical of DNS tunneling)
        let tunneling_domain = format!(
            "{}.tunnel.example.com",
            "a".repeat(101)
        );
        // This exceeds the 100-char threshold
        assert!(intel.check_domain(&tunneling_domain).is_some());
    }

    #[test]
    fn dns_tunneling_detection_high_entropy() {
        let mut intel = ThreatIntel::new();

        // High-entropy subdomain (base64-encoded data)
        let tunneling = "aGVsbG8gd29ybGQgdGhpcyBpcyBlbmNvZGVk.tunnel.example.com";
        assert!(intel.check_domain(tunneling).is_some());
    }

    #[test]
    fn normal_domain_not_flagged() {
        let mut intel = ThreatIntel::new();

        assert!(intel.check_domain("www.google.com").is_none());
        assert!(intel.check_domain("github.com").is_none());
        assert!(intel.check_domain("mail.example.org").is_none());
    }

    #[test]
    fn shannon_entropy_calculation() {
        // Low entropy (repeated characters)
        let low = TunnelingDetector::shannon_entropy("aaaaaa");
        assert!(low < 1.0);

        // High entropy (random-looking)
        let high = TunnelingDetector::shannon_entropy("aGVsbG8gd29ybGQ");
        assert!(high > 3.0);
    }

    #[test]
    fn bulk_load_domains() {
        let mut intel = ThreatIntel::strict();
        intel.load_domains(
            &builtin_malware_domains(),
            ThreatCategory::MalwareC2,
            "builtin",
        );
        intel.load_domains(
            &builtin_ad_domains(),
            ThreatCategory::AdTracking,
            "builtin",
        );

        assert!(intel.entry_count() > 0);
        assert!(intel.check_domain("evil-botnet.example.net").is_some());
    }

    #[test]
    fn strict_mode_blocks_ads() {
        let mut intel = ThreatIntel::strict();
        intel.add_domain("*.doubleclick.net", ThreatCategory::AdTracking, "builtin");

        assert!(intel.check_domain("ad.doubleclick.net").is_some());
    }

    #[test]
    fn default_actions_correct() {
        assert_eq!(
            default_action_for_category(ThreatCategory::MalwareC2),
            ThreatAction::BlockAndAlert
        );
        assert_eq!(
            default_action_for_category(ThreatCategory::AdTracking),
            ThreatAction::Block
        );
        assert_eq!(
            default_action_for_category(ThreatCategory::NewlyRegistered),
            ThreatAction::Monitor
        );
    }
}
