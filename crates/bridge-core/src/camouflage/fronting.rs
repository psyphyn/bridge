//! Domain fronting for traffic camouflage.
//!
//! Domain fronting exploits the difference between the TLS SNI (visible to
//! network observers) and the HTTP Host header (encrypted, only visible to
//! the CDN). This means:
//!
//! - TLS SNI = "cdn.cloudflare.com" (innocent, high-collateral domain)
//! - HTTP Host = "bridge-relay-7f3a.workers.dev" (actual destination)
//!
//! A censor would need to block the entire CDN to block Bridge, which causes
//! massive collateral damage to legitimate services — the core of Tor's
//! "collateral freedom" strategy.

use serde::{Deserialize, Serialize};

/// Configuration for domain fronting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontingConfig {
    /// Strategy for selecting front domains.
    pub strategy: DomainStrategy,
    /// Available front domains.
    pub fronts: Vec<FrontDomain>,
    /// Fallback if no fronts are available.
    pub fallback_direct: bool,
}

/// A domain that can be used as a front.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontDomain {
    /// The domain shown in TLS SNI (e.g., "cdn.example.com").
    pub sni_domain: String,
    /// The real Host header (e.g., "bridge-relay.workers.dev").
    pub host_header: String,
    /// CDN provider (for categorization).
    pub provider: CdnProvider,
    /// Whether this front is currently known to work.
    pub verified: bool,
    /// Priority (lower = preferred).
    pub priority: u8,
}

/// Known CDN providers that support domain fronting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdnProvider {
    /// Cloudflare Workers/Pages.
    Cloudflare,
    /// Amazon CloudFront.
    CloudFront,
    /// Google Cloud CDN.
    GoogleCloud,
    /// Azure CDN.
    Azure,
    /// Fastly CDN.
    Fastly,
    /// Other/custom CDN.
    Other(String),
}

/// Strategy for selecting front domains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainStrategy {
    /// Use fronts in priority order.
    Priority,
    /// Rotate through fronts randomly.
    Random,
    /// Use different fronts for different connections (harder to fingerprint).
    PerConnection,
    /// Geo-aware: pick fronts that make sense for the client's region.
    GeoAware,
}

impl FrontingConfig {
    /// Select the best front domain based on the strategy.
    pub fn select_front(&self) -> Option<&FrontDomain> {
        match &self.strategy {
            DomainStrategy::Priority => {
                self.fronts
                    .iter()
                    .filter(|f| f.verified)
                    .min_by_key(|f| f.priority)
            }
            DomainStrategy::Random | DomainStrategy::PerConnection => {
                // Simple selection: pick from verified fronts
                // In production, use proper randomization
                let verified: Vec<_> = self.fronts.iter().filter(|f| f.verified).collect();
                if verified.is_empty() {
                    None
                } else {
                    // Use a simple hash of the current time for "randomness"
                    let idx = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos() as usize
                        % verified.len();
                    Some(verified[idx])
                }
            }
            DomainStrategy::GeoAware => {
                // Fallback to priority for now
                // In production, use GeoIP to pick region-appropriate fronts
                self.fronts
                    .iter()
                    .filter(|f| f.verified)
                    .min_by_key(|f| f.priority)
            }
        }
    }

    /// Mark a front as failed (unverified).
    pub fn mark_failed(&mut self, sni_domain: &str) {
        if let Some(front) = self.fronts.iter_mut().find(|f| f.sni_domain == sni_domain) {
            front.verified = false;
            tracing::warn!(domain = %sni_domain, "Front domain marked as failed");
        }
    }

    /// Mark a front as working (verified).
    pub fn mark_verified(&mut self, sni_domain: &str) {
        if let Some(front) = self.fronts.iter_mut().find(|f| f.sni_domain == sni_domain) {
            front.verified = true;
        }
    }
}

/// Create a default fronting config with example domains.
/// In production, these would come from the control plane.
pub fn example_config() -> FrontingConfig {
    FrontingConfig {
        strategy: DomainStrategy::Priority,
        fronts: vec![
            FrontDomain {
                sni_domain: "cdn.example.com".to_string(),
                host_header: "bridge-relay.workers.dev".to_string(),
                provider: CdnProvider::Cloudflare,
                verified: true,
                priority: 1,
            },
            FrontDomain {
                sni_domain: "d1234.cloudfront.net".to_string(),
                host_header: "bridge-relay.example.com".to_string(),
                provider: CdnProvider::CloudFront,
                verified: true,
                priority: 2,
            },
            FrontDomain {
                sni_domain: "storage.googleapis.com".to_string(),
                host_header: "bridge-relay.appspot.com".to_string(),
                provider: CdnProvider::GoogleCloud,
                verified: false, // Not yet tested
                priority: 3,
            },
        ],
        fallback_direct: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_front_by_priority() {
        let config = example_config();
        let front = config.select_front().unwrap();
        assert_eq!(front.sni_domain, "cdn.example.com");
        assert_eq!(front.priority, 1);
    }

    #[test]
    fn select_front_skips_unverified() {
        let mut config = example_config();
        // Mark the highest-priority front as failed
        config.mark_failed("cdn.example.com");

        let front = config.select_front().unwrap();
        assert_eq!(front.sni_domain, "d1234.cloudfront.net");
        assert_eq!(front.priority, 2);
    }

    #[test]
    fn select_front_returns_none_when_all_failed() {
        let mut config = example_config();
        config.mark_failed("cdn.example.com");
        config.mark_failed("d1234.cloudfront.net");
        // The third is already unverified
        assert!(config.select_front().is_none());
    }

    #[test]
    fn mark_verified_restores_front() {
        let mut config = example_config();
        config.mark_failed("cdn.example.com");
        assert_ne!(
            config.select_front().unwrap().sni_domain,
            "cdn.example.com"
        );

        config.mark_verified("cdn.example.com");
        assert_eq!(
            config.select_front().unwrap().sni_domain,
            "cdn.example.com"
        );
    }

    #[test]
    fn fronting_config_serializes() {
        let config = example_config();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: FrontingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fronts.len(), 3);
    }

    #[test]
    fn cdn_provider_variants() {
        let cf = CdnProvider::Cloudflare;
        let custom = CdnProvider::Other("akamai".to_string());
        assert_ne!(cf, custom);
    }
}
