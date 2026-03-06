//! Policy rules, conditions, and actions.

use serde::{Deserialize, Serialize};

use crate::posture::AccessTier;

use super::PolicyContext;

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Allow the traffic through.
    Allow,
    /// Block the traffic with a reason.
    Block { reason: String },
    /// Allow but create a shadow copy for audit.
    ShadowCopy,
    /// Allow but generate an alert.
    Alert { severity: String, message: String },
    /// Redirect to a remediation page.
    Redirect { url: String },
}

/// A condition that must be true for a rule to match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Condition {
    /// Domain matches any of the patterns (supports * wildcard prefix).
    DomainMatches(Vec<String>),
    /// Destination port matches.
    PortIs(u16),
    /// User is in the specified group.
    InGroup(String),
    /// User is NOT in the specified group.
    NotInGroup(String),
    /// Application matches (process name or bundle ID).
    ApplicationIs(String),
    /// Access tier is below the specified tier.
    AccessTierBelow(AccessTier),
    /// Access tier is at or above the specified tier.
    AccessTierAtLeast(AccessTier),
    /// Platform matches.
    PlatformIs(String),
    /// Protocol matches.
    ProtocolIs(String),
    /// Destination IP matches a CIDR range (stored as string for now).
    DestIpInRange(String),
}

/// A single policy rule with conditions and an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub conditions: Vec<Condition>,
    pub action: Action,
}

/// A named set of rules with a default action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySet {
    pub name: String,
    pub default_action: Action,
    pub rules: Vec<PolicyRule>,
}

/// Indicates which rule matched and why.
#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub rule_name: String,
    pub action: Action,
}

impl PolicyRule {
    /// Check if ALL conditions match the given context.
    pub fn matches(&self, ctx: &PolicyContext) -> bool {
        self.conditions.iter().all(|c| c.matches(ctx))
    }
}

impl Condition {
    /// Evaluate a single condition against a context.
    pub fn matches(&self, ctx: &PolicyContext) -> bool {
        match self {
            Condition::DomainMatches(patterns) => {
                let domain = match &ctx.domain {
                    Some(d) => d,
                    None => return false,
                };
                patterns.iter().any(|p| domain_matches(domain, p))
            }

            Condition::PortIs(port) => ctx.dest_port == Some(*port),

            Condition::InGroup(group) => ctx.user_groups.contains(group),

            Condition::NotInGroup(group) => !ctx.user_groups.contains(group),

            Condition::ApplicationIs(app) => {
                ctx.application.as_deref() == Some(app.as_str())
            }

            Condition::AccessTierBelow(tier) => {
                tier_ordinal(&ctx.access_tier) < tier_ordinal(tier)
            }

            Condition::AccessTierAtLeast(tier) => {
                tier_ordinal(&ctx.access_tier) >= tier_ordinal(tier)
            }

            Condition::PlatformIs(platform) => {
                ctx.platform.as_deref() == Some(platform.as_str())
            }

            Condition::ProtocolIs(proto) => {
                ctx.protocol.as_deref() == Some(proto.as_str())
            }

            Condition::DestIpInRange(_cidr) => {
                // TODO: Implement CIDR matching
                false
            }
        }
    }
}

/// Match a domain against a pattern (supports * wildcard prefix).
fn domain_matches(domain: &str, pattern: &str) -> bool {
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..]; // ".example.com"
        domain.ends_with(suffix) || domain == &pattern[2..]
    } else {
        domain == pattern
    }
}

/// Convert access tier to an ordinal for comparison.
fn tier_ordinal(tier: &AccessTier) -> u8 {
    match tier {
        AccessTier::Quarantined => 0,
        AccessTier::Restricted => 1,
        AccessTier::Standard => 2,
        AccessTier::FullAccess => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_exact_match() {
        assert!(domain_matches("example.com", "example.com"));
        assert!(!domain_matches("other.com", "example.com"));
    }

    #[test]
    fn domain_wildcard_match() {
        assert!(domain_matches("sub.example.com", "*.example.com"));
        assert!(domain_matches("deep.sub.example.com", "*.example.com"));
        assert!(domain_matches("example.com", "*.example.com"));
        assert!(!domain_matches("notexample.com", "*.example.com"));
    }

    #[test]
    fn tier_ordering() {
        assert!(tier_ordinal(&AccessTier::Quarantined) < tier_ordinal(&AccessTier::Standard));
        assert!(tier_ordinal(&AccessTier::FullAccess) > tier_ordinal(&AccessTier::Standard));
        assert!(tier_ordinal(&AccessTier::Standard) == tier_ordinal(&AccessTier::Standard));
    }
}
