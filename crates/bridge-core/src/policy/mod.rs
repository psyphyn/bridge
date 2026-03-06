//! Policy evaluation engine.
//!
//! Evaluates access policies based on device posture, user identity,
//! application, and network context.
//!
//! Policies are defined as rules with conditions and actions.
//! The engine evaluates rules top-to-bottom, first match wins.

mod rules;

pub use rules::{
    Action, Condition, PolicyRule, PolicySet, RuleMatch,
};

use serde::{Deserialize, Serialize};

use crate::posture::AccessTier;

/// Context provided to the policy engine for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// Device access tier (from posture score).
    pub access_tier: AccessTier,
    /// Application making the request (process name or bundle ID).
    pub application: Option<String>,
    /// Destination domain (from DNS proxy correlation).
    pub domain: Option<String>,
    /// Destination IP.
    pub dest_ip: Option<String>,
    /// Destination port.
    pub dest_port: Option<u16>,
    /// Protocol (tcp, udp, etc).
    pub protocol: Option<String>,
    /// User groups the device owner belongs to.
    pub user_groups: Vec<String>,
    /// Device platform.
    pub platform: Option<String>,
}

impl Default for PolicyContext {
    fn default() -> Self {
        Self {
            access_tier: AccessTier::Standard,
            application: None,
            domain: None,
            dest_ip: None,
            dest_port: None,
            protocol: None,
            user_groups: Vec::new(),
            platform: None,
        }
    }
}

/// Result of policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub action: Action,
    pub matched_rule: Option<String>,
}

/// Evaluate a policy set against a context. First matching rule wins.
pub fn evaluate(policy_set: &PolicySet, ctx: &PolicyContext) -> PolicyDecision {
    for rule in &policy_set.rules {
        if rule.matches(ctx) {
            return PolicyDecision {
                action: rule.action.clone(),
                matched_rule: Some(rule.name.clone()),
            };
        }
    }

    // Default action if no rule matches
    PolicyDecision {
        action: policy_set.default_action.clone(),
        matched_rule: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy_set() -> PolicySet {
        PolicySet {
            name: "test-policy".to_string(),
            default_action: Action::Allow,
            rules: vec![
                PolicyRule {
                    name: "block-malware".to_string(),
                    conditions: vec![Condition::DomainMatches(vec![
                        "malware.com".to_string(),
                        "*.evil.net".to_string(),
                    ])],
                    action: Action::Block {
                        reason: "Malware domain".to_string(),
                    },
                },
                PolicyRule {
                    name: "restrict-social-for-quarantined".to_string(),
                    conditions: vec![
                        Condition::AccessTierBelow(AccessTier::Standard),
                        Condition::DomainMatches(vec![
                            "*.facebook.com".to_string(),
                            "*.twitter.com".to_string(),
                        ]),
                    ],
                    action: Action::Block {
                        reason: "Social media blocked for low posture devices".to_string(),
                    },
                },
                PolicyRule {
                    name: "shadow-copy-personal-uploads".to_string(),
                    conditions: vec![
                        Condition::DomainMatches(vec!["drive.google.com".to_string()]),
                        Condition::NotInGroup("corporate-google".to_string()),
                    ],
                    action: Action::ShadowCopy,
                },
                PolicyRule {
                    name: "engineering-ssh".to_string(),
                    conditions: vec![
                        Condition::InGroup("engineering".to_string()),
                        Condition::PortIs(22),
                    ],
                    action: Action::Allow,
                },
            ],
        }
    }

    #[test]
    fn block_malware_domain() {
        let ps = test_policy_set();
        let ctx = PolicyContext {
            domain: Some("malware.com".to_string()),
            ..Default::default()
        };
        let decision = evaluate(&ps, &ctx);
        assert_eq!(decision.matched_rule.as_deref(), Some("block-malware"));
        assert!(matches!(decision.action, Action::Block { .. }));
    }

    #[test]
    fn block_wildcard_domain() {
        let ps = test_policy_set();
        let ctx = PolicyContext {
            domain: Some("sub.evil.net".to_string()),
            ..Default::default()
        };
        let decision = evaluate(&ps, &ctx);
        assert_eq!(decision.matched_rule.as_deref(), Some("block-malware"));
    }

    #[test]
    fn allow_normal_traffic() {
        let ps = test_policy_set();
        let ctx = PolicyContext {
            domain: Some("google.com".to_string()),
            ..Default::default()
        };
        let decision = evaluate(&ps, &ctx);
        assert_eq!(decision.action, Action::Allow);
        assert!(decision.matched_rule.is_none()); // Hit default
    }

    #[test]
    fn quarantined_blocked_from_social() {
        let ps = test_policy_set();
        let ctx = PolicyContext {
            access_tier: AccessTier::Quarantined,
            domain: Some("www.facebook.com".to_string()),
            ..Default::default()
        };
        let decision = evaluate(&ps, &ctx);
        assert_eq!(
            decision.matched_rule.as_deref(),
            Some("restrict-social-for-quarantined")
        );
    }

    #[test]
    fn standard_tier_allowed_social() {
        let ps = test_policy_set();
        let ctx = PolicyContext {
            access_tier: AccessTier::Standard,
            domain: Some("www.facebook.com".to_string()),
            ..Default::default()
        };
        let decision = evaluate(&ps, &ctx);
        // Should NOT match the quarantine rule (tier is Standard, not below)
        assert_eq!(decision.action, Action::Allow);
    }

    #[test]
    fn shadow_copy_personal_google_drive() {
        let ps = test_policy_set();
        let ctx = PolicyContext {
            domain: Some("drive.google.com".to_string()),
            user_groups: vec!["engineering".to_string()], // not in corporate-google
            ..Default::default()
        };
        let decision = evaluate(&ps, &ctx);
        assert_eq!(decision.action, Action::ShadowCopy);
    }

    #[test]
    fn engineering_ssh_allowed() {
        let ps = test_policy_set();
        let ctx = PolicyContext {
            user_groups: vec!["engineering".to_string()],
            dest_port: Some(22),
            ..Default::default()
        };
        let decision = evaluate(&ps, &ctx);
        assert_eq!(decision.matched_rule.as_deref(), Some("engineering-ssh"));
        assert_eq!(decision.action, Action::Allow);
    }
}
