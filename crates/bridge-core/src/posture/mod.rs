//! Device posture assessment using osquery and native checks.
//!
//! Evaluates device health and produces a posture score (0-100)
//! that determines the access tier.

pub mod osquery;

use serde::{Deserialize, Serialize};

/// Posture score range: 0 (quarantined) to 100 (full access).
pub type PostureScore = u8;

/// Access tier derived from posture score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessTier {
    /// Score 90-100: All resources accessible
    FullAccess,
    /// Score 70-89: Standard resources
    Standard,
    /// Score 40-69: Limited to essential apps
    Restricted,
    /// Score 0-39: Only remediation portal
    Quarantined,
}

impl AccessTier {
    pub fn from_score(score: PostureScore) -> Self {
        match score {
            90..=100 => Self::FullAccess,
            70..=89 => Self::Standard,
            40..=69 => Self::Restricted,
            _ => Self::Quarantined,
        }
    }
}

impl std::fmt::Display for AccessTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FullAccess => write!(f, "full_access"),
            Self::Standard => write!(f, "standard"),
            Self::Restricted => write!(f, "restricted"),
            Self::Quarantined => write!(f, "quarantined"),
        }
    }
}

/// A single posture check with a weight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureCheck {
    pub name: String,
    pub passed: bool,
    /// Weight for scoring (0-100). Higher = more impactful.
    pub weight: u8,
    pub detail: Option<String>,
}

/// Full posture assessment result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureAssessment {
    pub score: PostureScore,
    pub tier: AccessTier,
    pub checks: Vec<PostureCheck>,
}

/// Calculate posture score from a set of checks.
pub fn calculate_score(checks: &[PostureCheck]) -> PostureScore {
    if checks.is_empty() {
        return 100; // No checks = assume good (new device)
    }

    let total_weight: u32 = checks.iter().map(|c| c.weight as u32).sum();
    if total_weight == 0 {
        return 100;
    }

    let passed_weight: u32 = checks
        .iter()
        .filter(|c| c.passed)
        .map(|c| c.weight as u32)
        .sum();

    ((passed_weight * 100) / total_weight) as u8
}

/// Run a full posture assessment.
pub fn assess(checks: Vec<PostureCheck>) -> PostureAssessment {
    let score = calculate_score(&checks);
    let tier = AccessTier::from_score(score);

    PostureAssessment {
        score,
        tier,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_tier_from_score() {
        assert_eq!(AccessTier::from_score(95), AccessTier::FullAccess);
        assert_eq!(AccessTier::from_score(75), AccessTier::Standard);
        assert_eq!(AccessTier::from_score(50), AccessTier::Restricted);
        assert_eq!(AccessTier::from_score(20), AccessTier::Quarantined);
    }

    #[test]
    fn score_all_passing() {
        let checks = vec![
            PostureCheck { name: "disk_encryption".into(), passed: true, weight: 25, detail: None },
            PostureCheck { name: "firewall".into(), passed: true, weight: 15, detail: None },
            PostureCheck { name: "os_updated".into(), passed: true, weight: 30, detail: None },
        ];
        assert_eq!(calculate_score(&checks), 100);
    }

    #[test]
    fn score_partial_failure() {
        let checks = vec![
            PostureCheck { name: "disk_encryption".into(), passed: true, weight: 25, detail: None },
            PostureCheck { name: "firewall".into(), passed: false, weight: 15, detail: None },
            PostureCheck { name: "os_updated".into(), passed: true, weight: 30, detail: None },
        ];
        // 55/70 * 100 = 78 → Standard
        let score = calculate_score(&checks);
        assert_eq!(score, 78);
        assert_eq!(AccessTier::from_score(score), AccessTier::Standard);
    }

    #[test]
    fn score_all_failing() {
        let checks = vec![
            PostureCheck { name: "a".into(), passed: false, weight: 50, detail: None },
            PostureCheck { name: "b".into(), passed: false, weight: 50, detail: None },
        ];
        assert_eq!(calculate_score(&checks), 0);
        assert_eq!(AccessTier::from_score(0), AccessTier::Quarantined);
    }

    #[test]
    fn score_empty_checks() {
        assert_eq!(calculate_score(&[]), 100);
    }

    #[test]
    fn full_assessment() {
        let assessment = assess(vec![
            PostureCheck { name: "disk_encryption".into(), passed: true, weight: 25, detail: None },
            PostureCheck { name: "firewall".into(), passed: false, weight: 25, detail: Some("Firewall disabled".into()) },
        ]);
        assert_eq!(assessment.score, 50);
        assert_eq!(assessment.tier, AccessTier::Restricted);
        assert_eq!(assessment.checks.len(), 2);
    }
}
