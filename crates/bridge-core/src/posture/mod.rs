//! Device posture assessment using osquery and native checks.
//!
//! Evaluates device health and produces a posture score (0-100)
//! that determines the access tier.

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
}
