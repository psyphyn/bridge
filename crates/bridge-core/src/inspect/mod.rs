//! Traffic inspection engine (mitmproxy-inspired).
//!
//! Provides flow-based inspection with hooks and addons for TLS interception,
//! DLP scanning, and threat detection.

use serde::{Deserialize, Serialize};

/// Inspection verdict for a flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Block { reason: String },
    ShadowCopy,
    Alert { severity: Severity, message: String },
}

/// Alert severity levels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}
