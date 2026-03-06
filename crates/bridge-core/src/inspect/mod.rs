//! Traffic inspection engine (mitmproxy-inspired).
//!
//! Provides flow-based inspection with a pipeline of inspectors.
//! Each flow represents a connection or request/response pair.
//!
//! Architecture (inspired by mitmproxy):
//! - Flows track connection lifecycle
//! - Inspectors are chained in a pipeline
//! - Each inspector can allow, block, alert, or shadow-copy
//! - First blocking verdict wins

mod dlp;
mod flow;
mod pipeline;
pub mod tls;

pub use dlp::{DlpScanner, DlpPattern, DlpMatch};
pub use flow::{Flow, FlowMetadata, FlowDirection, FlowState};
pub use pipeline::{InspectionPipeline, Inspector, InspectorResult};
pub use tls::{BridgeCA, TlsInspectConfig, extract_sni};

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
