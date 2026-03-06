//! Security event types — CIM-inspired structured events.
//!
//! Events follow a common schema inspired by Splunk's Common Information Model
//! and the OCSF (Open Cybersecurity Schema Framework).

use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A structured security event ready for SIEM export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Unique event identifier.
    pub id: Uuid,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Event category.
    pub category: EventCategory,
    /// Severity level.
    pub severity: EventSeverity,
    /// Whether the action was allowed or blocked.
    pub outcome: EventOutcome,
    /// Short description of the event.
    pub message: String,
    /// Device ID that generated the event.
    pub device_id: Option<String>,
    /// Source IP address.
    pub src_ip: Option<IpAddr>,
    /// Destination IP address.
    pub dst_ip: Option<IpAddr>,
    /// Destination domain.
    pub domain: Option<String>,
    /// Source application (bundle ID or process name).
    pub application: Option<String>,
    /// Destination port.
    pub dst_port: Option<u16>,
    /// Protocol (TCP, UDP, etc.).
    pub protocol: Option<String>,
    /// Bytes sent (TX).
    pub bytes_out: Option<u64>,
    /// Bytes received (RX).
    pub bytes_in: Option<u64>,
    /// Inspector/detector that generated this event.
    pub detector: String,
    /// Additional key-value metadata.
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl SecurityEvent {
    /// Create a new security event with required fields.
    pub fn new(
        category: EventCategory,
        severity: EventSeverity,
        outcome: EventOutcome,
        message: impl Into<String>,
        detector: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            category,
            severity,
            outcome,
            message: message.into(),
            device_id: None,
            src_ip: None,
            dst_ip: None,
            domain: None,
            application: None,
            dst_port: None,
            protocol: None,
            bytes_out: None,
            bytes_in: None,
            detector: detector.into(),
            metadata: HashMap::new(),
        }
    }

    /// Builder: set source IP.
    pub fn with_src_ip(mut self, ip: IpAddr) -> Self {
        self.src_ip = Some(ip);
        self
    }

    /// Builder: set destination IP.
    pub fn with_dst_ip(mut self, ip: IpAddr) -> Self {
        self.dst_ip = Some(ip);
        self
    }

    /// Builder: set domain.
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// Builder: set application.
    pub fn with_application(mut self, app: impl Into<String>) -> Self {
        self.application = Some(app.into());
        self
    }

    /// Builder: set byte counts.
    pub fn with_bytes(mut self, bytes_out: u64, bytes_in: u64) -> Self {
        self.bytes_out = Some(bytes_out);
        self.bytes_in = Some(bytes_in);
        self
    }

    /// Builder: set device ID.
    pub fn with_device_id(mut self, id: impl Into<String>) -> Self {
        self.device_id = Some(id.into());
        self
    }

    /// Builder: add metadata key-value pair.
    pub fn with_meta(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Serialize to JSON with pretty printing.
    pub fn to_json_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as syslog-compatible message (RFC 5424-ish).
    pub fn to_syslog(&self) -> String {
        let facility = 4; // auth
        let priority = match self.severity {
            EventSeverity::Critical => facility * 8 + 2,
            EventSeverity::High => facility * 8 + 3,
            EventSeverity::Medium => facility * 8 + 4,
            EventSeverity::Low => facility * 8 + 5,
            EventSeverity::Info => facility * 8 + 6,
        };

        format!(
            "<{}>1 {} bridge {} - - - {}",
            priority,
            self.timestamp.to_rfc3339(),
            self.detector,
            self.message,
        )
    }
}

/// Event category following OCSF-inspired taxonomy.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventCategory {
    /// DLP: sensitive data detected in traffic.
    DataLoss,
    /// C2 beacon or callback activity.
    CommandAndControl,
    /// DNS-based threat (tunneling, malware domain).
    DnsThreat,
    /// Data exfiltration (volume anomaly).
    Exfiltration,
    /// Policy violation (blocked by policy rule).
    PolicyViolation,
    /// Authentication or posture event.
    Authentication,
    /// Tunnel lifecycle (connect, disconnect, error).
    TunnelEvent,
    /// Device posture change.
    PostureChange,
    /// Administrative action.
    AdminAction,
}

/// Event severity levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EventSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Event outcome — was the action allowed or blocked?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventOutcome {
    /// Action was allowed.
    Allowed,
    /// Action was blocked.
    Blocked,
    /// Action was allowed but flagged for review.
    Alerted,
    /// Action was allowed and a copy was captured.
    ShadowCopied,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn create_event_with_builder() {
        let event = SecurityEvent::new(
            EventCategory::DataLoss,
            EventSeverity::High,
            EventOutcome::Blocked,
            "Credit card detected in upload",
            "dlp-scanner",
        )
        .with_src_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
        .with_domain("drive.google.com")
        .with_bytes(4096, 0)
        .with_meta("pattern", "credit-card");

        assert_eq!(event.category, EventCategory::DataLoss);
        assert_eq!(event.severity, EventSeverity::High);
        assert_eq!(event.domain.as_deref(), Some("drive.google.com"));
        assert_eq!(event.metadata.get("pattern").map(|s| s.as_str()), Some("credit-card"));
    }

    #[test]
    fn event_serializes_to_json() {
        let event = SecurityEvent::new(
            EventCategory::CommandAndControl,
            EventSeverity::Critical,
            EventOutcome::Blocked,
            "C2 beacon detected",
            "beacon-detector",
        );

        let json = event.to_json();
        assert!(json.contains("CommandAndControl"));
        assert!(json.contains("C2 beacon detected"));
    }

    #[test]
    fn event_formats_as_syslog() {
        let event = SecurityEvent::new(
            EventCategory::DnsThreat,
            EventSeverity::High,
            EventOutcome::Blocked,
            "DNS tunneling to evil.com",
            "dns-threat",
        );

        let syslog = event.to_syslog();
        assert!(syslog.starts_with("<35>")); // facility=4(auth), severity=3(err)
        assert!(syslog.contains("DNS tunneling"));
    }

    #[test]
    fn severity_ordering() {
        assert!(EventSeverity::Critical > EventSeverity::High);
        assert!(EventSeverity::High > EventSeverity::Medium);
        assert!(EventSeverity::Medium > EventSeverity::Low);
        assert!(EventSeverity::Low > EventSeverity::Info);
    }
}
