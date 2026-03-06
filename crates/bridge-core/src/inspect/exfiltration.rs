//! Data exfiltration detection via volume anomaly analysis.
//!
//! Detects potential data exfiltration by monitoring:
//! - Unusual upload volumes per destination (vs. historical baseline)
//! - Large single transfers to uncommon destinations
//! - Sustained upload streams exceeding thresholds

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::flow::Flow;
use super::{Inspector, Severity, Verdict};

/// Configuration for the exfiltration detector.
#[derive(Debug, Clone)]
pub struct ExfilConfig {
    /// Absolute upload threshold per destination per window (bytes).
    pub upload_threshold: u64,
    /// Single-flow upload threshold (bytes) — immediate alert.
    pub single_flow_threshold: u64,
    /// Time window for volume tracking.
    pub window: Duration,
    /// Multiplier over baseline to trigger alert (e.g., 5.0 = 5x normal).
    pub baseline_multiplier: f64,
    /// Minimum baseline samples before anomaly detection activates.
    pub min_baseline_windows: usize,
}

impl Default for ExfilConfig {
    fn default() -> Self {
        Self {
            upload_threshold: 50 * 1024 * 1024, // 50 MB
            single_flow_threshold: 100 * 1024 * 1024, // 100 MB
            window: Duration::from_secs(300), // 5 minutes
            baseline_multiplier: 5.0,
            min_baseline_windows: 3,
        }
    }
}

/// Tracks upload volumes per destination over time.
pub struct ExfiltrationDetector {
    config: ExfilConfig,
    /// Destination → volume tracking.
    destinations: HashMap<String, DestinationVolume>,
}

struct DestinationVolume {
    /// Current window upload bytes.
    current_bytes: u64,
    /// When the current window started.
    window_start: Instant,
    /// Historical window totals (for baseline).
    history: Vec<u64>,
}

impl DestinationVolume {
    fn new() -> Self {
        Self {
            current_bytes: 0,
            window_start: Instant::now(),
            history: Vec::new(),
        }
    }

    fn rotate_if_needed(&mut self, window: Duration) {
        if self.window_start.elapsed() >= window {
            self.history.push(self.current_bytes);
            // Keep last 24 windows (2 hours at 5-min windows)
            if self.history.len() > 24 {
                self.history.remove(0);
            }
            self.current_bytes = 0;
            self.window_start = Instant::now();
        }
    }

    fn baseline_mean(&self) -> Option<f64> {
        if self.history.is_empty() {
            return None;
        }
        let sum: u64 = self.history.iter().sum();
        Some(sum as f64 / self.history.len() as f64)
    }
}

impl ExfiltrationDetector {
    pub fn new() -> Self {
        Self::with_config(ExfilConfig::default())
    }

    pub fn with_config(config: ExfilConfig) -> Self {
        Self {
            config,
            destinations: HashMap::new(),
        }
    }

    /// Record an upload and check for exfiltration.
    pub fn record_upload(
        &mut self,
        destination: &str,
        bytes: u64,
    ) -> ExfilVerdict {
        let vol = self
            .destinations
            .entry(destination.to_string())
            .or_insert_with(DestinationVolume::new);

        vol.rotate_if_needed(self.config.window);
        vol.current_bytes += bytes;

        // Check 1: Single-flow massive upload
        if bytes >= self.config.single_flow_threshold {
            return ExfilVerdict::Alert {
                reason: format!(
                    "Large upload: {} MB to {}",
                    bytes / (1024 * 1024),
                    destination,
                ),
                severity: ExfilSeverity::High,
            };
        }

        // Check 2: Absolute window threshold
        if vol.current_bytes >= self.config.upload_threshold {
            return ExfilVerdict::Alert {
                reason: format!(
                    "Upload volume {} MB exceeds threshold in window to {}",
                    vol.current_bytes / (1024 * 1024),
                    destination,
                ),
                severity: ExfilSeverity::High,
            };
        }

        // Check 3: Anomaly vs baseline
        if vol.history.len() >= self.config.min_baseline_windows {
            if let Some(baseline) = vol.baseline_mean() {
                if baseline > 0.0 {
                    let ratio = vol.current_bytes as f64 / baseline;
                    if ratio >= self.config.baseline_multiplier {
                        return ExfilVerdict::Alert {
                            reason: format!(
                                "Upload anomaly: {:.1}x baseline ({} MB vs {:.0} MB avg) to {}",
                                ratio,
                                vol.current_bytes / (1024 * 1024),
                                baseline / (1024.0 * 1024.0),
                                destination,
                            ),
                            severity: ExfilSeverity::Medium,
                        };
                    }
                }
            }
        }

        ExfilVerdict::Normal
    }

    /// Number of tracked destinations.
    pub fn destination_count(&self) -> usize {
        self.destinations.len()
    }
}

impl Default for ExfiltrationDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Verdict from exfiltration analysis.
#[derive(Debug, Clone, PartialEq)]
pub enum ExfilVerdict {
    Normal,
    Alert { reason: String, severity: ExfilSeverity },
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExfilSeverity {
    Medium,
    High,
}

/// Inspector that wraps ExfiltrationDetector for the pipeline.
pub struct ExfiltrationInspector {
    detector: std::sync::Mutex<ExfiltrationDetector>,
}

impl ExfiltrationInspector {
    pub fn new() -> Self {
        Self {
            detector: std::sync::Mutex::new(ExfiltrationDetector::new()),
        }
    }

    pub fn with_config(config: ExfilConfig) -> Self {
        Self {
            detector: std::sync::Mutex::new(ExfiltrationDetector::with_config(config)),
        }
    }
}

impl Inspector for ExfiltrationInspector {
    fn name(&self) -> &str {
        "exfiltration-detector"
    }

    fn inspect(&self, flow: &Flow) -> Verdict {
        let destination = flow
            .metadata
            .domain
            .as_deref()
            .or(flow.metadata.tls_sni.as_deref())
            .unwrap_or("unknown");

        let mut detector = self.detector.lock().unwrap();
        match detector.record_upload(destination, flow.tx_bytes) {
            ExfilVerdict::Normal => Verdict::Allow,
            ExfilVerdict::Alert { reason, severity } => {
                let sev = match severity {
                    ExfilSeverity::High => Severity::High,
                    ExfilSeverity::Medium => Severity::Medium,
                };
                Verdict::Alert {
                    severity: sev,
                    message: reason,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_upload_passes() {
        let mut detector = ExfiltrationDetector::new();
        let verdict = detector.record_upload("drive.google.com", 1024);
        assert_eq!(verdict, ExfilVerdict::Normal);
    }

    #[test]
    fn massive_single_upload_alerts() {
        let mut detector = ExfiltrationDetector::with_config(ExfilConfig {
            single_flow_threshold: 1024 * 1024, // 1 MB for test
            ..Default::default()
        });

        let verdict = detector.record_upload("suspicious.com", 2 * 1024 * 1024);
        assert!(matches!(verdict, ExfilVerdict::Alert { severity: ExfilSeverity::High, .. }));
    }

    #[test]
    fn cumulative_window_threshold() {
        let mut detector = ExfiltrationDetector::with_config(ExfilConfig {
            upload_threshold: 10_000,
            ..Default::default()
        });

        // Several small uploads that cumulatively exceed threshold
        for _ in 0..5 {
            let _ = detector.record_upload("upload.example.com", 2500);
        }

        // This one tips over
        let verdict = detector.record_upload("upload.example.com", 1);
        assert!(matches!(verdict, ExfilVerdict::Alert { .. }));
    }

    #[test]
    fn different_destinations_tracked_separately() {
        let mut detector = ExfiltrationDetector::with_config(ExfilConfig {
            upload_threshold: 10_000,
            ..Default::default()
        });

        let v1 = detector.record_upload("site-a.com", 5000);
        let v2 = detector.record_upload("site-b.com", 5000);

        assert_eq!(v1, ExfilVerdict::Normal);
        assert_eq!(v2, ExfilVerdict::Normal);
        assert_eq!(detector.destination_count(), 2);
    }

    #[test]
    fn exfil_inspector_allows_normal() {
        let inspector = ExfiltrationInspector::new();
        let mut flow = Flow::new();
        flow.metadata.domain = Some("safe.example.com".to_string());
        flow.record_tx(1024);

        assert_eq!(inspector.inspect(&flow), Verdict::Allow);
    }
}
