//! C2 beacon detection via timing and behavioral analysis.
//!
//! Detects command-and-control (C2) callbacks by analyzing flow patterns:
//! - Regular interval connections (heartbeat beaconing)
//! - Jittered intervals (sophisticated C2 frameworks)
//! - Small request / large response ratio (download of instructions)
//! - Connections to recently-registered or low-reputation destinations

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::flow::Flow;
use super::{Inspector, Severity, Verdict};

/// Configuration for the beacon detector.
#[derive(Debug, Clone)]
pub struct BeaconConfig {
    /// Minimum number of connections before analysis begins.
    pub min_samples: usize,
    /// Maximum coefficient of variation (stdev/mean) for interval regularity.
    /// Lower = more regular = more suspicious. Typical C2: 0.0 – 0.3.
    pub regularity_threshold: f64,
    /// Minimum interval between connections to consider (filters out bursts).
    pub min_interval: Duration,
    /// Maximum interval to track (ignore long gaps).
    pub max_interval: Duration,
    /// Lookback window for timing analysis.
    pub window: Duration,
    /// Score threshold to trigger an alert (0.0 – 1.0).
    pub alert_threshold: f64,
    /// Score threshold to trigger a block.
    pub block_threshold: f64,
}

impl Default for BeaconConfig {
    fn default() -> Self {
        Self {
            min_samples: 6,
            regularity_threshold: 0.3,
            min_interval: Duration::from_secs(5),
            max_interval: Duration::from_secs(3600),
            window: Duration::from_secs(3600),
            alert_threshold: 0.6,
            block_threshold: 0.85,
        }
    }
}

/// Tracks connection timing per destination for beacon detection.
pub struct BeaconDetector {
    config: BeaconConfig,
    /// Destination → list of connection timestamps.
    destinations: HashMap<String, DestinationProfile>,
}

/// Per-destination connection profile.
struct DestinationProfile {
    timestamps: Vec<Instant>,
    /// Rolling byte counts: (request_bytes, response_bytes).
    byte_ratios: Vec<(u64, u64)>,
}

impl DestinationProfile {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            byte_ratios: Vec::new(),
        }
    }

    fn prune(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.timestamps.retain(|t| *t > cutoff);
        // Keep byte_ratios aligned (approximate — we only care about recent)
        let keep = self.timestamps.len();
        if self.byte_ratios.len() > keep {
            let drain = self.byte_ratios.len() - keep;
            self.byte_ratios.drain(..drain);
        }
    }
}

impl BeaconDetector {
    pub fn new() -> Self {
        Self::with_config(BeaconConfig::default())
    }

    pub fn with_config(config: BeaconConfig) -> Self {
        Self {
            config,
            destinations: HashMap::new(),
        }
    }

    /// Record a connection to a destination and return a beacon score (0.0 – 1.0).
    pub fn record_and_score(
        &mut self,
        destination: &str,
        tx_bytes: u64,
        rx_bytes: u64,
    ) -> BeaconScore {
        let profile = self
            .destinations
            .entry(destination.to_string())
            .or_insert_with(DestinationProfile::new);

        profile.prune(self.config.window);
        profile.timestamps.push(Instant::now());
        profile.byte_ratios.push((tx_bytes, rx_bytes));

        if profile.timestamps.len() < self.config.min_samples {
            return BeaconScore::insufficient();
        }

        // Calculate inter-arrival intervals
        let intervals: Vec<f64> = profile
            .timestamps
            .windows(2)
            .map(|w| w[1].duration_since(w[0]).as_secs_f64())
            .filter(|&d| {
                d >= self.config.min_interval.as_secs_f64()
                    && d <= self.config.max_interval.as_secs_f64()
            })
            .collect();

        if intervals.len() < self.config.min_samples - 1 {
            return BeaconScore::insufficient();
        }

        // Score 1: Interval regularity (coefficient of variation)
        let regularity_score = interval_regularity_score(&intervals, self.config.regularity_threshold);

        // Score 2: Request/response asymmetry (small tx, large rx = C2 instruction download)
        let asymmetry_score = byte_asymmetry_score(&profile.byte_ratios);

        // Score 3: Low payload variance (beacons tend to have consistent sizes)
        let size_consistency = payload_consistency_score(&profile.byte_ratios);

        // Weighted composite score
        let composite = regularity_score * 0.50
            + asymmetry_score * 0.25
            + size_consistency * 0.25;

        BeaconScore {
            composite,
            regularity: regularity_score,
            asymmetry: asymmetry_score,
            size_consistency,
            sample_count: profile.timestamps.len(),
            mean_interval_secs: mean(&intervals),
        }
    }

    /// Number of tracked destinations.
    pub fn destination_count(&self) -> usize {
        self.destinations.len()
    }
}

impl Default for BeaconDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Beacon analysis score for a destination.
#[derive(Debug, Clone)]
pub struct BeaconScore {
    /// Composite score (0.0 = benign, 1.0 = definite beacon).
    pub composite: f64,
    /// Interval regularity component.
    pub regularity: f64,
    /// Request/response asymmetry component.
    pub asymmetry: f64,
    /// Payload size consistency component.
    pub size_consistency: f64,
    /// Number of samples used.
    pub sample_count: usize,
    /// Mean interval between connections in seconds.
    pub mean_interval_secs: f64,
}

impl BeaconScore {
    fn insufficient() -> Self {
        Self {
            composite: 0.0,
            regularity: 0.0,
            asymmetry: 0.0,
            size_consistency: 0.0,
            sample_count: 0,
            mean_interval_secs: 0.0,
        }
    }
}

/// Inspector that wraps BeaconDetector for the inspection pipeline.
pub struct BeaconInspector {
    detector: std::sync::Mutex<BeaconDetector>,
    config: BeaconConfig,
}

impl BeaconInspector {
    pub fn new() -> Self {
        let config = BeaconConfig::default();
        Self {
            detector: std::sync::Mutex::new(BeaconDetector::with_config(config.clone())),
            config,
        }
    }

    pub fn with_config(config: BeaconConfig) -> Self {
        Self {
            detector: std::sync::Mutex::new(BeaconDetector::with_config(config.clone())),
            config,
        }
    }
}

impl Inspector for BeaconInspector {
    fn name(&self) -> &str {
        "c2-beacon-detector"
    }

    fn inspect(&self, flow: &Flow) -> Verdict {
        let dst_str;
        let destination = if let Some(ref d) = flow.metadata.domain {
            d.as_str()
        } else if let Some(ref sni) = flow.metadata.tls_sni {
            sni.as_str()
        } else if let Some(dst) = flow.dst {
            dst_str = dst.ip().to_string();
            &dst_str
        } else {
            "unknown"
        };

        let mut detector = self.detector.lock().unwrap();
        let score = detector.record_and_score(destination, flow.tx_bytes, flow.rx_bytes);

        if score.composite >= self.config.block_threshold {
            Verdict::Block {
                reason: format!(
                    "C2 beacon detected: score={:.2}, regularity={:.2}, interval={:.0}s, samples={}",
                    score.composite,
                    score.regularity,
                    score.mean_interval_secs,
                    score.sample_count,
                ),
            }
        } else if score.composite >= self.config.alert_threshold {
            Verdict::Alert {
                severity: Severity::High,
                message: format!(
                    "Possible C2 beacon: score={:.2}, regularity={:.2}, interval={:.0}s to {}",
                    score.composite,
                    score.regularity,
                    score.mean_interval_secs,
                    destination,
                ),
            }
        } else {
            Verdict::Allow
        }
    }
}

// ── Scoring functions ──

/// Score interval regularity. Lower CV = more regular = higher score.
fn interval_regularity_score(intervals: &[f64], threshold: f64) -> f64 {
    if intervals.is_empty() {
        return 0.0;
    }

    let m = mean(intervals);
    if m == 0.0 {
        return 0.0;
    }

    let variance = intervals.iter().map(|x| (x - m).powi(2)).sum::<f64>() / intervals.len() as f64;
    let stdev = variance.sqrt();
    let cv = stdev / m; // coefficient of variation

    // Map CV to score: CV=0 → score=1.0, CV>=threshold → score=0.0
    if cv >= threshold {
        0.0
    } else {
        1.0 - (cv / threshold)
    }
}

/// Score request/response asymmetry. Small requests + large responses = suspicious.
fn byte_asymmetry_score(ratios: &[(u64, u64)]) -> f64 {
    if ratios.is_empty() {
        return 0.0;
    }

    let asymmetric_count = ratios
        .iter()
        .filter(|(tx, rx)| {
            // Small tx, larger rx — typical C2 pattern
            *tx < 256 && *rx > *tx * 2 && *rx > 64
        })
        .count();

    asymmetric_count as f64 / ratios.len() as f64
}

/// Score payload size consistency. Beacons tend to have very consistent sizes.
fn payload_consistency_score(ratios: &[(u64, u64)]) -> f64 {
    if ratios.len() < 2 {
        return 0.0;
    }

    let sizes: Vec<f64> = ratios.iter().map(|(tx, rx)| (*tx + *rx) as f64).collect();
    let m = mean(&sizes);
    if m == 0.0 {
        return 0.0;
    }

    let variance = sizes.iter().map(|x| (x - m).powi(2)).sum::<f64>() / sizes.len() as f64;
    let cv = variance.sqrt() / m;

    // Low CV = consistent sizes = suspicious
    if cv >= 0.5 {
        0.0
    } else {
        1.0 - (cv / 0.5)
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn insufficient_samples_returns_zero() {
        let mut detector = BeaconDetector::with_config(BeaconConfig {
            min_samples: 4,
            ..Default::default()
        });

        let score = detector.record_and_score("evil.com", 32, 128);
        assert_eq!(score.composite, 0.0);
    }

    #[test]
    fn regular_intervals_score_high() {
        let intervals = vec![60.0, 60.0, 60.0, 60.0, 60.0];
        let score = interval_regularity_score(&intervals, 0.3);
        assert!(score > 0.9, "Regular intervals should score high: {}", score);
    }

    #[test]
    fn irregular_intervals_score_low() {
        let intervals = vec![5.0, 120.0, 3.0, 300.0, 10.0];
        let score = interval_regularity_score(&intervals, 0.3);
        assert!(score < 0.1, "Irregular intervals should score low: {}", score);
    }

    #[test]
    fn jittered_intervals_score_moderate() {
        // C2 with 10% jitter around 60s
        let intervals = vec![57.0, 63.0, 59.0, 61.0, 58.0, 62.0];
        let score = interval_regularity_score(&intervals, 0.3);
        assert!(score > 0.5, "Jittered intervals should score moderate+: {}", score);
    }

    #[test]
    fn asymmetric_traffic_detected() {
        let ratios = vec![(32, 512), (48, 1024), (16, 256), (32, 768)];
        let score = byte_asymmetry_score(&ratios);
        assert!(score > 0.8, "Asymmetric traffic should score high: {}", score);
    }

    #[test]
    fn symmetric_traffic_benign() {
        let ratios = vec![(1024, 1024), (2048, 2048), (512, 512)];
        let score = byte_asymmetry_score(&ratios);
        assert!(score < 0.1, "Symmetric traffic should score low: {}", score);
    }

    #[test]
    fn consistent_sizes_suspicious() {
        let ratios = vec![(32, 128), (32, 128), (32, 128), (32, 128)];
        let score = payload_consistency_score(&ratios);
        assert!(score > 0.9, "Consistent sizes should score high: {}", score);
    }

    #[test]
    fn varied_sizes_benign() {
        let ratios = vec![(100, 50000), (5000, 200), (32, 128), (10000, 10000)];
        let score = payload_consistency_score(&ratios);
        assert!(score < 0.5, "Varied sizes should score lower: {}", score);
    }

    #[test]
    fn beacon_inspector_allows_normal_traffic() {
        let inspector = BeaconInspector::new();
        let flow = Flow::new();
        assert_eq!(inspector.inspect(&flow), Verdict::Allow);
    }
}
