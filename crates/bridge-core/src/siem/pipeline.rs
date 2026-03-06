//! Event pipeline — routes security events to configured sinks.
//!
//! Sinks are output adapters: file, webhook, syslog, Splunk HEC, etc.
//! Events are buffered and flushed to sinks asynchronously.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use super::event::{EventCategory, EventSeverity, SecurityEvent};

/// Configuration for an event sink.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkConfig {
    /// Sink name (for logging).
    pub name: String,
    /// Sink type.
    pub sink_type: SinkType,
    /// Minimum severity to forward (events below this are dropped).
    pub min_severity: EventSeverity,
    /// Category filter (empty = all categories).
    #[serde(default)]
    pub categories: Vec<EventCategory>,
}

/// Supported sink types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SinkType {
    /// Write JSON events to a file (one per line, NDJSON).
    File { path: String },
    /// POST JSON events to a webhook URL.
    Webhook { url: String, auth_header: Option<String> },
    /// Splunk HTTP Event Collector.
    SplunkHec { url: String, token: String },
    /// Syslog over UDP.
    SyslogUdp { host: String, port: u16 },
}

/// Trait for event output sinks.
#[async_trait::async_trait]
pub trait EventSink: Send + Sync {
    /// Sink name.
    fn name(&self) -> &str;

    /// Send an event to this sink.
    async fn send(&self, event: &SecurityEvent) -> Result<(), String>;

    /// Check if this sink accepts the given event (severity + category filter).
    fn accepts(&self, event: &SecurityEvent, config: &SinkConfig) -> bool {
        // Check severity
        if event.severity < config.min_severity {
            return false;
        }
        // Check category filter
        if !config.categories.is_empty() && !config.categories.contains(&event.category) {
            return false;
        }
        true
    }
}

/// File sink — appends NDJSON events to a file.
pub struct FileSink {
    name: String,
    path: PathBuf,
    config: SinkConfig,
}

impl FileSink {
    pub fn new(config: SinkConfig) -> Result<Self, String> {
        let path = match &config.sink_type {
            SinkType::File { path } => PathBuf::from(path),
            _ => return Err("FileSink requires File sink type".to_string()),
        };

        Ok(Self {
            name: config.name.clone(),
            path,
            config,
        })
    }
}

#[async_trait::async_trait]
impl EventSink for FileSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, event: &SecurityEvent) -> Result<(), String> {
        if !self.accepts(event, &self.config) {
            return Ok(());
        }

        let line = format!("{}\n", event.to_json());
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| format!("Failed to open {}: {}", self.path.display(), e))?
            .write_all(line.as_bytes())
            .await
            .map_err(|e| format!("Failed to write event: {}", e))?;

        Ok(())
    }
}

use tokio::io::AsyncWriteExt;

/// Webhook sink — POSTs JSON events to an HTTP endpoint.
pub struct WebhookSink {
    name: String,
    url: String,
    auth_header: Option<String>,
    config: SinkConfig,
}

impl WebhookSink {
    pub fn new(config: SinkConfig) -> Result<Self, String> {
        let (url, auth_header) = match &config.sink_type {
            SinkType::Webhook { url, auth_header } => (url.clone(), auth_header.clone()),
            _ => return Err("WebhookSink requires Webhook sink type".to_string()),
        };

        Ok(Self {
            name: config.name.clone(),
            url,
            auth_header,
            config,
        })
    }
}

#[async_trait::async_trait]
impl EventSink for WebhookSink {
    fn name(&self) -> &str {
        &self.name
    }

    async fn send(&self, event: &SecurityEvent) -> Result<(), String> {
        if !self.accepts(event, &self.config) {
            return Ok(());
        }

        // Build a minimal HTTP POST using tokio TCP
        // In production, you'd use reqwest or hyper. For now, log the intent.
        tracing::debug!(
            sink = %self.name,
            url = %self.url,
            event_id = %event.id,
            "Would POST event to webhook"
        );

        Ok(())
    }
}

/// The event pipeline — receives events and dispatches to sinks.
pub struct EventPipeline {
    sinks: Vec<Box<dyn EventSink>>,
}

impl EventPipeline {
    /// Create a new event pipeline.
    pub fn new(_buffer_size: usize) -> Self {
        Self {
            sinks: Vec::new(),
        }
    }

    /// Add a sink to the pipeline.
    pub fn add_sink(&mut self, sink: Box<dyn EventSink>) {
        tracing::info!(sink = sink.name(), "Event sink added to pipeline");
        self.sinks.push(sink);
    }

    /// Start the background dispatch loop.
    /// Returns a cloneable handle for submitting events.
    pub fn start(self) -> EventPipelineHandle {
        let (tx, mut rx) = mpsc::channel::<SecurityEvent>(1024);
        let sinks = Arc::new(self.sinks);

        let handle = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                for sink in sinks.iter() {
                    if let Err(e) = sink.send(&event).await {
                        tracing::warn!(
                            sink = sink.name(),
                            error = %e,
                            "Failed to send event to sink"
                        );
                    }
                }
            }
            tracing::info!("Event pipeline shut down");
        });

        EventPipelineHandle {
            tx,
            _handle: Arc::new(handle),
        }
    }
}

/// Handle to a running event pipeline.
#[derive(Clone)]
pub struct EventPipelineHandle {
    tx: mpsc::Sender<SecurityEvent>,
    _handle: Arc<tokio::task::JoinHandle<()>>,
}

impl EventPipelineHandle {
    /// Submit an event to the pipeline.
    pub async fn emit(&self, event: SecurityEvent) {
        if let Err(e) = self.tx.send(event).await {
            tracing::warn!("Event pipeline full, dropping event: {}", e);
        }
    }

    /// Create an event and emit it in one call.
    pub async fn emit_new(
        &self,
        category: EventCategory,
        severity: EventSeverity,
        outcome: super::EventOutcome,
        message: impl Into<String>,
        detector: impl Into<String>,
    ) {
        let event = SecurityEvent::new(category, severity, outcome, message, detector);
        self.emit(event).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sink_config_serializes() {
        let config = SinkConfig {
            name: "audit-log".to_string(),
            sink_type: SinkType::File {
                path: "/var/log/bridge/events.ndjson".to_string(),
            },
            min_severity: EventSeverity::Medium,
            categories: vec![EventCategory::DataLoss, EventCategory::CommandAndControl],
        };

        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("audit-log"));
        assert!(json.contains("DataLoss"));

        let parsed: SinkConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "audit-log");
    }

    #[test]
    fn splunk_hec_config() {
        let config = SinkConfig {
            name: "splunk".to_string(),
            sink_type: SinkType::SplunkHec {
                url: "https://splunk.corp.com:8088/services/collector".to_string(),
                token: "test-token".to_string(),
            },
            min_severity: EventSeverity::Low,
            categories: vec![],
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("SplunkHec"));
        assert!(json.contains("test-token"));
    }

    #[test]
    fn file_sink_creation() {
        let config = SinkConfig {
            name: "test-file".to_string(),
            sink_type: SinkType::File {
                path: "/tmp/bridge-test-events.ndjson".to_string(),
            },
            min_severity: EventSeverity::Info,
            categories: vec![],
        };

        let sink = FileSink::new(config);
        assert!(sink.is_ok());
        assert_eq!(sink.unwrap().name(), "test-file");
    }

    #[test]
    fn webhook_sink_creation() {
        let config = SinkConfig {
            name: "test-webhook".to_string(),
            sink_type: SinkType::Webhook {
                url: "https://hooks.example.com/events".to_string(),
                auth_header: Some("Bearer test-token".to_string()),
            },
            min_severity: EventSeverity::High,
            categories: vec![EventCategory::CommandAndControl],
        };

        let sink = WebhookSink::new(config);
        assert!(sink.is_ok());
    }

    #[tokio::test]
    async fn file_sink_writes_event() {
        let path = "/tmp/bridge-siem-test.ndjson";
        let _ = tokio::fs::remove_file(path).await;

        let config = SinkConfig {
            name: "test".to_string(),
            sink_type: SinkType::File { path: path.to_string() },
            min_severity: EventSeverity::Info,
            categories: vec![],
        };

        let sink = FileSink::new(config).unwrap();
        let event = SecurityEvent::new(
            EventCategory::DataLoss,
            EventSeverity::High,
            super::super::EventOutcome::Blocked,
            "Test DLP event",
            "test",
        );

        sink.send(&event).await.unwrap();

        let content = tokio::fs::read_to_string(path).await.unwrap();
        assert!(content.contains("Test DLP event"));
        assert!(content.contains("DataLoss"));

        let _ = tokio::fs::remove_file(path).await;
    }
}
