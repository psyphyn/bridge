//! SIEM event pipeline — structured security event export.
//!
//! Generates CIM-compliant security events and routes them to
//! configured output adapters (syslog, webhook, file, Splunk HEC, etc.).

mod event;
mod pipeline;

pub use event::{SecurityEvent, EventCategory, EventSeverity, EventOutcome};
pub use pipeline::{EventPipeline, EventSink, SinkConfig, FileSink, WebhookSink};
