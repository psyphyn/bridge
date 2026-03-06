//! Security event API — query and manage SIEM events.
//!
//! Events are submitted by relay nodes and queryable by admin dashboard.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use bridge_core::siem::{EventCategory, EventSeverity, SecurityEvent};

use crate::state::AppState;

/// Query parameters for listing events.
#[derive(Debug, Deserialize)]
pub struct EventQuery {
    /// Filter by category.
    pub category: Option<String>,
    /// Filter by minimum severity.
    pub min_severity: Option<String>,
    /// Maximum number of events to return.
    pub limit: Option<usize>,
}

/// Response for event listing.
#[derive(Debug, Serialize)]
pub struct EventListResponse {
    pub events: Vec<SecurityEvent>,
    pub total: usize,
}

/// List recent security events with optional filtering.
pub async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventQuery>,
) -> Json<EventListResponse> {
    let events = state.events.read().await;
    let limit = query.limit.unwrap_or(100).min(1000);

    let filtered: Vec<SecurityEvent> = events
        .iter()
        .rev() // Most recent first
        .filter(|e| {
            if let Some(ref cat) = query.category {
                let cat_str = serde_json::to_string(&e.category)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string();
                if cat_str != *cat {
                    return false;
                }
            }
            if let Some(ref sev) = query.min_severity {
                let min = parse_severity(sev);
                if e.severity < min {
                    return false;
                }
            }
            true
        })
        .take(limit)
        .cloned()
        .collect();

    let total = filtered.len();
    Json(EventListResponse {
        events: filtered,
        total,
    })
}

/// Ingest events from relay nodes.
pub async fn ingest_events(
    State(state): State<AppState>,
    Json(incoming): Json<Vec<SecurityEvent>>,
) -> StatusCode {
    let mut events = state.events.write().await;
    let count = incoming.len();

    for event in incoming {
        events.push(event);
    }

    // Cap the in-memory buffer (ring buffer behavior)
    const MAX_EVENTS: usize = 10_000;
    if events.len() > MAX_EVENTS {
        let drain = events.len() - MAX_EVENTS;
        events.drain(..drain);
    }

    tracing::debug!(count, total = events.len(), "Ingested security events");
    StatusCode::ACCEPTED
}

/// Get event summary/stats.
pub async fn event_stats(
    State(state): State<AppState>,
) -> Json<EventStats> {
    let events = state.events.read().await;

    let mut by_category: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let mut by_severity: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    for event in events.iter() {
        let cat = serde_json::to_string(&event.category)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        *by_category.entry(cat).or_default() += 1;

        let sev = serde_json::to_string(&event.severity)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        *by_severity.entry(sev).or_default() += 1;
    }

    Json(EventStats {
        total: events.len(),
        by_category,
        by_severity,
    })
}

#[derive(Debug, Serialize)]
pub struct EventStats {
    pub total: usize,
    pub by_category: std::collections::HashMap<String, usize>,
    pub by_severity: std::collections::HashMap<String, usize>,
}

fn parse_severity(s: &str) -> EventSeverity {
    match s.to_lowercase().as_str() {
        "critical" => EventSeverity::Critical,
        "high" => EventSeverity::High,
        "medium" => EventSeverity::Medium,
        "low" => EventSeverity::Low,
        _ => EventSeverity::Info,
    }
}
