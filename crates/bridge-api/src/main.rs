//! Bridge control plane API server.
//!
//! Handles authentication, device registration, policy management,
//! and admin dashboard API. Never touches traffic data (split-knowledge).

use axum::{routing::{get, post}, Json, Router};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

mod auth;
mod models;
mod routes;
mod state;

use state::{AppState, RelayConfig};

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: bridge_core::VERSION,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Generate relay keypair (in production, loaded from config/secrets)
    let (relay_private, relay_public) = bridge_core::tunnel::generate_keypair();

    let listen_addr = std::env::var("BRIDGE_API_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let relay_endpoint = std::env::var("BRIDGE_RELAY_ENDPOINT")
        .unwrap_or_else(|_| "127.0.0.1:51820".to_string());

    tracing::info!(relay_public_key = %relay_public, "Relay keypair generated");

    let state = AppState::new(RelayConfig {
        private_key: relay_private,
        public_key: relay_public,
        endpoint: relay_endpoint,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/devices/register", post(routes::devices::register_device))
        .route("/api/v1/devices/posture", post(routes::devices::report_posture))
        .route("/api/v1/devices/heartbeat", post(routes::devices::heartbeat))
        .route("/api/v1/devices", get(routes::devices::list_devices))
        .route("/api/v1/attest/challenge", get(routes::attest::issue_challenge))
        .route("/api/v1/attest/verify", post(routes::attest::verify_attestation))
        // Policy management
        .route("/api/v1/policies", get(routes::policy::list_policies).post(routes::policy::upsert_policy))
        .route("/api/v1/policies/:name", get(routes::policy::get_policy).delete(routes::policy::delete_policy))
        .route("/api/v1/policies/rules", post(routes::policy::add_rule))
        .route("/api/v1/policies/evaluate", post(routes::policy::evaluate_policy))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    tracing::info!("Bridge API v{} listening on {}", bridge_core::VERSION, listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}
