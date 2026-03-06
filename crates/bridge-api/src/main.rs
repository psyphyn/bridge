//! Bridge control plane API server.
//!
//! Handles authentication, device registration, policy management,
//! and admin dashboard API. Never touches traffic data (split-knowledge).

use axum::{routing::get, Json, Router};
use serde::Serialize;
use tracing_subscriber::EnvFilter;

mod auth;
mod models;
mod routes;

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
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Bridge API v{} starting", bridge_core::VERSION);

    let app = Router::new()
        .route("/health", get(health))
        .layer(tower_http::trace::TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("Listening on {}", listener.local_addr()?);

    axum::serve(listener, app).await?;

    Ok(())
}
