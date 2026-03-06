//! Bridge relay - data plane server handling WireGuard tunnels and traffic inspection.
//!
//! The relay never sees user identity (split-knowledge architecture).
//! It only knows tunnel IDs and inspection policies.

use axum::{routing::get, Json, Router};
use base64::Engine;
use serde::Serialize;
use tracing_subscriber::EnvFilter;

mod peer_map;
mod wg_server;

use wg_server::WgServer;

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    peers: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    tracing::info!("Bridge relay v{} starting", bridge_core::VERSION);

    let wg_listen = std::env::var("BRIDGE_WG_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:51820".to_string());

    let health_listen = std::env::var("BRIDGE_HEALTH_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8081".to_string());

    // Load or generate relay keypair
    let relay_private_key = match std::env::var("BRIDGE_RELAY_PRIVATE_KEY") {
        Ok(key_b64) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&key_b64)
                .expect("Invalid base64 relay private key");
            let arr: [u8; 32] = bytes.try_into().expect("Key must be 32 bytes");
            arr
        }
        Err(_) => {
            let (private_b64, public_b64) = bridge_core::tunnel::generate_keypair();
            tracing::info!(public_key = %public_b64, "Generated relay keypair");
            tracing::warn!("Set BRIDGE_RELAY_PRIVATE_KEY env var for persistence");
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(&private_b64)
                .unwrap();
            bytes.try_into().unwrap()
        }
    };

    // Start WireGuard server
    let wg_server = WgServer::bind(&wg_listen, relay_private_key).await?;

    // Start health check HTTP server
    let wg_server_ref = std::sync::Arc::new(wg_server);
    let wg_for_health = wg_server_ref.clone();

    tokio::spawn(async move {
        let app = Router::new().route(
            "/health",
            get(move || {
                let wg = wg_for_health.clone();
                async move {
                    let peers = wg.peer_count().await;
                    Json(HealthResponse {
                        status: "ok",
                        version: bridge_core::VERSION,
                        peers,
                    })
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind(&health_listen)
            .await
            .unwrap();
        tracing::info!(addr = %health_listen, "Health endpoint listening");
        axum::serve(listener, app).await.unwrap();
    });

    tracing::info!("Bridge relay running");

    // Run WireGuard server (blocks)
    wg_server_ref.run().await?;

    Ok(())
}
