//! Bridge relay - data plane server handling WireGuard tunnels and traffic inspection.
//!
//! The relay never sees user identity (split-knowledge architecture).
//! It only knows tunnel IDs and inspection policies.

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Bridge relay v{} starting", bridge_core::VERSION);

    // TODO: Start WireGuard listener (UDP)
    // TODO: Initialize inspection pipeline
    // TODO: Connect to control plane for policy sync
    // TODO: Start health check endpoint

    tracing::info!("Bridge relay running");

    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");

    Ok(())
}
