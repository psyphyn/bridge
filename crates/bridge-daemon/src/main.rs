//! Bridge daemon - background service that manages tunnels, posture, and IPC.

use tracing_subscriber::EnvFilter;

mod platform;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("Bridge daemon v{} starting", bridge_core::VERSION);

    // TODO: Initialize tunnel manager
    // TODO: Start gRPC IPC server for UI communication
    // TODO: Start posture assessment loop
    // TODO: Connect to control plane for policy sync

    tracing::info!("Bridge daemon running");

    // Keep the daemon alive
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down");

    Ok(())
}
