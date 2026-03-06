//! Local IPC server for client UI communication.
//!
//! Speaks JSON over a Unix domain socket (macOS/Linux) or named pipe (Windows).
//! The SwiftUI/Kotlin/WinUI client connects here to:
//! - Query daemon status (tunnels, posture, router state)
//! - Send commands (connect/disconnect, update config)

use std::sync::Arc;

use bridge_core::dns::DnsProxy;
use bridge_core::routing::AppRouter;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use uuid::Uuid;

/// IPC socket path.
fn socket_path() -> String {
    std::env::var("BRIDGE_IPC_SOCKET")
        .unwrap_or_else(|_| {
            let dir = std::env::var("TMPDIR")
                .unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/bridge-daemon.sock", dir.trim_end_matches('/'))
        })
}

/// IPC request from the client UI.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum IpcRequest {
    /// Get daemon status.
    #[serde(rename = "status")]
    Status,
    /// Get router configuration summary.
    #[serde(rename = "router_info")]
    RouterInfo,
    /// Resolve a domain via the DNS proxy.
    #[serde(rename = "dns_lookup")]
    DnsLookup { domain: String },
    /// Ping (health check).
    #[serde(rename = "ping")]
    Ping,
}

/// IPC response to the client UI.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum IpcResponse {
    #[serde(rename = "status")]
    Status {
        device_id: String,
        version: String,
        router_groups: usize,
    },
    #[serde(rename = "router_info")]
    RouterInfo {
        groups: Vec<GroupInfo>,
        default_route: String,
    },
    #[serde(rename = "dns_lookup")]
    DnsLookup {
        domain: String,
        cached: bool,
    },
    #[serde(rename = "pong")]
    Pong,
    #[serde(rename = "error")]
    Error { message: String },
}

#[derive(Debug, Serialize)]
pub struct GroupInfo {
    pub name: String,
    pub tunnel_id: String,
    pub app_count: usize,
    pub domain_count: usize,
}

/// Run the IPC server on a Unix domain socket.
pub async fn run_ipc_server(
    device_id: Uuid,
    router: Arc<RwLock<AppRouter>>,
    dns_proxy: Arc<DnsProxy>,
) -> anyhow::Result<()> {
    let path = socket_path();

    // Remove stale socket file if it exists
    let _ = tokio::fs::remove_file(&path).await;

    let listener = tokio::net::UnixListener::bind(&path)?;
    tracing::info!(path = %path, "IPC server listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let router = router.clone();
        let dns_proxy = dns_proxy.clone();
        let device_id = device_id;

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut lines = BufReader::new(reader).lines();

            while let Ok(Some(line)) = lines.next_line().await {
                let response = match serde_json::from_str::<IpcRequest>(&line) {
                    Ok(req) => handle_request(req, device_id, &router, &dns_proxy).await,
                    Err(e) => IpcResponse::Error {
                        message: format!("Invalid request: {}", e),
                    },
                };

                let mut json = serde_json::to_string(&response).unwrap_or_default();
                json.push('\n');

                if writer.write_all(json.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
    }
}

async fn handle_request(
    req: IpcRequest,
    device_id: Uuid,
    router: &Arc<RwLock<AppRouter>>,
    _dns_proxy: &Arc<DnsProxy>,
) -> IpcResponse {
    match req {
        IpcRequest::Status => {
            let r = router.read().await;
            IpcResponse::Status {
                device_id: device_id.to_string(),
                version: bridge_core::VERSION.to_string(),
                router_groups: r.groups().len(),
            }
        }
        IpcRequest::RouterInfo => {
            let r = router.read().await;
            let groups = r
                .groups()
                .iter()
                .map(|g| GroupInfo {
                    name: g.name.clone(),
                    tunnel_id: g.tunnel_id.to_string(),
                    app_count: g.applications.len(),
                    domain_count: g.domains.len(),
                })
                .collect();

            let default_route = match r.config().default_route {
                bridge_core::routing::DefaultRoute::TunnelAll => "tunnel_all",
                bridge_core::routing::DefaultRoute::SplitTunnel => "split_tunnel",
            };

            IpcResponse::RouterInfo {
                groups,
                default_route: default_route.to_string(),
            }
        }
        IpcRequest::DnsLookup { domain } => {
            // Check if we have a cached resolution
            // Note: DnsProxy.lookup_domain takes an IP, not a domain.
            // For domain lookups, the proxy would need to be queried directly.
            // For now, just confirm the domain was received.
            IpcResponse::DnsLookup {
                domain,
                cached: false,
            }
        }
        IpcRequest::Ping => IpcResponse::Pong,
    }
}
