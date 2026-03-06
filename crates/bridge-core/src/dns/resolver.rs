//! Upstream DNS resolver.
//!
//! Forwards DNS queries to an upstream server over UDP.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

/// Timeout for upstream DNS queries.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Forwards DNS queries to an upstream resolver.
#[derive(Clone)]
pub struct DnsResolver {
    upstream: SocketAddr,
}

impl DnsResolver {
    pub fn new(upstream: SocketAddr) -> Self {
        Self { upstream }
    }

    /// Forward a raw DNS query to upstream and return the raw response.
    pub async fn forward(&self, query: &[u8]) -> anyhow::Result<Vec<u8>> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.send_to(query, self.upstream).await?;

        let mut buf = vec![0u8; 4096];
        let len = timeout(UPSTREAM_TIMEOUT, socket.recv(&mut buf))
            .await
            .map_err(|_| anyhow::anyhow!("DNS upstream timeout"))??;

        buf.truncate(len);
        Ok(buf)
    }
}
