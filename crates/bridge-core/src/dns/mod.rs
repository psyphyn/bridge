//! Local DNS proxy for per-app routing and filtering.
//!
//! Intercepts DNS queries to:
//! 1. Apply domain-based blocklists (malware, ad networks)
//! 2. Record DNS→IP mappings for tunnel routing decisions
//! 3. Forward allowed queries to upstream DNS resolvers
//!
//! The proxy speaks standard DNS over UDP (port 53).

mod parser;
mod resolver;
mod threat;

pub use parser::{DnsPacket, DnsQuestion, DnsRecord, QueryType};
pub use resolver::DnsResolver;
pub use threat::{
    ThreatIntel, ThreatCategory, ThreatAction, ThreatEntry,
    builtin_malware_domains, builtin_phishing_domains, builtin_ad_domains,
};

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

/// DNS-to-IP mapping cache entry.
#[derive(Debug, Clone)]
pub struct DnsMapping {
    pub domain: String,
    pub ips: Vec<IpAddr>,
    pub resolved_at: Instant,
    pub ttl: Duration,
}

/// The DNS proxy that intercepts and filters queries.
pub struct DnsProxy {
    /// Listen address for the proxy.
    listen_addr: SocketAddr,
    /// Upstream DNS resolver.
    resolver: DnsResolver,
    /// Domain blocklist.
    blocklist: Arc<RwLock<Vec<String>>>,
    /// DNS→IP mapping cache for tunnel routing correlation.
    mappings: Arc<RwLock<HashMap<IpAddr, DnsMapping>>>,
}

impl DnsProxy {
    pub fn new(listen_addr: SocketAddr, upstream: SocketAddr) -> Self {
        Self {
            listen_addr,
            resolver: DnsResolver::new(upstream),
            blocklist: Arc::new(RwLock::new(Vec::new())),
            mappings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add domains to the blocklist.
    pub async fn add_blocked_domains(&self, domains: Vec<String>) {
        self.blocklist.write().await.extend(domains);
    }

    /// Look up which domain an IP address resolved from.
    pub async fn lookup_domain(&self, ip: &IpAddr) -> Option<String> {
        self.mappings
            .read()
            .await
            .get(ip)
            .filter(|m| m.resolved_at.elapsed() < m.ttl)
            .map(|m| m.domain.clone())
    }

    /// Get all current IP→domain mappings (for feeding into the router).
    /// Only returns non-expired entries.
    pub async fn current_mappings(&self) -> Vec<(IpAddr, String)> {
        self.mappings
            .read()
            .await
            .iter()
            .filter(|(_, m)| m.resolved_at.elapsed() < m.ttl)
            .map(|(ip, m)| (*ip, m.domain.clone()))
            .collect()
    }

    /// Run the DNS proxy. Listens for queries, filters, forwards, and caches.
    pub async fn run(&self) -> anyhow::Result<()> {
        let socket = Arc::new(UdpSocket::bind(self.listen_addr).await?);
        tracing::info!(addr = %self.listen_addr, "DNS proxy listening");

        let mut buf = vec![0u8; 4096];

        loop {
            let (len, client_addr) = socket.recv_from(&mut buf).await?;
            let query_data = buf[..len].to_vec();

            let resolver = self.resolver.clone();
            let blocklist = self.blocklist.clone();
            let mappings = self.mappings.clone();
            let sock = socket.clone();

            tokio::spawn(async move {
                match handle_query(&query_data, &resolver, &blocklist, &mappings).await {
                    Ok(response) => {
                        if let Err(e) = sock.send_to(&response, client_addr).await {
                            tracing::warn!(%e, "Failed to send DNS response");
                        }
                    }
                    Err(e) => {
                        tracing::warn!(%e, "DNS query handling failed");
                    }
                }
            });
        }
    }
}

async fn handle_query(
    query_data: &[u8],
    resolver: &DnsResolver,
    blocklist: &Arc<RwLock<Vec<String>>>,
    mappings: &Arc<RwLock<HashMap<IpAddr, DnsMapping>>>,
) -> anyhow::Result<Vec<u8>> {
    let packet = DnsPacket::parse(query_data)?;

    if let Some(question) = packet.questions.first() {
        let domain = &question.name;

        // Check blocklist
        let blocked = {
            let bl = blocklist.read().await;
            bl.iter().any(|b| domain == b || domain.ends_with(&format!(".{}", b)))
        };

        if blocked {
            tracing::info!(domain = %domain, "DNS query blocked");
            return Ok(build_nxdomain_response(query_data, &packet));
        }

        tracing::debug!(domain = %domain, qtype = ?question.qtype, "DNS query");

        // Forward to upstream
        let response_data = resolver.forward(query_data).await?;

        // Parse response to cache IP→domain mappings
        if let Ok(response) = DnsPacket::parse(&response_data) {
            let ips: Vec<IpAddr> = response
                .answers
                .iter()
                .filter_map(|r| match r {
                    DnsRecord::A { ip, .. } => Some(IpAddr::V4(*ip)),
                    DnsRecord::AAAA { ip, .. } => Some(IpAddr::V6(*ip)),
                    _ => None,
                })
                .collect();

            if !ips.is_empty() {
                let ttl = response.answers.first().map(|r| r.ttl()).unwrap_or(300);

                let mapping = DnsMapping {
                    domain: domain.clone(),
                    ips: ips.clone(),
                    resolved_at: Instant::now(),
                    ttl: Duration::from_secs(ttl as u64),
                };

                let mut map = mappings.write().await;
                for ip in &ips {
                    map.insert(*ip, mapping.clone());
                }
            }
        }

        Ok(response_data)
    } else {
        Ok(build_nxdomain_response(query_data, &packet))
    }
}

/// Build an NXDOMAIN response for blocked domains.
fn build_nxdomain_response(raw_query: &[u8], query: &DnsPacket) -> Vec<u8> {
    let mut resp = Vec::with_capacity(raw_query.len());

    // Header
    resp.extend_from_slice(&query.id.to_be_bytes());
    resp.extend_from_slice(&[0x81, 0x83]); // QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    resp.extend_from_slice(&(query.questions.len() as u16).to_be_bytes());
    resp.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT, NSCOUNT, ARCOUNT = 0

    // Copy question section from raw query (everything after 12-byte header)
    if raw_query.len() > 12 {
        // We need to copy just the question section
        // For simplicity, copy everything after header up to end of questions
        let question_end = query.question_end_offset;
        if question_end > 12 && question_end <= raw_query.len() {
            resp.extend_from_slice(&raw_query[12..question_end]);
        }
    }

    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_matching() {
        let blocked = vec!["example.com".to_string(), "malware.net".to_string()];

        let check = |domain: &str| -> bool {
            blocked.iter().any(|b| domain == b || domain.ends_with(&format!(".{}", b)))
        };

        assert!(check("example.com"));
        assert!(check("ads.example.com"));
        assert!(check("sub.ads.example.com"));
        assert!(!check("safe.org"));
        assert!(!check("notexample.com")); // Should NOT match
        assert!(check("malware.net"));
    }
}
