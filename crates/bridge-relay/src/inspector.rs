//! Relay-side inspection integration.
//!
//! Sets up the inspection pipeline for the relay data plane.
//! The relay inspects decapsulated traffic for DLP, threat detection, etc.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use bridge_core::inspect::{DlpScanner, Flow, FlowState, InspectionPipeline, Verdict};
use tokio::sync::Mutex;
use uuid::Uuid;

/// Flow tracker for the relay — maps peer + flow ID to active flows.
pub struct FlowTracker {
    /// Active flows indexed by a composite key.
    flows: HashMap<Uuid, Flow>,
    /// Map from (peer_addr) to flow IDs for that peer.
    peer_flows: HashMap<SocketAddr, Vec<Uuid>>,
}

impl FlowTracker {
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            peer_flows: HashMap::new(),
        }
    }

    /// Get or create a flow for a peer's packet.
    /// For now, one flow per peer (will expand to per-connection tracking).
    pub fn get_or_create_flow(&mut self, peer_addr: SocketAddr) -> &mut Flow {
        let flow_ids = self.peer_flows.entry(peer_addr).or_default();

        // Find an active flow for this peer
        if let Some(flow_id) = flow_ids.last() {
            if self.flows.contains_key(flow_id) {
                let id = *flow_id;
                return self.flows.get_mut(&id).unwrap();
            }
        }

        // Create a new flow
        let mut flow = Flow::new();
        flow.src = Some(peer_addr);
        flow.state = FlowState::Active;
        let flow_id = flow.id;
        self.flows.insert(flow_id, flow);
        flow_ids.push(flow_id);
        self.flows.get_mut(&flow_id).unwrap()
    }

    /// Remove all flows for a peer.
    pub fn remove_peer(&mut self, peer_addr: &SocketAddr) {
        if let Some(flow_ids) = self.peer_flows.remove(peer_addr) {
            for id in flow_ids {
                self.flows.remove(&id);
            }
        }
    }

    /// Total number of active flows.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }
}

/// Relay inspection context — holds the pipeline and flow tracker.
pub struct RelayInspector {
    pub pipeline: InspectionPipeline,
    pub flows: FlowTracker,
}

impl RelayInspector {
    /// Create a new relay inspector with default inspectors (DLP).
    pub fn new() -> Self {
        let mut pipeline = InspectionPipeline::new();
        pipeline.add_inspector(Box::new(DlpScanner::with_defaults()));

        Self {
            pipeline,
            flows: FlowTracker::new(),
        }
    }

    /// Inspect a decapsulated packet from a peer.
    /// Returns the verdict and updates flow tracking.
    pub fn inspect_packet(
        &mut self,
        peer_addr: SocketAddr,
        packet_data: &[u8],
    ) -> Verdict {
        let flow = self.flows.get_or_create_flow(peer_addr);
        flow.record_rx(packet_data.len());

        // Buffer the packet data for inspection
        // In production, we'd parse IP/TCP headers to extract the payload
        // For now, inspect the raw decapsulated packet
        flow.inspect_buffer.clear();
        flow.inspect_buffer.extend_from_slice(packet_data);

        let verdict = self.pipeline.evaluate(flow);

        if matches!(verdict, Verdict::Block { .. }) {
            flow.state = FlowState::Blocked;
        }

        verdict
    }
}

/// Thread-safe handle to the relay inspector.
pub type SharedInspector = Arc<Mutex<RelayInspector>>;

pub fn create_shared_inspector() -> SharedInspector {
    Arc::new(Mutex::new(RelayInspector::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 12345)
    }

    #[test]
    fn flow_tracker_creates_flow() {
        let mut tracker = FlowTracker::new();
        let addr = test_addr();
        let flow = tracker.get_or_create_flow(addr);
        assert_eq!(flow.src, Some(addr));
        assert_eq!(tracker.flow_count(), 1);
    }

    #[test]
    fn flow_tracker_reuses_flow() {
        let mut tracker = FlowTracker::new();
        let addr = test_addr();
        let id1 = tracker.get_or_create_flow(addr).id;
        let id2 = tracker.get_or_create_flow(addr).id;
        assert_eq!(id1, id2);
        assert_eq!(tracker.flow_count(), 1);
    }

    #[test]
    fn inspect_clean_packet_allows() {
        let mut inspector = RelayInspector::new();
        let verdict = inspector.inspect_packet(
            test_addr(),
            b"Hello, this is normal traffic",
        );
        assert_eq!(verdict, Verdict::Allow);
    }

    #[test]
    fn inspect_credit_card_blocks() {
        let mut inspector = RelayInspector::new();
        let verdict = inspector.inspect_packet(
            test_addr(),
            b"Send payment to card 4111111111111111",
        );
        assert!(matches!(verdict, Verdict::Block { .. }));
    }
}
