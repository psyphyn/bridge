//! Inspection pipeline — chain of inspectors that process flows.
//!
//! Inspired by mitmproxy's addon system. Each inspector in the pipeline
//! gets a chance to inspect the flow. A blocking verdict short-circuits
//! the pipeline.

use super::flow::Flow;
use super::Verdict;

/// Result from a single inspector.
#[derive(Debug, Clone)]
pub struct InspectorResult {
    pub inspector_name: String,
    pub verdict: Verdict,
}

/// Trait for traffic inspectors.
///
/// Implement this to add custom inspection logic (DLP, threat detection, etc).
pub trait Inspector: Send + Sync {
    /// Name of this inspector (for logging/audit).
    fn name(&self) -> &str;

    /// Inspect a flow and return a verdict.
    ///
    /// Called when new data is available on the flow.
    /// Return `Verdict::Allow` to pass to the next inspector.
    fn inspect(&self, flow: &Flow) -> Verdict;
}

/// Pipeline of inspectors that processes flows.
pub struct InspectionPipeline {
    inspectors: Vec<Box<dyn Inspector>>,
}

impl InspectionPipeline {
    pub fn new() -> Self {
        Self {
            inspectors: Vec::new(),
        }
    }

    /// Add an inspector to the end of the pipeline.
    pub fn add_inspector(&mut self, inspector: Box<dyn Inspector>) {
        tracing::info!(name = inspector.name(), "Inspector added to pipeline");
        self.inspectors.push(inspector);
    }

    /// Run all inspectors on a flow.
    ///
    /// Returns the results from all inspectors. If any inspector blocks,
    /// it's included but the pipeline continues (caller decides precedence).
    pub fn inspect(&self, flow: &Flow) -> Vec<InspectorResult> {
        let mut results = Vec::with_capacity(self.inspectors.len());

        for inspector in &self.inspectors {
            let verdict = inspector.inspect(flow);
            let is_block = matches!(verdict, Verdict::Block { .. });

            results.push(InspectorResult {
                inspector_name: inspector.name().to_string(),
                verdict,
            });

            // Short-circuit on block
            if is_block {
                break;
            }
        }

        results
    }

    /// Run the pipeline and return the final verdict (most restrictive wins).
    pub fn evaluate(&self, flow: &Flow) -> Verdict {
        let results = self.inspect(flow);

        // Priority: Block > ShadowCopy > Alert > Allow
        let mut final_verdict = Verdict::Allow;

        for result in &results {
            match &result.verdict {
                Verdict::Block { .. } => return result.verdict.clone(),
                Verdict::ShadowCopy => {
                    if !matches!(final_verdict, Verdict::Block { .. }) {
                        final_verdict = Verdict::ShadowCopy;
                    }
                }
                Verdict::Alert { .. } => {
                    if matches!(final_verdict, Verdict::Allow) {
                        final_verdict = result.verdict.clone();
                    }
                }
                Verdict::Allow => {}
            }
        }

        final_verdict
    }

    /// Number of inspectors in the pipeline.
    pub fn inspector_count(&self) -> usize {
        self.inspectors.len()
    }
}

impl Default for InspectionPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::Severity;

    struct AllowAll;
    impl Inspector for AllowAll {
        fn name(&self) -> &str { "allow-all" }
        fn inspect(&self, _flow: &Flow) -> Verdict { Verdict::Allow }
    }

    struct BlockEverything;
    impl Inspector for BlockEverything {
        fn name(&self) -> &str { "block-all" }
        fn inspect(&self, _flow: &Flow) -> Verdict {
            Verdict::Block { reason: "blocked".to_string() }
        }
    }

    struct AlertOnLargeFlows;
    impl Inspector for AlertOnLargeFlows {
        fn name(&self) -> &str { "large-flow-alert" }
        fn inspect(&self, flow: &Flow) -> Verdict {
            if flow.total_bytes() > 1_000_000 {
                Verdict::Alert {
                    severity: Severity::Medium,
                    message: "Large data transfer detected".to_string(),
                }
            } else {
                Verdict::Allow
            }
        }
    }

    #[test]
    fn empty_pipeline_allows() {
        let pipeline = InspectionPipeline::new();
        let flow = Flow::new();
        assert_eq!(pipeline.evaluate(&flow), Verdict::Allow);
    }

    #[test]
    fn single_allow_inspector() {
        let mut pipeline = InspectionPipeline::new();
        pipeline.add_inspector(Box::new(AllowAll));
        let flow = Flow::new();
        assert_eq!(pipeline.evaluate(&flow), Verdict::Allow);
    }

    #[test]
    fn block_overrides_allow() {
        let mut pipeline = InspectionPipeline::new();
        pipeline.add_inspector(Box::new(AllowAll));
        pipeline.add_inspector(Box::new(BlockEverything));
        let flow = Flow::new();
        assert!(matches!(pipeline.evaluate(&flow), Verdict::Block { .. }));
    }

    #[test]
    fn alert_on_large_flow() {
        let mut pipeline = InspectionPipeline::new();
        pipeline.add_inspector(Box::new(AlertOnLargeFlows));

        let mut flow = Flow::new();
        flow.record_tx(2_000_000);

        assert!(matches!(pipeline.evaluate(&flow), Verdict::Alert { .. }));
    }

    #[test]
    fn small_flow_allowed() {
        let mut pipeline = InspectionPipeline::new();
        pipeline.add_inspector(Box::new(AlertOnLargeFlows));

        let mut flow = Flow::new();
        flow.record_tx(100);

        assert_eq!(pipeline.evaluate(&flow), Verdict::Allow);
    }
}
