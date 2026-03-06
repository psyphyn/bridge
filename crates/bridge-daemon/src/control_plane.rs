//! Control plane client.
//!
//! Handles communication with the Bridge control plane API:
//! device registration, posture reporting, heartbeat.

use bridge_core::api_types::{
    DeviceRegistrationRequest, DeviceRegistrationResponse, HeartbeatRequest, HeartbeatResponse,
    PostureReportRequest, PostureReportResponse,
};
use uuid::Uuid;

/// Client for the Bridge control plane API.
pub struct ControlPlaneClient {
    http: reqwest::Client,
    base_url: String,
    device_id: Option<Uuid>,
}

impl ControlPlaneClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.trim_end_matches('/').to_string(),
            device_id: None,
        }
    }

    pub fn device_id(&self) -> Option<Uuid> {
        self.device_id
    }

    /// Register this device with the control plane.
    pub async fn register(
        &mut self,
        req: DeviceRegistrationRequest,
    ) -> anyhow::Result<DeviceRegistrationResponse> {
        let url = format!("{}/api/v1/devices/register", self.base_url);

        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json::<DeviceRegistrationResponse>()
            .await?;

        self.device_id = Some(resp.device_id);
        tracing::info!(device_id = %resp.device_id, "Registered with control plane");

        Ok(resp)
    }

    /// Submit a posture report.
    pub async fn report_posture(
        &self,
        req: PostureReportRequest,
    ) -> anyhow::Result<PostureReportResponse> {
        let url = format!("{}/api/v1/devices/posture", self.base_url);

        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await?
            .error_for_status()?
            .json::<PostureReportResponse>()
            .await?;

        tracing::info!(
            score = resp.posture_score,
            tier = %resp.access_tier,
            "Posture report accepted"
        );

        Ok(resp)
    }

    /// Send a heartbeat.
    pub async fn heartbeat(
        &self,
        active_tunnels: u32,
        uptime_secs: u64,
    ) -> anyhow::Result<HeartbeatResponse> {
        let device_id = self
            .device_id
            .ok_or_else(|| anyhow::anyhow!("Not registered"))?;

        let url = format!("{}/api/v1/devices/heartbeat", self.base_url);

        let resp = self
            .http
            .post(&url)
            .json(&HeartbeatRequest {
                device_id,
                active_tunnels,
                uptime_secs,
            })
            .send()
            .await?
            .error_for_status()?
            .json::<HeartbeatResponse>()
            .await?;

        Ok(resp)
    }
}
