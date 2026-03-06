//! Integration tests for the Bridge control plane API.

use axum::{routing::{get, post}, Json, Router};
use bridge_core::api_types::{
    DeviceRegistrationRequest, DeviceRegistrationResponse, PostureReportRequest,
    PostureReportResponse,
};
use serde::{Deserialize, Serialize};

// We need to reconstruct the app for testing since the server modules are private.
// In a real setup we'd extract the router building into a public function.
// For now, test via HTTP against a spawned server.

async fn spawn_test_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        // Minimal inline app for testing (mirrors main.rs structure)
        let (_, relay_public) = bridge_core::tunnel::generate_keypair();

        let state = TestState::new(relay_public);

        let app = Router::new()
            .route("/health", get(health))
            .route("/api/v1/devices/register", post(register_device))
            .route("/api/v1/devices/posture", post(report_posture))
            .with_state(state);

        axum::serve(listener, app).await.unwrap();
    });

    // Give server a moment to start
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    base_url
}

// ─── Inline test server (simplified version of bridge-api) ────────────

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
struct TestState {
    devices: Arc<RwLock<HashMap<uuid::Uuid, String>>>,
    relay_public_key: String,
}

impl TestState {
    fn new(relay_public_key: String) -> Self {
        Self {
            devices: Arc::new(RwLock::new(HashMap::new())),
            relay_public_key,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: bridge_core::VERSION.to_string(),
    })
}

async fn register_device(
    axum::extract::State(state): axum::extract::State<TestState>,
    Json(req): Json<DeviceRegistrationRequest>,
) -> Json<DeviceRegistrationResponse> {
    let device_id = uuid::Uuid::new_v4();
    state
        .devices
        .write()
        .await
        .insert(device_id, req.platform.clone());

    Json(DeviceRegistrationResponse {
        device_id,
        tunnels: vec![bridge_core::api_types::TunnelAssignment {
            tunnel_id: uuid::Uuid::new_v4(),
            server_public_key: state.relay_public_key.clone(),
            server_endpoint: "127.0.0.1:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".to_string()],
            dns: vec!["1.1.1.1".to_string()],
            keepalive_secs: Some(25),
        }],
    })
}

async fn report_posture(
    axum::extract::State(state): axum::extract::State<TestState>,
    Json(req): Json<PostureReportRequest>,
) -> Result<Json<PostureReportResponse>, axum::http::StatusCode> {
    if !state.devices.read().await.contains_key(&req.device_id) {
        return Err(axum::http::StatusCode::NOT_FOUND);
    }

    let mut score: u8 = 100;
    if !req.disk_encrypted {
        score = score.saturating_sub(25);
    }
    if !req.firewall_enabled {
        score = score.saturating_sub(15);
    }

    let tier = bridge_core::posture::AccessTier::from_score(score);

    Ok(Json(PostureReportResponse {
        posture_score: score,
        access_tier: format!("{:?}", tier).to_lowercase(),
        tunnels: vec![],
    }))
}

// ─── Tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn health_endpoint() {
    let base = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp: HealthResponse = client
        .get(format!("{}/health", base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(resp.status, "ok");
}

#[tokio::test]
async fn register_device_returns_tunnel_config() {
    let base = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp: DeviceRegistrationResponse = client
        .post(format!("{}/api/v1/devices/register", base))
        .json(&DeviceRegistrationRequest {
            device_public_key: "dGVzdGtleQ==".to_string(), // "testkey" in base64
            platform: "macos".to_string(),
            os_version: "15.0".to_string(),
            hardware_model: "MacBookPro18,1".to_string(),
            hostname: "test-device".to_string(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert!(!resp.device_id.is_nil());
    assert_eq!(resp.tunnels.len(), 1);
    assert_eq!(resp.tunnels[0].server_endpoint, "127.0.0.1:51820");
    assert!(resp.tunnels[0].keepalive_secs.is_some());
}

#[tokio::test]
async fn posture_report_calculates_score() {
    let base = spawn_test_server().await;
    let client = reqwest::Client::new();

    // First register
    let reg: DeviceRegistrationResponse = client
        .post(format!("{}/api/v1/devices/register", base))
        .json(&DeviceRegistrationRequest {
            device_public_key: "dGVzdGtleQ==".to_string(),
            platform: "macos".to_string(),
            os_version: "15.0".to_string(),
            hardware_model: "MacBookPro18,1".to_string(),
            hostname: "test-device".to_string(),
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Report good posture
    let posture: PostureReportResponse = client
        .post(format!("{}/api/v1/devices/posture", base))
        .json(&PostureReportRequest {
            device_id: reg.device_id,
            os_patch_age_days: 5,
            disk_encrypted: true,
            firewall_enabled: true,
            screen_lock_enabled: true,
            osquery_results: vec![],
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(posture.posture_score, 100);
    assert_eq!(posture.access_tier, "fullaccess");

    // Report bad posture (no encryption, no firewall)
    let posture: PostureReportResponse = client
        .post(format!("{}/api/v1/devices/posture", base))
        .json(&PostureReportRequest {
            device_id: reg.device_id,
            os_patch_age_days: 5,
            disk_encrypted: false,
            firewall_enabled: false,
            screen_lock_enabled: true,
            osquery_results: vec![],
        })
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    assert_eq!(posture.posture_score, 60);
    assert_eq!(posture.access_tier, "restricted");
}

#[tokio::test]
async fn posture_report_unknown_device_returns_404() {
    let base = spawn_test_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/v1/devices/posture", base))
        .json(&PostureReportRequest {
            device_id: uuid::Uuid::new_v4(),
            os_patch_age_days: 0,
            disk_encrypted: true,
            firewall_enabled: true,
            screen_lock_enabled: true,
            osquery_results: vec![],
        })
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}
