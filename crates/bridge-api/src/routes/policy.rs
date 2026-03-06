//! Policy management endpoints.
//!
//! CRUD for policy sets that control per-app traffic decisions.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use bridge_core::policy::{Action, Condition, PolicyRule, PolicySet};

use crate::state::AppState;

/// API representation of a policy set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicySetResponse {
    pub name: String,
    pub default_action: Action,
    pub rules: Vec<PolicyRule>,
}

impl From<PolicySet> for PolicySetResponse {
    fn from(ps: PolicySet) -> Self {
        Self {
            name: ps.name,
            default_action: ps.default_action,
            rules: ps.rules,
        }
    }
}

/// Request to create or update a policy set.
#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub default_action: Option<Action>,
    pub rules: Vec<PolicyRule>,
}

/// Request to add a single rule to an existing policy.
#[derive(Debug, Deserialize)]
pub struct AddRuleRequest {
    pub policy_name: String,
    pub rule: PolicyRule,
}

/// List all policy sets.
pub async fn list_policies(
    State(state): State<AppState>,
) -> Json<Vec<PolicySetResponse>> {
    let policies = state.policies.read().await;
    let result: Vec<PolicySetResponse> = policies
        .values()
        .cloned()
        .map(PolicySetResponse::from)
        .collect();
    Json(result)
}

/// Get a specific policy set by name.
pub async fn get_policy(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Result<Json<PolicySetResponse>, StatusCode> {
    let policies = state.policies.read().await;
    policies
        .get(&name)
        .cloned()
        .map(|ps| Json(PolicySetResponse::from(ps)))
        .ok_or(StatusCode::NOT_FOUND)
}

/// Create or update a policy set.
pub async fn upsert_policy(
    State(state): State<AppState>,
    Json(req): Json<CreatePolicyRequest>,
) -> (StatusCode, Json<PolicySetResponse>) {
    let policy = PolicySet {
        name: req.name.clone(),
        default_action: req.default_action.unwrap_or(Action::Allow),
        rules: req.rules,
    };

    let response = PolicySetResponse::from(policy.clone());
    let mut policies = state.policies.write().await;
    let is_new = !policies.contains_key(&req.name);
    policies.insert(req.name, policy);

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };

    (status, Json(response))
}

/// Delete a policy set by name.
pub async fn delete_policy(
    State(state): State<AppState>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> StatusCode {
    let mut policies = state.policies.write().await;
    if policies.remove(&name).is_some() {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::NOT_FOUND
    }
}

/// Add a rule to an existing policy set.
pub async fn add_rule(
    State(state): State<AppState>,
    Json(req): Json<AddRuleRequest>,
) -> Result<Json<PolicySetResponse>, StatusCode> {
    let mut policies = state.policies.write().await;
    let policy = policies
        .get_mut(&req.policy_name)
        .ok_or(StatusCode::NOT_FOUND)?;

    policy.rules.push(req.rule);
    Ok(Json(PolicySetResponse::from(policy.clone())))
}

/// Evaluate a policy against a test context (for admin testing/preview).
#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    pub policy_name: String,
    pub context: bridge_core::policy::PolicyContext,
}

#[derive(Debug, Serialize)]
pub struct EvaluateResponse {
    pub action: Action,
    pub matched_rule: Option<String>,
}

pub async fn evaluate_policy(
    State(state): State<AppState>,
    Json(req): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, StatusCode> {
    let policies = state.policies.read().await;
    let policy = policies
        .get(&req.policy_name)
        .ok_or(StatusCode::NOT_FOUND)?;

    let decision = bridge_core::policy::evaluate(policy, &req.context);

    Ok(Json(EvaluateResponse {
        action: decision.action,
        matched_rule: decision.matched_rule,
    }))
}
