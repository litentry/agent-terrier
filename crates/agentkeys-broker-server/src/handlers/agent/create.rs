//! `POST /v1/agent/create` — master mints a one-time link code (issue #144 §10.2).
//!
//! Gated by the master's `J1` session bearer. Derives the HDKD child omni
//! `O_agent = SHA256(HDKD_DOMAIN || O_master || "//label")`, mints a single-use
//! link code bound to it (TTL 600s), and records the scope the master wants the
//! agent to have (like an app manifest). The master hands the code to the agent
//! out-of-band; the agent redeems it at `/v1/auth/link-code/redeem`.

use axum::{extract::State, http::HeaderMap, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::handlers::agent::unix_now;
use crate::handlers::grant::{random_b64url, require_session_jwt};
use crate::state::SharedState;
use crate::storage::LINK_CODE_TTL_SECONDS;

#[derive(Debug, Deserialize)]
pub struct AgentCreateBody {
    /// HDKD child label, e.g. `"agent-a"` (`^[a-z0-9-]{1,32}$`).
    pub label: String,
    /// Scope the master intends to grant the agent (the "app manifest").
    /// Defaults to `"memory"`. Comma-separated service list mirrors
    /// `heima-scope-set.sh --services`.
    #[serde(default)]
    pub requested_scope: Option<String>,
}

pub async fn agent_create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<AgentCreateBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let session = require_session_jwt(&headers, &state)?;
    let master_omni = session.agentkeys.omni_account;

    agentkeys_core::actor_omni::validate_label(&body.label)
        .map_err(|e| BrokerError::BadRequest(format!("invalid label: {e}")))?;
    let child_omni = agentkeys_core::actor_omni::child_omni_hex(&master_omni, &body.label)
        .map_err(|e| BrokerError::BadRequest(format!("derive child omni: {e}")))?;

    let requested_scope = body
        .requested_scope
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "memory".to_string());

    let link_code = random_b64url(32);
    let now = unix_now()?;
    let expires_at = now + LINK_CODE_TTL_SECONDS;
    state.link_code_store.issue(
        &link_code,
        &child_omni,
        &master_omni,
        &body.label,
        &requested_scope,
        now,
        expires_at,
    )?;

    tracing::info!(
        operator_omni = %master_omni,
        child_omni = %child_omni,
        label = %body.label,
        "issued §10.2 agent link code"
    );

    Ok((
        StatusCode::OK,
        Json(json!({
            "link_code": link_code,
            "child_omni": child_omni,
            "operator_omni": master_omni,
            "label": body.label,
            "requested_scope": requested_scope,
            "expires_at": expires_at,
        })),
    ))
}
