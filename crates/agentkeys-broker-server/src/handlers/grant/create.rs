//! `POST /v1/grant/create` — Phase B, US-026.
//!
//! Master OmniAccount authorizes a daemon to mint AWS credentials for a
//! specific (service, scope_path), bounded by expires_at + max_uses.
//! Returns `grant_id` + `audit_proof` (ES256-signed JWT over the canonical
//! grant content; tampering with the SQLite row breaks audit_proof
//! verification — DB exfiltration cannot produce a verified-but-tampered
//! grant).

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::json;

use crate::error::BrokerError;
use crate::jwt::issue::mint_grant_audit_proof;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct GrantCreateBody {
    /// EVM address (0x-prefixed, lowercase) of the daemon being granted
    /// permission. The mint flow consults the active grant for
    /// `(master_omni, daemon_address, service)`.
    pub daemon_address: String,
    /// AWS service the grant authorizes (e.g. `"s3"`).
    pub service: String,
    /// Resource path scope (e.g. `"bots/0xdaemon/"`).
    pub scope_path: String,
    /// Unix-seconds when the grant becomes invalid.
    pub expires_at: i64,
    /// Maximum number of mint calls this grant authorizes. Plan §3.5.5
    /// recommends bounding to defeat key-leak amplification.
    pub max_uses: i64,
}

pub async fn grant_create(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<GrantCreateBody>,
) -> Result<impl IntoResponse, BrokerError> {
    let session = super::require_session_jwt(&headers, &state)?;
    let master = session.agentkeys.omni_account;

    if body.daemon_address.is_empty()
        || !body.daemon_address.starts_with("0x")
        || body.daemon_address.len() < 6
    {
        return Err(BrokerError::BadRequest(
            "daemon_address must be a 0x-prefixed address".into(),
        ));
    }
    if body.service.is_empty() || body.scope_path.is_empty() {
        return Err(BrokerError::BadRequest(
            "service + scope_path must be non-empty".into(),
        ));
    }
    if body.max_uses < 1 {
        return Err(BrokerError::BadRequest("max_uses must be >= 1".into()));
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if body.expires_at <= now {
        return Err(BrokerError::BadRequest(format!(
            "expires_at ({}) must be in the future (now={})",
            body.expires_at, now
        )));
    }

    let grant_id = format!("grn-{}", crate::handlers::grant::random_b64url(12));

    // Mint audit_proof: ES256-signed JWT carrying the canonical grant
    // content. Verifying audit_proof requires the broker's session
    // pubkey + an untampered SQLite row (every field of the grant is
    // checked against the JWT claims).
    let audit_proof = mint_grant_audit_proof(
        &state.session_keypair,
        &state.config.oidc_issuer,
        &grant_id,
        &master,
        &body.daemon_address,
        &body.service,
        &body.scope_path,
        now,
        body.expires_at,
        body.max_uses,
    )?;

    state
        .grant_store
        .create(
            &grant_id,
            &master,
            &body.daemon_address,
            &body.service,
            &body.scope_path,
            now,
            body.expires_at,
            body.max_uses,
            &audit_proof,
        )
        .map_err(|e| BrokerError::Internal(format!("create grant: {}", e)))?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "grant_id":     grant_id,
            "audit_proof":  audit_proof,
            "granted_at":   now,
            "expires_at":   body.expires_at,
            "max_uses":     body.max_uses,
        })),
    ))
}
