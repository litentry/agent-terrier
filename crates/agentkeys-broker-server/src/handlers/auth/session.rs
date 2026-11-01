use crate::{error::BrokerError, state::SharedState};
use agentkeys_protocol::auth::MasterSessionInfo;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};

pub(crate) fn signer_url(state: &SharedState) -> Result<String, BrokerError> {
    state
        .config
        .login_config
        .as_ref()
        .map(|config| config.signer_url.clone())
        .ok_or_else(|| BrokerError::BackendUnreachable("browser login is not configured".into()))
}

pub async fn login_config(
    State(state): State<SharedState>,
) -> Result<impl IntoResponse, BrokerError> {
    let mut config =
        state.config.login_config.clone().ok_or_else(|| {
            BrokerError::BackendUnreachable("browser login is not configured".into())
        })?;
    config.email_allowlist_enabled = state.config.login_access.is_restricted();
    Ok(([("cache-control", "no-store")], Json(config)))
}

pub async fn session_info(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, BrokerError> {
    let claims = crate::handlers::wallet::require_master_session(&headers, &state)?;
    let identity = claims.agentkeys;
    if identity.identity_type != "evm" && identity.identity_type != "passkey" {
        return Err(BrokerError::Unauthorized(
            "complete wallet verification before using the master session".into(),
        ));
    }
    state
        .config
        .login_access
        .require_omni(&state, &identity.omni_account)
        .await?;
    Ok((
        StatusCode::OK,
        [("cache-control", "no-store")],
        Json(MasterSessionInfo {
            omni_account: identity.omni_account,
            wallet_address: identity.wallet_address,
            expires_at: claims.exp,
        }),
    ))
}
