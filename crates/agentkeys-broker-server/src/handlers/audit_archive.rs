use crate::{error::BrokerError, state::SharedState};
use agentkeys_core::{audit::AuditClient, capability_verify::eth_call};
use agentkeys_protocol::{AuditAppendV2, AuditAppendV2Resp};
use agentkeys_web_core::chain::decode_word;
use axum::{
    body::Body,
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};

pub(super) async fn operator(
    state: &SharedState,
    headers: &HeaderMap,
) -> Result<String, BrokerError> {
    let claims = super::wallet::require_master_session(headers, state)?;
    if !matches!(claims.agentkeys.identity_type.as_str(), "evm" | "passkey") {
        return Err(BrokerError::Forbidden(
            "audit archive requires an owner session".into(),
        ));
    }
    state
        .config
        .login_access
        .require_omni(state, &claims.agentkeys.omni_account)
        .await?;
    let owner = decode_word(&claims.agentkeys.omni_account)
        .map_err(|_| BrokerError::Unauthorized("invalid owner identity".into()))?;
    let (url, registry) =
        super::accept::load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
    let mut calldata =
        agentkeys_core::audit::calldata::selector("operatorMasterWallet(bytes32)").to_vec();
    calldata.extend_from_slice(&owner);
    let master = eth_call(
        &state.http,
        &url,
        &format!("0x{}", hex::encode(registry)),
        &format!("0x{}", hex::encode(calldata)),
    )
    .await
    .map_err(|_| BrokerError::BackendUnreachable("audit authority read failed".into()))?;
    let master = decode_word(&master)
        .map_err(|_| BrokerError::BackendUnreachable("invalid audit authority response".into()))?;
    let wallet = if claims.agentkeys.identity_type == "passkey" {
        &claims.agentkeys.identity_value
    } else {
        &claims.agentkeys.wallet_address
    }
    .trim_start_matches("0x");
    if master == [0; 32]
        || wallet.len() != 40
        || !hex::encode(&master[12..]).eq_ignore_ascii_case(wallet)
    {
        return Err(BrokerError::Forbidden(
            "audit owner is no longer active".into(),
        ));
    }
    Ok(format!("0x{}", hex::encode(owner)))
}
fn archive() -> Result<AuditClient, BrokerError> {
    super::console::profile()?
        .require_local_development(true, None)
        .map_err(|_| {
            BrokerError::Unavailable("local audit archive requires the development profile".into())
        })?;
    let endpoint = std::env::var("AGENTKEYS_AUDIT_WORKER_URL")
        .map_err(|_| BrokerError::Unavailable("audit archive is not configured".into()))?;
    if !agentkeys_core::chain_profile::is_loopback_http_endpoint(&endpoint) {
        return Err(BrokerError::Unavailable(
            "audit archive requires loopback transport".into(),
        ));
    }
    if std::env::var_os("AGENTKEYS_AUDIT_TOKEN_FILE").is_none() {
        return Err(BrokerError::Unavailable(
            "audit service credential is not configured".into(),
        ));
    }
    Ok(AuditClient::new(endpoint))
}
pub async fn append(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(request): Json<AuditAppendV2>,
) -> Result<Json<AuditAppendV2Resp>, BrokerError> {
    let claims = super::wallet::require_master_session(&headers, &state)?;
    let owner = if claims.agentkeys.identity_type == "agent_hdkd" {
        let actor = &claims.agentkeys.omni_account;
        let parent = claims
            .agentkeys
            .parent_omni
            .as_deref()
            .ok_or_else(|| BrokerError::Forbidden("audit actor has no parent".into()))?;
        let address = claims
            .agentkeys
            .device_pubkey
            .as_deref()
            .ok_or_else(|| BrokerError::Forbidden("audit actor has no device".into()))?;
        let hash = agentkeys_core::device_crypto::device_key_hash(address)
            .map_err(|_| BrokerError::Forbidden("invalid audit device".into()))?;
        let (rpc, registry) =
            super::accept::load_chain_read_config().map_err(BrokerError::BackendUnreachable)?;
        let device = agentkeys_core::capability_verify::get_chain_device(
            &state.http,
            &rpc,
            &format!("0x{}", hex::encode(registry)),
            &hash,
        )
        .await
        .map_err(|_| BrokerError::BackendUnreachable("audit device read failed".into()))?;
        if device.registered_at == 0
            || device.revoked
            || device.roles & agentkeys_core::capability_verify::ROLE_CAP_MINT == 0
            || decode_word(&device.actor_omni).ok() != decode_word(actor).ok()
            || decode_word(&device.operator_omni).ok() != decode_word(parent).ok()
            || decode_word(&request.actor_omni).ok() != decode_word(actor).ok()
        {
            return Err(BrokerError::Forbidden(
                "audit actor binding is inactive or mismatched".into(),
            ));
        }
        let kind = agentkeys_core::audit::AuditOpKind::from_u8(request.op_kind);
        if !matches!(
            kind,
            Some(
                agentkeys_core::audit::AuditOpKind::RuntimeToolResult
                    | agentkeys_core::audit::AuditOpKind::RuntimeApproval
                    | agentkeys_core::audit::AuditOpKind::DelegateLifecycle
            )
        ) {
            return Err(BrokerError::Forbidden(
                "audit actor cannot emit this operation kind".into(),
            ));
        }
        parent.to_owned()
    } else {
        operator(&state, &headers).await?
    };
    if decode_word(&request.operator_omni).ok() != decode_word(&owner).ok() {
        return Err(BrokerError::Forbidden(
            "audit envelope belongs to another owner".into(),
        ));
    }
    let receipt = archive()?
        .append_json(&request)
        .await
        .map_err(|_| BrokerError::BackendUnreachable("audit archive append failed".into()))?;
    Ok(Json(receipt))
}
pub async fn fetch(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(hash): Path<String>,
) -> Result<Response, BrokerError> {
    let owner = operator(&state, &headers).await?;
    match archive()?
        .get_envelope_for_operator(&hash, Some(&owner))
        .await
        .map_err(|_| BrokerError::BackendUnreachable("audit archive read failed".into()))?
    {
        Some(bytes) => {
            Ok(([("content-type", "application/cbor")], Body::from(bytes)).into_response())
        }
        None => Ok((
            axum::http::StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error":"audit_envelope_not_found"})),
        )
            .into_response()),
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}
pub async fn list(
    State(state): State<SharedState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<ListQuery>,
) -> Result<Json<agentkeys_protocol::AuditArchivePage>, BrokerError> {
    let owner = operator(&state, &headers).await?;
    if query.limit.is_some_and(|limit| limit == 0 || limit > 100)
        || query
            .cursor
            .as_deref()
            .is_some_and(|cursor| decode_word(cursor).is_err())
    {
        return Err(BrokerError::BadRequest(
            "invalid audit page selection".into(),
        ));
    }
    Ok(Json(
        archive()?
            .list_envelopes(
                Some(&owner),
                query.cursor.as_deref(),
                query.limit.unwrap_or(20),
            )
            .await
            .map_err(|_| BrokerError::BackendUnreachable("audit index read failed".into()))?,
    ))
}
