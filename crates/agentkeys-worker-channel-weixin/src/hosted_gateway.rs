use agentkeys_protocol::{auth::MasterSessionInfo, hosted_gateway::HostedGatewayRequest};
use axum::{
    extract::{Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use std::time::Duration;

use crate::{admin, state::SharedWeixinGatewayState};

const SESSION_VERIFICATION_TIMEOUT_SECS: u64 = 15;

fn refusal(status: StatusCode, reason: &str) -> Response {
    (status, Json(json!({"ok": false, "reason": reason}))).into_response()
}

fn same_omni(left: &str, right: &str) -> bool {
    match (
        crate::relay::decode_omni_32(left),
        crate::relay::decode_omni_32(right),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

async fn authenticate_owner(
    state: &SharedWeixinGatewayState,
    headers: &HeaderMap,
) -> Result<String, Response> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| refusal(StatusCode::UNAUTHORIZED, "master_session_required"))?;
    let broker_url = state.device.broker_url().ok_or_else(|| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_broker_not_configured",
        )
    })?;
    let session_response = state
        .http
        .get(format!(
            "{}/v1/auth/session",
            broker_url.trim_end_matches('/')
        ))
        .bearer_auth(token)
        .timeout(Duration::from_secs(SESSION_VERIFICATION_TIMEOUT_SECS))
        .send()
        .await
        .map_err(|_| {
            refusal(
                StatusCode::BAD_GATEWAY,
                "master_session_verification_unavailable",
            )
        })?;
    if !session_response.status().is_success() {
        return Err(refusal(
            if session_response.status().as_u16() == 403 {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::UNAUTHORIZED
            },
            "master_session_refused",
        ));
    }
    let session: MasterSessionInfo = session_response
        .json()
        .await
        .map_err(|_| refusal(StatusCode::BAD_GATEWAY, "master_session_response_invalid"))?;
    if session.expires_at <= crate::relay::unix_secs()
        || crate::relay::decode_omni_32(&session.omni_account).is_none()
    {
        return Err(refusal(StatusCode::UNAUTHORIZED, "master_session_invalid"));
    }
    let actor_omni = state
        .device
        .actor_omni()
        .ok_or_else(|| refusal(StatusCode::CONFLICT, "gateway_not_enrolled"))?;
    let device_key_hash = state
        .device
        .device_key_hash()
        .ok_or_else(|| refusal(StatusCode::CONFLICT, "gateway_not_enrolled"))?;
    let device_config = state.device.cfg();
    let rpc_url = device_config.chain_rpc_http.as_deref().ok_or_else(|| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_chain_not_configured",
        )
    })?;
    let registry = device_config.registry_contract.as_deref().ok_or_else(|| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "gateway_chain_not_configured",
        )
    })?;
    let binding = agentkeys_worker_creds::verify::get_chain_device(
        &state.http,
        rpc_url,
        registry,
        &device_key_hash,
    )
    .await
    .map_err(|_| refusal(StatusCode::BAD_GATEWAY, "gateway_chain_verification_failed"))?;
    if binding.registered_at == 0 || binding.revoked || !same_omni(&binding.actor_omni, &actor_omni)
    {
        return Err(refusal(StatusCode::FORBIDDEN, "gateway_binding_inactive"));
    }
    if !same_omni(&binding.operator_omni, &session.omni_account) {
        return Err(refusal(StatusCode::FORBIDDEN, "gateway_operator_mismatch"));
    }
    let armed_owner = state.effective_operator_omni();
    if crate::relay::decode_omni_32(&armed_owner).is_some()
        && !same_omni(&armed_owner, &session.omni_account)
    {
        return Err(refusal(StatusCode::FORBIDDEN, "gateway_operator_mismatch"));
    }
    Ok(session.omni_account)
}

pub(crate) async fn console(
    State(state): State<SharedWeixinGatewayState>,
    headers: HeaderMap,
    Json(request): Json<HostedGatewayRequest>,
) -> Response {
    let operator_omni = match authenticate_owner(&state, &headers).await {
        Ok(owner) => owner,
        Err(response) => return response,
    };
    if matches!(
        request,
        HostedGatewayRequest::LoginStatus { .. } | HostedGatewayRequest::LoginVerify(_)
    ) {
        let login = state.admin_login.lock().await;
        if let Some(login) = login.as_ref() {
            if !login
                .operator_omni
                .as_deref()
                .is_some_and(|owner| same_omni(owner, &operator_omni))
            {
                return refusal(StatusCode::FORBIDDEN, "gateway_login_operator_mismatch");
            }
        }
    }
    let Some(admin_token) = state.config.admin_token.as_deref() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "admin_disabled");
    };
    let Ok(internal_authorization) = format!("Bearer {admin_token}").parse() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "admin_disabled");
    };
    let mut internal_headers = HeaderMap::new();
    internal_headers.insert(AUTHORIZATION, internal_authorization);
    let state = State(state);
    let mut response = match request {
        HostedGatewayRequest::Status => admin::admin_status(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::DeviceStatus => admin::device_status(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::Contacts => admin::admin_contacts(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::Channels => admin::channels_list(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::BindPending => admin::bind_pending(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::Router => admin::router_view(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::Monitor { after } => admin::monitor(
            state,
            internal_headers,
            Query(admin::MonitorQuery { after }),
        )
        .await
        .into_response(),
        HostedGatewayRequest::History(page) => admin::history(
            state,
            internal_headers,
            Query(admin::HistoryQuery {
                before: page.before,
                limit: page.limit,
            }),
        )
        .await
        .into_response(),
        HostedGatewayRequest::Activity(page) => admin::activity(
            state,
            internal_headers,
            Query(admin::HistoryQuery {
                before: page.before,
                limit: page.limit,
            }),
        )
        .await
        .into_response(),
        HostedGatewayRequest::LoginStart(request) => admin::login_start(
            state,
            internal_headers,
            Some(Json(agentkeys_protocol::GatewayLoginStartRequest {
                operator_omni: Some(operator_omni),
                contact_id: request.contact_id,
            })),
        )
        .await
        .into_response(),
        HostedGatewayRequest::LoginStatus { login_id } => admin::login_status(
            state,
            internal_headers,
            Query(admin::LoginStatusQuery { login_id }),
        )
        .await
        .into_response(),
        HostedGatewayRequest::LoginVerify(request) => {
            admin::login_verify(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::LoginDisconnect => admin::login_disconnect(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::BindInvite(request) => {
            admin::bind_invite(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::BindApprove(request) => {
            admin::bind_approve(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::BindReject(request) => {
            admin::bind_reject(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::ContactsUpdate(request) => {
            admin::contacts_update(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::ContactsRevoke(request) => {
            admin::contacts_revoke(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::ContactsWelcome(request) => {
            admin::contacts_welcome(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::ChannelsUpdate(request) => {
            admin::channels_update(state, internal_headers, Json(*request))
                .await
                .into_response()
        }
        HostedGatewayRequest::RouterSettings(request) => {
            admin::router_settings(state, internal_headers, Json(request))
                .await
                .into_response()
        }
        HostedGatewayRequest::RegistryExport => admin::registry_export(state, internal_headers)
            .await
            .into_response(),
        HostedGatewayRequest::RegistryRestore { registry } => admin::registry_import(
            state,
            internal_headers,
            Json(admin::RegistryImportRequest {
                registry: *registry,
                force: false,
            }),
        )
        .await
        .into_response(),
    };
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        "no-store".parse().expect("static header"),
    );
    response
}
