use crate::ui_bridge::SharedUiBridgeState;
use agentkeys_backend_client::protocol::hosted_signer::{
    HostedSignerApproval, HostedSignerBuildRequest,
};
use agentkeys_backend_client::protocol::SubmitAcceptUserOpRequest;
use agentkeys_web_core::broker::{BrokerClient, BrokerError};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

fn error(error: BrokerError) -> Response {
    let status = match &error {
        BrokerError::Rejected { status, .. } => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        _ => StatusCode::BAD_GATEWAY,
    };
    (status, Json(serde_json::json!({"error":error.to_string()}))).into_response()
}
async fn context(state: &SharedUiBridgeState) -> Result<(BrokerClient, String), Response> {
    let broker = state.broker_url.as_deref().ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error":"broker is not configured"})),
        )
            .into_response()
    })?;
    let held = state.onboarding_session.read().await;
    let session = held
        .as_ref()
        .filter(|session| !session.j1.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"Sign in on this original console first."})),
            )
                .into_response()
        })?;
    Ok((BrokerClient::new(broker), session.j1.clone()))
}
pub async fn prepare(
    State(state): State<SharedUiBridgeState>,
    Json(request): Json<HostedSignerApproval>,
) -> Response {
    let (broker, session) = match context(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match broker.hosted_signer_prepare(&session, &request).await {
        Ok(response) => Json(response).into_response(),
        Err(failure) => error(failure),
    }
}
pub async fn build(
    State(state): State<SharedUiBridgeState>,
    Json(request): Json<HostedSignerBuildRequest>,
) -> Response {
    let (broker, session) = match context(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match broker.hosted_signer_build(&session, &request).await {
        Ok(response) => Json(response).into_response(),
        Err(failure) => error(failure),
    }
}
pub async fn submit(
    State(state): State<SharedUiBridgeState>,
    Json(request): Json<SubmitAcceptUserOpRequest>,
) -> Response {
    let (broker, session) = match context(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match broker.hosted_signer_submit(&session, &request).await {
        Ok(response) => Json(response).into_response(),
        Err(failure) => error(failure),
    }
}

pub async fn pending(State(state): State<SharedUiBridgeState>) -> Response {
    let (broker, session) = match context(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match broker.hosted_signer_pending(&session).await {
        Ok(response) => Json(response).into_response(),
        Err(failure) => error(failure),
    }
}
pub async fn dismiss(
    State(state): State<SharedUiBridgeState>,
    Json(request): Json<agentkeys_backend_client::protocol::hosted_signer::HostedSignerRequestId>,
) -> Response {
    let (broker, session) = match context(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };
    match broker.hosted_signer_dismiss(&session, &request).await {
        Ok(response) => Json(response).into_response(),
        Err(failure) => error(failure),
    }
}
