//! HTTP surface for the email-service worker.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use aws_sdk_sesv2::types::{Body, Content, Destination, EmailContent, Message};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;

#[derive(Deserialize)]
pub struct SendRequest {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body_text: String,
    /// Optional HTML body alongside text.
    #[serde(default)]
    pub body_html: Option<String>,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub ok: bool,
    pub message_id: String,
}

/// POST /v1/email/send — wrap aws-sdk-sesv2 SendEmail.
///
/// The operator must have verified `from` in SES first (per #83's setup
/// workflow). Per-actor outbound SES identities should be pre-provisioned.
pub async fn send(
    State(state): State<SharedState>,
    Json(req): Json<SendRequest>,
) -> Result<Json<SendResponse>, (StatusCode, String)> {
    let body = if let Some(html) = req.body_html {
        Body::builder()
            .text(Content::builder().data(req.body_text).build().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?)
            .html(Content::builder().data(html).build().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?)
            .build()
    } else {
        Body::builder()
            .text(Content::builder().data(req.body_text).build().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?)
            .build()
    };
    let message = Message::builder()
        .subject(Content::builder().data(req.subject).build().map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?)
        .body(body)
        .build();
    let content = EmailContent::builder().simple(message).build();
    let destination = Destination::builder().set_to_addresses(Some(req.to)).build();

    let out = state
        .ses
        .send_email()
        .from_email_address(req.from)
        .destination(destination)
        .content(content)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("SES SendEmail: {e}")))?;

    let message_id = out.message_id().unwrap_or_default().to_string();
    Ok(Json(SendResponse { ok: true, message_id }))
}

#[derive(Serialize)]
pub struct InboxEntry {
    pub key: String,
    pub size: i64,
    pub last_modified: String,
}

#[derive(Serialize)]
pub struct InboxResponse {
    pub ok: bool,
    pub actor_omni: String,
    pub bucket: String,
    pub prefix: String,
    pub entries: Vec<InboxEntry>,
}

/// GET /v1/email/inbox/:actor_omni — list the actor's per-actor SES inbox.
///
/// Prefix scheme: `bots/<actor_omni_hex>/inbound/`. The actual inbound
/// routing is done by the SES routing Lambda from #83; this worker only
/// surfaces what's already been delivered.
pub async fn inbox(
    State(state): State<SharedState>,
    Path(actor_omni): Path<String>,
) -> Result<Json<InboxResponse>, (StatusCode, String)> {
    let omni_hex = actor_omni.trim_start_matches("0x").to_lowercase();
    if omni_hex.len() != 64 || !omni_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("actor_omni must be 0x + 64 hex; got {actor_omni}"),
        ));
    }
    let prefix = format!("bots/{omni_hex}/inbound/");

    let out = state
        .s3
        .list_objects_v2()
        .bucket(&state.inbox_bucket)
        .prefix(&prefix)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("S3 ListObjects: {e}")))?;

    let entries: Vec<InboxEntry> = out
        .contents()
        .iter()
        .map(|obj| InboxEntry {
            key: obj.key().unwrap_or_default().to_string(),
            size: obj.size().unwrap_or(0),
            last_modified: obj
                .last_modified()
                .map(|t| t.to_string())
                .unwrap_or_default(),
        })
        .collect();

    Ok(Json(InboxResponse {
        ok: true,
        actor_omni: format!("0x{omni_hex}"),
        bucket: state.inbox_bucket.clone(),
        prefix,
        entries,
    }))
}
