//! HTTP + stdio transports.
//!
//! HTTP transport:
//!   - POST /mcp        — JSON-RPC request, returns JSON-RPC response
//!   - GET  /healthz    — liveness
//!   - Auth: Bearer (vendor) + X-AgentKeys-Actor (actor binding)
//!
//! Stdio transport:
//!   - Reads newline-framed JSON-RPC requests from stdin.
//!   - Writes newline-framed responses to stdout.
//!   - No auth; parent process is implicitly trusted.

use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::auth::{check_actor_header, check_bearer, CallerContext};
use crate::mcp::Request;
use crate::server::Server;

pub fn http_router(server: Arc<Server>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/mcp", post(handle_mcp))
        .with_state(server)
}

async fn healthz() -> impl IntoResponse {
    axum::Json(serde_json::json!({"ok": true, "name": crate::mcp::MCP_SERVER_NAME}))
}

async fn handle_mcp(
    State(server): State<Arc<Server>>,
    headers: HeaderMap,
    Json(req): Json<Request>,
) -> impl IntoResponse {
    let req_id = req.id.clone();

    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let vendor_id = match check_bearer(&server.config, auth_header) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::UNAUTHORIZED,
                axum::Json(e.into_response(req_id)),
            )
                .into_response();
        }
    };

    let actor_header = headers
        .get("x-agentkeys-actor")
        .and_then(|v| v.to_str().ok());
    let actor_omni = match check_actor_header(actor_header) {
        Ok(a) => a,
        Err(e) => {
            return (StatusCode::FORBIDDEN, axum::Json(e.into_response(req_id))).into_response();
        }
    };

    let caller = CallerContext::new(vendor_id, actor_omni);

    let session_bearer = headers
        .get("x-agentkeys-session-bearer")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let resp = server.dispatch(&caller, session_bearer, req).await;
    (StatusCode::OK, axum::Json(resp)).into_response()
}

/// Read newline-framed JSON-RPC requests from `stdin`, dispatch them, and
/// write newline-framed responses to `stdout`.
pub async fn run_stdio(server: Arc<Server>) -> anyhow::Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin).lines();

    let caller = CallerContext::local_stdio();

    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }

        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = crate::mcp::Response::error(
                    None,
                    crate::mcp::codes::PARSE_ERROR,
                    format!("parse error: {e}"),
                );
                stdout
                    .write_all(serde_json::to_string(&resp)?.as_bytes())
                    .await?;
                stdout.write_all(b"\n").await?;
                stdout.flush().await?;
                continue;
            }
        };

        // MCP notifications (no `id`) get no response — same rule as the
        // mcp-endpoint transport. Without this, Claude Desktop /
        // Claude Code's stdio MCP client sees an unexpected response
        // to `notifications/initialized` and disconnects.
        let is_notification = req.id.is_none();
        let resp = server.dispatch(&caller, "", req).await;
        if is_notification {
            continue;
        }
        stdout
            .write_all(serde_json::to_string(&resp)?.as_bytes())
            .await?;
        stdout.write_all(b"\n").await?;
        stdout.flush().await?;
    }
    Ok(())
}

/// xiaozhi MCP-endpoint relay transport.
///
/// Connects out to a relay URL of the form
/// `ws[s]://host:port/mcp_endpoint/mcp/?token=...`. The relay forwards
/// MCP JSON-RPC frames between this server (acting as the tool) and
/// the xiaozhi-server / xiaozhi cloud (acting as the client). No
/// firmware on the xiaozhi device needs to change — the relay is the
/// integration point.
///
/// Wire format is identical to the stdio transport: one JSON-RPC
/// message per WebSocket text frame. The token in the URL authenticates
/// the tool side; no per-call Bearer + actor headers (the xiaozhi cloud
/// sets the binding via the token + agent config).
///
/// Auto-reconnects with exponential backoff (mirrors xiaozhi's own
/// `mcp_pipe.py`: 1s → 600s).
pub async fn run_mcp_endpoint(server: std::sync::Arc<Server>, url: String) -> anyhow::Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let caller = CallerContext::local_stdio();
    let mut backoff_secs: u64 = 1;
    const MAX_BACKOFF_SECS: u64 = 600;
    let redacted = redact_url(&url);

    loop {
        tracing::info!(url = %redacted, "mcp-endpoint: connecting");
        let conn = match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _resp)) => ws,
            Err(e) => {
                tracing::warn!(error = %e, backoff_secs, "mcp-endpoint: connect failed; backing off");
                tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                continue;
            }
        };
        tracing::info!("mcp-endpoint: connected; awaiting MCP frames");
        backoff_secs = 1;

        let (mut write, mut read) = conn.split();

        while let Some(frame) = read.next().await {
            let frame = match frame {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(error = %e, "mcp-endpoint: read error; will reconnect");
                    break;
                }
            };

            let text = match frame {
                Message::Text(t) => t,
                Message::Close(_) => {
                    tracing::info!("mcp-endpoint: relay closed connection");
                    break;
                }
                Message::Ping(payload) => {
                    let _ = write.send(Message::Pong(payload)).await;
                    continue;
                }
                _ => continue,
            };

            tracing::debug!(frame = %truncate(&text, 400), "mcp-endpoint: recv");

            let req: crate::mcp::Request = match serde_json::from_str(&text) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, frame = %truncate(&text, 200), "mcp-endpoint: parse error");
                    let resp = crate::mcp::Response::error(
                        None,
                        crate::mcp::codes::PARSE_ERROR,
                        format!("parse error: {e}"),
                    );
                    let _ = write
                        .send(Message::Text(serde_json::to_string(&resp).unwrap()))
                        .await;
                    continue;
                }
            };

            // Tool calls are interesting enough to log at info; everything
            // else (initialize, tools/list, notifications/initialized,
            // ping) is debug-level noise.
            if req.method == "tools/call" {
                let tool_name = req
                    .params
                    .as_ref()
                    .and_then(|p| p.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                tracing::info!(
                    id = ?req.id, tool = %tool_name,
                    "mcp-endpoint: tool call"
                );
            } else {
                tracing::debug!(method = %req.method, id = ?req.id, "mcp-endpoint: request");
            }

            // MCP `notifications/initialized` has no `id` and expects no
            // response — match xiaozhi's mcp_endpoint_handler.py.
            let is_notification = req.id.is_none();
            let method_for_log = req.method.clone();
            let resp = server.dispatch(&caller, "", req).await;
            if !is_notification {
                if resp.error.is_some() {
                    tracing::warn!(
                        method = %method_for_log,
                        error = ?resp.error,
                        "mcp-endpoint: dispatch error"
                    );
                }
                let out = serde_json::to_string(&resp).unwrap();
                tracing::debug!(frame = %truncate(&out, 400), "mcp-endpoint: send");
                if let Err(e) = write.send(Message::Text(out)).await {
                    tracing::warn!(error = %e, "mcp-endpoint: write error; will reconnect");
                    break;
                }
            }
        }

        tracing::info!(backoff_secs, "mcp-endpoint: disconnected; reconnecting");
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
    }
}

/// Truncate a string to `n` chars for log output, appending an ellipsis
/// when truncation happens. Used to keep frame logs readable.
fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…<{} bytes total>", &s[..n], s.len())
    }
}

/// Replace the `token=…` query value with `<JWT>` so journalctl /
/// stdout don't leak the cap token. The token is a Bearer secret —
/// anyone holding it can impersonate this MCP server to the relay.
fn redact_url(url: &str) -> String {
    if let Some(idx) = url.find("token=") {
        let prefix_end = idx + "token=".len();
        let suffix_start = url[prefix_end..]
            .find('&')
            .map(|off| prefix_end + off)
            .unwrap_or(url.len());
        format!("{}<JWT>{}", &url[..prefix_end], &url[suffix_start..])
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::redact_url;

    #[test]
    fn redact_url_strips_jwt() {
        assert_eq!(
            redact_url("wss://api.xiaozhi.me/mcp/?token=eyJhbGc.somepayload.sig"),
            "wss://api.xiaozhi.me/mcp/?token=<JWT>"
        );
    }

    #[test]
    fn redact_url_preserves_trailing_params() {
        assert_eq!(
            redact_url("wss://x.example/?token=secret&user=bob"),
            "wss://x.example/?token=<JWT>&user=bob"
        );
    }

    #[test]
    fn redact_url_passthrough_when_no_token() {
        assert_eq!(redact_url("ws://127.0.0.1:8004/"), "ws://127.0.0.1:8004/");
    }
}
