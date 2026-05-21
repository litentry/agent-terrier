//! `--master-companion` mode — second-daemon-as-mobile-app alternative.
//!
//! The primary master daemon runs on `localhost` with its own K11 credential
//! (registered in `SidecarRegistry` with `roles = CAP_MINT|RECOVERY|SCOPE_MGMT`).
//! The companion daemon runs on `companion.localhost`, holds a SECOND, distinct
//! K11 credential (Touch ID prompt against a different platform passkey), and
//! is registered with `roles = CAP_MINT|RECOVERY` (no SCOPE_MGMT by default).
//!
//! With both registered, the operator can `agentkeys recovery --revoke-device`
//! and require an M-of-N quorum (default `recoveryThreshold=2` once a 2nd
//! master is added, see arch.md §10.3.1). The primary daemon's CLI prompts the
//! companion daemon's HTTP API, which runs its OWN Touch ID ceremony.
//!
//! Wire surface (HTTP / localhost only):
//!
//!   GET  /v1/companion/whoami
//!     Returns { device_key_hash, k11_cred_id, operator_omni } so the primary
//!     master knows the companion's on-chain identity.
//!
//!   POST /v1/companion/approve
//!     Body: { expected_challenge_hex: "0x<64-hex>" }
//!     Runs `agentkeys k11 assert --webauthn --rp-id companion.localhost
//!     --emit-chain-payload` against the bound credential, returns the
//!     resulting `K11ChainAssertion` JSON.
//!
//! The companion bind address defaults to `127.0.0.1:9091` (primary cap-proxy
//! is `9090` when TCP enabled). Bound to loopback only — no remote reachable.

use std::sync::Arc;

use anyhow::Context;
use axum::{extract::State, http::StatusCode, routing::{get, post}, Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tracing::info;

const DEFAULT_BIND: &str = "127.0.0.1:9091";
pub const DEFAULT_COMPANION_RP_ID: &str = "companion.localhost";

#[derive(Clone)]
pub struct CompanionState {
    pub operator_omni: String,
    pub device_key_hash: String,
    pub k11_cred_id: String,
    pub rp_id: String,
}

#[derive(Debug, Serialize)]
pub struct WhoAmIResponse {
    pub operator_omni: String,
    pub device_key_hash: String,
    pub k11_cred_id: String,
    pub rp_id: String,
    pub role: &'static str,
}

#[derive(Debug, Deserialize)]
pub struct ApproveRequest {
    pub expected_challenge_hex: String,
    /// **Preferred** — typed K11 operation intent (per
    /// `wiki/k11-intent-conventions.md`). Deserializes into
    /// `K11OpIntent`; rendered via the shared formatter so the
    /// companion's K11 page is byte-for-byte uniform with the primary's
    /// rendering of the same op. When present, this field WINS over the
    /// raw `intent_text` + `intent_fields` below.
    #[serde(default)]
    pub intent_op: Option<agentkeys_cli::k11_intent::K11OpIntent>,
    /// Legacy raw fallback — operator-readable headline + per-field
    /// rows. Kept for back-compat with callers that haven't migrated to
    /// `intent_op` yet; ignored when `intent_op` is set.
    #[serde(default)]
    pub intent_text: Option<String>,
    /// Legacy raw fallback — `Label=Value` rows. Ignored when `intent_op`
    /// is set.
    #[serde(default)]
    pub intent_fields: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ApproveResponse {
    pub assertion: agentkeys_cli::k11_webauthn::K11ChainAssertion,
}

/// Top-level companion server. Binds the configured TCP listener and serves
/// the two routes; blocks until the listener is closed (Ctrl-C / SIGTERM).
pub async fn run(args: CompanionArgs) -> anyhow::Result<()> {
    let state = CompanionState {
        operator_omni: args.operator_omni,
        device_key_hash: args.device_key_hash,
        k11_cred_id: args.k11_cred_id,
        rp_id: args.rp_id.unwrap_or_else(|| DEFAULT_COMPANION_RP_ID.to_string()),
    };

    let app = Router::new()
        .route("/v1/companion/whoami", get(whoami))
        .route("/v1/companion/approve", post(approve))
        .with_state(Arc::new(state));

    let bind = args.bind.as_deref().unwrap_or(DEFAULT_BIND);
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind companion daemon at {bind}"))?;

    info!(bind = %bind, "agentkeys-daemon companion mode listening");
    axum::serve(listener, app).await.context("companion axum serve")?;
    Ok(())
}

async fn whoami(State(state): State<Arc<CompanionState>>) -> Json<WhoAmIResponse> {
    Json(WhoAmIResponse {
        operator_omni: state.operator_omni.clone(),
        device_key_hash: state.device_key_hash.clone(),
        k11_cred_id: state.k11_cred_id.clone(),
        rp_id: state.rp_id.clone(),
        role: "CAP_MINT|RECOVERY",
    })
}

async fn approve(
    State(state): State<Arc<CompanionState>>,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, (StatusCode, String)> {
    // Decode the expected_challenge_hex into 32 bytes.
    let stripped = req.expected_challenge_hex.trim_start_matches("0x");
    let bytes = hex::decode(stripped).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("expected_challenge_hex must be hex: {e}"),
        )
    })?;
    if bytes.len() != 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "expected_challenge_hex must be 32 bytes (got {})",
                bytes.len()
            ),
        ));
    }
    let mut challenge = [0u8; 32];
    challenge.copy_from_slice(&bytes);

    info!(
        operator_omni = %state.operator_omni,
        challenge = %req.expected_challenge_hex,
        typed_op = req.intent_op.is_some(),
        legacy_intent = ?req.intent_text,
        legacy_field_count = req.intent_fields.len(),
        "companion received approval request; opening Touch ID prompt"
    );

    // Typed-intent path wins: it renders via the shared formatter so
    // the companion's prompt is byte-for-byte uniform with the
    // primary's rendering of the same op. Legacy raw `intent_text` +
    // `intent_fields` are the fallback for callers that haven't
    // migrated yet.
    let intent = if let Some(op) = req.intent_op.as_ref() {
        op.render()
    } else {
        agentkeys_cli::k11_webauthn::K11IntentContext {
            text: req.intent_text.clone(),
            fields: req
                .intent_fields
                .iter()
                .map(|raw| match raw.split_once('=') {
                    Some((label, value)) => (label.to_string(), value.to_string()),
                    None => (raw.clone(), String::new()),
                })
                .collect(),
        }
    };

    let assertion = agentkeys_cli::k11_webauthn::assert_webauthn_for_chain_with_intent(
        &state.operator_omni,
        challenge,
        &state.rp_id,
        intent,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("webauthn: {e}")))?;

    Ok(Json(ApproveResponse { assertion }))
}

/// Parsed companion-mode args, passed from main.rs.
pub struct CompanionArgs {
    pub bind: Option<String>,
    pub operator_omni: String,
    pub device_key_hash: String,
    pub k11_cred_id: String,
    /// WebAuthn RP ID. Defaults to "companion.localhost". The demo bumps
    /// to "companion-v2.localhost" / etc. when the prior companion is
    /// revoked, so a fresh K11 credential can be enrolled at a distinct
    /// effective domain.
    pub rp_id: Option<String>,
}
