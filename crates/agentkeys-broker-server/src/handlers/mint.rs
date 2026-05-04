use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;

use crate::audit::{MintOutcome, MintRecord};
use crate::auth::{extract_bearer_token, validate_bearer_token};
use crate::error::{BrokerError, BrokerResult};
use crate::state::SharedState;

#[derive(Serialize)]
pub struct MintResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: i64,
    pub wallet: String,
}

#[tracing::instrument(skip_all, fields(wallet = tracing::field::Empty, outcome = tracing::field::Empty))]
pub async fn mint_aws_creds(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> BrokerResult<Json<MintResponse>> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(extract_bearer_token)
        .ok_or_else(|| BrokerError::Unauthorized("missing Authorization header".into()))?;

    let session = match validate_bearer_token(&state.http, &state.config.backend_url, token).await {
        Ok(s) => s,
        Err(e) => {
            // Distinguish bearer-rejected (auth_failed) from backend-down
            // (backend_error). An operator chasing a backend outage should
            // not see it as a flood of auth failures.
            let (outcome, span_label) = match &e {
                BrokerError::Unauthorized(_) => (MintOutcome::AuthFailed, "auth_failed"),
                BrokerError::BackendUnreachable(_) => (MintOutcome::BackendError, "backend_error"),
                _ => (MintOutcome::BackendError, "backend_error"),
            };
            record_outcome(
                &state,
                token,
                "unknown",
                "(unauthenticated)",
                outcome,
                Some(&e.to_string()),
            );
            tracing::Span::current().record("outcome", span_label);
            return Err(e);
        }
    };

    tracing::Span::current().record("wallet", session.wallet.as_str());

    let session_name = build_session_name(&session.wallet);

    match state
        .sts
        .assume_role(
            &state.config.data_role_arn,
            &session_name,
            state.config.session_duration_seconds,
        )
        .await
    {
        Ok(creds) => {
            // Audit must succeed before we hand out credentials. A credential
            // mint with no audit row is exactly the silent-failure mode the
            // operator is trying to defend against.
            state.audit.record_mint(
                MintRecord {
                    requester_token: token,
                    requester_wallet: &session.wallet,
                    requested_role: &state.config.data_role_arn,
                    session_duration_seconds: state.config.session_duration_seconds,
                    sts_session_name: &session_name,
                    outcome: MintOutcome::Ok,
                },
                None,
            )?;
            tracing::Span::current().record("outcome", "ok");
            Ok(Json(MintResponse {
                access_key_id: creds.access_key_id,
                secret_access_key: creds.secret_access_key,
                session_token: creds.session_token,
                expiration: creds.expiration_unix,
                wallet: session.wallet,
            }))
        }
        Err(e) => {
            record_outcome(
                &state,
                token,
                &session.wallet,
                &session_name,
                MintOutcome::StsError,
                Some(&e.to_string()),
            );
            tracing::Span::current().record("outcome", "sts_error");
            Err(e)
        }
    }
}

/// Best-effort audit record on a failure path. We never want a broken audit
/// log to mask the underlying error the caller is going to receive — but we
/// also refuse to swallow the audit failure silently (the prior bug). On
/// audit-write failure, log loudly and continue with the original error.
fn record_outcome(
    state: &SharedState,
    token: &str,
    wallet: &str,
    session_name: &str,
    outcome: MintOutcome,
    detail: Option<&str>,
) {
    if let Err(audit_err) = state.audit.record_mint(
        MintRecord {
            requester_token: token,
            requester_wallet: wallet,
            requested_role: &state.config.data_role_arn,
            session_duration_seconds: state.config.session_duration_seconds,
            sts_session_name: session_name,
            outcome,
        },
        detail,
    ) {
        tracing::error!(
            error = %audit_err,
            wallet = %wallet,
            outcome = ?outcome,
            "audit insert failed on failure path — anomaly detection is now blind"
        );
    }
}

fn build_session_name(wallet: &str) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    // Microsecond suffix prevents per-second collisions from the same wallet.
    let micros = now.subsec_micros();
    let safe_wallet: String = wallet
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '-' | '_'))
        .take(40)
        .collect();
    let mut name = format!("agentkeys-{}-{}-{:06}", safe_wallet, secs, micros);
    if name.len() > 64 {
        name.truncate(64);
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_name_under_64_chars() {
        let n = build_session_name("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
        assert!(n.len() <= 64, "session name {} exceeds 64 chars", n);
        assert!(n.starts_with("agentkeys-"));
    }

    #[test]
    fn session_name_strips_unsafe_chars() {
        let n = build_session_name("0xABC/123 weird");
        assert!(!n.contains('/'));
        assert!(!n.contains(' '));
    }

    #[test]
    fn session_name_handles_empty_wallet() {
        let n = build_session_name("");
        assert!(n.starts_with("agentkeys--"));
    }

    #[test]
    fn session_name_includes_microsecond_suffix() {
        // Same wallet, two consecutive calls should yield distinct names
        // because microsecond resolution moves between calls. Worst case
        // (same micros), we still pass the format check.
        let a = build_session_name("0xabc");
        let b = build_session_name("0xabc");
        assert!(a.matches('-').count() >= 3, "expected at least 3 dashes, got {}", a);
        assert!(b.matches('-').count() >= 3);
        // Suffix is a 6-digit microsecond field; both names share prefix up
        // through the unix-seconds field.
    }
}
