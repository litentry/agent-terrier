//! First-time bootstrap helpers for issue #74 step 1.
//!
//! Both `agentkeys-cli`'s `cmd_init` and `agentkeys-daemon`'s startup
//! routine drive the same chain on a cold start:
//!
//! 1. Authenticate the operator's identity (email-link or OAuth2/Google).
//! 2. From the resulting identity-omni session JWT, ask the dev_key_service
//!    to derive the managed EVM wallet.
//! 3. Link that wallet at the broker (`POST /v1/wallet/link`) so any linked
//!    identity can recover the same wallet later.
//! 4. Run a SIWE round-trip with the dev_key_service signing on behalf of
//!    the identity-omni; receive an EVM-omni session JWT.
//! 5. Hand the EVM-omni session JWT back to the caller so it can persist
//!    in the keychain (CLI) or seed the MCP server (daemon).
//!
//! The helpers below have no I/O side effects beyond HTTP calls — they
//! never touch `session_store`. Persistence is the caller's choice.

use std::time::{Duration, Instant};

use agentkeys_types::{Session, WalletAddress};
use serde_json::json;
use thiserror::Error;

use crate::signer_client::{HttpSignerClient, SignerClient, SignerClientError};

/// Result of a successful first-time init flow.
#[derive(Debug, Clone)]
pub struct InitResult {
    /// EVM-omni session JWT — what the daemon uses going forward.
    pub session: Session,
    /// Identity omni computed from the verified identity (email or OAuth2).
    /// Daemon callers stash this so subsequent SIWE round-trips know which
    /// omni to drive the signer with.
    pub identity_omni: String,
    /// EVM omni from the broker's `/v1/auth/wallet/verify` response.
    pub evm_omni: String,
    /// Derived wallet address (lowercase hex, 0x-prefixed).
    pub derived_wallet: String,
    /// `("email", "alice@…")` or `("oauth2_google", "<google-sub>")`.
    pub identity_type: String,
    pub identity_value: String,
}

#[derive(Debug, Error)]
pub enum InitFlowError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("broker rejected {endpoint}: status={status} body={body}")]
    BrokerRejected {
        endpoint: String,
        status: u16,
        body: String,
    },
    #[error("auth flow timed out after {0}s")]
    Timeout(u64),
    #[error("auth flow ended without success: status={0}")]
    AuthFailed(String),
    #[error("signer error: {0}")]
    Signer(#[from] SignerClientError),
    #[error("address mismatch: derive returned {derived}, sign returned {signed}")]
    AddressMismatch { derived: String, signed: String },
    #[error("missing field {field} in {endpoint} response")]
    MissingField {
        endpoint: &'static str,
        field: &'static str,
    },
}

type FlowResult<T> = Result<T, InitFlowError>;

/// Email-link bootstrap.
pub async fn init_via_email_link(
    broker_url: &str,
    signer_url: &str,
    email: &str,
    chain_id: u64,
    poll_timeout: Duration,
) -> FlowResult<InitResult> {
    let http = reqwest::Client::new();
    let broker = broker_url.trim_end_matches('/');

    // 1. Request a magic link.
    let req = post_json(
        &http,
        &format!("{broker}/v1/auth/email/request"),
        json!({ "email": email }),
    )
    .await?;
    let request_id = string_field(&req, "/v1/auth/email/request", "request_id")?;

    // 2. Poll until verified.
    let (identity_session_jwt, identity_omni) = poll_auth_status(
        &http,
        broker,
        "email",
        &request_id,
        poll_timeout,
    )
    .await?;

    // 3-5. Derive + link + SIWE round-trip.
    let result = finish_init(
        &http,
        broker,
        signer_url,
        &identity_session_jwt,
        &identity_omni,
        chain_id,
        "email",
        email,
    )
    .await?;
    Ok(result)
}

/// OAuth2/Google bootstrap. Returns `(authorization_url, request_id)` after
/// `/v1/auth/oauth2/start`; the caller prints the URL and waits for the
/// operator. Then call `complete_oauth2_google(...)` with the request_id.
///
/// Two-step shape (vs single-call `init_via_email_link`) so the caller can
/// surface the URL to the operator and handle interrupt cleanly between
/// the start and poll.
pub async fn start_oauth2_google(broker_url: &str) -> FlowResult<Oauth2StartResult> {
    let http = reqwest::Client::new();
    let broker = broker_url.trim_end_matches('/');
    let body = post_json(
        &http,
        &format!("{broker}/v1/auth/oauth2/start"),
        json!({ "provider": "google" }),
    )
    .await?;
    let request_id = string_field(&body, "/v1/auth/oauth2/start", "request_id")?;
    let authorization_url = string_field(&body, "/v1/auth/oauth2/start", "authorization_url")?;
    Ok(Oauth2StartResult {
        request_id,
        authorization_url,
    })
}

#[derive(Debug, Clone)]
pub struct Oauth2StartResult {
    pub request_id: String,
    pub authorization_url: String,
}

/// Complete an OAuth2/Google flow that was kicked off via `start_oauth2_google`.
pub async fn complete_oauth2_google(
    broker_url: &str,
    signer_url: &str,
    request_id: &str,
    chain_id: u64,
    poll_timeout: Duration,
) -> FlowResult<InitResult> {
    let http = reqwest::Client::new();
    let broker = broker_url.trim_end_matches('/');
    let (identity_session_jwt, identity_omni) =
        poll_auth_status(&http, broker, "oauth2", request_id, poll_timeout).await?;

    // For OAuth2/Google the broker's status response includes
    // identity_value=<google-sub>. We pull it from the same call.
    let identity_value = identity_value_from_status(&http, broker, "oauth2", request_id).await?;

    finish_init(
        &http,
        broker,
        signer_url,
        &identity_session_jwt,
        &identity_omni,
        chain_id,
        "oauth2_google",
        &identity_value,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn finish_init(
    http: &reqwest::Client,
    broker: &str,
    signer_url: &str,
    identity_session_jwt: &str,
    identity_omni: &str,
    chain_id: u64,
    identity_type: &str,
    identity_value: &str,
) -> FlowResult<InitResult> {
    let derived = derive_via_signer(signer_url, identity_omni, identity_session_jwt).await?;
    link_wallet_at_broker(http, broker, identity_session_jwt, "evm", &derived).await?;
    let (evm_session_jwt, evm_omni, wallet_addr) = siwe_round_trip(
        http,
        broker,
        signer_url,
        identity_omni,
        &derived,
        chain_id,
        identity_session_jwt,
    )
    .await?;
    let session = build_session_from_jwt(&evm_session_jwt, &wallet_addr);
    Ok(InitResult {
        session,
        identity_omni: identity_omni.to_string(),
        evm_omni,
        derived_wallet: derived,
        identity_type: identity_type.to_string(),
        identity_value: identity_value.to_string(),
    })
}

async fn poll_auth_status(
    http: &reqwest::Client,
    broker: &str,
    provider: &str,
    request_id: &str,
    poll_timeout: Duration,
) -> FlowResult<(String, String)> {
    let url = format!("{broker}/v1/auth/{provider}/status/{request_id}");
    let deadline = Instant::now() + poll_timeout;
    loop {
        let resp = http
            .get(&url)
            .send()
            .await
            .map_err(|e| InitFlowError::Transport(format!("GET {url}: {e}")))?;
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| InitFlowError::Transport(format!("parse JSON: {e}")))?;
        match body["status"].as_str() {
            Some("verified") => {
                let session_jwt =
                    string_field(&body, "/v1/auth/{provider}/status", "session_jwt")?;
                let omni =
                    string_field(&body, "/v1/auth/{provider}/status", "omni_account")?;
                return Ok((session_jwt, omni));
            }
            Some("expired") | Some("rejected") => {
                return Err(InitFlowError::AuthFailed(
                    body["status"].as_str().unwrap_or("?").to_string(),
                ));
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(InitFlowError::Timeout(poll_timeout.as_secs()));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn identity_value_from_status(
    http: &reqwest::Client,
    broker: &str,
    provider: &str,
    request_id: &str,
) -> FlowResult<String> {
    let url = format!("{broker}/v1/auth/{provider}/status/{request_id}");
    let body: serde_json::Value = http
        .get(&url)
        .send()
        .await
        .map_err(|e| InitFlowError::Transport(format!("GET {url}: {e}")))?
        .json()
        .await
        .map_err(|e| InitFlowError::Transport(format!("parse JSON: {e}")))?;
    string_field(&body, "/v1/auth/{provider}/status", "identity_value")
}

async fn derive_via_signer(
    signer_url: &str,
    omni_account: &str,
    session_jwt: &str,
) -> FlowResult<String> {
    // Signer (post-issue-#74 step 1b) requires the broker's session JWT
    // as a Bearer token on every /dev/* request. Standalone commands
    // (cli::cmd_signer_derive) chain .with_session_jwt() from the
    // keychain; the in-flow init_via_email_link path also has the
    // identity-session JWT in hand (just minted by the broker after
    // the magic-link click), so chain it here too.
    let client = HttpSignerClient::new(signer_url).with_session_jwt(session_jwt.to_string());
    let derived = client.derive_address(omni_account).await?;
    Ok(derived.address)
}

async fn link_wallet_at_broker(
    http: &reqwest::Client,
    broker: &str,
    session_jwt: &str,
    identity_type: &str,
    identity_value: &str,
) -> FlowResult<()> {
    let url = format!("{broker}/v1/wallet/link");
    let resp = http
        .post(&url)
        .header("authorization", format!("Bearer {session_jwt}"))
        .json(&json!({
            "identity_type":  identity_type,
            "identity_value": identity_value,
        }))
        .send()
        .await
        .map_err(|e| InitFlowError::Transport(format!("POST {url}: {e}")))?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(InitFlowError::BrokerRejected {
            endpoint: "/v1/wallet/link".into(),
            status,
            body,
        });
    }
    Ok(())
}

async fn siwe_round_trip(
    http: &reqwest::Client,
    broker: &str,
    signer_url: &str,
    identity_omni: &str,
    derived_addr: &str,
    chain_id: u64,
    session_jwt: &str,
) -> FlowResult<(String, String, String)> {
    let start = post_json(
        http,
        &format!("{broker}/v1/auth/wallet/start"),
        json!({ "address": derived_addr, "chain_id": chain_id }),
    )
    .await?;
    let request_id = string_field(&start, "/v1/auth/wallet/start", "request_id")?;
    let siwe_message = string_field(&start, "/v1/auth/wallet/start", "siwe_message")?;

    // Signer requires the broker's session JWT (same one threaded
    // through derive_via_signer above) for the SIWE-message sign call.
    let signer = HttpSignerClient::new(signer_url).with_session_jwt(session_jwt.to_string());
    let signed = signer
        .sign_eip191(identity_omni, siwe_message.as_bytes())
        .await?;
    if signed.address.to_lowercase() != derived_addr.to_lowercase() {
        return Err(InitFlowError::AddressMismatch {
            derived: derived_addr.to_string(),
            signed: signed.address,
        });
    }

    let verify = post_json(
        http,
        &format!("{broker}/v1/auth/wallet/verify"),
        json!({ "request_id": request_id, "signature": signed.signature }),
    )
    .await?;
    let evm_session_jwt = string_field(&verify, "/v1/auth/wallet/verify", "session_jwt")?;
    let evm_omni = string_field(&verify, "/v1/auth/wallet/verify", "omni_account")?;
    let wallet_addr = verify["wallet_address"]
        .as_str()
        .unwrap_or(derived_addr)
        .to_string();
    Ok((evm_session_jwt, evm_omni, wallet_addr))
}

async fn post_json(
    http: &reqwest::Client,
    url: &str,
    body: serde_json::Value,
) -> FlowResult<serde_json::Value> {
    let resp = http
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| InitFlowError::Transport(format!("POST {url}: {e}")))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(InitFlowError::BrokerRejected {
            endpoint: url.to_string(),
            status: status.as_u16(),
            body,
        });
    }
    resp.json::<serde_json::Value>()
        .await
        .map_err(|e| InitFlowError::Transport(format!("parse JSON from {url}: {e}")))
}

fn string_field(
    body: &serde_json::Value,
    endpoint: &'static str,
    field: &'static str,
) -> FlowResult<String> {
    body[field]
        .as_str()
        .map(|s| s.to_string())
        .ok_or(InitFlowError::MissingField { endpoint, field })
}

fn build_session_from_jwt(session_jwt: &str, wallet_addr: &str) -> Session {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    Session {
        token: session_jwt.to_string(),
        wallet: WalletAddress(wallet_addr.to_string()),
        scope: None,
        created_at: now,
        ttl_seconds: 18_000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_session_from_jwt_populates_required_fields() {
        let s = build_session_from_jwt("eyJ.fake.jwt", "0xdeadbeef");
        assert_eq!(s.token, "eyJ.fake.jwt");
        assert_eq!(s.wallet.0, "0xdeadbeef");
        assert!(s.scope.is_none());
        assert_eq!(s.ttl_seconds, 18_000);
        assert!(s.created_at > 0);
    }

    #[test]
    fn missing_field_error_carries_endpoint_and_field() {
        let body = serde_json::json!({});
        match string_field(&body, "/x", "y") {
            Err(InitFlowError::MissingField { endpoint, field }) => {
                assert_eq!(endpoint, "/x");
                assert_eq!(field, "y");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
