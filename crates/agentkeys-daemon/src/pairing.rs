use std::time::{Duration, Instant};

use agentkeys_core::auth_request;
use agentkeys_core::backend::{BackendError, CredentialBackend};
use agentkeys_types::{
    AgentIdentity, AuthRequestType, PublicKey, Scope, Session, WalletAddress,
};
use anyhow::{anyhow, Context, Result};

pub struct PairResult {
    pub session: Session,
    pub wallet: WalletAddress,
}

/// Run the pair-on-startup flow. Returns a PairResult with the minted session.
/// poll_timeout_secs: how long to poll before giving up (default 300 for prod, 3 for tests).
pub async fn run_pair_flow(
    backend: &dyn CredentialBackend,
    poll_timeout_secs: u64,
) -> Result<PairResult> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pubkey_bytes = ed25519_dalek::VerifyingKey::from(&signing_key).to_bytes().to_vec();
    let child_pubkey = PublicKey(pubkey_bytes);

    let scope = Scope { services: vec![], read_only: false };
    let request_type = AuthRequestType::Pair { requested_scope: scope };
    let request_details = auth_request::canonical_bytes(&request_type)
        .map_err(|e| anyhow!("canonical_bytes failed: {e}"))?;

    let opened = backend
        .open_auth_request(&child_pubkey, request_type, &request_details)
        .await
        .context("open_auth_request failed")?;

    let pair_code = opened.pair_code.clone();
    let request_id = opened.id.clone();

    let reg_token = backend
        .register_rendezvous(&child_pubkey, &pair_code)
        .await
        .context("register_rendezvous failed")?;

    println!(
        "Pair code: {}. Approve on your Master device. OTP: {}",
        pair_code.0, opened.otp
    );

    let deadline = Instant::now() + Duration::from_secs(poll_timeout_secs);

    loop {
        if Instant::now() >= deadline {
            let err = anyhow!(
                "Pair timeout: no approval received within {} seconds. \
                 Restart the daemon to try again.",
                poll_timeout_secs
            );
            tracing::error!("{err}");
            return Err(err);
        }

        match backend.poll_rendezvous(&reg_token).await {
            Ok(Some(payload)) => {
                // Rendezvous payload delivered by the CLI approve flow.
                // Log receipt; the signed decision is retrieved via await_auth_decision.
                tracing::info!(
                    "Rendezvous payload received ({} bytes). Fetching auth decision.",
                    payload.0.len()
                );
                break;
            }
            Ok(None) => {
                // This poll window timed out — continue waiting.
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Err(BackendError::Expired) => {
                return Err(anyhow!("Pair code expired before approval"));
            }
            Err(e) => {
                tracing::error!("poll_rendezvous error: {e}");
                return Err(anyhow!("poll_rendezvous error: {e}"));
            }
        }
    }

    let decision = backend
        .await_auth_decision(&request_id)
        .await
        .context("await_auth_decision failed")?;

    // TODO(v0.1): verify decision.signature against the master's public key
    // (retrieved during pair initiation) to ensure the approval was not tampered with.

    if !decision.approved {
        return Err(anyhow!("Pair request was rejected"));
    }

    let session = decision.session.ok_or_else(|| anyhow!("no session in decision"))?;
    let wallet = decision.wallet.ok_or_else(|| anyhow!("no wallet in decision"))?;

    println!("Paired. Session received. Daemon ready.");

    Ok(PairResult { session, wallet })
}

/// Run the recover flow. Returns a PairResult with the recovered session.
pub async fn run_recover_flow(
    backend: &dyn CredentialBackend,
    agent_identity_str: &str,
    poll_timeout_secs: u64,
) -> Result<PairResult> {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let pubkey_bytes = ed25519_dalek::VerifyingKey::from(&signing_key).to_bytes().to_vec();
    let child_pubkey = PublicKey(pubkey_bytes.clone());

    let agent_identity = if agent_identity_str.starts_with("0x") {
        AgentIdentity::WalletAddress(WalletAddress(agent_identity_str.to_string()))
    } else {
        AgentIdentity::Alias(agent_identity_str.to_string())
    };

    let request_type = AuthRequestType::Recover {
        agent_identity: agent_identity.clone(),
        new_daemon_pubkey: pubkey_bytes,
    };
    let request_details = auth_request::canonical_bytes(&request_type)
        .map_err(|e| anyhow!("canonical_bytes failed: {e}"))?;

    let opened = backend
        .open_auth_request(&child_pubkey, request_type, &request_details)
        .await
        .context("open_auth_request (recover) failed")?;

    let pair_code = opened.pair_code.clone();
    let request_id = opened.id.clone();

    let reg_token = backend
        .register_rendezvous(&child_pubkey, &pair_code)
        .await
        .context("register_rendezvous (recover) failed")?;

    println!(
        "Recovery code: {}. Approve on your Master device. OTP: {}",
        pair_code.0, opened.otp
    );

    let deadline = Instant::now() + Duration::from_secs(poll_timeout_secs);

    loop {
        if Instant::now() >= deadline {
            let err = anyhow!(
                "Recover timeout: no approval received within {} seconds. \
                 Restart the daemon to try again.",
                poll_timeout_secs
            );
            tracing::error!("{err}");
            return Err(err);
        }

        match backend.poll_rendezvous(&reg_token).await {
            Ok(Some(payload)) => {
                tracing::info!(
                    "Rendezvous payload received ({} bytes). Fetching auth decision.",
                    payload.0.len()
                );
                break;
            }
            Ok(None) => {
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
            Err(BackendError::Expired) => {
                return Err(anyhow!("Recovery code expired before approval"));
            }
            Err(BackendError::NotFound(msg)) => {
                return Err(anyhow!("Agent not found: {msg}"));
            }
            Err(e) => {
                tracing::error!("poll_rendezvous error: {e}");
                return Err(anyhow!("poll_rendezvous error: {e}"));
            }
        }
    }

    let decision = backend
        .await_auth_decision(&request_id)
        .await
        .context("await_auth_decision (recover) failed")?;

    // TODO(v0.1): verify decision.signature against the master's public key
    // (retrieved during pair initiation) to ensure the approval was not tampered with.

    if !decision.approved {
        return Err(anyhow!("Recover request was rejected"));
    }

    let session = decision.session.ok_or_else(|| anyhow!("no session in recover decision"))?;
    let wallet = decision.wallet.ok_or_else(|| anyhow!("no wallet in recover decision"))?;

    println!("Recovered. Session received. Daemon ready.");

    Ok(PairResult { session, wallet })
}
