//! Agent-side credential fetch (#216) — the agent pulls its AUTHORIZED
//! credential (e.g. its LLM key) from the vault to *use* it. Unlike the master's
//! store/list (which never reveal a secret), this returns the decrypted
//! plaintext: the agent needs the actual secret to make calls. It is gated by the
//! agent's `cred:<service>` scope — the broker won't mint a cred-fetch cap the
//! actor isn't scoped for, and the worker re-checks the cap.
//!
//! Routes through the shared `agentkeys-backend-client` (issue #204): cap-mint
//! (`CredFetch`) → per-actor STS under the VAULT role → cred worker
//! `/v1/cred/fetch` → decrypt → plaintext. No re-typed wire shapes.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use agentkeys_backend_client::{
    normalize_omni_0x, BackendClient, CapMintOp, CapMintRequest, CredFetchInput, CredStoreInput,
};

/// Fetch + decrypt the credential `service` the actor is authorized for, returning
/// the plaintext secret. `operator_omni` == `actor_omni` for a master-self fetch;
/// for an agent they are (master, agent). The omnis are normalized to the broker's
/// `0x`-prefixed shape (issue #200 — the bare-vs-0x drift normalizer).
#[allow(clippy::too_many_arguments)]
pub async fn cred_fetch(
    service: &str,
    operator_omni: &str,
    actor_omni: &str,
    device_key_hash: &str,
    session_bearer: &str,
    broker_url: &str,
    cred_url: &str,
    vault_role_arn: &str,
    region: &str,
) -> Result<String> {
    let client = BackendClient::new(
        Some(broker_url.to_string()),
        None, // memory_url
        None, // audit_url
        Some(cred_url.to_string()),
        Some(session_bearer.to_string()), // agent_session_bearer → per-actor STS
        None,                             // memory_role_arn
        Some(vault_role_arn.to_string()),
        region.to_string(),
    );
    let cap = client
        .cap_mint(
            CapMintOp::CredFetch,
            CapMintRequest {
                operator_omni: normalize_omni_0x(operator_omni),
                actor_omni: normalize_omni_0x(actor_omni),
                service: service.to_string(),
                device_key_hash: device_key_hash.to_string(),
                ttl_seconds: 300,
            },
            session_bearer,
        )
        .await
        .with_context(|| format!("cap-mint cred-fetch for service `{service}`"))?;
    let result = client
        .cred_fetch(CredFetchInput { cap })
        .await
        .with_context(|| format!("cred worker fetch for service `{service}`"))?;
    let bytes = STANDARD
        .decode(&result.plaintext_b64)
        .context("decode cred plaintext_b64")?;
    String::from_utf8(bytes).context("cred plaintext is not valid UTF-8")
}

/// Vault the credential `service` = `secret` (the symmetric store half of
/// [`cred_fetch`]). `operator_omni` == `actor_omni` for a master-self store (the
/// master vaulting into its OWN vault — the common case, e.g. seeding the agent's
/// LLM key). Returns the worker's S3 key. Routes through the shared
/// `agentkeys-backend-client` (#204): cap-mint (`CredStore`) → per-actor STS under
/// the VAULT role → cred worker `/v1/cred/store` → encrypt + S3 PUT.
#[allow(clippy::too_many_arguments)]
pub async fn cred_store(
    service: &str,
    secret: &str,
    operator_omni: &str,
    actor_omni: &str,
    device_key_hash: &str,
    session_bearer: &str,
    broker_url: &str,
    cred_url: &str,
    vault_role_arn: &str,
    region: &str,
) -> Result<String> {
    let client = BackendClient::new(
        Some(broker_url.to_string()),
        None, // memory_url
        None, // audit_url
        Some(cred_url.to_string()),
        Some(session_bearer.to_string()), // session bearer → per-actor STS
        None,                             // memory_role_arn
        Some(vault_role_arn.to_string()),
        region.to_string(),
    );
    let cap = client
        .cap_mint(
            CapMintOp::CredStore,
            CapMintRequest {
                operator_omni: normalize_omni_0x(operator_omni),
                actor_omni: normalize_omni_0x(actor_omni),
                service: service.to_string(),
                device_key_hash: device_key_hash.to_string(),
                ttl_seconds: 300,
            },
            session_bearer,
        )
        .await
        .with_context(|| format!("cap-mint cred-store for service `{service}`"))?;
    let result = client
        .cred_store(CredStoreInput {
            cap,
            plaintext_b64: STANDARD.encode(secret.as_bytes()),
        })
        .await
        .with_context(|| format!("cred worker store for service `{service}`"))?;
    Ok(result.s3_key)
}
