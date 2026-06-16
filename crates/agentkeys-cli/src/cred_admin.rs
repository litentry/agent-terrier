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

use std::path::{Path, PathBuf};

use agentkeys_backend_client::{
    normalize_omni_0x, BackendClient, CapMintOp, CapMintRequest, CredFetchInput, CredStoreInput,
    MemoryGetInput,
};
use agentkeys_types::CredManifest;

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

/// #295 P1 §7a — delegate-side canonical-memory READ. Pulls a `namespace` of the
/// MASTER's CANONICAL memory (`bots/<operator>/memory/`) this actor is
/// authorized for, returning the decrypted plaintext. Gated by the actor's
/// on-chain `memory:<ns>` scope grant and run under the DELEGATE's OWN session:
/// the shared client presents the CanonicalFetch cap + this session to the
/// broker's `/v1/cap/canonical-sts`, which (after verifying the cap) returns
/// read-only, exact-object STS creds. The delegate NEVER holds the operator
/// session bearer (the Codex critical fix). The cap's `service` carries the
/// namespace (the worker keys S3 on operator + service). Routes through the
/// shared `agentkeys-backend-client`.
#[allow(clippy::too_many_arguments)]
pub async fn memory_canonical_get(
    namespace: &str,
    operator_omni: &str,
    actor_omni: &str,
    device_key_hash: &str,
    session_bearer: &str,
    broker_url: &str,
    memory_url: &str,
    region: &str,
) -> Result<String> {
    // The DELEGATE's own session bearer authenticates to the broker, which (after
    // verifying the cap) issues scoped read-only creds — no MEMORY_ROLE_ARN is
    // needed on this side (the broker holds it). cred_fetch keeps the role-relay.
    let client = BackendClient::new(
        Some(broker_url.to_string()),
        Some(memory_url.to_string()),
        None, // audit_url
        None, // cred_url
        Some(session_bearer.to_string()),
        None, // memory_role_arn — unused on the broker-brokered canonical path
        None, // vault_role_arn
        region.to_string(),
    );
    let cap = client
        .cap_mint(
            CapMintOp::MemoryCanonicalGet,
            CapMintRequest {
                operator_omni: normalize_omni_0x(operator_omni),
                actor_omni: normalize_omni_0x(actor_omni),
                service: namespace.to_string(),
                device_key_hash: device_key_hash.to_string(),
                ttl_seconds: 300,
            },
            session_bearer,
        )
        .await
        .with_context(|| format!("cap-mint memory-canonical-get for namespace `{namespace}`"))?;
    let result = client
        .memory_canonical_get(MemoryGetInput {
            cap,
            namespace: namespace.to_string(),
        })
        .await
        .with_context(|| format!("memory worker canonical-get for namespace `{namespace}`"))?;
    let bytes = STANDARD
        .decode(&result.plaintext_b64)
        .context("decode memory plaintext_b64")?;
    String::from_utf8(bytes).context("memory plaintext is not valid UTF-8")
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

// ─── #216 default-key selection — the OFF-CHAIN manifest (discovery only) ────
// The on-chain AgentKeysScope stores only keccak(service) hashes, so the agent
// can't enumerate its authorized service NAMES or learn its default LLM key from
// chain. The master records both here, off-chain; every fetch still re-verifies
// on-chain (isServiceInScope), so this never widens authorization.

/// Resolve the cred-manifest path: an explicit `--manifest` /
/// `$AGENTKEYS_CRED_MANIFEST` (clap merges both into `explicit`), else
/// `~/.agentkeys/cred-manifest.json`.
pub fn cred_manifest_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return PathBuf::from(p);
    }
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home)
            .join(".agentkeys")
            .join("cred-manifest.json");
    }
    PathBuf::from("cred-manifest.json")
}

/// Render the authorized-services listing (the chain can't enumerate names —
/// this is the off-chain discovery layer). Marks the master-designated default.
pub fn cred_list(path: &Path) -> Result<String> {
    let man = CredManifest::load(path)
        .with_context(|| format!("read cred manifest {}", path.display()))?;
    if man.services.is_empty() {
        return Ok(format!(
            "no authorized credential services recorded ({} absent or empty).\n\
             The master records them at grant time:\n  \
             agentkeys cred manifest --services <a,b,c> --default <a>",
            path.display()
        ));
    }
    let default = man.default_name();
    let mut out = format!("authorized credential services ({}):\n", path.display());
    for (i, s) in man.services.iter().enumerate() {
        let mark = if Some(s.as_str()) == default {
            "  ← default"
        } else {
            ""
        };
        out.push_str(&format!("  {}. {}{}\n", i + 1, s, mark));
    }
    Ok(out.trim_end().to_string())
}

/// Write the off-chain cred manifest: authorized service NAMES + the
/// master-designated default (public names only, never secrets). The master /
/// operator runs this at grant time so the agent's no-arg fetch picks the default.
pub fn cred_manifest_write(
    path: &Path,
    services_csv: &str,
    default: Option<String>,
) -> Result<String> {
    let services: Vec<String> = services_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if services.is_empty() {
        anyhow::bail!("--services must list at least one service name");
    }
    if let Some(d) = default.as_deref() {
        if !services.iter().any(|s| s == d) {
            anyhow::bail!(
                "--default '{d}' is not in --services [{}]",
                services.join(", ")
            );
        }
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let man = CredManifest::new(services, default);
    man.save(path)
        .with_context(|| format!("write cred manifest {}", path.display()))?;
    Ok(format!(
        "recorded cred manifest {} — {} service(s), default `{}`",
        path.display(),
        man.services.len(),
        man.default_name().unwrap_or("(none)")
    ))
}
